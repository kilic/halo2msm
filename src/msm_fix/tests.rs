use crate::util::multiexp_naive_var;
use crate::RegionCtx;
use ff::Field;
use ff::PrimeField;
use group::Curve;
use group::Group;
use halo2::dev::MockProver;
use halo2::halo2curves::pasta::Eq;
use halo2::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::CurveAffine,
    plonk::Error,
    plonk::{Circuit, ConstraintSystem},
};
use rand_core::OsRng;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::collections::BTreeMap;
use std::vec;

use super::config::FixMSMGate;

pub(crate) fn incremental_table<C: CurveAffine>(point: &C, size: usize, aux: &C) -> Vec<C> {
    assert!(size > 0);
    let mut acc = aux.to_curve();
    let table = (0..size)
        .map(|i| {
            let ret = acc;
            if i != size - 1 {
                acc += point;
            }
            ret
        })
        .collect::<Vec<_>>();

    let mut table_affine = vec![C::identity(); size];

    C::CurveExt::batch_normalize(&table, &mut table_affine);

    table_affine
}

#[derive(Default, Clone, Debug)]
struct Params<C: CurveAffine> {
    window: usize,
    bases: Vec<C>,
    aux: C,
}

#[derive(Clone, Debug)]
struct TestConfig<F: PrimeField + Ord, App: CurveAffine<Base = F>> {
    msm_gate: FixMSMGate<F, App>,
}
#[derive(Debug, Default)]
struct MyCircuit<F: PrimeField + Ord, App: CurveAffine<Base = F>> {
    window: usize,
    bases: Vec<App>,
    aux: App,
}

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> Circuit<F> for MyCircuit<F, App> {
    type Config = TestConfig<F, App>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Params<App>;
    fn without_witnesses(&self) -> Self {
        Self {
            window: self.window,
            bases: self.bases.clone(),
            aux: self.aux,
        }
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let a0 = meta.advice_column();
        let a1 = meta.advice_column();
        let a2 = meta.advice_column();
        let a3 = meta.advice_column();
        let a4 = meta.advice_column();
        let constant = meta.fixed_column();
        let range_table = meta.lookup_table_column();
        let address_table = meta.lookup_table_column();
        let x_table = meta.lookup_table_column();
        let y_table = meta.lookup_table_column();

        let window = params.window;
        let window_size = 1 << window;

        let mut memory = BTreeMap::<F, (F, F)>::new();
        let mut aux = params.aux.to_curve();

        let mut correction = App::CurveExt::identity();

        let auxes = params
            .bases
            .iter()
            .enumerate()
            .map(|(point_idx, point)| {
                let table = incremental_table(point, window_size, &aux.to_affine());
                let cur_aux = aux.clone();
                aux = aux.double();

                let _table = table
                    .iter()
                    .enumerate()
                    .map(|(offset, point)| {
                        let address = (point_idx * window_size) + offset;

                        let coordinates = point.coordinates().unwrap();

                        assert_eq!(
                            memory.insert(
                                F::from(address as u64),
                                (*coordinates.x(), *coordinates.y()),
                            ),
                            None
                        );

                        coordinates
                    })
                    .collect::<Vec<_>>();

                cur_aux
            })
            .collect::<Vec<_>>();

        let mut aux_sum = auxes
            .iter()
            .fold(App::CurveExt::identity(), |acc, next| acc + next);

        for _ in 0..div_ceil!(App::ScalarExt::NUM_BITS as usize, window) {
            correction += aux_sum;
            (0..window).for_each(|_| aux_sum = aux_sum.double());
        }

        let msm_gate = FixMSMGate::configure(
            meta,
            a0,
            a1,
            a2,
            a3,
            a4,
            range_table,
            address_table,
            x_table,
            y_table,
            constant,
            window,
            memory,
            correction.to_affine(),
        );
        Self::Config { msm_gate }
    }
    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!();
    }
    fn synthesize(&self, mut cfg: Self::Config, mut ly: impl Layouter<F>) -> Result<(), Error> {
        macro_rules! v {
            ($e:expr) => {
                Value::known($e)
            };
        }
        let ly = &mut ly;
        let rand_scalar = || App::Scalar::random(OsRng);

        let offset = ly.assign_region(
            || "app",
            |region| {
                cfg.msm_gate.unassign_constants();
                let ctx = &mut RegionCtx::new(region);

                let scalars = (0..self.bases.len())
                    .map(|_| rand_scalar())
                    .collect::<Vec<_>>();
                let bases = self.bases.iter().map(|p| p.to_curve()).collect::<Vec<_>>();
                let res0 = multiexp_naive_var(&bases[..], &scalars[..]).to_affine();
                let res0 = cfg.msm_gate.assign_point(ctx, &v!(res0))?;

                let scalars = scalars
                    .into_iter()
                    .map(|scalar| v!(scalar))
                    .collect::<Vec<_>>();

                let res1 = cfg.msm_gate.msm(ctx, &scalars[..])?;

                cfg.msm_gate.equal(ctx, &res0, &res1)?;
                Ok(ctx.offset())
            },
        )?;
        let number_of_points = self.bases.len();
        println!(
            "fixed mul gate, window {}, # terms: {}, row cost: {}, area cost: {}",
            self.window,
            number_of_points,
            offset / number_of_points,
            5 * offset / number_of_points,
        );
        cfg.msm_gate.layout_range_table(ly)?;
        cfg.msm_gate.layout_point_table(ly)?;
        Ok(())
    }
    fn params(&self) -> Self::Params {
        Params {
            window: self.window,
            bases: self.bases.clone(),
            aux: self.aux,
        }
    }
}

#[test]
fn test_fixed_msm() {
    // let rand_point = || App::CurveExt::random(OsRng);
    use halo2::halo2curves::pasta::{EqAffine, Fq};
    const K: u32 = 21;

    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let n = 10000;
    let bases: Vec<EqAffine> = (0..n).map(|_| Eq::random(&mut rng).to_affine()).collect();

    let aux = Eq::generator().to_affine();

    let window = 6;
    let circuit = MyCircuit::<Fq, EqAffine> { bases, window, aux };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
}
