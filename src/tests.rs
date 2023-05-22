use std::marker::PhantomData;

use crate::util::compose;
use crate::{config::MSMGate, RegionCtx};
use ff::Field;
use ff::PrimeField;
use group::Curve;
use group::Group;
use halo2::dev::MockProver;
use halo2::halo2curves::pasta::{EpAffine, EqAffine, Fp, Fq};

use halo2::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::CurveAffine,
    plonk::Error,
    plonk::{Circuit, ConstraintSystem},
};

use halo2::arithmetic::CurveExt;
pub(crate) fn multiexp_naive_var<C: CurveExt>(point: &[C], scalar: &[C::ScalarExt]) -> C
where
    <C::ScalarExt as PrimeField>::Repr: AsRef<[u8]>,
{
    assert!(!point.is_empty());
    assert_eq!(point.len(), scalar.len());
    point
        .iter()
        .zip(scalar.iter())
        .fold(C::identity(), |acc, (point, scalar)| {
            acc + (*point * *scalar)
        })
}

pub(crate) fn modulus<F: PrimeField>() -> BigUint {
    BigUint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

pub(crate) fn from_big<F: PrimeField>(e: BigUint) -> F {
    let modulus = modulus::<F>();
    let e = e % modulus;
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}

fn from_str<C: CurveAffine>(x: &str, y: &str) -> C {
    use num_bigint::BigUint as Big;
    use num_traits::Num;
    let x: C::Base = from_big(Big::from_str_radix(x, 16).unwrap());
    let y: C::Base = from_big(Big::from_str_radix(y, 16).unwrap());
    C::from_xy(x, y).unwrap()
}

use num_bigint::BigUint;
use num_traits::Num;
use rand_core::OsRng;

#[derive(Default, Clone, Debug)]
struct Params {
    window: usize,
}

#[derive(Clone, Debug)]
struct TestConfig<F: PrimeField + Ord, App: CurveAffine<Base = F>> {
    msm_gate: MSMGate<F, App>,
}
#[derive(Debug, Default)]
struct MyCircuit<F: PrimeField + Ord, App: CurveAffine<Base = F>> {
    _marker: PhantomData<(F, App)>,
    window: usize,
}

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> Circuit<F> for MyCircuit<F, App> {
    type Config = TestConfig<F, App>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Params;

    fn without_witnesses(&self) -> Self {
        Self {
            _marker: PhantomData,
            window: self.window,
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
        let window = params.window;
        let aux = App::CurveExt::random(OsRng).to_affine();
        let msm_gate =
            MSMGate::configure(meta, a0, a1, a2, a3, a4, range_table, constant, window, aux);
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
        macro_rules! f {
            // I just want not to see too much cloned expressions around :/ this is a bit less ugly
            ($e:expr) => {
                F::from($e)
            };
        }
        let ly = &mut ly;
        let rand_base = || F::random(OsRng);
        let rand_scalar = || App::Scalar::random(OsRng);
        // let rand_point = || App::CurveExt::random(OsRng).to_affine();
        let rand_point = || App::CurveExt::random(OsRng);
        let rand_affine = || App::CurveExt::random(OsRng).to_affine();

        // cfg.msm_gate.layout_table(ly)?;
        ly.assign_region(
            || "app",
            |region| {
                cfg.msm_gate.unassign_constants();
                cfg.msm_gate.memory.clear_queries();
                let ctx = &mut RegionCtx::new(region);

                let number_of_points = 10000;
                let points: Vec<_> = (0..number_of_points)
                    .map(|_| rand_point())
                    .collect::<Vec<_>>();
                let scalars = (0..number_of_points)
                    .map(|_| rand_scalar())
                    .collect::<Vec<_>>();
                let res0 = multiexp_naive_var(&points[..], &scalars[..]).to_affine();
                let res0 = cfg.msm_gate.assign_point(ctx, &v!(res0))?;
                let points: Vec<_> = points
                    .iter()
                    .map(|point| {
                        let point = v!(point.to_affine());
                        cfg.msm_gate.assign_point(ctx, &point)
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                let scalars = scalars
                    .into_iter()
                    .map(|scalar| v!(scalar))
                    .collect::<Vec<_>>();
                let res1 = cfg
                    .msm_gate
                    .msm_var(ctx, &points[..], &scalars[..], self.window)?;
                let offset = ctx.offset();
                println!("row per term {}", offset / number_of_points);
                cfg.msm_gate.equal(ctx, &res0, &res1)?;
                Ok(())
            },
        )?;
        cfg.msm_gate.layout_sorted_rw(ly)?;
        Ok(())
    }

    fn params(&self) -> Self::Params {
        Params {
            window: self.window,
        }
    }
}

#[test]
fn test_msm_var() {
    const K: u32 = 23;
    let circuit = MyCircuit::<Fq, EqAffine> {
        _marker: PhantomData::<(Fq, EqAffine)>,
        window: 8,
    };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
}
