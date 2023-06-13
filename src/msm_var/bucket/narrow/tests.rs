use super::super::instructions::MSMGate;
use super::config::VarMSMGateNarrow;
use crate::util::multiexp_naive_var;
use crate::RegionCtx;
use ff::Field;
use ff::PrimeField;
use group::Curve;
use group::Group;
use halo2::circuit::floor_planner::V1;
use halo2::dev::MockProver;
use halo2::{
    circuit::{Layouter, Value},
    halo2curves::CurveAffine,
    plonk::Error,
    plonk::{Circuit, ConstraintSystem},
};
use rand_core::OsRng;
use std::marker::PhantomData;

#[derive(Default, Clone, Debug)]
struct Params {
    window: usize,
}

#[derive(Clone, Debug)]
struct TestConfig<F: PrimeField + Ord, App: CurveAffine<Base = F>> {
    msm_gate: VarMSMGateNarrow<F, App>,
}
#[derive(Debug, Default)]
struct MyCircuit<F: PrimeField + Ord, App: CurveAffine<Base = F>> {
    _marker: PhantomData<(F, App)>,
    window: usize,
    number_of_points: usize,
}
impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> Circuit<F> for MyCircuit<F, App> {
    type Config = TestConfig<F, App>;
    type FloorPlanner = V1;
    type Params = Params;

    fn without_witnesses(&self) -> Self {
        Self {
            _marker: PhantomData,
            window: self.window,
            number_of_points: self.number_of_points,
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
        let msm_gate = VarMSMGateNarrow::configure(
            meta,
            a0,
            a1,
            a2,
            a3,
            a4,
            range_table,
            constant,
            window,
            aux,
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
        let rand_point = || App::CurveExt::random(OsRng);
        let number_of_points = self.number_of_points;
        let offset = ly.assign_region(
            || "app",
            |region| {
                cfg.msm_gate.unassign_constants();
                cfg.msm_gate.clear_rw();
                let ctx = &mut RegionCtx::new(region);
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
                let res1 = cfg.msm_gate.msm(ctx, &points[..], &scalars[..])?;
                cfg.msm_gate.equal(ctx, &res0, &res1)?;
                Ok(ctx.offset())
            },
        )?;

        let row_cost = offset / number_of_points;
        let mem_cost = cfg.msm_gate.memory.timestamp() / number_of_points;
        println!(
                "narrow bucket gate, window {}, # terms: {}, msm row cost: {}, mem row cost: {}, area cost: {}",
                self.window,
                self.number_of_points,
                row_cost,
                mem_cost,
                5 * (row_cost+mem_cost),
            );
        cfg.msm_gate.layout_range_table(ly)?;
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
fn test_bucket_narrow_msm_var() {
    use halo2::halo2curves::pasta::{EqAffine, Fq};
    const K: u32 = 21;
    let window = 8;
    let circuit = MyCircuit::<Fq, EqAffine> {
        _marker: PhantomData::<(Fq, EqAffine)>,
        window,
        number_of_points: 10000,
    };
    let public_inputs = vec![vec![]];
    let prover = match MockProver::run(K, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
}
