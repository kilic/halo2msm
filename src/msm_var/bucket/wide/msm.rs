use super::super::instructions::MSMGate;
use super::config::VarMSMGateWide;
use crate::{msm_var::bucket::instructions::MSMHelper, util::decompose, AssignedPoint, RegionCtx};
use ff::PrimeField;
use group::{Curve, Group};
use halo2::{circuit::Value, halo2curves::CurveAffine, plonk::Error};

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> MSMHelper<F, App> for VarMSMGateWide<F, App> {
    fn window(&self) -> usize {
        self.window
    }
    fn reset_buckets(&mut self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        let buckets = self.initial_buckets(ctx)?;
        for (address, bucket) in buckets.iter().enumerate() {
            let address = F::from(address as u64);
            let address = self.get_constant(ctx, address)?;
            self.write_point(ctx, &address, &bucket)?;
        }
        Ok(())
    }
    fn gen_initial_buckets(&mut self) -> Vec<App> {
        match &self.initial_buckets {
            Some(buckets) => buckets.clone(),
            None => {
                let size = 1 << self.window;
                let mut acc: App::CurveExt = self.aux_generator.into();
                let initial_buckets = (0..size)
                    .map(|_| {
                        let ret = acc;
                        acc = acc.double();
                        ret.to_affine()
                    })
                    .collect::<Vec<_>>();
                self.initial_buckets = Some(initial_buckets.clone());
                initial_buckets
            }
        }
    }
    fn correction_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<AssignedPoint<App>, Error> {
        let point = match &self.correction_point {
            Some(point) => *point,
            None => {
                let initial_buckets = self.initial_buckets.clone().unwrap();
                let number_of_rounds = div_ceil!(App::Scalar::NUM_BITS as usize, self.window);
                let bucket_sum = initial_buckets
                    .iter()
                    .skip(1)
                    .rev()
                    .fold(
                        (App::Curve::identity(), App::Curve::identity()),
                        |(sum, acc), bucket| {
                            let sum = sum + bucket;
                            (sum, acc + sum)
                        },
                    )
                    .1;
                let correction_point = (0..number_of_rounds)
                    .fold(App::CurveExt::identity(), |acc, _| {
                        let acc = (0..self.window).fold(acc, |acc, _| acc.double());
                        acc + bucket_sum
                    })
                    .to_affine();
                self.correction_point = Some(correction_point.neg());
                correction_point.neg()
            }
        };
        self.get_constant_point(ctx, &point)
    }
    fn initial_buckets(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<Vec<AssignedPoint<App>>, Error> {
        let buckets: Vec<App> = self.gen_initial_buckets();
        buckets
            .iter()
            .map(|point| self.get_constant_point(ctx, point))
            .collect::<Result<Vec<_>, _>>()
    }
    fn decompose_scalars(&self, scalars: &[Value<App::Scalar>]) -> Vec<Vec<Value<F>>> {
        let number_of_rounds = div_ceil!(F::NUM_BITS as usize, self.window);
        let scalars = scalars
            .iter()
            .map(|scalar| {
                let decomposed = scalar.map(|scalar| {
                    let mut decomposed: Vec<F> = decompose(scalar, number_of_rounds, self.window);
                    decomposed.reverse();
                    decomposed
                });
                decomposed.transpose_vec(number_of_rounds)
            })
            .collect::<Vec<_>>();
        scalars
    }
}
