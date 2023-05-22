use core::num;

use crate::{config::MSMGate, AssignedPoint, RegionCtx};
use ff::PrimeField;
use group::{Curve, Group};
use halo2::{circuit::Value, halo2curves::CurveAffine, plonk::Error};

macro_rules! div_ceil {
    ($a:expr, $b:expr) => {
        (($a - 1) / $b) + 1
    };
}

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> MSMGate<F, App> {
    pub(crate) fn reset_buckets(&mut self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
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
                            // let acc = acc + sum;
                            // let sum = sum + bucket;
                            // (sum, acc)
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
                correction_point
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
    pub fn msm_var(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        points: &[AssignedPoint<App>],
        scalars: &[Value<App::Scalar>],
        window: usize,
    ) -> Result<AssignedPoint<App>, Error> {
        let number_of_points = points.len();
        assert!(number_of_points > 0);
        assert_eq!(number_of_points, scalars.len());
        let number_of_buckets = 1 << window;
        let number_of_rounds = div_ceil!(F::NUM_BITS as usize, window);
        let scalars = scalars
            .iter()
            .map(|scalar| {
                let scalar = self.assign_scalar(ctx, scalar)?;
                Ok(scalar)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut acc = None;

        for j in 0..number_of_rounds {
            if j != 0 {
                for _ in 0..window {
                    acc = Some(self.double(ctx, &acc.unwrap())?)
                }
            }

            self.reset_buckets(ctx)?;

            // accumulate buckets
            for (scalar, point) in scalars.iter().zip(points.iter()) {
                self.rw_add(ctx, &scalar[j], point)?;
            }

            // aggregate buckets
            let last = self.get_constant(ctx, F::from(number_of_buckets - 1))?;
            let mut inner_acc = self.read_point(ctx, &last)?;
            let mut sum = inner_acc.clone();

            for i in (1..number_of_buckets - 1).rev() {
                let address = self.get_constant(ctx, F::from(i))?;
                // sum = B_0 + B_1 + B_2 + ...
                sum = self.read_add(ctx, &address, &sum)?;
                // inner_acc = 0*B_0 + 1*B_1 + 2*B_2 + ...
                inner_acc = self.add(ctx, &sum, &inner_acc)?;
            }
            let address = self.get_constant(ctx, F::ZERO)?;
            let _dummy_read = self.read_point(ctx, &address)?;
            acc = match acc {
                None => Some(inner_acc),
                Some(_) => Some(self.add(ctx, &inner_acc, &acc.unwrap())?),
            };
        }
        let correction_point = self.correction_point(ctx)?;
        Ok(self.add(ctx, &acc.unwrap(), &correction_point)?)
    }
}
