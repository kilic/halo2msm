use super::config::MSMGate;
use crate::{
    util::{big_to_fe, decompose},
    AssignedPoint, RegionCtx,
};
use ff::PrimeField;
use group::{Curve, Group};
use halo2::{circuit::Value, halo2curves::CurveAffine, plonk::Error};
use num_bigint::BigUint;
use num_traits::One;

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> MSMGate<F, App> {
    fn correction_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        number_of_points: usize,
    ) -> Result<AssignedPoint<App>, Error> {
        let correction_point = match &self.correction_point {
            Some(point) => *point,
            None => {
                assert!(self.window > 0);
                assert!(number_of_points > 0);
                let n = App::Scalar::NUM_BITS as usize;
                let mut number_of_selectors = n / self.window;
                if n % self.window != 0 {
                    number_of_selectors += 1;
                }
                let mut k0 = BigUint::one();
                let one = BigUint::one();
                for i in 0..number_of_selectors {
                    k0 |= &one << (i * self.window);
                }
                let k1 = (one << number_of_points) - 1usize;
                let k = k0 * k1;
                let correction_point =
                    (-self.aux_generator * big_to_fe::<App::Scalar>(k)).to_affine();
                self.correction_point = Some(correction_point);
                correction_point
            }
        };
        self.get_constant_point(ctx, &correction_point)
    }
    fn assign_table(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        points: &[Value<App>],
    ) -> Result<Vec<AssignedPoint<App>>, Error> {
        let table_size = 1 << self.window;
        let mut running_aux = self.aux_generator.clone();
        let points = points
            .iter()
            .map(|point| self.assign_point(ctx, point))
            .collect::<Result<Vec<_>, Error>>()?;
        for (i, point) in points.iter().enumerate() {
            let mut acc: AssignedPoint<App> = self.get_constant_point(ctx, &running_aux)?;
            for j in 0..table_size {
                let offset = i * table_size;
                let address = F::from(j as u64);
                let offset = F::from(offset as u64);
                self.write_point(ctx, address, offset, &acc)?;
                if j != table_size - 1 {
                    acc = self.add(ctx, &acc, point)?;
                }
            }
            running_aux = running_aux.to_curve().double().to_affine();
        }
        Ok(points)
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
    pub fn msm_var(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        points: &[Value<App>],
        scalars: &[Value<App::Scalar>],
    ) -> Result<AssignedPoint<App>, Error> {
        let number_of_points = points.len();
        assert!(number_of_points > 0);
        assert_eq!(number_of_points, scalars.len());
        let _ = self.assign_table(ctx, points)?;
        let scalars = self.decompose_scalars(scalars);
        let number_of_rounds = div_ceil!(F::NUM_BITS as usize, self.window);
        let mut acc = None;
        for round in 0..number_of_rounds {
            if round != 0 {
                for _ in 0..self.window {
                    acc = Some(self.dbl(ctx, &acc.unwrap())?)
                }
            }
            let mut offset = 0;
            for scalar in scalars.iter() {
                acc = match &acc {
                    Some(acc) => {
                        Some(self.read_add(ctx, &scalar[round], F::from(offset as u64), &acc)?)
                    }
                    None => {
                        assert!(offset == 0 && round == 0);
                        Some(self.read_point(ctx, &scalar[round], F::from(offset as u64))?)
                    }
                };
                offset += 1 << self.window;
            }
        }
        let correction_point = self.correction_point(ctx, number_of_points)?;
        let res = self.add(ctx, &acc.unwrap(), &correction_point)?;
        Ok(res)
    }
}
