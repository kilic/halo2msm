use super::config::VarMSMGateWide;
use crate::{
    msm_var::sliding::instructions::{MSMGate, MSMHelper},
    util::big_to_fe,
    AssignedPoint, RegionCtx,
};
use ff::PrimeField;
use group::{Curve, Group};
use halo2::{circuit::Value, halo2curves::CurveAffine, plonk::Error};
use num_bigint::BigUint;
use num_traits::One;

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> MSMHelper<F, App> for VarMSMGateWide<F, App> {
    fn window(&self) -> usize {
        self.window
    }
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
}
