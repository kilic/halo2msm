use crate::{util::decompose, AssignedPoint, AssignedValue, RegionCtx};
use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    halo2curves::CurveAffine,
    plonk::{Advice, Column, Error, Fixed},
};

pub trait MSMHelper<F: PrimeField + Ord, App: CurveAffine<Base = F>> {
    fn window(&self) -> usize;
    fn reset_buckets(&mut self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error>;
    fn gen_initial_buckets(&mut self) -> Vec<App>;
    fn correction_point(&mut self, ctx: &mut RegionCtx<'_, F>)
        -> Result<AssignedPoint<App>, Error>;
    fn initial_buckets(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<Vec<AssignedPoint<App>>, Error>;
    fn decompose_scalars(&self, scalars: &[Value<App::Scalar>]) -> Vec<Vec<Value<F>>> {
        let number_of_rounds = div_ceil!(F::NUM_BITS as usize, self.window());
        let scalars = scalars
            .iter()
            .map(|scalar| {
                let decomposed = scalar.map(|scalar| {
                    let mut decomposed: Vec<F> = decompose(scalar, number_of_rounds, self.window());
                    decomposed.reverse();
                    decomposed
                });
                decomposed.transpose_vec(number_of_rounds)
            })
            .collect::<Vec<_>>();
        scalars
    }
}
pub trait MSMGate<F: PrimeField + Ord, App: CurveAffine<Base = F>>: MSMHelper<F, App> {
    fn msm(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        points: &[AssignedPoint<App>],
        scalars: &[Value<App::Scalar>],
    ) -> Result<AssignedPoint<App>, Error> {
        let number_of_points = points.len();
        assert!(number_of_points > 0);
        assert_eq!(number_of_points, scalars.len());
        let number_of_buckets = 1 << self.window();
        let number_of_rounds = div_ceil!(F::NUM_BITS as usize, self.window());
        let scalars = self.decompose_scalars(scalars);
        let mut acc = None;
        for round in 0..number_of_rounds {
            if round != 0 {
                for _ in 0..self.window() {
                    acc = Some(self.dbl(ctx, &acc.unwrap())?)
                }
            }
            self.reset_buckets(ctx)?;
            // accumulate buckets
            for (scalar, point) in scalars.iter().zip(points.iter()) {
                self.rw_add(ctx, &scalar[round], point)?;
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
    fn advice_columns(&self) -> Vec<Column<Advice>>;
    fn fixed_colmns(&self) -> Vec<Column<Fixed>>;
    fn get_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        scalar: F,
    ) -> Result<AssignedValue<F>, Error>;
    fn get_constant_point(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        point: &App,
    ) -> Result<AssignedPoint<App>, Error> {
        let coordianates = point.coordinates().unwrap();
        let x = coordianates.x().clone();
        let y = coordianates.y().clone();
        let x = self.get_constant(ctx, x)?;
        let y = self.get_constant(ctx, y)?;
        Ok(AssignedPoint::new(x, y))
    }
    fn assign_point(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        point: &Value<App>,
    ) -> Result<AssignedPoint<App>, Error>;
    fn equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedPoint<App>,
        b: &AssignedPoint<App>,
    ) -> Result<(), Error> {
        ctx.equal(a.x.cell(), b.x.cell())?;
        ctx.equal(a.y.cell(), b.y.cell())
    }
    fn add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedPoint<App>,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error>;
    fn rw_add(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &Value<F>,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error>;
    fn read_add(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &AssignedValue<F>,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error>;
    fn write_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &AssignedValue<F>,
        point: &AssignedPoint<App>,
    ) -> Result<(), Error>;
    fn read_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &AssignedValue<F>,
    ) -> Result<AssignedPoint<App>, Error>;
    fn dbl(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        point: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error>;
    fn assign_scalar(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        scalar: &Value<App::Scalar>,
    ) -> Result<Vec<AssignedValue<F>>, Error>;
    fn all_zero(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        let advice_columns = self.advice_columns();
        for column in advice_columns.into_iter() {
            ctx.empty(|| "zero", column.into())?;
        }
        let fixed_columns = self.fixed_colmns();
        for column in fixed_columns.into_iter() {
            ctx.empty(|| "zero", column.into())?;
        }
        ctx.next();
        Ok(())
    }
    fn layout_sorted_rw(&self, ly: &mut impl Layouter<F>) -> Result<(), Error>;
    fn layout_range_table(&self, ly: &mut impl Layouter<F>) -> Result<(), Error>;
}
