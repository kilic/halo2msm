use crate::{util::decompose, AssignedPoint, AssignedValue, RegionCtx};
use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    halo2curves::CurveAffine,
    plonk::{Advice, Column, Error, Fixed},
};

pub trait MSMHelper<F: PrimeField + Ord, App: CurveAffine<Base = F>> {
    fn window(&self) -> usize;
    fn correction_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        number_of_points: usize,
    ) -> Result<AssignedPoint<App>, Error>;
    fn assign_table(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        points: &[Value<App>],
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
        points: &[Value<App>],
        scalars: &[Value<App::Scalar>],
    ) -> Result<AssignedPoint<App>, Error> {
        let number_of_points = points.len();
        assert!(number_of_points > 0);
        assert_eq!(number_of_points, scalars.len());
        let _ = self.assign_table(ctx, points)?;
        let scalars = self.decompose_scalars(scalars);
        let number_of_rounds = div_ceil!(F::NUM_BITS as usize, self.window());
        let mut acc = None;
        for round in 0..number_of_rounds {
            if round != 0 {
                for _ in 0..self.window() {
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
                offset += 1 << self.window();
            }
        }
        let correction_point = self.correction_point(ctx, number_of_points)?;
        let res = self.add(ctx, &acc.unwrap(), &correction_point)?;
        Ok(res)
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
    fn read_add(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &Value<F>,
        offset: F,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error>;
    fn write_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: F,
        offset: F,
        point: &AssignedPoint<App>,
    ) -> Result<(), Error>;
    fn read_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &Value<F>,
        offset: F,
    ) -> Result<AssignedPoint<App>, Error>;
    fn dbl(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        point: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error>;
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
    fn layout_range_table(&self, ly: &mut impl Layouter<F>) -> Result<(), Error>;
}
