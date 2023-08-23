use super::config::FixMSMGate;
use crate::{util::decompose, AssignedPoint, AssignedValue, RegionCtx};
use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    halo2curves::CurveAffine,
    plonk::{Advice, Column, Error, Fixed},
};

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> FixMSMGate<F, App> {
    pub fn get_constant_point(
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

    pub fn correction_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        _number_of_points: usize,
    ) -> Result<AssignedPoint<App>, Error> {
        self.get_constant_point(ctx, &(-self.correction))
    }

    pub fn decompose_scalars(&self, scalars: &[Value<App::Scalar>]) -> Vec<Vec<Value<F>>> {
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

    pub fn msm(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        scalars: &[Value<App::Scalar>],
    ) -> Result<AssignedPoint<App>, Error> {
        let number_of_points = scalars.len();
        assert_eq!(self.memory.len(), scalars.len() * (1 << self.window));

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
            for (point_idx, scalar) in scalars.iter().enumerate() {
                acc = match &acc {
                    Some(acc) => Some(self.read_add(ctx, point_idx, &scalar[round], &acc)?),
                    None => {
                        assert!(offset == 0 && round == 0);
                        Some(self.read_point(ctx, point_idx, &scalar[round])?)
                    }
                };
                offset += 1 << self.window;
            }
        }

        let correction_point = self.correction_point(ctx, number_of_points)?;

        let res = self.add(ctx, &acc.unwrap(), &correction_point)?;

        Ok(res)
    }
    pub fn advice_columns(&self) -> Vec<Column<Advice>> {
        vec![self.a0, self.a1, self.a2, self.a3, self.a4]
    }
    pub fn fixed_colmns(&self) -> Vec<Column<Fixed>> {
        vec![self.constant]
    }
    pub fn get_constant(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        scalar: F,
    ) -> Result<AssignedValue<F>, Error> {
        match self.constants.get(&scalar) {
            Some(constant) => Ok(constant.clone()),
            _ => {
                ctx.enable(self.s_assign_constant)?;
                ctx.fixed(|| "get constant: fix", self.constant, scalar)?;
                ctx.empty(|| "get constant:", self.a0.into())?;
                ctx.empty(|| "get constant:", self.a1.into())?;
                ctx.empty(|| "get constant:", self.a2.into())?;
                ctx.empty(|| "get constant:", self.a3.into())?;
                let constant =
                    ctx.advice(|| "get constant: constant", self.a4, Value::known(scalar))?;
                ctx.next();
                Ok(constant)
            }
        }
    }
    pub fn assign_point(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        point: &Value<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        let (x, y) = point
            .map(|c| {
                let coordinates = c.coordinates().unwrap();
                (coordinates.x().clone(), coordinates.y().clone())
            })
            .unzip();
        let x_square = x * x;
        let x_cube = x * x * x;
        ctx.enable(self.s_point)?;
        let x = ctx.advice(|| "assign x", self.a0, x)?;
        let y = ctx.advice(|| "assign y", self.a1, y)?;
        ctx.advice(|| "assign x^2", self.a2, x_square)?;
        ctx.advice(|| "assign x^3", self.a3, x_cube)?;
        ctx.empty(|| "assign point: constant", self.constant.into())?;
        ctx.next();
        Ok(AssignedPoint::new(x, y))
    }
    pub fn read_point_in_place(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        point_idx: usize,
        address: &Value<F>,
    ) -> Result<AssignedPoint<App>, Error> {
        ctx.enable(self.s_query)?;
        ctx.enable(self.s_range)?;
        let address_base = F::from(((1 << self.window) * point_idx) as u64);

        let (x, y) = address
            .map(|address| self.memory.get(&(address_base + address)).cloned().unwrap())
            .unzip();

        let _address = ctx.advice(|| "read in place: offset", self.a0, *address)?;
        ctx.fixed(
            || "read in place: base",
            self.constant,
            address_base + F::ONE,
        )?;

        let x = ctx.advice(|| "read in place: a_x", self.a1, x)?;
        let y = ctx.advice(|| "read in place: a_y", self.a2, y)?;

        Ok(AssignedPoint::new(x, y))
    }
    fn read_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        point_idx: usize,
        address: &Value<F>,
    ) -> Result<AssignedPoint<App>, Error> {
        let point = self.read_point_in_place(ctx, point_idx, address)?;
        ctx.empty(|| "read add: b_x", self.a3.into())?;
        ctx.empty(|| "read add: b_y", self.a4.into())?;
        ctx.next();
        Ok(point)
    }
    pub fn read_add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        point_idx: usize,
        address: &Value<F>,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        ctx.enable(self.s_add)?;
        let a = self.read_point_in_place(ctx, point_idx, address)?;

        let t = a.x.value().zip(b.x.value()).map(|(a_x, b_x)| *b_x - *a_x);
        let t = t * t;
        let inverse_t = t.map(|t| t.invert().unwrap());
        let (out_x, out_y) = a + b;

        ctx.copy(|| "add: b_x", self.a3, &b.x)?;
        ctx.copy(|| "add: b_y", self.a4, &b.y)?;

        ctx.next();

        ctx.empty(|| "add:", self.a0.into())?;
        let out_x = ctx.advice(|| "add: out_x", self.a1, out_x)?;
        let out_y = ctx.advice(|| "add: out_y", self.a2, out_y)?;
        ctx.advice(|| "add: t", self.a3, t)?;
        ctx.advice(|| "add: inverse_t", self.a4, inverse_t)?;
        ctx.empty(|| "add: constant", self.constant.into())?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    pub fn add(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedPoint<App>,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        ctx.enable(self.s_add)?;
        let t = a.x.value().zip(b.x.value()).map(|(a_x, b_x)| *b_x - *a_x);
        let t = t * t;
        let inverse_t = t.map(|t| t.invert().unwrap());
        let (out_x, out_y) = a + b;
        ctx.enable(self.s_add)?;
        ctx.copy(|| "add: a_x", self.a1, &a.x)?;
        ctx.copy(|| "add: a_y", self.a2, &a.y)?;
        ctx.copy(|| "add: b_x", self.a3, &b.x)?;
        ctx.copy(|| "add: b_y", self.a4, &b.y)?;
        ctx.empty(|| "add: constant", self.constant.into())?;
        ctx.next();
        ctx.empty(|| "add:", self.a0.into())?;
        let out_x = ctx.advice(|| "add: out_x", self.a1, out_x)?;
        let out_y = ctx.advice(|| "add: out_y", self.a2, out_y)?;
        ctx.advice(|| "add: t", self.a3, t)?;
        ctx.advice(|| "add: inverse_t", self.a4, inverse_t)?;
        ctx.empty(|| "add: constant", self.constant.into())?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    pub fn dbl(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        point: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        let (x, y) = point.coords().unzip();
        let x_square = x * x;
        let x_square_square = x_square * x_square;
        let y_square = y * y;
        let (out_x, out_y) = point.dbl();
        ctx.enable(self.s_double)?;
        ctx.copy(|| "double: x", self.a0, &point.x)?;
        ctx.copy(|| "double: y", self.a1, &point.y)?;
        ctx.advice(|| "double: x^2", self.a2, x_square)?;
        ctx.advice(|| "double: x^4", self.a3, x_square_square)?;
        ctx.empty(|| "double:", self.a4.into())?;
        ctx.empty(|| "double: constant", self.constant.into())?;
        ctx.next();
        ctx.empty(|| "double:", self.a0.into())?;
        ctx.advice(|| "double: t", self.a1, y_square)?;
        let out_x = ctx.advice(|| "double: out_x", self.a2, out_x)?;
        let out_y = ctx.advice(|| "double: out_y", self.a3, out_y)?;
        ctx.empty(|| "double:", self.a4.into())?;
        ctx.empty(|| "double: constant", self.constant.into())?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    pub fn equal(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        a: &AssignedPoint<App>,
        b: &AssignedPoint<App>,
    ) -> Result<(), Error> {
        ctx.equal(a.x.cell(), b.x.cell())?;
        ctx.equal(a.y.cell(), b.y.cell())
    }
    pub fn layout_range_table(&self, ly: &mut impl Layouter<F>) -> Result<(), Error> {
        ly.assign_table(
            || "range table",
            |mut table| {
                for i in 0..1 << self.window {
                    let value = F::from(i);
                    table.assign_cell(
                        || "value in range",
                        self.range_table,
                        i as usize,
                        || Value::known(value),
                    )?;
                }

                Ok(())
            },
        )?;
        Ok(())
    }
    pub fn layout_point_table(&self, ly: &mut impl Layouter<F>) -> Result<(), Error> {
        ly.assign_table(
            || "window table",
            |mut meta| {
                meta.assign_cell(|| "x coordinate", self.x_table, 0, || Value::known(F::ZERO))?;
                meta.assign_cell(|| "y coordinate", self.y_table, 0, || Value::known(F::ZERO))?;

                meta.assign_cell(
                    || "address",
                    self.address_table,
                    0,
                    || Value::known(F::from((0) as u64)),
                )?;

                for (address, (_address, (x, y))) in self.memory.iter().enumerate() {
                    assert_eq!(F::from(address as u64), *_address);

                    meta.assign_cell(
                        || "x coordinate",
                        self.x_table,
                        address + 1,
                        || Value::known(x),
                    )?;

                    meta.assign_cell(
                        || "y coordinate",
                        self.y_table,
                        address + 1,
                        || Value::known(y),
                    )?;

                    meta.assign_cell(
                        || "address",
                        self.address_table,
                        address + 1,
                        || Value::known(F::from((address + 1) as u64)),
                    )?;
                }

                Ok(())
            },
        )?;
        Ok(())
    }
}
