use super::config::VarMSMGateNarrow;
use crate::{
    coords, msm_var::sliding::instructions::MSMGate, AssignedPoint, AssignedValue, RegionCtx,
};
use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    halo2curves::CurveAffine,
    plonk::{Advice, Column, Error, Fixed},
};

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> MSMGate<F, App> for VarMSMGateNarrow<F, App> {
    fn advice_columns(&self) -> Vec<Column<Advice>> {
        vec![self.a0, self.a1, self.a2, self.a3, self.a4]
    }
    fn fixed_colmns(&self) -> Vec<Column<Fixed>> {
        vec![self.constant]
    }
    fn get_constant(
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
    fn assign_point(
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
    fn read_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &Value<F>,
        offset: F,
    ) -> Result<AssignedPoint<App>, Error> {
        ctx.enable(self.s_query)?;
        let address = ctx.advice(|| "read add: address", self.a0, *address)?;
        ctx.enable(self.s_range)?;
        let a: Value<App> = self.memory.read(&address.value().copied(), offset);
        let (a_x, a_y) = coords(a).unzip();
        let x = ctx.advice(|| "read add: a_x", self.a1, a_x)?;
        let y = ctx.advice(|| "read add: a_y", self.a2, a_y)?;
        ctx.empty(|| "read add: b_x", self.a3.into())?;
        ctx.empty(|| "read add: b_y", self.a4.into())?;
        ctx.fixed(|| "read add: offset", self.constant, offset)?;
        ctx.next();
        Ok(AssignedPoint::new(x, y))
    }
    fn write_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: F,
        offset: F,
        point: &AssignedPoint<App>,
    ) -> Result<(), Error> {
        let coords = point.coords();
        self.memory.write(address, offset, &coords);
        let (x, y) = coords.unzip();
        ctx.fixed(|| "write point: address", self.constant, address + offset)?;
        ctx.enable(self.s_table)?;
        ctx.empty(|| "write point:", self.a0.into())?;
        ctx.advice(|| "write point: x", self.a1, x)?;
        ctx.advice(|| "write point: y", self.a2, y)?;
        ctx.empty(|| "write point:", self.a3.into())?;
        ctx.empty(|| "write point:", self.a4.into())?;
        ctx.next();
        Ok(())
    }
    fn add(
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
    fn read_add(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &Value<F>,
        offset: F,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        ctx.enable(self.s_add)?;
        ctx.enable(self.s_query)?;
        ctx.enable(self.s_range)?;
        let address = ctx.advice(|| "read add: address", self.a0, *address)?;
        let a: Value<App> = self.memory.read(&address.value().copied(), offset);
        let out = b + &a;
        let (a_x, a_y) = coords(a).unzip();
        let (out_x, out_y) = coords(out).unzip();
        let t = b.x.value().map(|v| *v) - a_x;
        let t = t * t;
        let inverse_t = t.map(|t| t.invert().unwrap());
        ctx.advice(|| "read add: a_x", self.a1, a_x)?;
        ctx.advice(|| "read add: a_y", self.a2, a_y)?;
        ctx.copy(|| "read add: b_x", self.a3, &b.x)?;
        ctx.copy(|| "read add: b_y", self.a4, &b.y)?;
        ctx.fixed(|| "read add: offset", self.constant, offset)?;
        ctx.next();
        ctx.empty(|| "read add:", self.a0.into())?;
        let out_x = ctx.advice(|| "read add: out_x", self.a1, out_x)?;
        let out_y = ctx.advice(|| "read add: out_y", self.a2, out_y)?;
        ctx.advice(|| "read add: t", self.a3, t)?;
        ctx.advice(|| "read add: inverse_t", self.a4, inverse_t)?;
        ctx.empty(|| "read add: constant", self.constant.into())?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    fn dbl(
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
    fn all_zero(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        ctx.empty(|| "all zero", self.a0.into())?;
        ctx.empty(|| "all zero", self.a1.into())?;
        ctx.empty(|| "all zero", self.a2.into())?;
        ctx.empty(|| "all zero", self.a3.into())?;
        ctx.empty(|| "all zero", self.a3.into())?;
        ctx.empty(|| "all zero", self.constant.into())?;
        ctx.next();
        Ok(())
    }
    fn layout_range_table(&self, ly: &mut impl Layouter<F>) -> Result<(), Error> {
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
}
