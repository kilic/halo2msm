use super::super::instructions::MSMGate;
use super::config::VarMSMGateWide;
use crate::{coords, util::decompose, AssignedPoint, AssignedValue, RegionCtx};
use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    halo2curves::CurveAffine,
    plonk::{Advice, Column, Error, Fixed},
};

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> MSMGate<F, App> for VarMSMGateWide<F, App> {
    fn advice_columns(&self) -> Vec<Column<Advice>> {
        vec![
            self.a0, self.a1, self.a2, self.a3, self.a4, self.a5, self.a6, self.a7, self.a8,
        ]
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
                ctx.empty(|| "get constant:", self.a4.into())?;
                ctx.empty(|| "get constant:", self.a5.into())?;
                ctx.empty(|| "get constant:", self.a6.into())?;
                ctx.empty(|| "get constant:", self.a7.into())?;
                let constant =
                    ctx.advice(|| "get constant: constant", self.a8, Value::known(scalar))?;
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
        let x = ctx.advice(|| "assign point: x", self.a0, x)?;
        let y = ctx.advice(|| "assign point: y", self.a1, y)?;
        ctx.advice(|| "assign point: x^2", self.a2, x_square)?;
        ctx.advice(|| "assign point: x^3", self.a3, x_cube)?;
        ctx.empty(|| "assign point:", self.a4.into())?;
        ctx.empty(|| "assign point:", self.a5.into())?;
        ctx.empty(|| "assign point:", self.a6.into())?;
        ctx.empty(|| "assign point:", self.a7.into())?;
        ctx.empty(|| "assign point:", self.a8.into())?;
        ctx.empty(|| "assign point:", self.constant.into())?;
        ctx.next();
        Ok(AssignedPoint::new(x, y))
    }
    fn write_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &AssignedValue<F>,
        point: &AssignedPoint<App>,
    ) -> Result<(), Error> {
        let timestamp = self.memory.queries.len();
        let point = point.coords();
        let (x1, y1) = point.unzip();

        let previous_point: Value<(App::Base, App::Base)> =
            self.memory.read::<App>(&address.value().copied());
        self.memory.write(&address.value().copied(), &point);

        let (x0, y0) = previous_point.unzip();

        ctx.enable(self.s_query)?;
        ctx.enable(self.s_range)?;
        ctx.copy(|| "write point: address", self.a0, address)?;
        ctx.advice(|| "write point: x0", self.a1, x0)?;
        ctx.advice(|| "write point: y0", self.a2, y0)?;
        ctx.advice(|| "write point: x1", self.a3, x1)?;
        ctx.advice(|| "write point: y1", self.a4, y1)?;
        ctx.empty(|| "write point:", self.a5.into())?;
        ctx.empty(|| "write point:", self.a6.into())?;
        ctx.empty(|| "write point:", self.a7.into())?;
        ctx.empty(|| "write point:", self.a8.into())?;
        ctx.fixed(
            || "write point: timestamp",
            self.constant,
            F::from(timestamp as u64),
        )?;

        ctx.next();
        Ok(())
    }
    fn read_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &AssignedValue<F>,
    ) -> Result<AssignedPoint<App>, Error> {
        let timestamp = self.memory.queries.len();

        let point: Value<(App::Base, App::Base)> =
            self.memory.read::<App>(&address.value().copied());
        self.memory.dummy_write(&address.value().copied());

        let (x, y) = point.unzip();

        ctx.enable(self.s_query)?;
        ctx.copy(|| "read point: address", self.a0, address)?;
        let x = ctx.advice(|| "read point: x", self.a1, x)?;
        let y = ctx.advice(|| "read point: y", self.a2, y)?;
        ctx.empty(|| "read point: finalize with zero", self.a3.into())?;
        ctx.empty(|| "read point: finalize with zero", self.a4.into())?;
        ctx.empty(|| "read point:", self.a5.into())?;
        ctx.empty(|| "read point:", self.a6.into())?;
        ctx.empty(|| "read point:", self.a7.into())?;
        ctx.empty(|| "read point:", self.a8.into())?;
        ctx.fixed(
            || "read point: timestamp",
            self.constant,
            F::from(timestamp as u64),
        )?;
        ctx.next();
        Ok(AssignedPoint::new(x, y))
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
        ctx.empty(|| "add:", self.a0.into())?;
        ctx.copy(|| "add: a_x", self.a1, &a.x)?;
        ctx.copy(|| "add: a_y", self.a2, &a.y)?;
        let out_x = ctx.advice(|| "add: out_x", self.a3, out_x)?;
        let out_y = ctx.advice(|| "add: out_y", self.a4, out_y)?;
        ctx.copy(|| "add: b_x", self.a5, &b.x)?;
        ctx.copy(|| "add: b_y", self.a6, &b.y)?;
        ctx.advice(|| "add: t", self.a7, t)?;
        ctx.advice(|| "add: inverse_t", self.a8, inverse_t)?;
        ctx.empty(|| "add: constant", self.constant.into())?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    fn rw_add(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &Value<F>,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        let timestamp = self.memory.timestamp();
        ctx.enable(self.s_add)?;
        ctx.enable(self.s_query)?;
        let address = ctx.advice(|| "rwadd: address", self.a0, *address)?;

        let a_coords: Value<(App::Base, App::Base)> =
            self.memory.read::<App>(&address.value().copied());
        let a = a_coords.map(|(x, y)| App::from_xy(x, y).unwrap());
        let out = b + &a;
        let (out_x, out_y) = coords(out).unzip();
        self.memory
            .write(&address.value().copied(), &out_x.zip(out_y));

        let (a_x, a_y) = coords(a).unzip();
        let t = b.x.value().map(|v| *v) - a_x;
        let t = t * t;

        let inverse_t = t.map(|t| t.invert().unwrap());
        ctx.advice(|| "rwadd: a_x", self.a1, a_x)?;
        ctx.advice(|| "rwadd: a_y", self.a2, a_y)?;
        let out_x = ctx.advice(|| "rwadd: out_x", self.a3, out_x)?;
        let out_y = ctx.advice(|| "rwadd: out_y", self.a4, out_y)?;
        ctx.copy(|| "rwadd: b_x", self.a5, &b.x)?;
        ctx.copy(|| "rwadd: b_y", self.a6, &b.y)?;
        ctx.advice(|| "rwadd: t", self.a7, t)?;
        ctx.advice(|| "rwadd: inverse_t", self.a8, inverse_t)?;
        ctx.empty(|| "rwadd: constant", self.constant.into())?;
        ctx.fixed(
            || "rwadd: timestamp",
            self.constant,
            F::from(timestamp as u64),
        )?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    fn read_add(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &AssignedValue<F>,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        let timestamp = self.memory.timestamp();
        ctx.enable(self.s_add)?;
        ctx.enable(self.s_query)?;
        let address = ctx.copy(|| "read add: address", self.a0, address)?;

        let a_coords: Value<(App::Base, App::Base)> =
            self.memory.read::<App>(&address.value().copied());
        let a = a_coords.map(|(x, y)| App::from_xy(x, y).unwrap());
        let out = b + &a;
        let (out_x, out_y) = coords(out).unzip();
        self.memory
            .write(&address.value().copied(), &out_x.zip(out_y));

        let (a_x, a_y) = coords(a).unzip();
        let t = b.x.value().map(|v| *v) - a_x;
        let t = t * t;
        let inverse_t = t.map(|t| t.invert().unwrap());
        ctx.advice(|| "read add: a_x", self.a1, a_x)?;
        ctx.advice(|| "read add: a_y", self.a2, a_y)?;
        let out_x = ctx.advice(|| "read add: out_x", self.a3, out_x)?;
        let out_y = ctx.advice(|| "read add: out_y", self.a4, out_y)?;
        ctx.copy(|| "read add: b_x", self.a5, &b.x)?;
        ctx.copy(|| "read add: b_y", self.a6, &b.y)?;
        ctx.advice(|| "read add: t", self.a7, t)?;
        ctx.advice(|| "read add: inverse_t", self.a8, inverse_t)?;
        ctx.empty(|| "read add:", self.constant.into())?;
        ctx.fixed(
            || "read add: timestamp",
            self.constant,
            F::from(timestamp as u64),
        )?;
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
        ctx.advice(|| "double: y^2", self.a4, y_square)?;
        let out_x = ctx.advice(|| "double: out_x", self.a5, out_x)?;
        let out_y = ctx.advice(|| "double: out_y", self.a6, out_y)?;
        ctx.empty(|| "double:", self.a7.into())?;
        ctx.empty(|| "double:", self.a8.into())?;
        ctx.empty(|| "double:", self.constant.into())?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    fn assign_scalar(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        scalar: &Value<App::Scalar>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        const NUMBER_OF_COLUMNS: usize = 5;
        let window = self.window;
        let number_of_bits = F::NUM_BITS as usize;
        let number_of_limbs = div_ceil!(number_of_bits, window);
        let decomposed = scalar.map(|scalar| {
            let decomposed: Vec<F> = decompose(scalar, number_of_limbs, window);
            decomposed
        });
        let decomposed = decomposed.transpose_vec(number_of_limbs);
        let columns = vec![self.a0, self.a1, self.a2, self.a3, self.a4];
        let zero = self.get_constant(ctx, F::ZERO)?;
        let mut assigned = vec![];
        for (_, chunk) in decomposed.chunks(NUMBER_OF_COLUMNS).enumerate() {
            for (v, c) in chunk.iter().zip(columns.iter()) {
                let limb = ctx.advice(|| "window: assign limb", *c, *v)?;
                assigned.push(limb);
            }
            for i in chunk.len()..NUMBER_OF_COLUMNS {
                ctx.copy(|| "window: copy zero to unused cells", columns[i], &zero)?;
            }
            ctx.fixed(|| "window: constant", self.constant, F::ZERO)?;
            ctx.next();
        }
        assigned.reverse();
        Ok(assigned)
    }
    fn layout_sorted_rw(&self, ly: &mut impl Layouter<F>) -> Result<(), Error> {
        let sorted_queries = self.memory.sort();
        let number_of_queries = self.memory.queries.len();
        ly.assign_region(
            || "sorted rw",
            |region| {
                let ctx = &mut RegionCtx::new(region);
                self.all_zero(ctx)?;
                for i in 0..number_of_queries {
                    ctx.enable(self.s_sorted)?;
                    let address = sorted_queries.as_ref().map(|queries| queries[i].address);
                    let timestamp = sorted_queries.as_ref().map(|queries| queries[i].timestamp);
                    let x0 = sorted_queries.as_ref().map(|queries| queries[i].x0);
                    let y0 = sorted_queries.as_ref().map(|queries| queries[i].y0);
                    let x1 = sorted_queries.as_ref().map(|queries| queries[i].x1);
                    let y1 = sorted_queries.as_ref().map(|queries| queries[i].y1);
                    ctx.advice(|| "sorted rw: address", self.a0, address)?;
                    ctx.advice(|| "sorted rw: x read", self.a1, x0)?;
                    ctx.advice(|| "sorted rw: y read", self.a2, y0)?;
                    ctx.advice(|| "sorted rw: x write", self.a3, x1)?;
                    ctx.advice(|| "sorted rw: y write", self.a4, y1)?;
                    ctx.advice(|| "sorted rw: timestamp", self.a5, timestamp)?;
                    ctx.empty(|| "sorted rw:", self.a6.into())?;
                    ctx.empty(|| "sorted rw:", self.a7.into())?;
                    ctx.empty(|| "sorted rw:", self.a8.into())?;
                    ctx.empty(|| "sorted rw:", self.constant.into())?;
                    ctx.next();
                }
                Ok(())
            },
        )
    }
    fn layout_range_table(&self, ly: &mut impl Layouter<F>) -> Result<(), Error> {
        let max_limb = 1 << self.window;
        ly.assign_table(
            || "range table",
            |mut table| {
                for i in 0..max_limb {
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
