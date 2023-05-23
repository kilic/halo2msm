use crate::{coords, util::decompose, AssignedPoint, AssignedValue, RegionCtx};
use ff::PrimeField;
use halo2::{
    circuit::{Layouter, Value},
    halo2curves::CurveAffine,
    plonk::Error,
};

use super::config::MSMGate;

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> MSMGate<F, App> {
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
                ctx.empty(|| "get constant: empty", self.a0)?;
                ctx.empty(|| "get constant: empty", self.a1)?;
                ctx.empty(|| "get constant: empty", self.a2)?;
                ctx.empty(|| "get constant: empty", self.a3)?;
                let constant =
                    ctx.advice(|| "get constant: constant", self.a4, Value::known(scalar))?;
                ctx.next();
                Ok(constant)
            }
        }
    }
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
        ctx.fixed(|| "assign point: constant", self.constant, F::ZERO)?;
        ctx.next();
        Ok(AssignedPoint::new(x, y))
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
        ctx.fixed(|| "add: constant", self.constant, F::ZERO)?;
        ctx.next();
        ctx.empty(|| "add: empty", self.a0)?;
        let out_x = ctx.advice(|| "add: out_x", self.a1, out_x)?;
        let out_y = ctx.advice(|| "add: out_y", self.a2, out_y)?;
        ctx.advice(|| "add: t", self.a3, t)?;
        ctx.advice(|| "add: inverse_t", self.a4, inverse_t)?;
        ctx.fixed(|| "add: constant", self.constant, F::ZERO)?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    pub fn rw_add(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &Value<F>,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        let timestamp = self.memory.timestamp();
        ctx.enable(self.s_add)?;
        ctx.enable(self.s_query)?;
        ctx.enable(self.s_query_read)?;
        let address = ctx.advice(|| "rwadd: address", self.a0, *address)?;
        let a: Value<App> = self.memory.read(&address.value().map(|v| *v));
        let out = b + &a;
        let (a_x, a_y) = coords(a).unzip();
        let (out_x, out_y) = coords(out).unzip();
        let t = b.x.value().map(|v| *v) - a_x;
        let t = t * t;
        let inverse_t = t.map(|t| t.invert().unwrap());
        ctx.advice(|| "rwadd: a_x", self.a1, a_x)?;
        ctx.advice(|| "rwadd: a_y", self.a2, a_y)?;
        ctx.copy(|| "rwadd: b_x", self.a3, &b.x)?;
        ctx.copy(|| "rwadd: b_y", self.a4, &b.y)?;
        ctx.fixed(
            || "rwadd: timestamp",
            self.constant,
            F::from(timestamp as u64),
        )?;
        ctx.next();
        self.memory
            .write(&address.value().map(|v| *v), &out_x.zip(out_y));
        ctx.enable(self.s_query)?;
        ctx.copy(|| "rwadd: address", self.a0, &address)?;
        let out_x = ctx.advice(|| "rwadd: out_x", self.a1, out_x)?;
        let out_y = ctx.advice(|| "rwadd: out_y", self.a2, out_y)?;
        ctx.advice(|| "rwadd: t", self.a3, t)?;
        ctx.advice(|| "rwadd: inverse_t", self.a4, inverse_t)?;
        ctx.fixed(
            || "rwadd: timestamp",
            self.constant,
            F::from(timestamp as u64 + 1),
        )?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    pub fn read_add(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &AssignedValue<F>,
        b: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        let timestamp = self.memory.queries.len();
        let a: Value<App> = self.memory.read(&address.value().map(|v| *v));
        let out = b + &a;
        let (a_x, a_y) = coords(a).unzip();
        let (out_x, out_y) = coords(out).unzip();
        let t = b.x.value().map(|v| *v) - a_x;
        let t = t * t;
        let inverse_t = t.map(|t| t.invert().unwrap());
        ctx.enable(self.s_add)?;
        ctx.enable(self.s_query)?;
        ctx.enable(self.s_query_read)?;
        ctx.copy(|| "read add: address", self.a0, address)?;
        ctx.advice(|| "read add: a_x", self.a1, a_x)?;
        ctx.advice(|| "read add: a_y", self.a2, a_y)?;
        ctx.copy(|| "read add: b_x", self.a3, &b.x)?;
        ctx.copy(|| "read add: b_y", self.a4, &b.y)?;
        ctx.fixed(
            || "read add: timestamp",
            self.constant,
            F::from(timestamp as u64),
        )?;
        ctx.next();
        ctx.empty(|| "read add: empty", self.a0)?;
        let out_x = ctx.advice(|| "read add: out_x", self.a1, out_x)?;
        let out_y = ctx.advice(|| "read add: out_y", self.a2, out_y)?;
        ctx.advice(|| "read add: t", self.a3, t)?;
        ctx.advice(|| "read add: inverse_t", self.a4, inverse_t)?;
        ctx.fixed(|| "read add: constant", self.constant, F::ZERO)?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    pub fn write_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &AssignedValue<F>,
        point: &AssignedPoint<App>,
    ) -> Result<(), Error> {
        let timestamp = self.memory.queries.len();
        let coords = point.coords();
        self.memory.write(&address.value().map(|v| *v), &coords);
        let (x, y) = coords.unzip();
        ctx.enable(self.s_query)?;
        ctx.enable(self.s_range)?;
        ctx.copy(|| "write point: address", self.a0, address)?;
        ctx.advice(|| "write point: x", self.a1, x)?;
        ctx.advice(|| "write point: y", self.a2, y)?;
        ctx.empty(|| "write point: empty", self.a3)?;
        ctx.empty(|| "write point: empty", self.a4)?;
        ctx.fixed(
            || "write point: timestamp",
            self.constant,
            F::from(timestamp as u64),
        )?;
        ctx.next();
        Ok(())
    }
    pub fn read_point(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
        address: &AssignedValue<F>,
    ) -> Result<AssignedPoint<App>, Error> {
        let timestamp = self.memory.queries.len();
        let point: Value<App> = self.memory.read(&address.value().map(|v| *v));
        let (x, y) = coords(point).unzip();
        ctx.enable(self.s_query)?;
        ctx.enable(self.s_query_read)?;
        ctx.copy(|| "read point: address", self.a0, address)?;
        let x = ctx.advice(|| "read point: x", self.a1, x)?;
        let y = ctx.advice(|| "read point: y", self.a2, y)?;
        ctx.empty(|| "read point: empty", self.a3)?;
        ctx.empty(|| "read point: empty", self.a4)?;
        ctx.fixed(
            || "read point: timestamp",
            self.constant,
            F::from(timestamp as u64),
        )?;
        ctx.next();
        Ok(AssignedPoint::new(x, y))
    }
    pub fn double(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        point: &AssignedPoint<App>,
    ) -> Result<AssignedPoint<App>, Error> {
        let (x, y) = point.coords().unzip();
        let x_square = x * x;
        let x_square_square = x_square * x_square;
        let y_square = y * y;
        let (out_x, out_y) = point.double();
        ctx.enable(self.s_double)?;
        ctx.copy(|| "double: x", self.a0, &point.x)?;
        ctx.copy(|| "double: y", self.a1, &point.y)?;
        ctx.advice(|| "double: x^2", self.a2, x_square)?;
        ctx.advice(|| "double: x^4", self.a3, x_square_square)?;
        ctx.empty(|| "double: empty", self.a4)?;
        ctx.fixed(|| "double: constant", self.constant, F::ZERO)?;
        ctx.next();
        ctx.empty(|| "double: empty", self.a0)?;
        ctx.advice(|| "double: t", self.a1, y_square)?;
        let out_x = ctx.advice(|| "double: out_x", self.a2, out_x)?;
        let out_y = ctx.advice(|| "double: out_y", self.a3, out_y)?;
        ctx.empty(|| "double: empty", self.a4)?;
        ctx.fixed(|| "double: constant", self.constant, F::ZERO)?;
        ctx.next();
        Ok(AssignedPoint::new(out_x, out_y))
    }
    pub fn assign_scalar(
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
            // ctx.enable(self.s_range)?;
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
    pub fn all_zero(&self, ctx: &mut RegionCtx<'_, F>) -> Result<(), Error> {
        ctx.empty(|| "all zero", self.a0)?;
        ctx.empty(|| "all zero", self.a1)?;
        ctx.empty(|| "all zero", self.a2)?;
        ctx.empty(|| "all zero", self.a3)?;
        ctx.empty(|| "all zero", self.a3)?;
        ctx.fixed(|| "all zero", self.constant, F::ZERO)?;
        ctx.next();
        Ok(())
    }
    pub fn layout_sorted_rw(&self, ly: &mut impl Layouter<F>) -> Result<(), Error> {
        let sorted_queries = self.memory.sort();
        let number_of_queries = self.memory.queries.len();
        ly.assign_region(
            || "sorted rw",
            |region| {
                let ctx = &mut RegionCtx::new(region);
                self.all_zero(ctx)?;
                for i in 0..number_of_queries {
                    ctx.enable(self.s_sorted)?;
                    let is_read = sorted_queries.as_ref().map(|queries| queries[i].is_read);
                    if i & 1 == 1 {
                        is_read.map(|is_read| assert!(is_read));
                        ctx.enable(self.s_sorted_read)?;
                    } else {
                        is_read.map(|is_read| assert!(!is_read));
                    }
                    let address = sorted_queries.as_ref().map(|queries| queries[i].address);
                    let timestamp = sorted_queries.as_ref().map(|queries| queries[i].timestamp);
                    let x = sorted_queries.as_ref().map(|queries| queries[i].x);
                    let y = sorted_queries.as_ref().map(|queries| queries[i].y);
                    ctx.advice(|| "sorted rw: address", self.a0, address)?;
                    ctx.advice(|| "sorted rw: x", self.a1, x)?;
                    ctx.advice(|| "sorted rw: y", self.a2, y)?;
                    ctx.advice(|| "sorted rw: timestamp", self.a3, timestamp)?;
                    ctx.empty(|| "sorted rw: empty", self.a4)?;
                    ctx.fixed(|| "sorted rw: constant", self.constant, F::ZERO)?;
                    ctx.next();
                }
                Ok(())
            },
        )
    }
    pub fn layout_range_table(&self, ly: &mut impl Layouter<F>) -> Result<(), Error> {
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

// pub fn window_scalar(
//     &self,
//     ctx: &mut RegionCtx<'_, F>,
//     scalar: Value<App::Scalar>,
// ) -> Result<Vec<AssignedValue<F>>, Error> {
//     macro_rules! div_ceil {
//         ($a:expr, $b:expr) => {
//             (($a - 1) / $b) + 1
//         };
//     }
//     let window = self.window;
//     let number_of_bits = F::NUM_BITS as usize;
//     let number_of_limbs = div_ceil!(number_of_bits, window);
//     let decomposed = scalar.map(|scalar| {
//         let decomposed: Vec<F> = decompose(scalar, number_of_limbs, number_of_bits);
//         decomposed
//     });
//     let decomposed = decomposed.transpose_vec(number_of_limbs);
//     let columns = vec![self.a0, self.a1, self.a2, self.a3];
//     let zero = self.get_constant(ctx, F::ZERO)?;
//     let mut assigned = vec![];
//     let mut sum = Value::known(F::ZERO);
//     let last_index = div_ceil!(decomposed.len(), 4);
//     for (i, chunk) in decomposed.chunks(4).rev().enumerate() {
//         ctx.enable(self.s_range)?;
//         // assign limbs
//         for (v, c) in chunk.iter().zip(columns.iter()) {
//             let limb = ctx.advice(|| "window: assign limb", *c, *v)?;
//             assigned.push(limb);
//         }
//         // first row likely has less than 4 elements
//         for _ in chunk.len()..4 {
//             ctx.copy(|| "window: copy zero to unused cells", columns[i], &zero)?;
//         }
//         // calculate intermadiate sum
//         let chunk: Value<Vec<F>> = Value::from_iter(chunk.to_vec());
//         sum.as_mut()
//             .zip(chunk)
//             .map(|(sum, chunk)| *sum += F::sum(chunk.iter()));
//         // assign intermediate sum
//         if i == 0 {
//             ctx.copy(|| "window: start with copy zero", self.a4, &zero)?;
//         } else {
//             ctx.advice(|| "window: intermediate sums", self.a4, sum)?;
//         }
//         ctx.next();
//     }
//     Ok(assigned)
// }
