use crate::AssignedValue;

use super::rw::Memory;
use ff::PrimeField;
use halo2::{
    halo2curves::CurveAffine,
    plonk::{
        Advice, Column, ConstraintSystem, Constraints, Expression, Fixed, Selector, TableColumn,
    },
    poly::Rotation,
};
use std::{collections::BTreeMap, marker::PhantomData};

#[derive(Clone, Debug)]
pub struct MSMGate<F: PrimeField + Ord, App: CurveAffine<Base = F>> {
    pub(crate) a0: Column<Advice>,
    pub(crate) a1: Column<Advice>,
    pub(crate) a2: Column<Advice>,
    pub(crate) a3: Column<Advice>,
    pub(crate) a4: Column<Advice>,
    pub(crate) constant: Column<Fixed>,
    pub(crate) range_table: TableColumn,
    pub(crate) s_point: Selector,
    pub(crate) s_add: Selector,
    pub(crate) s_double: Selector,
    pub(crate) s_range: Selector,
    pub(crate) s_assign_constant: Selector,
    pub(crate) s_sorted: Selector,
    pub(crate) s_sorted_read: Selector,
    pub(crate) s_query: Selector,
    pub(crate) s_query_read: Selector,
    pub(crate) window: usize,
    pub(crate) aux_generator: App,
    pub(crate) memory: Memory<F>,
    pub(crate) constants: BTreeMap<F, AssignedValue<F>>,
    pub(crate) initial_buckets: Option<Vec<App>>,
    pub(crate) correction_point: Option<App>,
    pub(crate) _marker: PhantomData<(F, App)>,
}

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> MSMGate<F, App> {
    pub fn unassign_constants(&mut self) {
        self.constants.clear();
    }
}

impl<F: PrimeField + Ord, App: CurveAffine<Base = F>> MSMGate<F, App> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        a0: Column<Advice>,
        a1: Column<Advice>,
        a2: Column<Advice>,
        a3: Column<Advice>,
        a4: Column<Advice>,
        range_table: TableColumn,
        constant: Column<Fixed>,
        window: usize,
        aux_generator: App,
    ) -> Self {
        meta.enable_equality(a0);
        meta.enable_equality(a1);
        meta.enable_equality(a2);
        meta.enable_equality(a3);
        meta.enable_equality(a4);
        let s_add = meta.selector();
        let s_double = meta.selector();
        let s_point = meta.selector();
        let s_range = meta.complex_selector();
        let s_assign_constant = meta.selector();
        let _ = meta.instance_column();
        // address @ a0
        // x @ a2
        // y @ a3
        // timestamp @ fixed (or a3 when sorted)
        meta.create_gate("assign point", |meta| {
            let s = meta.query_selector(s_point);
            let x = meta.query_advice(a0, Rotation::cur());
            let y = meta.query_advice(a1, Rotation::cur());
            let x_2 = meta.query_advice(a2, Rotation::cur());
            let x_3 = meta.query_advice(a3, Rotation::cur());
            let expr_x_square = e!(x) * e!(x) - e!(x_2);
            let expr_x_cube = e!(x_2) * e!(x) - e!(x_3);
            let b = App::b();
            let b = Expression::Constant(b);
            let expr_assign = (x_3 + b) - e!(y) * e!(y);
            Constraints::with_selector(
                s,
                [
                    ("assign_x_square", expr_x_square),
                    ("assign_x_cube", expr_x_cube),
                    ("assign_assign", expr_assign),
                ],
            )
        });
        meta.create_gate("incomplete addition", |meta| {
            let s = meta.query_selector(s_add);
            let out_x = meta.query_advice(a1, Rotation::next());
            let out_y = meta.query_advice(a2, Rotation::next());
            let t = meta.query_advice(a3, Rotation::next());
            let inverse_t = meta.query_advice(a4, Rotation::next());
            let a_x = meta.query_advice(a1, Rotation::cur());
            let a_y = meta.query_advice(a2, Rotation::cur());
            let b_x = meta.query_advice(a3, Rotation::cur());
            let b_y = meta.query_advice(a4, Rotation::cur());
            let one = Expression::Constant(F::ONE);
            // t = (b_x - a_x) ^ 2
            let expr_t = (e!(b_x) - e!(a_x)).square() - e!(t);
            // 1/t * t = 1
            let expr_inverse_t = e!(t) * e!(inverse_t) - e!(one);
            // out_x + a_x + b_x * t = (b_y - a_y) ^ 2
            let expr_x = (e!(out_x) + e!(a_x) + e!(b_x)) * e!(t) - (e!(b_y) - e!(a_y)).square();
            // (out_y + a_y) * (b_x - a_x) = (b_y - a_y) * (a_x - out_x)
            let expr_y = (e!(out_y) + e!(a_y)) * (e!(b_x) - e!(a_x))
                - (e!(b_y) - e!(a_y)) * (e!(a_x) - e!(out_x));
            Constraints::with_selector(
                s,
                [
                    ("add_t", expr_t),
                    ("add_inverse_t", expr_inverse_t),
                    ("add_x", expr_x),
                    ("add_y", expr_y),
                ],
            )
        });
        meta.create_gate("incomplete doubling", |meta| {
            let s = meta.query_selector(s_double);
            let y_2 = meta.query_advice(a1, Rotation::next());
            let out_x = meta.query_advice(a2, Rotation::next());
            let out_y = meta.query_advice(a3, Rotation::next());
            let x = meta.query_advice(a0, Rotation::cur());
            let y = meta.query_advice(a1, Rotation::cur());
            let x_2 = meta.query_advice(a2, Rotation::cur());
            let x_4 = meta.query_advice(a3, Rotation::cur());
            let expr_x_square = e!(x).square() - e!(x_2);
            let expr_x_square_square = e!(x_2).square() - e!(x_4);
            let expr_y_square = e!(y).square() - e!(y_2);
            let four_y_2 = e!(y_2) * F::from(4);
            let two_x = e!(x) * F::from(2);
            let nine_x_4 = e!(x_4) * F::from(9);
            let three_x_2 = e!(x_2) * F::from(3);
            let two_y = e!(y) * F::from(2);
            let expr_out_x = four_y_2 * (e!(out_x) + two_x) - nine_x_4;
            let expr_out_y = two_y * (e!(out_y) + y) - three_x_2 * (x - e!(out_x));
            Constraints::with_selector(
                s,
                [
                    ("double_x_square", expr_x_square),
                    ("double_x_square_square", expr_x_square_square),
                    ("double_y_square", expr_y_square),
                    ("double_out_x", expr_out_x),
                    ("double_out_y", expr_out_y),
                ],
            )
        });

        meta.create_gate("assign constant", |meta| {
            let s = meta.query_selector(s_assign_constant);
            let advice = meta.query_advice(a4, Rotation::cur());
            let constant = meta.query_fixed(constant, Rotation::cur());
            let expr = advice - constant;
            Constraints::with_selector(s, [("expr", expr)])
        });
        let one = Expression::Constant(F::ONE);
        let s_sorted = meta.complex_selector();
        let s_query = meta.complex_selector();
        let s_query_read = meta.complex_selector();
        let s_sorted_read = meta.complex_selector();
        meta.create_gate("transition", |meta| {
            let s_sort = meta.query_selector(s_sorted);
            // READ: op == 1, WRITE: op == 0
            let sorted_op = meta.query_selector(s_sorted_read);
            let address_prev = meta.query_advice(a0, Rotation::prev());
            let address = meta.query_advice(a0, Rotation::cur());
            let x_prev = meta.query_advice(a1, Rotation::prev());
            let x = meta.query_advice(a1, Rotation::cur());
            let y_prev = meta.query_advice(a2, Rotation::prev());
            let y = meta.query_advice(a2, Rotation::cur());
            // read the latest
            let latest_x = e!(sorted_op) * (e!(x) - e!(x_prev));
            let latest_y = e!(sorted_op) * (e!(y) - e!(y_prev));
            // sorted by address
            let same_address = e!(address) - e!(address_prev);
            let next_address = e!(address) - e!(address_prev) - e!(one);
            let same_address_or_incremented = e!(same_address) * e!(next_address);
            Constraints::with_selector(
                s_sort,
                vec![latest_x, latest_y, same_address_or_incremented],
            )
        });
        // TODO: this lookup can be moved to range gate to reduce number of lookups
        meta.lookup_any("timestamp diff", |meta| {
            let s_sorted = meta.query_selector(s_sorted);
            let timestamp_prev = meta.query_advice(a3, Rotation::prev());
            let timestamp = meta.query_advice(a3, Rotation::cur());
            let prev_address = meta.query_advice(a0, Rotation::prev());
            let address = meta.query_advice(a0, Rotation::cur());
            let next_address = e!(prev_address) - e!(address) + e!(one);
            let timestamp_diff = e!(timestamp) - e!(timestamp_prev);
            let timestamp_diff_in_same_address = e!(timestamp_diff) * e!(next_address);
            vec![(
                e!(s_sorted) * e!(timestamp_diff_in_same_address),
                e!(s_sorted) * e!(timestamp),
            )]
        });
        // TODO: use shuffle arg instead of lookup arg
        meta.lookup_any("one to one map", |meta| {
            let s_query = meta.query_selector(s_query);
            let query_address = meta.query_advice(a0, Rotation::cur());
            let query_x = meta.query_advice(a1, Rotation::cur());
            let query_y = meta.query_advice(a2, Rotation::cur());
            let query_timestamp: Expression<F> = meta.query_fixed(constant, Rotation::cur());
            let s_sorted = meta.query_selector(s_sorted);
            let sorted_address = meta.query_advice(a0, Rotation::cur());
            let sorted_x = meta.query_advice(a1, Rotation::cur());
            let sorted_y = meta.query_advice(a2, Rotation::cur());
            let sorted_timestamp = meta.query_advice(a3, Rotation::cur());
            vec![
                (e!(s_query) * query_address, e!(s_sorted) * sorted_address),
                (e!(s_query) * query_x, e!(s_sorted) * sorted_x),
                (e!(s_query) * query_y, e!(s_sorted) * sorted_y),
                (
                    e!(s_query) * query_timestamp,
                    e!(s_sorted) * sorted_timestamp,
                ),
            ]
        });
        meta.lookup("range address", |meta| {
            let s = meta.query_selector(s_range);
            let a0 = meta.query_advice(a0, Rotation::cur());
            vec![(e!(s) * a0, range_table)]
        });
        Self {
            s_point,
            s_add,
            s_double,
            s_range,
            s_assign_constant,
            a0,
            a1,
            a2,
            a3,
            a4,
            range_table,
            constant,
            window,
            s_sorted,
            s_sorted_read,
            s_query,
            s_query_read,
            constants: BTreeMap::new(),
            memory: Memory::default(),
            initial_buckets: None,
            correction_point: None,
            aux_generator,
            _marker: PhantomData,
        }
    }
}

// meta.create_gate("compose", |meta| {
//     let s = meta.query_selector(s_range);
//     let a0 = meta.query_advice(a0, Rotation::cur());
//     let a1 = meta.query_advice(a1, Rotation::cur());
//     let a2 = meta.query_advice(a2, Rotation::cur());
//     let a3 = meta.query_advice(a3, Rotation::cur());
//     let e = meta.query_advice(a4, Rotation::cur());
//     let composition = meta.query_advice(a4, Rotation::next());
//     let r = F::from(window as u64);
//     let expr = a0 + a1 * r + a2 * r * r + a3 * r * r * r + e * r * r * r * r - composition;
//     Constraints::with_selector(s, [("expr", expr)])
// });
// let s_is_equal = meta.selector();
// meta.create_gate("is equal", |meta| {
//     let s = meta.query_selector(s_is_equal);
//     let a = meta.query_advice(a0, Rotation::cur());
//     let b = meta.query_advice(a1, Rotation::cur());
//     let x = meta.query_advice(a2, Rotation::cur());
//     let r = meta.query_advice(a3, Rotation::cur());
//     let t = meta.query_advice(a4, Rotation::cur());
//     // 0 = (a - b) * (r * (1 - x) + x) + r - 1
//     let one = Expression::Constant(F::ONE);
//     let expr_t = (e!(r) * (e!(x) - e!(one)) + e!(x)) - e!(t);
//     let expr_rest = (e!(a) - e!(b)) * e!(t) + e!(r) - e!(one);
//     let expr_bitness = e!(r) * e!(r) - e!(r);
//     Constraints::with_selector(
//         s,
//         [
//             ("expr_t", expr_t),
//             ("expr_rest", expr_rest),
//             ("expr_bitness", expr_bitness),
//         ],
//     )
// });