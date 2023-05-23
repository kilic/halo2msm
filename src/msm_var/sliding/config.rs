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
    pub(crate) s_table: Selector,
    pub(crate) s_query: Selector,
    pub(crate) window: usize,
    pub(crate) aux_generator: App,
    pub(crate) memory: Memory<F>,
    pub(crate) constants: BTreeMap<F, AssignedValue<F>>,
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
        // x @ a1
        // y @ a2
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
        let s_table = meta.complex_selector();
        let s_query = meta.complex_selector();
        meta.lookup_any("windowed point table", |meta| {
            let s_table = meta.query_selector(s_table);
            let table_address = meta.query_fixed(constant, Rotation::cur());
            let table_x = meta.query_advice(a1, Rotation::cur());
            let table_y = meta.query_advice(a2, Rotation::cur());
            let s_query = meta.query_selector(s_query);
            let query_address = meta.query_advice(a0, Rotation::cur());
            let query_x = meta.query_advice(a1, Rotation::cur());
            let query_y = meta.query_advice(a2, Rotation::cur());
            let query_offset = meta.query_fixed(constant, Rotation::cur());
            vec![
                (
                    e!(s_query) * (query_address + query_offset),
                    e!(s_table) * table_address,
                ),
                (e!(s_query) * query_x, e!(s_table) * table_x),
                (e!(s_query) * query_y, e!(s_table) * table_y),
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
            s_table,
            s_query,
            constants: BTreeMap::new(),
            memory: Memory::default(),
            correction_point: None,
            aux_generator,
            _marker: PhantomData,
        }
    }
}
