use std::marker::PhantomData;

use ff::Field;
use group::Curve;
use halo2::{
    circuit::{AssignedCell, Cell, Region, Value},
    halo2curves::CurveAffine,
    plonk::{Advice, Any, Column, Error, Fixed, Selector},
};

macro_rules! e {
    // I just want not to see too much cloned expressions around :/ this is a bit less ugly
    ($a:expr) => {
        $a.clone()
    };
}
macro_rules! div_ceil {
    ($a:expr, $b:expr) => {
        (($a - 1) / $b) + 1
    };
}
pub mod msm_var;
pub(crate) mod util;

pub type AssignedValue<F> = AssignedCell<F, F>;

#[derive(Debug, Clone)]
pub struct AssignedPoint<C: CurveAffine> {
    x: AssignedValue<C::Base>,
    y: AssignedValue<C::Base>,
    _marker: PhantomData<C>,
}

pub(crate) fn coords<C: CurveAffine>(point: Value<C>) -> Value<(C::Base, C::Base)> {
    point.map(|c| {
        let coordinates = c.coordinates().unwrap();
        (coordinates.x().clone(), coordinates.y().clone())
    })
}

impl<C: CurveAffine> AssignedPoint<C> {
    pub fn new(x: AssignedValue<C::Base>, y: AssignedValue<C::Base>) -> AssignedPoint<C> {
        AssignedPoint {
            x,
            y,
            _marker: PhantomData,
        }
    }
    pub fn x(&self) -> &AssignedValue<C::Base> {
        &self.x
    }
    pub fn y(&self) -> &AssignedValue<C::Base> {
        &self.y
    }
    pub fn value(&self) -> Value<C> {
        let x = self.x.value().map(|v| *v);
        let y = self.y.value().map(|v| *v);
        x.zip(y).map(|(x, y)| C::from_xy(x, y).unwrap())
    }
    pub fn coords(&self) -> Value<(C::Base, C::Base)> {
        let x = self.x.value().map(|v| *v);
        let y = self.y.value().map(|v| *v);
        x.zip(y)
    }
    pub fn dbl(&self) -> (Value<C::Base>, Value<C::Base>) {
        let this = self.value();
        let res = this.map(|this| (this + this).to_affine());
        coords(res).unzip()
    }
    fn _add(&self, other: &Self) -> Value<C> {
        let this = self.value();
        let other = other.value();
        let u = this + other;
        u.map(|c| c.to_affine())
    }
    fn _double(&self) -> Value<C> {
        let this = self.value();
        this.map(|this| (this + this).to_affine())
    }
}

impl<C: CurveAffine> std::ops::Add<&AssignedPoint<C>> for AssignedPoint<C> {
    type Output = (Value<C::Base>, Value<C::Base>);
    fn add(self, other: &AssignedPoint<C>) -> Self::Output {
        let res = self + &other.value();
        coords(res).unzip()
    }
}
impl<C: CurveAffine> std::ops::Add<&AssignedPoint<C>> for &AssignedPoint<C> {
    type Output = (Value<C::Base>, Value<C::Base>);
    fn add(self, other: &AssignedPoint<C>) -> Self::Output {
        let res = self + &other.value();
        coords(res).unzip()
    }
}
impl<C: CurveAffine> std::ops::Add<&Value<C>> for &AssignedPoint<C> {
    type Output = Value<C>;
    fn add(self, other: &Value<C>) -> Self::Output {
        self.value()
            .zip(*other)
            .map(|(this, other)| (this + other).to_affine())
    }
}
impl<C: CurveAffine> std::ops::Add<&Value<C>> for AssignedPoint<C> {
    type Output = Value<C>;
    fn add(self, other: &Value<C>) -> Self::Output {
        self.value()
            .zip(*other)
            .map(|(this, other)| (this + other).to_affine())
    }
}

#[derive(Debug)]
pub struct RegionCtx<'a, F: Field> {
    region: Region<'a, F>,
    offset: usize,
}
impl<'a, F: Field> RegionCtx<'a, F> {
    pub fn new(region: Region<'a, F>) -> RegionCtx<'a, F> {
        RegionCtx { region, offset: 0 }
    }
    pub fn offset(&self) -> usize {
        self.offset
    }
    pub fn fixed<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Fixed>,
        value: F,
    ) -> Result<AssignedCell<F, F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_fixed(annotation, column, self.offset, || Value::known(value))
    }
    pub fn advice<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Advice>,
        value: Value<F>,
    ) -> Result<AssignedValue<F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        self.region
            .assign_advice(annotation, column, self.offset, || value)
    }
    pub fn empty<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Any>,
    ) -> Result<AssignedValue<F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        match column.column_type() {
            Any::Advice(_) => self.region.assign_advice(
                annotation,
                column.try_into().unwrap(),
                self.offset,
                || Value::known(F::ZERO),
            ),
            Any::Fixed => self.region.assign_fixed(
                annotation,
                column.try_into().unwrap(),
                self.offset,
                || Value::known(F::ZERO),
            ),
            _ => panic!("Cannot assign to instance column"),
        }
    }
    pub fn copy<A, AR>(
        &mut self,
        annotation: A,
        column: Column<Advice>,
        assigned: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        assigned.copy_advice(annotation, &mut self.region, column, self.offset)
    }
    pub fn equal(&mut self, cell_0: Cell, cell_1: Cell) -> Result<(), Error> {
        self.region.constrain_equal(cell_0, cell_1)
    }
    pub fn enable(&mut self, selector: Selector) -> Result<(), Error> {
        selector.enable(&mut self.region, self.offset)
    }
    pub fn next(&mut self) {
        self.offset += 1
    }
}
