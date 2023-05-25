use ff::PrimeField;
use halo2::{circuit::Value, halo2curves::CurveAffine};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub(crate) struct Memory<F: PrimeField + Ord> {
    state: BTreeMap<F, (F, F)>,
}
impl<F: PrimeField + Ord> Memory<F> {
    pub(crate) fn read<C: CurveAffine<Base = F>>(
        &mut self,
        address: &Value<F>,
        offset: F,
    ) -> Value<C> {
        let coords = address.map(|address| {
            let value: &(F, F) = self
                .state
                .get(&(address + offset))
                .expect("must be written first");
            *value
        });
        let (x, y) = coords.unzip();
        x.zip(y).map(|(x, y)| C::from_xy(x, y).unwrap())
    }
    pub(crate) fn write(&mut self, address: F, offset: F, coords: &Value<(F, F)>) {
        coords.map(|coords| {
            let coords_new = self.state.insert(address + offset, coords);
            if let Some(coords_new) = coords_new {
                assert_eq!(coords_new, coords);
            };
        });
    }
}
