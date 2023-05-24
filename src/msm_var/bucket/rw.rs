use std::collections::BTreeMap;

use ff::PrimeField;
use halo2::{circuit::Value, halo2curves::CurveAffine};

#[derive(Clone, Debug)]
pub(crate) struct Query<F: PrimeField + Ord> {
    is_read: bool,
    address: Value<F>,
    x: Value<F>,
    y: Value<F>,
}
#[derive(Clone, Debug)]
pub(crate) struct SortedQuery<F: PrimeField + Ord> {
    pub(crate) is_read: bool,
    pub(crate) timestamp: usize,
    pub(crate) address: F,
    pub(crate) x: F,
    pub(crate) y: F,
}
impl<F: PrimeField + Ord> Query<F> {
    pub(crate) fn read(address: &Value<F>, x: &Value<F>, y: &Value<F>) -> Self {
        Self {
            is_read: true,
            address: address.clone(),
            x: x.clone(),
            y: y.clone(),
        }
    }
    pub(crate) fn write(address: &Value<F>, x: &Value<F>, y: &Value<F>) -> Self {
        Self {
            is_read: false,
            address: address.clone(),
            x: x.clone(),
            y: y.clone(),
        }
    }
}
#[derive(Clone, Debug, Default)]
pub(crate) struct Memory<F: PrimeField + Ord> {
    pub(crate) queries: Vec<Query<F>>,
    state: BTreeMap<F, (F, F)>,
}
impl<F: PrimeField + Ord> Memory<F> {
    pub(crate) fn clear_queries(&mut self) {
        self.queries.clear();
    }
    pub(crate) fn timestamp(&self) -> usize {
        self.queries.len()
    }
    pub(crate) fn read<C: CurveAffine<Base = F>>(&mut self, address: &Value<F>) -> Value<C> {
        let coords = address.map(|address| {
            let value: &(F, F) = self.state.get(&address).expect("must be written first");
            *value
        });
        let (x, y) = coords.unzip();
        let query = Query::read(&address, &x, &y);
        self.add_query(&query);
        x.zip(y).map(|(x, y)| C::from_xy(x, y).unwrap())
    }
    pub(crate) fn write(&mut self, address: &Value<F>, coords: &Value<(F, F)>) {
        address.zip(coords.clone()).map(|(address, coords)| {
            self.state.insert(address, coords);
        });
        let (x, y) = coords.unzip();
        let query = Query::write(&address, &x, &y);
        self.add_query(&query);
    }
    pub(crate) fn add_query(&mut self, query: &Query<F>) {
        self.queries.push(query.clone());
    }
    pub(crate) fn sort(&self) -> Value<Vec<SortedQuery<F>>> {
        let sorted_queries = self
            .queries
            .iter()
            .enumerate()
            .map(|(timestamp, query)| {
                let address = query.address;
                let x = query.x;
                let y = query.y;
                let sorted_query: Value<SortedQuery<F>> =
                    address.zip(x).zip(y).map(|((address, x), y)| SortedQuery {
                        is_read: query.is_read,
                        timestamp,
                        address,
                        x,
                        y,
                    });
                sorted_query
            })
            .collect::<Vec<_>>();
        let mut sorted_queries: Value<Vec<SortedQuery<_>>> = Value::from_iter(sorted_queries);
        sorted_queries.as_mut().map(|queries| {
            queries.sort_by(|a, b| a.address.cmp(&b.address));
        });
        sorted_queries
    }
}
