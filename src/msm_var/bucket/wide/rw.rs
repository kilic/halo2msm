use std::collections::BTreeMap;

use ff::PrimeField;
use halo2::{
    circuit::Value,
    halo2curves::{pasta::pallas::Base, CurveAffine},
};

use crate::coords;

#[derive(Clone, Debug)]
pub(crate) struct Query<F: PrimeField + Ord> {
    address: Value<F>,
    x0: Value<F>,
    y0: Value<F>,
    x1: Value<F>,
    y1: Value<F>,
}
#[derive(Clone, Debug)]
pub(crate) struct SortedQuery<F: PrimeField + Ord> {
    pub(crate) timestamp: F,
    pub(crate) address: F,
    pub(crate) x0: F,
    pub(crate) y0: F,
    pub(crate) x1: F,
    pub(crate) y1: F,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Memory<F: PrimeField + Ord> {
    pub(crate) queries: Vec<Query<F>>,
    pub(crate) state: BTreeMap<F, (F, F)>,
}
impl<F: PrimeField + Ord> Memory<F> {
    pub(crate) fn clear(&mut self) {
        self.queries.clear();
        self.state.clear();
    }
    pub(crate) fn timestamp(&self) -> usize {
        self.queries.len()
    }
    pub(crate) fn read<C: CurveAffine<Base = F>>(&mut self, address: &Value<F>) -> Value<C> {
        address.map(|address| {
            let (x, y): &(F, F) = self.state.get(&address).expect("must be written first");
            C::from_xy(*x, *y).unwrap()
        })
    }
    pub(crate) fn write(&mut self, address: &Value<F>, coords_write: &Value<(F, F)>) {
        let coords_read = address.zip(coords_write.clone()).map(|(address, coords)| {
            let coords_read = self.state.insert(address, coords);
            match coords_read {
                None => (F::ZERO, F::ZERO),       // first write
                Some(coords_read) => coords_read, // intermediate write
            }
        });
        let (x0, y0) = coords_read.unzip();
        let (x1, y1) = coords_write.unzip();
        let query = Query {
            address: address.clone(),
            x0,
            y0,
            x1,
            y1,
        };
        self.queries.push(query.clone());
    }
    // pub(crate) fn finalize<C: CurveAffine<Base = F>>(&mut self, address: &Value<F>) -> Value<C> {
    //     let (coords_read, coords_write) = address
    //         .map(|address| {
    //             let coords_read = *self.state.get(&address).expect("must be written first");
    //             let coords_write = (F::ZERO, F::ZERO);
    //             (coords_read, coords_write)
    //         })
    //         .unzip();
    //     let res = coords_read.map(|coords| C::from_xy(coords.0, coords.1).unwrap());
    //     let (x0, y0) = coords_read.unzip();
    //     let (x1, y1) = coords_write.unzip();
    //     let query = Query {
    //         address: address.clone(),
    //         x0,
    //         y0,
    //         x1,
    //         y1,
    //     };
    //     self.queries.push(query.clone());
    //     res
    // }
    pub(crate) fn sort(&self) -> Value<Vec<SortedQuery<F>>> {
        let sorted_queries = self
            .queries
            .iter()
            .enumerate()
            .map(|(timestamp, query)| {
                let address = query.address;
                let x0 = query.x0;
                let y0 = query.y0;
                let x1 = query.x1;
                let y1 = query.y1;
                let sorted_query: Value<SortedQuery<F>> =
                    address.zip(x0).zip(y0).zip(x1).zip(y1).map(
                        |((((address, x0), y0), x1), y1)| SortedQuery {
                            timestamp: F::from(timestamp as u64),
                            address,
                            x0,
                            y0,
                            x1,
                            y1,
                        },
                    );
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
