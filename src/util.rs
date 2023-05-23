use ff::PrimeField;
use halo2::{
    arithmetic::best_multiexp,
    halo2curves::{CurveAffine, CurveExt},
};
use num_bigint::BigUint;
use num_traits::{Num, One, Zero};
use std::ops::Shl;

pub(crate) fn modulus<F: PrimeField>() -> BigUint {
    BigUint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}
pub(crate) fn power_of_two<F: PrimeField>(n: usize) -> F {
    big_to_fe(BigUint::one() << n)
}
pub(crate) fn big_to_fe<F: PrimeField>(e: BigUint) -> F {
    let modulus = modulus::<F>();
    let e = e % modulus;
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}
pub(crate) fn fe_to_big<F: PrimeField>(fe: F) -> BigUint {
    BigUint::from_bytes_le(fe.to_repr().as_ref())
}
pub(crate) fn decompose<W: PrimeField, N: PrimeField>(
    e: W,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<N> {
    decompose_big(fe_to_big(e), number_of_limbs, bit_len)
}
pub(crate) fn bool_to_big(truth: bool) -> BigUint {
    if truth {
        BigUint::one()
    } else {
        BigUint::zero()
    }
}
pub(crate) fn decompose_big<F: PrimeField>(
    e: BigUint,
    number_of_limbs: usize,
    bit_len: usize,
) -> Vec<F> {
    let mut e = e;
    let mask = BigUint::from(1usize).shl(bit_len) - 1usize;
    let limbs: Vec<F> = (0..number_of_limbs)
        .map(|_| {
            let limb = mask.clone() & e.clone();
            e = e.clone() >> bit_len;
            big_to_fe(limb)
        })
        .collect();

    limbs
}
pub(crate) fn compose<W: PrimeField, N: PrimeField>(input: Vec<N>, bit_len: usize) -> W {
    big_to_fe(compose_big(
        input.into_iter().map(|e| fe_to_big(e)).collect(),
        bit_len,
    ))
}
pub(crate) fn compose_big(input: Vec<BigUint>, bit_len: usize) -> BigUint {
    input
        .iter()
        .rev()
        .fold(BigUint::zero(), |acc, val| (acc << bit_len) + val)
}
pub(crate) fn multiexp_naive_var<C: CurveExt>(point: &[C], scalar: &[C::ScalarExt]) -> C
where
    <C::ScalarExt as PrimeField>::Repr: AsRef<[u8]>,
{
    assert!(!point.is_empty());
    assert_eq!(point.len(), scalar.len());
    point
        .iter()
        .zip(scalar.iter())
        .fold(C::identity(), |acc, (point, scalar)| {
            acc + (*point * *scalar)
        })
}
pub(crate) fn from_str<C: CurveAffine>(x: &str, y: &str) -> C {
    use num_bigint::BigUint as Big;
    let x: C::Base = big_to_fe(Big::from_str_radix(x, 16).unwrap());
    let y: C::Base = big_to_fe(Big::from_str_radix(y, 16).unwrap());
    C::from_xy(x, y).unwrap()
}
