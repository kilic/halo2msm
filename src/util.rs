use ff::PrimeField;
use num_bigint::BigUint;
use num_traits::Num;
use std::ops::Shl;

pub(crate) fn modulus<F: PrimeField>() -> BigUint {
    BigUint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
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
#[cfg(test)]
use halo2::halo2curves::CurveExt;
#[cfg(test)]
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
