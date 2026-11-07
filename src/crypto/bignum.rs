//! Arbitrary-precision unsigned integers for the few places SSH handles
//! them directly: Diffie-Hellman, RSA key components and the `moduli`
//! screening in `ssh-keygen`. A thin layer over [`crypto_bigint::BoxedUint`]
//! that hides its fixed-precision arithmetic: values here grow as needed and
//! mixed-width operands are widened before an operation.
//!
//! Secret-dependent operations (modular exponentiation with a secret
//! exponent, inversion) go through `crypto-bigint`'s constant-time paths;
//! comparisons and the byte conversions are variable-time and are only used
//! on public values or for sanity checks on freshly parsed key material.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{ConcatenatingMul, Integer, NonZero, Odd, Resize};

/// An unsigned big integer.
#[derive(Clone, Debug)]
pub struct BoxedUint(crypto_bigint::BoxedUint);

fn unify(
    a: &crypto_bigint::BoxedUint,
    b: &crypto_bigint::BoxedUint,
) -> (crypto_bigint::BoxedUint, crypto_bigint::BoxedUint) {
    let bits = a.bits_precision().max(b.bits_precision());
    (a.resize(bits), b.resize(bits))
}

impl BoxedUint {
    /// Zero.
    pub fn zero() -> Self {
        BoxedUint(crypto_bigint::BoxedUint::from(0u64))
    }

    /// From big-endian bytes of any length (leading zeros allowed).
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let trimmed = {
            let mut i = 0;
            while i < bytes.len() && bytes[i] == 0 {
                i += 1;
            }
            &bytes[i..]
        };
        if trimmed.is_empty() {
            return Self::zero();
        }
        BoxedUint(crypto_bigint::BoxedUint::from_be_slice_vartime(trimmed))
    }

    /// From a machine word.
    pub fn from_u64(v: u64) -> Self {
        BoxedUint(crypto_bigint::BoxedUint::from(v))
    }

    /// Big-endian bytes, exactly `len` long: zero-padded on the left, or,
    /// if the value does not fit, its low `len` bytes.
    pub fn to_be_bytes(&self, len: usize) -> Vec<u8> {
        let t = self.to_be_bytes_trimmed();
        if t.len() >= len {
            t[t.len() - len..].to_vec()
        } else {
            let mut out = alloc::vec![0u8; len];
            out[len - t.len()..].copy_from_slice(&t);
            out
        }
    }

    /// Minimal big-endian bytes (empty for zero).
    pub fn to_be_bytes_trimmed(&self) -> Vec<u8> {
        if self.is_zero() {
            return Vec::new();
        }
        self.0.to_be_bytes_trimmed_vartime().into_vec()
    }

    /// Number of significant bits (0 for zero).
    pub fn bit_len(&self) -> usize {
        self.0.bits_vartime() as usize
    }

    /// Bytes needed to hold the value (0 for zero).
    pub fn byte_len(&self) -> usize {
        self.bit_len().div_ceil(8)
    }

    /// Is the value zero?
    pub fn is_zero(&self) -> bool {
        self.0.is_zero().into()
    }

    /// Is the value odd?
    pub fn is_odd(&self) -> bool {
        self.0.is_odd().into()
    }

    /// `self + rhs`.
    pub fn add(&self, rhs: &Self) -> Self {
        let bits = self.0.bits_precision().max(rhs.0.bits_precision()) + 64;
        BoxedUint(
            self.0
                .clone()
                .resize(bits)
                .wrapping_add(rhs.0.clone().resize(bits)),
        )
    }

    /// `self - rhs`, saturating at zero.
    pub fn sub(&self, rhs: &Self) -> Self {
        if self < rhs {
            return Self::zero();
        }
        let (a, b) = unify(&self.0, &rhs.0);
        BoxedUint(a.wrapping_sub(&b))
    }

    /// `self * rhs`.
    pub fn mul(&self, rhs: &Self) -> Self {
        BoxedUint(self.0.concatenating_mul(&rhs.0))
    }

    /// `self mod m` (zero if `m` is zero).
    pub fn reduce(&self, m: &Self) -> Self {
        let (a, m) = unify(&self.0, &m.0);
        match NonZero::new(m).into_option() {
            Some(nz) => BoxedUint(a.rem(&nz)),
            None => Self::zero(),
        }
    }

    /// `self >> bits`.
    pub fn shr_bits(&self, bits: usize) -> Self {
        if bits >= self.0.bits_precision() as usize {
            return Self::zero();
        }
        BoxedUint(self.0.shr(bits as u32))
    }

    /// `self^-1 mod m`, or `None` if it does not exist.
    pub fn inv_mod(&self, m: &Self) -> Option<Self> {
        if m.is_zero() {
            return None;
        }
        let (a, m) = unify(&self.0, &m.0);
        let m = NonZero::new(m).into_option()?;
        a.invert_mod(&m).into_option().map(BoxedUint)
    }

    /// `self^exp mod m` in constant time with respect to `exp`, or `None` if
    /// `m` is even or below 3.
    pub fn pow_mod(&self, exp: &Self, m: &Self) -> Option<Self> {
        Some(MontModulus::new(m)?.pow(self, exp))
    }
}

impl PartialEq for BoxedUint {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for BoxedUint {}

impl PartialOrd for BoxedUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BoxedUint {
    fn cmp(&self, other: &Self) -> Ordering {
        let (a, b) = unify(&self.0, &other.0);
        a.cmp(&b)
    }
}

/// An odd modulus prepared for repeated exponentiation and multiplication
/// (Montgomery form).
#[derive(Clone)]
pub struct MontModulus {
    params: BoxedMontyParams,
    modulus: BoxedUint,
}

impl MontModulus {
    /// Prepare `m`; `None` if it is even or below 3.
    pub fn new(m: &BoxedUint) -> Option<Self> {
        if !m.is_odd() || m.bit_len() < 2 {
            return None;
        }
        let odd = Odd::new(m.0.clone()).into_option()?;
        Some(MontModulus {
            params: BoxedMontyParams::new(odd),
            modulus: m.clone(),
        })
    }

    /// The modulus.
    pub fn modulus(&self) -> &BoxedUint {
        &self.modulus
    }

    fn form(&self, x: &BoxedUint) -> BoxedMontyForm {
        let reduced = x
            .reduce(&self.modulus)
            .0
            .resize(self.params.bits_precision());
        BoxedMontyForm::new(reduced, &self.params)
    }

    /// `base^exp mod m`, constant time in `exp`.
    pub fn pow(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        BoxedUint(self.form(base).pow(&exp.0).retrieve())
    }

    /// `base^exp mod m` for public operands. Currently the same constant-time
    /// routine; the name records that the inputs need no protection.
    pub fn pow_public(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        self.pow(base, exp)
    }

    /// `a * b mod m`.
    pub fn mul_mod(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        BoxedUint(self.form(a).mul(&self.form(b)).retrieve())
    }
}

/// `a^-1 mod m`.
pub fn inv_mod_boxed(a: &BoxedUint, m: &BoxedUint) -> Option<BoxedUint> {
    a.inv_mod(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_and_widths() {
        let x = BoxedUint::from_be_bytes(&[0, 0, 0x01, 0x02, 0x03]);
        assert_eq!(x.bit_len(), 17);
        assert_eq!(x.to_be_bytes_trimmed(), alloc::vec![1, 2, 3]);
        assert_eq!(x.to_be_bytes(5), alloc::vec![0, 0, 1, 2, 3]);
        assert_eq!(x.to_be_bytes(2), alloc::vec![2, 3]);
        assert!(BoxedUint::from_be_bytes(&[0, 0]).is_zero());
        assert_eq!(BoxedUint::zero().to_be_bytes_trimmed(), Vec::<u8>::new());
        assert_eq!(
            BoxedUint::from_u64(65537).to_be_bytes(3),
            alloc::vec![1, 0, 1]
        );
    }

    #[test]
    fn arithmetic_across_widths() {
        let big = BoxedUint::from_be_bytes(&[0xff; 40]);
        let one = BoxedUint::from_u64(1);
        let sum = big.add(&one);
        assert_eq!(sum.bit_len(), 321);
        assert_eq!(sum.sub(&one), big);
        assert!(one.sub(&big).is_zero());
        assert_eq!(big.mul(&one), big);
        assert_eq!(
            BoxedUint::from_u64(10).reduce(&BoxedUint::from_u64(7)),
            BoxedUint::from_u64(3)
        );
        assert_eq!(big.reduce(&big), BoxedUint::zero());
        assert!(big > one && one < big && big == big.clone());
        assert_eq!(
            BoxedUint::from_u64(0x100).shr_bits(4),
            BoxedUint::from_u64(0x10)
        );
        assert!(BoxedUint::from_u64(1).shr_bits(500).is_zero());
    }

    #[test]
    fn modular_inverse_and_power() {
        let m = BoxedUint::from_u64(1_000_003);
        let a = BoxedUint::from_u64(12345);
        let inv = a.inv_mod(&m).unwrap();
        assert_eq!(a.mul(&inv).reduce(&m), BoxedUint::from_u64(1));
        assert!(
            BoxedUint::from_u64(6)
                .inv_mod(&BoxedUint::from_u64(9))
                .is_none()
        );
        assert_eq!(
            BoxedUint::from_u64(3)
                .pow_mod(&BoxedUint::from_u64(200), &m)
                .unwrap(),
            BoxedUint::from_u64(3)
                .pow_mod(&BoxedUint::from_u64(100), &m)
                .unwrap()
                .mul(
                    &BoxedUint::from_u64(3)
                        .pow_mod(&BoxedUint::from_u64(100), &m)
                        .unwrap()
                )
                .reduce(&m)
        );
        assert!(
            BoxedUint::from_u64(3)
                .pow_mod(&one(), &BoxedUint::from_u64(10))
                .is_none()
        );
        let mont = MontModulus::new(&m).unwrap();
        assert_eq!(mont.mul_mod(&a, &inv), one());
        // Fermat: a^(m-1) == 1 mod prime m.
        assert_eq!(mont.pow_public(&a, &m.sub(&one())), one());
    }

    fn one() -> BoxedUint {
        BoxedUint::from_u64(1)
    }
}
