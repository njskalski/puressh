//! Finite-field Diffie-Hellman for the `diffie-hellman-group*` key
//! exchanges: the RFC 3526 groups 14, 16 and 18, and arbitrary
//! server-supplied groups for group exchange (RFC 4419).
//!
//! Exponentiation is `crypto-bigint`'s constant-time Montgomery ladder via
//! [`MontModulus`]. Peer public values are checked to lie in `[2, p-2]` and
//! the shared secret is rejected if it is 1 or `p-1`, which with the safe
//! primes SSH uses rules out every small subgroup.

use alloc::vec::Vec;

use super::bignum::{BoxedUint, MontModulus};
use super::rng::{CryptoRng, RngCore};
use super::zeroize::{Zeroize, Zeroizing};

/// An invalid group or an out-of-range public value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

/// A DH group: prime modulus `p`, generator `g`, and the size of the private
/// exponents drawn for it.
#[derive(Clone)]
pub struct DhGroup {
    name: &'static str,
    p: BoxedUint,
    g: BoxedUint,
    priv_bits: usize,
    mont: MontModulus,
}

impl DhGroup {
    /// Largest prime accepted for a custom group.
    pub const MAX_CUSTOM_GROUP_BITS: usize = 16384;

    /// A group from `p` and `g` without a primality test (the caller trusts
    /// the source or screens it separately). Requires `p` odd and at least
    /// 3 bits, `2 <= g <= p-2`, and `0 < priv_bits <= bits(p)`.
    pub fn from_custom_unchecked(
        p: BoxedUint,
        g: BoxedUint,
        priv_bits: usize,
    ) -> Result<Self, Error> {
        if p.bit_len() > Self::MAX_CUSTOM_GROUP_BITS || p.bit_len() < 3 || !p.is_odd() {
            return Err(Error);
        }
        let p_minus_two = p.sub(&BoxedUint::from_u64(2));
        if g < BoxedUint::from_u64(2) || g > p_minus_two {
            return Err(Error);
        }
        if priv_bits == 0 || priv_bits > p.bit_len() {
            return Err(Error);
        }
        let mont = MontModulus::new(&p).ok_or(Error)?;
        Ok(DhGroup {
            name: "custom",
            p,
            g,
            priv_bits,
            mont,
        })
    }

    fn rfc3526(name: &'static str, p: &[u8], priv_bits: usize) -> Self {
        let p = BoxedUint::from_be_bytes(p);
        let mont = MontModulus::new(&p).expect("RFC 3526 primes are odd");
        DhGroup {
            name,
            p,
            g: BoxedUint::from_u64(2),
            priv_bits,
            mont,
        }
    }

    /// The group's name (`group14`, `custom`, ...).
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Bits in `p`.
    pub fn bit_size(&self) -> usize {
        self.p.bit_len()
    }

    /// Bytes needed for `p`.
    pub fn byte_size(&self) -> usize {
        self.p.byte_len()
    }

    /// The prime modulus.
    pub fn p(&self) -> &BoxedUint {
        &self.p
    }

    /// The generator.
    pub fn g(&self) -> &BoxedUint {
        &self.g
    }

    /// Bits in the private exponents drawn for this group.
    pub fn priv_bits(&self) -> usize {
        self.priv_bits
    }

    /// Is `y` a valid public value: `2 <= y <= p-2`?
    fn public_in_range(&self, y: &BoxedUint) -> bool {
        *y >= BoxedUint::from_u64(2) && *y <= self.p.sub(&BoxedUint::from_u64(2))
    }
}

/// RFC 3526 2048-bit MODP group. 256-bit private exponents, as OpenSSH.
pub fn group14() -> DhGroup {
    DhGroup::rfc3526("group14", &super::dh_groups::GROUP14_P, 256)
}

/// RFC 3526 4096-bit MODP group. 384-bit private exponents.
pub fn group16() -> DhGroup {
    DhGroup::rfc3526("group16", &super::dh_groups::GROUP16_P, 384)
}

/// RFC 3526 8192-bit MODP group. 512-bit private exponents.
pub fn group18() -> DhGroup {
    DhGroup::rfc3526("group18", &super::dh_groups::GROUP18_P, 512)
}

/// A private exponent `x` with its group.
pub struct DhPrivateKey {
    group: DhGroup,
    x: BoxedUint,
    x_bytes: Zeroizing<Vec<u8>>,
}

/// A public value `y = g^x mod p` with its group.
#[derive(Clone)]
pub struct DhPublicKey {
    group: DhGroup,
    y: BoxedUint,
}

/// The shared secret `K`, wiped on drop.
pub struct SharedSecret(Zeroizing<Vec<u8>>);

impl SharedSecret {
    /// `K` as a minimal big-endian magnitude.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Take `K` out; the caller is responsible for wiping it.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl DhPrivateKey {
    /// Draw a random exponent of the group's `priv_bits` bits (at least 2).
    pub fn generate<R: RngCore + CryptoRng>(group: DhGroup, rng: &mut R) -> Self {
        let nbytes = group.priv_bits.div_ceil(8);
        let excess = nbytes * 8 - group.priv_bits;
        let mut x_bytes = Zeroizing::new(alloc::vec![0u8; nbytes]);
        loop {
            rng.fill_bytes(&mut x_bytes);
            if excess > 0 {
                x_bytes[0] &= 0xffu8 >> excess;
            }
            let x = BoxedUint::from_be_bytes(&x_bytes);
            if x >= BoxedUint::from_u64(2) {
                return DhPrivateKey { group, x, x_bytes };
            }
        }
    }

    /// From an explicit exponent (tests and deterministic vectors).
    pub fn from_bytes(group: DhGroup, bytes: &[u8]) -> Result<Self, Error> {
        let x = BoxedUint::from_be_bytes(bytes);
        if x < BoxedUint::from_u64(2) || x >= group.p {
            return Err(Error);
        }
        Ok(DhPrivateKey {
            group,
            x,
            x_bytes: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// The exponent as minimal big-endian bytes.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.x.to_be_bytes_trimmed())
    }

    /// The group.
    pub fn group(&self) -> &DhGroup {
        &self.group
    }

    /// `g^x mod p`.
    pub fn public_key(&self) -> DhPublicKey {
        DhPublicKey {
            group: self.group.clone(),
            y: self.group.mont.pow(&self.group.g, &self.x),
        }
    }

    /// `peer^x mod p`, rejecting a peer outside `[2, p-2]` or a degenerate
    /// result (1 or `p-1`).
    pub fn shared_secret(&self, peer: &DhPublicKey) -> Result<SharedSecret, Error> {
        if peer.group.p != self.group.p || !self.group.public_in_range(&peer.y) {
            return Err(Error);
        }
        let k = self.group.mont.pow(&peer.y, &self.x);
        if k <= BoxedUint::from_u64(1) || k == self.group.p.sub(&BoxedUint::from_u64(1)) {
            return Err(Error);
        }
        Ok(SharedSecret(Zeroizing::new(k.to_be_bytes_trimmed())))
    }
}

impl Drop for DhPrivateKey {
    fn drop(&mut self) {
        self.x_bytes.zeroize();
        // `x` itself lives in a `crypto_bigint::BoxedUint`, which zeroizes
        // its limbs on drop.
    }
}

impl DhPublicKey {
    /// Parse a big-endian public value and check `2 <= y <= p-2`.
    pub fn from_bytes(group: DhGroup, bytes: &[u8]) -> Result<Self, Error> {
        let y = BoxedUint::from_be_bytes(bytes);
        if !group.public_in_range(&y) {
            return Err(Error);
        }
        Ok(DhPublicKey { group, y })
    }

    /// Minimal big-endian bytes of `y`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.y.to_be_bytes_trimmed()
    }

    /// The group.
    pub fn group(&self) -> &DhGroup {
        &self.group
    }

    /// `y`.
    pub fn y(&self) -> &BoxedUint {
        &self.y
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::OsRng;

    #[test]
    fn group_primes_match_rfc3526() {
        for (g, bits, tail) in [
            (group14(), 2048, 256),
            (group16(), 4096, 512),
            (group18(), 8192, 1024),
        ] {
            assert_eq!(g.bit_size(), bits);
            assert_eq!(g.byte_size(), tail);
            let p = g.p().to_be_bytes(tail);
            assert_eq!(&p[..8], &[0xff; 8]);
            assert_eq!(&p[8..12], &[0xc9, 0x0f, 0xda, 0xa2]);
            assert_eq!(&p[tail - 8..], &[0xff; 8]);
            assert_eq!(*g.g(), BoxedUint::from_u64(2));
        }
    }

    #[test]
    fn agreement_round_trip() {
        let g = group14();
        let a = DhPrivateKey::generate(g.clone(), &mut OsRng);
        let b = DhPrivateKey::generate(g.clone(), &mut OsRng);
        assert!(a.to_bytes().len() <= 32 && a.to_bytes().len() >= 30);
        let ya = DhPublicKey::from_bytes(g.clone(), &a.public_key().to_bytes()).unwrap();
        let yb = DhPublicKey::from_bytes(g.clone(), &b.public_key().to_bytes()).unwrap();
        let ka = a.shared_secret(&yb).unwrap();
        let kb = b.shared_secret(&ya).unwrap();
        assert_eq!(ka.as_bytes(), kb.as_bytes());
        assert!(ka.as_bytes().len() > 200);
    }

    #[test]
    fn rejects_degenerate_public_values() {
        let g = group14();
        assert!(DhPublicKey::from_bytes(g.clone(), &[0]).is_err());
        assert!(DhPublicKey::from_bytes(g.clone(), &[1]).is_err());
        let p_minus_1 = g.p().sub(&BoxedUint::from_u64(1)).to_be_bytes_trimmed();
        assert!(DhPublicKey::from_bytes(g.clone(), &p_minus_1).is_err());
        assert!(DhPublicKey::from_bytes(g.clone(), &g.p().to_be_bytes_trimmed()).is_err());
        assert!(DhPublicKey::from_bytes(g.clone(), &[2]).is_ok());
    }

    #[test]
    fn custom_group_checks() {
        let p = BoxedUint::from_u64(23);
        assert!(DhGroup::from_custom_unchecked(p.clone(), BoxedUint::from_u64(5), 4).is_ok());
        assert!(DhGroup::from_custom_unchecked(p.clone(), BoxedUint::from_u64(1), 4).is_err());
        assert!(DhGroup::from_custom_unchecked(p.clone(), BoxedUint::from_u64(22), 4).is_err());
        assert!(
            DhGroup::from_custom_unchecked(BoxedUint::from_u64(24), BoxedUint::from_u64(5), 4)
                .is_err()
        );
        assert!(DhGroup::from_custom_unchecked(p, BoxedUint::from_u64(5), 0).is_err());
        // Known small answer: 5^6 mod 23 = 8.
        let g = DhGroup::from_custom_unchecked(BoxedUint::from_u64(23), BoxedUint::from_u64(5), 4)
            .unwrap();
        let sk = DhPrivateKey::from_bytes(g, &[6]).unwrap();
        assert_eq!(sk.public_key().to_bytes(), alloc::vec![8]);
    }
}
