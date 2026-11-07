//! RSA with PKCS#1 v1.5 signatures (`ssh-rsa`, `rsa-sha2-256`,
//! `rsa-sha2-512`), on the RustCrypto [`rsa`] crate.
//!
//! Private operations are blinded with [`OsRng`](super::rng::OsRng), so
//! signing needs the `std` feature; without it `sign_pkcs1v15` fails rather
//! than run unblinded. Keys are built from their integer components exactly
//! as the SSH wire and key-file formats carry them; the library's size
//! bounds (2048 bits minimum for a host or user key) are enforced by the
//! callers in `hostkey::rsa`, this module accepts 1024 to 16384 bits so the
//! tools can still read and fingerprint legacy keys.

use alloc::vec::Vec;

use rsa::traits::{PrivateKeyParts, PublicKeyParts};

use super::bignum::BoxedUint;
use super::hash::Digest;
use super::rng::{CryptoRng, RngCore};

/// A key component out of range, a malformed key, or a signature that does
/// not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

/// A digest with a PKCS#1 `DigestInfo` prefix: SHA-1, SHA-256, SHA-512.
pub trait Pkcs1Digest: Digest + digest::const_oid::AssociatedOid {}
impl<D: Digest + digest::const_oid::AssociatedOid> Pkcs1Digest for D {}

/// Smallest modulus accepted here (the tools read legacy keys; the protocol
/// layer requires 2048).
pub const MIN_MODULUS_BITS: usize = 1024;
/// Largest modulus accepted.
pub const MAX_MODULUS_BITS: usize = 16384;
/// Largest public exponent accepted, in bits.
pub const MAX_EXPONENT_BITS: usize = 64;

fn check_public(n: &BoxedUint, e: &BoxedUint) -> Result<(), Error> {
    let bits = n.bit_len();
    if !n.is_odd() || !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) {
        return Err(Error);
    }
    if !e.is_odd() || *e < BoxedUint::from_u64(3) || e.bit_len() > MAX_EXPONENT_BITS || *e >= *n {
        return Err(Error);
    }
    Ok(())
}

fn inner(u: &BoxedUint) -> crypto_bigint::BoxedUint {
    crypto_bigint::BoxedUint::from_be_slice_vartime(&u.to_be_bytes(u.byte_len().max(1)))
}

fn outer(u: &crypto_bigint::BoxedUint) -> BoxedUint {
    BoxedUint::from_be_bytes(&u.to_be_bytes_trimmed_vartime())
}

/// An RSA public key `(n, e)`.
#[derive(Clone)]
pub struct RsaPublicKey(rsa::PublicKey);

impl RsaPublicKey {
    /// From the modulus and public exponent, checking their ranges.
    pub fn try_new(n: BoxedUint, e: BoxedUint) -> Result<Self, Error> {
        check_public(&n, &e)?;
        Ok(RsaPublicKey(rsa::PublicKey::new_unchecked(
            inner(&n),
            inner(&e),
        )))
    }

    /// `n`.
    pub fn modulus(&self) -> BoxedUint {
        outer(self.0.n().as_ref())
    }

    /// `e`.
    pub fn exponent(&self) -> BoxedUint {
        outer(self.0.e())
    }

    /// Bytes in `n`.
    pub fn size(&self) -> usize {
        self.0.size()
    }

    /// Verify a PKCS#1 v1.5 signature over `D(msg)`. `sig` may be shorter
    /// than the modulus (leading zeros stripped); it is left-padded.
    pub fn verify_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let k = self.0.size();
        if sig.len() > k {
            return Err(Error);
        }
        let mut padded = alloc::vec![0u8; k];
        padded[k - sig.len()..].copy_from_slice(sig);
        let hashed = D::digest(msg);
        self.0
            .verify(rsa::Pkcs1v15Sign::new::<D>(), &hashed, &padded)
            .map_err(|_| Error)
    }
}

/// An RSA private key.
#[derive(Clone)]
pub struct RsaPrivateKey(rsa::PrivateKey);

impl RsaPrivateKey {
    /// From `(n, e, d)`; the prime factors are recovered from them.
    pub fn from_components(n: BoxedUint, e: BoxedUint, d: BoxedUint) -> Result<Self, Error> {
        check_public(&n, &e)?;
        rsa::PrivateKey::from_components_with_large_exponent(
            inner(&n),
            inner(&e),
            inner(&d),
            Vec::new(),
        )
        .map(RsaPrivateKey)
        .map_err(|_| Error)
    }

    /// From `(n, e, d, p, q)`. Checks `p * q == n`.
    pub fn from_components_with_primes(
        n: BoxedUint,
        e: BoxedUint,
        d: BoxedUint,
        p: BoxedUint,
        q: BoxedUint,
    ) -> Result<Self, Error> {
        check_public(&n, &e)?;
        rsa::PrivateKey::from_components_with_large_exponent(
            inner(&n),
            inner(&e),
            inner(&d),
            alloc::vec![inner(&p), inner(&q)],
        )
        .map(RsaPrivateKey)
        .map_err(|_| Error)
    }

    /// Generate a `bits`-bit key with public exponent `e`.
    pub fn generate<R: RngCore + CryptoRng>(
        bits: usize,
        e: BoxedUint,
        rng: &mut R,
    ) -> Result<Self, Error> {
        if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) {
            return Err(Error);
        }
        rsa::PrivateKey::new_with_exp(rng, bits, inner(&e))
            .map(RsaPrivateKey)
            .map_err(|_| Error)
    }

    /// The public half.
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey(self.0.to_public_key())
    }

    /// `n`.
    pub fn modulus(&self) -> BoxedUint {
        outer(self.0.n().as_ref())
    }

    /// `e`.
    pub fn exponent(&self) -> BoxedUint {
        outer(self.0.e())
    }

    /// `d`.
    pub fn private_exponent(&self) -> BoxedUint {
        outer(self.0.d())
    }

    /// `(p, q)`.
    pub fn primes(&self) -> Option<(BoxedUint, BoxedUint)> {
        let primes = self.0.primes();
        if primes.len() != 2 {
            return None;
        }
        Some((outer(primes[0].as_ref()), outer(primes[1].as_ref())))
    }

    /// Sign `D(msg)` with PKCS#1 v1.5, blinded with the OS RNG.
    #[cfg(feature = "std")]
    pub fn sign_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let hashed = D::digest(msg);
        self.0
            .sign_with_rng(
                &mut super::rng::OsRng,
                rsa::Pkcs1v15Sign::new::<D>(),
                &hashed,
            )
            .map_err(|_| Error)
    }

    /// Signing needs the OS RNG for blinding, which needs `std`.
    #[cfg(not(feature = "std"))]
    pub fn sign_pkcs1v15<D: Pkcs1Digest>(&self, _msg: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::{Sha1, Sha256, Sha512};
    use crate::crypto::rng::OsRng;

    #[test]
    fn generate_sign_verify_round_trip() {
        let sk = RsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut OsRng).unwrap();
        let pk = sk.public_key();
        assert_eq!(pk.modulus().bit_len(), 1024);
        assert_eq!(pk.exponent(), BoxedUint::from_u64(65537));
        for sig_ok in [
            sk.sign_pkcs1v15::<Sha256>(b"msg").unwrap(),
            sk.sign_pkcs1v15::<Sha512>(b"msg").unwrap(),
            sk.sign_pkcs1v15::<Sha1>(b"msg").unwrap(),
        ] {
            assert_eq!(sig_ok.len(), 128);
        }
        let sig = sk.sign_pkcs1v15::<Sha256>(b"msg").unwrap();
        pk.verify_pkcs1v15::<Sha256>(b"msg", &sig).unwrap();
        assert!(pk.verify_pkcs1v15::<Sha256>(b"other", &sig).is_err());
        assert!(pk.verify_pkcs1v15::<Sha512>(b"msg", &sig).is_err());

        // Rebuild from components, with and without primes.
        let (p, q) = sk.primes().unwrap();
        let again = RsaPrivateKey::from_components_with_primes(
            sk.modulus(),
            sk.exponent(),
            sk.private_exponent(),
            p.clone(),
            q,
        )
        .unwrap();
        again
            .public_key()
            .verify_pkcs1v15::<Sha256>(b"msg", &sig)
            .unwrap();
        let recovered =
            RsaPrivateKey::from_components(sk.modulus(), sk.exponent(), sk.private_exponent())
                .unwrap();
        assert_eq!(
            recovered.primes().map(|(a, b)| a.mul(&b)),
            Some(sk.modulus())
        );
        assert!(
            RsaPrivateKey::from_components_with_primes(
                sk.modulus(),
                sk.exponent(),
                sk.private_exponent(),
                p.clone(),
                p,
            )
            .is_err()
        );
    }

    #[test]
    fn public_key_bounds() {
        let sk = RsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut OsRng).unwrap();
        let n = sk.modulus();
        assert!(RsaPublicKey::try_new(n.clone(), BoxedUint::from_u64(2)).is_err());
        assert!(RsaPublicKey::try_new(n.clone(), BoxedUint::from_u64(1)).is_err());
        assert!(RsaPublicKey::try_new(n.clone(), n.clone()).is_err());
        assert!(RsaPublicKey::try_new(BoxedUint::from_u64(65537), BoxedUint::from_u64(3)).is_err());
        assert!(
            RsaPublicKey::try_new(n.add(&BoxedUint::from_u64(1)), BoxedUint::from_u64(65537))
                .is_err()
        );
        assert!(RsaPublicKey::try_new(n, BoxedUint::from_be_bytes(&[0x01; 9])).is_err());
    }
}
