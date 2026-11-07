//! Elliptic-curve primitives: X25519, Ed25519 and the NIST curves.
//!
//! * [`X25519PrivateKey`]: RFC 7748 Diffie-Hellman, on `x25519-dalek`.
//! * [`Ed25519PrivateKey`] / [`Ed25519PublicKey`] / [`Ed25519Signature`]:
//!   RFC 8032 signatures, on `ed25519-dalek`.
//! * [`EcdsaPrivateKey`] / [`EcdsaPublicKey`] / [`EcdsaSignature`] and
//!   [`EcdhPrivateKey`]: P-256, P-384 and P-521 for `ecdsa-sha2-nistp*` and
//!   `ecdh-sha2-nistp*`, on the RustCrypto `p256` / `p384` / `p521` crates
//!   with `ecdsa` and `elliptic-curve`. The curve is a run-time [`CurveId`]
//!   so that the SSH layer, which learns the curve from the wire, needs one
//!   type per role rather than one per curve.
//!
//! Every byte format is the one SSH and the key-file formats use: raw
//! 32-byte X25519 and Ed25519 keys, uncompressed SEC1 points, fixed-width
//! big-endian scalars and `(r, s)` signature components.

use alloc::vec::Vec;

use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use elliptic_curve::Generate;
use elliptic_curve::sec1::ToSec1Point;

use super::hash::Digest;
use super::rng::{CryptoRng, RngCore};
use super::zeroize::Zeroizing;

/// An elliptic-curve operation failed: malformed encoding, point not on the
/// curve, scalar out of range, or a signature that does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("elliptic-curve error")
    }
}

// ---------------------------------------------------------------------------
// X25519

/// X25519 small-order peer: the shared secret would be all zeros.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519Error;

/// An X25519 private scalar.
#[derive(Clone)]
pub struct X25519PrivateKey(x25519_dalek::StaticSecret);

impl X25519PrivateKey {
    /// A fresh random key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        X25519PrivateKey(x25519_dalek::StaticSecret::random_from_rng(rng))
    }

    /// From a 32-byte scalar (clamped on use, as RFC 7748 specifies).
    pub fn from_bytes(scalar: [u8; 32]) -> Self {
        X25519PrivateKey(x25519_dalek::StaticSecret::from(scalar))
    }

    /// The scalar bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The public u-coordinate.
    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }

    /// The shared secret with `peer`, or an error if the peer point has small
    /// order (RFC 7748 §6.1's all-zero check).
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<[u8; 32], X25519Error> {
        let shared = self.0.diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
        if shared.was_contributory() {
            Ok(shared.to_bytes())
        } else {
            Err(X25519Error)
        }
    }
}

// ---------------------------------------------------------------------------
// Ed25519

/// An Ed25519 signing key (the 32-byte seed and its expansion).
#[derive(Clone)]
pub struct Ed25519PrivateKey(ed25519_dalek::SigningKey);

/// An Ed25519 public key.
///
/// Constructed infallibly from 32 bytes, like the wire format; an encoding
/// that is not a curve point simply never verifies.
#[derive(Clone)]
pub struct Ed25519PublicKey {
    bytes: [u8; 32],
    key: Option<ed25519_dalek::VerifyingKey>,
}

/// An Ed25519 signature, `R || S`.
#[derive(Clone, Copy)]
pub struct Ed25519Signature(ed25519_dalek::Signature);

impl Ed25519PrivateKey {
    /// A fresh random key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Ed25519PrivateKey(ed25519_dalek::SigningKey::generate(rng))
    }

    /// From the 32-byte seed.
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Ed25519PrivateKey(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// The 32-byte seed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The matching public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        let vk = self.0.verifying_key();
        Ed25519PublicKey {
            bytes: vk.to_bytes(),
            key: Some(vk),
        }
    }

    /// Sign `message` (pure Ed25519, no prehash, no context).
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        use ed25519_dalek::Signer;
        Ed25519Signature(self.0.sign(message))
    }
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        // `SigningKey` zeroizes itself on drop; nothing else to wipe.
    }
}

impl Ed25519PublicKey {
    /// From the 32-byte encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Ed25519PublicKey {
            bytes,
            key: ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok(),
        }
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Verify `signature` over `message`.
    ///
    /// Strict verification: canonical `R`, `A` and `S` encodings, and a
    /// public key of full order. Every signature an honest signer produces
    /// passes; the rejected ones are malleated or forged under weak keys.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), Error> {
        let key = self.key.as_ref().ok_or(Error)?;
        key.verify_strict(message, &signature.0).map_err(|_| Error)
    }
}

impl Ed25519Signature {
    /// From the 64-byte `R || S` encoding.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Ed25519Signature(ed25519_dalek::Signature::from_bytes(&bytes))
    }

    /// The 64-byte encoding.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

// ---------------------------------------------------------------------------
// NIST curves

/// A NIST prime curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurveId {
    /// secp256r1 / prime256v1.
    P256,
    /// secp384r1.
    P384,
    /// secp521r1.
    P521,
}

impl CurveId {
    /// Bytes in a field element (and in a fixed-width scalar).
    pub const fn field_len(self) -> usize {
        match self {
            CurveId::P256 => 32,
            CurveId::P384 => 48,
            CurveId::P521 => 66,
        }
    }

    /// Bytes in a scalar modulo the group order. Equal to the field length
    /// on these curves.
    pub const fn order_len(self) -> usize {
        self.field_len()
    }

    /// Length of an uncompressed SEC1 point.
    pub const fn sec1_len(self) -> usize {
        1 + 2 * self.field_len()
    }
}

macro_rules! per_curve {
    ($self:expr, $k:ident => $body:expr) => {
        match $self {
            Self::P256($k) => $body,
            Self::P384($k) => $body,
            Self::P521($k) => $body,
        }
    };
}

/// A public point on one of the NIST curves.
#[derive(Clone)]
pub enum EcdsaPublicKey {
    /// P-256 point.
    P256(p256::PublicKey),
    /// P-384 point.
    P384(p384::PublicKey),
    /// P-521 point.
    P521(p521::PublicKey),
}

/// A private scalar on one of the NIST curves, for ECDSA signing.
#[derive(Clone)]
pub enum EcdsaPrivateKey {
    /// P-256 scalar.
    P256(p256::SecretKey),
    /// P-384 scalar.
    P384(p384::SecretKey),
    /// P-521 scalar.
    P521(p521::SecretKey),
}

/// A private scalar on one of the NIST curves, for ECDH. The same object
/// as [`EcdsaPrivateKey`]; the alias names the role.
pub type EcdhPrivateKey = EcdsaPrivateKey;

/// An ECDSA signature `(r, s)`.
#[derive(Clone)]
pub enum EcdsaSignature {
    /// P-256 signature.
    P256(p256::ecdsa::Signature),
    /// P-384 signature.
    P384(p384::ecdsa::Signature),
    /// P-521 signature.
    P521(p521::ecdsa::Signature),
}

/// Left-pad `bytes` to `len` with zeros; `None` if it is longer than `len`
/// once leading zeros are dropped.
fn fixed_width(bytes: &[u8], len: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut start = 0;
    while start < bytes.len() && bytes[start] == 0 && bytes.len() - start > len {
        start += 1;
    }
    let bytes = &bytes[start..];
    if bytes.len() > len {
        return None;
    }
    let mut out = Zeroizing::new(alloc::vec![0u8; len]);
    out[len - bytes.len()..].copy_from_slice(bytes);
    Some(out)
}

impl EcdsaPublicKey {
    /// Parse a SEC1 point (uncompressed or compressed) and check it lies on
    /// the curve and is not the identity.
    pub fn from_sec1(curve: CurveId, bytes: &[u8]) -> Result<Self, Error> {
        match curve {
            CurveId::P256 => p256::PublicKey::from_sec1_bytes(bytes).map(Self::P256),
            CurveId::P384 => p384::PublicKey::from_sec1_bytes(bytes).map(Self::P384),
            CurveId::P521 => p521::PublicKey::from_sec1_bytes(bytes).map(Self::P521),
        }
        .map_err(|_| Error)
    }

    /// The uncompressed SEC1 encoding (`0x04 || x || y`).
    pub fn to_sec1(&self) -> Vec<u8> {
        per_curve!(self, k => k.to_sec1_point(false).as_bytes().to_vec())
    }

    /// The curve.
    pub fn curve(&self) -> CurveId {
        match self {
            Self::P256(_) => CurveId::P256,
            Self::P384(_) => CurveId::P384,
            Self::P521(_) => CurveId::P521,
        }
    }

    /// Verify `sig` over `D(msg)`.
    pub fn verify<D: Digest>(&self, msg: &[u8], sig: &EcdsaSignature) -> Result<(), Error> {
        self.verify_prehash(&D::digest(msg), sig)
    }

    /// Verify `sig` over an already hashed message. A prehash longer than
    /// the group order is truncated as FIPS 186-5 specifies.
    pub fn verify_prehash(&self, prehash: &[u8], sig: &EcdsaSignature) -> Result<(), Error> {
        match (self, sig) {
            (Self::P256(k), EcdsaSignature::P256(s)) => {
                p256::ecdsa::VerifyingKey::from(k).verify_prehash(prehash, s)
            }
            (Self::P384(k), EcdsaSignature::P384(s)) => {
                p384::ecdsa::VerifyingKey::from(k).verify_prehash(prehash, s)
            }
            (Self::P521(k), EcdsaSignature::P521(s)) => {
                p521::ecdsa::VerifyingKey::from(k).verify_prehash(prehash, s)
            }
            _ => return Err(Error),
        }
        .map_err(|_| Error)
    }
}

impl EcdsaPrivateKey {
    /// A fresh random key.
    pub fn generate<R: RngCore + CryptoRng>(curve: CurveId, rng: &mut R) -> Self {
        match curve {
            CurveId::P256 => Self::P256(p256::SecretKey::generate_from_rng(rng)),
            CurveId::P384 => Self::P384(p384::SecretKey::generate_from_rng(rng)),
            CurveId::P521 => Self::P521(p521::SecretKey::generate_from_rng(rng)),
        }
    }

    /// From a big-endian scalar, with or without leading zeros. Rejects zero
    /// and values at or above the group order.
    pub fn from_bytes(curve: CurveId, bytes: &[u8]) -> Result<Self, Error> {
        let fixed = fixed_width(bytes, curve.order_len()).ok_or(Error)?;
        match curve {
            CurveId::P256 => p256::SecretKey::from_slice(&fixed).map(Self::P256),
            CurveId::P384 => p384::SecretKey::from_slice(&fixed).map(Self::P384),
            CurveId::P521 => p521::SecretKey::from_slice(&fixed).map(Self::P521),
        }
        .map_err(|_| Error)
    }

    /// The scalar as a fixed-width big-endian integer.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        per_curve!(self, k => Zeroizing::new(k.to_bytes().to_vec()))
    }

    /// The curve.
    pub fn curve(&self) -> CurveId {
        match self {
            Self::P256(_) => CurveId::P256,
            Self::P384(_) => CurveId::P384,
            Self::P521(_) => CurveId::P521,
        }
    }

    /// The public point.
    pub fn public_key(&self) -> EcdsaPublicKey {
        match self {
            Self::P256(k) => EcdsaPublicKey::P256(k.public_key()),
            Self::P384(k) => EcdsaPublicKey::P384(k.public_key()),
            Self::P521(k) => EcdsaPublicKey::P521(k.public_key()),
        }
    }

    /// Sign `D(msg)` with deterministic (RFC 6979) nonces.
    pub fn sign<D: Digest>(&self, msg: &[u8]) -> Result<EcdsaSignature, Error> {
        self.sign_prehash(&D::digest(msg))
    }

    /// Sign an already hashed message.
    pub fn sign_prehash(&self, prehash: &[u8]) -> Result<EcdsaSignature, Error> {
        match self {
            Self::P256(k) => p256::ecdsa::SigningKey::from(k)
                .sign_prehash(prehash)
                .map(EcdsaSignature::P256),
            Self::P384(k) => p384::ecdsa::SigningKey::from(k)
                .sign_prehash(prehash)
                .map(EcdsaSignature::P384),
            Self::P521(k) => p521::ecdsa::SigningKey::from(k)
                .sign_prehash(prehash)
                .map(EcdsaSignature::P521),
        }
        .map_err(|_| Error)
    }

    /// ECDH: the x-coordinate of `[d]Q`, `field_len` bytes. Fails if the peer
    /// is on another curve.
    pub fn diffie_hellman(&self, peer: &EcdsaPublicKey) -> Result<Vec<u8>, Error> {
        match (self, peer) {
            (Self::P256(k), EcdsaPublicKey::P256(p)) => {
                Ok(k.diffie_hellman(p).raw_secret_bytes().to_vec())
            }
            (Self::P384(k), EcdsaPublicKey::P384(p)) => {
                Ok(k.diffie_hellman(p).raw_secret_bytes().to_vec())
            }
            (Self::P521(k), EcdsaPublicKey::P521(p)) => {
                Ok(k.diffie_hellman(p).raw_secret_bytes().to_vec())
            }
            _ => Err(Error),
        }
    }
}

impl EcdsaSignature {
    /// From big-endian `r` and `s`, each with or without leading zeros.
    /// Rejects zero components and values at or above the group order.
    pub fn from_components(curve: CurveId, r: &[u8], s: &[u8]) -> Result<Self, Error> {
        let n = curve.order_len();
        let r = fixed_width(r, n).ok_or(Error)?;
        let s = fixed_width(s, n).ok_or(Error)?;
        let mut rs = Zeroizing::new(Vec::with_capacity(2 * n));
        rs.extend_from_slice(&r);
        rs.extend_from_slice(&s);
        match curve {
            CurveId::P256 => p256::ecdsa::Signature::from_slice(&rs).map(Self::P256),
            CurveId::P384 => p384::ecdsa::Signature::from_slice(&rs).map(Self::P384),
            CurveId::P521 => p521::ecdsa::Signature::from_slice(&rs).map(Self::P521),
        }
        .map_err(|_| Error)
    }

    /// `r` as a fixed-width big-endian integer.
    pub fn r_bytes(&self) -> Vec<u8> {
        per_curve!(self, s => s.split_bytes().0.to_vec())
    }

    /// `s` as a fixed-width big-endian integer.
    pub fn s_bytes(&self) -> Vec<u8> {
        per_curve!(self, s => s.split_bytes().1.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::Sha256;
    use crate::crypto::rng::OsRng;

    #[test]
    fn x25519_rfc7748_vector() {
        let scalar: [u8; 32] =
            hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u: [u8; 32] = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let sk = X25519PrivateKey::from_bytes(scalar);
        assert_eq!(
            sk.diffie_hellman(&u).unwrap(),
            hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
        assert!(sk.diffie_hellman(&[0u8; 32]).is_err());
    }

    #[test]
    fn ed25519_rfc8032_vector_1() {
        let sk = Ed25519PrivateKey::from_bytes(hex32(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let pk = sk.public_key();
        assert_eq!(
            pk.to_bytes(),
            hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let sig = sk.sign(b"");
        assert_eq!(
            &sig.to_bytes()[..8],
            &[0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72]
        );
        pk.verify(b"", &sig).unwrap();
        assert!(pk.verify(b"x", &sig).is_err());
        assert!(
            Ed25519PublicKey::from_bytes([0xff; 32])
                .verify(b"", &sig)
                .is_err()
        );
    }

    #[test]
    fn ecdsa_round_trips_on_every_curve() {
        for curve in [CurveId::P256, CurveId::P384, CurveId::P521] {
            let sk = EcdsaPrivateKey::generate(curve, &mut OsRng);
            let pk = sk.public_key();
            let sec1 = pk.to_sec1();
            assert_eq!(sec1.len(), curve.sec1_len());
            assert_eq!(sec1[0], 0x04);
            let pk2 = EcdsaPublicKey::from_sec1(curve, &sec1).unwrap();
            let sig = sk.sign::<Sha256>(b"msg").unwrap();
            pk2.verify::<Sha256>(b"msg", &sig).unwrap();
            assert!(pk2.verify::<Sha256>(b"other", &sig).is_err());
            let r = sig.r_bytes();
            let s = sig.s_bytes();
            assert_eq!(r.len(), curve.order_len());
            let sig2 = EcdsaSignature::from_components(curve, &r, &s).unwrap();
            pk2.verify::<Sha256>(b"msg", &sig2).unwrap();
            assert!(EcdsaSignature::from_components(curve, &[0u8; 4], &s).is_err());

            let d = sk.to_bytes();
            assert_eq!(d.len(), curve.order_len());
            let sk2 = EcdsaPrivateKey::from_bytes(curve, &d).unwrap();
            assert_eq!(sk2.public_key().to_sec1(), sec1);
            let trimmed = &d[d.iter().position(|&b| b != 0).unwrap()..];
            let sk3 = EcdsaPrivateKey::from_bytes(curve, trimmed).unwrap();
            assert_eq!(sk3.public_key().to_sec1(), sec1);
            assert!(EcdsaPrivateKey::from_bytes(curve, &[0u8; 32]).is_err());

            let other = EcdhPrivateKey::generate(curve, &mut OsRng);
            let a = sk.diffie_hellman(&other.public_key()).unwrap();
            let b = other.diffie_hellman(&pk).unwrap();
            assert_eq!(a, b);
            assert_eq!(a.len(), curve.field_len());
        }
        let p256 = EcdsaPrivateKey::generate(CurveId::P256, &mut OsRng);
        let p384 = EcdsaPrivateKey::generate(CurveId::P384, &mut OsRng);
        assert!(p256.diffie_hellman(&p384.public_key()).is_err());
    }

    #[test]
    fn ecdsa_rejects_off_curve_points() {
        let mut bad = alloc::vec![0x04u8; 65];
        bad[1..].fill(1);
        assert!(EcdsaPublicKey::from_sec1(CurveId::P256, &bad).is_err());
        assert!(EcdsaPublicKey::from_sec1(CurveId::P256, &[0x04]).is_err());
        assert!(EcdsaPublicKey::from_sec1(CurveId::P384, &bad).is_err());
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
