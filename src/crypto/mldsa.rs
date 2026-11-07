//! ML-DSA-44 (FIPS 204) for the `ssh-mldsa44-ed25519` composite signature,
//! on the RustCrypto [`ml_dsa`] crate.

use ml_dsa::MlDsa44;

use super::rng::{CryptoRng, RngCore};

/// Bytes in an ML-DSA-44 public key.
pub const PUBLIC_KEY_BYTES: usize = 1312;
/// Bytes in an ML-DSA-44 signature.
pub const SIGNATURE_BYTES: usize = 2420;
/// Bytes in the key-generation seed.
pub const SEED_SIZE: usize = 32;

/// A malformed key, a context string over 255 bytes, or (for `verify`) a
/// signature that does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

/// An ML-DSA-44 signing key, kept as its 32-byte seed.
pub struct MlDsa44PrivateKey(ml_dsa::SigningKey<MlDsa44>);

/// An ML-DSA-44 verification key.
#[derive(Clone)]
pub struct MlDsa44PublicKey {
    key: ml_dsa::VerifyingKey<MlDsa44>,
    encoded: ml_dsa::EncodedVerifyingKey<MlDsa44>,
}

impl MlDsa44PrivateKey {
    /// The key pair derived from `seed` (FIPS 204 Algorithm 6).
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> (Self, MlDsa44PublicKey) {
        let sk = ml_dsa::SigningKey::<MlDsa44>::from_seed(&(*seed).into());
        let vk = sk.expanded_key().verifying_key();
        let encoded = vk.encode();
        (MlDsa44PrivateKey(sk), MlDsa44PublicKey { key: vk, encoded })
    }

    /// A fresh random key pair.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> (Self, MlDsa44PublicKey) {
        let mut seed = super::zeroize::Zeroizing::new([0u8; SEED_SIZE]);
        rng.fill_bytes(&mut *seed);
        Self::from_seed(&seed)
    }

    /// The matching public key.
    pub fn public_key(&self) -> MlDsa44PublicKey {
        let vk = self.0.expanded_key().verifying_key();
        let encoded = vk.encode();
        MlDsa44PublicKey { key: vk, encoded }
    }

    /// Sign `msg` under context `ctx` with hedged (randomised) signing.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<[u8; SIGNATURE_BYTES], Error> {
        let sig = self
            .0
            .expanded_key()
            .sign_randomized(msg, ctx, rng)
            .map_err(|_| Error)?;
        Ok(sig.encode().into())
    }

    /// Sign `msg` under context `ctx` deterministically.
    pub fn sign_deterministic(
        &self,
        msg: &[u8],
        ctx: &[u8],
    ) -> Result<[u8; SIGNATURE_BYTES], Error> {
        let sig = self
            .0
            .expanded_key()
            .sign_deterministic(msg, ctx)
            .map_err(|_| Error)?;
        Ok(sig.encode().into())
    }
}

impl MlDsa44PublicKey {
    /// Parse an encoded public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(bytes).map_err(|_| Error)?;
        let key = ml_dsa::VerifyingKey::<MlDsa44>::decode(&encoded);
        Ok(MlDsa44PublicKey { key, encoded })
    }

    /// The encoded public key.
    pub fn to_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Verify `sig` over `msg` under context `ctx`. Returns `false` for a
    /// malformed signature as well as a wrong one.
    pub fn verify(&self, sig: &[u8], msg: &[u8], ctx: &[u8]) -> bool {
        let Ok(encoded) = ml_dsa::EncodedSignature::<MlDsa44>::try_from(sig) else {
            return false;
        };
        let Some(sig) = ml_dsa::Signature::<MlDsa44>::decode(&encoded) else {
            return false;
        };
        self.key.verify_with_context(msg, ctx, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::OsRng;

    #[test]
    fn sign_verify_round_trip() {
        let (sk, pk) = MlDsa44PrivateKey::from_seed(&[7u8; 32]);
        assert_eq!(pk.to_bytes().len(), PUBLIC_KEY_BYTES);
        let sig = sk.sign(&mut OsRng, b"msg", b"ctx").unwrap();
        assert_eq!(sig.len(), SIGNATURE_BYTES);
        assert!(pk.verify(&sig, b"msg", b"ctx"));
        assert!(!pk.verify(&sig, b"msg", b"other"));
        assert!(!pk.verify(&sig, b"msG", b"ctx"));
        assert!(!pk.verify(&sig[..100], b"msg", b"ctx"));
        let det = sk.sign_deterministic(b"msg", b"ctx").unwrap();
        assert_eq!(det, sk.sign_deterministic(b"msg", b"ctx").unwrap());
        assert!(pk.verify(&det, b"msg", b"ctx"));
        let pk2 = MlDsa44PublicKey::from_bytes(pk.to_bytes()).unwrap();
        assert!(pk2.verify(&sig, b"msg", b"ctx"));
        assert_eq!(sk.public_key().to_bytes(), pk.to_bytes());
        assert!(MlDsa44PublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(sk.sign(&mut OsRng, b"m", &[0u8; 256]).is_err());
    }
}
