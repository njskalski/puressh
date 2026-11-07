//! ML-KEM-768 (FIPS 203) for the `mlkem768x25519-sha256` and
//! `mlkem768nistp256-sha256` hybrid key exchanges, on the RustCrypto
//! [`ml_kem`] crate.

use kem::{Decapsulate, Decapsulator, Encapsulate, FromSeed, Kem};
use ml_kem::{KeyExport, MlKem768};

use super::rng::{CryptoRng, RngCore};

/// Bytes in an ML-KEM-768 encapsulation (public) key.
pub const ENCAPS_KEY_BYTES: usize = 1184;
/// Bytes in an ML-KEM-768 ciphertext.
pub const CIPHERTEXT_BYTES: usize = 1088;
/// Bytes in the shared secret.
pub const SHARED_SECRET_BYTES: usize = 32;

/// An encapsulation key that failed FIPS 203's modulus check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncapsKeyCheckError;

/// An ML-KEM-768 decapsulation (private) key.
pub struct MlKem768DecapsKey(ml_kem::DecapsulationKey<MlKem768>);

/// An ML-KEM-768 encapsulation (public) key.
#[derive(Clone)]
pub struct MlKem768EncapsKey(ml_kem::EncapsulationKey<MlKem768>);

/// An ML-KEM-768 ciphertext.
#[derive(Clone)]
pub struct MlKem768Ciphertext(kem::Ciphertext<MlKem768>);

impl MlKem768DecapsKey {
    /// Bytes in the matching encapsulation key.
    pub const ENCAPS_KEY_BYTES: usize = ENCAPS_KEY_BYTES;
    /// Bytes in a ciphertext.
    pub const CIPHERTEXT_BYTES: usize = CIPHERTEXT_BYTES;

    /// A fresh key pair.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> (Self, MlKem768EncapsKey) {
        let (dk, ek) = MlKem768::generate_keypair_from_rng(rng);
        (MlKem768DecapsKey(dk), MlKem768EncapsKey(ek))
    }

    /// The key pair for the seeds `(d, z)` (FIPS 203 Algorithm 16's inputs);
    /// deterministic, for known-answer tests.
    pub fn from_seeds(d: &[u8; 32], z: &[u8; 32]) -> (Self, MlKem768EncapsKey) {
        let mut seed = kem::Seed::<MlKem768>::default();
        seed[..32].copy_from_slice(d);
        seed[32..].copy_from_slice(z);
        let (dk, ek) = MlKem768::from_seed(&seed);
        (MlKem768DecapsKey(dk), MlKem768EncapsKey(ek))
    }

    /// The matching encapsulation key.
    pub fn encapsulation_key(&self) -> MlKem768EncapsKey {
        MlKem768EncapsKey(Decapsulator::encapsulation_key(&self.0).clone())
    }

    /// Recover the shared secret from `ct`. Implicit rejection: an invalid
    /// ciphertext yields a pseudorandom secret, never an error.
    pub fn decapsulate(&self, ct: &MlKem768Ciphertext) -> [u8; SHARED_SECRET_BYTES] {
        self.0.decapsulate(&ct.0).into()
    }
}

impl MlKem768EncapsKey {
    /// Parse and check an encapsulation key (FIPS 203 §7.2 modulus check).
    pub fn from_bytes_validated(
        bytes: [u8; ENCAPS_KEY_BYTES],
    ) -> Result<Self, EncapsKeyCheckError> {
        ml_kem::EncapsulationKey::<MlKem768>::new(&bytes.into())
            .map(MlKem768EncapsKey)
            .map_err(|_| EncapsKeyCheckError)
    }

    /// The encoded key.
    pub fn to_bytes(&self) -> [u8; ENCAPS_KEY_BYTES] {
        KeyExport::to_bytes(&self.0).into()
    }

    /// Encapsulate a fresh shared secret.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (MlKem768Ciphertext, [u8; SHARED_SECRET_BYTES]) {
        let (ct, ss) = self.0.encapsulate_with_rng(rng);
        (MlKem768Ciphertext(ct), ss.into())
    }

    /// Encapsulate with the explicit randomness `m` (known-answer tests).
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8; 32],
    ) -> (MlKem768Ciphertext, [u8; SHARED_SECRET_BYTES]) {
        let (ct, ss) = self.0.encapsulate_deterministic(&(*m).into());
        (MlKem768Ciphertext(ct), ss.into())
    }
}

impl MlKem768Ciphertext {
    /// From the wire bytes.
    pub fn from_bytes(bytes: [u8; CIPHERTEXT_BYTES]) -> Self {
        MlKem768Ciphertext(bytes.into())
    }

    /// The wire bytes.
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        self.0.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rng::OsRng;

    #[test]
    fn round_trip_and_sizes() {
        let (dk, ek) = MlKem768DecapsKey::generate(&mut OsRng);
        let ek_bytes = ek.to_bytes();
        assert_eq!(ek_bytes.len(), 1184);
        let ek2 = MlKem768EncapsKey::from_bytes_validated(ek_bytes).unwrap();
        let (ct, ss) = ek2.encapsulate(&mut OsRng);
        assert_eq!(ct.to_bytes().len(), 1088);
        let ss2 = dk.decapsulate(&MlKem768Ciphertext::from_bytes(ct.to_bytes()));
        assert_eq!(ss, ss2);
        assert_eq!(dk.encapsulation_key().to_bytes(), ek_bytes);
        // Implicit rejection: a corrupted ciphertext gives a different secret.
        let mut bad = ct.to_bytes();
        bad[0] ^= 1;
        assert_ne!(dk.decapsulate(&MlKem768Ciphertext::from_bytes(bad)), ss);
        // Modulus check: all 0xff coefficients are out of range.
        assert!(MlKem768EncapsKey::from_bytes_validated([0xff; 1184]).is_err());
    }

    #[test]
    fn deterministic_paths_agree() {
        let (dk, ek) = MlKem768DecapsKey::from_seeds(&[1u8; 32], &[2u8; 32]);
        let (dk2, ek2) = MlKem768DecapsKey::from_seeds(&[1u8; 32], &[2u8; 32]);
        assert_eq!(ek.to_bytes(), ek2.to_bytes());
        let (ct, ss) = ek.encapsulate_deterministic(&[3u8; 32]);
        let (ct2, ss2) = ek2.encapsulate_deterministic(&[3u8; 32]);
        assert_eq!(ct.to_bytes(), ct2.to_bytes());
        assert_eq!(ss, ss2);
        assert_eq!(dk.decapsulate(&ct), ss);
        assert_eq!(dk2.decapsulate(&ct), ss);
    }
}
