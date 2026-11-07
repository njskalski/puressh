//! Key derivation: PBKDF2, bcrypt_pbkdf and HKDF, from the RustCrypto
//! [`pbkdf2`], [`bcrypt_pbkdf`] and [`hkdf`] crates.

use alloc::vec::Vec;

use super::hash::{HmacDigest, HmacOutput};

/// PBKDF2-HMAC-`D` (RFC 8018 §5.2) into `out`.
pub fn pbkdf2<D: HmacDigest>(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<D>(password, salt, iterations, out);
}

/// bcrypt_pbkdf parameters out of range (empty passphrase or salt, zero
/// rounds, or an output length that is zero or over 1024 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BcryptPbkdfError;

/// OpenBSD's `bcrypt_pbkdf`, the KDF of OpenSSH's encrypted private-key
/// format. Returns `out_len` bytes.
pub fn bcrypt_pbkdf(
    passphrase: &[u8],
    salt: &[u8],
    rounds: u32,
    out_len: usize,
) -> Result<Vec<u8>, BcryptPbkdfError> {
    if out_len == 0 || out_len > 1024 {
        return Err(BcryptPbkdfError);
    }
    let mut out = alloc::vec![0u8; out_len];
    bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, rounds, &mut out).map_err(|_| BcryptPbkdfError)?;
    Ok(out)
}

/// HKDF-Extract (RFC 5869 §2.2): the pseudorandom key for `salt` and `ikm`.
pub fn hkdf_extract<D: HmacDigest>(salt: &[u8], ikm: &[u8]) -> HmacOutput<D> {
    hkdf::Hkdf::<D>::extract(Some(salt), ikm).0
}

/// HKDF-Expand (RFC 5869 §2.3) of `prk` with `info` into `out`. Panics if
/// `out` is longer than 255 hash outputs or `prk` is shorter than one.
pub fn hkdf_expand<D: HmacDigest>(prk: &[u8], info: &[u8], out: &mut [u8]) {
    hkdf::Hkdf::<D>::from_prk(prk)
        .expect("HKDF prk is at least one hash output long")
        .expand(info, out)
        .expect("HKDF output is at most 255 hash outputs long");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::Sha256;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5869 test case 1.
    #[test]
    fn hkdf_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = h("000102030405060708090a0b0c");
        let info = h("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract::<Sha256>(&salt, &ikm);
        assert_eq!(
            prk.to_vec(),
            h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let mut okm = [0u8; 42];
        hkdf_expand::<Sha256>(&prk, &info, &mut okm);
        assert_eq!(
            okm.to_vec(),
            h(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    /// RFC 6070 vector 2 (SHA-1 was the RFC's; this is the widely published
    /// SHA-256 analogue: "password" / "salt" / 2 iterations).
    #[test]
    fn pbkdf2_sha256_known_answer() {
        let mut out = [0u8; 32];
        pbkdf2::<Sha256>(b"password", b"salt", 2, &mut out);
        assert_eq!(
            out.to_vec(),
            h("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        );
    }

    #[test]
    fn bcrypt_pbkdf_shape() {
        let a = bcrypt_pbkdf(b"pass", b"salt1234salt1234", 4, 48).unwrap();
        let b = bcrypt_pbkdf(b"pass", b"salt1234salt1234", 4, 48).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 48);
        assert_ne!(
            a,
            bcrypt_pbkdf(b"pasS", b"salt1234salt1234", 4, 48).unwrap()
        );
        assert!(bcrypt_pbkdf(b"pass", b"salt", 0, 48).is_err());
        assert!(bcrypt_pbkdf(b"pass", b"salt", 4, 0).is_err());
    }
}
