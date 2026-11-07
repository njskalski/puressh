//! Hash functions and HMAC.
//!
//! The digests are the RustCrypto types re-exported under short names; the
//! [`Digest`] trait is [`digest::Digest`], so `D::digest(data)`, `D::new()`,
//! `update` and `finalize` behave as every other crate in the ecosystem
//! expects. A digest's `finalize()` yields a fixed-size [`Output<D>`] array
//! that dereferences to `[u8]` and converts into `[u8; N]` with `.into()`.
//!
//! [`Hmac`] is a thin wrapper around [`hmac::Hmac`] with the handful of
//! methods SSH needs: one-shot [`Hmac::mac`], incremental `update` /
//! `finalize`, and a constant-time [`Hmac::verify`].

pub use digest::{Digest, FixedOutput, Output, OutputSizeUser, Update};
pub use md5::Md5;
pub use sha1::Sha1;
pub use sha2::{Sha256, Sha384, Sha512};

pub use digest::block_api::EagerHash as HmacDigest;
use digest::{KeyInit, Mac};

/// The tag type of [`Hmac<D>`].
pub type HmacOutput<D> = Output<hmac::Hmac<D>>;

/// Output length of `D` in bytes.
#[inline]
pub fn output_len<D: OutputSizeUser>() -> usize {
    <D as OutputSizeUser>::output_size()
}

/// HMAC over the digest `D` (RFC 2104).
pub struct Hmac<D: HmacDigest>(hmac::Hmac<D>);

impl<D: HmacDigest> Clone for Hmac<D> {
    fn clone(&self) -> Self {
        Hmac(self.0.clone())
    }
}

impl<D: HmacDigest> Hmac<D> {
    /// Key the MAC. Any key length is accepted: longer keys are hashed first,
    /// as the RFC specifies.
    pub fn new(key: &[u8]) -> Self {
        Hmac(hmac::Hmac::<D>::new_from_slice(key).expect("HMAC accepts any key length"))
    }

    /// Feed more message bytes.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        Mac::update(&mut self.0, data);
    }

    /// Feed more message bytes, by value.
    #[inline]
    pub fn chain(mut self, data: &[u8]) -> Self {
        Mac::update(&mut self.0, data);
        self
    }

    /// Finish and return the tag.
    #[inline]
    pub fn finalize(self) -> HmacOutput<D> {
        self.0.finalize().into_bytes()
    }

    /// Finish and compare with `expected` in constant time. `expected` may be
    /// a truncated (left-most bytes) tag, as SSH's `-96` MACs use.
    #[inline]
    pub fn verify(self, expected: &[u8]) -> subtle::Choice {
        let tag = self.0.finalize().into_bytes();
        if expected.is_empty() || expected.len() > tag.len() {
            return subtle::Choice::from(0);
        }
        subtle::ConstantTimeEq::ct_eq(&tag[..expected.len()], expected)
    }

    /// One-shot HMAC.
    pub fn mac(key: &[u8], data: &[u8]) -> HmacOutput<D> {
        let mut m = Self::new(key);
        m.update(data);
        m.finalize()
    }
}

/// HMAC-SHA-256.
pub type HmacSha256 = Hmac<Sha256>;
/// HMAC-SHA-512.
pub type HmacSha512 = Hmac<Sha512>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_rfc4231_case_2() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let tag = Hmac::<Sha256>::mac(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let mut m = Hmac::<Sha256>::new(b"Jefe");
        m.update(b"what do ya want ");
        m.update(b"for nothing?");
        assert!(bool::from(m.clone().verify(&tag)));
        assert!(bool::from(m.clone().verify(&tag[..12])));
        assert!(!bool::from(m.verify(&[0u8; 32])));
    }

    #[test]
    fn digest_shapes() {
        let h = Sha256::digest(b"abc");
        let arr: [u8; 32] = h.into();
        assert_eq!(
            hex(&arr),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(output_len::<Sha512>(), 64);
        assert_eq!(output_len::<Sha1>(), 20);
        assert_eq!(output_len::<Md5>(), 16);
    }

    fn hex(b: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for x in b {
            write!(s, "{x:02x}").unwrap();
        }
        s
    }
}
