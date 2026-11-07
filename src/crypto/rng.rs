//! Random number generation.
//!
//! [`OsRng`] is the operating system's CSPRNG, read from `/dev/urandom`
//! with plain `std::fs` so that no foreign function is involved (it needs
//! the `std` feature). The traits are [`rand_core`]'s: [`RngCore`] is what every
//! `generate`-style function in this crate takes, [`CryptoRng`] marks the
//! generators fit for key material. Both are implemented for `OsRng`, so a
//! `&mut OsRng` can be passed wherever the dalek, RustCrypto or puressh APIs
//! ask for a random source.
//!
//! [`HmacDrbg`] is SP 800-90A's HMAC_DRBG, a deterministic generator used by
//! the known-answer tests to drive a key exchange from a fixed seed.

use core::convert::Infallible;

pub use rand_core::{CryptoRng, Rng as RngCore, TryCryptoRng, TryRng};

use digest::block_api::EagerHash;
use digest::{KeyInit, Mac, Output};

/// The operating system's random source: `/dev/urandom`.
///
/// Failure to read it is treated as fatal: there is no safe way to continue
/// a key exchange without randomness, so `fill_bytes` panics the way the
/// `rand` crate's `OsRng` does. Linux has fed `/dev/urandom` from the same
/// pool as `getrandom(2)` since 5.6, and every other supported Unix either
/// does the same or never blocks on it, so reading the device is equivalent
/// to the system call without the foreign call.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

#[cfg(feature = "std")]
fn fill_from_os(dst: &mut [u8]) {
    use std::io::Read;
    std::thread_local! {
        static URANDOM: core::cell::RefCell<Option<std::fs::File>> =
            const { core::cell::RefCell::new(None) };
    }
    URANDOM.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(
                std::fs::File::open("/dev/urandom").expect("OsRng: opening /dev/urandom failed"),
            );
        }
        if let Err(e) = slot.as_mut().expect("just opened").read_exact(dst) {
            // Retry once with a fresh descriptor (the old one may have been
            // closed under us by a fork or a misbehaving library).
            *slot = None;
            let mut f = std::fs::File::open("/dev/urandom").unwrap_or_else(|e2| {
                panic!("OsRng: reopening /dev/urandom failed: {e2} (after {e})")
            });
            f.read_exact(dst)
                .expect("OsRng: reading /dev/urandom failed");
            *slot = Some(f);
        }
    });
}

#[cfg(feature = "std")]
impl TryRng for OsRng {
    type Error = Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    #[inline]
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        if dst.is_empty() {
            return Ok(());
        }
        fill_from_os(dst);
        Ok(())
    }
}

#[cfg(feature = "std")]
impl TryCryptoRng for OsRng {}

/// HMAC_DRBG (NIST SP 800-90A §10.1.2) over the digest `D`.
///
/// Deterministic for a given seed; used by tests that need reproducible
/// key-exchange transcripts. Not reseeded automatically: after 2^48
/// requests `generate` panics, which no test comes near.
#[derive(Clone)]
pub struct HmacDrbg<D: EagerHash> {
    keyed: hmac::Hmac<D>,
    v: Output<hmac::Hmac<D>>,
    reseed_counter: u64,
}

const RESEED_INTERVAL: u64 = 1u64 << 48;
const MAX_BYTES_PER_REQUEST: usize = 1 << 16;

impl<D: EagerHash> HmacDrbg<D> {
    /// Instantiate from `entropy || nonce || personalization`.
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Self {
        assert!(
            !entropy.is_empty(),
            "HMAC-DRBG requires non-empty entropy input (SP 800-90A §8.6.5)"
        );
        let out_len = <hmac::Hmac<D> as digest::OutputSizeUser>::output_size();
        let mut v: Output<hmac::Hmac<D>> = Default::default();
        v.iter_mut().for_each(|b| *b = 0x01);
        let zero_key = alloc::vec![0u8; out_len];
        let mut drbg = HmacDrbg {
            keyed: hmac::Hmac::<D>::new_from_slice(&zero_key).expect("HMAC key length"),
            v,
            reseed_counter: 1,
        };
        drbg.update(&[entropy, nonce, personalization]);
        drbg
    }

    fn mac_v(&self) -> Output<hmac::Hmac<D>> {
        let mut m = self.keyed.clone();
        Mac::update(&mut m, &self.v);
        m.finalize().into_bytes()
    }

    fn rekey(&mut self, sep: u8, provided: &[&[u8]]) {
        let mut m = self.keyed.clone();
        Mac::update(&mut m, &self.v);
        Mac::update(&mut m, &[sep]);
        for p in provided {
            Mac::update(&mut m, p);
        }
        let mut k = m.finalize().into_bytes();
        self.keyed = hmac::Hmac::<D>::new_from_slice(&k).expect("HMAC key length");
        zeroize::Zeroize::zeroize(k.as_mut_slice());
        self.v = self.mac_v();
    }

    fn update(&mut self, provided: &[&[u8]]) {
        self.rekey(0x00, provided);
        if provided.iter().any(|p| !p.is_empty()) {
            self.rekey(0x01, provided);
        }
    }

    /// Mix in fresh entropy (§10.1.2.4).
    pub fn reseed(&mut self, entropy: &[u8], additional: &[u8]) {
        assert!(
            !entropy.is_empty(),
            "HMAC-DRBG reseed requires non-empty entropy input (SP 800-90A §9.2)"
        );
        self.update(&[entropy, additional]);
        self.reseed_counter = 1;
    }

    /// Fill `out` with pseudo-random bytes (§10.1.2.5), splitting requests
    /// longer than the 2^16-byte maximum.
    pub fn generate(&mut self, out: &mut [u8], additional: &[u8]) {
        if out.len() <= MAX_BYTES_PER_REQUEST {
            self.generate_request(out, additional);
            return;
        }
        let mut first = true;
        for chunk in out.chunks_mut(MAX_BYTES_PER_REQUEST) {
            self.generate_request(chunk, if first { additional } else { &[] });
            first = false;
        }
    }

    fn generate_request(&mut self, out: &mut [u8], additional: &[u8]) {
        assert!(
            self.reseed_counter < RESEED_INTERVAL,
            "HMAC-DRBG reseed interval exceeded (SP 800-90A §10.1.2.4); call reseed() first"
        );
        if !additional.is_empty() {
            self.update(&[additional]);
        }
        let mut filled = 0;
        while filled < out.len() {
            self.v = self.mac_v();
            let n = (out.len() - filled).min(self.v.len());
            out[filled..filled + n].copy_from_slice(&self.v[..n]);
            filled += n;
        }
        self.update(&[additional]);
        self.reseed_counter += 1;
    }
}

impl<D: EagerHash> Drop for HmacDrbg<D> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self.v.as_mut_slice());
    }
}

impl<D: EagerHash> TryRng for HmacDrbg<D> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.generate(&mut b, &[]);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.generate(&mut b, &[]);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.generate(dst, &[]);
        Ok(())
    }
}

impl<D: EagerHash> TryCryptoRng for HmacDrbg<D> {}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    fn from_hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// NIST CAVP HMAC_DRBG SHA-256, no reseed, no additional input, count 0.
    #[test]
    fn nist_hmac_drbg_sha256() {
        let entropy =
            from_hex::<32>("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488");
        let nonce = from_hex::<16>("659ba96c601dc69fc902940805ec0ca8");
        let expected = from_hex::<128>(
            "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89\
             d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1\
             07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668\
             961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
        );
        let mut drbg = HmacDrbg::<Sha256>::new(&entropy, &nonce, &[]);
        let mut buf = [0u8; 128];
        drbg.generate(&mut buf, &[]);
        drbg.generate(&mut buf, &[]);
        assert_eq!(buf, expected);
    }

    #[test]
    #[cfg(feature = "std")]
    fn os_rng_fills() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut a);
        OsRng.fill_bytes(&mut b);
        assert_ne!(a, b);
        fn takes_crypto<R: RngCore + CryptoRng>(_r: &mut R) {}
        takes_crypto(&mut OsRng);
        takes_crypto(&mut HmacDrbg::<Sha256>::new(&[1], &[], &[]));
    }
}
