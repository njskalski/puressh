//! Symmetric ciphers: AES in CTR, CBC and GCM, ChaCha20 with Poly1305, and
//! DES / 3DES in CBC for legacy key files.
//!
//! Block ciphers are the RustCrypto [`aes`] and [`des`] crates; CTR and GCM
//! are the [`ctr`] and [`aes_gcm`] crates; the ChaCha20 keystream and the
//! Poly1305 one-time authenticator are [`chacha20`] and [`poly1305`]. The
//! OpenSSH `chacha20-poly1305@openssh.com` construction (two keys, the
//! length-encrypting one with counter 0, the Poly1305 key from block 0 of the
//! payload key) is assembled in `hazmat::cipher::chachapoly` from the two
//! primitives exposed here, exactly as OpenSSH assembles it.
//!
//! CBC is a few lines of chaining over the block cipher, written here rather
//! than taken from the `cbc` crate because SSH needs one object that can run
//! either direction across packets; it is checked against the NIST vectors in
//! `hazmat::cipher::cbc`.

use alloc::vec::Vec;

use cipher::{
    Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit, KeyIvInit, StreamCipher,
    StreamCipherSeek,
};

use super::zeroize::{Zeroize, Zeroizing};

pub use aes::{Aes128, Aes192, Aes256};
pub use des::{Des, TdesEde3};

/// A key, IV or data buffer of the wrong length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLength;

/// An authentication tag did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagMismatch;

// ---------------------------------------------------------------------------
// CTR

/// A block cipher in CTR mode with a 128-bit big-endian counter (RFC 4344's
/// `aes*-ctr`).
pub struct Ctr<C: BlockCipherEncrypt + BlockSizeUser<BlockSize = cipher::consts::U16>>(
    ctr::Ctr128BE<C>,
);

impl<C> Ctr<C>
where
    C: BlockCipherEncrypt + KeyInit + BlockSizeUser<BlockSize = cipher::consts::U16>,
{
    /// Key the cipher and set the initial counter block.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        ctr::Ctr128BE::<C>::new_from_slices(key, iv)
            .map(Ctr)
            .map_err(|_| InvalidLength)
    }

    /// XOR the next `buf.len()` keystream bytes into `buf`.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}

/// AES-128-CTR.
pub type Aes128Ctr = Ctr<Aes128>;
/// AES-192-CTR.
pub type Aes192Ctr = Ctr<Aes192>;
/// AES-256-CTR.
pub type Aes256Ctr = Ctr<Aes256>;

// ---------------------------------------------------------------------------
// CBC

/// A block cipher in CBC mode. One object encrypts or decrypts a stream of
/// block-aligned buffers; the chaining value carries across calls.
pub struct Cbc<C: BlockCipherEncrypt + BlockCipherDecrypt> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt + KeyInit> Cbc<C> {
    /// Key the cipher and set the IV.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        let cipher = C::new_from_slice(key).map_err(|_| InvalidLength)?;
        if iv.len() != C::block_size() {
            return Err(InvalidLength);
        }
        Ok(Cbc {
            cipher,
            iv: Block::<C>::try_from(iv).map_err(|_| InvalidLength)?,
        })
    }

    /// The block size in bytes.
    pub fn block_size(&self) -> usize {
        C::block_size()
    }

    /// Encrypt `data` in place; it must be a whole number of blocks.
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<(), InvalidLength> {
        let (blocks, rest) = Block::<C>::slice_as_chunks_mut(data);
        if !rest.is_empty() {
            return Err(InvalidLength);
        }
        for block in blocks {
            for (b, v) in block.iter_mut().zip(self.iv.iter()) {
                *b ^= v;
            }
            self.cipher.encrypt_block(block);
            self.iv.copy_from_slice(block);
        }
        Ok(())
    }

    /// Decrypt `data` in place; it must be a whole number of blocks.
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result<(), InvalidLength> {
        let (blocks, rest) = Block::<C>::slice_as_chunks_mut(data);
        if !rest.is_empty() {
            return Err(InvalidLength);
        }
        for block in blocks {
            let next_iv = block.clone();
            self.cipher.decrypt_block(block);
            for (b, v) in block.iter_mut().zip(self.iv.iter()) {
                *b ^= v;
            }
            self.iv = next_iv;
        }
        Ok(())
    }
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt> Drop for Cbc<C> {
    fn drop(&mut self) {
        self.iv.as_mut_slice().zeroize();
    }
}

// ---------------------------------------------------------------------------
// GCM

/// AES-GCM with a 96-bit nonce and a 128-bit tag.
pub struct Gcm<C>(aes_gcm::AesGcm<C, cipher::consts::U12>)
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = cipher::consts::U16> + KeyInit;

impl<C> Gcm<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = cipher::consts::U16> + KeyInit,
{
    /// Key the cipher.
    pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        aes_gcm::AesGcm::<C, cipher::consts::U12>::new_from_slice(key)
            .map(Gcm)
            .map_err(|_| InvalidLength)
    }

    /// Encrypt `buffer` in place under `nonce`, authenticating `aad` as well,
    /// and return the tag.
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        use aes_gcm::AeadInOut;
        let tag = self
            .0
            .encrypt_inout_detached(nonce.into(), aad, buffer.into())
            .expect("AES-GCM accepts every message shorter than 2^36 bytes");
        tag.into()
    }

    /// Verify `tag` and decrypt `buffer` in place. On a mismatch the buffer
    /// is left as the caller must assume it: unusable.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        use aes_gcm::AeadInOut;
        self.0
            .decrypt_inout_detached(nonce.into(), aad, buffer.into(), tag.into())
            .map_err(|_| TagMismatch)
    }
}

/// AES-128-GCM.
pub type Aes128Gcm = Gcm<Aes128>;
/// AES-256-GCM.
pub type Aes256Gcm = Gcm<Aes256>;

// ---------------------------------------------------------------------------
// ChaCha20 / Poly1305

/// The ChaCha20 keystream generator (RFC 8439: 96-bit nonce, 32-bit block
/// counter), keyed once and positioned per call.
pub struct ChaCha20 {
    key: Zeroizing<[u8; 32]>,
}

impl ChaCha20 {
    /// Key the cipher.
    pub fn new(key: &[u8; 32]) -> Self {
        ChaCha20 {
            key: Zeroizing::new(*key),
        }
    }

    fn positioned(&self, nonce: &[u8; 12], counter: u32) -> chacha20::ChaCha20 {
        let mut c = chacha20::ChaCha20::new(&chacha20::Key::from(*self.key), nonce.into());
        c.seek(u64::from(counter) * 64);
        c
    }

    /// XOR the keystream starting at block `counter` into `buf`.
    pub fn apply_keystream(&self, nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        self.positioned(nonce, counter).apply_keystream(buf);
    }

    /// Keystream block `counter`.
    pub fn block(&self, nonce: &[u8; 12], counter: u32) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.apply_keystream(nonce, counter, &mut out);
        out
    }
}

/// Poly1305 one-time authenticator (RFC 8439 §2.5), over the plain
/// concatenation of everything fed to it (no padding between parts, as the
/// OpenSSH construction requires).
pub struct Poly1305 {
    key: Zeroizing<[u8; 32]>,
    data: Zeroizing<Vec<u8>>,
}

impl Poly1305 {
    /// Start a MAC under the one-time `key`.
    pub fn new(key: &[u8; 32]) -> Self {
        Poly1305 {
            key: Zeroizing::new(*key),
            data: Zeroizing::new(Vec::new()),
        }
    }

    /// Append message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// The 16-byte tag.
    pub fn finish(self) -> [u8; 16] {
        poly1305::Poly1305::new(&poly1305::Key::from(*self.key))
            .compute_unpadded(&self.data)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn des_cbc_and_tdes_cbc_round_trip() {
        let mut e = Cbc::<Des>::new(&[1u8; 8], &[2u8; 8]).unwrap();
        let mut d = Cbc::<Des>::new(&[1u8; 8], &[2u8; 8]).unwrap();
        let mut buf = [7u8; 24];
        e.encrypt(&mut buf).unwrap();
        assert_ne!(buf, [7u8; 24]);
        d.decrypt(&mut buf).unwrap();
        assert_eq!(buf, [7u8; 24]);
        assert!(Cbc::<Des>::new(&[1u8; 7], &[2u8; 8]).is_err());
        assert!(Cbc::<TdesEde3>::new(&[1u8; 24], &[2u8; 7]).is_err());
        assert!(e.encrypt(&mut [0u8; 9]).is_err());
    }

    /// RFC 8439 §2.4.2: ChaCha20 keystream block 1 with the test nonce.
    #[test]
    fn chacha20_rfc8439_block() {
        let key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = h("000000000000004a00000000");
        let c = ChaCha20::new(key.as_slice().try_into().unwrap());
        let block = c.block(nonce.as_slice().try_into().unwrap(), 1);
        assert_eq!(&block[..8], &h("224f51f3401bd9e1")[..]);
        let mut buf = [0u8; 70];
        c.apply_keystream(nonce.as_slice().try_into().unwrap(), 1, &mut buf);
        assert_eq!(&buf[..64], &block[..]);
        assert_eq!(
            &buf[64..],
            &c.block(nonce.as_slice().try_into().unwrap(), 2)[..6]
        );
    }

    /// RFC 8439 §2.5.2 Poly1305 vector.
    #[test]
    fn poly1305_rfc8439_vector() {
        let key = h("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let mut mac = Poly1305::new(key.as_slice().try_into().unwrap());
        mac.update(b"Cryptographic Forum ");
        mac.update(b"Research Group");
        assert_eq!(mac.finish().to_vec(), h("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    /// NIST GCM test case 2 (AES-128, zero key, zero nonce, one zero block).
    #[test]
    fn aes128_gcm_nist_tc2() {
        let g = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let mut buf = [0u8; 16];
        let tag = g.encrypt(&[0u8; 12], &[], &mut buf);
        assert_eq!(buf.to_vec(), h("0388dace60b6a392f328c2b971b2fe78"));
        assert_eq!(tag.to_vec(), h("ab6e47d42cec13bdf53a67b21257bddf"));
        g.decrypt(&[0u8; 12], &[], &mut buf, &tag).unwrap();
        assert_eq!(buf, [0u8; 16]);
        let mut bad = tag;
        bad[0] ^= 1;
        assert_eq!(g.decrypt(&[0u8; 12], &[], &mut buf, &bad), Err(TagMismatch));
        assert!(Aes128Gcm::new(&[0u8; 15]).is_err());
    }

    #[test]
    fn ctr_rejects_bad_lengths() {
        assert!(Aes128Ctr::new(&[0u8; 15], &[0u8; 16]).is_err());
        assert!(Aes128Ctr::new(&[0u8; 16], &[0u8; 15]).is_err());
        assert!(Aes256Ctr::new(&[0u8; 32], &[0u8; 16]).is_ok());
    }
}
