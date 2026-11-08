//! The cryptographic backend behind puressh.
//!
//! Every primitive the protocol needs comes through this module, so the rest
//! of the crate never names a crypto crate directly. The implementations are
//! the RustCrypto project's crates (`sha2`, `aes`, `chacha20`, `p256`, `rsa`,
//! `ml-kem`, ...) and the dalek curves (`x25519-dalek`, `ed25519-dalek`): the
//! most widely used and most reviewed pure-Rust implementations, with the
//! same no-`unsafe`, no-foreign-code posture as the rest of this library.
//!
//! The submodules keep a small, SSH-shaped surface: what the key exchanges,
//! ciphers, MACs, host-key algorithms and key-file formats actually use.
//! Anything a caller might reasonably want from the underlying crate (traits
//! such as [`hash::Digest`] or [`rng::RngCore`]) is re-exported rather than
//! wrapped, so generic code written against the public API keeps working.

pub mod bignum;
pub mod cipher;
pub mod ct;
pub mod der;
pub mod dh;
mod dh_groups;
pub mod ec;
pub mod hash;
pub mod kdf;
pub mod mldsa;
pub mod mlkem;
pub mod rng;
pub mod rsa;
pub mod zeroize;
