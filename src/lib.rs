//! Pure Rust implementation of SLH-DSA (FIPS 205) / SPHINCS+.
//!
//! A stateless hash-based digital signature scheme standardized as FIPS 205.
//! Security relies only on the security of hash functions — the most
//! conservative post-quantum assumption.
//!
//! Supports all 12 FIPS 205 parameter sets (6 SHAKE + 6 SHA-2):
//! - SLH-DSA-128s / SLH-DSA-128f (NIST Level 1)
//! - SLH-DSA-192s / SLH-DSA-192f (NIST Level 3)
//! - SLH-DSA-256s / SLH-DSA-256f (NIST Level 5)
//!
//! # FIPS 205 conformance
//!
//! [`sign`] / [`verify`] implement the FIPS 205 **pure** variant with an
//! empty context string, using deterministic signing (`opt_rand = PK.seed`,
//! Algorithm 22). Use [`sign_ctx`] / [`verify_ctx`] to bind a context string
//! (up to 255 bytes), and [`sign_internal`] / [`verify_internal`] for the raw
//! internal functions (KATs, or building HashSLH-DSA-style schemes on top).
//! Hedged signing is available by passing `addrnd` to [`sign_internal`].
//!
//! Interoperability is enforced in CI: key generation and signatures are
//! compared byte-for-byte against the independent RustCrypto `slh-dsa`
//! crate across both hash families and all three security categories.
//!
//! Versions before 0.4.0 implemented round-3 SPHINCS+ semantics and are
//! **not** interoperable with FIPS 205 implementations (or with 0.4.0+).
//!
//! # Quick Start
//!
//! ```rust
//! use slh_dsa::safe_api::SlhDsaKeyPair;
//! use slh_dsa::params::SLH_DSA_SHAKE_128F;
//!
//! let kp = SlhDsaKeyPair::generate(SLH_DSA_SHAKE_128F).unwrap();
//! let sig = kp.sign(b"Hello, post-quantum!").unwrap();
//! assert!(slh_dsa::safe_api::SlhDsaSignature::verify(
//!     sig.to_bytes(), kp.public_key(), b"Hello, post-quantum!", SLH_DSA_SHAKE_128F,
//! ));
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod address;
pub mod fors;
pub mod hash;
pub mod merkle;
pub mod params;
pub mod prelude;
pub mod safe_api;
pub mod sign;
pub mod thash;
mod utils;
pub mod wots;

pub use params::SlhDsaMode;
pub use safe_api::{SlhDsaError, SlhDsaKeyPair, SlhDsaSignature};
pub use sign::{keygen_seed, sign, sign_ctx, sign_internal, verify, verify_ctx, verify_internal};
