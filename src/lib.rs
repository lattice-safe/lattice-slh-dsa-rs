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
pub use sign::{keygen_seed, sign, verify};
