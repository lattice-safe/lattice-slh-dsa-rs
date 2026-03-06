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
//! use slh_dsa::params::SLH_DSA_SHAKE_128F;
//! use slh_dsa::sign::{keygen_seed, sign, verify};
//!
//! let mode = SLH_DSA_SHAKE_128F;
//! let seed = vec![42u8; mode.seed_bytes()];
//! let (pk, sk) = keygen_seed(mode, &seed);
//! let sig = sign(&sk, b"Hello, post-quantum!", mode);
//! assert!(verify(&pk, &sig, b"Hello, post-quantum!", mode));
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod params;
pub mod address;
pub mod hash;
pub mod thash;
pub mod wots;
pub mod fors;
pub mod merkle;
pub mod sign;
mod utils;

pub use params::SlhDsaMode;
pub use sign::{keygen_seed, sign, verify};
