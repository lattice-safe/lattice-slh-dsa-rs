//! Convenience re-exports for SLH-DSA.
//!
//! ```rust
//! use slh_dsa::prelude::*;
//!
//! let kp = SlhDsaKeyPair::generate(SLH_DSA_SHAKE_128F).unwrap();
//! let sig = kp.sign(b"message").unwrap();
//! assert!(SlhDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"message", SLH_DSA_SHAKE_128F));
//! ```

pub use crate::params::*;
pub use crate::safe_api::{SlhDsaError, SlhDsaKeyPair, SlhDsaSignature};
