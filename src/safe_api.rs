//! High-level safe Rust API for SLH-DSA (FIPS 205).
//!
//! Provides `SlhDsaKeyPair` and `SlhDsaSignature` with automatic key zeroization
//! and optional serde support.
//!
//! # Example
//!
//! ```rust
//! use slh_dsa::safe_api::{SlhDsaKeyPair, SlhDsaSignature};
//! use slh_dsa::params::SLH_DSA_SHAKE_128F;
//!
//! let kp = SlhDsaKeyPair::generate(SLH_DSA_SHAKE_128F).unwrap();
//! let sig = kp.sign(b"Hello, post-quantum!").unwrap();
//! assert!(SlhDsaSignature::verify(&sig.to_bytes(), kp.public_key(), b"Hello, post-quantum!", SLH_DSA_SHAKE_128F));
//! ```

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::params::SlhDsaMode;
use crate::sign;

// ======================================================================
// Error type
// ======================================================================

/// Errors returned by the SLH-DSA API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SlhDsaError {
    /// Key generation failed (e.g., insufficient entropy).
    KeygenFailed,
    /// Signing failed.
    SignFailed,
    /// Signature verification failed.
    BadSignature,
    /// An argument was invalid (wrong size, etc.).
    BadArgument,
}

impl fmt::Display for SlhDsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlhDsaError::KeygenFailed => write!(f, "key generation failed"),
            SlhDsaError::SignFailed => write!(f, "signing failed"),
            SlhDsaError::BadSignature => write!(f, "bad signature"),
            SlhDsaError::BadArgument => write!(f, "bad argument"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SlhDsaError {}

// ======================================================================
// Key pair
// ======================================================================

/// An SLH-DSA key pair (secret key + public key).
///
/// The secret key bytes are **automatically zeroized on drop**.
///
/// # Example
///
/// ```rust
/// use slh_dsa::safe_api::SlhDsaKeyPair;
/// use slh_dsa::params::SLH_DSA_SHAKE_128F;
///
/// let kp = SlhDsaKeyPair::generate(SLH_DSA_SHAKE_128F).unwrap();
/// let sig = kp.sign(b"message").unwrap();
/// ```
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlhDsaKeyPair {
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes_mod"))]
    sk: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes_mod"))]
    pk: Vec<u8>,
    mode: SlhDsaMode,
}

// Manual Zeroize implementation for the secret key
impl Drop for SlhDsaKeyPair {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

impl ZeroizeOnDrop for SlhDsaKeyPair {}

impl fmt::Debug for SlhDsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlhDsaKeyPair")
            .field("pk_len", &self.pk.len())
            .field("sk_len", &self.sk.len())
            .field("mode_n", &self.mode.n)
            .finish()
    }
}

impl SlhDsaKeyPair {
    /// Generate a new key pair using OS randomness.
    ///
    /// Requires the `getrandom` feature (enabled by default via `std`).
    #[cfg(feature = "getrandom")]
    pub fn generate(mode: SlhDsaMode) -> Result<Self, SlhDsaError> {
        let mut seed = vec![0u8; mode.seed_bytes()];
        getrandom::getrandom(&mut seed).map_err(|_| SlhDsaError::KeygenFailed)?;
        Self::from_seed(mode, &seed)
    }

    /// Generate a key pair from a deterministic seed.
    ///
    /// Seed must be exactly `mode.seed_bytes()` bytes (3*n).
    pub fn from_seed(mode: SlhDsaMode, seed: &[u8]) -> Result<Self, SlhDsaError> {
        if seed.len() < mode.seed_bytes() {
            return Err(SlhDsaError::BadArgument);
        }
        let (pk, sk) = sign::keygen_seed(mode, seed);
        Ok(SlhDsaKeyPair { sk, pk, mode })
    }

    /// Create a key pair from raw bytes.
    pub fn from_bytes(mode: SlhDsaMode, pk: &[u8], sk: &[u8]) -> Result<Self, SlhDsaError> {
        if pk.len() != mode.pk_bytes() || sk.len() != mode.sk_bytes() {
            return Err(SlhDsaError::BadArgument);
        }
        Ok(SlhDsaKeyPair {
            sk: sk.to_vec(),
            pk: pk.to_vec(),
            mode,
        })
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> Result<SlhDsaSignature, SlhDsaError> {
        let sig_bytes = sign::sign(&self.sk, msg, self.mode);
        Ok(SlhDsaSignature {
            sig: sig_bytes,
            mode: self.mode,
        })
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.pk
    }

    /// Get the secret key bytes.
    pub fn secret_key(&self) -> &[u8] {
        &self.sk
    }

    /// Get the parameter set.
    pub fn mode(&self) -> SlhDsaMode {
        self.mode
    }
}

// ======================================================================
// Signature
// ======================================================================

/// An SLH-DSA signature.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SlhDsaSignature {
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes_mod"))]
    sig: Vec<u8>,
    mode: SlhDsaMode,
}

impl SlhDsaSignature {
    /// Get the raw signature bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.sig
    }

    /// Get the signature length.
    pub fn len(&self) -> usize {
        self.sig.len()
    }

    /// Check if the signature is empty.
    pub fn is_empty(&self) -> bool {
        self.sig.is_empty()
    }

    /// Verify a signature against a public key and message.
    pub fn verify(sig_bytes: &[u8], pk: &[u8], msg: &[u8], mode: SlhDsaMode) -> bool {
        sign::verify(pk, sig_bytes, msg, mode)
    }

    /// Create from raw bytes.
    pub fn from_bytes(mode: SlhDsaMode, sig: &[u8]) -> Result<Self, SlhDsaError> {
        if sig.len() != mode.sig_bytes() {
            return Err(SlhDsaError::BadArgument);
        }
        Ok(SlhDsaSignature {
            sig: sig.to_vec(),
            mode,
        })
    }

    /// Get the parameter set.
    pub fn mode(&self) -> SlhDsaMode {
        self.mode
    }
}

// ======================================================================
// Serde helper for Vec<u8> (compact binary encoding)
// ======================================================================

#[cfg(feature = "serde")]
mod serde_bytes_mod {
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        bytes.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}
