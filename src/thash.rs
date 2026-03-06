//! Tweakable hash function (T_l) for SLH-DSA.
//!
//! Computes H(pub_seed || ADRS || input) with SHAKE-256 or SHA-256.

use alloc::vec;
use crate::params::{SlhDsaMode, HashFamily};
use crate::hash::SpxCtx;
use crate::address::Addr;

/// Tweakable hash: T_l(pub_seed, ADRS, M).
/// Takes `inblocks` concatenated n-byte values.
pub fn thash(
    out: &mut [u8],
    input: &[u8],
    inblocks: usize,
    ctx: &SpxCtx,
    addr: &Addr,
    mode: &SlhDsaMode,
) {
    let input_len = inblocks * mode.n;

    match mode.hash {
        HashFamily::Shake => {
            use sha3::Shake256;
            use sha3::digest::{Update, ExtendableOutput, XofReader};
            let mut hasher = Shake256::default();
            hasher.update(&ctx.pub_seed);
            hasher.update(addr.as_slice());
            hasher.update(&input[..input_len]);
            let mut reader = hasher.finalize_xof();
            reader.read(&mut out[..mode.n]);
        }
        HashFamily::Sha2 => {
            use sha2::Sha256;
            use sha2::digest::Digest;
            let mut hasher = Sha256::new();
            sha2::digest::Digest::update(&mut hasher, &ctx.pub_seed);
            if ctx.pub_seed.len() < 64 {
                sha2::digest::Digest::update(&mut hasher, vec![0u8; 64 - ctx.pub_seed.len()]);
            }
            sha2::digest::Digest::update(&mut hasher, &addr[..22]);
            sha2::digest::Digest::update(&mut hasher, &input[..input_len]);
            let result = sha2::digest::Digest::finalize(hasher);
            out[..mode.n].copy_from_slice(&result[..mode.n]);
        }
    }
}
