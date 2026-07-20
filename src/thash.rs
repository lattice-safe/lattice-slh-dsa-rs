//! Tweakable hash function (F / H / T_l) for SLH-DSA.
//!
//! Computes Trunc_n(Hash(pub_seed || ADRS || input)).
//!
//! For SHA-2 parameter sets, FIPS 205 §11.2.2 instantiates `F` (one input
//! block) with SHA-256 at every security category, while `H` and `T_l`
//! (more than one input block) use SHA-512 at categories 3 and 5 (n >= 24).
//! The public seed is zero-padded to one hash block (64 bytes for SHA-256,
//! 128 for SHA-512) and the compressed 22-byte address is used.

use crate::address::Addr;
use crate::hash::{sha2_uses_sha512, SpxCtx, SHA2_ADDR_BYTES};
use crate::params::{HashFamily, SlhDsaMode};

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
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            use sha3::Shake256;
            let mut hasher = Shake256::default();
            hasher.update(&ctx.pub_seed);
            hasher.update(addr.as_slice());
            hasher.update(&input[..input_len]);
            let mut reader = hasher.finalize_xof();
            reader.read(&mut out[..mode.n]);
        }
        HashFamily::Sha2 if sha2_uses_sha512(mode.n) && inblocks > 1 => {
            use sha2::digest::Digest;
            use sha2::Sha512;
            const BLOCK: usize = 128;
            let pad = [0u8; BLOCK];
            let mut hasher = Sha512::new();
            Digest::update(&mut hasher, &ctx.pub_seed);
            Digest::update(&mut hasher, &pad[..BLOCK - ctx.pub_seed.len()]);
            Digest::update(&mut hasher, &addr[..SHA2_ADDR_BYTES]);
            Digest::update(&mut hasher, &input[..input_len]);
            let result = Digest::finalize(hasher);
            out[..mode.n].copy_from_slice(&result[..mode.n]);
        }
        HashFamily::Sha2 => {
            use sha2::digest::Digest;
            use sha2::Sha256;
            const BLOCK: usize = 64;
            let pad = [0u8; BLOCK];
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, &ctx.pub_seed);
            Digest::update(&mut hasher, &pad[..BLOCK - ctx.pub_seed.len()]);
            Digest::update(&mut hasher, &addr[..SHA2_ADDR_BYTES]);
            Digest::update(&mut hasher, &input[..input_len]);
            let result = Digest::finalize(hasher);
            out[..mode.n].copy_from_slice(&result[..mode.n]);
        }
    }
}
