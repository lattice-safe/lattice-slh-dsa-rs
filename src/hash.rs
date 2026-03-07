//! Hash function abstraction layer for SLH-DSA.
//!
//! Supports both SHAKE-256 and SHA-256 based instantiations.

use crate::address::Addr;
use crate::params::{HashFamily, SlhDsaMode};
use crate::utils::bytes_to_ull;
use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroize;

/// SPX context (holds seeds and precomputed state).
pub struct SpxCtx {
    pub pub_seed: Vec<u8>,
    pub sk_seed: Vec<u8>,
}

impl SpxCtx {
    pub fn new(n: usize) -> Self {
        SpxCtx {
            pub_seed: vec![0u8; n],
            sk_seed: vec![0u8; n],
        }
    }
}

impl Drop for SpxCtx {
    fn drop(&mut self) {
        self.sk_seed.zeroize();
    }
}

// ---- Helper: SHAKE-256 hash wrapper ----
fn shake256(out: &mut [u8], inputs: &[&[u8]]) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;
    let mut hasher = Shake256::default();
    for inp in inputs {
        hasher.update(inp);
    }
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

// ---- Helper: SHA-256 hash wrapper ----
fn sha256(out: &mut [u8], inputs: &[&[u8]]) {
    use sha2::digest::Digest;
    use sha2::Sha256;
    let mut hasher = Sha256::new();
    for inp in inputs {
        sha2::digest::Digest::update(&mut hasher, *inp);
    }
    let result = sha2::digest::Digest::finalize(hasher);
    let len = out.len().min(32);
    out[..len].copy_from_slice(&result[..len]);
}

fn sha256_full(inputs: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sha256(&mut out, inputs);
    out
}

/// PRF(pub_seed, sk_seed, addr) — generates pseudorandom output.
pub fn prf_addr(out: &mut [u8], ctx: &SpxCtx, addr: &Addr, mode: &SlhDsaMode) {
    match mode.hash {
        HashFamily::Shake => {
            shake256(
                &mut out[..mode.n],
                &[&ctx.pub_seed, addr.as_slice(), &ctx.sk_seed],
            );
        }
        HashFamily::Sha2 => {
            // SHA-256: H(pub_seed_padded || addr_compressed || sk_seed)
            let mut padded = Vec::new();
            padded.extend_from_slice(&ctx.pub_seed);
            if ctx.pub_seed.len() < 64 {
                padded.extend_from_slice(&vec![0u8; 64 - ctx.pub_seed.len()]);
            }
            padded.extend_from_slice(&addr[..22]);
            padded.extend_from_slice(&ctx.sk_seed);
            sha256(&mut out[..mode.n], &[&padded]);
        }
    }
}

/// Generate message randomness R = PRF_msg(sk_prf, optrand, m).
pub fn gen_message_random(
    r_out: &mut [u8],
    sk_prf: &[u8],
    optrand: &[u8],
    m: &[u8],
    mode: &SlhDsaMode,
) {
    match mode.hash {
        HashFamily::Shake => {
            shake256(&mut r_out[..mode.n], &[sk_prf, optrand, m]);
        }
        HashFamily::Sha2 => {
            let block_size = 64usize;
            let mut ipad = vec![0x36u8; block_size];
            for i in 0..mode.n.min(block_size) {
                ipad[i] ^= sk_prf[i];
            }
            let inner = sha256_full(&[&ipad, optrand, m]);
            let mut opad = vec![0x5cu8; block_size];
            for i in 0..mode.n.min(block_size) {
                opad[i] ^= sk_prf[i];
            }
            let result = sha256_full(&[&opad, &inner]);
            r_out[..mode.n].copy_from_slice(&result[..mode.n]);
        }
    }
}

/// Hash message to produce digest, tree index, and leaf index.
pub fn hash_message(
    digest: &mut [u8],
    tree: &mut u64,
    leaf_idx: &mut u32,
    r: &[u8],
    pk: &[u8],
    m: &[u8],
    mode: &SlhDsaMode,
) {
    let dgst_bytes = mode.dgst_bytes();

    let buf = match mode.hash {
        HashFamily::Shake => {
            let mut buf = vec![0u8; dgst_bytes];
            shake256(&mut buf, &[&r[..mode.n], &pk[..mode.pk_bytes()], m]);
            buf
        }
        HashFamily::Sha2 => {
            let seed_hash = sha256_full(&[&r[..mode.n], &pk[..mode.pk_bytes()], m]);
            let mut mgf_seed = Vec::new();
            mgf_seed.extend_from_slice(&r[..mode.n]);
            mgf_seed.extend_from_slice(&pk[..mode.n]);
            mgf_seed.extend_from_slice(&seed_hash);
            mgf1_sha256(&mgf_seed, dgst_bytes)
        }
    };

    let fmb = mode.fors_msg_bytes();
    digest[..fmb].copy_from_slice(&buf[..fmb]);

    let tree_bits = mode.tree_bits();
    let tree_bytes = mode.tree_bytes();
    let leaf_bytes = mode.leaf_bytes();

    if mode.d == 1 {
        *tree = 0;
    } else {
        *tree = bytes_to_ull(&buf[fmb..], tree_bytes);
        *tree &= u64::MAX >> (64 - tree_bits);
    }

    *leaf_idx = bytes_to_ull(&buf[fmb + tree_bytes..], leaf_bytes) as u32;
    *leaf_idx &= u32::MAX >> (32 - mode.leaf_bits());
}

/// MGF1 with SHA-256.
fn mgf1_sha256(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while out.len() < out_len {
        let ctr = counter.to_be_bytes();
        let block = sha256_full(&[seed, &ctr]);
        let remaining = out_len - out.len();
        out.extend_from_slice(&block[..remaining.min(32)]);
        counter += 1;
    }
    out
}
