//! Hash function abstraction layer for SLH-DSA.
//!
//! Supports both SHAKE-256 and SHA-2 based instantiations.
//!
//! Per FIPS 205 §11.2, the SHA-2 parameter sets use SHA-256 for every
//! function at security category 1 (n = 16). At categories 3 and 5
//! (n = 24, 32), `H_msg`, `PRF_msg`, `H` and `T_l` are instantiated with
//! SHA-512 while `PRF` and `F` remain SHA-256.

use crate::address::Addr;
use crate::params::{HashFamily, SlhDsaMode};
use crate::utils::bytes_to_ull;
use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroize;

/// Number of bytes of the compressed address used by the SHA-2 variants.
pub(crate) const SHA2_ADDR_BYTES: usize = 22;

const SHA256_BLOCK: usize = 64;
const SHA512_BLOCK: usize = 128;

/// SHA-2 parameter sets with n >= 24 (security categories 3 and 5) use
/// SHA-512 for H_msg, PRF_msg, H and T_l (FIPS 205 §11.2.2).
pub(crate) const fn sha2_uses_sha512(n: usize) -> bool {
    n >= 24
}

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

// ---- Helper: SHA-256 / SHA-512 one-shot wrappers ----
fn sha256_full(inputs: &[&[u8]]) -> [u8; 32] {
    use sha2::digest::Digest;
    use sha2::Sha256;
    let mut hasher = Sha256::new();
    for inp in inputs {
        Digest::update(&mut hasher, *inp);
    }
    Digest::finalize(hasher).into()
}

fn sha512_full(inputs: &[&[u8]]) -> [u8; 64] {
    use sha2::digest::Digest;
    use sha2::Sha512;
    let mut hasher = Sha512::new();
    for inp in inputs {
        Digest::update(&mut hasher, *inp);
    }
    Digest::finalize(hasher).into()
}

/// PRF(pub_seed, sk_seed, addr) — generates pseudorandom output.
///
/// SHA-2 variants always use SHA-256 here, at every security category
/// (FIPS 205 §11.2.2).
pub fn prf_addr(out: &mut [u8], ctx: &SpxCtx, addr: &Addr, mode: &SlhDsaMode) {
    match mode.hash {
        HashFamily::Shake => {
            shake256(
                &mut out[..mode.n],
                &[&ctx.pub_seed, addr.as_slice(), &ctx.sk_seed],
            );
        }
        HashFamily::Sha2 => {
            // Trunc_n(SHA-256(pub_seed || toByte(0, 64 - n) || ADRS_c || sk_seed))
            let pad = [0u8; SHA256_BLOCK];
            let result = sha256_full(&[
                &ctx.pub_seed,
                &pad[..SHA256_BLOCK - ctx.pub_seed.len()],
                &addr[..SHA2_ADDR_BYTES],
                &ctx.sk_seed,
            ]);
            out[..mode.n].copy_from_slice(&result[..mode.n]);
        }
    }
}

/// HMAC over `msgs` with `key` (zero-padded to the block size).
/// `block` selects SHA-256 (64) or SHA-512 (128).
fn hmac_sha2(out: &mut [u8], key: &[u8], msgs: &[&[u8]], block: usize) {
    debug_assert!(key.len() <= block);
    let mut ipad = vec![0x36u8; block];
    let mut opad = vec![0x5cu8; block];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }

    if block == SHA512_BLOCK {
        let mut inner: [u8; 64] = {
            use sha2::digest::Digest;
            let mut h = sha2::Sha512::new();
            Digest::update(&mut h, &ipad);
            for m in msgs {
                Digest::update(&mut h, *m);
            }
            Digest::finalize(h).into()
        };
        let result = sha512_full(&[&opad, &inner]);
        let len = out.len().min(64);
        out[..len].copy_from_slice(&result[..len]);
        inner.zeroize();
    } else {
        let mut inner: [u8; 32] = {
            use sha2::digest::Digest;
            let mut h = sha2::Sha256::new();
            Digest::update(&mut h, &ipad);
            for m in msgs {
                Digest::update(&mut h, *m);
            }
            Digest::finalize(h).into()
        };
        let result = sha256_full(&[&opad, &inner]);
        let len = out.len().min(32);
        out[..len].copy_from_slice(&result[..len]);
        inner.zeroize();
    }

    ipad.zeroize();
    opad.zeroize();
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
            // PRF_msg = Trunc_n(HMAC-SHA-X(sk_prf, optrand || m))
            let block = if sha2_uses_sha512(mode.n) {
                SHA512_BLOCK
            } else {
                SHA256_BLOCK
            };
            hmac_sha2(
                &mut r_out[..mode.n],
                &sk_prf[..mode.n],
                &[optrand, m],
                block,
            );
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
            // H_msg = MGF1-SHA-X(R || PK.seed || SHA-X(R || PK.seed || PK.root || M), m)
            let mut mgf_seed = Vec::new();
            mgf_seed.extend_from_slice(&r[..mode.n]);
            mgf_seed.extend_from_slice(&pk[..mode.n]);
            if sha2_uses_sha512(mode.n) {
                let seed_hash = sha512_full(&[&r[..mode.n], &pk[..mode.pk_bytes()], m]);
                mgf_seed.extend_from_slice(&seed_hash);
                mgf1_sha512(&mgf_seed, dgst_bytes)
            } else {
                let seed_hash = sha256_full(&[&r[..mode.n], &pk[..mode.pk_bytes()], m]);
                mgf_seed.extend_from_slice(&seed_hash);
                mgf1_sha256(&mgf_seed, dgst_bytes)
            }
        }
    };

    let fmb = mode.fors_msg_bytes();
    digest[..fmb].copy_from_slice(&buf[..fmb]);

    let tree_bits = mode.tree_bits();
    let tree_bytes = mode.tree_bytes();
    let leaf_bytes = mode.leaf_bytes();

    // Masks are computed without shift overflow so that degenerate custom
    // modes (tree_bits >= 64, leaf_bits >= 32 or 0) cannot panic.
    if mode.d == 1 || tree_bits == 0 {
        *tree = 0;
    } else {
        *tree = bytes_to_ull(&buf[fmb..], tree_bytes);
        if tree_bits < 64 {
            *tree &= (1u64 << tree_bits) - 1;
        }
    }

    *leaf_idx = bytes_to_ull(&buf[fmb + tree_bytes..], leaf_bytes) as u32;
    if mode.leaf_bits() < 32 {
        *leaf_idx &= (1u32 << mode.leaf_bits()) - 1;
    }
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

/// MGF1 with SHA-512.
fn mgf1_sha512(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while out.len() < out_len {
        let ctr = counter.to_be_bytes();
        let block = sha512_full(&[seed, &ctr]);
        let remaining = out_len - out.len();
        out.extend_from_slice(&block[..remaining.min(64)]);
        counter += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 4231 test case 2 (key "Jefe", data "what do ya want for nothing?").
    #[test]
    fn test_hmac_sha256_rfc4231() {
        let mut out = [0u8; 32];
        hmac_sha2(
            &mut out,
            b"Jefe",
            &[b"what do ya want for nothing?"],
            SHA256_BLOCK,
        );
        assert_eq!(
            out.to_vec(),
            unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn test_hmac_sha512_rfc4231() {
        let mut out = [0u8; 64];
        hmac_sha2(
            &mut out,
            b"Jefe",
            &[b"what do ya want for nothing?"],
            SHA512_BLOCK,
        );
        assert_eq!(
            out.to_vec(),
            unhex(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                 9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            )
        );
    }

    #[test]
    fn test_hmac_truncated_output() {
        // SLH-DSA truncates PRF_msg output to n bytes.
        let mut full = [0u8; 32];
        let mut trunc = [0u8; 16];
        hmac_sha2(&mut full, b"key", &[b"msg"], SHA256_BLOCK);
        hmac_sha2(&mut trunc, b"key", &[b"msg"], SHA256_BLOCK);
        assert_eq!(&full[..16], &trunc[..]);
    }

    #[test]
    fn test_mgf1_prefix_property() {
        // MGF1 output for a shorter length must be a prefix of a longer one,
        // and must span multiple hash blocks correctly.
        let seed = b"mgf1 seed";
        let short = mgf1_sha256(seed, 20);
        let long = mgf1_sha256(seed, 100);
        assert_eq!(long.len(), 100);
        assert_eq!(&long[..20], &short[..]);

        let short512 = mgf1_sha512(seed, 30);
        let long512 = mgf1_sha512(seed, 200);
        assert_eq!(long512.len(), 200);
        assert_eq!(&long512[..30], &short512[..]);
        assert_ne!(&long[..30], &long512[..30]);
    }
}
