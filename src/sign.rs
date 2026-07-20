//! SLH-DSA keygen, sign, and verify (FIPS 205).

use crate::address::*;
use crate::fors;
use crate::hash::{gen_message_random, hash_message, SpxCtx};
use crate::merkle;
use crate::params::SlhDsaMode;
use crate::thash::thash;
use crate::wots;
use alloc::vec;
use alloc::vec::Vec;
use subtle::ConstantTimeEq;

/// Generate SLH-DSA key pair from a seed.
///
/// Seed is 3*n bytes: [SK_SEED || SK_PRF || PUB_SEED].
///
/// Returns (public_key, secret_key).
/// - pk = [PUB_SEED || root]  (2*n bytes)
/// - sk = [SK_SEED || SK_PRF || PUB_SEED || root]  (4*n bytes)
pub fn keygen_seed(mode: SlhDsaMode, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let n = mode.n;
    if seed.len() < mode.seed_bytes() {
        return (vec![], vec![]);
    }

    let mut sk = vec![0u8; mode.sk_bytes()];
    let mut pk = vec![0u8; mode.pk_bytes()];

    sk[..3 * n].copy_from_slice(&seed[..3 * n]);
    pk[..n].copy_from_slice(&seed[2 * n..3 * n]);

    let mut ctx = SpxCtx::new(n);
    ctx.pub_seed.copy_from_slice(&pk[..n]);
    ctx.sk_seed.copy_from_slice(&seed[..n]);

    let mut root = vec![0u8; n];
    merkle::merkle_gen_root(&mut root, &ctx, &mode);

    sk[3 * n..4 * n].copy_from_slice(&root);
    pk[n..2 * n].copy_from_slice(&root);

    (pk, sk)
}

/// FIPS 205 "pure" message encoding: M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M.
///
/// Returns `None` when the context string exceeds 255 bytes.
fn wrap_message(m: &[u8], ctx: &[u8]) -> Option<Vec<u8>> {
    if ctx.len() > 255 {
        return None;
    }
    let mut mp = Vec::with_capacity(2 + ctx.len() + m.len());
    mp.push(0u8);
    mp.push(ctx.len() as u8);
    mp.extend_from_slice(ctx);
    mp.extend_from_slice(m);
    Some(mp)
}

/// Sign a message (FIPS 205 `slh_sign`, pure variant, empty context string).
///
/// Uses the deterministic variant (`addrnd = PK.seed`). Returns an empty
/// vector if `sk` is too short.
pub fn sign(sk: &[u8], m: &[u8], mode: SlhDsaMode) -> Vec<u8> {
    sign_ctx(sk, m, &[], mode)
}

/// Sign a message with a context string (FIPS 205 `slh_sign`, pure variant).
///
/// Returns an empty vector if `sk` is too short or `ctx` exceeds 255 bytes.
pub fn sign_ctx(sk: &[u8], m: &[u8], ctx: &[u8], mode: SlhDsaMode) -> Vec<u8> {
    match wrap_message(m, ctx) {
        Some(mp) => sign_internal(sk, &mp, None, mode),
        None => vec![],
    }
}

/// FIPS 205 `slh_sign_internal`.
///
/// `addrnd` is the additional randomness for the hedged variant; pass `None`
/// for the deterministic variant (which uses `PK.seed`, per FIPS 205
/// Algorithm 22). If provided, it must be at least `n` bytes.
///
/// Signs the raw message without domain separation — use [`sign`] or
/// [`sign_ctx`] unless implementing a higher-level scheme or running KATs.
pub fn sign_internal(sk: &[u8], m: &[u8], addrnd: Option<&[u8]>, mode: SlhDsaMode) -> Vec<u8> {
    let n = mode.n;

    if sk.len() < mode.sk_bytes() {
        return vec![];
    }
    if let Some(rnd) = addrnd {
        if rnd.len() < n {
            return vec![];
        }
    }

    let sk_seed = &sk[..n];
    let sk_prf = &sk[n..2 * n];
    let pk = &sk[2 * n..];

    let mut ctx = SpxCtx::new(n);
    ctx.sk_seed.copy_from_slice(sk_seed);
    ctx.pub_seed.copy_from_slice(&pk[..n]);

    let mut sig = vec![0u8; mode.sig_bytes()];
    let mut sig_offset = 0usize;

    // Deterministic variant substitutes PK.seed for opt_rand (FIPS 205 §9.2).
    let optrand = addrnd.map(|r| &r[..n]).unwrap_or(&pk[..n]);
    gen_message_random(&mut sig[..n], sk_prf, optrand, m, &mode);
    let r = sig[..n].to_vec();
    sig_offset += n;

    let mut mhash = vec![0u8; mode.fors_msg_bytes()];
    let mut tree: u64 = 0;
    let mut idx_leaf: u32 = 0;
    hash_message(&mut mhash, &mut tree, &mut idx_leaf, &r, pk, m, &mode);

    let mut wots_addr: Addr = [0; ADDR_BYTES];
    let mut tree_addr: Addr = [0; ADDR_BYTES];
    set_type(&mut wots_addr, ADDR_TYPE_WOTS, &mode);
    set_type(&mut tree_addr, ADDR_TYPE_HASHTREE, &mode);
    set_tree_addr(&mut wots_addr, tree, &mode);
    set_keypair_addr(&mut wots_addr, idx_leaf, &mode);

    let mut fors_root = vec![0u8; n];
    fors::fors_sign(
        &mut sig[sig_offset..],
        &mut fors_root,
        &mhash,
        &ctx,
        &wots_addr,
        &mode,
    );
    sig_offset += mode.fors_bytes();

    let mut root = fors_root;
    for i in 0..mode.d {
        set_layer_addr(&mut tree_addr, i as u32, &mode);
        set_tree_addr(&mut tree_addr, tree, &mode);

        copy_subtree_addr(&mut wots_addr, &tree_addr, &mode);
        set_keypair_addr(&mut wots_addr, idx_leaf, &mode);

        let sig_len = mode.wots_bytes() + mode.tree_height() * n;
        merkle::merkle_sign(
            &mut sig[sig_offset..sig_offset + sig_len],
            &mut root,
            &ctx,
            &wots_addr,
            &tree_addr,
            idx_leaf,
            &mode,
        );
        sig_offset += sig_len;

        idx_leaf = (tree & ((1u64 << mode.tree_height()) - 1)) as u32;
        tree >>= mode.tree_height();
    }

    sig
}

/// Verify a signature (FIPS 205 `slh_verify`, pure variant, empty context string).
pub fn verify(pk: &[u8], sig: &[u8], m: &[u8], mode: SlhDsaMode) -> bool {
    verify_ctx(pk, sig, m, &[], mode)
}

/// Verify a signature with a context string (FIPS 205 `slh_verify`, pure variant).
pub fn verify_ctx(pk: &[u8], sig: &[u8], m: &[u8], ctx: &[u8], mode: SlhDsaMode) -> bool {
    match wrap_message(m, ctx) {
        Some(mp) => verify_internal(pk, sig, &mp, mode),
        None => false,
    }
}

/// FIPS 205 `slh_verify_internal`.
///
/// Verifies over the raw message without domain separation — use [`verify`]
/// or [`verify_ctx`] unless implementing a higher-level scheme or running KATs.
pub fn verify_internal(pk: &[u8], sig: &[u8], m: &[u8], mode: SlhDsaMode) -> bool {
    let n = mode.n;

    if sig.len() != mode.sig_bytes() {
        return false;
    }

    if pk.len() != mode.pk_bytes() {
        return false;
    }

    let pub_seed = &pk[..n];
    let pub_root = &pk[n..2 * n];

    let mut ctx = SpxCtx::new(n);
    ctx.pub_seed.copy_from_slice(pub_seed);

    let mut sig_offset = 0usize;

    let r = &sig[..n];
    sig_offset += n;

    let mut mhash = vec![0u8; mode.fors_msg_bytes()];
    let mut tree: u64 = 0;
    let mut idx_leaf: u32 = 0;
    hash_message(&mut mhash, &mut tree, &mut idx_leaf, r, pk, m, &mode);

    let mut wots_addr: Addr = [0; ADDR_BYTES];
    let mut tree_addr: Addr = [0; ADDR_BYTES];
    let mut wots_pk_addr: Addr = [0; ADDR_BYTES];

    set_type(&mut wots_addr, ADDR_TYPE_WOTS, &mode);
    set_type(&mut tree_addr, ADDR_TYPE_HASHTREE, &mode);
    set_type(&mut wots_pk_addr, ADDR_TYPE_WOTSPK, &mode);

    set_tree_addr(&mut wots_addr, tree, &mode);
    set_keypair_addr(&mut wots_addr, idx_leaf, &mode);

    let mut root = vec![0u8; n];
    fors::fors_pk_from_sig(
        &mut root,
        &sig[sig_offset..],
        &mhash,
        &ctx,
        &wots_addr,
        &mode,
    );
    sig_offset += mode.fors_bytes();

    for i in 0..mode.d {
        set_layer_addr(&mut tree_addr, i as u32, &mode);
        set_tree_addr(&mut tree_addr, tree, &mode);

        copy_subtree_addr(&mut wots_addr, &tree_addr, &mode);
        set_keypair_addr(&mut wots_addr, idx_leaf, &mode);
        copy_keypair_addr(&mut wots_pk_addr, &wots_addr, &mode);

        let mut wots_pk = vec![0u8; mode.wots_bytes()];
        wots::wots_pk_from_sig(
            &mut wots_pk,
            &sig[sig_offset..],
            &root,
            &ctx,
            &mut wots_addr,
            &mode,
        );
        sig_offset += mode.wots_bytes();

        let mut leaf = vec![0u8; n];
        thash(
            &mut leaf,
            &wots_pk,
            mode.wots_len(),
            &ctx,
            &wots_pk_addr,
            &mode,
        );

        fors::compute_root(
            &mut root,
            &leaf,
            idx_leaf,
            0,
            &sig[sig_offset..],
            mode.tree_height(),
            &ctx,
            &mut tree_addr,
            &mode,
        );
        sig_offset += mode.tree_height() * n;

        idx_leaf = (tree & ((1u64 << mode.tree_height()) - 1)) as u32;
        tree >>= mode.tree_height();
    }

    root.ct_eq(pub_root).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SLH_DSA_SHAKE_128F;

    #[test]
    fn test_keygen_sign_verify_shake_128f() {
        let mode = SLH_DSA_SHAKE_128F;
        let seed = vec![42u8; mode.seed_bytes()];
        let (pk, sk) = keygen_seed(mode, &seed);

        assert_eq!(pk.len(), mode.pk_bytes());
        assert_eq!(sk.len(), mode.sk_bytes());

        let msg = b"Hello, SLH-DSA!";
        let sig = sign(&sk, msg, mode);
        assert_eq!(sig.len(), mode.sig_bytes());

        assert!(
            verify(&pk, &sig, msg, mode),
            "signature verification failed"
        );
    }

    #[test]
    fn test_wrong_message_fails() {
        let mode = SLH_DSA_SHAKE_128F;
        let seed = vec![42u8; mode.seed_bytes()];
        let (pk, sk) = keygen_seed(mode, &seed);

        let sig = sign(&sk, b"correct", mode);
        assert!(!verify(&pk, &sig, b"wrong", mode));
    }

    #[test]
    fn test_keygen_seed_too_short() {
        let mode = SLH_DSA_SHAKE_128F;
        let (pk, sk) = keygen_seed(mode, &[0u8; 5]);
        assert!(pk.is_empty());
        assert!(sk.is_empty());
    }

    #[test]
    fn test_sign_sk_too_short() {
        let mode = SLH_DSA_SHAKE_128F;
        assert!(sign(&[0u8; 5], b"msg", mode).is_empty());
        assert!(sign_internal(&[0u8; 5], b"msg", None, mode).is_empty());
    }

    #[test]
    fn test_context_string_roundtrip() {
        let mode = SLH_DSA_SHAKE_128F;
        let seed = vec![42u8; mode.seed_bytes()];
        let (pk, sk) = keygen_seed(mode, &seed);

        let sig = sign_ctx(&sk, b"msg", b"app-context", mode);
        assert!(verify_ctx(&pk, &sig, b"msg", b"app-context", mode));
        // Wrong or missing context must fail.
        assert!(!verify_ctx(&pk, &sig, b"msg", b"other-context", mode));
        assert!(!verify(&pk, &sig, b"msg", mode));
        // A no-context signature differs from a context one.
        assert_ne!(sig, sign(&sk, b"msg", mode));
    }

    #[test]
    fn test_context_string_too_long() {
        let mode = SLH_DSA_SHAKE_128F;
        let seed = vec![42u8; mode.seed_bytes()];
        let (pk, sk) = keygen_seed(mode, &seed);

        let long_ctx = vec![0u8; 256];
        assert!(sign_ctx(&sk, b"msg", &long_ctx, mode).is_empty());
        let sig = sign(&sk, b"msg", mode);
        assert!(!verify_ctx(&pk, &sig, b"msg", &long_ctx, mode));

        // 255 bytes is the maximum valid context length.
        let max_ctx = vec![7u8; 255];
        let sig = sign_ctx(&sk, b"msg", &max_ctx, mode);
        assert!(verify_ctx(&pk, &sig, b"msg", &max_ctx, mode));
    }

    #[test]
    fn test_hedged_signing() {
        let mode = SLH_DSA_SHAKE_128F;
        let seed = vec![42u8; mode.seed_bytes()];
        let (pk, sk) = keygen_seed(mode, &seed);

        // Additional randomness that is too short is rejected.
        assert!(sign_internal(&sk, b"msg", Some(&[0u8; 4]), mode).is_empty());

        // Hedged signature differs from the deterministic one but verifies.
        let rnd = vec![0x55u8; mode.n];
        let hedged = sign_internal(&sk, b"msg", Some(&rnd), mode);
        let determ = sign_internal(&sk, b"msg", None, mode);
        assert_ne!(hedged, determ);
        assert!(verify_internal(&pk, &hedged, b"msg", mode));
        assert!(verify_internal(&pk, &determ, b"msg", mode));
    }
}
