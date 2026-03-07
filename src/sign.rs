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

/// Sign a message.
pub fn sign(sk: &[u8], m: &[u8], mode: SlhDsaMode) -> Vec<u8> {
    let n = mode.n;

    if sk.len() < mode.sk_bytes() {
        return vec![];
    }

    let sk_seed = &sk[..n];
    let sk_prf = &sk[n..2 * n];
    let pk = &sk[2 * n..];

    let mut ctx = SpxCtx::new(n);
    ctx.sk_seed.copy_from_slice(sk_seed);
    ctx.pub_seed.copy_from_slice(&pk[..n]);

    let mut sig = vec![0u8; mode.sig_bytes()];
    let mut sig_offset = 0usize;

    let optrand = vec![0u8; n];
    gen_message_random(&mut sig[..n], sk_prf, &optrand, m, &mode);
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

/// Verify a signature.
pub fn verify(pk: &[u8], sig: &[u8], m: &[u8], mode: SlhDsaMode) -> bool {
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
}
