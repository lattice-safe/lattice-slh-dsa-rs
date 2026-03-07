//! Merkle tree operations for the SLH-DSA hypertree.

use crate::address::*;
use crate::fors;
use crate::hash::SpxCtx;
use crate::params::SlhDsaMode;
use crate::thash::thash;
use crate::wots;
use alloc::vec;

/// Generate a WOTS+ leaf: generates the full WOTS+ pk, then hashes it.
/// If this is the target leaf for signing, also computes the WOTS+ signature.
fn wots_gen_leaf_and_sign(
    leaf: &mut [u8],
    mut wots_sig: Option<(&mut [u8], &[u8])>,
    ctx: &SpxCtx,
    leaf_idx: u32,
    tree_addr: &Addr,
    mode: &SlhDsaMode,
) {
    let n = mode.n;
    let wots_len = mode.wots_len();

    let mut leaf_addr: Addr = [0; ADDR_BYTES];
    let mut pk_addr: Addr = [0; ADDR_BYTES];
    copy_subtree_addr(&mut leaf_addr, tree_addr, mode);
    copy_subtree_addr(&mut pk_addr, tree_addr, mode);
    set_type(&mut leaf_addr, ADDR_TYPE_WOTS, mode);
    set_type(&mut pk_addr, ADDR_TYPE_WOTSPK, mode);
    set_keypair_addr(&mut leaf_addr, leaf_idx, mode);
    copy_keypair_addr(&mut pk_addr, &leaf_addr, mode);

    let mut steps = vec![0u32; wots_len];
    if let Some((_, root)) = &wots_sig {
        wots::chain_lengths(&mut steps, root, mode);
    }

    let mut wots_pk = vec![0u8; wots_len * n];
    let is_signing = wots_sig.is_some();

    for i in 0..wots_len {
        set_chain_addr(&mut leaf_addr, i as u32, mode);
        set_hash_addr(&mut leaf_addr, 0, mode);

        // C reference: set type to WOTSPRF before prf_addr, then revert to WOTS
        set_type(&mut leaf_addr, ADDR_TYPE_WOTSPRF, mode);
        let mut sk = vec![0u8; n];
        crate::hash::prf_addr(&mut sk, ctx, &leaf_addr, mode);
        set_type(&mut leaf_addr, ADDR_TYPE_WOTS, mode);

        let mut val = sk.clone();

        if is_signing {
            for j in 0..steps[i] {
                set_hash_addr(&mut leaf_addr, j, mode);
                let tmp = val.clone();
                thash(&mut val, &tmp, 1, ctx, &leaf_addr, mode);
            }
            if let Some((ref mut sig_buf, _)) = wots_sig {
                sig_buf[i * n..(i + 1) * n].copy_from_slice(&val);
            }

            for j in steps[i]..mode.wots_w as u32 - 1 {
                set_hash_addr(&mut leaf_addr, j, mode);
                let tmp = val.clone();
                thash(&mut val, &tmp, 1, ctx, &leaf_addr, mode);
            }
        } else {
            for j in 0..mode.wots_w as u32 - 1 {
                set_hash_addr(&mut leaf_addr, j, mode);
                let tmp = val.clone();
                thash(&mut val, &tmp, 1, ctx, &leaf_addr, mode);
            }
        }

        wots_pk[i * n..(i + 1) * n].copy_from_slice(&val);
    }

    thash(leaf, &wots_pk, wots_len, ctx, &pk_addr, mode);
}

/// Merkle sign: produce WOTS+ signature and authentication path.
pub fn merkle_sign(
    sig: &mut [u8],
    root: &mut [u8],
    ctx: &SpxCtx,
    _wots_addr: &Addr,
    tree_addr: &Addr,
    idx_leaf: u32,
    mode: &SlhDsaMode,
) {
    let n = mode.n;
    let tree_height = mode.tree_height();
    let num_leaves = 1usize << tree_height;
    let wots_bytes = mode.wots_bytes();

    let mut leaves = vec![0u8; num_leaves * n];

    for i in 0..num_leaves {
        if i as u32 == idx_leaf {
            let root_copy = root.to_vec();
            wots_gen_leaf_and_sign(
                &mut leaves[i * n..(i + 1) * n],
                Some((&mut sig[..wots_bytes], &root_copy)),
                ctx,
                i as u32,
                tree_addr,
                mode,
            );
        } else {
            wots_gen_leaf_and_sign(
                &mut leaves[i * n..(i + 1) * n],
                None,
                ctx,
                i as u32,
                tree_addr,
                mode,
            );
        }
    }

    let mut t_addr: Addr = [0; ADDR_BYTES];
    copy_subtree_addr(&mut t_addr, tree_addr, mode);
    set_type(&mut t_addr, ADDR_TYPE_HASHTREE, mode);

    fors::treehash(
        root,
        &mut sig[wots_bytes..],
        &leaves,
        idx_leaf,
        0,
        tree_height,
        ctx,
        &mut t_addr,
        mode,
    );
}

/// Generate root node of the top-most subtree.
pub fn merkle_gen_root(root: &mut [u8], ctx: &SpxCtx, mode: &SlhDsaMode) {
    let n = mode.n;
    let tree_height = mode.tree_height();
    let num_leaves = 1usize << tree_height;

    let mut top_tree_addr: Addr = [0; ADDR_BYTES];
    set_layer_addr(&mut top_tree_addr, (mode.d - 1) as u32, mode);

    let mut leaves = vec![0u8; num_leaves * n];
    for i in 0..num_leaves {
        wots_gen_leaf_and_sign(
            &mut leaves[i * n..(i + 1) * n],
            None,
            ctx,
            i as u32,
            &top_tree_addr,
            mode,
        );
    }

    let mut t_addr: Addr = [0; ADDR_BYTES];
    copy_subtree_addr(&mut t_addr, &top_tree_addr, mode);
    set_type(&mut t_addr, ADDR_TYPE_HASHTREE, mode);

    let mut dummy_auth = vec![0u8; tree_height * n];
    fors::treehash(
        root,
        &mut dummy_auth,
        &leaves,
        0,
        0,
        tree_height,
        ctx,
        &mut t_addr,
        mode,
    );
}
