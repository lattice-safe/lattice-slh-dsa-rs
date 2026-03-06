//! FORS (Forest of Random Subsets) few-time signature for SLH-DSA.

use alloc::vec;
use alloc::vec::Vec;
use crate::params::SlhDsaMode;
use crate::hash::SpxCtx;
use crate::thash::thash;
use crate::address::*;

/// Convert message bits to FORS tree indices.
fn message_to_indices(indices: &mut [u32], m: &[u8], mode: &SlhDsaMode) {
    let mut offset = 0usize;
    for i in 0..mode.fors_trees {
        indices[i] = 0;
        for j in 0..mode.fors_height {
            indices[i] ^= (((m[offset >> 3] >> (offset & 0x7)) & 1) as u32) << j;
            offset += 1;
        }
    }
}

/// Generate a FORS secret key value.
fn fors_gen_sk(sk: &mut [u8], ctx: &SpxCtx, addr: &Addr, mode: &SlhDsaMode) {
    crate::hash::prf_addr(sk, ctx, addr, mode);
}

/// Compute leaf from secret key.
fn fors_sk_to_leaf(leaf: &mut [u8], sk: &[u8], ctx: &SpxCtx, addr: &Addr, mode: &SlhDsaMode) {
    thash(leaf, sk, 1, ctx, addr, mode);
}

/// Compute the root of a subtree from a leaf and authentication path.
/// Exact port of compute_root from C reference (utils.c).
pub fn compute_root(
    root: &mut [u8],
    leaf: &[u8],
    leaf_idx: u32,
    idx_offset: u32,
    auth_path: &[u8],
    tree_height: usize,
    ctx: &SpxCtx,
    addr: &mut Addr,
    mode: &SlhDsaMode,
) {
    let n = mode.n;
    let mut buffer = vec![0u8; 2 * n];
    let mut leaf_idx = leaf_idx;
    let mut idx_offset = idx_offset;
    let mut auth_off = 0usize;

    if leaf_idx & 1 != 0 {
        buffer[n..2 * n].copy_from_slice(&leaf[..n]);
        buffer[..n].copy_from_slice(&auth_path[..n]);
    } else {
        buffer[..n].copy_from_slice(&leaf[..n]);
        buffer[n..2 * n].copy_from_slice(&auth_path[..n]);
    }
    auth_off += n;

    for i in 0..tree_height as u32 - 1 {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        set_tree_height(addr, i + 1, mode);
        set_tree_index(addr, leaf_idx + idx_offset, mode);

        let buf_copy = buffer.clone();
        if leaf_idx & 1 != 0 {
            thash(&mut buffer[n..2 * n], &buf_copy, 2, ctx, addr, mode);
            buffer[..n].copy_from_slice(&auth_path[auth_off..auth_off + n]);
        } else {
            thash(&mut buffer[..n], &buf_copy, 2, ctx, addr, mode);
            buffer[n..2 * n].copy_from_slice(&auth_path[auth_off..auth_off + n]);
        }
        auth_off += n;
    }

    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height as u32, mode);
    set_tree_index(addr, leaf_idx + idx_offset, mode);
    thash(root, &buffer, 2, ctx, addr, mode);
}

/// Treehash: computes root and auth path.
/// Exact port of treehash from C reference (utilsx1.c).
pub fn treehash(
    root: &mut [u8],
    auth_path: &mut [u8],
    leaves: &[u8],
    leaf_idx: u32,
    idx_offset: u32,
    tree_height: usize,
    ctx: &SpxCtx,
    addr: &mut Addr,
    mode: &SlhDsaMode,
) {
    let n = mode.n;
    let num_leaves = 1u32 << tree_height;

    let mut stack = vec![0u8; (tree_height + 1) * n];
    let mut heights = vec![0u32; tree_height + 1];
    let mut offset = 0usize;

    for idx in 0..num_leaves {
        stack[offset * n..(offset + 1) * n]
            .copy_from_slice(&leaves[idx as usize * n..(idx as usize + 1) * n]);
        offset += 1;
        heights[offset - 1] = 0;

        if (leaf_idx ^ 0x1) == idx {
            auth_path[..n].copy_from_slice(&stack[(offset - 1) * n..offset * n]);
        }

        while offset >= 2 && heights[offset - 1] == heights[offset - 2] {
            let tree_idx = idx >> (heights[offset - 1] + 1);

            set_tree_height(addr, heights[offset - 1] + 1, mode);
            set_tree_index(addr, tree_idx + (idx_offset >> (heights[offset - 1] + 1)), mode);

            let two_nodes = stack[(offset - 2) * n..offset * n].to_vec();
            thash(
                &mut stack[(offset - 2) * n..(offset - 1) * n],
                &two_nodes,
                2,
                ctx,
                addr,
                mode,
            );
            offset -= 1;
            heights[offset - 1] += 1;

            if ((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx {
                let h = heights[offset - 1] as usize;
                auth_path[h * n..(h + 1) * n]
                    .copy_from_slice(&stack[(offset - 1) * n..offset * n]);
            }
        }
    }

    root[..n].copy_from_slice(&stack[..n]);
}

/// FORS sign: produce FORS signature from message hash.
pub fn fors_sign(
    sig: &mut [u8],
    pk: &mut [u8],
    m: &[u8],
    ctx: &SpxCtx,
    fors_addr: &Addr,
    mode: &SlhDsaMode,
) {
    let n = mode.n;
    let mut indices = vec![0u32; mode.fors_trees];
    message_to_indices(&mut indices, m, mode);

    let mut roots = vec![0u8; mode.fors_trees * n];
    let mut sig_offset = 0usize;

    for i in 0..mode.fors_trees {
        let idx_offset = (i as u32) * (1u32 << mode.fors_height);

        let mut fors_leaf_addr: Addr = [0; ADDR_BYTES];
        copy_keypair_addr(&mut fors_leaf_addr, fors_addr, mode);
        set_tree_index(&mut fors_leaf_addr, indices[i] + idx_offset, mode);
        set_type(&mut fors_leaf_addr, ADDR_TYPE_FORSPRF, mode);
        fors_gen_sk(&mut sig[sig_offset..], ctx, &fors_leaf_addr, mode);
        sig_offset += n;

        // Build tree: generate all leaves
        let tree_size = 1usize << mode.fors_height;
        let mut leaves = vec![0u8; tree_size * n];
        for j in 0..tree_size {
            let mut leaf_addr: Addr = [0; ADDR_BYTES];
            copy_keypair_addr(&mut leaf_addr, fors_addr, mode);
            set_tree_index(&mut leaf_addr, j as u32 + idx_offset, mode);
            set_type(&mut leaf_addr, ADDR_TYPE_FORSPRF, mode);
            let mut sk = vec![0u8; n];
            fors_gen_sk(&mut sk, ctx, &leaf_addr, mode);
            set_type(&mut leaf_addr, ADDR_TYPE_FORSTREE, mode);
            fors_sk_to_leaf(&mut leaves[j * n..(j + 1) * n], &sk, ctx, &leaf_addr, mode);
        }

        let mut tree_addr: Addr = [0; ADDR_BYTES];
        copy_keypair_addr(&mut tree_addr, fors_addr, mode);
        set_type(&mut tree_addr, ADDR_TYPE_FORSTREE, mode);
        treehash(
            &mut roots[i * n..(i + 1) * n],
            &mut sig[sig_offset..sig_offset + mode.fors_height * n],
            &leaves,
            indices[i],
            idx_offset,
            mode.fors_height,
            ctx,
            &mut tree_addr,
            mode,
        );
        sig_offset += mode.fors_height * n;
    }

    let mut fors_pk_addr: Addr = [0; ADDR_BYTES];
    copy_keypair_addr(&mut fors_pk_addr, fors_addr, mode);
    set_type(&mut fors_pk_addr, ADDR_TYPE_FORSPK, mode);
    thash(pk, &roots, mode.fors_trees, ctx, &fors_pk_addr, mode);
}

/// FORS public key from signature (for verification).
pub fn fors_pk_from_sig(
    pk: &mut [u8],
    sig: &[u8],
    m: &[u8],
    ctx: &SpxCtx,
    fors_addr: &Addr,
    mode: &SlhDsaMode,
) {
    let n = mode.n;
    let mut indices = vec![0u32; mode.fors_trees];
    message_to_indices(&mut indices, m, mode);

    let mut roots = vec![0u8; mode.fors_trees * n];
    let mut sig_offset = 0usize;

    for i in 0..mode.fors_trees {
        let idx_offset = (i as u32) * (1u32 << mode.fors_height);

        let mut fors_tree_addr: Addr = [0; ADDR_BYTES];
        copy_keypair_addr(&mut fors_tree_addr, fors_addr, mode);
        set_type(&mut fors_tree_addr, ADDR_TYPE_FORSTREE, mode);
        set_tree_height(&mut fors_tree_addr, 0, mode);
        set_tree_index(&mut fors_tree_addr, indices[i] + idx_offset, mode);

        let mut leaf = vec![0u8; n];
        fors_sk_to_leaf(&mut leaf, &sig[sig_offset..sig_offset + n], ctx, &fors_tree_addr, mode);
        sig_offset += n;

        compute_root(
            &mut roots[i * n..(i + 1) * n],
            &leaf,
            indices[i],
            idx_offset,
            &sig[sig_offset..],
            mode.fors_height,
            ctx,
            &mut fors_tree_addr,
            mode,
        );
        sig_offset += mode.fors_height * n;
    }

    let mut fors_pk_addr: Addr = [0; ADDR_BYTES];
    copy_keypair_addr(&mut fors_pk_addr, fors_addr, mode);
    set_type(&mut fors_pk_addr, ADDR_TYPE_FORSPK, mode);
    thash(pk, &roots, mode.fors_trees, ctx, &fors_pk_addr, mode);
}
