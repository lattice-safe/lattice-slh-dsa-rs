//! WOTS+ one-time signature scheme for SLH-DSA.

use alloc::vec;
use alloc::vec::Vec;
use crate::params::SlhDsaMode;
use crate::hash::SpxCtx;
use crate::thash::thash;
use crate::address::*;

/// Compute base-w representation of `input`.
fn base_w(output: &mut [u32], out_len: usize, input: &[u8], w: usize) {
    let logw = if w == 16 { 4 } else { 8 };
    let mut in_idx = 0usize;
    let mut bits = 0u32;
    let mut total = 0u32;

    for i in 0..out_len {
        if bits == 0 {
            total = input[in_idx] as u32;
            in_idx += 1;
            bits += 8;
        }
        bits -= logw;
        output[i] = (total >> bits) & ((w as u32) - 1);
    }
}

/// Compute WOTS+ checksum.
fn wots_checksum(csum_output: &mut [u32], msg_base_w: &[u32], mode: &SlhDsaMode) {
    let mut csum: u32 = 0;
    for i in 0..mode.wots_len1() {
        csum += (mode.wots_w as u32 - 1) - msg_base_w[i];
    }

    let csum_bits = mode.wots_len2() * mode.wots_logw();
    csum <<= (8 - (csum_bits % 8)) % 8;

    let csum_bytes = (csum_bits + 7) / 8;
    let mut csum_buf = vec![0u8; csum_bytes];
    for i in 0..csum_bytes {
        csum_buf[i] = (csum >> (8 * (csum_bytes - 1 - i))) as u8;
    }

    base_w(csum_output, mode.wots_len2(), &csum_buf, mode.wots_w);
}

/// Compute chain lengths from a message.
pub fn chain_lengths(lengths: &mut [u32], msg: &[u8], mode: &SlhDsaMode) {
    base_w(lengths, mode.wots_len1(), msg, mode.wots_w);
    let len1 = mode.wots_len1();
    let mut csum_out = vec![0u32; mode.wots_len2()];
    wots_checksum(&mut csum_out, &lengths[..len1], mode);
    lengths[len1..len1 + mode.wots_len2()].copy_from_slice(&csum_out);
}

/// Iteratively apply the chain function.
fn gen_chain(
    out: &mut [u8],
    input: &[u8],
    start: u32,
    steps: u32,
    ctx: &SpxCtx,
    addr: &mut Addr,
    mode: &SlhDsaMode,
) {
    out[..mode.n].copy_from_slice(&input[..mode.n]);

    for i in start..start + steps {
        set_hash_addr(addr, i, mode);
        let tmp = out[..mode.n].to_vec();
        thash(out, &tmp, 1, ctx, addr, mode);
    }
}

/// Compute WOTS+ public key from signature.
pub fn wots_pk_from_sig(
    pk: &mut [u8],
    sig: &[u8],
    msg: &[u8],
    ctx: &SpxCtx,
    addr: &mut Addr,
    mode: &SlhDsaMode,
) {
    let wots_len = mode.wots_len();
    let n = mode.n;
    let w = mode.wots_w as u32;

    let mut lengths = vec![0u32; wots_len];
    chain_lengths(&mut lengths, msg, mode);

    for i in 0..wots_len {
        set_chain_addr(addr, i as u32, mode);
        let mut chain_out = vec![0u8; n];
        gen_chain(
            &mut chain_out,
            &sig[i * n..(i + 1) * n],
            lengths[i],
            w - 1 - lengths[i],
            ctx,
            addr,
            mode,
        );
        pk[i * n..(i + 1) * n].copy_from_slice(&chain_out);
    }
}

/// Generate WOTS+ signature for a message (n-byte hash).
pub fn wots_sign(
    sig: &mut [u8],
    msg: &[u8],
    ctx: &SpxCtx,
    addr: &mut Addr,
    mode: &SlhDsaMode,
) {
    let wots_len = mode.wots_len();
    let n = mode.n;

    let mut lengths = vec![0u32; wots_len];
    chain_lengths(&mut lengths, msg, mode);

    for i in 0..wots_len {
        set_chain_addr(addr, i as u32, mode);
        set_hash_addr(addr, 0, mode);
        // Generate secret key element
        let mut sk = vec![0u8; n];
        crate::hash::prf_addr(&mut sk, ctx, addr, mode);
        // Apply chain up to lengths[i]
        let mut chain_out = vec![0u8; n];
        gen_chain(&mut chain_out, &sk, 0, lengths[i], ctx, addr, mode);
        sig[i * n..(i + 1) * n].copy_from_slice(&chain_out);
    }
}
