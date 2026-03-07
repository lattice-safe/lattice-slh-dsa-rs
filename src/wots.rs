//! WOTS+ one-time signature scheme for SLH-DSA.

use crate::address::*;
use crate::hash::SpxCtx;
use crate::params::SlhDsaMode;
use crate::thash::thash;
use alloc::vec;
use zeroize::Zeroize;

/// Compute base-w representation of `input`.
fn base_w(output: &mut [u32], out_len: usize, input: &[u8], w: usize) {
    let logw = if w == 16 { 4 } else { 8 };
    let mut in_idx = 0usize;
    let mut bits = 0u32;
    let mut total = 0u32;

    for item in output.iter_mut().take(out_len) {
        if bits == 0 {
            total = input[in_idx] as u32;
            in_idx += 1;
            bits += 8;
        }
        bits -= logw;
        *item = (total >> bits) & ((w as u32) - 1);
    }
}

/// Compute WOTS+ checksum.
fn wots_checksum(csum_output: &mut [u32], msg_base_w: &[u32], mode: &SlhDsaMode) {
    let mut csum: u32 = 0;
    for val in msg_base_w.iter().take(mode.wots_len1()) {
        csum += (mode.wots_w as u32 - 1) - val;
    }

    let csum_bits = mode.wots_len2() * mode.wots_logw();
    csum <<= (8 - (csum_bits % 8)) % 8;

    let csum_bytes = (csum_bits + 7) / 8;
    let mut csum_buf = vec![0u8; csum_bytes];
    for (i, byte) in csum_buf.iter_mut().enumerate() {
        *byte = (csum >> (8 * (csum_bytes - 1 - i))) as u8;
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
pub fn wots_sign(sig: &mut [u8], msg: &[u8], ctx: &SpxCtx, addr: &mut Addr, mode: &SlhDsaMode) {
    let wots_len = mode.wots_len();
    let n = mode.n;

    let mut lengths = vec![0u32; wots_len];
    chain_lengths(&mut lengths, msg, mode);

    for i in 0..wots_len {
        set_chain_addr(addr, i as u32, mode);
        set_hash_addr(addr, 0, mode);
        // C reference: set type to WOTSPRF before prf_addr, then revert to WOTS
        set_type(addr, ADDR_TYPE_WOTSPRF, mode);
        let mut sk = vec![0u8; n];
        crate::hash::prf_addr(&mut sk, ctx, addr, mode);
        set_type(addr, ADDR_TYPE_WOTS, mode);
        // Apply chain up to lengths[i]
        let mut chain_out = vec![0u8; n];
        gen_chain(&mut chain_out, &sk, 0, lengths[i], ctx, addr, mode);
        sk.zeroize();
        sig[i * n..(i + 1) * n].copy_from_slice(&chain_out);
    }
}
