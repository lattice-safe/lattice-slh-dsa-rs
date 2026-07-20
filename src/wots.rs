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

    let mut sk = vec![0u8; n];
    let mut chain_out = vec![0u8; n];

    for i in 0..wots_len {
        set_chain_addr(addr, i as u32, mode);
        set_hash_addr(addr, 0, mode);
        // C reference: set type to WOTSPRF before prf_addr, then revert to WOTS
        set_type(addr, ADDR_TYPE_WOTSPRF, mode);
        sk.iter_mut().for_each(|b| *b = 0);
        crate::hash::prf_addr(&mut sk, ctx, addr, mode);
        set_type(addr, ADDR_TYPE_WOTS, mode);
        // Apply chain up to lengths[i]
        gen_chain(&mut chain_out, &sk, 0, lengths[i], ctx, addr, mode);
        sig[i * n..(i + 1) * n].copy_from_slice(&chain_out);
    }
    sk.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SLH_DSA_SHAKE_128F;

    #[test]
    fn test_base_w_w16_nibbles() {
        let mut out = [0u32; 4];
        base_w(&mut out, 4, &[0xAB, 0xCD], 16);
        assert_eq!(out, [0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn test_base_w_w256_bytes() {
        let mut out = [0u32; 2];
        base_w(&mut out, 2, &[0xAB, 0xCD], 256);
        assert_eq!(out, [0xAB, 0xCD]);
    }

    #[test]
    fn test_chain_lengths_checksum() {
        let mode = SLH_DSA_SHAKE_128F;
        let mut lengths = vec![0u32; mode.wots_len()];

        // All-zero message: csum = len1 * (w - 1) = 32 * 15 = 480 = 0x1E0.
        // Left-shifted by 4 (12-bit checksum) -> 0x1E00 -> nibbles [1, 14, 0].
        chain_lengths(&mut lengths, &[0u8; 16], &mode);
        assert!(lengths[..mode.wots_len1()].iter().all(|&v| v == 0));
        assert_eq!(&lengths[mode.wots_len1()..], &[1, 14, 0]);

        // All-0xFF message: every digit is w-1, csum = 0.
        chain_lengths(&mut lengths, &[0xFFu8; 16], &mode);
        assert!(lengths[..mode.wots_len1()].iter().all(|&v| v == 15));
        assert_eq!(&lengths[mode.wots_len1()..], &[0, 0, 0]);

        // Every digit must be < w.
        chain_lengths(&mut lengths, &[0x37u8; 16], &mode);
        assert!(lengths.iter().all(|&v| v < mode.wots_w as u32));
    }
}
