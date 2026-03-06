//! Utility functions for SLH-DSA.

use alloc::vec;
use alloc::vec::Vec;

/// Convert bytes to u64 (big-endian), reading `n` bytes.
pub fn bytes_to_ull(bytes: &[u8], n: usize) -> u64 {
    let mut result: u64 = 0;
    for i in 0..n {
        result = (result << 8) | bytes[i] as u64;
    }
    result
}

/// Convert u64 to bytes (big-endian), writing `n` bytes.
pub fn ull_to_bytes(out: &mut [u8], n: usize, val: u64) {
    for i in 0..n {
        out[i] = (val >> (8 * (n - 1 - i))) as u8;
    }
}
