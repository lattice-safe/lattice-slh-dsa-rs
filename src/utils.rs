//! Utility functions for SLH-DSA.


/// Convert bytes to u64 (big-endian), reading `n` bytes.
pub fn bytes_to_ull(bytes: &[u8], n: usize) -> u64 {
    let mut result: u64 = 0;
    for b in bytes.iter().take(n) {
        result = (result << 8) | *b as u64;
    }
    result
}

/// Convert u64 to bytes (big-endian), writing `n` bytes.
#[allow(dead_code)]
pub fn ull_to_bytes(out: &mut [u8], n: usize, val: u64) {
    for (i, byte) in out.iter_mut().enumerate().take(n) {
        *byte = (val >> (8 * (n - 1 - i))) as u8;
    }
}
