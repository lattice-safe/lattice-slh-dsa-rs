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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_ull() {
        assert_eq!(bytes_to_ull(&[0x12, 0x34, 0x56], 3), 0x123456);
        assert_eq!(bytes_to_ull(&[0xff; 8], 8), u64::MAX);
        assert_eq!(bytes_to_ull(&[0x12, 0x34], 1), 0x12);
        assert_eq!(bytes_to_ull(&[], 0), 0);
    }

    #[test]
    fn test_ull_to_bytes() {
        let mut out = [0u8; 4];
        ull_to_bytes(&mut out, 4, 0x0102_0304);
        assert_eq!(out, [1, 2, 3, 4]);

        let mut out2 = [0u8; 8];
        ull_to_bytes(&mut out2, 8, u64::MAX);
        assert_eq!(out2, [0xff; 8]);
    }

    #[test]
    fn test_roundtrip() {
        let val = 0xdead_beef_cafe_u64;
        let mut buf = [0u8; 6];
        ull_to_bytes(&mut buf, 6, val);
        assert_eq!(bytes_to_ull(&buf, 6), val);
    }
}
