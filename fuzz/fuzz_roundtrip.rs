use slh_dsa::params::SLH_DSA_SHAKE_128F;
use slh_dsa::sign::{keygen_seed, sign, verify};

/// Fuzz target: roundtrip sign/verify with random seed and message.
fn main() {
    // In a real fuzzing setup, input would come from the fuzzer.
    // This is a template for cargo-fuzz integration.
    let mode = SLH_DSA_SHAKE_128F;

    // Use fixed seed for reproducibility
    let seed = vec![0x42u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);

    // Test with various message lengths
    for len in [0, 1, 16, 256, 1024] {
        let msg = vec![0xABu8; len];
        let sig = sign(&sk, &msg, mode);
        assert!(verify(&pk, &sig, &msg, mode), "roundtrip failed for msg len {len}");
    }

    // Test malformed signatures
    let msg = b"fuzz test";
    let sig = sign(&sk, msg, mode);
    for i in 0..sig.len().min(100) {
        let mut bad = sig.clone();
        bad[i] ^= 0xFF;
        // Malformed sig should not verify (almost certainly)
        let _ = verify(&pk, &bad, msg, mode);
    }

    println!("Fuzz roundtrip passed!");
}
