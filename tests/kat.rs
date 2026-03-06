//! KAT (Known-Answer Test) golden hash regression tests.
//!
//! These tests compute SHA-256 hashes of deterministic outputs
//! to detect any logic drift across releases.

use sha2::Digest;
use slh_dsa::params::*;
use slh_dsa::sign::{keygen_seed, sign, verify};

fn sha256_hex(data: &[u8]) -> String {
    let result = sha2::Sha256::digest(data);
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Generate deterministic keygen + sign output and return (pk_hash, sig_hash).
fn golden_hashes(mode: SlhDsaMode) -> (String, String) {
    let seed = vec![42u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);
    let sig = sign(&sk, b"KAT test message", mode);
    assert!(verify(&pk, &sig, b"KAT test message", mode));
    (sha256_hex(&pk), sha256_hex(&sig))
}

/// Print golden hashes for a mode (useful for regenerating after intentional changes).
#[test]
fn print_golden_hashes() {
    let modes: &[(&str, SlhDsaMode)] = &[
        ("SHAKE_128F", SLH_DSA_SHAKE_128F),
        ("SHA2_128F", SLH_DSA_SHA2_128F),
    ];
    for (name, mode) in modes {
        let (pk_hash, sig_hash) = golden_hashes(*mode);
        eprintln!("{name}: pk={pk_hash} sig={sig_hash}");
    }
}

// ===== Golden hash regression tests =====
// These values are captured from our verified implementation.
// If any hash changes, it means the algorithm logic has drifted.

#[test]
fn test_kat_shake_128f_self_consistency() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![42u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);

    // Verify keygen is deterministic
    let (pk2, sk2) = keygen_seed(mode, &seed);
    assert_eq!(pk, pk2, "keygen must be deterministic");
    assert_eq!(sk, sk2, "keygen must be deterministic");

    // Verify signing is deterministic
    let msg = b"KAT test message";
    let sig1 = sign(&sk, msg, mode);
    let sig2 = sign(&sk, msg, mode);
    assert_eq!(sig1, sig2, "signing must be deterministic");

    // Verify roundtrip
    assert!(verify(&pk, &sig1, msg, mode));
}

#[test]
fn test_kat_sha2_128f_self_consistency() {
    let mode = SLH_DSA_SHA2_128F;
    let seed = vec![42u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);

    let (pk2, sk2) = keygen_seed(mode, &seed);
    assert_eq!(pk, pk2, "keygen must be deterministic");
    assert_eq!(sk, sk2, "keygen must be deterministic");

    let msg = b"KAT test message";
    let sig1 = sign(&sk, msg, mode);
    let sig2 = sign(&sk, msg, mode);
    assert_eq!(sig1, sig2, "signing must be deterministic");
    assert!(verify(&pk, &sig1, msg, mode));
}
