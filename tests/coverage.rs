//! Edge-case and full-coverage tests for lattice-slh-dsa.
//!
//! Mirrors dilithium-rs/tests/coverage.rs.

use slh_dsa::params::*;
use slh_dsa::safe_api::*;
use slh_dsa::sign::{keygen_seed, sign, verify};

// ================================================================
// FIPS 205 parameter size validation
// ================================================================

#[test]
fn test_all_mode_sizes_match_fips205() {
    // FIPS 205 Table 1 — SHAKE variants
    let shake128f = SLH_DSA_SHAKE_128F;
    assert_eq!(shake128f.n, 16);
    assert_eq!(shake128f.pk_bytes(), 32);
    assert_eq!(shake128f.sk_bytes(), 64);
    assert_eq!(shake128f.sig_bytes(), 17088);

    let shake192f = SLH_DSA_SHAKE_192F;
    assert_eq!(shake192f.n, 24);
    assert_eq!(shake192f.pk_bytes(), 48);
    assert_eq!(shake192f.sk_bytes(), 96);

    let shake256f = SLH_DSA_SHAKE_256F;
    assert_eq!(shake256f.n, 32);
    assert_eq!(shake256f.pk_bytes(), 64);
    assert_eq!(shake256f.sk_bytes(), 128);

    // SHA-2 variants should have same sizes as SHAKE for same security level
    assert_eq!(SLH_DSA_SHA2_128F.pk_bytes(), SLH_DSA_SHAKE_128F.pk_bytes());
    assert_eq!(SLH_DSA_SHA2_128F.sk_bytes(), SLH_DSA_SHAKE_128F.sk_bytes());
    assert_eq!(
        SLH_DSA_SHA2_128F.sig_bytes(),
        SLH_DSA_SHAKE_128F.sig_bytes()
    );

    assert_eq!(SLH_DSA_SHA2_192F.pk_bytes(), SLH_DSA_SHAKE_192F.pk_bytes());
    assert_eq!(SLH_DSA_SHA2_256F.pk_bytes(), SLH_DSA_SHAKE_256F.pk_bytes());
}

// ================================================================
// Cross-mode rejection
// ================================================================

#[test]
fn test_cross_mode_rejection_shake_sha2() {
    let mode1 = SLH_DSA_SHAKE_128F;
    let mode2 = SLH_DSA_SHA2_128F;
    let seed = vec![42u8; mode1.seed_bytes()];
    let (pk1, sk1) = keygen_seed(mode1, &seed);
    let sig1 = sign(&sk1, b"msg", mode1);

    // Same-mode verify should succeed
    assert!(verify(&pk1, &sig1, b"msg", mode1));

    // Cross-hash-family verify should fail
    assert!(
        !verify(&pk1, &sig1, b"msg", mode2),
        "SHAKE sig should not verify under SHA2 mode"
    );
}

#[test]
fn test_cross_security_level_rejection() {
    let seed128 = vec![42u8; SLH_DSA_SHAKE_128F.seed_bytes()];
    let (pk128, sk128) = keygen_seed(SLH_DSA_SHAKE_128F, &seed128);
    let sig128 = sign(&sk128, b"msg", SLH_DSA_SHAKE_128F);

    // 128f sig (17088 bytes) != 192f sig size, so verify should fail
    assert!(
        !verify(&pk128, &sig128, b"msg", SLH_DSA_SHAKE_192F),
        "128f sig should not verify under 192f mode"
    );
}

// ================================================================
// Key import validation (Safe API)
// ================================================================

#[test]
fn test_from_bytes_wrong_pk_size() {
    let result = SlhDsaKeyPair::from_bytes(SLH_DSA_SHAKE_128F, &[0u8; 10], &[0u8; 64]);
    assert_eq!(result.err(), Some(SlhDsaError::BadArgument));
}

#[test]
fn test_from_bytes_wrong_sk_size() {
    let result = SlhDsaKeyPair::from_bytes(SLH_DSA_SHAKE_128F, &[0u8; 32], &[0u8; 10]);
    assert_eq!(result.err(), Some(SlhDsaError::BadArgument));
}

#[test]
fn test_from_seed_too_short() {
    let result = SlhDsaKeyPair::from_seed(SLH_DSA_SHAKE_128F, &[0u8; 5]);
    assert_eq!(result.err(), Some(SlhDsaError::BadArgument));
}

#[test]
fn test_from_bytes_roundtrip_all_modes() {
    let modes = [
        SLH_DSA_SHAKE_128F,
        SLH_DSA_SHA2_128F,
        SLH_DSA_SHAKE_192F,
        SLH_DSA_SHAKE_256F,
    ];
    for mode in &modes {
        let seed = vec![0x42u8; mode.seed_bytes()];
        let kp = SlhDsaKeyPair::from_seed(*mode, &seed).unwrap();
        let kp2 = SlhDsaKeyPair::from_bytes(*mode, kp.public_key(), kp.secret_key()).unwrap();
        assert_eq!(kp.public_key(), kp2.public_key());
        assert_eq!(kp.secret_key(), kp2.secret_key());
    }
}

// ================================================================
// Signature bytes round-trip
// ================================================================

#[test]
fn test_signature_from_bytes_roundtrip() {
    let mode = SLH_DSA_SHAKE_128F;
    let kp = SlhDsaKeyPair::generate(mode).unwrap();
    let sig = kp.sign(b"msg").unwrap();
    let sig2 = SlhDsaSignature::from_bytes(mode, sig.to_bytes()).unwrap();
    assert!(SlhDsaSignature::verify(
        sig2.to_bytes(),
        kp.public_key(),
        b"msg",
        mode,
    ));
}

#[test]
fn test_signature_from_bytes_wrong_size() {
    let result = SlhDsaSignature::from_bytes(SLH_DSA_SHAKE_128F, &[0u8; 100]);
    assert_eq!(result.err(), Some(SlhDsaError::BadArgument));
}

// ================================================================
// Deterministic keygen consistency
// ================================================================

#[test]
fn test_deterministic_keygen_all_modes() {
    let modes = [
        SLH_DSA_SHAKE_128F,
        SLH_DSA_SHAKE_128S,
        SLH_DSA_SHAKE_192F,
        SLH_DSA_SHAKE_192S,
        SLH_DSA_SHAKE_256F,
        SLH_DSA_SHAKE_256S,
        SLH_DSA_SHA2_128F,
        SLH_DSA_SHA2_128S,
        SLH_DSA_SHA2_192F,
        SLH_DSA_SHA2_192S,
        SLH_DSA_SHA2_256F,
        SLH_DSA_SHA2_256S,
    ];
    for mode in &modes {
        let seed = vec![0x42u8; mode.seed_bytes()];
        let (pk1, sk1) = keygen_seed(*mode, &seed);
        let (pk2, sk2) = keygen_seed(*mode, &seed);
        assert_eq!(pk1, pk2, "{}: keygen not deterministic", mode.name);
        assert_eq!(sk1, sk2, "{}: keygen not deterministic", mode.name);

        // Different seed → different keys
        let seed2 = vec![0x43u8; mode.seed_bytes()];
        let (pk3, _) = keygen_seed(*mode, &seed2);
        assert_ne!(
            pk3, pk1,
            "{}: different seeds should produce different keys",
            mode.name
        );
    }
}

// ================================================================
// Deterministic signing consistency
// ================================================================

#[test]
fn test_deterministic_signing_all_fast_modes() {
    let modes = [
        SLH_DSA_SHAKE_128F,
        SLH_DSA_SHA2_128F,
        SLH_DSA_SHAKE_192F,
        SLH_DSA_SHAKE_256F,
    ];
    for mode in &modes {
        let seed = vec![0x42u8; mode.seed_bytes()];
        let (_, sk) = keygen_seed(*mode, &seed);
        let sig1 = sign(&sk, b"msg", *mode);
        let sig2 = sign(&sk, b"msg", *mode);
        assert_eq!(sig1, sig2, "{}: signing not deterministic", mode.name);
    }
}

// ================================================================
// Empty and large messages
// ================================================================

#[test]
fn test_sign_empty_message_all_fast() {
    let modes = [SLH_DSA_SHAKE_128F, SLH_DSA_SHA2_128F];
    for mode in &modes {
        let seed = vec![1u8; mode.seed_bytes()];
        let (pk, sk) = keygen_seed(*mode, &seed);
        let sig = sign(&sk, b"", *mode);
        assert!(
            verify(&pk, &sig, b"", *mode),
            "{}: empty msg failed",
            mode.name
        );
    }
}

#[test]
fn test_sign_large_message() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![2u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);
    let msg = vec![0xABu8; 100_000];
    let sig = sign(&sk, &msg, mode);
    assert!(verify(&pk, &sig, &msg, mode), "100KB msg failed");
}

// ================================================================
// Verify error paths
// ================================================================

#[test]
fn test_verify_wrong_pk_size() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![1u8; mode.seed_bytes()];
    let (_, sk) = keygen_seed(mode, &seed);
    let sig = sign(&sk, b"msg", mode);
    // Wrong pk size should fail gracefully
    assert!(!verify(&[0u8; 10], &sig, b"msg", mode));
}

#[test]
fn test_verify_wrong_sig_size() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![1u8; mode.seed_bytes()];
    let (pk, _sk) = keygen_seed(mode, &seed);
    assert!(!verify(&pk, &[0u8; 100], b"msg", mode));
}

#[test]
fn test_verify_corrupted_sig() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![1u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);
    let mut sig = sign(&sk, b"msg", mode);

    // Flip a byte in the middle of the signature
    let mid = sig.len() / 2;
    sig[mid] ^= 0xFF;
    assert!(
        !verify(&pk, &sig, b"msg", mode),
        "corrupted sig should fail"
    );
}

// ================================================================
// Mode name coverage
// ================================================================

#[test]
fn test_all_mode_names() {
    let modes = [
        (SLH_DSA_SHAKE_128F, "SLH-DSA-SHAKE-128f"),
        (SLH_DSA_SHAKE_128S, "SLH-DSA-SHAKE-128s"),
        (SLH_DSA_SHAKE_192F, "SLH-DSA-SHAKE-192f"),
        (SLH_DSA_SHAKE_192S, "SLH-DSA-SHAKE-192s"),
        (SLH_DSA_SHAKE_256F, "SLH-DSA-SHAKE-256f"),
        (SLH_DSA_SHAKE_256S, "SLH-DSA-SHAKE-256s"),
        (SLH_DSA_SHA2_128F, "SLH-DSA-SHA2-128f"),
        (SLH_DSA_SHA2_128S, "SLH-DSA-SHA2-128s"),
        (SLH_DSA_SHA2_192F, "SLH-DSA-SHA2-192f"),
        (SLH_DSA_SHA2_192S, "SLH-DSA-SHA2-192s"),
        (SLH_DSA_SHA2_256F, "SLH-DSA-SHA2-256f"),
        (SLH_DSA_SHA2_256S, "SLH-DSA-SHA2-256s"),
    ];
    for (mode, expected_name) in &modes {
        assert_eq!(mode.name, *expected_name);
    }
}
