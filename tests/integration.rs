//! Comprehensive tests for all 12 SLH-DSA parameter sets.

use slh_dsa::params::*;
use slh_dsa::sign::{keygen_seed, sign, verify};

/// Helper: test keygen/sign/verify roundtrip for a given mode.
fn roundtrip_test(mode: SlhDsaMode, name: &str) {
    let seed = vec![42u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);

    assert_eq!(pk.len(), mode.pk_bytes(), "{name}: pk size mismatch");
    assert_eq!(sk.len(), mode.sk_bytes(), "{name}: sk size mismatch");

    // sk embeds pk: sk = [SK_SEED || SK_PRF || PUB_SEED || root], pk = [PUB_SEED || root]
    assert_eq!(&sk[2 * mode.n..], &pk[..], "{name}: sk/pk consistency");

    let msg = b"Hello from SLH-DSA roundtrip test!";
    let sig = sign(&sk, msg, mode);
    assert_eq!(sig.len(), mode.sig_bytes(), "{name}: sig size mismatch");

    assert!(
        verify(&pk, &sig, msg, mode),
        "{name}: signature verification failed"
    );

    // Wrong message must fail
    assert!(
        !verify(&pk, &sig, b"wrong message", mode),
        "{name}: should reject wrong message"
    );

    // Tampered signature must fail
    let mut bad_sig = sig.clone();
    bad_sig[mode.n + 1] ^= 0xFF;
    assert!(
        !verify(&pk, &bad_sig, msg, mode),
        "{name}: should reject tampered signature"
    );
}

/// Helper: deterministic signing must be stable.
fn deterministic_test(mode: SlhDsaMode, name: &str) {
    let seed = vec![99u8; mode.seed_bytes()];
    let (_, sk) = keygen_seed(mode, &seed);
    let msg = b"deterministic test";
    let sig1 = sign(&sk, msg, mode);
    let sig2 = sign(&sk, msg, mode);
    assert_eq!(sig1, sig2, "{name}: deterministic signing must be stable");
}

// ===== SHAKE variants =====

#[test]
fn test_shake_128f_roundtrip() {
    roundtrip_test(SLH_DSA_SHAKE_128F, "SHAKE-128f");
}

#[test]
fn test_shake_128f_deterministic() {
    deterministic_test(SLH_DSA_SHAKE_128F, "SHAKE-128f");
}

#[test]
fn test_shake_128s_roundtrip() {
    roundtrip_test(SLH_DSA_SHAKE_128S, "SHAKE-128s");
}

#[test]
fn test_shake_192f_roundtrip() {
    roundtrip_test(SLH_DSA_SHAKE_192F, "SHAKE-192f");
}

#[test]
fn test_shake_192s_roundtrip() {
    roundtrip_test(SLH_DSA_SHAKE_192S, "SHAKE-192s");
}

#[test]
fn test_shake_256f_roundtrip() {
    roundtrip_test(SLH_DSA_SHAKE_256F, "SHAKE-256f");
}

#[test]
fn test_shake_256s_roundtrip() {
    roundtrip_test(SLH_DSA_SHAKE_256S, "SHAKE-256s");
}

// ===== SHA-2 variants =====

#[test]
fn test_sha2_128f_roundtrip() {
    roundtrip_test(SLH_DSA_SHA2_128F, "SHA2-128f");
}

#[test]
fn test_sha2_128s_roundtrip() {
    roundtrip_test(SLH_DSA_SHA2_128S, "SHA2-128s");
}

#[test]
fn test_sha2_192f_roundtrip() {
    roundtrip_test(SLH_DSA_SHA2_192F, "SHA2-192f");
}

#[test]
fn test_sha2_192s_roundtrip() {
    roundtrip_test(SLH_DSA_SHA2_192S, "SHA2-192s");
}

#[test]
fn test_sha2_256f_roundtrip() {
    roundtrip_test(SLH_DSA_SHA2_256F, "SHA2-256f");
}

#[test]
fn test_sha2_256s_roundtrip() {
    roundtrip_test(SLH_DSA_SHA2_256S, "SHA2-256s");
}

// ===== Edge cases =====

#[test]
fn test_empty_message() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![1u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);
    let sig = sign(&sk, b"", mode);
    assert!(verify(&pk, &sig, b"", mode), "empty message should verify");
}

#[test]
fn test_large_message() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![2u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);
    let msg = vec![0xABu8; 10_000];
    let sig = sign(&sk, &msg, mode);
    assert!(verify(&pk, &sig, &msg, mode), "10KB message should verify");
}

#[test]
fn test_wrong_pk_fails() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed1 = vec![1u8; mode.seed_bytes()];
    let seed2 = vec![2u8; mode.seed_bytes()];
    let (_, sk1) = keygen_seed(mode, &seed1);
    let (pk2, _) = keygen_seed(mode, &seed2);
    let sig = sign(&sk1, b"test", mode);
    assert!(!verify(&pk2, &sig, b"test", mode), "wrong pk should reject");
}

#[test]
fn test_truncated_sig_fails() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![3u8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);
    let sig = sign(&sk, b"test", mode);
    assert!(
        !verify(&pk, &sig[..sig.len() - 1], b"test", mode),
        "truncated sig should reject"
    );
}
