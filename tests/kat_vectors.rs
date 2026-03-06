//! KAT (Known-Answer Test) golden hash validation.
//!
//! Uses SHAKE-256 hashes of deterministic keygen/sign outputs as
//! frozen golden values. Any changes to the algorithm logic will
//! cause these tests to fail, detecting regressions.
//!
//! Golden values captured from verified implementation v0.2.2
//! (all 12 modes pass sign→verify roundtrip).

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use slh_dsa::params::*;
use slh_dsa::sign::{keygen_seed, sign, verify};

fn shake256_hex(data: &[u8]) -> String {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut hash = [0u8; 32];
    reader.read(&mut hash);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Run full KAT for a mode: keygen + sign + verify + hash comparison.
fn run_kat(
    mode: SlhDsaMode,
    name: &str,
    expected_pk_hash: &str,
    expected_sk_hash: &str,
    expected_sig_hash: &str,
) {
    let seed = vec![0x2au8; mode.seed_bytes()];
    let (pk, sk) = keygen_seed(mode, &seed);
    let msg = b"KAT test message";
    let sig = sign(&sk, msg, mode);

    // Verify roundtrip
    assert!(verify(&pk, &sig, msg, mode), "{name}: verification failed");

    // Deterministic: second keygen/sign must match
    let (pk2, sk2) = keygen_seed(mode, &seed);
    let sig2 = sign(&sk2, msg, mode);
    assert_eq!(pk, pk2, "{name}: keygen not deterministic");
    assert_eq!(sk, sk2, "{name}: keygen not deterministic");
    assert_eq!(sig, sig2, "{name}: signing not deterministic");

    // Compare golden hashes
    let pk_hash = shake256_hex(&pk);
    let sk_hash = shake256_hex(&sk);
    let sig_hash = shake256_hex(&sig);

    assert_eq!(
        pk_hash, expected_pk_hash,
        "{name}: pk hash mismatch — keygen logic changed"
    );
    assert_eq!(
        sk_hash, expected_sk_hash,
        "{name}: sk hash mismatch — keygen logic changed"
    );
    assert_eq!(
        sig_hash, expected_sig_hash,
        "{name}: sig hash mismatch — signing logic changed"
    );
}

// ================================================================
// SHAKE variants
// ================================================================

#[test]
fn test_kat_shake_128f() {
    run_kat(
        SLH_DSA_SHAKE_128F,
        "SHAKE-128f",
        "0b8b0591f39ba49fca8266166e7d6134685fa4d0e152d5ae01a96eba0b6fada5",
        "ee4a21626916d5f6523716ab06674323a7e9e60fe844c4ce07a7a95cc702a8e1",
        "a3072c2f3b5ce76695aba11290988d32b21570379c9a371ce14c63af38aacbc9",
    );
}

#[test]
fn test_kat_shake_128s() {
    run_kat(
        SLH_DSA_SHAKE_128S,
        "SHAKE-128s",
        "b3cf38f9419e7cf683380ae236485d8c390e94016f281e3ef0dd8e63433c03cc",
        "4f4ca62dec9eac9c6a1dc4c7b08c96ed9e0b9c4a088284bf33bcf7fcc134ab37",
        "6c430587466a8f9ca23578997e4fdd8cb11a089e11cb2a1e0cbc9216a1f9d3c1",
    );
}

#[test]
fn test_kat_sha2_128f() {
    run_kat(
        SLH_DSA_SHA2_128F,
        "SHA2-128f",
        "0734f7d400eeaf12ea1f366058dc011de47b9369fe364659528c196d11f11577",
        "8bf584a4311f16bcd6d1a7bb3960104031a4b515459b3527392d137ffbc83f69",
        "f3e790eda3347bcc92d86e6a2a21040b0510a9b27343e3240dccb5144391b400",
    );
}
