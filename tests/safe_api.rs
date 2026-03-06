//! Safe API integration tests.

use slh_dsa::params::SLH_DSA_SHAKE_128F;
use slh_dsa::safe_api::{SlhDsaError, SlhDsaKeyPair, SlhDsaSignature};

#[test]
fn test_safe_api_roundtrip() {
    let kp = SlhDsaKeyPair::generate(SLH_DSA_SHAKE_128F).unwrap();
    let sig = kp.sign(b"test message").unwrap();
    assert!(SlhDsaSignature::verify(
        sig.to_bytes(),
        kp.public_key(),
        b"test message",
        SLH_DSA_SHAKE_128F,
    ));
}

#[test]
fn test_safe_api_from_seed() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![99u8; mode.seed_bytes()];
    let kp = SlhDsaKeyPair::from_seed(mode, &seed).unwrap();
    let sig = kp.sign(b"hello").unwrap();
    assert!(SlhDsaSignature::verify(
        sig.to_bytes(),
        kp.public_key(),
        b"hello",
        mode,
    ));
}

#[test]
fn test_safe_api_deterministic() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![77u8; mode.seed_bytes()];
    let kp1 = SlhDsaKeyPair::from_seed(mode, &seed).unwrap();
    let kp2 = SlhDsaKeyPair::from_seed(mode, &seed).unwrap();
    assert_eq!(kp1.public_key(), kp2.public_key());
    assert_eq!(kp1.secret_key(), kp2.secret_key());
}

#[test]
fn test_safe_api_wrong_message_rejected() {
    let kp = SlhDsaKeyPair::generate(SLH_DSA_SHAKE_128F).unwrap();
    let sig = kp.sign(b"correct").unwrap();
    assert!(!SlhDsaSignature::verify(
        sig.to_bytes(),
        kp.public_key(),
        b"wrong",
        SLH_DSA_SHAKE_128F,
    ));
}

#[test]
fn test_safe_api_from_bytes() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![42u8; mode.seed_bytes()];
    let kp = SlhDsaKeyPair::from_seed(mode, &seed).unwrap();
    let kp2 = SlhDsaKeyPair::from_bytes(mode, kp.public_key(), kp.secret_key()).unwrap();
    assert_eq!(kp.public_key(), kp2.public_key());
    assert_eq!(kp.secret_key(), kp2.secret_key());
}

#[test]
fn test_safe_api_bad_seed_size() {
    let result = SlhDsaKeyPair::from_seed(SLH_DSA_SHAKE_128F, &[0u8; 5]);
    assert_eq!(result.err(), Some(SlhDsaError::BadArgument));
}

#[test]
fn test_safe_api_signature_from_bytes() {
    let mode = SLH_DSA_SHAKE_128F;
    let kp = SlhDsaKeyPair::generate(mode).unwrap();
    let sig = kp.sign(b"test").unwrap();
    let sig2 = SlhDsaSignature::from_bytes(mode, sig.to_bytes()).unwrap();
    assert_eq!(sig.to_bytes(), sig2.to_bytes());
}
