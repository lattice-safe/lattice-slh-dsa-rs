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

#[test]
fn test_safe_api_context_string() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![11u8; mode.seed_bytes()];
    let kp = SlhDsaKeyPair::from_seed(mode, &seed).unwrap();

    let sig = kp.sign_with_context(b"msg", b"my-app").unwrap();
    assert!(SlhDsaSignature::verify_with_context(
        sig.to_bytes(),
        kp.public_key(),
        b"msg",
        b"my-app",
        mode,
    ));
    // Wrong context rejected.
    assert!(!SlhDsaSignature::verify_with_context(
        sig.to_bytes(),
        kp.public_key(),
        b"msg",
        b"other",
        mode,
    ));
    // Context strings longer than 255 bytes are rejected.
    assert_eq!(
        kp.sign_with_context(b"msg", &[0u8; 256]).err(),
        Some(SlhDsaError::BadArgument)
    );
}

#[test]
fn test_safe_api_accessors_and_traits() {
    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![13u8; mode.seed_bytes()];
    let kp = SlhDsaKeyPair::from_seed(mode, &seed).unwrap();

    assert_eq!(kp.mode(), mode);
    assert_eq!(kp.public_key().len(), mode.pk_bytes());
    assert_eq!(kp.secret_key().len(), mode.sk_bytes());

    // Debug must not leak key material.
    let dbg = format!("{kp:?}");
    assert!(dbg.contains("SlhDsaKeyPair"));
    assert!(!dbg.contains("13, 13"));

    // Clone preserves keys.
    let kp2 = kp.clone();
    assert_eq!(kp.public_key(), kp2.public_key());

    let sig = kp.sign(b"x").unwrap();
    assert_eq!(sig.mode(), mode);
    assert_eq!(sig.len(), mode.sig_bytes());
    assert!(!sig.is_empty());
    let dbg_sig = format!("{:?}", sig.clone());
    assert!(dbg_sig.contains("SlhDsaSignature"));
}

#[test]
fn test_safe_api_error_display() {
    assert_eq!(
        SlhDsaError::KeygenFailed.to_string(),
        "key generation failed"
    );
    assert_eq!(SlhDsaError::SignFailed.to_string(), "signing failed");
    assert_eq!(SlhDsaError::BadSignature.to_string(), "bad signature");
    assert_eq!(SlhDsaError::BadArgument.to_string(), "bad argument");

    // std::error::Error is implemented.
    let e: &dyn std::error::Error = &SlhDsaError::BadArgument;
    assert!(e.source().is_none());
}

#[cfg(feature = "serde")]
mod serde_tests {
    use super::*;

    #[test]
    fn test_keypair_serde_roundtrip() {
        let mode = SLH_DSA_SHAKE_128F;
        let seed = vec![21u8; mode.seed_bytes()];
        let kp = SlhDsaKeyPair::from_seed(mode, &seed).unwrap();

        let json = serde_json::to_string(&kp).unwrap();
        let kp2: SlhDsaKeyPair = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.public_key(), kp2.public_key());
        assert_eq!(kp.secret_key(), kp2.secret_key());

        // Signatures from the deserialized keypair still verify.
        let sig = kp2.sign(b"serde msg").unwrap();
        assert!(SlhDsaSignature::verify(
            sig.to_bytes(),
            kp.public_key(),
            b"serde msg",
            mode,
        ));
    }

    #[test]
    fn test_signature_serde_roundtrip() {
        let mode = SLH_DSA_SHAKE_128F;
        let seed = vec![22u8; mode.seed_bytes()];
        let kp = SlhDsaKeyPair::from_seed(mode, &seed).unwrap();
        let sig = kp.sign(b"serde sig").unwrap();

        let json = serde_json::to_string(&sig).unwrap();
        let sig2: SlhDsaSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.to_bytes(), sig2.to_bytes());
        assert!(SlhDsaSignature::verify(
            sig2.to_bytes(),
            kp.public_key(),
            b"serde sig",
            mode,
        ));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let json = serde_json::to_string(&SlhDsaError::BadSignature).unwrap();
        let e: SlhDsaError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, SlhDsaError::BadSignature);
    }
}
