//! KAT (Known-Answer Test) golden hash validation — C reference parity.
//!
//! pk and sk hashes are validated against the SPHINCS+ C reference
//! implementation (seed = 0x2a, SHAKE-256 hash).
//! Sig hashes are golden values for the FIPS 205 deterministic pure
//! signature (empty context); the signing logic itself is cross-validated
//! byte-for-byte against the RustCrypto `slh-dsa` crate in
//! tests/interop_rustcrypto.rs.

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

/// Run full KAT: keygen + sign + verify + SHAKE-256 hash comparison.
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

    assert!(verify(&pk, &sig, msg, mode), "{name}: verification failed");

    // Determinism check
    let (pk2, sk2) = keygen_seed(mode, &seed);
    let sig2 = sign(&sk2, msg, mode);
    assert_eq!(pk, pk2, "{name}: keygen not deterministic");
    assert_eq!(sk, sk2, "{name}: keygen not deterministic");
    assert_eq!(sig, sig2, "{name}: signing not deterministic");

    // Golden hash comparison (pk/sk validated against C reference)
    assert_eq!(
        shake256_hex(&pk),
        expected_pk_hash,
        "{name}: pk hash mismatch — C parity broken"
    );
    assert_eq!(
        shake256_hex(&sk),
        expected_sk_hash,
        "{name}: sk hash mismatch — C parity broken"
    );
    assert_eq!(
        shake256_hex(&sig),
        expected_sig_hash,
        "{name}: sig hash mismatch — signing logic changed"
    );
}

// ================================================================
// SHAKE variants (pk/sk hashes validated against C reference)
// ================================================================

#[test]
fn test_kat_shake_128f() {
    run_kat(
        SLH_DSA_SHAKE_128F,
        "SHAKE-128f",
        "65330503cef963c382f57e15ff89315e189cab5ab65d9dd26df0acd928e9a64a",
        "afbe51d903be30665a8da3cdc7b914428599ae3265c72fa3549bd2656ec4a1e4",
        "e2e69d2359746fa41d8da44eba1ce761a7cffbb3e45e942858e0b5474e8343b5",
    );
}

#[test]
fn test_kat_shake_128s() {
    run_kat(
        SLH_DSA_SHAKE_128S,
        "SHAKE-128s",
        "0c61f03905f01427cd64d63768a57c2f4b97ee6d6acef510c79bee5ab38dc64f",
        "cbd638291670a9921c8b0b27f71fbf53fec95ca8df391b49012722b86bde2e63",
        "2e40778e3af064b0ba5b55df1cab58571170f1a08b21c3a15453b9a38647a5eb",
    );
}

#[test]
fn test_kat_shake_192f() {
    run_kat(
        SLH_DSA_SHAKE_192F,
        "SHAKE-192f",
        "8381134190af68e96e9401935cbc5570499269627d88e9e105ecef5e15bdfc06",
        "79cb68c9442ac02cff16675a8513b5f0b634b13b6bef6defcdb05f9b054ff795",
        "1f73f4054317594a6530f306472f52ab9cd01dfe3c60f59200759d86b6779a3a",
    );
}

#[test]
fn test_kat_shake_256f() {
    run_kat(
        SLH_DSA_SHAKE_256F,
        "SHAKE-256f",
        "2ca8db8d4dfa7bfe1455ea07387dab0a0caed28751a64a7e18f75bdfdfeb5c98",
        "b5e9dd9f665cc65d6ee56773f5617dd596b87fcb0135c7d7eb13312b07c4e0ac",
        "22a44c9110e1d5b46b09e60d18e1076aa612d31bf258bb2e5a8c4320cc0b2772",
    );
}

// ================================================================
// SHA-2 variants (pk/sk hashes validated against C reference)
// ================================================================

#[test]
fn test_kat_sha2_128f() {
    run_kat(
        SLH_DSA_SHA2_128F,
        "SHA2-128f",
        "8b83943ac1f9f03681830bc7333f4e53c7e3635ae1025b845b7f53c7111f4dae",
        "7dd247a42a1c6303ce1ff2a12011b54381eee146a2fa2b21242830cafba665c3",
        "63f58a3d7bd5518c71ab29132cf0a7b35cf0810dc521633dfe7c55ec7e3fe26f",
    );
}
