//! SLH-DSA serialization example.
//!
//! Demonstrates serializing and deserializing key pairs and signatures
//! using the `serde` feature.
//!
//! Run with: `cargo run --example serialize --features serde`

fn main() {
    use slh_dsa::params::SLH_DSA_SHAKE_128F;
    use slh_dsa::safe_api::{SlhDsaKeyPair, SlhDsaSignature};

    let mode = SLH_DSA_SHAKE_128F;

    println!("=== SLH-DSA Serialization Demo ===\n");

    // 1. Generate a key pair
    let kp = SlhDsaKeyPair::from_seed(mode, &vec![42u8; mode.seed_bytes()]).unwrap();
    println!("Generated key pair:");
    println!("  PK: {} bytes", kp.public_key().len());
    println!("  SK: {} bytes", kp.secret_key().len());

    // 2. Sign a message
    let msg = b"Hello, serialized world!";
    let sig = kp.sign(msg).unwrap();
    println!("  Sig: {} bytes\n", sig.to_bytes().len());

    // 3. Serialize key pair to JSON
    #[cfg(feature = "serde")]
    {
        let kp_json = serde_json::to_string(&kp).unwrap();
        println!("Serialized KeyPair: {} bytes JSON", kp_json.len());

        // 4. Deserialize key pair
        let kp2: SlhDsaKeyPair = serde_json::from_str(&kp_json).unwrap();
        println!(
            "Deserialized KeyPair: PK matches = {}",
            kp.public_key() == kp2.public_key()
        );

        // 5. Sign with deserialized key pair
        let sig2 = kp2.sign(msg).unwrap();
        println!(
            "Sig from deserialized key matches = {}",
            sig.to_bytes() == sig2.to_bytes()
        );

        // 6. Serialize signature
        let sig_json = serde_json::to_string(&sig).unwrap();
        println!("\nSerialized Sig: {} bytes JSON", sig_json.len());

        // 7. Deserialize and verify
        let sig3: SlhDsaSignature = serde_json::from_str(&sig_json).unwrap();
        let valid = SlhDsaSignature::verify(sig3.to_bytes(), kp.public_key(), msg, mode);
        println!("Deserialized Sig verifies = {} ✅", valid);

        // 8. Raw bytes export/import
        println!("\n--- Raw bytes round-trip ---");
        let pk_bytes = kp.public_key().to_vec();
        let sk_bytes = kp.secret_key().to_vec();
        let kp3 = SlhDsaKeyPair::from_bytes(mode, &pk_bytes, &sk_bytes).unwrap();
        let sig4 = kp3.sign(msg).unwrap();
        println!(
            "from_bytes round-trip: sig matches = {}",
            sig.to_bytes() == sig4.to_bytes()
        );
    }

    #[cfg(not(feature = "serde"))]
    {
        println!("⚠️  Run with --features serde to see JSON serialization demo");
        println!("    cargo run --example serialize --features serde");

        // Raw bytes still work without serde
        println!("\n--- Raw bytes round-trip ---");
        let pk_bytes = kp.public_key().to_vec();
        let sk_bytes = kp.secret_key().to_vec();
        let kp2 = SlhDsaKeyPair::from_bytes(mode, &pk_bytes, &sk_bytes).unwrap();
        let sig2 = kp2.sign(msg).unwrap();
        println!(
            "from_bytes round-trip: sig matches = {}",
            sig.to_bytes() == sig2.to_bytes()
        );
    }
}
