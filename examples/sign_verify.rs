//! SLH-DSA sign and verify example.

fn main() {
    use slh_dsa::params::SLH_DSA_SHAKE_128F;
    use slh_dsa::sign::{keygen_seed, sign, verify};

    let mode = SLH_DSA_SHAKE_128F;
    let seed = vec![42u8; mode.seed_bytes()];

    println!("=== SLH-DSA-SHAKE-128f Sign/Verify ===\n");

    // Key generation
    let start = std::time::Instant::now();
    let (pk, sk) = keygen_seed(mode, &seed);
    println!("Keygen:  {:.2?}", start.elapsed());

    // Sign
    let msg = b"Hello, post-quantum world!";
    let start = std::time::Instant::now();
    let sig = sign(&sk, msg, mode);
    println!("Sign:    {:.2?} ({} bytes)", start.elapsed(), sig.len());

    // Verify (valid)
    let start = std::time::Instant::now();
    let valid = verify(&pk, &sig, msg, mode);
    println!("Verify:  {:.2?} → {}", start.elapsed(), if valid { "✅ VALID" } else { "❌ INVALID" });

    // Verify (wrong message)
    let tampered = verify(&pk, &sig, b"tampered message", mode);
    println!("Tamper:  → {}", if tampered { "❌ FALSE POSITIVE" } else { "✅ REJECTED" });
}
