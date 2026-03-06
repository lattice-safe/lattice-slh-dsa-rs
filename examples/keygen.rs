//! SLH-DSA key generation example.

fn main() {
    use slh_dsa::params::*;
    use slh_dsa::sign::keygen_seed;

    let modes = [
        ("SLH-DSA-SHAKE-128f", SLH_DSA_SHAKE_128F),
        ("SLH-DSA-SHAKE-128s", SLH_DSA_SHAKE_128S),
        ("SLH-DSA-SHAKE-192f", SLH_DSA_SHAKE_192F),
        ("SLH-DSA-SHAKE-192s", SLH_DSA_SHAKE_192S),
        ("SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256F),
        ("SLH-DSA-SHAKE-256s", SLH_DSA_SHAKE_256S),
    ];

    for (name, mode) in &modes {
        let seed = vec![42u8; mode.seed_bytes()];
        let start = std::time::Instant::now();
        let (pk, sk) = keygen_seed(*mode, &seed);
        let elapsed = start.elapsed();

        println!("{name}:");
        println!("  Seed:  {} bytes", seed.len());
        println!("  PK:    {} bytes", pk.len());
        println!("  SK:    {} bytes", sk.len());
        println!("  Time:  {:.2?}", elapsed);
        println!();
    }
}
