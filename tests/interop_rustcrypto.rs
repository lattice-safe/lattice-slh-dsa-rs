//! Cross-implementation interoperability tests against the independent,
//! ACVP-tested RustCrypto `slh-dsa` crate.
//!
//! For each covered parameter set this checks:
//! 1. Keygen parity: same 3n-byte seed -> byte-identical public key.
//! 2. Signature parity: our deterministic pure signature (empty context)
//!    is byte-identical to RustCrypto's deterministic signature.
//! 3. Cross-verification in both directions.

use rand_core::{CryptoRng, RngCore};
use signature::{Keypair, Signer, Verifier};
use slh_dsa::params::*;
use slh_dsa::sign::keygen_seed;

/// Deterministic "RNG" that replays a fixed byte string, so RustCrypto's
/// `SigningKey::new` consumes exactly our keygen seed (sk_seed || sk_prf || pk_seed).
struct SeedRng {
    data: Vec<u8>,
    pos: usize,
}

impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.data[self.pos..self.pos + dest.len()]);
        self.pos += dest.len();
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeedRng {}

fn test_seed(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 13) as u8).collect()
}

macro_rules! interop_test {
    ($name:ident, $P:ty, $mode:expr) => {
        #[test]
        fn $name() {
            let mode = $mode;
            let seed = test_seed(mode.seed_bytes());
            let msg = b"cross-implementation interop test";

            // RustCrypto keygen from the same seed material.
            let mut rng = SeedRng {
                data: seed.clone(),
                pos: 0,
            };
            let rc_sk = slh_dsa_rc::SigningKey::<$P>::new(&mut rng);
            let rc_vk = rc_sk.verifying_key();

            // Our keygen.
            let (pk, sk) = keygen_seed(mode, &seed);
            assert_eq!(
                pk.as_slice(),
                rc_vk.to_bytes().as_slice(),
                "{}: public key mismatch vs RustCrypto",
                mode.name
            );

            // Deterministic pure signing (empty context) must match byte-for-byte.
            let our_sig = slh_dsa::sign(&sk, msg, mode);
            let rc_sig = rc_sk.sign(msg);
            assert_eq!(
                our_sig.as_slice(),
                rc_sig.to_bytes().as_slice(),
                "{}: signature mismatch vs RustCrypto",
                mode.name
            );

            // Cross-verify: our signature under their verifier...
            let our_sig_rc = slh_dsa_rc::Signature::<$P>::try_from(our_sig.as_slice())
                .expect("signature length");
            rc_vk
                .verify(msg, &our_sig_rc)
                .expect("RustCrypto rejected our signature");

            // ...and their signature under ours.
            assert!(
                slh_dsa::verify(&pk, rc_sig.to_bytes().as_slice(), msg, mode),
                "{}: we rejected RustCrypto's signature",
                mode.name
            );
        }
    };
}

interop_test!(
    interop_shake_128f,
    slh_dsa_rc::Shake128f,
    SLH_DSA_SHAKE_128F
);
interop_test!(
    interop_shake_192f,
    slh_dsa_rc::Shake192f,
    SLH_DSA_SHAKE_192F
);
interop_test!(
    interop_shake_256f,
    slh_dsa_rc::Shake256f,
    SLH_DSA_SHAKE_256F
);
interop_test!(interop_sha2_128f, slh_dsa_rc::Sha2_128f, SLH_DSA_SHA2_128F);
interop_test!(interop_sha2_192f, slh_dsa_rc::Sha2_192f, SLH_DSA_SHA2_192F);
interop_test!(interop_sha2_256f, slh_dsa_rc::Sha2_256f, SLH_DSA_SHA2_256F);

// One "s" (small/slow) parameter set per family to cover the taller trees.
interop_test!(
    interop_shake_128s,
    slh_dsa_rc::Shake128s,
    SLH_DSA_SHAKE_128S
);
interop_test!(interop_sha2_128s, slh_dsa_rc::Sha2_128s, SLH_DSA_SHA2_128S);
