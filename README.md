# lattice-slh-dsa

Pure Rust implementation of **SLH-DSA** (FIPS 205) — the stateless hash-based digital signature scheme, also known as SPHINCS+.

[![Crates.io](https://img.shields.io/crates/v/lattice-slh-dsa)](https://crates.io/crates/lattice-slh-dsa)
[![Docs.rs](https://docs.rs/lattice-slh-dsa/badge.svg)](https://docs.rs/lattice-slh-dsa)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- ✅ **FIPS 205 compliant** — all 12 parameter sets (6 SHAKE + 6 SHA-2)
- 🦀 **Pure Rust** — no C/ASM dependencies, `#![forbid(unsafe_code)]`
- 🔒 **`no_std` compatible** — suitable for embedded and WASM targets
- 🧹 **Zeroization** — sensitive keys cleared on drop
- 📦 **Typed safe API** — `SlhDsaKeyPair`, `SlhDsaSignature`, `SlhDsaError`
- 🔑 **Optional serde** — serialize/deserialize keys and signatures

## Parameter Sets

| Parameter Set | NIST Level | Sig Size | PK Size | SK Size |
|---|---|---|---|---|
| SLH-DSA-SHAKE-128s | 1 | ~7,856 B | 32 B | 64 B |
| SLH-DSA-SHAKE-128f | 1 | ~17,088 B | 32 B | 64 B |
| SLH-DSA-SHAKE-192s | 3 | ~16,224 B | 48 B | 96 B |
| SLH-DSA-SHAKE-192f | 3 | ~35,664 B | 48 B | 96 B |
| SLH-DSA-SHAKE-256s | 5 | ~29,792 B | 64 B | 128 B |
| SLH-DSA-SHAKE-256f | 5 | ~49,856 B | 64 B | 128 B |

## Quick Start

### Safe API (recommended)

```rust
use slh_dsa::{SlhDsaKeyPair, SlhDsaSignature};
use slh_dsa::params::SLH_DSA_SHAKE_128F;

let kp = SlhDsaKeyPair::generate(SLH_DSA_SHAKE_128F).unwrap();
let sig = kp.sign(b"Hello, post-quantum!").unwrap();
assert!(SlhDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"Hello, post-quantum!", SLH_DSA_SHAKE_128F));
```

### Low-level API

```rust
use slh_dsa::params::SLH_DSA_SHAKE_128F;
use slh_dsa::sign::{keygen_seed, sign, verify};

let mode = SLH_DSA_SHAKE_128F;
let seed = vec![42u8; mode.seed_bytes()];
let (pk, sk) = keygen_seed(mode, &seed);
let sig = sign(&sk, b"Hello, post-quantum!", mode);
assert!(verify(&pk, &sig, b"Hello, post-quantum!", mode));
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | ✅ | Standard library support |
| `getrandom` | ✅ (via std) | OS entropy for `SlhDsaKeyPair::generate()` |
| `serde` | ❌ | Serialize/deserialize keys and signatures |

## Architecture

| Module | Description |
|---|---|
| `safe_api` | **High-level typed API** — `SlhDsaKeyPair`, `SlhDsaError`, etc. |
| `sign` | Top-level keygen, sign, verify API |
| `params` | All 12 FIPS 205 parameter sets |
| `address` | ADRS structure with byte-level encoding (SHAKE/SHA-2 layouts) |
| `hash` | PRF, H_msg, gen_message_random (SHAKE-256 + SHA-256/HMAC) |
| `thash` | Tweakable hash T_l |
| `wots` | WOTS+ one-time signatures (base-w, chain, sign/verify) |
| `fors` | FORS few-time signatures (treehash + auth paths) |
| `merkle` | Hypertree Merkle signing and root generation |

## Part of lattice-safe-suite

This crate implements **FIPS 205 (SLH-DSA)** as part of the [`lattice-safe-suite`](https://crates.io/crates/lattice-safe-suite) ecosystem:

| Standard | Crate | Algorithm |
|---|---|---|
| FIPS 203 | [`lattice-kyber`](https://crates.io/crates/lattice-kyber) | ML-KEM (Kyber) |
| FIPS 204 | [`dilithium-rs`](https://crates.io/crates/dilithium-rs) | ML-DSA (Dilithium) |
| FIPS 205 | **`lattice-slh-dsa`** | SLH-DSA (SPHINCS+) |
| FIPS 206 | [`falcon-rs`](https://crates.io/crates/falcon-rs) | FN-DSA (Falcon) |

## License

MIT
