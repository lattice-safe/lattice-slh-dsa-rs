# Changelog

All notable changes to this project will be documented in this file.

## [0.3.3] — 2026-03-07

### Added
- `#![forbid(unsafe_code)]` — enforced crate-wide
- CI: MSRV (1.70), WASM build, serde test, bench compile, cargo-deny

### Changed
- Expanded `SECURITY.md` with caveats, dependency audit, version update (0.3.x)
- Updated README with Safe API examples, feature table, module documentation
- CI clippy now uses `--all-targets --all-features`

## [0.3.2] — 2026-03-07

### Added
- Safe API: `SlhDsaKeyPair`, `SlhDsaSignature`, `SlhDsaError`
- Serde support behind `serde` feature flag
- Getrandom support for randomized keygen
- 3 examples (keygen, sign_verify, serialize)
- Benchmarks with Criterion
- Fuzz target
- 48 tests (integration + KAT + safe_api + coverage + doctests)

## [0.1.0] — 2026-03-07

### Added
- Initial release of `lattice-slh-dsa` — pure Rust SLH-DSA (FIPS 205).
- All 12 parameter sets: 6 SHAKE + 6 SHA-2 (128s/f, 192s/f, 256s/f).
- Byte-level ADRS encoding with separate SHAKE and SHA-2 layouts.
- WOTS+ one-time signatures with base-w conversion and chain functions.
- FORS few-time signatures with treehash and authentication paths.
- Hypertree Merkle signing with D-layer WOTS+/Merkle traversal.
- SHAKE-256 and SHA-256/HMAC hash abstractions.
- Keygen (seed-based), sign, and verify API.
- `no_std` support.
- Zeroize support for key material.
