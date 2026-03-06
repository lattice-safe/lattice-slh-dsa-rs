# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-03-07

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
