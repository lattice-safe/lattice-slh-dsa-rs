# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] — 2026-07-20

### Fixed — FIPS 205 compliance (BREAKING: changes signature bytes)

Previous releases implemented round-3 SPHINCS+ semantics in several places
and were **not interoperable** with FIPS 205 implementations. Signatures
produced by 0.3.x do not verify under 0.4.0 (and vice versa); public keys
for SHA2-192/256 parameter sets also change. Fixed:

- **SHA2 categories 3/5 hash selection**: `H_msg`, `PRF_msg`, `H` and `T_l`
  now use SHA-512 (with 128-byte block padding and MGF1-SHA-512) for
  n ≥ 24, per FIPS 205 §11.2.2. Previously SHA-256 was used everywhere,
  making SLH-DSA-SHA2-192s/f and -256s/f incompatible with the standard.
- **FORS index derivation**: `message_to_indices` now follows FIPS 205
  `base_2b` (MSB-first bit order). Previously the round-3 LSB-first order
  was used.
- **Deterministic signing randomness**: `opt_rand` is now `PK.seed` per
  FIPS 205 Algorithm 22 (was all-zeros).
- **Pure-message domain separation**: `sign`/`verify` now implement the
  FIPS 205 *pure* variant, prepending `0x00 || len(ctx) || ctx` to the
  message (empty context by default).

All of the above are cross-validated byte-for-byte against the independent
RustCrypto `slh-dsa` crate (ACVP-tested) in `tests/interop_rustcrypto.rs`,
covering both hash families and all three security categories.

### Added
- `sign_ctx` / `verify_ctx` — pure variant with a context string (≤ 255 bytes).
- `sign_internal` / `verify_internal` — FIPS 205 internal functions
  (raw message, optional hedged `addrnd`) for KATs and higher-level schemes.
- `SlhDsaKeyPair::sign_with_context` / `SlhDsaSignature::verify_with_context`.
- Cross-implementation interop test suite (8 parameter sets).
- Unit tests for address layouts, WOTS base-w/checksum, FORS indexing,
  HMAC (RFC 4231 vectors), MGF1, and error paths — line coverage ≥ 97%.

### Fixed — packaging
- The `serde` feature now enables serde's `alloc` feature; previously the
  crate failed to compile with `--features serde` unless another dependency
  happened to enable serde's `std`/`alloc` (e.g. in `no_std` builds).
- MSRV raised to 1.71 (required by current `quote`/`proc-macro2` releases;
  CI resolves fresh dependency versions since `Cargo.lock` is not committed).

### Hardened
- HMAC pads and inner digests are zeroized after use; SHA-2 `PRF` no longer
  copies `SK.seed` into an unzeroized heap buffer.
- `compute_root` no longer underflows on a zero tree height; `hash_message`
  index masking can no longer shift-overflow on degenerate custom modes.
- `SlhDsaMode` equality now compares numeric parameters only, so modes
  deserialized via serde (which skips the `name` label) compare equal to
  their source constants.
- `SlhDsaKeyPair::from_seed` requires exactly `3*n` bytes instead of
  silently truncating longer seeds.
- `SlhDsaKeyPair::sign` returns `SignFailed`/`BadArgument` instead of an
  empty signature on failure.

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
