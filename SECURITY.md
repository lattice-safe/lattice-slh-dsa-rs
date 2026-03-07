# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ Current |

## Reporting a Vulnerability

If you discover a security vulnerability in `lattice-slh-dsa`, **please do not use public issues**.

**Email**: latticesafe@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response
within 7 days.

## Security Properties

- **FIPS 205 compliant**: Implements all 12 SLH-DSA (SPHINCS+) parameter sets
- **Hash-based security**: Security relies only on hash function security —
  the most conservative post-quantum assumption
- **Stateless**: No state management required, eliminating nonce-reuse risks
- **`forbid(unsafe_code)`**: No `unsafe` blocks anywhere in the crate
- **Zeroization**: Sensitive key material (`SlhDsaKeyPair`) is zeroized via the `zeroize` crate
- **Constant-time hashing**: Uses constant-time hash implementations from `sha3` and `sha2` crates

## Caveats — What This Crate Does NOT Provide

- This implementation has **not** been independently audited or certified
- **No FIPS 140-3 / CMVP certification**
- Side-channel resistance depends on the underlying hash crate implementations
- No formal verification has been performed
- For production use, consider pairing with a hardware security module (HSM)

## Dependency Audit

| Crate | Version | Purpose | Audit Status |
|-------|---------|---------|-------------|
| `sha3` | 0.10 | SHAKE-256 XOF | RustCrypto — widely reviewed |
| `sha2` | 0.10 | SHA-256/HMAC | RustCrypto — widely reviewed |
| `subtle` | 2 | Constant-time operations | RustCrypto — widely reviewed |
| `zeroize` | 1 | Memory zeroization | RustCrypto — widely reviewed |
| `getrandom` | 0.2 | OS entropy (optional) | RustCrypto — widely reviewed |
| `serde` | 1 | Serialization (optional) | Widely reviewed |

## Scope

This policy covers the `lattice-slh-dsa` crate published on [crates.io](https://crates.io/crates/lattice-slh-dsa).
