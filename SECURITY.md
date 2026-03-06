# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

If you discover a security vulnerability in `lattice-slh-dsa`, please report it
responsibly:

1. **Email**: Open a private security advisory on the
   [GitHub repository](https://github.com/lattice-safe/lattice-slh-dsa-rs/security/advisories/new).
2. **Do not** open a public issue for security vulnerabilities.
3. We will acknowledge your report within 48 hours and aim to release a fix
   within 7 days for critical issues.

## Security Properties

- **FIPS 205 compliant**: Implements the SLH-DSA (SPHINCS+) standard.
- **Hash-based security**: Security relies only on hash function security —
  the most conservative post-quantum assumption.
- **Stateless**: No state management required, eliminating nonce-reuse risks.
- **Constant-time hashing**: Uses constant-time hash function implementations
  from the `sha3` and `sha2` crates.
- **Zeroization**: Sensitive key material is zeroized via the `zeroize` crate.
- **No `unsafe` code**: The crate contains no `unsafe` blocks.

## Caveats

- This implementation has **not** been independently audited.
- Side-channel resistance depends on the underlying hash crate implementations.
- For production use, consider pairing with a hardware security module (HSM).
