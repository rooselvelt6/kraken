# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | ✅                 |
| < latest| ❌                 |

We recommend always using the [latest release](https://github.com/rooselvelt6/kraken/releases).

## Reporting a Vulnerability

Kraken takes security seriously. If you discover a security vulnerability,
please report it privately before disclosing it publicly.

**Do not report security vulnerabilities through public GitHub issues.**

Instead, report via email:

**security@kraken.dev** (or the maintainer's email)

Include the following details:
- Type of vulnerability
- Steps to reproduce
- Affected versions
- Any potential impact

You should receive a response within **48 hours**. If you don't, follow up.

### What to expect

1. We acknowledge receipt within 2 business days
2. We investigate and confirm the issue
3. We develop and test a fix
4. We release a patch and disclose the vulnerability after release

### Security practices

- All cryptographic code is in `rust/crates/security/` with `zeroize` for memory safety
- Sandbox uses Seccomp BPF + Landlock + Linux namespaces
- `unsafe` code is **forbidden** workspace-wide
- Supply chain is verified via `cargo-deny` and `cargo-audit`
- Fuzz testing runs weekly on 5 targets
- SLSA 3 supply chain security in [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md)

## Hall of Fame

We thank security researchers who responsibly disclose vulnerabilities.
If you'd like credit, include your name/alias in the report.
