# Supply Chain Security Policy

## Overview
Kraken follows a defense-in-depth approach to supply chain security, targeting SLSA Level 3 compliance.

## Policies

### 1. Dependency Licenses
- **Allowlist**: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, CC0-1.0, Zlib, 0BSD, Unicode-DFS-2016, MPL-2.0, OpenSSL
- **Denied**: GPL family, AGPL, LGPL-3.0 — copyleft licenses are not permitted
- Enforcement: `cargo deny check licenses`

### 2. Vulnerability Management
- All dependencies are scanned against the RustSec Advisory Database
- Critical vulnerabilities: **deny** (blocks CI)
- Unmaintained packages: **warn** (monitored for replacement)
- Enforcement: `cargo deny check advisories` + `cargo audit`

### 3. Duplicate Dependency Ban
- Multiple versions of the same crate are warned and investigated
- Wildcard version dependencies are denied
- Enforcement: `cargo deny check bans`

### 4. Source Control
- Only crates.io is allowed as an external source
- Git dependencies are denied (must be vendored if critical)
- Enforcement: `cargo deny check sources`

### 5. Unsafe Code Audit
- Workspace-level lint: `unsafe_code = "forbid"` (allows unsafe in local crates)
- All `unsafe` blocks in dependencies are audited quarterly
- Enforcement: CI checks for unsafe usage in local crates

### 6. Fuzz Testing
- Critical interfaces are continuously fuzzed:
  - Path traversal detection
  - Bash command validation
  - Feature extraction
  - JSON config parsing
- Enforcement: Weekly fuzz run in CI

### 7. SBOM Generation
- CycloneDX SBOM is generated for every release
- Includes: dependencies (direct + transitive), licenses, checksums
- Enforcement: CI generates SBOM on tag push

### 8. Vendoring
- Critical dependencies are vendored for air-gapped deployments
  - `ring` — cryptographic primitives
  - `rustls` — TLS implementation
  - `hickory-resolver` — DNS resolution
- Vendored deps are audited for unsafe code
- Enforcement: Vendor script available, CI verifies vendored deps

## CI Enforcement

| Check | Command | Blocks PR |
|-------|---------|-----------|
| License compliance | `cargo deny check licenses` | Yes |
| Vulnerability scan | `cargo deny check advisories` | Advisory only |
| Duplicate bans | `cargo deny check bans` | Yes |
| Source validation | `cargo deny check sources` | Yes |
| Unsafe code audit | CI script | No (informational) |
| SBOM generation | `cargo cyclonedx` | No (on release) |

## Incident Response

1. **Critical advisory detected**: CI fails, issue auto-created
2. **Unmaintained dependency**: Investigate replacement, file migration issue
3. **License violation**: Remove dependency, find alternative
4. **Supply chain attack**: Pin known-good version, rotate all credentials, audit builds

## Review Cadence

- Dependency audit: Monthly
- Unsafe code review: Quarterly
- SBOM review: Per release
- Policy review: Semi-annual
