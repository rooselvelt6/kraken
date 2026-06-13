# Contributing to Kraken

First off, thanks for taking the time to contribute! 🦀

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
- Check the [issues](https://github.com/rooselvelt6/kraken/issues) to see if it's already reported
- Use the bug report template when creating an issue

### Suggesting Features

Use the feature request template and clearly describe:
- The problem you're trying to solve
- The proposed solution
- Any alternatives you've considered

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run tests: `cargo test --workspace`
5. Run clippy: `cargo clippy --workspace`
6. Ensure formatting: `cargo fmt --all --check`
7. Commit with a conventional commit message (see below)
8. Push and open a PR against `main`

### Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `ci`, `perf`

Examples:
```
feat: add OSINT dork generator
fix: crash on empty workspace path
docs: update API key configuration
```

## Development Setup

### Prerequisites

- Rust 1.85+
- `pkg-config`, `libssl-dev`, `git`

### Build & Test

```bash
cd rust
cargo build
cargo test --workspace
cargo clippy --workspace
cargo fmt --all --check
```

### Project Structure

```
rust/
├── crates/
│   ├── rusty-claude-cli/   # Main binary (kraken)
│   ├── runtime/            # Core engine & permissions
│   ├── tools/              # Agent tools
│   ├── vulnscan/           # Vulnerability scanner
│   ├── security/           # Cryptography & audit
│   ├── sandbox/            # Seccomp, Landlock, namespaces
│   ├── localmodels/        # ML threat detection
│   ├── osint/              # OSINT framework
│   └── ...                 # 18 crates total
├── tests/                  # Property-based tests
└── fuzz/                   # Fuzz targets
```

## Questions?

Open a [discussion](https://github.com/rooselvelt6/kraken/discussions) or ask in issues.
