# Kraken

<p align="center">
  <strong>Autonomous coding agent · Vulnerability scanner · Exploit generator · OSINT · Offensive security</strong>
  <br>
  <em>100% Rust · 18 crates · 110,000+ lines · 1500+ tests · 44 tools</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.85+-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/tests-1500%2B-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/unsafe-forbidden-red" alt="Unsafe Forbidden">
  <img src="https://img.shields.io/badge/SLSA-3-purple" alt="SLSA 3">
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20BSD%20%7C%20RPi-brightgreen" alt="OS">
</p>

---

## Quick Start

### Install (seconds)

**Linux / macOS / WSL / BSD**
```bash
curl -fsSL https://raw.githubusercontent.com/rooselvelt6/kraken/main/scripts/get-kraken.sh | sh
```

**Windows (PowerShell)**
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/rooselvelt6/kraken/main/scripts/get-kraken.ps1'))
```

**Docker**
```bash
docker run --rm -it ghcr.io/rooselvelt6/kraken --help
```

### Build from source

```bash
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust
cargo build --release
./target/release/kraken
```

### First steps

```bash
# Health check
kraken doctor

# Interactive REPL
kraken

# One-shot prompt
kraken prompt "analyze this repository"

# Vulnerability scan
kraken vulnscan --dir .

# Set your API key
export ANTHROPIC_API_KEY="sk-ant-..."
```

## What is Kraken?

Kraken is an **autonomous coding agent** with **offensive security capabilities**: multi-language vulnerability scanner, exploit generation, secret detection with Shannon entropy, OSINT analysis, sandbox with Seccomp + Landlock, and a granular permission system.

Built 100% in Rust with `unsafe` forbidden workspace-wide, ~40 MB release binary, supporting free LLM providers (DeepSeek, Big Pickle, Ollama).

## Key Features

| Feature | Description |
|---------|-------------|
| **44+ tools** | File ops, bash, web search, agent delegation |
| **140+ slash commands** | Full REPL with tab completion |
| **Vulnerability scanner** | 9 languages + 4 IaC formats + secrets |
| **OSINT framework** | DNS, WHOIS, social media, darkweb, dorking |
| **Sandbox** | Seccomp BPF, Landlock, namespaces, NSJail |
| **Cryptography** | AES-256-GCM, XChaCha20Poly1305, Argon2id |
| **ML threat detection** | 66-feature classifier with online learning |
| **Multi-provider** | Anthropic, OpenAI, DeepSeek, Ollama, DashScope |
| **Multi-platform** | Linux, macOS, Windows, FreeBSD, Docker |

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    kraken (CLI binary)                          │
├────────────────────────────────────────────────────────────────┤
│  tools      commands     api          compat-harness           │
│  (44+)      (140+)      (LLM clients) (parity testing)         │
├────────────────────────────────────────────────────────────────┤
│  runtime: permissions, sanitizer, fingerprint, health, MCP     │
├────────────────────────────────────────────────────────────────┤
│  security · sandbox · vulnscan · localmodels · osint           │
│  enterprise · cache · offline · plugins · telemetry            │
└────────────────────────────────────────────────────────────────┘
```

## Documentation

- [USAGE.md](USAGE.md) — Detailed usage guide
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
- [SECURITY.md](SECURITY.md) — Security policy
- [CHANGELOG.md](CHANGELOG.md) — Release history
- [ROADMAP.md](ROADMAP.md) — Development roadmap
- [PHILOSOPHY.md](PHILOSOPHY.md) — Project philosophy

## License

MIT © 2024 Kraken Contributors
