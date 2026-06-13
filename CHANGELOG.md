# Changelog

All notable changes to Kraken are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-06-13

### Added

#### Core Engine
- Multi-agent orchestration with autonomous task execution
- REPL and one-shot prompt modes
- Session management with persist/resume
- Config file system (`.kraken.json`) with validation
- Structured error classification with typed error contracts

#### 44+ Agent Tools
- File operations: read, write, edit, glob, grep
- Web: search, fetch, scrape
- Bash execution with permission enforcement
- Agent delegation and task planning
- System: doctor, status, diff, export, memory

#### 140+ Slash Commands
- `/bash`, `/read`, `/write`, `/edit`, `/glob`, `/grep`
- `/web_search`, `/web_fetch`, `/agent`, `/task`
- `/vulnscan`, `/osint`, `/skill`, `/analyze`
- Session management: `/session`, `/history`, `/status`
- Memory: `/memory`, `/config`, `/diff`, `/export`

#### Vulnerability Scanner (vulnscan)
- Multi-language scan: Rust, Python, JavaScript, Go, Java, Ruby, C, C++, Swift
- IaC scan: Docker, Kubernetes, Terraform, CloudFormation
- Secret detection: 17 canonical patterns + Shannon entropy
- Image scanning (Docker/OCI)
- HTML/JSON report generation

#### OSINT Framework
- DNS resolution (A/AAAA/MX/TXT/NS/SOA/CNAME)
- WHOIS queries with record parsing
- Email breach verification (HIBP v3)
- Infrastructure: ASN, rDNS, Shodan, crt.sh, Censys, ThreatFox
- Port scanning with service detection
- Social media: 75+ platforms, profile search
- Person search: name, email, phone (100+ countries)
- Darkweb: Tor, onion sites, markets
- Google Dorking: 20+ predefined dorks

#### Security & Cryptography
- AES-256-GCM / XChaCha20Poly1305 (runtime selectable)
- Argon2id (OWASP 2024: m=46MB, t=1, p=1) + HKDF-SHA256
- Ed25519 audit chain signing
- Memory zeroization via `zeroize`
- Constant-time comparison (`subtle`)
- Credential vault with MasterKey
- `mlock`/`VirtualLock` memory locking

#### Sandbox
- Seccomp BPF syscall filter (80+ read-write, 50+ read-only)
- Landlock filesystem isolation (Linux 5.13+)
- PID, mount, network, UTS, IPC namespaces
- tmpfs ephemeral filesystem
- rlimits (CPU, memory, processes, files)
- NSJail container (opt-in)
- macOS Seatbelt profiles
- Windows JobObject limits

#### Machine Learning (localmodels)
- 66 features per tool call
- Softmax multiclass classifier (safe/suspicious/malicious)
- Ensemble scorer with weighted voting
- Online learner via SGD with WAL
- Markov chain sequence anomaly detection
- 5 Criterion benchmarks (~53µs extraction, ~24µs inference)

#### Enterprise
- Circuit breaker with health probes
- Distributed tracing
- Telemetry event system
- Plugin lifecycle management (MCP-compatible)
- Self-healing with 6 recovery modes

#### Cache & Offline
- Multi-level cache: LRU + FIFO + SQLite with TTL
- Compression (flate2)
- Offline-first operation queue
- LRU cache with `lru` crate, `AtomicU64` counters

#### Optimization
- Particle Swarm Optimization (PSO)
- Genetic Algorithm (GA)
- Ant Colony Optimization (ACO)
- Simulated Annealing

#### LLM Provider Support
- Anthropic Claude API
- OpenAI-compatible API
- DeepSeek
- Big Pickle
- Ollama (local)
- DashScope (Qwen)
- OpenRouter
- kimi/k2.5
- Custom provider routing with prefix detection

#### CLI
- Provider auto-detection
- `--output-format json` for machine-readable output
- `--model`, `--reasoning-effort`, `--compact` flags
- Tab completion infrastructure
- Build info: Git SHA, target triple, build date
- Cross-platform: Linux, macOS, Windows, FreeBSD
- 4 aliases: kraken, krak, krkn, kra

#### Testing
- 1500+ unit tests
- 23 property-based tests (proptest)
- 5 cargo-fuzz targets (path traversal, bash, features, config, sandbox)
- 13 Criterion benchmarks
- 10 mock parity test scenarios
- Integration tests for CLI JSON parity

#### Infrastructure
- 100% Rust with `unsafe` forbidden workspace-wide
- SLSA 3 supply chain security
- Multi-platform CI (fmt, clippy, test, deny, audit, fuzz, SBOM)
- CycloneDX SBOM generation
- Offline vendoring for air-gapped builds
- Pre-commit hook for secret scanning
- Chaos testing for self-healing
- Multi-arch Docker image (amd64, arm64, armv7)

### Changed
- Consolidated from 4 binaries to 1 binary with symlinks
- Upstream parity: Batches 1-6 with Claude Code compatibility

### Fixed
- Session isolation across worktrees
- Provider routing for DashScope, OpenAI, and custom endpoints
- JSON output parity for all diagnostic commands
- Model validation at parse time
- Windows HOME fallback to USERPROFILE
- Config validation with helpful error messages
- MCP graceful degradation on malformed config
- Test flakiness via env_lock and canonicalization

### Security
- Zeroize for all sensitive data
- Fixed vulnerabilities in lru, rand, rustls-webpki
- Permission enforcement with 4 levels (ReadOnly → Allow)
- Path traversal detection (7 patterns)
- Fingerprint verification (SHA-256)
- 7-stage sanitizer pipeline
