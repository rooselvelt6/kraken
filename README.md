# Kraken

<p align="center">
  <a href="https://github.com/rooselvelt6/kraken">
    <img src="https://img.shields.io/badge/Rust-100%25-b84100?style=for-the-badge&logo=rust" alt="Rust"/>
  </a>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT"/>
  <img src="https://img.shields.io/badge/status-production-green?style=for-the-badge" alt="Production"/>
</p>

<p align="center">
  <i>AI coding agent + vulnerability scanner + exploit generator.</i><br>
  <b>100% Rust. Multi-provider. 0% Python. 0% USD required.</b>
</p>

---

## What is Kraken?

Kraken is a **security-first autonomous AI coding agent** — a single Rust binary that edits code, runs commands, scans for vulnerabilities, generates exploits, and coordinates multi-agent workflows. It is not a fork of another tool. It is its own implementation, built from the ground up in Rust.

Unlike other AI coding assistants, Kraken also functions as a **full vulnerability scanner and penetration testing tool**, capable of static analysis across 9 languages, autonomous overnight bug hunting, vulnerability chaining, and exploit generation.

---

## Why Kraken?

| Other AI tools | Kraken |
|---|---|
| Require USD, credit card, or paid subscription | **Free providers: DeepSeek (5M tokens/mo), Big Pickle (unlimited), Ollama (local)** |
| Single LLM provider lock-in | **6+ providers: Anthropic, DeepSeek, xAI, OpenAI, DashScope, Ollama — auto-routed by model name** |
| Python/TypeScript/Node — heavy runtime deps | **Single ~150MB Rust binary. Zero runtime dependencies.** |
| No security analysis | **Built-in 9-language AST scanner, exploit generator, vulnerability chaining** |
| No offline mode | **SQLite-backed offline queue with auto-sync** |
| No enterprise features without SaaS | **Circuit breaker, health checks, distributed tracing, metrics — included, not upsold** |

---

## Capabilities

### AI Coding Agent
- Interactive REPL and one-shot prompts
- 44+ tools: read, edit, write, grep, glob, bash, web fetch, WriteNote, ReadNote, ListNotes, and more
- 140+ slash commands (including `/effort`, `/notes`, `/compact`, `/resume`, ...)
- Multi-agent orchestration (sub-agents, parallel work)
- Reasoning effort control (`/effort low|medium|high`) with self-validation mode
- Persistent file-based memory (WriteNote, ReadNote, ListNotes)
- Session management with checkpoint/resume
- MCP (Model Context Protocol) support
- Plugin system

### Vulnerability Scanner (`vulnscan`)
- **Static analysis**: Tree-sitter AST analyzers for C, C++, Rust, Go, Java, JavaScript, Python, Ruby, Swift
- **Security checks**: SQLi, XSS, CSRF, SSRF, XXE, command injection, path traversal, crypto flaws, hardcoded secrets, supply chain, auth bypass, IDOR
- **LLM-powered analysis**: Multi-provider agent with chunked file analysis, bug probability ranking, finding validation with CVSS scoring

### Autonomous Hacking
- **Exploit generation**: ROP chains, heap sprays, privilege escalation, shellcode
- **Vulnerability chaining**: BFS primitive graph solver — finds shortest path from primitives to RCE
- **Overnight bughunt**: Full autonomous pipeline: rank → scan → validate → exploit → report
- **Persistent memory**: Hypothesis tracking across sessions, automatic checkpoint/resume
- **Attack surface mapping**: Recon, lateral movement, pivot detection, attack graphs

### Enterprise Features (built-in, free)
| Feature | What it does |
|---|---|
| Circuit breaker | Automatic upstream failure tolerance |
| Exponential backoff | Jittered retry with configurable delays |
| Health checks | Provider latency and error rate monitoring |
| Graceful degradation | Provider priority chain fallback |
| Metrics | Per-provider request count, latency, token usage, cost |
| Structured logging | JSON output with severity levels |
| Distributed tracing | Span correlation across requests |
| Rate limiting | Per-user and per-provider limits |
| Audit logging | Immutable hash chain for all actions |

### Security
- **Encryption**: AES-256-GCM, XChaCha20Poly1305 (runtime-selectable)
- **Key derivation**: Argon2id (RFC 9106, OWASP 2024 parameters)
- **Memory safety**: Zeroize on drop, constant-time comparisons
- **Audit**: SHA-256 authenticated log chain

### Free LLM Providers
| Provider | Models | Cost |
|---|---|---|
| **DeepSeek** | V3, R1, Coder | 5M free tokens/month |
| **Big Pickle** | OpenCode Zen GLM-4.6 | Unlimited free |
| **Ollama** | Any local model (qwen2.5-coder, llama3.2, ...) | Free (local) |
| **LM Studio** | Any local model | Free (local) |

No credit card required. No USD needed.

---

## Quick Start

```bash
# 1. Clone and build
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust
cargo build --release

# 2. Set a free API key (DeepSeek = 5M free tokens/month)
export DEEPSEEK_API_KEY="sk-..."

# 3. Run
./target/release/kraken prompt "analyze this repository"
```

### Or use local models (Ollama, completely free)

```bash
# Start Ollama with any model
ollama pull qwen2.5-coder

# Run Kraken with local model
./target/release/kraken --model ollama/qwen2.5-coder
```

### Run a vulnerability scan

```bash
# Quick scan
./target/release/kraken --vulnscan ./src

# Overnight autonomous bughunt (scan → validate → exploit → report)
./target/release/kraken --model deepseek-chat --vulnscan --overnight ./src
```

---

## Architecture (17 Rust crates)

```
┌─────────────────────────────────────────────────────────────┐
│                    kraken CLI (binary)                       │
├─────────────────────────────────────────────────────────────┤
│  commands (135+)   tools (40)   plugins   telemetry          │
├─────────────────────────────────────────────────────────────┤
│  api (multi-provider)   runtime (sessions, MCP, permissions) │
│  enterprise (retry, circuit breaker, metrics, tracing)       │
├─────────────────────────────────────────────────────────────┤
│  vulnscan (scanner + exploit + hunting)    security (AES)    │
│  cache (mem+disk, LRU/LFU/FIFO/TTL)       offline (SQLite)  │
│  localmodels (Ollama, LM Studio)           optimization (PSO,│
│                                            GA, ACO, SA)     │
├─────────────────────────────────────────────────────────────┤
│  sandbox (isolation)   compat-harness   mock-anthropic       │
└─────────────────────────────────────────────────────────────┘
```

### Crate overview

| Crate | Purpose | Lines |
|---|---|---|
| `api` | Multi-provider LLM client (Anthropic, DeepSeek, xAI, OpenAI, Ollama) | ~3,500 |
| `commands` | 140+ slash commands | ~5,900 |
| `tools` | 44+ tools (read, edit, bash, grep, glob, web_fetch, WriteNote, ...) | ~10,000 |
| `runtime` | Sessions, MCP server, permissions, task registry, workers, prompt builder | ~4,100 |
| **`vulnscan`** | **9-language AST scanner, exploit gen, chain solver, bughunt** | **~6,500** |
| `security` | AES-256-GCM, XChaCha20Poly1305, Argon2id, zeroize | ~1,000 |
| `enterprise` | Circuit breaker, retry, health checks, metrics, tracing | ~1,800 |
| `cache` | Multi-level (mem+SQLite), zlib, LRU/LFU/FIFO/TTL, 45 tests | ~1,200 |
| `offline` | SQLite operation queue with auto-sync | ~800 |
| `localmodels` | Ollama/LM Studio auto-discovery | ~300 |
| `optimization` | PSO, Genetic Algorithm, Ant Colony, Simulated Annealing | ~1,500 |
| `plugins` | Plugin lifecycle management | ~600 |
| `sandbox` | Container isolation | ~200 |
| `telemetry` | Analytics and structured logging | ~400 |
| `compat-harness` | Behavioral compatibility tests | ~1,000 |
| `mock-anthropic-service` | Deterministic mock API for testing | ~300 |
| `rusty-claude-cli` | Main binary entry point | ~13,600 |

**Total: ~95,000 lines of Rust, 1,100+ tests, 545+ commits.**

---

## Vulnscan Deep Dive

The `vulnscan` crate (6,500 lines, 38 source files) is Kraken's crown jewel.

### Static Analyzers (9 languages)

| Language | Analyzer |
|---|---|
| C | `.c`, `.h` — memory safety, buffer overflows, use-after-free |
| C++ | `.cpp`, `.hpp`, `.cc`, `.cxx` — type confusion, integer overflows |
| Rust | `.rs` — unsafe blocks, transmute, pointer arithmetic |
| Go | `.go` — nil dereference, race conditions |
| Java | `.java` — deserialization, path traversal |
| JavaScript | `.js`, `.ts` — prototype pollution, XSS, eval injection |
| Python | `.py` — code injection, SSRF, YAML deserialization |
| Ruby | `.rb` — command injection, unsafe reflection |
| Swift | `.swift` — memory safety, crypto misuse |

### Hunting Pipeline

```
┌────────┐  ┌──────────┐  ┌────────┐  ┌──────────┐  ┌────────┐
│ Recon  │→│ Discover  │→│ Chain  │→│ Exploit  │→│ Report │
└────────┘  └──────────┘  └────────┘  └──────────┘  └────────┘
     │            │            │            │            │
     ▼            ▼            ▼            ▼            ▼
 surface    findings    attack      PoC code    HTML/JSON
 mapping    + CVSS      paths       + chain     with graphs
```

### Modes

| Mode | What it does | Use case |
|---|---|---|
| `--fast` | Pattern-based scan only | Quick CI check |
| `--deep` | Pattern + LLM analysis | Full audit |
| `--overnight` | Full autonomous pipeline: rank → scan → validate → exploit → report | Deep bug hunt |

---

## Requirements

- **OS**: Linux, macOS, or Windows (via WSL)
- **Rust**: 1.80+ (install via `rustup`)
- **Disk**: ~2GB for build artifacts
- **RAM**: 512MB minimum, 4GB+ recommended
- **Internet**: Required for remote LLM providers (offline mode available for local models)

---

## Documentation

- [`rust/USAGE.md`](./rust/USAGE.md) — CLI usage, authentication, sessions, configuration
- [`docs/GRATIS.md`](./docs/GRATIS.md) — Free model providers guide (Spanish)
- [`PHILOSOPHY.md`](./PHILOSOPHY.md) — Project philosophy
- [`ROADMAP.md`](./ROADMAP.md) — Development roadmap

---

## License

MIT

---

<p align="center">
  <b>100% Rust. 0% Python. Free providers. No USD required.</b>
</p>
