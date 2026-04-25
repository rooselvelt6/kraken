# 🦀 Claw Code Venezuela - Enterprise AI Coding Agent

<p align="center">
  <img src="assets/claw-hero.jpeg" alt="Claw Code Venezuela" width="400" />
</p>

<p align="center">
  <a href="https://github.com/rooselvelt6/claw-vzla">
    <img src="https://img.shields.io/github stars/rooselvelt6/claw-vzla?style=flat&color=blue" alt="GitHub stars" />
  </a>
  <a href="https://discord.gg/5TUQKqFWd">
    <img src="https://img.shields.io/discord/5TUQKqFWd?style=flat&color=blue" alt="Discord" />
  </a>
  <img src="https://img.shields.io/badge/rust-100%25-blue" alt="Rust" />
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License" />
</p>

---

## 🇻🇪 Description

**Claw Code Venezuela** is an enterprise-grade fork of Claw Code optimized for Venezuelan users and the Latin American market. Built with 100% Rust for maximum performance, security, and cost-effectiveness.

### Why Venezuela?

- **No USD dependency** - Free models that work without international payment
- **Optimized for LATAM** - Models available without restrictions
- **Enterprise-ready** - Production features built-in

---

## ✨ Key Features

### Free Models (No API Key Required)

| Provider | Models | Free Tier |
|----------|-------|----------|
| **DeepSeek** | V3, R1, Coder | 5M tokens/month |
| **Big Pickle** | OpenCode Zen | Unlimited |
| **Ollama** | qwen2.5-coder, llama3.1 | Local (free) |

### Enterprise Features (Built-in)

| Feature | Module | Description |
|---------|--------|------------|
| **Retry with Backoff** | `enterprise/retry.rs` | Exponential backoff + jitter |
| **Circuit Breaker** | `enterprise/circuit_breaker.rs` | Fault tolerance |
| **Health Checks** | `enterprise/health.rs` | Provider health monitoring |
| **Graceful Degradation** | `enterprise/graceful_degradation.rs` | Automatic fallback |
| **Metrics** | `enterprise/metrics.rs` | Per-provider metrics |
| **Structured Logging** | `enterprise/logging.rs` | JSON format |
| **Distributed Tracing** | `enterprise/tracing.rs` | Request correlation |
| **Connection Pooling** | `enterprise/performance.rs` | Connection reuse |
| **Timed Cache** | `enterprise/performance.rs` | TTL-based caching |
| **Enterprise Audit** | `enterprise/enterprise_features.rs` | User action audit |
| **Rate Limiting** | `enterprise/enterprise_features.rs` | Per-user limits |
| **AES-GCM Encryption** | `security/crypto.rs` | Config encryption |
| **Audit Log Chain** | `security/audit.rs` | Hash chain integrity |

### Nature-Inspired Algorithms (Rust 100%)

```
rust/crates/optimization/
├── pso.rs    # Particle Swarm Optimization
├── ga.rs     # Genetic Algorithm
├── aco.rs    # Ant Colony Optimization
└── sa.rs     # Simulated Annealing
```

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/rooselvelt6/claw-vzla.git
cd claw-vzla/rust

# Build
cargo build --release

# Run with DeepSeek (free)
DEEPSEEK_API_KEY=your_key ./target/release/claw run "Hello"

# Or with Ollama (local free)
./target/release/claw run "Hello" --model ollama/qwen2.5-coder
```

---

## 📊 Architecture

```
claw-vzla/
├── rust/
│   ├── crates/
│   │   ├── api/              # Providers (DeepSeek, Big Pickle, Ollama)
│   │   ├── enterprise/       # Enterprise features (27 tests)
│   │   ├── optimization/    # Bio-inspired algorithms
│   │   ├── security/        # Encryption + audit
│   │   ├── sandbox/         # Tool isolation
│   │   ├── runtime/         # Core runtime
│   │   └── rusty-claude-cli/ # Main CLI (~150MB)
���   └── target/release/claw  # Single binary
└── docs/
    └── GRATIS.md           # Free models guide
```

---

## 🏢 Enterprise Production Ready

### Fault Tolerance

```rust
use enterprise::{CircuitBreaker, RetryConfig, GracefulDegradation};

let cb = CircuitBreaker::new(5, std::time::Duration::from_secs(30));
let retry = RetryConfig::default();
let fallback = GracefulDegradation::with_default();
```

### Observability

```rust
use enterprise::{JsonLogger, Level, TraceContext};

let logger = JsonLogger::new(Level::Info);
logger.info("provider", "DeepSeek request completed");

let trace = TraceContext::new("api_call");
trace.with_tag("provider", "deepseek");
```

### Rate Limiting & Audit

```rust
use enterprise::{RateLimiter, EnterpriseAuditLog};

let limiter = RateLimiter::new(60, 100_000, 10); // 60 req/min, 100k tokens
let audit = EnterpriseAuditLog::new(10_000);
```

---

## 📈 Comparison

| Feature | Original Claw | Venezuela Fork |
|---------|--------------|--------------|
| **Providers** | Anthropic only | DeepSeek + Big Pickle + Ollama |
| **Free Tier** | ❌ | ✅ 5M+ tokens |
| **Encryption** | Basic | AES-GCM |
| **Audit** | ❌ | ✅ Hash chain |
| **Circuit Breaker** | ❌ | ✅ Built-in |
| **Rate Limiting** | ❌ | ✅ Per-user |
| **Language** | EN | ES + EN |

---

## 📝 Documentation

- [Roadmap](./ROADMAP.md) - Original roadmap
- [Enterprise Roadmap](./ROADMAP-ENTERPRISE.md) - Production features
- [Free Models Guide](./docs/GRATIS.md) - Modelos gratuitos

---

## 🤝 Contributing

```bash
# Build and test
cd rust
cargo test --workspace
cargo fmt
cargo clippy --workspace -- -D warnings
```

---

## 📜 License

MIT License - See [LICENSE](./LICENSE)

---

**Built with ❤️ for Venezuela**  
100% Rust • Enterprise Ready • Free Models