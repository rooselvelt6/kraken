<div align="center">

# 🦑 KRAKEN CODE

**The autonomous AI agent that hunts vulnerabilities, rewrites code, and never sleeps.**

<img src="https://raw.githubusercontent.com/ultraworkers/kraken-code/main/assets/logo.svg" alt="KRAKEN" width="280"/>

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)](https://github.com/ultraworkers/kraken-code/actions)
[![Rust](https://img.shields.io/badge/rust-1.98+-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/security-hardened-red?style=for-the-badge)](SECURITY.md)

**A fully isolated, sandboxed, self-healing AI coding agent that runs entirely in containers—zero host impact.**

</div>

---

## 🌊 What is Kraken?

Kraken is an **autonomous AI coding agent** designed for high-stakes environments. It doesn't just complete code—it **hunts vulnerabilities**, **refactors entire architectures**, **generates exploits for verification**, and **self-validates via LLM cross-checking**.

| Capability | Status |
|------------|--------|
| 🔒 **Zero-host-impact isolation** | ✅ Docker + KVM VM |
| 🛡️ **Hardened permissions matrix** | ✅ Prompt/Allow never auto-escalate |
| 🏰 **Landlock + Seccomp sandbox** | ✅ Process-level syscall filtering |
| 🔍 **Vulnerability hunting (Bughunter)** | ✅ Multi-stage: recon → scan → chain → hypotheses |
| 🧠 **LLM cross-validation (opt-in)** | ✅ `--allow-llm-upload` with explicit warning |
| 📦 **MCP stdio server with enforcer** | ✅ All tools gated by policy |
| 🐙 **Workspace boundary enforcement** | ✅ Canonical paths, symlink rejection, allowlist |

---

## 🚀 Quick Start

### Prerequisites
- **Docker** (user in `docker` group)
- **KVM** (optional, for kernel-touching modules)
- **8 GB RAM** recommended

### One-Command Build
```bash
# From repo root
docker run --rm -it \
  --user "$(id -u):$(id -g)" \
  --cap-drop=ALL \
  --security-opt no-new-privileges=true \
  --security-opt label=disable \
  --pids-limit=4096 \
  --memory=8g --cpus=8 \
  --tmpfs /tmp:rw,size=2g,exec,mode=1777 \
  -v "$PWD":/workspace:rw \
  -v kraken-cargo:/cargo \
  -w /workspace/rust \
  -e CARGO_HOME=/cargo \
  -e RUSTUP_HOME=/usr/local/rustup \
  -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  rust:1.98-slim \
  bash -c 'cargo build --locked --workspace --profile release-lto -j4 && cargo test --locked --workspace --exclude compat-harness --exclude kraken-git --exclude kraken-mcp -j4'
```

### Run Kraken
```bash
# Inside the container (after build)
./target/release/kraken --help

# Interactive REPL
./target/release/kraken

# One-shot prompt
./target/release/kraken prompt "refactor the auth module to use zero-trust principles"

# Vulnerability hunting
./target/release/kraken hunt --deep --allow-llm-upload
./target/release/kraken bughunter --allow-llm-upload
```

---

## 🎯 Today's Major Updates (2026-09-25)

### 🔒 **Fase 2: Permissions Matrix Hardened (P0)**
| Component | Change |
|-----------|--------|
| `kraken-policy/src/permissions.rs` | Added `PermissionMode::permits()` — explicit semantics; `Prompt`/`Allow` **never** satisfy escalation by ordinal comparison |
| `rusty-claude-cli/src/args.rs` | Fallback `DangerFullAccess` → `WorkspaceWrite` (was silent escalation) |
| `kraken-config/src/config.rs` | **Project config ceiling**: `.kraken.json`/`.kraken/settings.json` cannot raise mode above user ceiling; warnings emitted |
| `tools/src/lib.rs` | **Single gate** `execute_tool_with_enforcer` — every tool passes through enforcer; redundant per-arm calls removed |
| `rusty-claude-cli/src/main.rs:713` | `mcp serve` now uses `GlobalToolRegistry::builtin().with_enforcer(...)` — no more raw `execute_tool` bypass |
| `tools/src/lib.rs` | `config` tool `permissions.defaultMode` options restricted to `["default", "plan", "read-only"]` — escalation requires CLI flag |

### 🏰 **Fase 3: Sandbox Effectivo (Landlock + Seccomp)**
| File | Implementation |
|------|----------------|
| `kraken-infra/src/sandbox.rs` | `apply_process_sandbox()` — applies Landlock (kernel ≥ 5.13) + Seccomp in child process via `pre_exec` |
| `runtime/src/bash.rs` | `prepare_command` / `prepare_tokio_command` call sandbox before `exec`; `filesystem_active: false` + clear `fallback_reason` when unsupported |

### 🏰 **Fase 4: Límites de Workspace (Sanitizer Activado)**
| Tool | Protection |
|------|------------|
| `read_file`, `write_file`, `edit_file` | Canonicalization + symlink rejection + workspace boundary + allowlist (`/tmp`, `/var/tmp`) |
| `glob_search`, `grep_search` | Same + size/entry limits |
| `NotebookEdit`, `Skill`, `TodoWrite` | Path sanitization enforced |

### 🔐 **Fase 5: Privacidad LLM (Opt-In Only)**
| Feature | Detail |
|---------|--------|
| `vulnscan/src/lib.rs` | `enable_llm_validation = false` by default |
| `/hunt` & `/bughunter` | New `--allow-llm-upload` flag; explicit warning before sending code to LLM |
| `commands/src/lib.rs` | Parser accepts `--allow-llm-upload` for both slash commands |

### 🧹 **Fase 1: Build Sin Dependencias del Sistema**
- `reqwest` → `rustls-tls` in 8 crates (removed `native-tls`/`openssl-sys`)
- `syntect` → `default-fancy` (no `oniguruma`)
- `sniffer/pcap` → optional feature + compile-time stub
- `postexploit/ssh2` removed (unused)
- Workspace simplified: `members = ["crates/*"]` + explicit `default-members`

---

## 🏗 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        KRAKEN RUNTIME                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Conversation │  │   Tool       │  │ Permission           │  │
│  │ Runtime      │──▶│  Registry    │──▶│  Enforcer          │  │
│  └──────────────┘  └──────────────┘  └──────────┬───────────┘  │
│                                                  │              │
│  ┌──────────────────────────────────────────────▼───────────┐  │
│  │                    EXECUTE BASH                           │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │  │
│  │  │  Landlock   │  │  Seccomp    │  │  Sanitizer      │  │  │
│  │  │  (FS)       │  │  (syscalls) │  │  (paths)        │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Built-in Tools (57)

| Category | Tools |
|----------|-------|
| **Filesystem** | `read_file`, `write_file`, `edit_file`, `glob_search`, `grep_search`, `NotebookEdit` |
| **Execution** | `bash`, `PowerShell`, `TaskCreate`, `RunTaskPacket`, `RunParallel`, `CronCreate` |
| **Intelligence** | `Skill`, `Agent`, `ToolSearch`, `WebFetch`, `WebSearch`, `OsintCollect`, `ShodanSearch` |
| **Analysis** | `bughunter`, `hunt`, `vulnscan`, `lateral`, `chaining` |
| **Git/Workflow** | `commit`, `pr`, `issue`, `diff`, `session`, `compact` |
| **MCP/Ext** | `MCP`, `McpAuth`, `ListMcpResources`, `ReadMcpResource`, `RemoteTrigger` |
| **Debug** | `debug-tool-call`, `doctor`, `sandbox`, `status` |

---

## 🔐 Permission Modes

| Mode | Description | Default |
|------|-------------|---------|
| `read-only` | Read-only tools only (`cat`, `grep`, `ls`, `git log`...) | — |
| `workspace-write` | Workspace writes allowed; system paths blocked | ✅ **DEFAULT** |
| `danger-full-access` | Full system access (requires explicit `--permission-mode`) | — |

**Key invariant:** `Prompt` and `Allow` modes **never** auto-approve escalations. They require interactive confirmation.

---

## 🐙 Bughunter & Hunt

```bash
# Fast scan (no LLM)
kraken bughunter

# Deep scan with LLM cross-validation (opt-in)
kraken bughunter --allow-llm-upload

# Multi-stage hunt: recon → scan → chain → hypotheses
kraken hunt --deep --allow-llm-upload
kraken hunt --overnight --allow-llm-upload
```

**Output includes:**
- Findings ranked by severity
- Attack paths & lateral movement hypotheses
- Attack surface mapping (tech, endpoints, entry points)
- Deorphaned findings (previously unlinked, now contextualized)
- LLM cross-validation rankings (if `--allow-llm-upload`)

---

## 🐳 Container Isolation Guarantees

| Isolation Layer | Mechanism |
|-----------------|-----------|
| **User namespace** | `--user 1000:1000` + `--cap-drop=ALL` |
| **No new privileges** | `--security-opt no-new-privileges:true` |
| **SELinux** | `--security-opt label=disable` (no host relabeling) |
| **PIDs** | `--pids-limit=4096` |
| **Memory/CPU** | `--memory=8g --cpus=8` |
| **Tmpfs** | `--tmpfs /tmp:rw,size=2g,exec,mode=1777` |
| **No host mounts** | Only repo (`/workspace`) + cargo cache (`/cargo`) |
| **No host sockets** | No `/var/run/docker.sock`, no `--network=host` |

---

## 📁 Project Structure

```
kraken/
├── rust/
│   ├── Cargo.toml                 # Workspace (43 crates)
│   ├── .kraken.json               # Project config (workspace-write)
│   ├── crates/
│   │   ├── kraken-policy/         # Permission matrix + enforcer
│   │   ├── kraken-config/         # Config loader + ceiling logic
│   │   ├── kraken-infra/          # Landlock, Seccomp, Sanitizer, Sandbox
│   │   ├── runtime/               # Conversation runtime + bash execution
│   │   ├── tools/                 # 57 built-in tool implementations
│   │   ├── rusty-claude-cli/      # CLI entrypoint + REPL
│   │   ├── vulnscan/              # Bughunter + Hunt pipelines
│   │   ├── commands/              # Slash command registry
│   │   └── ... (35 more crates)
│   └── target/                    # Build artifacts (gitignored)
├── plan2030.md                    # Master implementation plan
├── README.md                      # This file
└── LICENSE
```

---

## 🧪 Testing

```bash
# All tests (excludes pre-existing env failures)
cargo test --locked --workspace --exclude compat-harness --exclude kraken-git --exclude kraken-mcp

# Specific crates
cargo test -p kraken-policy -p kraken-config -p kraken-infra -p runtime -p tools -p vulnscan

# Permission matrix exhaustive (25 combinations)
cargo test -p kraken-policy permission_matrix

# Sandbox guardrails
cargo test -p runtime bash_guardrails

# Bughunter integration
cargo test -p vulnscan
```

---

## 📋 Roadmap (Fases 6-9)

| Fase | Focus | Status |
|------|-------|--------|
| **6** | Funcionalidad anunciada: conectar `LogicAnalyzer`, `CryptoAnalyzer`, `SecretsDetector`, `WebAppScanner` en Bughunter; fix `/vulnscan` action | 🔄 |
| **7** | Toolchain: `rust-toolchain.toml` (1.98.1), CI fixes, `README` updates, `get-kraken.sh` checksum | 🔄 |
| **8** | Verificación completa: `cargo fmt`, `clippy -D warnings`, `cargo tree -i native-tls/openssl-sys` vacíos | 🔄 |
| **9** | Limpieza: `docker rm -f kraken-build && docker volume rm kraken-cargo` | 🔄 |

---

## 🤝 Contributing

1. Fork → branch → PR
2. All changes must pass: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --locked --workspace`
3. No host modifications in CI — all tests in Docker
4. Security-first: any permission/sandbox change requires threat model note

---

## ⚖️ License

MIT — see [LICENSE](LICENSE)

---

## 🙏 Acknowledgments

- **Landlock LSM** — unprivileged filesystem sandboxing
- **seccomp-bpf** — syscall filtering
- **Rust async ecosystem** — tokio, reqwest, serde
- **Upstream inspiration** — Claude Code architecture patterns

---

<div align="center">

**Release the Kraken.** 🦑

[Report Security Issue](mailto:security@kraken-code.dev) • [Discord](https://discord.gg/kraken-code) • [Twitter](https://twitter.com/kraken_code)

</div>