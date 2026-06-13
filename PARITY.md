# Parity Status — Kraken

## Summary

Kraken aims for feature parity with Claude Code (Anthropic's official CLI) while adding security, OSINT, and sandbox capabilities that exceed the upstream baseline.

## Parity Lanes

| Lane | Status | Notes |
|------|--------|-------|
| File operations | ✅ | read, write, edit, glob, grep |
| Bash execution | ✅ | Sandboxed with permission enforcement |
| Session management | ✅ | persist, resume, list, switch |
| MCP plugin lifecycle | ✅ | Tool bridge, config, liveness checks |
| Provider routing | ✅ | Anthropic, OpenAI, DeepSeek, Ollama, DashScope, OpenRouter |
| JSON output | ✅ | All diagnostic commands |
| Permission system | ✅ | 4 levels: ReadOnly → Allow |
| Config validation | ✅ | Typed errors, helpful messages |
| Hook system | ✅ | Pre/post execution hooks |
| Tab completion | ✅ | Internal infrastructure |

## Beyond Parity (Exclusive to Kraken)

| Feature | Description |
|---------|-------------|
| Vulnerability scanner | Multi-language + IaC + secrets |
| OSINT framework | DNS, WHOIS, social, darkweb, dorking |
| Sandbox | Seccomp BPF, Landlock, namespaces, NSJail |
| Crypto | AES-256-GCM, XChaCha20Poly1305, Argon2id |
| ML threat detection | 66-feature classifier, online learning |
| Supply chain security | SLSA 3, cargo-deny, cargo-audit |
| Multi-arch release | 7 platforms, Docker multi-arch |
| Property-based testing | 23 proptest targets |

## Version

Current parity baseline: **Claude Code v0.2.x** (2026)
