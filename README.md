# Kraken

Plataforma de ciberseguridad ofensiva. Un solo binario en Rust que reemplaza ~40 herramientas de Kali Linux.

```
cargo install kraken
```

## Comandos principales

```bash
kraken vulnscan --dir .              # Escaneo de vulnerabilidades
kraken osint --domain example.com   # OSINT completo
kraken campaign --target 10.0.0/24  # Campaña autónoma
kraken exploit --generate           # Generación de exploits
```

## Capacidades

| Area | Herramientas |
|------|-------------|
| Vulnerability Scanning | SQLi, XSS, command injection, secrets, IaC (Terraform, Docker, K8s, CloudFormation), kernel analysis (14 AST checkers) |
| Exploitation | ROP chains, shellcode multi-arch (x64/x86/ARM/ARM64/Windows/macOS), reverse/bind shells, PE/ELF/MachO injectors, payload encoders |
| OSINT | DNS, WHOIS, email, ASN, Shodan, crt.sh, 75+ redes sociales, darkweb, Google dorking |
| Networks | Packet capture, ARP/DNS spoofing, WiFi audit, Bluetooth |
| Post-Exploit | Credential hunting, persistence, lateral movement, pivoting |
| Cloud | AWS/GCP/Azure audit, Kubernetes, Docker |
| Kernel Analysis | Tree-sitter AST patterns, KASAN/KCSAN/KMSAN parsers, syzkaller/kAFL wrappers, exploit generation (commit_creds ROP, modprobe_path, Dirty Pipe) |
| Intelligence | 1M context pipeline (Kimi K3), program-slice analysis, call graph builder, risk-ranked code slicing |
| Multi-Agent | MetaAgent coordinator, 3 sub-agents (Static/LLM/Exploit), cross-validation of findings |
| AI Campaign | Autonomous planner, multi-agent coordination, adaptive targeting |
| Reporting | Markdown, HTML dashboard, Slack/Discord/Teams webhooks, Telegram bot |

## Stats

- **35 crates** / **210k lineas** / **513+ tests** / **0 unsafe**
- 8 LLM providers (Anthropic, OpenAI, DeepSeek, Ollama, DashScope, Kimi K3, OpenRouter, Big Pickle)
- 6 shellcode architectures (Linux x64/x86/ARM/ARM64, Windows x64/x86, macOS)
- Linux, macOS, Windows, FreeBSD, Raspberry Pi

## Build from source

```bash
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust
OPENSSL_DIR=/usr OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu OPENSSL_INCLUDE_DIR=/usr/include cargo build --release
```

## Roadmap

| Fase | Estado | Detalle |
|------|--------|---------|
| F1: Foundation | ✅ | Shellcode multi-arch, kernel PoC, fuzz targets, Frida scripts, 74 integration tests |
| F2: Intelligence | ✅ | Kimi K3, 1M context pipeline, program-slice analysis, multi-agent |
| F3: Supply Chain | ⏳ | SBOM, dependency graph, compliance, MCP trust |
| F4: Offensive | ⏳ | C2 server, malleable profiles, WiFi real, firmware LLM |
| F5: Enterprise | ⏳ | Dashboard, PDF reports, MCP server, CLI polish |

## License

MIT
