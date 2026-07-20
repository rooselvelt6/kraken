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
| Exploitation | ROP chains, shellcode, reverse/bind shells, PE/ELF/MachO injectors, payload encoders |
| OSINT | DNS, WHOIS, email, ASN, Shodan, crt.sh, 75+ redes sociales, darkweb, Google dorking |
| Networks | Packet capture, ARP/DNS spoofing, WiFi audit, Bluetooth |
| Post-Exploit | Credential hunting, persistence, lateral movement, pivoting |
| Cloud | AWS/GCP/Azure audit, Kubernetes, Docker |
| Kernel Analysis | Tree-sitter AST patterns, KASAN/KCSAN/KMSAN parsers, syzkaller/kAFL wrappers, exploit generation (commit_creds ROP, modprobe_path, Dirty Pipe) |
| AI Campaign | Autonomous planner, multi-agent coordination, adaptive targeting |
| Reporting | Markdown, HTML dashboard, Slack/Discord/Teams webhooks, Telegram bot |

## Stats

- **35 crates** / **210k lineas** / **2650+ tests** / **0 unsafe**
- 7 LLM providers (Anthropic, OpenAI, DeepSeek, Ollama, DashScope, OpenRouter, Big Pickle)
- Linux, macOS, Windows, FreeBSD, Raspberry Pi

## Build from source

```bash
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust
cargo build --release
```

## License

MIT
