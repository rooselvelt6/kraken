# 🐙 Kraken

<p align="center">
  <strong>Cybersecurity Swiss Army Knife · Autonomous Coding Agent · OSINT · Exploits · 200 offensive capabilities</strong>
  <br>
  <em>100% Rust · 35 crates · 210,000 lines · 2,620 tests · 59 tools · Zero `unsafe`</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.85+-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/tests-2620-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/unsafe-forbidden-red" alt="Unsafe Forbidden">
  <img src="https://img.shields.io/badge/SLSA-3-purple" alt="SLSA 3">
  <img src="https://img.shields.io/badge/roadmap-200%2F200%20(100%25)-brightgreen" alt="Roadmap 100%">
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20BSD%20%7C%20RPi-brightgreen" alt="OS">
</p>

---

## 🚀 Kraken in 5 Seconds

Kraken is an **all-in-one offensive cybersecurity platform** built entirely in Rust. It replaces **~40 Kali Linux tools** in a single ~40 MB static binary, with integrated AI capabilities, multi-layer sandboxing, and real-time machine learning threat detection.

```bash
# Install (seconds)
curl -fsSL https://raw.githubusercontent.com/rooselvelt6/kraken/main/scripts/get-kraken.sh | sh

# Vulnerability scan
kraken vulnscan --dir .

# Full OSINT
kraken osint --domain ejemplo.com --all

# Cloud audit
kraken vulnscan --aws --k8s --docker

# Autonomous campaign
kraken campaign --target 192.168.1.0/24 --auto
```

| Metric | Value |
|--------|-------|
| Workspace crates | **35** |
| Rust lines | **210,000** |
| Unit tests | **2,620** |
| Roadmap complete | **200/200 (100%)** |
| Agent tools | **59** |
| Slash commands | **200+** |
| Modules (`pub mod`) | **250+** |
| LLM providers | **7** (Anthropic, OpenAI, DeepSeek, Ollama, DashScope, OpenRouter, Big Pickle) |
| Platforms | **6** (Linux x64/ARM, macOS Intel/Silicon, Windows, FreeBSD) |

---

## ⚡ Response Times (Criterion Benchmarks)

| Operation | Time |
|-----------|------|
| ML feature extraction (66 features) | **~53 µs** |
| Classifier inference | **~24 µs** |
| Ensemble scoring (3 classifiers) | **~254 µs** |
| Sequential anomaly detection | **~327 µs** |
| Model deserialization | **~9 µs** |
| API request building (10 messages) | **~16 µs** |
| API request building (100 messages) | **~209 µs** |
| Reasoning model detection | **~26-42 ns** |
| Tool result flatten (1 text) | **~17 ns** |
| Tool result flatten (50 blocks) | **~12 µs** |

---

## 🧠 What Can Kraken Do?

### 🔍 OSINT & Reconnaissance (Phases 1-2)
- SYN/UDP port scanner, OS & service fingerprinting
- DNS enumeration (A, AAAA, MX, TXT, NS, SOA, CNAME, brute-force, reverse PTR)
- Web fuzzing (directories, extensions, VHost, parameters, WAF detection)
- Full OSINT: DNS, WHOIS, email (HIBP), infrastructure (ASN, Shodan, crt.sh, Censys), 75+ social networks, darkweb, Google Dorking

### 💉 Web Exploitation (Phases 3-4)
- SQLi detector + exploiter (blind, error-based, UNION, automatic data extraction)
- NoSQLi, XSS (reflected, stored, DOM, blind), command injection, LFI/RFI, SSTI, CSRF
- Exploit generation: ROP chains, shellcode, reverse/bind shells, payload encoders (XOR, base64, alphanumeric), PE/ELF/MachO injector, Searchsploit integration

### 🔑 Password Attacks (Phase 5)
- Hash type identifier, CPU cracker (MD5, SHA1/2, bcrypt, argon2id), mask attack (hashcat-style), rainbow tables, wordlist generator (crunch-style + CeWL)
- Online brute-force: HTTP, FTP, SSH, MySQL, SMB
- Password statistics (Pipal-style): entropy, lengths, patterns, top N

### 📡 Networking (Phases 6-7)
- Live packet capture with BPF filters, protocol dissectors (HTTP, DNS, ARP, DHCP, ICMP)
- ARP spoofing, DNS spoofing, DHCP spoofing, SSL/TLS strip, credential sniffer, session hijack
- Wi-Fi: scanning, handshake capture, PMKID, WPA/WPA2 dictionary, WPS PIN brute-force, deauth, beacon flood, evil twin
- Bluetooth/BLE: device discovery, service enumeration

### 🔬 Reverse Engineering (Phase 8)
- ELF/PE/MachO parser (sections, symbols, imports, exports, resources)
- x86/x64/ARM disassembler, string extraction, entropy analysis, YARA scanner
- Packer detection (UPX, Themida, VMProtect) with PEiD-style signatures

### 🎯 Post-Exploitation (Phase 9)
- PE checker Linux (SUID, capabilities, cron, writable scripts) and Windows (AlwaysInstallElevated, tokens)
- Credential hunter (files, env, git, configs)
- Persistence: Linux (cron, systemd, SSH keys, LD_PRELOAD), Windows (registry, startup, tasks), macOS (launchd)
- Lateral movement: SSH jump, SMB PsExec-style, SOCKS5 pivoting, port forwarding, token impersonation

### 📡 C2 Framework (Phase 10)
- Beacons: HTTP(S) with jitter, DNS tunneling, WebSocket bidirectional, SMB pipes
- Task management, payload staging, multi-client, AES-256-GCM encryption, kill/reconnect, proxy-aware, egress detection

### 🕵️ Forensics (Phase 11)
- Disk imaging with SHA-256 hash, file carving by magic headers, PhotoRec-style deep scan
- Memory analysis (processes, sockets, modules), Windows registry (SAM, SYSTEM, SOFTWARE), MAC timeline
- PDF forensics (malicious JS, embedded files), email (.pst/.mbox, SPF/DKIM), browser (Chrome, Firefox), EXIF/metadata

### 🎭 Social Engineering (Phase 12)
- Phishing page cloner, credential harvester, fake login templates (Google, Office365, GitHub)
- Email campaigns via SMTP with HTML templates, QR code phishing, USB drop (Rubber Ducky/Bash Bunny)
- Evilginx-style reverse proxy (2FA capture), SMS phishing, pretexting templates, campaign tracking

### ☁️ Cloud Security (Phase 13)
- AWS: S3 bucket enumeration, IAM audit, EC2/EBS audit
- GCP: Storage bucket enumeration, Azure: Blob enumeration
- Kubernetes: pod security, RBAC, network policies, CIS benchmark (kube-bench style)
- Docker: host config, exposed ports, container audit
- Cloud metadata SSRF (169.254.169.254)

### ⚙️ Hardware & IoT (Phase 14)
- Firmware extraction (SquashFS, JFFS2), entropy analysis, version diffing
- UART pin detection, JTAG/SWD debug interface detection, GPIO control, SPI flash reader
- SDR scanner (RTL-SDR), IoT protocol fuzzing (MQTT, CoAP, Zigbee)

### 📱 Mobile Security (Phase 15)
- APK decompiler (apktool wrapper), DEX parser, Android manifest analyzer
- iOS IPA analysis (plist, binary, entitlements), root/jailbreak detection (Magisk, SuperSU, unc0ver)
- Certificate pinning check, Frida script generator, OWASP MASVS checker (L1-L3)

### 🔗 Supply Chain (Phase 16)
- OSV.dev, GitHub Advisory, NVD API integration
- CIS benchmark scanner (Docker, K8s, Linux, Windows), license compliance
- SBOM diffing, SLSA provenance (L1-L4), policy-as-code, typosquatting detection (Levenshtein + homograph)

### 🕶️ Anonymity (Phase 17)
- Tor proxy integration, SOCKS5 chain (proxychains-style), onion service scanner
- Metadata scrubber (EXIF, PNG, JPEG, PDF, ZIP), MAC randomizer
- DNS leak test, IP leak test, anonsurf-style routing, OnionShare-style file sharing

### 💥 Stress Testing (Phase 18)
- SYN flood, UDP flood, HTTP flood + slow loris + slow read
- SSL/TLS renegotiation flood, DHCP starvation, MAC flooding
- Wireless deauth flood, beacon flood, amplification scan (DNS/NTP/SNMP)

### 🧠 AI Campaign Orchestrator (Phase 19)
- Autonomous campaign planner, multi-agent coordinator, adaptive targeting
- Auto-exploitation chaining (recon → exploit → post), overnight mode with scheduling
- Learning engine (learns from failures), campaign replay with snapshots

### 📊 Reporting & Collaboration (Phase 20)
- Executive reports in Markdown with SHA-256 hash, auto-refreshing HTML dashboard
- Webhooks: Slack, Discord, Microsoft Teams with native payloads
- Telegram bot with severity alerts, multi-user collaborative sessions
- Screenshot capture (EyeWitness-style), password statistics (Pipal-style)

---

## 🛡️ Security & Cryptography

| Component | Algorithm / Technique |
|---|---|
| Symmetric encryption | AES-256-GCM / XChaCha20Poly1305 (runtime selectable) |
| Key derivation | Argon2id (OWASP 2024) + HKDF-SHA256 |
| Audit signing | Ed25519 — signed blockchain with chain verification |
| Secret redaction | 17 canonical patterns + Shannon entropy detection |
| Memory zeroization | `zeroize` on Drop for all sensitive material |
| Constant-time comparison | `subtle::ConstantTimeEq` — no timing side-channels |
| Multi-layer sandbox | Seccomp BPF + Landlock + namespaces + NSJail + rlimits |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            kraken (CLI binary)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  tools(59)   commands(200+)   api(7 providers)   runtime(15 modules)        │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ vulnscan │ │  osint   │ │ security │ │ sandbox  │ │  localmodels     │  │
│  │ (9 langs,│ │ (10 mod) │ │(crypto,  │ │(seccomp, │ │  (66 features,   │  │
│  │ 4 IaC,   │ │ DNS/WEB  │ │ audit,   │ │ landlock,│ │   ML ensemble,   │  │
│  │ secrets) │ │ social)  │ │ vault)   │ │ nsjail)  │ │   online learn)  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│  20 offensive phases: password · sniffer · wireless · reverse · post-exploit│
│  C2 · forensics · social · cloud · hardware · mobile · supplychain         │
│  anonymity · stress · aicampaign · reporting                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 ML & Threat Detection

| Component | Description | Time |
|---|---|---|
| Feature Extractor | 66 features per tool call | ~53 µs |
| Command Classifier | Softmax logistic regression (3 classes) | ~24 µs |
| Ensemble Scorer | Weighted voting from 3 classifiers | ~254 µs |
| Online Learner | SGD with WAL — learns from user decisions | ~9 µs (deser) |
| Sequence Detector | Markov chain over tool transitions | ~327 µs |

---

## 📦 Project Structure

```
kraken/
├── rust/
│   ├── Cargo.toml              # Workspace (35 crates)
│   ├── crates/ (35 crates covering all 20 phases)
│   ├── tests/                  # Proptests (23 properties)
│   └── fuzz/                   # 4 fuzz targets
├── scripts/                    # Installer, CI, systemd, man page
├── completions/                # Zsh, Bash, Fish
└── docs/                       # Documentation
```

---

## 🏁 Quick Start

```bash
# Install (binary, seconds)
curl -fsSL https://raw.githubusercontent.com/rooselvelt6/kraken/main/scripts/get-kraken.sh | sh

# Build from source
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust && cargo build --release

# Use
kraken                                          # Interactive REPL
kraken prompt "analyze this repository"         # One-shot prompt
kraken vulnscan --dir .                         # Quick vulnerability scan
kraken vulnscan --dir . --html report.html      # HTML report
kraken osint --domain example.com --all         # Full OSINT
kraken campaign --target 10.0.0.0/24            # Autonomous campaign
```

---

## 📚 Documentation

- [USAGE.md](USAGE.md) — Detailed usage guide
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
- [SECURITY.md](SECURITY.md) — Security policy
- [CHANGELOG.md](CHANGELOG.md) — Release history
- [ROADMAP.md](ROADMAP.md) — Development roadmap
- [PHILOSOPHY.md](PHILOSOPHY.md) — Project philosophy

## License

MIT © 2024 Kraken Contributors

---

<p align="center">
  🦀 <strong>Built in Rust, made in Venezuela</strong> 🦀<br>
  <sub>210,000 lines · 2,620 tests · 0 unsafe · 35 crates · 200 capabilities</sub>
</p>
