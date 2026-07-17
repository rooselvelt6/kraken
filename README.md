# 🐙 Kraken

<p align="center">
  <strong>Navaja suiza de ciberseguridad · Agente de código autónomo · OSINT · Exploits · 200 capacidades ofensivas</strong>
  <br>
  <em>100% Rust · 35 crates · 210 000 líneas · 2 620 tests · 59 herramientas · Ningún `unsafe`</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.85+-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/tests-2620-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/unsafe-forbidden-red" alt="Unsafe Forbidden">
  <img src="https://img.shields.io/badge/SLSA-3-purple" alt="SLSA 3">
  <img src="https://img.shields.io/badge/cosign-signed-brightgreen" alt="Cosign Signed">
  <img src="https://img.shields.io/badge/roadmap-100%2F100-brightgreen" alt="Roadmap 100%">
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20BSD%20%7C%20RPi-brightgreen" alt="OS">
  <img src="https://img.shields.io/badge/bench-24%C2%B5s%20inference-yellow" alt="ML Inference 24µs">
</p>

---

## 🚀 Kraken en 5 segundos

Kraken es una **plataforma de ciberseguridad ofensiva todo-en-uno** construida completamente en Rust. Reemplaza **~40 herramientas de Kali Linux** en un solo binario estático de ~9 MB, con capacidades de IA integradas, sandbox multi-capa y detección de amenazas por machine learning en tiempo real.

```bash
# Instalar (segundos)
curl -fsSL https://raw.githubusercontent.com/rooselvelt6/kraken/main/scripts/get-kraken.sh | sh

# Homebrew (macOS / Linux)
brew install rooselvelt6/kraken/kraken

# Docker
docker pull ghcr.io/rooselvelt6/kraken:latest

# Escanear vulnerabilidades
kraken vulnscan --dir .

# OSINT completo
kraken osint --domain ejemplo.com --all

# Auditoría cloud
kraken vulnscan --aws --k8s --docker

# Campaña autónoma
kraken campaign --target 192.168.1.0/24 --auto
```

| Métrica | Valor |
|---------|-------|
| Crates en workspace | **35** |
| Líneas de Rust | **210 000** |
| Tests unitarios | **2 620** |
| Roadmap completado | **200/200 (100%)** |
| Herramientas de agente | **59** |
| Comandos slash | **200+** |
| Módulos (`pub mod`) | **250+** |
| Proveedores LLM | **7** (Anthropic, OpenAI, DeepSeek, Ollama, DashScope, OpenRouter, Big Pickle) |
| Plataformas | **6** (Linux x64/ARM, macOS Intel/Silicon, Windows, FreeBSD) |

---

## ⚡ Tiempos de respuesta (benchmarks Criterion)

| Operación | Tiempo |
|-----------|--------|
| Extracción de características ML (66 features) | **~53 µs** |
| Inferencia del clasificador | **~24 µs** |
| Scoring ensemble (3 clasificadores) | **~254 µs** |
| Detección de anomalías secuenciales | **~327 µs** |
| Deserialización del modelo | **~9 µs** |
| Construcción de request API (10 mensajes) | **~16 µs** |
| Construcción de request API (100 mensajes) | **~209 µs** |
| Detección de modelo reasoning | **~26-42 ns** |
| Flatten de tool results (1 text) | **~17 ns** |
| Flatten de tool results (50 bloques) | **~12 µs** |

---

## 🧠 ¿Qué puede hacer Kraken?

### 🔍 OSINT & Reconocimiento (Fases 1-2)
- Escáner de puertos SYN/UDP, fingerprint de SO y servicios
- Enumeración DNS (A, AAAA, MX, TXT, NS, SOA, CNAME, brute-force, reverse PTR)
- Fuzzing web (directorios, extensiones, VHost, parámetros, WAF detection)
- OSINT completo: DNS, WHOIS, email (HIBP), infraestructura (ASN, Shodan, crt.sh, Censys), 75+ redes sociales, darkweb, Google Dorking

### 💉 Explotación Web (Fases 3-4)
- SQLi detector + exploiter (blind, error-based, UNION, automático con extracción de datos)
- NoSQLi, XSS (reflejado, almacenado, DOM, blind), command injection, LFI/RFI, SSTI, CSRF
- Generación de exploits: ROP chains, shellcode, reverse/bind shells, payload encoders (XOR, base64, alphanumeric), PE/ELF/MachO injector, búsqueda en Searchsploit

### 🔑 Password Attacks (Fase 5)
- Hash type identifier, cracker CPU (MD5, SHA1/2, bcrypt, argon2id), mask attack (hashcat-style), rainbow tables, wordlist generator (crunch-style + CeWL)
- Online brute-force: HTTP, FTP, SSH, MySQL, SMB
- Análisis estadístico de contraseñas (Pipal-style): entropía, longitudes, patrones, top N

### 📡 Redes (Fases 6-7)
- Packet capture live con filtros BPF, dissectors (HTTP, DNS, ARP, DHCP, ICMP)
- ARP spoofing, DNS spoofing, DHCP spoofing, SSL/TLS strip, NetCreds sniffer, session hijack
- Wi-Fi: scan, handshake capture, PMKID, WPA/WPA2 dictionary, WPS PIN brute-force, deauth, beacon flood, evil twin
- Bluetooth/BLE: device discovery, service enumeration

### 🔬 Ingeniería Inversa (Fase 8)
- Parser de ELF/PE/MachO (secciones, símbolos, imports, exports, resources)
- Disassembler x86/x64/ARM, extracción de strings, análisis de entropía, escáner YARA
- Detección de packers (UPX, Themida, VMProtect) con firmas PEiD-style

### 🎯 Post-Explotación (Fase 9)
- PE checker Linux (SUID, capabilities, cron, writable scripts) y Windows (AlwaysInstallElevated, tokens)
- Credential hunter en archivos, env, git, configs
- Persistencia: Linux (cron, systemd, SSH keys, LD_PRELOAD), Windows (registry, startup, tasks), macOS (launchd)
- Lateral movement: SSH jump, SMB PsExec-style, pivoting SOCKS5, port forwarding, token impersonation

### 📡 C2 Framework (Fase 10)
- Beacons: HTTP(S) con jitter, DNS tunneling, WebSocket bidireccional, SMB pipes
- Task management, payload staging, multi-client, cifrado AES-256-GCM, kill/reconnect, proxy-aware, egress detection

### 🕵️ Forense (Fase 11)
- Disk imaging con hash SHA-256, file carving por magic headers, PhotoRec-style deep scan
- Análisis de memoria (procesos, sockets, módulos), registro de Windows (SAM, SYSTEM, SOFTWARE), timeline MAC
- Forense de PDF (JS malicioso, embedded files), email (.pst/.mbox, SPF/DKIM), browser (Chrome, Firefox), EXIF/metadata

### 🎭 Social Engineering (Fase 12)
- Phishing page cloner, credential harvester, fake login templates (Google, Office365, GitHub)
- Email campaigns SMTP con templates HTML, QR code phishing, USB drop (Rubber Ducky/Bash Bunny)
- Evilginx-style reverse proxy (captura 2FA), SMS phishing, pretexting templates, campaign tracking

### ☁️ Cloud Security (Fase 13)
- AWS: S3 bucket enumeration, IAM audit, EC2/EBS audit
- GCP: Storage bucket enumeration, Azure: Blob enumeration
- Kubernetes: pod security, RBAC, network policies, CIS benchmark (kube-bench style)
- Docker: host config, exposed ports, container audit
- Cloud metadata SSRF (169.254.169.254)

### ⚙️ Hardware & IoT (Fase 14)
- Firmware extraction (SquashFS, JFFS2), análisis de entropía, diff entre versiones
- Detección de UART, JTAG/SWD, GPIO control, flash reader (SPI)
- SDR scanner (RTL-SDR), fuzzing de protocolos IoT (MQTT, CoAP, Zigbee)

### 📱 Mobile Security (Fase 15)
- APK decompiler (apktool wrapper), DEX parser, Android manifest analyzer
- iOS IPA analysis (plist, binary, entitlements), root/jailbreak detection (Magisk, SuperSU, unc0ver)
- Certificate pinning check, Frida script generator, OWASP MASVS checker (L1-L3)

### 🔗 Supply Chain (Fase 16)
- OSV.dev, GitHub Advisory, NVD API integration
- CIS benchmark scanner (Docker, K8s, Linux, Windows), license compliance
- SBOM diffing, SLSA provenance (L1-L4), policy-as-code, typosquatting detection (Levenshtein + homograph)

### 🕶️ Anonimato (Fase 17)
- Tor proxy integration, SOCKS5 chain (proxychains-style), onion service scanner
- Metadata scrubber (EXIF, PNG, JPEG, PDF, ZIP), MAC randomizer
- DNS leak test, IP leak test, anonsurf-style routing, OnionShare-style file sharing

### 💥 Stress Testing (Fase 18)
- SYN flood, UDP flood, HTTP flood + slow loris + slow read
- SSL/TLS renegotiation flood, DHCP starvation, MAC flooding
- Wireless deauth flood, beacon flood, amplification scan (DNS/NTP/SNMP)

### 🧠 AI Campaign Orchestrator (Fase 19)
- Campaign planner autónomo, coordinador multi-agente, adaptive targeting
- Auto-exploitation chaining (recon → exploit → post), overnight mode con scheduling
- Learning engine (aprende de fallos), campaign replay con snapshots

### 📊 Reporting & Collaboration (Fase 20)
- Reportes ejecutivos en Markdown con hash SHA-256, dashboard HTML auto-refrescable
- Webhooks: Slack, Discord, Microsoft Teams con payloads nativos
- Bot de Telegram con alertas por severidad, sesiones multi-usuario colaborativas
- Screenshot capture (EyeWitness-style), estadísticas de contraseñas (Pipal-style)

### 🐧 Análisis Profundo de Kernel (Fases 21-25)
- **Detección de lenguaje kernel** — reconocimiento automático de Linux/FreeBSD/OpenBSD por rutas (`arch/`, `drivers/`, `fs/`, `net/`)
- **Auditor de mitigaciones** — 15 checks (KASLR, SMAP, SMEP, KPTI, stack protector, FORTIFY_SOURCE, MM_MINIMAL, etc.) parseando `.config` real
- **Detector de versión** — parseo de `Makefile` y `UTS_RELEASE` para identificar versión exacta del kernel
- **Análisis estático con tree-sitter** — validación de C estructural + 8 checkers: `copy_from_user` sin size, `copy_to_user` sin zero-fill, `kmalloc` sin NULL check, doble fetch, ioctl handlers, procfs locking, stack buffers, null deref post-alloc
- **LLM especializado en kernel** — 4 clases expertas (kernel_memory, kernel_race, kernel_info_leak, kernel_priv_esc) con prompts de terminología real de kernel
- **Pipeline kernel-aware** — flag `enable_kernel_analysis` integrado en pipeline de escaneo; `run_kernel_mitigation_audit()` ejecutado automáticamente en targets kernel
- **Explotación de kernel** — `commit_creds` ROP, shellcode, modprobe_path, core_pattern; `ChainType::InfoLeakChain` / `PhysmapSpray` / `DirtyPipeStyle` / `BPFChain` para cadenas de explotación
- **122 tests en vulnscan** — cobertura completa de patrones kernel, mitigaciones y parseo

---

## 🛡️ Seguridad & Criptografía

| Componente | Algoritmo / Técnica |
|---|---|
| Cifrado simétrico | AES-256-GCM / XChaCha20Poly1305 (seleccionable en runtime) |
| Derivación de clave | Argon2id (OWASP 2024) + HKDF-SHA256 |
| Firma de auditoría | Ed25519 — blockchain firmado y encadenado |
| Redacción de secretos | 17 patrones canónicos + detección por entropía Shannon |
| Ceroización en memoria | `zeroize` en Drop para todo material sensible |
| Comparación constante | `subtle::ConstantTimeEq` — sin fugas por timing |
| Sandbox multinivel | Seccomp BPF + Landlock + namespaces + NSJail + rlimits |

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            kraken (CLI binario)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  tools(59)   commands(200+)   api(7 providers)   runtime(15 módulos)         │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
 │  │ vulnscan │ │  osint   │ │ security │ │ sandbox  │ │  localmodels     │  │
 │  │ (9 langs,│ │ (10 mod) │ │(crypto,  │ │(seccomp, │ │  (66 features,   │  │
 │  │ 4 IaC,   │ │ DNS/WEB  │ │ audit,   │ │ landlock,│ │   ML ensemble,   │  │
 │  │ secrets, │ │ social)  │ │ vault)   │ │ nsjail)  │ │   online learn)  │  │
 │  │ kernel)  │ │          │ │          │ │          │ │                  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│  20 fases ofensivas: password · sniffer · wireless · reverse · post-exploit │
│  C2 · forensics · social · cloud · hardware · mobile · supplychain         │
│  anonymity · stress · aicampaign · reporting                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 ML & Detección de Amenazas

| Componente | Descripción | Tiempo |
|---|---|---|
| Feature Extractor | 66 características por tool call | ~53 µs |
| Command Classifier | Regresión logística softmax (3 clases) | ~24 µs |
| Ensemble Scorer | Votación ponderada sobre 3 clasificadores | ~254 µs |
| Online Learner | SGD con WAL — aprende de decisiones del usuario | ~9 µs (deser) |
| Sequence Detector | Markov chain sobre transiciones de herramientas | ~327 µs |

---

## 📦 Estructura del Proyecto

```
kraken/
├── rust/
│   ├── Cargo.toml              # Workspace (35 crates)
│   ├── crates/
│   │   ├── rusty-claude-cli/   # CLI principal
│   │   ├── runtime/            # Core engine, permisos, MCP, self-healing
│   │   ├── tools/              # 59 herramientas del agente
│   │   ├── commands/           # 200+ comandos slash
│   │   ├── api/                # Clientes LLM (7 proveedores)
 │   │   ├── vulnscan/           # Escáner multi-lenguaje + IaC + secretos + kernel
│   │   ├── security/           # Criptografía, auditoría, bóveda
│   │   ├── sandbox/            # Seccomp, Landlock, namespaces, NSJail
│   │   ├── localmodels/        # ML: 66 features, clasificador, online learning
│   │   ├── osint/              # DNS, WHOIS, email, social, darkweb, dorking
│   │   ├── password/           # Hash cracker, online brute, wordlist, rainbow
│   │   ├── sniffer/            # Packet capture, ARP/DNS/DHCP spoof, MITM
│   │   ├── wireless/           # Wi-Fi audit, Bluetooth, deauth, evil twin
│   │   ├── reverse/            # ELF/PE/MachO parser, disasm, YARA, packers
│   │   ├── postexploit/        # PE, cred hunter, persistence, lateral, pivot
│   │   ├── c2/                 # Beacons HTTP/DNS/WS/SMB, sessions, tasks
│   │   ├── forensics/          # Disk imaging, carving, memory, registry
│   │   ├── socialeng/          # Phishing, proxy, USB drop, campaigns
│   │   ├── cloudsec/           # AWS, GCP, Azure, K8s, Docker audit
│   │   ├── hardware/           # Firmware, UART, JTAG, SDR, IoT fuzz
│   │   ├── mobile/             # APK, DEX, iOS IPA, Frida, MASVS
│   │   ├── supplychain/        # OSV, NVD, CIS, SBOM, SLSA, typosquat
│   │   ├── anonymity/          # Tor, SOCKS5, MAC, metadata scrub, OnionShare
│   │   ├── stress/             # SYN/UDP/HTTP flood, deauth, amplification
│   │   ├── aicampaign/         # Planner, coordinator, adaptive, learning
│   │   ├── reporting/          # PDF, dashboard, webhooks, Telegram, collab
│   │   ├── enterprise/         # Circuit breaker, health probes, tracing
│   │   ├── cache/              # LRU/LFU/FIFO + SQLite
│   │   ├── offline/            # Cola offline-first
│   │   ├── plugins/            # Lifecycle de plugins MCP
│   │   ├── telemetry/          # Telemetría estructurada
│   │   ├── compat-harness/     # Test de paridad con Anthropic
│   │   ├── mock-anthropic/     # Mock service E2E
│   │   ├── optimization/       # PSO, GA, ACO, Simulated Annealing
│   │   └── network/            # Soporte de red transversal
│   ├── tests/                  # Proptests (23 propiedades)
│   └── fuzz/                   # 4 targets de fuzzing
├── scripts/                    # Instaladores, CI, systemd, man page
├── completions/                # Zsh, Bash, Fish
└── docs/                       # Documentación
```

---

## 🏁 Inicio Rápido

```bash
# Instalar (binario, segundos)
curl -fsSL https://raw.githubusercontent.com/rooselvelt6/kraken/main/scripts/get-kraken.sh | sh

# Compilar desde fuente
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust && cargo build --release

# Usar
kraken                                          # REPL interactivo
kraken prompt "analiza este repositorio"        # Comando directo
kraken vulnscan --dir .                         # Escaneo rápido
kraken vulnscan --dir . --html reporte.html     # Reporte HTML
kraken osint --domain ejemplo.com --all         # OSINT completo
kraken campaign --target 10.0.0.0/24            # Campaña autónoma
```

### Instalación

| Método | Comando |
|--------|---------|
| Script | `curl -fsSL https://raw.githubusercontent.com/rooselvelt6/kraken/main/scripts/get-kraken.sh \| sh` |
| Homebrew | `brew install rooselvelt6/kraken/kraken` |
| Docker | `docker pull ghcr.io/rooselvelt6/kraken:latest` |
| GitHub Releases | Descargar binario firmado desde [Releases](https://github.com/rooselvelt6/kraken/releases) |
| Compilar | `git clone ... && cd kraken/rust && cargo build --release` |

### Verificar firma (Cosign / Sigstore)

```bash
# Instalar cosign
curl -LO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64 && sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# Verificar binario
cosign verify-blob kraken-linux-x86_64 \
  --bundle kraken-linux-x86_64.cosign.bundle \
  --certificate-identity=https://github.com/rooselvelt6/kraken/.github/workflows/release.yml@refs/tags/v* \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

---

## 📚 Documentación

- [PHILOSOPHY.md](PHILOSOPHY.md) — Filosofía del proyecto
- [CONTRIBUTING.md](CONTRIBUTING.md) — Guía de contribución
- [SECURITY.md](SECURITY.md) — Política de seguridad
- [CHANGELOG.md](CHANGELOG.md) — Historial de cambios
- [dashboard.html](dashboard.html) — Visor de reportes offline

---

<p align="center">
  🦀 <strong>Hecho en Rust, construido en Venezuela</strong> 🦀<br>
  <sub>210 000 líneas · 2 620 tests · 0 unsafe · 35 crates · Cosign firmado · CI/CD completo</sub>
</p>
