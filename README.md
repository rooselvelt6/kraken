# 🐙 Kraken

<p align="center">
  <strong>Agente de código autónomo · Escáner de vulnerabilidades · Generador de exploits · OSINT · Seguridad ofensiva</strong>
  <br>
  <em>100% Rust · 18 crates · 110 000+ líneas · 1500+ tests · 44 herramientas</em>
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

## Tabla de Contenidos

- [¿Qué es Kraken?](#qué-es-kraken)
- [Arquitectura](#arquitectura)
- [Seguridad & Criptografía](#seguridad--criptografía)
- [Sandbox](#sandbox)
- [ML & Detección de Amenazas](#ml--detección-de-amenazas)
- [OSINT](#osint)
- [Inicio Rápido](#inicio-rápido)
- [Comandos](#comandos)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Licencia](#licencia)

---

## ¿Qué es Kraken?

Kraken es un **agente de código autónomo** con capacidades de **seguridad ofensiva**: escáner de vulnerabilidades multi-lenguaje, generación de exploits, detección de secretos con entropía Shannon, análisis OSINT, sandbox con Seccomp + Landlock, y un sistema de permisos granular.

Está construido completamente en Rust con `unsafe` prohibido a nivel workspace, pesa ~40 MB en release, y funciona con proveedores LLM gratuitos (DeepSeek, Big Pickle, Ollama).

| Estadística | Valor |
|---|---|
| Crates en workspace | 18 |
| Líneas de código | ~110 000 |
| Tests unitarios | 1500+ |
| Tests de propiedad (proptest) | 23 |
| Herramientas (tools) | 44+ |
| Comandos slash | 140+ |
| Analizadores IaC | 4 (Docker, K8s, Terraform, CloudFormation) |
| Lenguajes analizados | 9 + 3 IaC |
| Patrones de secretos | 17 canónicos + entropía |
| Benchmarks | 5 (Criterion) |
| Fuzz targets | 4 (cargo-fuzz) |

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────────┐
│                        rusty-claude-cli                              │
│                    (CLI binario: kraken)                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │   tools     │  │ commands │  │   api    │  │  compat-harness   │  │
│  │(44+ tools)  │  │(140+ /cmds)│ │(LLM clients)│ (parity testing) │  │
│  └──────┬──────┘  └────┬─────┘  └────┬─────┘  └──────────────────┘  │
│         │              │              │                              │
│  ┌──────┴──────────────┴──────────────┴──────────────────────────┐  │
│  │                         runtime                                │  │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌──────────────────┐   │  │
│  │  │permisos │ │sanitizer │ │fingerprint││path_traversal    │   │  │
│  │  │enforcer │ │(7 stages)│ │(SHA-256) ││(7 detecciones)   │   │  │
│  │  └─────────┘ └──────────┘ └─────────┘ └──────────────────┘   │  │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌──────────────────┐   │  │
│  │  │circuit  │ │rate      │ │health   │ │adaptive_engine   │   │  │
│  │  │breaker  │ │limiter   │ │probe    │ │(honeytoken, ML)  │   │  │
│  │  └─────────┘ └──────────┘ └─────────┘ └──────────────────┘   │  │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌──────────────────┐   │  │
│  │  │MCP      │ │audit     │ │SIEM     │ │self-healing      │   │  │
│  │  │client   │ │integration││export   │ │(6 recovery modes) │   │  │
│  │  └─────────┘ └──────────┘ └─────────┘ └──────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────────┐  │
│  │security  │ │ sandbox  │ │vulnscan  │ │localmodels           │  │
│  │(crypto,  │ │(seccomp, │ │(9 langs, │ │(66 features, ML,     │  │
│  │ audit,   │ │ landlock,│ │ 4 IaC,   │ │ online learning,     │  │
│  │vault)    │ │ nsjail)  │ │ secrets) │ │ ensemble, sequence)  │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────────┘  │
│                                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────────┐  │
│  │enterprise│ │   osint  │ │  cache   │ │    offline · plugins │  │
│  │(HA,      │ │(DNS,     │ │(LRU/FIFO │ │    telemetry ·       │  │
│  │tracing)  │ │WHOIS,    │ │ + SQLite)│ │    optimization(PSO) │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

---

## Seguridad & Criptografía

## Seguridad & Criptografía

| Componente | Algoritmo / Técnica |
|---|---|
| Cifrado simétrico | AES-256-GCM (modo seguro) / XChaCha20Poly1305 (modo rápido) — seleccionable en runtime |
| Derivación de clave | Argon2id (OWASP 2024 — m=46MB, t=1, p=1) + HKDF-SHA256 |
| Firma de auditoría | Ed25519 — encadenamiento de bloques firmados, verificación en cadena |
| Redacción de secretos | 17 patrones canónicos (API keys, tokens JWT, AWS, GitHub, Stripe, SSH, etc.) |
| Ceroización | `zeroize` en Drop para todo material sensible |
| Comparación constante | `subtle::ConstantTimeEq` — sin fugas por timing |
| Bóveda de credenciales | `CredentialVault` con apertura por `MasterKey`, cifrado autenticado |
| Seguridad en memoria | `mlock`/`mprotect` en Unix, `VirtualLock` en Windows |
| Configuración segura | `SecureConfig` con parseo hardening |

---

## Sandbox

Kraken ejecuta herramientas en un sandbox multinivel:

| Capa | Tecnología | Alcance |
|------|-----------|---------|
| Seccomp BPF | Filtro de syscalls (80+ read-write, 50+ read-only) | Linux |
| Landlock | Aislamiento de jerarquía de archivos | Linux 5.13+ |
| Namespaces | PID, mount, network, UTS, IPC | Linux |
| tmpfs | Sistema de archivos efímero | Linux |
| rlimits | Límites de recursos (CPU, memoria, procesos, archivos) | Linux |
| NSJail | Contenedor de servicio pesado | Linux (opt-in) |
| Seatbelt | Perfil de sandbox macOS | macOS |
| JobObject | Límites de proceso Windows | Windows |

---

## ML & Detección de Amenazas

El crate `localmodels` implementa detección estadística de amenazas en runtime:

| Componente | Descripción |
|---|---|
| **Feature Extractor** | 66 características por tool call — longitud, entropía, tipos de carácter, profundidad de path, flags de bash, etc. |
| **Command Classifier** | Regresión logística softmax multiclase (3 clases: safe/suspicious/malicious) |
| **Ensemble Scorer** | Votación ponderada sobre 3 clasificadores independientes |
| **Online Learner** | SGD con WAL (Write-Ahead Log) — aprende de decisiones del usuario en tiempo real |
| **Sequence Detector** | Detección de anomalías secuenciales — markov chain sobre transiciones de herramientas |
| **Benchmarks** | 5 benchmarks Criterion: extracción (~53 µs), inferencia (~24 µs), ensemble (~255 µs), secuencia (~328 µs), deserialización (~9 µs) |

---

## OSINT

Kraken incluye un framework OSINT completo integrado como tool:

| Módulo | Capacidades |
|---|---|
| **DNS** | Resolución A/AAAA/MX/TXT/NS/SOA/CNAME (hickory-resolver) |
| **WHOIS** | Consulta WHOIS con parseo de registros |
| **Email** | Verificación HIBP v3 (brechas conocidas) |
| **Infraestructura** | ASN, rDNS, Shodan, crt.sh, Censys, ThreatFox |
| **Puertos** | TCP connect scan con detección de servicios |
| **Social** | 75+ plataformas, perfiles, búsqueda por username |
| **Persona** | Búsqueda por nombre/email/teléfono en 100+ países |
| **Darkweb** | Tor, onion sites, mercados |
| **Google Dorking** | 20+ dorks predefinidos con generación automática |

---

## Inicio Rápido

### Instalar (segundos)

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

### Compilar desde fuente

```bash
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust
cargo build --release
./target/release/kraken
```

### Primeros pasos

```bash
# Modo interactivo (REPL)
kraken

# Comando directo
kraken prompt "analiza este repositorio"

# Escaneo de vulnerabilidades
kraken vulnscan --dir .

# Verificar actualizaciones
kraken update
```

```bash
# Escaneo completo de un proyecto
kraken vulnscan --dir /ruta/al/proyecto

# Escaneo específico de IaC
kraken vulnscan --dir ./infra --docker --kubernetes --terraform

# Detección de secretos
kraken vulnscan --dir . --secrets

# Escaneo de imágenes de contenedor
kraken vulnscan --image alpine:latest

# Generar reporte HTML
kraken vulnscan --dir . --html reporte.html
```

### Pre-commit hook (detección de secretos)

```bash
bash scripts/install-pre-commit.sh
```

---

## Comandos

| Comando | Descripción |
|---------|-------------|
| `/bash` | Ejecutar comandos shell (sandboxeado) |
| `/read` | Leer archivos del workspace |
| `/write` | Escribir archivos |
| `/edit` | Editar archivos con diff estructural |
| `/glob` | Buscar archivos por patrón |
| `/grep` | Buscar contenido con regex |
| `/web_search` | Buscar en internet |
| `/web_fetch` | Obtener contenido de URL |
| `/agent` | Delegar tarea a subagente |
| `/task` | Crear y gestionar plan de tareas |
| `/vulnscan` | Escáner de vulnerabilidades |
| `/osint` | Framework OSINT |
| `/skill` | Cargar skill especializado |
| `/analyze` | Análisis de código con IA |

---

## Estructura del Proyecto

```
kraken/
├── rust/
│   ├── Cargo.toml              # Workspace root (18 crates, profile.release tuneado)
│   ├── crates/
│   │   ├── rusty-claude-cli/   # CLI principal (cargo run → kraken)
│   │   ├── runtime/            # Runtime core, permisos, sanitizer, fingerprint
│   │   ├── tools/              # 44+ herramientas del agente
│   │   ├── commands/           # 140+ comandos slash
│   │   ├── api/                # Clientes LLM (DeepSeek, Ollama, Anthropic...)
│   │   ├── vulnscan/           # Escáner multi-lenguaje + IaC + secretos
│   │   ├── security/           # Criptografía, auditoría, bóveda
│   │   ├── sandbox/            # Seccomp, Landlock, namespaces, NSJail
│   │   ├── localmodels/        # ML: 66 features, clasificador, entropía
│   │   ├── enterprise/         # Circuit breaker, health probes, tracing
│   │   ├── osint/              # DNS, WHOIS, email, infra, social, darkweb
│   │   ├── cache/              # LRU/LFU/FIFO + SQLite con TTL
│   │   ├── offline/            # Cola de operaciones offline-first
│   │   ├── plugins/            # Lifecycle de plugins MCP
│   │   ├── telemetry/          # Tipos de telemetría estructurada
│   │   ├── compat-harness/     # Test de paridad con Anthropic
│   │   ├── mock-anthropic/     # Mock service para tests E2E
│   │   └── optimization/       # PSO, GA, ACO, Simulated Annealing
│   ├── tests/                  # Proptests (sanitizer, path traversal, permisos, fingerprint)
│   └── fuzz/                   # Fuzzing (path traversal, bash, features, config)
├── scripts/
│   ├── chaos-test.sh          # Chaos testing para self-healing
│   ├── checksums.sh           # Generador de SHA256SUMS
│   ├── generate-sbom.sh       # Generación de SBOM CycloneDX
│   ├── get-kraken.sh          # Instalador universal (Linux/macOS/BSD/WSL)
│   ├── get-kraken.ps1         # Instalador Windows PowerShell
│   ├── install-pre-commit.sh  # Pre-commit hook de secret scanning
│   ├── kraken.1               # Página de manual (man)
│   ├── kraken.service         # Systemd service unit
│   └── vendor-deps.sh         # Vendorización offline
├── completions/
│   ├── _kraken                # Completado Zsh
│   ├── kraken.bash            # Completado Bash
│   └── kraken.fish            # Completado Fish
├── SUPPLY-CHAIN.md             # Política SLSA 3, cargo-deny, SBOM
├── Containerfile               # Docker build environment (multi-arch)
├── deny.toml                   # cargo-deny: licencias, fuentes, bans
└── install.sh                  # Instalador build-from-source
```

---

## Licencia

MIT © 2026 Kraken Contributors

---

<p align="center">
  <sub>Hecho en Rust, con ❤️ y paranoia.</sub>
  <br>
  <sub>~1500 tests · 0 unsafe · 40 MB binary · 22 horas de implementación roadmap</sub>
</p>
