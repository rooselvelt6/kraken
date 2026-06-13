# Kraken 🦞

<p align="center">
  <a href="https://github.com/rooselvelt6/kraken">
    <img src="https://img.shields.io/badge/Rust-100%25-b84100?style=for-the-badge&logo=rust" alt="Rust"/>
  </a>
  <img src="https://img.shields.io/badge/tests-1400%20pasaron-2ea44f?style=for-the-badge" alt="Tests"/>
  <img src="https://img.shields.io/badge/commits-960-0052cc?style=for-the-badge" alt="Commits"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT"/>
  <img src="https://img.shields.io/badge/status-production-green?style=for-the-badge" alt="Production"/>
</p>

<p align="center">
  <b>Agente de IA autónomo + escáner de vulnerabilidades + generador de exploits.</b><br>
  <b>100% Rust. 20+ crates. 110,000+ líneas. 1,400+ tests. Multi-provider. 0% Python. 0% USD.</b>
</p>

---

## 📋 Tabla de Contenidos

- [¿Qué es Kraken?](#-qué-es-kraken)
- [Capacidades](#-capacidades)
- [Escáner de Vulnerabilidades (vulnscan)](#-escáner-de-vulnerabilidades-vulnscan)
- [Pruebas](#-pruebas)
- [Proveedores LLM Gratuitos](#-proveedores-llm-gratuitos)
- [Roadmap](#-roadmap)
- [Inicio Rápido](#-inicio-rápido)
- [Arquitectura](#-arquitectura)
- [Requisitos](#-requisitos)

---

## 🦞 ¿Qué es Kraken?

Kraken es un **agente de IA autónomo para código con seguridad incorporada** — un solo binario de Rust que funciona como asistente de programación, escáner de vulnerabilidades, generador de exploits y orquestador multi-agente.

A diferencia de otras herramientas de IA, Kraken no requiere suscripciones de pago. Utiliza proveedores LLM gratuitos (DeepSeek, Big Pickle, Ollama) y ejecuta todo en un binario estático sin dependencias de runtime.

**¿Qué lo hace único?**

| Otras herramientas | Kraken |
|---|---|
| Requieren tarjeta de crédito o suscripción | **Proveedores gratuitos: DeepSeek (5M tokens/mes), Big Pickle (ilimitado), Ollama (local)** |
| Bloqueo a un solo proveedor LLM | **6+ proveedores: Anthropic, DeepSeek, xAI, OpenAI, DashScope, Ollama — enrutamiento automático** |
| Python/TypeScript/Node — dependencias pesadas | **Binario Rust único ~150MB. Sin runtime externo.** |
| Sin análisis de seguridad | **Escáner AST de 9 lenguajes, generador de exploits, encadenamiento de vulnerabilidades** |
| Sin modo offline | **Cola offline con SQLite y sincronización automática** |
| Funcionalidades enterprise como SaaS | **Circuit breaker, health checks, tracing, métricas — incluidas, gratuitas** |

---

## 🚀 Capacidades

### 🤖 Agente de Código IA

| Capacidad | Detalle |
|-----------|---------|
| **REPL interactivo** | Terminal interactiva con historial, autocompletado de tabs, 140+ comandos slash |
| **Prompts de un solo uso** | `kraken prompt "haz X"` para automatización |
| **44+ herramientas** | `read_file`, `write_file`, `edit_file`, `bash`, `grep`, `glob`, `WebSearch`, `WebFetch`, `Agent`, `TodoWrite`, `NotebookEdit`, `Skill`, `ToolSearch`, `PlanMigration`, `BatchEdit`, `VerifyMigration` y más |
| **140+ comandos slash** | `/help`, `/status`, `/compact`, `/model`, `/effort`, `/notes`, `/plan`, `/commit`, `/pr`, `/review`, `/team`, `/subagent`, `/doctor`, `/plugin`, `/mcp`, `/skills`, `/cron`, y más |
| **Memoria persistente** | `WriteNote` / `ReadNote` / `ListNotes` — notas guardadas en `.kraken/memory/` |
| **Auto-validación** | Modo high-effort que revisa y valida su propio trabajo antes de presentarlo |
| **Orquestación multi-agente** | Sub-agentes paralelos, equipos, delegación con contexto |
| **Visión / Imágenes** | Captura de pantalla (`/screenshot`) y lectura de imágenes (`/image`) |
| **Migraciones autónomas** | `PlanMigration` → `BatchEdit` → `VerifyMigration`: pipeline completo de refactors multi-archivo |
| **Sesiones** | Checkpoint, resume, compactación automática, exportación JSON |
| **MCP** | Model Context Protocol — servidores, herramientas, recursos |
| **Plugins** | Sistema de plugins instalables con ciclo de vida completo |
| **Modo offline** | Cola de operaciones SQLite con sincronización automática |
| **Control de esfuerzo** | `/effort low|medium|high` — controla la profundidad de razonamiento |

### 🔒 Seguridad y Criptografía

- Cifrado AES-256-GCM y XChaCha20Poly1305 (seleccionable en runtime)
- Derivación de claves con Argon2id (parámetros OWASP 2024)
- Zeroize en cada drop, comparaciones en tiempo constante
- Cadena de auditoría autenticada con SHA-256

### 🏢 Funcionalidades Enterprise (Incluidas, Gratis)

| Funcionalidad | Descripción |
|---|---|
| Circuit breaker | Tolerancia automática a fallos de upstream |
| Exponential backoff | Reintento con jitter y retrasos configurables |
| Health checks | Monitoreo de latencia y tasa de error por proveedor |
| Health probes | Heartbeats, latencia percentil (p50/p95/p99), estado Degraded/Unhealthy |
| Graceful degradation | Fallback por cadena de prioridad de proveedores |
| Concurrency management | Semáforos por tool (bash=5, read=20, write=3) con RAII |
| Rate limiting adaptativo | Token bucket con ajuste automático cada 30s (bonus/malus) |
| Métricas | Conteo de requests, latencia, uso de tokens, costo por proveedor |
| Logging estructurado | JSON con niveles de severidad |
| Distributed tracing | Correlación de spans entre requests |
| Auditoría | Cadena de hash inmutable para todas las acciones |
| SIEM export | ECS, Splunk HEC, OpenTelemetry, JSON plano |
| Sandbox (Seccomp + Landlock) | ~80 syscalls read-write, ~50 read-only, FS isolation vía Landlock |
| ML detection local | 66 features, logistic regression 3-class, ensemble scorer, online learning |
| Supply chain security | cargo-deny, cargo-audit, SBOM CycloneDX, fuzzing semanal, vendoring |
| Self-healing | Session checkpointing, health monitor, auto-restart con backoff, graceful shutdown |
| Adaptive Security Engine | Threat intel feeds, honeytokens, auto-threshold tuning, incident response, post-mortem, policy evolution, A/B testing |

### 🔧 Optimización

- Particle Swarm Optimization (PSO)
- Algoritmo Genético (GA)
- Optimización de Colonia de Hormigas (ACO)
- Recocido Simulado (SA)

---

## 🛡️ Escáner de Vulnerabilidades (vulnscan)

El crate `vulnscan` (~6,500 líneas, 38 archivos fuente) es la pieza central de seguridad de Kraken. Realiza análisis **multi-capa** combinando detección estática por patrones con análisis potenciado por LLM.

### Análisis Estático — 9 Lenguajes

| Lenguaje | Vulnerabilidades Detectadas |
|---|---|
| **C** | Buffer overflow (`strcpy`/`strcat`/`gets`), double-free, integer overflow en malloc |
| **C++** | Buffer overflow, unsafe casts (`reinterpret_cast`), type confusion |
| **Rust** | Bloques `unsafe`, transmute, aritmética de punteros |
| **Go** | Paquete `unsafe`, format string, command injection, SQLi |
| **Java** | Command injection (`Runtime.exec`), reflection, deserialization, SQLi, XSS |
| **JavaScript/TypeScript** | XSS (`innerHTML`/`outerHTML`), eval, SQLi, tipo `any`, non-null assertions |
| **Python** | SQLi, command injection, pickle deserialization, secrets hardcodeados |
| **Ruby** | Command injection, deserialization insegura (`Marshal`/`YAML`), XSS (`html_safe`) |
| **Swift** | Force unwrapping, WebView XSS, SQLi, expression injection |

### Cobertura de Clases de Vulnerabilidad

| Clase | CWEs | Fuente de Detección |
|---|---|---|
| SQL Injection | CWE-89 | Estático + LLM per-class |
| XSS (Cross-Site Scripting) | CWE-79 | Estático + LLM per-class |
| Command Injection | CWE-78 | Estático + LLM per-class |
| Buffer Overflow | CWE-120 | Estático + LLM per-class |
| Use-After-Free | CWE-416 | Estático + LLM per-class |
| Double-Free | CWE-415 | Estático + LLM per-class |
| Integer Overflow | CWE-190 | Estático + LLM per-class |
| Crypto Flaws | CWE-327, CWE-338 | Estático + LLM per-class |
| Auth Bypass | CWE-287, CWE-384 | Estático + LLM per-class |
| IDOR | CWE-639 | Estático + LLM per-class |
| CSRF | CWE-352 | Estático + LLM per-class |
| SSRF | CWE-918 | Estático + LLM per-class |
| Path Traversal | CWE-22 | Estático |
| XXE | CWE-611 | Estático |
| Open Redirect | CWE-601 | Estático |
| Hardcoded Secrets | CWE-798 | Estático |
| Supply Chain | CWE-1104 | Estático |
| Race Conditions | — | Hypothesis generation |
| Memory Corruption | — | Hypothesis generation |

### Pipeline de Cacería (Hunt Pipeline)

```
┌─────────┐   ┌──────────┐   ┌─────────┐   ┌──────────┐   ┌─────────┐
│ Recon   │ → │ Discover │ → │ Chain   │ → │ Exploit  │ → │ Report  │
└─────────┘   └──────────┘   └─────────┘   └──────────┘   └─────────┘
     │              │              │              │             │
     ▼              ▼              ▼              ▼             ▼
 surface      findings      attack paths    PoC code      HTML/JSON
 mapping      + CVSS        + BFS graph     + chain       con gráficas
```

### Modos de Escaneo

| Modo | Descripción | Caso de Uso |
|---|---|---|
| `--vulnscan --fast` | Escaneo basado en patrones Regex | CI rápido |
| `--vulnscan --deep` | Patrones + Análisis LLM con cross-validation | Auditoría completa |
| `--vulnscan --overnight` | Pipeline autónomo completo: rank → scan → validate → exploit → report | Cacería profunda |

### Análisis LLM por Clase de Vulnerabilidad (Fase 6)

Kraken utiliza **7 system prompts especializados** para el análisis LLM, uno por cada clase de vulnerabilidad:

| Clase | Prompt Especializado |
|---|---|
| **SQLi** | Experto en inyección SQL: concatenación raw, ORM mal usado, procedimientos almacenados |
| **XSS** | Experto en Cross-Site Scripting: DOM XSS, React dangerouslySetInnerHTML, template injection |
| **Command Injection** | Experto en inyección de comandos: system/exec/popen, shell escaping |
| **Crypto** | Experto en criptografía: algoritmos débiles, ECB, hardcoded keys, derivación débil |
| **Memory Safety** | Experto en seguridad de memoria: buffer overflow, UAF, double-free, unsafe Rust |
| **Logic Flaws** | Experto en fallos de lógica: IDOR, race conditions, TOCTOU, validación de input |
| **Auth Bypass** | Experto en autenticación: JWT flaws, session fixation, OAuth misconfiguration |

El análisis LLM **cross-valida** los hallazgos del escáner estático, ajusta puntuaciones CVSS, detecta falsos positivos y genera resúmenes explotables.

### Encadenamiento de Vulnerabilidades (BFS)

Kraken construye un **grafo de ataque** donde cada hallazgo es un nodo y las relaciones de explotabilidad son aristas. Luego ejecuta BFS (Breadth-First Search) para encontrar:

- **Ruta más corta** desde primitivas de entrada hasta RCE
- **Rutas alternativas** con mayor probabilidad de éxito
- **Nodos huérfanos** (hallazgos sin conexión a la cadena principal)

### Generación de Exploits

- **Generación por LLM**: Para hallazgos validados, el LLM genera PoC code funcional con lenguaje, tipo de exploit y prerrequisitos
- **Generación por template**: ROP chains, heap sprays, shellcode, escalación de privilegios
- **Reporte de bug hunt**: Resumen ejecutivo generado por LLM con riesgos clave, prioridad de correcciones y cadenas de ataque

---

## 🧪 Pruebas

Kraken cuenta con **1,400+ tests**. Distribución por crate:

| Crate | Tests |
|---|---|
| `runtime` | ~690 tests (sesiones, config, prompts, **heuristic_engine 89, circuit_breaker, health_probe, rate_limiter, concurrency, sanitizer, path_traversal, fingerprint, size_budget, audit_integration, forensic, siem_export, self_healing 21, recovery_recipes, worker_boot**) |
| `tools` | ~95 tests (herramientas, skills, agentes) |
| `commands` | ~40 tests (parseo de comandos slash, ayuda) |
| `vulnscan` | ~30 tests (analizadores, pipeline, LLM analyst, BFS, exploits) |
| `osint` | **66 tests** (DNS, email, social, personas, infra, reportes) |
| `sandbox` | **51 tests** (seccomp, landlock, namespace, tmpfs, rlimit, NSJail, macOS, Windows) |
| `security` | **46 tests** (cifrado, derivación de claves, Ed25519 audit, SIEM export) |
| `localmodels` | **66 tests** (features, classifier, model, ensemble, sequence, online_learning) |
| `cache` | ~45 tests (LRU, LFU, FIFO, TTL, zlib) |
| `api` | Tests de serialización, streaming, proveedores |
| `enterprise` | Tests de circuit breaker, retry, health checks |
| `compat-harness` | Tests de paridad con Anthropic |
| `mock-anthropic-service` | Tests del mock determinista |
| Otros | Tests de plugins, offline, optimización, etc. |

Para ejecutar las pruebas:

```bash
cd rust
cargo test --workspace          # Todas las pruebas (~1,400)
cargo test -p runtime           # Runtime + seguridad (~690)
cargo test -p sandbox           # Sandbox isolation (51)
cargo test -p localmodels       # ML detection (66)
cargo test -p security          # Crypto + audit (46)
cargo test -p vulnscan          # Escáner de vulnerabilidades
cargo test -p tools             # Solo herramientas
cargo test -p osint             # Solo OSINT
```

---

## 🕵️ OSINT Framework

El crate `osint` (~3,800 líneas, 8 módulos) es el motor de inteligencia de fuentes abiertas de Kraken. Proporciona capacidades de recolección, análisis y correlación de información pública.

| Módulo | Propósito | Métodos Clave |
|--------|-----------|---------------|
| **`collector`** | Extracción de datos de texto | Emails, URLs, IPs, teléfonos, mailto |
| **`dns`** | Resolución DNS y WHOIS | A, AAAA, MX, TXT, NS, SOA, CNAME, whois |
| **`search`** | Búsqueda en motores y dorking | Google Dork (20+ dorks), Bing, ranking |
| **`email`** | Enriquecimiento de emails | Validación MX, detección de proveedor, HIBP API v3 |
| **`social`** | OSINT en redes sociales | 70+ plataformas, `SocialSearcher`, `ProfileExtractor` |
| **`person`** | OSINT de personas | `NameParser`, `PhoneOSINT` (100+ países), `PersonSearcher`, `IdentityCorrelator` |
| **`infra`** | OSINT de infraestructura | `PortScanner`, `CertTransparency` (crt.sh), `ASNLookup`, `TechFingerprinter`, `IPEnricher` (Shodan, ipinfo, rDNS) |
| **`report`** | Generación de reportes | JSON, HTML (dark-mode), Markdown, CSV, Text |

```rust
use osint::{analyze_ip, analyze_domain, infra::*, person::*, social::*, email::*};

let findings = analyze_ip("8.8.8.8");                    // rDNS + ipinfo + Shodan + ASN
let findings = analyze_domain("example.com");            // crt.sh + SSL + IP + rDNS
let profiles = SocialSearcher::search_username("jdoe", &Platform::all()); // 70+ plataformas
let breaches = EmailEnricher::check_breaches("u@e.com"); // HIBP API v3
let phone = PhoneOSINT::validate("+584121234567");       // 100+ países + carrier
let report = ReportGenerator::to_html(&report);          // HTML dark-mode
```

---

## 💰 Proveedores LLM Gratuitos

| Proveedor | Modelos | Costo |
|---|---|---|
| **DeepSeek** | V3, R1, Coder | 5M tokens gratis/mes |
| **Big Pickle** | OpenCode Zen (GLM-4.6) | Ilimitado gratis |
| **Ollama** | Cualquier modelo local (qwen2.5-coder, llama3.2, deepseek-coder, etc.) | Gratis (local) |
| **LM Studio** | Cualquier modelo local | Gratis (local) |
| **Anthropic** | Claude Opus 4.6, Sonnet 4.6, Haiku | Plan gratuito limitado |
| **xAI** | Grok | Plan gratuito limitado |
| **OpenAI** | GPT-4o, o4-mini | Plan gratuito limitado |
| **DashScope** | Modelos Qwen | Plan gratuito limitado |

**No se requiere tarjeta de crédito. 0 USD necesarios.**

---

## 🗺️ Roadmap 2027 — Kraken Hardened

**Defense-in-Depth Enterprise Edition.** Convertir Kraken en un sistema inmune: detecta, contiene, recupera y aprende automáticamente.

| Fase | Capacidad | Área | KPI |
|------|-----------|------|-----|
| 1 ✅ | Fortaleza Criptográfica y Zero Trust Secrets | Seguridad | 0 secretos en texto plano |
| 2 ✅ | Input Fortress: Validación + Fuzzing | Seguridad | 0 path traversal bypass |
| 3 ✅ | Heuristic Anomaly Engine (HAE) (55+ reglas) | ML/Heurísticas | >95% detección, <5% FP |
| 4 ✅ | Circuit Breakers + Rate Limiting Adaptativo | Robustez | 0 fallos en cascada |
| 5 ✅ | Audit Fort Knox: Inmutabilidad + Forensics (SIEM) | Seguridad | 100% tool calls auditadas |
| 6 ✅ | Sandbox Real (Seccomp + Landlock + NSJail) | Seguridad | 0 escapes de sandbox. 51 tests |
| 7 ✅ | ML Local para Detección de Amenazas (66 features) | ML | >90% recall en ataques. 66 tests |
| 8 ✅ | Supply Chain Fortress + SBOM (SLSA 3+) | Robustez | 0 advisories críticos. 5 fuzz targets |
| 9 ✅ | Self-Healing Immune System | Robustez | Recovery <1s. 21 tests |
| 10 ✅ | Adaptive Security Engine (Auto-Defensa con ML) | ML/Seguridad | FP <3%, mejora semanal |

**Tecnologías clave:** XChaCha20Poly1305 + Argon2id, TPM 2.0, Seccomp BPF, Landlock, NSJail, cgroup2, Logistic Regression 3-class, SGD online learning, cargo-deny, CycloneDX SBOM, chaosd/litmus, AlienVault OTX.

**Métricas globales:** MTBF, MTTR, latencia añadida <100ms, 0 pérdida de datos en fallos. 844+ tests en workspace. ~110,000 líneas de Rust.

Ver [`ROADMAP-2027.md`](ROADMAP-2027.md) para el detalle completo de las 10 fases con KPIs, penetration tests y arquitectura.

---

## ⚡ Inicio Rápido

```bash
# 1. Clonar y compilar
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust
cargo build --release

# 2. Configurar API key gratuita (DeepSeek = 5M tokens gratis/mes)
export DEEPSEEK_API_KEY="sk-..."

# 3. Ejecutar
./target/release/kraken prompt "analiza este repositorio"
```

### Con modelos locales (Ollama, completamente gratis)

```bash
ollama pull qwen2.5-coder
./target/release/kraken --model ollama/qwen2.5-coder
```

### Escaneo de vulnerabilidades

```bash
# Escaneo rápido
./target/release/kraken --vulnscan --fast ./src

# Auditoría profunda con análisis LLM
./target/release/kraken --vulnscan --deep ./src

# Cacería autónoma nocturna (scan → validate → exploit → report)
./target/release/kraken --model deepseek-chat --vulnscan --overnight ./src
```

### REPL interactivo

```bash
./target/release/kraken
kraken> /help
kraken> /effort high
kraken> dime qué vulnerabilidades hay en este código
```

---

## 🏗️ Arquitectura

**20+ crates**, **110,000+ líneas de Rust**, **180+ archivos fuente**.

```
┌─────────────────────────────────────────────────────────────────┐
│                    kraken CLI (binary)                           │
│              rusty-claude-cli (~13,600 líneas)                   │
├─────────────────────────────────────────────────────────────────┤
│  commands (140+ cmds)    tools (44+ tools)    plugins   telemetry│
├─────────────────────────────────────────────────────────────────┤
│  api (6+ providers)   runtime (sesiones, MCP, permisos, prompts) │
│  enterprise (circuit breaker, retry, health checks, tracing)     │
├─────────────────────────────────────────────────────────────────┤
│  🛡️ SECURITY HARDENING LAYER (Fases 1-10)                      │
│  ├── heuristic_engine (55+ reglas, behavioral profiles)          │
│  ├── path_traversal (20+ técnicas de bypass)                    │
│  ├── sanitizer (7-stage pipeline)                               │
│  ├── fingerprint (tool call fingerprinting)                     │
│  ├── size_budget (límites por tool/sesión)                      │
│  ├── circuit_breaker (árbol jerárquico por provider/tool)       │
│  ├── health_probe (latencia percentil, heartbeat)               │
│  ├── rate_limiter (token bucket adaptativo)                     │
│  ├── concurrency (semáforos RAII por tool)                      │
│  ├── audit_integration + forensic + siem_export                 │
│      ├── self_healing (checkpointer, health monitor, restarter)     │
│  └── adaptive_engine (threat intel, honeytokens, auto-         │
│       threshold, incident response, post-mortem, A/B testing)   │
├─────────────────────────────────────────────────────────────────┤
│  vulnscan (~6,500 líneas, 38 archivos)     security (AES-256)   │
│    ├── Analizadores estáticos (9 lenguajes)                      │
│    ├── LLM Analyst (7 clases de vulnerabilidad)                  │
│    ├── Pipeline de cacería (Fast/Deep/Overnight)                 │
│    ├── BFS Attack Graph + Attack Paths                          │
│    ├── Exploit Generator + Chaining                             │
│    └── Reportes (CLI, JSON, HTML)                               │
├─────────────────────────────────────────────────────────────────┤
│  osint (~3,800 líneas, 8 módulos)                               │
│    ├── dns / email / search — recolección                        │
│    ├── social / person — identidades                             │
│    ├── infra — infraestructura (Shodan, crt.sh, ASN)             │
│    └── report — 5 formatos de salida                             │
├─────────────────────────────────────────────────────────────────┤
│  cache (mem+SQLite, LRU/LFU/FIFO/TTL)     offline (SQLite sync) │
│  localmodels (66 features, classifier 3-class, ensemble scorer, │
│               online learning SGD, sequence detector, WAL)       │
│  optimization (PSO, GA, ACO, SA)                                │
├─────────────────────────────────────────────────────────────────┤
│  sandbox (seccomp BPF, landlock, namespace, tmpfs, NSJail,      │
│           rlimit)  compat-harness   mock-anthropic               │
└─────────────────────────────────────────────────────────────────┘
```

### Detalle de Crates

| Crate | Propósito | Líneas |
|---|---|---|---|---|
| `rusty-claude-cli` | Binario principal — REPL, CLI, parser de args | ~13,600 |
| `tools` | 44+ herramientas del agente (read, write, edit, bash, search, plan, etc.) | ~10,000 |
| `vulnscan` | Escáner 9 lenguajes, LLM analyst, BFS, exploits, reportes | ~6,500 |
| `runtime` | Sesiones, config, permisos, MCP, prompts, workers, **heuristic_engine, circuit_breaker, health_probe, rate_limiter, concurrency, sanitizer, path_traversal, fingerprint, size_budget, audit_integration, forensic, siem_export, self_healing, adaptive_engine, worker_boot, recovery_recipes** | ~22,000+ |
| `api` | Clientes multi-provider (Anthropic, OpenAI, DeepSeek, xAI, Ollama) | ~3,500 |
| `commands` | 140+ comandos slash, parseo, ayuda | ~5,900 |
| `osint` | OSINT: DNS, email, social, personas, infra, reportes | ~3,800 |
| `enterprise` | Circuit breaker, retry, health checks, métricas, tracing | ~1,800 |
| `optimization` | PSO, GA, ACO, Simulated Annealing | ~1,500 |
| `localmodels` | Feature extraction (66), classifier 3-class softmax, ensemble scorer, online learning SGD, sequence detector, ModelStorage JSON | ~2,500+ |
| `sandbox` | Seccomp BPF, Landlock, namespace, tmpfs, rlimit, NSJail, macOS Seatbelt, Windows JobObject | ~4,000+ |
| `cache` | Caché multi-nivel (mem+SQLite), LRU/LFU/FIFO/TTL, zlib | ~1,200 |
| `security` | AES-256-GCM, XChaCha20Poly1305, Argon2id, zeroize, Ed25519 audit signing | ~1,500+ |
| `compat-harness` | Tests de paridad de comportamiento | ~1,000 |
| `offline` | Cola SQLite con auto-sync | ~800 |
| `plugins` | Ciclo de vida de plugins/MCP | ~600 |
| `telemetry` | Logging estructurado y telemetría | ~400 |
| `mock-anthropic-service` | Mock determinista Anthropic para tests | ~300 |

---

## 📋 Requisitos

- **SO**: Linux, macOS, Windows (vía WSL)
- **Rust**: 1.80+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Disco**: ~2GB para artefactos de compilación
- **RAM**: 512MB mínimo, 4GB+ recomendado
- **Internet**: Requerido para proveedores LLM remotos (modo offline disponible para modelos locales)

---

## 📄 Licencia

MIT — uso libre, modificación y distribución.

---

<p align="center">
  <b>100% Rust. 0% Python. 0% USD. Proveedores gratuitos. Sin bloqueo.</b><br>
  <sub>20+ crates · 110,000+ líneas · 1,400+ tests · 960+ commits · 35 user stories completadas · 10/10 fases de hardening ✅</sub>
</p>
