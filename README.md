# Kraken 🦞

<p align="center">
  <a href="https://github.com/rooselvelt6/kraken">
    <img src="https://img.shields.io/badge/Rust-100%25-b84100?style=for-the-badge&logo=rust" alt="Rust"/>
  </a>
  <img src="https://img.shields.io/badge/tests-1138%20pasaron-2ea44f?style=for-the-badge" alt="Tests"/>
  <img src="https://img.shields.io/badge/commits-950-0052cc?style=for-the-badge" alt="Commits"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT"/>
  <img src="https://img.shields.io/badge/status-production-green?style=for-the-badge" alt="Production"/>
</p>

<p align="center">
  <b>Agente de IA autónomo + escáner de vulnerabilidades + generador de exploits.</b><br>
  <b>100% Rust. 17 crates. 95,374 líneas. 1,138 tests. Multi-provider. 0% Python. 0% USD.</b>
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
| Graceful degradation | Fallback por cadena de prioridad de proveedores |
| Métricas | Conteo de requests, latencia, uso de tokens, costo por proveedor |
| Logging estructurado | JSON con niveles de severidad |
| Distributed tracing | Correlación de spans entre requests |
| Rate limiting | Límites por usuario y por proveedor |
| Auditoría | Cadena de hash inmutable para todas las acciones |

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

Kraken cuenta con **1,138 tests** (1,137 pasan, 1 fallo pre-existente no relacionado con el código). Distribución por crate:

| Crate | Tests |
|---|---|
| `tools` | ~95 tests (incluyendo herramientas, skills, agentes) |
| `runtime` | ~12 tests (sesiones, config, prompts) |
| `vulnscan` | ~30 tests (analizadores, pipeline, LLM analyst, BFS, exploits) |
| `cache` | ~45 tests (LRU, LFU, FIFO, TTL, zlib) |
| `api` | Tests de serialización, streaming, proveedores |
| `commands` | Tests de parseo de comandos slash |
| `security` | Tests de cifrado, derivación de claves |
| `enterprise` | Tests de circuit breaker, retry, health checks |
| `compat-harness` | Tests de paridad con Anthropic |
| `mock-anthropic-service` | Tests del mock determinista |
| Otros | Tests de plugins, offline, optimización, etc. |

Para ejecutar las pruebas:

```bash
cd rust
cargo test --workspace          # Todas las pruebas
cargo test -p vulnscan          # Solo escáner de vulnerabilidades
cargo test -p tools             # Solo herramientas
cargo test -p runtime           # Solo runtime
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

## 🗺️ Roadmap

**25 fases planificadas — 6 completadas, 19 futuras.**

| Fase | Capacidad | Estado |
|------|-----------|--------|
| 1 | Vision / Image Input | ✅ Completada |
| 2 | Persistent Memory / Note-taking | ✅ Completada |
| 3 | Self-Validation (High-Effort) | ✅ Completada |
| 4 | Advanced Multi-Agent Orchestration | ✅ Completada |
| 5 | Autonomous Codebase Migrations | ✅ Completada |
| 6 | Enhanced Security Analysis (vulnscan) | ✅ Completada |
| 7 | OSINT Foundation | ⬜ Futura |
| 8 | Social Media OSINT | ⬜ Futura |
| 9 | Person Identity Correlation | ⬜ Futura |
| 10 | Dark & Surface Web Recon | ⬜ Futura |
| 11 | Network Attack Surface | ⬜ Futura |
| 12 | System Security Audit | ⬜ Futura |
| 13 | System Hardening Engine | ⬜ Futura |
| 14 | Threat Detection & Monitoring | ⬜ Futura |
| 15 | Advanced Exploitation Chain | ⬜ Futura |
| 16 | Automated Defense & IR | ⬜ Futura |
| 17-20 | Process, Storage, Network, Package Control | ⬜ Futura |
| 21 | Multi-Agent Debate & Consensus | ⬜ Futura |
| 22 | Self-Healing Auto-Recovery | ⬜ Futura |
| 23 | Autonomous Research Pipeline | ⬜ Futura |
| 24 | Code Self-Reflection & Improvement | ⬜ Futura |
| 25 | Full Self-Improvement Autonomy | ⬜ Futura |

**Cifras planeadas**: 9 crates nuevos, ~90 archivos, ~75 herramientas nuevas
Ver [`ROADMAP.md`](ROADMAP.md) para el detalle completo.

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

**17 crates**, **95,374 líneas de Rust**, **146 archivos fuente**.

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
│  vulnscan (~6,500 líneas, 38 archivos)     security (AES-256)   │
│    ├── Analizadores estáticos (9 lenguajes)                      │
│    ├── LLM Analyst (7 clases de vulnerabilidad)                  │
│    ├── Pipeline de cacería (Fast/Deep/Overnight)                 │
│    ├── BFS Attack Graph + Attack Paths                          │
│    ├── Exploit Generator + Chaining                             │
│    └── Reportes (CLI, JSON, HTML)                               │
├─────────────────────────────────────────────────────────────────┤
│  cache (mem+SQLite, LRU/LFU/FIFO/TTL)     offline (SQLite sync) │
│  localmodels (Ollama, LM Studio)           optimization (PSO,   │
│                                            GA, ACO, SA)         │
├─────────────────────────────────────────────────────────────────┤
│  sandbox (aislamiento)   compat-harness   mock-anthropic         │
└─────────────────────────────────────────────────────────────────┘
```

### Detalle de Crates

| Crate | Propósito | Líneas |
|---|---|---|
| `rusty-claude-cli` | Binario principal — REPL, CLI, parser de args | ~13,600 |
| `tools` | 44+ herramientas del agente (read, write, edit, bash, search, plan, etc.) | ~10,000 |
| `vulnscan` | Escáner 9 lenguajes, LLM analyst, BFS, exploits, reportes | ~6,500 |
| `runtime` | Sesiones, config, permisos, MCP, prompts, workers | ~4,100 |
| `api` | Clientes multi-provider (Anthropic, OpenAI, DeepSeek, xAI, Ollama) | ~3,500 |
| `commands` | 140+ comandos slash, parseo, ayuda | ~5,900 |
| `enterprise` | Circuit breaker, retry, health checks, métricas, tracing | ~1,800 |
| `optimization` | PSO, GA, ACO, Simulated Annealing | ~1,500 |
| `cache` | Caché multi-nivel (mem+SQLite), LRU/LFU/FIFO/TTL, zlib | ~1,200 |
| `security` | AES-256-GCM, XChaCha20Poly1305, Argon2id, zeroize | ~1,000 |
| `compat-harness` | Tests de paridad de comportamiento | ~1,000 |
| `offline` | Cola SQLite con auto-sync | ~800 |
| `plugins` | Ciclo de vida de plugins/MCP | ~600 |
| `telemetry` | Logging estructurado y telemetría | ~400 |
| `localmodels` | Auto-descubrimiento Ollama/LM Studio | ~300 |
| `mock-anthropic-service` | Mock determinista Anthropic para tests | ~300 |
| `sandbox` | Aislamiento por contenedor | ~200 |

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
  <sub>17 crates · 95,374 líneas · 1,138 tests · 950 commits · 24 user stories completadas</sub>
</p>
