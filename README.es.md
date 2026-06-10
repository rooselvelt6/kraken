# Kraken

<p align="center">
  <a href="https://github.com/rooselvelt6/kraken">
    <img src="https://img.shields.io/badge/Rust-100%25-b84100?style=for-the-badge&logo=rust" alt="Rust"/>
  </a>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT"/>
  <img src="https://img.shields.io/badge/status-production-green?style=for-the-badge" alt="Production"/>
</p>

<p align="center">
  <i>Agente de IA autónomo + escáner de vulnerabilidades + generador de exploits.</i><br>
  <b>100% Rust. Multi-proveedor. 0% Python. 0% USD requerido.</b>
</p>

---

## ¿Qué es Kraken?

Kraken es un **agente autónomo de IA para desarrollo y seguridad ofensiva** — un solo binario Rust que edita código, ejecuta comandos, escanea vulnerabilidades, genera exploits y coordina flujos multi-agente. Construido desde cero en Rust.

A diferencia de otras herramientas de IA, Kraken también funciona como un **escáner de vulnerabilidades completo**, con análisis estático en 9 lenguajes, cacería autónoma nocturna, encadenamiento de vulnerabilidades y generación de exploits.

---

## ¿Por qué Kraken?

| Otras herramientas | Kraken |
|---|---|
| Requieren USD, tarjeta de crédito o suscripción paga | **Proveedores gratis: DeepSeek (5M tokens/mes), Big Pickle (ilimitado), Ollama (local)** |
| Un solo proveedor LLM | **6+ proveedores: Anthropic, DeepSeek, xAI, OpenAI, DashScope, Ollama** |
| Python/TypeScript/Node | **Binario único ~150MB Rust. Sin dependencias de runtime.** |
| Sin análisis de seguridad | **Escáner AST de 9 lenguajes, generador de exploits, chaining** |
| Sin modo offline | **Cola SQLite con auto-sync** |
| Features enterprise como SaaS pago | **Circuit breaker, health checks, tracing, métricas — incluidas gratis** |

---

## Capacidades

### Agente de IA
- REPL interactivo y comandos directos
- 40+ herramientas (read, edit, write, grep, glob, bash, web fetch)
- 135+ comandos slash
- Orquestación multi-agente
- Manejo de sesiones con checkpoint/reanudación
- Soporte MCP
- Sistema de plugins

### Escáner de Vulnerabilidades
- **Análisis estático**: AST Tree-sitter para C, C++, Rust, Go, Java, JavaScript, Python, Ruby, Swift
- **Chequeos**: SQLi, XSS, CSRF, SSRF, XXE, inyección de comandos, crypto flaws, secretos hardcodeados, supply chain, bypass de auth, IDOR
- **Análisis con LLM**: Agente multi-proveedor con chunking, ranking de probabilidad, validación con CVSS

### Hacking Autónomo
- **Generación de exploits**: ROP chains, heap sprays, escalación de privilegios, shellcode
- **Chaining**: Solver BFS de grafo de primitivas — ruta más corta a RCE
- **Bughunting nocturno**: Pipeline autónomo completo: rankear → escanear → validar → explotar → reportar
- **Memoria persistente**: Hipótesis entre sesiones, checkpoint/reanudación automática
- **Mapeo de superficie**: Reconocimiento, movimiento lateral, detección de pivotes, grafos de ataque

### Features Enterprise (incluidas, gratis)
- Circuit breaker, exponential backoff con jitter
- Health checks, graceful degradation con fallback
- Métricas por proveedor (latencia, tokens, costos)
- Logging estructurado JSON, tracing distribuido
- Rate limiting, auditoría con hash chain

### Seguridad
- Cifrado AES-256-GCM y XChaCha20Poly1305
- Derivación de claves Argon2id (OWASP 2024)
- Zeroize, comparaciones en tiempo constante
- Cadena de auditoría SHA-256

### Proveedores Gratuitos
| Proveedor | Costo |
|---|---|
| DeepSeek (V3, R1, Coder) | 5M tokens gratis/mes |
| Big Pickle (OpenCode Zen) | Ilimitado gratis |
| Ollama (cualquier modelo local) | Gratis |
| LM Studio (modelos locales) | Gratis |

Sin tarjeta de crédito. Sin USD.

---

## Inicio Rápido

```bash
git clone https://github.com/rooselvelt6/kraken.git
cd kraken/rust

# Compilar
cargo build --release

# Usar con DeepSeek (gratis)
export DEEPSEEK_API_KEY="sk-..."
./target/release/kraken prompt "analiza este repositorio"

# O con Ollama (local, completamente gratis)
ollama pull qwen2.5-coder
./target/release/kraken --model ollama/qwen2.5-coder

# Escaneo de vulnerabilidades
./target/release/kraken --vulnscan ./src

# Cacería autónoma nocturna
./target/release/kraken --model deepseek-chat --vulnscan --overnight ./src
```

---

## Arquitectura (17 crates Rust)

```
┌─────────────────────────────────────────────────┐
│              kraken CLI (binario)                │
├─────────────────────────────────────────────────┤
│  commands  tools  plugins  telemetry             │
├─────────────────────────────────────────────────┤
│  api (multi-proveedor)  runtime (sesiones, MCP)  │
│  enterprise (retry, circuit breaker, tracing)    │
├─────────────────────────────────────────────────┤
│  vulnscan (escaner + exploit)  security (AES)    │
│  cache (mem+disco)  offline (SQLite)             │
│  localmodels (Ollama)  optimization (PSO, GA)    │
├─────────────────────────────────────────────────┤
│  sandbox  compat-harness  mock-anthropic         │
└─────────────────────────────────────────────────┘
```

~93,000 líneas de Rust, 1,100+ tests, 545+ commits.

---

## Requisitos

- **OS**: Linux, macOS, Windows (via WSL)
- **Rust**: 1.80+ (`rustup`)
- **RAM**: 512MB mínimo, 4GB+ recomendado

---

## Licencia

MIT

---

<p align="center">
  <b>100% Rust. 0% Python. Proveedores gratis. Sin USD.</b>
</p>
