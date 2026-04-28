# 🦀 Claw Code Venezuela

<p align="center">
  <a href="https://github.com/rooselvelt6/claw-vzla">
    <img src="https://img.shields.io/badge/Rust-100%25-b84100?style=for-the-badge&logo=rust" alt="Rust"/>
  </a>
  <a href="https://github.com/rooselvelt6/claw-vzla/releases">
    <img src="https://img.shields.io/github/v/release/rooselvelt6/claw-vzla?include_prereleases&style=for-the-badge" alt="Release"/>
  </a>
</p>

---

## 🇻🇪 El Proyecto

**Claw Code Venezuela** es un fork de nivel enterprise del agente de código autónomo Claw Code, optimizado para usuarios venezolanos y el mercado latinoamericano. 100% Rust - 0% Python.

> *"Los humanos dan dirección; las claws ejecutan el trabajo."*

### Filosofía Unix/Linux

Inspirados en la tradición Unix: **"haz una cosa y hazla bien"**

| Principio | Implementación |
|----------|--------------|
| **Haz una cosa y hazla bien** | Cada componente tiene responsabilidad única |
| **Escribe programas que trabajen juntos** | Eventos tipados, APIs bien definidas |
| **Usa texto plano** | Configuración legible por humanos y máquinas |
| **Simplicidad sobre complejidad** | Rust por seguridad y rendimiento |
| **Portabilidad y acceso** | Sin dependencia USD, modelos gratuitos |
| **Recuperación antes que escalamiento** | Modos de falla auto-curables |
| **Código abierto** | Ingeniería reproducible |

---

## 🛡️ Seguridad Nivel Dios

El crate `security` implementa criptografía de grado militar/enterprise:

### Cifrado AEAD

| Algoritmo | Nonce | Uso | Rendimiento |
|----------|-------|-----|-----|
| **AES-256-GCM** | 12 bytes | Estándar | Rápido con AES-NI |
| **XChaCha20Poly1305** | 24 bytes | Alternativo | 3x más rápido sin AES-NI |

### Derivación de Claves

| Algoritmo | Estándar | Parámetros OWASP 2024 |
|----------|----------|---------------------|
| **Argon2id** | RFC 9106 | Interactive: 64MB, 4 iteraciones |
| **SHA256** | Legacy | Compatibilidad hacia atrás |

### Características de Seguridad

- ✅ **Zeroize** - Limpieza automática de memoria sensible
- ✅ **Algoritmo Agility** - Selección de cifrado en tiempo de ejecución
- ✅ **Constant-time comparisons** - Resistente a timing attacks
- ✅ **Audit Log Chain** - Integridad verificable con hash SHA-256
- ✅ **Parámetros OWASP 2024** - Cumplimiento de mejores prácticas

---

## ☁️ Módulos Venezuela

### Crates Nuevos

| Crate | Propósito | Features |
|-------|---------|----------|
| **localmodels** | Proveedores locales | Ollama, LM Studio, llama.cpp |
| **offline** | Sistema offline-first | SQLite, cola sync, recovery |
| **cache** | Cache multi-nivel | gzip, TTL, LRU, stats |

### Modo Offline-First

```rust
// Persistencia local SQLite
let manager = OfflineManager::new(data_dir)?;

// Guardar operación offline
manager.queue_operation(op).await?;

// Auto-sync cuando hay conexión
manager.update_connection_state().await;
```

### Cache Inteligente

```rust
// Cache con compresión gzip
cache.set("prompt-key", CacheType::Response, &response)?;

// Stats de hit rate
let stats = cache.stats();
// CacheStats { hits: 150, misses: 50, hit_rate: 75% }
```

### Proveedores Locales

```rust
// Auto-discovery de proveedores
let providers = discover_providers().await;
// [ProviderInfo { name: "ollama", available: true }, ...]
```

---

## ✨ Características Enterprise

### Features Incluidas (Sin Costo Extra)

| Módulo | Característica | Descripción |
|--------|---------------|-------------|
| `retry` | **Exponential Backoff** | Reintentos con jitter configurable |
| `circuit_breaker` | **Circuit Breaker** | Tolerancia a fallos upstream |
| `health` | **Health Checks** | Monitoreo de salud del sistema |
| `graceful_degradation` | **Fallback Automático** | Degradación elegante |
| `metrics` | **Métricas** | Métricas por proveedor |
| `logging` | **JSON Logging** | Formato estructurado |
| `tracing` | **Distributed Tracing** | Correlación de requests |
| `performance` | **Connection Pooling** | Reuso de conexiones HTTP |
| `performance` | **Timed Cache** | Cache con TTL |
| `enterprise_features` | **Auditoría** | Registro de acciones |
| `enterprise_features` | **Rate Limiting** | Límites por usuario |

---

## 🤖 Modelos Gratuitos (Sin USD)

| Proveedor | Modelos | Tokens Gratuitos |
|----------|--------|-----------------|
| **DeepSeek** | V3, R1, Coder | 5M/mes |
| **Big Pickle** | OpenCode Zen | Ilimitado |
| **Ollama** | qwen2.5-coder, llama3.1 | Local (gratis) |
| **LM Studio** | Modelos locales | Local (gratis) |

> Sin tarjeta de crédito internacional requerida

---

## 🧬 Algoritmos Bio-Inspirados (100% Rust)

```
rust/crates/optimization/
├── pso.rs    # Particle Swarm Optimization (PSO)
├── ga.rs     # Genetic Algorithm (GA)
├── aco.rs    # Ant Colony Optimization (ACO)
└── sa.rs     # Simulated Annealing (SA)
```

---

## 🏗️ Arquitectura

```
claw-vzla/
├── rust/
│   ├── Cargo.toml              # Workspace (17 crates)
│   ├── crates/
│   │   ├── api/              # Proveedores
│   │   ├── commands/         # Comandos CLI
│   │   ├── cache/            # Cache multi-nivel (NUEVO)
│   │   ├── compat-harness/
│   │   ├── enterprise/        # Features enterprise
│   │   ├── localmodels/      # Proveedores locales (NUEVO)
│   │   ├── mock-anthropic-service/
│   │   ├── offline/          # Sistema offline (NUEVO)
│   │   ├── optimization/     # PSO, GA, ACO, SA
│   │   ├── plugins/
│   │   ├── runtime/
│   │   ├── rusty-claude-cli/ # CLI (~150MB)
│   │   ├── sandbox/
│   │   ├── security/        # Cifrado nivel dios
│   │   ├── telemetry/
│   │   └── tools/
├── ROADMAP.md
├── ROADMAP-ENTERPRISE.md
├── ROADMAP-VENEZUELA.md     # Roadmap nuevos módulos
├── PHILOSOPHY.md
└── LICENSE
```

---

## 🧪 Pruebas

```bash
cd rust && cargo test --workspace
```

### Cobertura de Tests

| Crate | Tests | Estado |
|-------|------|--------|
| enterprise | 27 | ✅ Passing |
| optimization | 12 | ✅ Passing |
| security | 14 | ✅ Passing |
| sandbox | 2 | ✅ Passing |
| api | 50+ | ✅ Passing |

**Total: 465+ tests passing**

---

## 🚀 Inicio Rápido

```bash
# Clonar
git clone https://github.com/rooselvelt6/claw-vzla.git
cd claw-vzla/rust

# Compilar
cargo build --release

# Ejecutar (DeepSeek - gratis)
DEEPSEEK_API_KEY=tu_key ./target/release/claw run "Hola mundo"

# O con Ollama (local)
./target/release/claw run "Hola" --model ollama/qwen2.5-coder
```

---

## 📊 Comparativa

| Característica | Claw Original | Venezuela Fork |
|---------------|--------------|---------------|
| **Proveedores** | Anthropic | DeepSeek + Big Pickle + Ollama |
| **Tier Gratis** | ❌ | ✅ 5M+ tokens |
| **Cifrado** | AES-GCM básico | AES-256-GCM + XChaCha20Poly1305 |
| **KDF** | SHA256 | Argon2id (OWASP 2024) |
| **Audit Log** | ❌ | ✅ Hash chain |
| **Circuit Breaker** | ❌ | ✅ Incluido |
| **Offline Mode** | ❌ | ✅ SQLite + sync |
| **Cache** | ❌ | ✅ Multi-nivel gzip |
| **Zeroize** | ❌ | ✅ Memoria segura |
| **Python** | 30% | 0% |

---

## 🏆 Diferencial Venezuela

> *"En Venezuela, si algo funciona sin USD, sin tarjeta, y con buen rendimiento... **es tecnología de verdad.**"*

- ✅ **Sin dependencia USD**
- ✅ **Sin tarjeta de crédito internacional**
- ✅ **Mode Offline-first** - Funciona sin internet
- ✅ **Cache inteligente** - Reduce uso de API
- ✅ **Modelos locales** - Ollama, LM Studio
- ✅ **Cifrado nivel enterprise**
- ✅ **100% Rust - memoria segura**
- ✅ **0% Python**

---

## 📖 Documentación

- [PHILOSOPHY.md](./PHILOSOPHY.md) - Filosofía del proyecto
- [ROADMAP.md](./ROADMAP.md) - Roadmap original
- [ROADMAP-ENTERPRISE.md](./ROADMAP-ENTERPRISE.md) - Roadmap enterprise
- [ROADMAP-VENEZUELA.md](./ROADMAP-VENEZUELA.md) - Roadmap Venezuela
- [docs/GRATIS.md](./docs/GRATIS.md) - Guía modelos gratuitos

---

## 🤝 Contribuir

```bash
# Build y test
cd rust
cargo test --workspace
cargo fmt
cargo clippy --workspace -- -D warnings
```

---

## 📜 Licencia

MIT License - Ver [LICENSE](./LICENSE)

---

<p align="center">

**100% Rust • 0% Python • Offline-First • Sin USD**

Para Venezuela

</p>