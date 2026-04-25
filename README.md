# 🦀 Claw Code Venezuela - Agente de Código IA Enterprise

---

## 🇻🇪 Descripción

**Claw Code Venezuela** es un fork de nivel enterprise del agente de código Claw Code, optimizado para usuarios venezolanos y el mercado latinoamericano. Construido 100% en Rust para máximo rendimiento, seguridad y rentabilidad.

### ¿Por qué Venezuela?

- **Sin dependencia USD** - Modelos gratuitos sin tarjeta internacional
- **Optimizado para LATAM** - Modelos disponibles sin restricciones
- **Nivel enterprise** - Características de producción incluidas

---

## ✨ Características Principales

### Modelos Gratuitos (Sin API Key Requerida)

| Proveedor | Modelos | Tier Gratis |
|----------|-------|------------|
| **DeepSeek** | V3, R1, Coder | 5M tokens/mes |
| **Big Pickle** | OpenCode Zen | Ilimitado |
| **Ollama** | qwen2.5-coder, llama3.1 | Local (gratis) |

### Características Enterprise (Incluidas)

| Característica | Módulo | Descripción |
|---------------|--------|------------|
| **Retry con Backoff** | `enterprise/retry.rs` | Backoff exponencial + jitter |
| **Circuit Breaker** | `enterprise/circuit_breaker.rs` | Tolerancia a fallos |
| **Health Checks** | `enterprise/health.rs` | Monitoreo de salud |
| **Graceful Degradation** | `enterprise/graceful_degradation.rs` | Fallback automático |
| **Métricas** | `enterprise/metrics.rs` | Métricas por proveedor |
| **Logging Estructurado** | `enterprise/logging.rs` | Formato JSON |
| **Tracing Distribuido** | `enterprise/tracing.rs` | Correlación de requests |
| **Connection Pooling** | `enterprise/performance.rs` | Reuso de conexiones |
| **Timed Cache** | `enterprise/performance.rs` | Cache con TTL |
| **Auditoría Enterprise** | `enterprise/enterprise_features.rs` | Auditoría de acciones |
| **Rate Limiting** | `enterprise/enterprise_features.rs` | Límites por usuario |
| **Cifrado AES-GCM** | `security/crypto.rs` | Cifrado de config |
| **Audit Log Chain** | `security/audit.rs` | Integridad con hash |

### Algoritmos Bio-Inspirados (100% Rust)

```
rust/crates/optimization/
├── pso.rs    # Particle Swarm Optimization
├── ga.rs     # Genetic Algorithm
├── aco.rs    # Ant Colony Optimization
└── sa.rs     # Simulated Annealing
```

---

## 🧪 Pruebas y Calidad

```bash
# Ejecutar todas las pruebas
cd rust && cargo test --workspace

# Resultados actuales
test result: 27 passed (enterprise crate)
test result: 465+ passed (workspace total)
```

### Cobertura de Pruebas

| Crate | Pruebas | Estado |
|-------|--------|--------|
| enterprise | 27 | ✅ Passing |
| optimization | 12 | ✅ Passing |
| security | 6 | ✅ Passing |
| sandbox | 2 | ✅ Passing |
| api | 50+ | ✅ Passing |

---

## 🏗️ Arquitectura

```
claw-vzla/
├── rust/
│   ├── Cargo.toml              # Workspace (14 crates)
│   ├── crates/
│   │   ├── api/              # Proveedores (DeepSeek, Big Pickle, Ollama)
│   │   ├── commands/         # Comandos CLI
│   │   ├── compat-harness/  # Testing compatibility
│   │   ├── enterprise/      # Features enterprise (27 tests)
│   │   ├── mock-anthropic-service/ # Mock para testing
│   │   ├── optimization/    # Algoritmos bio-inspirados
│   │   ├── plugins/        # Lifecycle de plugins
│   │   ├── runtime/       # Core runtime (sesiones, MCP, permisos)
│   │   ├── rusty-claude-cli/ # CLI principal (~150MB)
│   │   ├── sandbox/       # Aislamiento de tools
│   │   ├── security/      # Cifrado + auditoría
│   │   ├── telemetry/     # Analytics
│   │   └── tools/        # Registro de tools
│   └── target/release/claw  # Binary único
├── docs/
│   └── GRATIS.md              # Guía de modelos gratuita
├── README.md
├── ROADMAP.md                # Roadmap original
├── ROADMAP-ENTERPRISE.md    # Roadmap enterprise
└── LICENSE
```

---

## 💻 Tecnologia y Stack

### Lenguaje

| Componente | Lenguaje | Porcentaje |
|-----------|----------|-----------|
| **Core CLI** | Rust | 100% |
| **Referencia upstream** | Python | <1% |
| **Total proyecto** | Rust | 99% |

### Dependencias Principales

| Crate | Version | Propósito |
|-------|---------|----------|
| tokio | 1.x | Async runtime |
| serde | 1.x | Serialización |
| reqwest | 0.12 | HTTP client |
| zeroize | 1.8 | Seguridad de memoria |
| aes-gcm | 0.10 | Cifrado |
| chrono | 0.4 | Fechas/tiempo |
| uuid | 1.x | Identificadores |
| tracing | 0.1 | Logging |

### Binary Final

| Métrica | Valor |
|--------|-------|
| **Tamaño** | ~150 MB |
| **Wrappers** | kraken, claw-vzla, claw-ve |
| **Tests** | 465+ |
| ** Crates workspace** | 14 |

---

## 🚀 Inicio Rápido

```bash
# Clonar
git clone https://github.com/rooselvelt6/claw-vzla.git
cd claw-vzla/rust

# Compilar
cargo build --release

# Ejecutar con DeepSeek (gratis)
DEEPSEEK_API_KEY=tu_key ./target/release/claw run "Hola"

# O con Ollama (local gratis)
./target/release/claw run "Hola" --model ollama/qwen2.5-coder
```

---

## 📈 Comparativa

| Característica | Claw Original | Venezuela Fork |
|---------------|--------------|---------------|
| **Proveedores** | Anthropic | DeepSeek + Big Pickle + Ollama |
| **Tier Gratis** | ❌ | ✅ 5M+ tokens |
| **Cifrado** | Básico | AES-GCM |
| **Auditoría** | ❌ | ✅ Hash chain |
| **Circuit Breaker** | ❌ | ✅ Incluido |
| **Rate Limiting** | ❌ | ✅ Por usuario |
| **Idioma** | EN | ES + EN |

---

## 📖 Documentación

- [ROADMAP.md](./ROADMAP.md) - Roadmap original
- [ROADMAP-ENTERPRISE.md](./ROADMAP-ENTERPRISE.md) - Features enterprise
- [docs/GRATIS.md](./docs/GRATIS.md) - Guía de modelos gratuitos

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

**Construido con ❤️ para Venezuela**  
100% Rust • Nivel Enterprise • Modelos Gratuitos