# Kraken Philosophy

> **Build once, breach everywhere.** Una plataforma, cero `unsafe`, 200 capacidades.

---

## Core Principles

### 1. Seguridad por Construcción

Kraken prohibe **todo** código `unsafe` a nivel workspace. Las 210,000+ líneas de Rust están libres de vulnerabilidades de memoria por construcción — no por revisión, no por suerte, por decisión arquitectónica. El comprobador de *ownership* de Rust es nuestra primera línea de defensa.

### 2. Todo-en-Uno, no navaja suiza

Kraken no es un conjunto de scripts sueltos. Es una plataforma cohesiva de 35 crates donde cada componente conoce al otro. Un hallazgo de `vulnscan` alimenta al generador de exploits, que alimenta al framework C2, que reporta al dashboard. No hay silos.

### 3. Determinista por defecto, Aumentado por ML

El análisis estático (tree-sitter, patrones, AST) corre primero: es rápido, offline y no alucina. El LLM y el ML aumentan, no reemplazan. Cuando el estático dice "esto es vulnerable", el LLM explica *por qué*. Cuando el ML detecta una anomalía, el agente ajusta su estrategia.

### 4. Híbrido Estático + LLM

El análisis de kernel (Fases 21-25) es el ejemplo perfecto: tree-sitter valida que el C es sintácticamente correcto, los checkers de patrones detectan vulnerabilidades conocidas (sin falsos positivos), y el LLM especializado en kernel (DeepSeek) entiende el contexto semántico — APIs de kernel, estructuras internas, técnicas de explotación. Cada capa compensa las debilidades de la otra.

### 5. Offline-First

Todo el análisis estático, los patrones de kernel, la detección de secretos, el cracking de contraseñas y el escaneo de red funcionan sin conexión. El LLM es aumentativo, no dependencia crítica. Kraken no se detiene porque la API de turno esté caída.

### 6. Rapidez como Feature

Benchmarks Criterion: 24 µs de inferencia ML, 53 µs de extracción de features, 327 µs de detección de anomalías. Cada microsegundo cuenta cuando estás analizando 210,000 líneas de código. El perfil de release optimiza para tamaño (~9 MB binario estático) y velocidad.

### 7. Cero Fricción, Una Dependencia

Un solo binario estático. Sin runtime de Python, sin Node, sin JVM. `curl | sh` y listo. Las 59 herramientas del agente, los 200+ comandos slash, los 7 proveedores LLM — todo en un binario.

---

## Design Tenets

### Para el Código

| Principio | Aplicación |
|-----------|------------|
| `forbid(unsafe_code)` | Cada crate, cada archivo. No hay excepciones. |
| Sin macros procedurales | Compilación rápida, código explícito. |
| Tests en cada PR | 2,620 tests (y creciendo). `cargo test` debe pasar siempre. |
| Criterion para benchmarks | Cada optimización se mide, no se supone. |
| `clippy --pedantic` | Sin advertencias. El linter es ley. |

### Para la Arquitectura

| Principio | Aplicación |
|-----------|------------|
| Un crate por dominio | 35 crates, cada uno con una responsabilidad clara. |
| Dependencias mínimas | Cada dependencia se justifica. Sin bloat. |
| Fases ofensivas | 25 fases → 25 capacidades, de OSINT a kernel exploit. |
| Pipeline en 3 modos | Fast (estático), Deep (+LLM), Overnight (+exploit generation). |

### Para el Usuario

| Principio | Aplicación |
|-----------|------------|
| CLI primero | Todo comando tiene flag. Todo flag tiene `--help`. |
| JSON machine-readable | `--output-format json` para pipelines y automatización. |
| MCP nativo | Integración con cualquier editor/IDE que soporte MCP. |
| Sandbox por defecto | Seccomp + Landlock + namespaces. Aislado desde el primer segundo. |

---

## Technical Commitments

- **Rust edition 2021**, toolchain 1.85+
- **Zero `unsafe`** en todo el workspace
- **100% de tests pasando** antes de cada merge
- **Benchmarks Criterion** para decisiones de rendimiento
- **Documentación en código** (`///`) en toda API pública
- **Semver consciente**: cambios breaking sólo en major versions

---

## El panorama completo

Kraken no es una herramienta más. Es una plataforma que nació de una pregunta simple: *¿y si todo lo que necesitas para una operación ofensiva estuviera en un solo binario, escrito en Rust, sin `unsafe`, con ML integrado, que funciona offline, y que además entiende de kernel?*

La respuesta es Kraken. 35 crates. 210,000 líneas. 2,620 tests. 0 `unsafe`.
