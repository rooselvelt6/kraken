# Plan Kraken — Pipeline Ofensivo

Este plan traduce las capacidades de kraken en fases concretas.

## Resumen de capacidades

| Capacidad kraken | Implementación |
|---|---|
| Agentic hacking (recon → descubrimiento → movimiento lateral → exploit) | Pipeline ofensivo multi-etapa autónomo |
| Memoria persistente (file-based notes) | Bug hunting con estado entre sesiones |
| Auto-validación y refinement de outputs | Findings que se auto-corrigen y re-rankear |
| Escaneo de codebases grandes con checkpointing | Chunking + paralelización + diferencial |
| Eficiencia de tokens (más capacidad por menos tokens) | Priorización inteligente de archivos/análisis |
| Cadenas de explotación multi-vulnerabilidad | Chaining avanzado con auto-descubrimiento de primitivas |

---

## Fase 1: Pipeline Ofensivo Multi-Etapa (Agentic Hacking)

**Objetivo**: Pipeline completo: recon → descubrimiento → movimiento lateral → exploit.

### 1.1 `recon.rs` — Módulo de Reconocimiento
- Enumeración de superficie de ataque: puertos, servicios, endpoints, APIs
- Fingerprinting de tecnologías (lenguajes, frameworks, versions)
- Mapeo de dependencias y relaciones entre módulos
- Entrada: Path/repo → Salida: `AttackSurface` struct con vectores

### 1.2 `lateral.rs` — Movimiento Lateral
- Análisis de relaciones entre vulnerabilidades en distintos módulos
- Identificación de rutas de pivote: vuln A → acceso a módulo B → vuln B
- Generación de grafo de ataque (attack graph)
- Entrada: `Vec<Finding>` → Salida: `Vec<AttackPath>`

### 1.3 `pipeline.rs` — Orchestrador Agentic
- Coordina recon → escaneo → chaining → lateral → exploit
- Estado persistente entre etapas (retoma desde checkpoint)
- Auto-priorización: si encuentra RCE en etapa 2, salta a explotación
- Modo "deep": si hay hallazgos críticos, profundiza con LLM

### 1.4 Integración CLI: `/hunt`
- Nuevo slash command: `/hunt [target] [--fast|--deep|--overnight]`
- Correlaciona resultados de todas las fases en un reporte unificado
- `--overnight`: ejecución larga con checkpointing y reanudación

---

## Fase 2: Memoria Persistente y Caza con Estado

**Objetivo**: Implementar memoria persistente para bug hunting.

### 2.1 `memory.rs` — Bug Hunter Memory
- Archivos de notas markdown en `.kraken/vulnscan/memory/`
- Hipótesis: "el módulo X podría tener race condition porque..."
- Findings parciales: "encontré un uso de unsafe en Y, sospecho use-after-free"
- Relaciones: "Z tiene patrón similar a W (CVE-2024-XXX)"
- Cache de análisis previos para evitar re-escanear

### 2.2 `hypothesis.rs` — Generación de Hipótesis
- Dado un conjunto de findings parciales, genera hipótesis de vulnerabilidades no descubiertas
- "Hay 3 llamadas a realloc sin NULL check → probablemente use-after-free"
- "Este endpoint no tiene CSRF token y el de al lado sí → probable bypass"
- Scoring de hipótesis por probabilidad e impacto

### 2.3 `resume.rs` — Checkpointing y Reanudación
- Guarda estado del escaneo cada N archivos
- Reanuda desde el último checkpoint si se interrumpe
- Reporte parcial: "Escaneo 40% completo — 15 hallazgos hasta ahora"

---

## Fase 3: Auto-Validación y Refinement

**Objetivo**: Findings auto-corregidos con validación cruzada.

### 3.1 `validator.rs` — Validación Cruzada
- Cada finding es verificado por al menos 2 métodos diferentes
- Ej: patrón estático encuentra X, LLM lo confirma, analyzer específico lo refina
- Score de confianza compuesto: `(confianza_método1 + confianza_método2) / 2`
- Findings con baja confianza (<0.4) se marcan como `NeedsReview`

### 3.2 `refiner.rs` — Auto-Refinement
- Toma findings existentes y los mejora:
  - Añade `vulnerable_code_snippet` si falta
  - Calcula CVSS más preciso
  - Genera `remediation` si no tiene
  - Encuentra CWE más específico
- Ejecutable como post-paso después de cualquier escaneo

### 3.3 `ranker.rs` — Re-Ranking Inteligente
- Re-ordena findings por: `(severidad * 0.4 + exploitabilidad * 0.3 + impacto_negocio * 0.2 + confianza * 0.1)`
- Prioriza hallazgos que son puerta de entrada a otros (pivoteables)
- Marca "low hanging fruit" para acción inmediata

---

## Fase 4: Escaneo de Grandes Codebases

**Objetivo**: kraken debe escalar a millones de líneas.

### 4.1 `chunker.rs` — Chunking Inteligente
- Divide codebase en segmentos por: directorio, módulo, límite de tamaño
- Preserva relaciones entre archivos (imports, cross-references)
- Metadata de chunk: archivos incluidos, LOC, lenguajes, dependencias

### 4.2 `parallel.rs` — Análisis Paralelo
- Procesa chunks en paralelo con Rayon/tokio
- Merge de resultados con deduplicación
- Límite configurable de concurrencia

### 4.3 `differential.rs` — Escaneo Diferencial
- Solo escanea archivos modificados desde último escaneo
- Mantiene base de hash de archivos (SHA-256)
- Ideal para CI/CD: `cargo kraken hunt --diff`

---

## Fase 5: Chaining Avanzado con Auto-Descubrimiento

**Objetivo**: kraken descubre cadenas de explotación automáticamente.

### 5.1 `primitive_discovery.rs` — Descubrimiento de Primitivas
- Clasifica findings en primitivas: lectura, escritura, ejecución, DoS
- Identifica relaciones: primitiva A + primitiva B → primitiva C
- Tabla de composición: `read + write = arbitrary_rw`, `uaf + spray = rce`

### 5.2 `chain_solver.rs` — Resolvedor de Cadenas
- Dado un conjunto de primitivas, encuentra la cadena más corta a RCE
- Algoritmo: BFS sobre grafo de primitivas
- Output: lista de pasos ordenados con código PoC para cada paso
- Scoring: `probabilidad_exito * impacto - complejidad`

### 5.3 `auto_exploit.rs` — Explotación Automática
- Genera PoC completo para la cadena encontrada
- Template-based: combina snippets de exploit.rs en secuencia
- Output: archivo `.exploit/chain-{id}.py` ejecutable

---

## Fase 6: Reportes Kraken-Grade

**Objetivo**: Reportes profesionales.

### 6.1 `report_kraken.rs` — Reporte Unificado
- HTML con gráficos de: severidad, CVSS, chains, timeline
- Sección de "ataque surface" (de Fase 1)
- Sección de "hipótesis activas" (de Fase 2)
- Sección de "cadenas de explotación" (de Fase 5)

### 6.2 `dashboard.rs` — Dashboard Persistente
- Servidor HTTP mínimo (activable con `--dashboard`)
- Muestra estado de escaneos activos y completados
- Actualización en tiempo real vía SSE

### 6.3 `timeline.rs` — Línea de Tiempo
- Registro cronológico de: findings descubiertos, hipótesis generadas, chains construidas
- Exportable a JSON para integración externa

---

## Prioridad de Implementación

| Fase | Prioridad | Dependencias | Esfuerzo |
|---|---|---|---|
| **Fase 1** (Pipeline Ofensivo) | 🔴 Alta | Ninguna | 3-4 días |
| **Fase 2** (Memoria Persistente) | 🔴 Alta | Ninguna | 2-3 días |
| **Fase 3** (Auto-Validación) | 🟡 Media | Fase 2 (opcional) | 2 días |
| **Fase 4** (Grandes Codebases) | 🟡 Media | Ninguna | 2-3 días |
| **Fase 5** (Chaining Avanzado) | 🟢 Baja | Fase 1 (primitivas) | 3-4 días |
| **Fase 6** (Reportes) | 🟢 Baja | Fases 1-5 | 2 días |

**Total estimado**: 14-20 días hábiles.

---

## Integración con Plan de Seguridad Ofensiva Existente

El código actual (`agent.rs`, `exploit.rs`, `chaining.rs`, `scan.rs`, `db.rs`, `report.rs`)
es la base sobre la que se construyen estas fases. No se reemplaza — se extiende.

| Módulo Existente | Nueva Fase | Relación |
|---|---|---|
| `agent.rs` (SecurityAgent) | Fase 1.3 pipeline.rs | Orchestrador invoca SecurityAgent |
| `exploit.rs` (generate_poc) | Fase 5.3 auto_exploit.rs | Template source para PoCs |
| `chaining.rs` (find_chains) | Fase 5.2 chain_solver.rs | BFS sobre primitivas de chaining.rs |
| `scan.rs` (VulnerabilityScanner) | Fase 4.1 chunker.rs | Scanner opera sobre chunks |
| `db.rs` (VulnDB) | Fase 2.1 memory.rs | DB existente + archivos markdown |
| `report.rs` (HTML) | Fase 6 | Reporte ampliado con nuevas secciones |
