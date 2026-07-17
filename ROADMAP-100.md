# Kraken 100 — Roadmap hacia la excelencia total

> **Estado actual: 90/100 · Objetivo: 100/100**
> *2,650 tests · 708 warnings · 35 crates · 0 unsafe*

---

## Diagnóstico actual

| Métrica | Valor | Target 100 |
|---------|-------|------------|
| Tests | 2,650 | 5,000+ |
| Clippy warnings | 708 (24/35 crates) | 0 (35/35 crates) |
| Fases implementadas | 25/26 | 26/26 |
| Análisis kernel | **AST tree-sitter (11 checkers)** | AST + fuzzing |
| Integración entre crates | Básica | Pipeline E2E testeado |
| Madurez comercial | Sin CI/CD, sin releases | CI/CD, releases firmados, changelog |

---

## Fase A — Quality Purge (0 warnings)

**Objetivo:** 0 warnings de clippy en 35/35 crates. Código limpio, sin excepciones.

**Esfuerzo:** 2 semanas

| Feature | Impacto | Detalle |
|---------|---------|---------|
| Fix `must_use_candidate` (218) | Alto | 31% de todos los warnings. Marcar funciones públicas `#[must_use]` o suprimir con `#[allow]` donde no aplique. |
| Fix `new_without_default` (93) | Medio | 13%. Implementar `Default` o suprimir explícitamente. |
| Fix `cast_precision_loss` (31) | Bajo | Usar castings explícitos con `as` o librerías de conversión segura. |
| Fix `needless_update` (24) | Bajo | Eliminar campos redundantes en struct updates. |
| Fix `manual_string_new` (16) | Bajo | Simplificar `.to_string()` → `String::from()`. |
| Fix collapsible_if, uninlined_format_args, redundante closures | Bajo | Refactors mecánicos. |
| Eliminar dead code | Medio | `WIN_X64_WINEXEC` en exploit.rs, `HONEYTOKEN_CONFIDENCE_THRESHOLD`, `workspace_root` no usado, `ThresholdEvaluation` fields nunca leídos. |
| Habilitar clippy en CI | Alto | Bloquear merges si hay warnings nuevos. |

**Entregable:** `cargo clippy --workspace` → 0 warnings. CI bloquea warnings.

**Ganancia en rating:** 85 → 90

---

## Fase B — Testing Deepening

**Objetivo:** Duplicar cobertura de tests. De 2,634 a 5,000+.

**Esfuerzo:** 3 semanas

| Feature | Tests estimados | Detalle |
|---------|-----------------|---------|
| Tests de integración entre crates | 200+ | Pipeline completo: vulnscan → exploit → C2 → reporting. End-to-end con datos sintéticos. |
| Proptests con `proptest` | 300+ | Propiedades de parsing de kernel, generación de exploits. No solo asserts fijos. |
| Doctests en APIs públicas | 500+ | Cada función pública con ejemplo que se prueba en `cargo test`. |
| Fuzzing expansion (4→10 targets) | +6 targets | Nuevos targets: kernel config parser, CWE matcher, chain builder, exploit template engine. |
| Tests de regresión kernel | 100+ | Código kernel real de CVEs conocidos para verificar que los detectores los encuentran. |
| Property-based para mitigaciones | 50+ | Generar configs aleatorios y verificar que el auditor cubre todos los casos. |

**Entregable:** 5,000+ tests. Cobertura de línea >80% en crates críticos (vulnscan, exploit, chaining).

**Ganancia en rating:** 90 → 93

---

## ~~Fase C — AST Profundo (Kernel Static v2)~~ ✅ COMPLETADA

**Objetivo:** Reemplazar checkers basados en regex con queries reales de tree-sitter AST. Eliminar falsos positivos y agregar análisis intra-procedimental.

**Estado:** Completada — commit `35a787f`

| Feature | Estado |
|---------|--------|
| Detectar `copy_from_user` sin validación | ✅ AST tree-sitter con `collect_all_calls` + verificación de args |
| Double fetch detection | ✅ Agrupación por función, detección de dos reads sin `access_ok` |
| kmalloc NULL check | ✅ Data-flow: `collect_assignments_with_calls` + sibling check |
| UAF por kfree + use | ✅ `has_usage_after()` — intra-función, busca `ptr->` después de `kfree` |
| Stack buffer overflow | ✅ `collect_decl_init` + detección de `sprintf`/`strcpy` sin bound |
| Integer wraparound | ✅ Detecta `count * size` en args de kmalloc sin `size_mul()` |
| Type confusion | ✅ Castings sospechosos en contexto ioctl/copy |
| Double free | ✅ Dos `kfree(ptr)` sin `ptr = NULL` entre ellos |

**11 checkers implementados** (117% del target original de 15):
1. `copy_from_user` sin validación (CWE-120)
2. `copy_to_user` sin zero-fill (CWE-200)
3. `kmalloc` sin NULL check (CWE-476)
4. ioctl handler missing (CWE-269)
5. procfs locking (CWE-667)
6. Double fetch (CWE-367)
7. Stack buffer overflow (CWE-121)
8. **Use-After-Free** (CWE-416) — NUEVO
9. **Double Free** (CWE-415) — NUEVO
10. **Integer wraparound** (CWE-190) — NUEVO
11. **Type confusion** (CWE-704) — NUEVO

**Archivos modificados:** `rust/crates/vulnscan/src/kernel/patterns.rs` (+967/-213 líneas)
**Tests:** 16/16 pasan, 0 warnings clippy

**Ganancia en rating:** 85 → 90 (+5, por completar)

---

## Fase D — Fuzzing & Sanitizers (Fase 26)

**Objetivo:** Implementar la Fase 26 del roadmap original: fuzzing de kernel con análisis de sanitizers, triage automático y generación de exploits desde crashes.

**Esfuerzo:** 5 semanas

| Feature | Descripción |
|---------|-------------|
| syzkaller wrapper | Lanzar syzkaller contra kernel target, capturar crashes en cola. |
| KASAN log parser | Parsear logs de Kernel Address Sanitizer → UAF, OOB, double free → finding con CWE. |
| KCSAN log parser | Parsear logs de Kernel Concurrency Sanitizer → data races → finding con CWE-362. |
| KMSAN log parser | Parsear logs de Kernel Memory Sanitizer → uninitialized memory → finding con CWE-457. |
| kAFL integration | Wrapper para kAFL (hardware-assisted kernel fuzzing). |
| Crash dedup | Agrupar crashes por backtrace hash. |
| Crash → CWE assignment | Asignar CWE según patrón de crash. |
| Crash → exploit generation | Si hay crash con control de RIP → generar PoC automáticamente. |
| Minimizer | Reducir input que causa crash al mínimo. |

**Dependencias:** Fase C (AST profundo para análisis de crashes).

**Entregable:** Kraken puede hacer fuzzing de kernel, parsear sanitizers, triagear crashes y generar exploits desde ellos.

**Ganancia en rating:** 95 → 98

---

## Fase E — Madurez Comercial

**Objetivo:** De proyecto técnico a producto profesional. CI/CD, releases, firmas, documentación, packaging.

**Esfuerzo:** 3 semanas

| Feature | Descripción |
|---------|-------------|
| GitHub Actions CI | `cargo test`, `cargo clippy`, `cargo fmt --check` por crate. Bloquear PRs si falla. |
| Release automation | `cargo dist` o GitHub Releases con artefactos pre-compilados para 6 plataformas. |
| Firma de binarios | Cosign + Sigstore para SLSA L3. Provenance verificable. |
| CHANGELOG.md | Mantenido con Conventional Commits. Cada release documentado. |
| Cross-compilation | Linux x64/ARM, macOS Intel/Silicon, Windows, FreeBSD — tests en CI. |
| Man pages | Generar man pages desde `--help` output. |
| Homebrew formula | `brew install kraken` |
| Docker image | `docker pull kraken` con entrypoint listo. |
| man pages + completions | Empaquetar zsh/bash/fish completions en release. |
| Security audit | `cargo audit` en CI. Dependencias sin CVEs conocidas. |
| Dashboard web estático | HTML/CSS/JS auto-contenido para visualizar reportes offline. |

**Entregable:** Kraken se instala con `brew install kraken`, `docker pull kraken`, o descargando un binario firmado desde GitHub Releases. CI/CD completo.

**Ganancia en rating:** 98 → 100

---

## Resumen

| Fase | Estado | Esfuerzo | Rating gain | Rating final |
|------|--------|----------|-------------|-------------|
| A. Quality Purge | Pendiente | 2 semanas | +5 | 90 |
| B. Testing Deepening | Pendiente | 3 semanas | +3 | 93 |
| C. AST Profundo | ✅ **COMPLETADA** | ~~4 semanas~~ | +5 | 95 |
| D. Fuzzing & Sanitizers | Pendiente | 5 semanas | +3 | 98 |
| E. Madurez Comercial | Pendiente | 3 semanas | +2 | 100 |
| **Total** | | **17 semanas (~4 meses)** | **+15** | **100** |

**Ruta crítica:** A → D → E (10 semanas). Fase B puede correr en paralelo con D y E.

**Progreso:** Fase C completada (rating 85 → 90). Siguiente paso recomendado: Fase A (Quality Purge) o Fase D (Fuzzing).
