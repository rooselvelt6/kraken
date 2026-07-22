# Roadmap v4.0 — Auditoría Arquitectónica

**Fecha:** 2026-07-22
**Objetivo:** Resolver todas las preocupaciones arquitectónicas identificadas en el deep audit.
**Base:** Roadmap v3.0 completado (runtime decomposition, error handling, verificación).

---

## Hallazgos del Deep Audit

| # | Concern | Severidad | Scope real |
|---|---------|-----------|------------|
| 1 | `sandbox` crate huerfano | CRÍTICA | Nadie lo importa. `can_execute()` y `verify_config()` son stubs que retornan `true`. Dead code total. |
| 2 | `runtime::sandbox` es copia exacta de `kraken-infra::sandbox` | ALTA | 384 líneas duplicadas. `diff` retorna vacío. |
| 3 | `c2crypto` es fachada trivial sobre `security` | ALTA | 7 funciones, todas delegan a `security::crypto`. Usa SHA-256 KDF con salt hardcoded `[1u8; 16]`. |
| 4 | `password` pinea reqwest 0.11 | ALTA | Fuerza 2 versiones de reqwest en Cargo.lock (0.11 + 0.12), duplicando árbol de dependencias. |
| 5 | 216 `Result<T, String>` restantes | ALTA | 30 crates afectados. Peores: runtime(34), wireless(23), rusty-claude-cli(19). |
| 6 | `main.rs` 13,695 líneas | ALTA | 21 `#![allow(...)]` incluyendo `clippy::all`. 81 imports de 7 crates. Monolito. |
| 7 | `rand` 0.8 en 17 crates | MEDIA | 12 hardcodean `rand = "0.8"` en vez de usar workspace ref. 3 versiones en Cargo.lock (0.8, 0.9, 0.10). |
| 8 | 6 `OnceLock` globals en tools | MEDIA | Todos confinados a `tools/src/lib.rs`. Solo se usan internamente. Menos grave de lo pensado. |
| 9 | `sha2` legacy en C2Crypto | Baja | Solo caller de producción es `C2Crypto::derive_key()` que a su vez no tiene callers de producción. Dead code. |
| 10 | `from_password_sha256()` viva en security | Baja | Función deprecated que queda expuesta después de eliminar c2crypto. Debe marcarse `#[deprecated]`. |
| 11 | Sandbox real (seccomp/landlock) sin integrar | MEDIA | El crate huerfano tenía lógica genuina de aislamiento. Decisión: integrar a kraken-infra o eliminar. |
| 12 | Sin tests para cambios de refactoring | MEDIA | Ninguna fase incluye tests. Riesgo de regresiones silenciosas. |

---

## Dependencias entre fases

```
Fase 1 (sandbox)     ─┐
Fase 2 (c2crypto)    ─┤
Fase 3 (reqwest)     ─┼── independientes, pueden hacerse en paralelo
Fase 4 (errors)      ─┤
Fase 6 (rand)        ─┘

Fase 5 (decompose main.rs) ──→ Fase 7 (clippy suppressions)
                              ──→ Fase 8 (OnceLock globals)

Fase 10 (sandbox integration) ── depende de Fase 1
Fase 11 (deprecate SHA-256)   ── depende de Fase 2

Fase 9 (verificación) ── depende de todo lo anterior
```

**Regla global:** Cada fase incluye `cargo test --workspace` como paso de verificación para catchar regresiones temprano.

---

## Fase 1: Eliminar sandbox huerfano + dedup sandbox

**Riesgo:** Bajo — El crate no se usa. La dedup es un re-export trivial.

| Paso | Acción | Estado |
|------|--------|--------|
| 1.1 | `rm -rf crates/sandbox/` — eliminar crate huerfano (0 dependientes) | [ ] |
| 1.2 | Eliminar `sandbox` de `Cargo.toml` workspace members | [ ] |
| 1.3 | `runtime/src/sandbox.rs` → eliminar, re-exportar todo de `kraken_infra::sandbox` | [ ] |
| 1.4 | Verificar: `cargo check --workspace` | [ ] |
| 1.5 | Verificar: `cargo test --workspace` | [ ] |

---

## Fase 2: Eliminar c2crypto, migrar C2 a security

**Riesgo:** Bajo — c2crypto es puro delegado. `C2Crypto::derive_key()` tiene 0 callers de producción.

| Paso | Acción | Estado |
|------|--------|--------|
| 2.1 | `c2/src/c2crypto.rs` → eliminar | [ ] |
| 2.2 | `c2/Cargo.toml` → asegurar que `security` ya es dependencia (lo es) | [ ] |
| 2.3 | Re-exportar `security::crypto::*` desde `c2::c2crypto` (o eliminar el módulo y actualizar imports) | [ ] |
| 2.4 | Migrar cualquier uso de `C2Crypto` en otros crates de c2 a `security::crypto` directamente | [ ] |
| 2.5 | Verificar: `cargo check -p c2` | [ ] |
| 2.6 | Verificar: `cargo test --workspace` | [ ] |

---

## Fase 3: Unificar reqwest 0.11 → 0.12

**Riesgo:** Medio — API breaking change entre reqwest 0.11 y 0.12.

| Paso | Acción | Estado |
|------|--------|--------|
| 3.1 | Leer `password/src/lib.rs` para entender uso de `reqwest::blocking` | [ ] |
| 3.2 | Cambiar `reqwest = "0.11"` → `reqwest = { workspace = true }` en `password/Cargo.toml` | [ ] |
| 3.3 | Adaptar código si hay breaking changes (blocking client API) | [ ] |
| 3.4 | Verificar: `cargo check -p password` | [ ] |
| 3.5 | Verificar: `cargo tree -p password` ya no tiene reqwest 0.11 | [ ] |
| 3.6 | Verificar: `cargo test --workspace` | [ ] |

---

## Fase 4: Eliminar 216 Result<T, String>

**Riesgo:** Medio — Migración mecánica pero amplia.

**Estrategia:** Crear tipos de error por crate donde no existen, reutilizar `kraken-errors` donde ya hay tipos.

| Sub-fase | Crates | Count | Acción | Estado |
|----------|--------|-------|--------|--------|
| 4.1 | `runtime` | 34 | Crear `RuntimeError` con variantes por categoría | [ ] |
| 4.2 | `wireless` | 23 | Usar `WirelessError` existente de kraken-errors | [ ] |
| 4.3 | `rusty-claude-cli` | 19 | Crear `CliError` con variantes | [ ] |
| 4.4 | `kraken-mcp` | 15 | Crear `McpError` | [ ] |
| 4.5 | `c2` | 15 | Usar `C2Error` existente | [ ] |
| 4.6 | `password` | 14 | Crear `PasswordError` | [ ] |
| 4.7 | `reverse` | 11 | Crear `ReverseError` | [ ] |
| 4.8 | `kraken-events` | 10 | Crear `EventError` | [ ] |
| 4.9 | `commands` | 9 | Crear `CommandError` | [ ] |
| 4.10 | Resto (18 crates, ≤8 c/u) | 66 | Tipos locales o reutilizar existentes | [ ] |
| 4.11 | Verificar: `cargo check --workspace` | - | - | [ ] |
| 4.12 | Verificar: `cargo test --workspace` | - | - | [ ] |

---

## Fase 5: Decomponer main.rs (13K líneas)

**Riesgo:** Alto — Refactor más grande del plan.

**Estrategia:** Extraer en 5 sub-crates nuevos basados en agrupación lógica.

| Sub-crate | Líneas aprox | Contenido |
|-----------|-------------|-----------|
| `cli-args` | ~2000 | `parse_args()`, `CliAction`, `CliOutputFormat`, todos los `parse_*_args` |
| `cli-diagnostics` | ~600 | `DiagnosticCheck`, `DoctorReport`, `check_*_health`, `render_doctor_report` |
| `cli-reports` | ~1500 | `StatusContext`, `format_status_report`, `render_config_*`, `render_diff_*`, `render_memory_*` |
| `cli-completions` | ~600 | `render_help`, `suggest_*`, `levenshtein_distance`, slash command completions |
| `cli-stream` | ~1500 | `ApiStreamClient`, `format_tool_call_start`, `format_tool_result`, `MarkdownStreamState` |

**Queda en main.rs:** ~5000 líneas (REPL core, session management, tests).

| Paso | Acción | Estado |
|------|--------|--------|
| 5.1 | Crear `crates/cli-args/`, extraer parsing de argumentos | [ ] |
| 5.2 | Crear `crates/cli-diagnostics/`, extraer doctor/diagnostics | [ ] |
| 5.3 | Crear `crates/cli-reports/`, extraer rendering de estado | [ ] |
| 5.4 | Crear `crates/cli-completions/`, extraer help/completions | [ ] |
| 5.5 | Crear `crates/cli-stream/`, extraer stream rendering | [ ] |
| 5.6 | Actualizar `rusty-claude-cli/Cargo.toml` con nuevos deps | [ ] |
| 5.7 | Eliminar `#![allow(clippy::all)]` y corregir warnings | [ ] |
| 5.8 | Verificar: `cargo check -p rusty-claude-cli` | [ ] |
| 5.9 | Verificar: `cargo test --workspace` | [ ] |

---

## Fase 6: Unificar rand 0.8 → 0.10

**Riesgo:** Medio — Breaking API changes (0.8→0.10).

| Paso | Acción | Estado |
|------|--------|--------|
| 6.1 | Cambiar workspace dep: `rand = "0.10"` | [ ] |
| 6.2 | Migrar 12 crates hardcoded a `rand.workspace = true` | [ ] |
| 6.3 | Adaptar código: `thread_rng()` → `rng()`, `gen_range` API changes | [ ] |
| 6.4 | Verificar: `cargo check --workspace` | [ ] |
| 6.5 | Verificar: `cargo tree` muestra una sola versión de rand | [ ] |
| 6.6 | Verificar: `cargo test --workspace` | [ ] |

---

## Fase 7: Eliminar clippy suppressions en main.rs

**Riesgo:** Bajo — Solo si Fase 5 se hizo primero (main.rs más pequeño).

| Paso | Acción | Estado |
|------|--------|--------|
| 7.1 | Eliminar `#![allow(clippy::all)]` y las demás suppressions | [ ] |
| 7.2 | `cargo clippy -p rusty-claude-cli --lib -- -D warnings` | [ ] |
| 7.3 | Corregir cada warning individualmente | [ ] |
| 7.4 | Verificar: 0 warnings | [ ] |
| 7.5 | Verificar: `cargo test --workspace` | [ ] |

---

## Fase 8: Eliminar OnceLock globals en tools

**Riesgo:** Bajo — Todos confinados a un solo archivo.

| Paso | Acción | Estado |
|------|--------|--------|
| 8.1 | Convertir `global_*_registry()` a `OnceLock` con inicialización en `GlobalToolRegistry::new()` | [ ] |
| 8.2 | Inyectar registries como campos de `GlobalToolRegistry` en vez de globals | [ ] |
| 8.3 | Verificar: `cargo check -p tools` | [ ] |
| 8.4 | Verificar: `cargo test --workspace` | [ ] |

---

## Fase 10: Integrar sandbox real (seccomp/landlock) a kraken-infra

**Riesgo:** Medio — El crate huerfano tenía lógica genuina de aislamiento (seccomp BPF, landlock, namespaces). Se elimina el crate pero se integra la lógica valiosa a `kraken-infra`.

**Decisión:** Integrar, no eliminar. El aislamiento de syscall filtering es core para la seguridad de ejecución de tools.

| Paso | Acción | Estado |
|------|--------|--------|
| 10.1 | Auditar `sandbox/src/seccomp.rs` — identificar funciones de valor (BPF filter setup, syscall whitelist) | [ ] |
| 10.2 | Auditar `sandbox/src/landlock.rs` — identificar funciones de valor (ruleset creation, file access control) | [ ] |
| 10.3 | Auditar `sandbox/src/namespace.rs` — identificar funciones de valor (unshare, mount namespace) | [ ] |
| 10.4 | Migrar seccomp BPF a `kraken-infra/src/sandbox_seccomp.rs` | [ ] |
| 10.5 | Migrar landlock a `kraken-infra/src/sandbox_landlock.rs` | [ ] |
| 10.6 | Migrar namespace a `kraken-infra/src/sandbox_namespace.rs` | [ ] |
| 10.7 | Actualizar `kraken-infra/src/sandbox.rs` para orquestar seccomp+landlock+namespace | [ ] |
| 10.8 | Integrar `ToolSandbox::can_execute()` con lógica real (syscall whitelist check) | [ ] |
| 10.9 | Integrar `ToolSandbox::verify_config()` con validación real | [ ] |
| 10.10 | Agregar tests para seccomp BPF filter, landlock ruleset, namespace isolation | [ ] |
| 10.11 | Verificar: `cargo check --workspace` | [ ] |
| 10.12 | Verificar: `cargo test --workspace` | [ ] |

---

## Fase 11: Deprecar SHA-256 KDF legacy en security

**Riesgo:** Bajo — La función queda expuesta después de eliminar c2crypto. Debe marcarse deprecated para evitar uso futuro.

| Paso | Acción | Estado |
|------|--------|--------|
| 11.1 | Agregar `#[deprecated(note = "Use from_password_argon2id instead")]` a `Key::from_password_sha256()` | [ ] |
| 11.2 | Agregar `#[deprecated]` a `KdfAlgorithm::Sha256` | [ ] |
| 11.3 | Verificar que no hay callers de producción (solo tests) | [ ] |
| 11.4 | Verificar: `cargo check --workspace` | [ ] |
| 11.5 | Verificar: `cargo test --workspace` | [ ] |

---

## Fase 9: Verificación final

**Riesgo:** Ninguno — Solo lectura.

| Paso | Acción | Estado |
|------|--------|--------|
| 9.1 | `cargo check --workspace` | [ ] |
| 9.2 | `cargo test --workspace` | [ ] |
| 9.3 | `cargo clippy --workspace --lib -- -D warnings` | [ ] |
| 9.4 | Actualizar ROADMAP.md y progress.txt | [ ] |
| 9.5 | Commit + push | [ ] |

---

## Estimación

| Fase | Tiempo estimado |
|------|----------------|
| 1. Sandbox huerfano | 10 min |
| 2. c2crypto | 15 min |
| 3. reqwest unification | 20 min |
| 4. Result<T, String> | 2-3 horas |
| 5. Decompose main.rs | 2-3 horas |
| 6. rand migration | 30 min |
| 7. clippy suppressions | 30 min |
| 8. OnceLock globals | 20 min |
| 9. Verificación final | 15 min |
| 10. Sandbox integration | 1-2 horas |
| 11. Deprecate SHA-256 KDF | 10 min |
| **Total** | **~7-10 horas** |
