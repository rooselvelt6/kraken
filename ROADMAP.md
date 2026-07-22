# Kraken v3.0 — Roadmap: Resolución de Deuda Técnica

> **Objetivo:** Resolver los problemas arquitectónicos críticos identificados en la auditoría del sistema.
>
> **Estado actual:** 35 crates · ~210K LOC · 417+ tests · 0 unsafe · Roadmap v2.0 completado

---

## Auditoría: Problemas Identificados

| # | Problema | Severidad | Crates afectados |
|---|----------|-----------|------------------|
| 1 | God Crate `runtime` (48K LOC, 64 módulos) | ALTA | runtime |
| 2 | C2 aislado — duplicación de crypto | ALTA | c2, security |
| 3 | Error handling inconsistente (20+ crates con `Result<T, String>`) | ALTA | tools, c2, sandbox, wireless, forensics, security, etc. |
| 4 | `#![allow(clippy::all)]` en api (suprime todos los warnings) | MEDIA | api |
| 5 | thiserror versiones mixtas (v1 y v2) + 3 dependencias muertas | MEDIA | workspace |
| 6 | Mensajes de error en español (cache, offline) | BAJA | cache, offline |
| 7 | 108/144 slash commands sin implementar | BAJA | rusty-claude-cli |
| 8 | Shellcode ARM/ARM64/Windows con placeholder bytes | BAJA | vulnscan |
| 9 | ~25 instancias de `let _ =` descartando errores importantes | MEDIA | vulnscan, c2, wireless |

---

## Fase 1: Higiene Inmediata ✅ COMPLETADA

**Objetivo:** Limpiar dependencias muertas, unificar versiones, eliminar supresiones blanket.
**Riesgo:** Bajo | **Esfuerzo:** 30 min

### 1.1 Eliminar dependencias muertas de thiserror
- [x] `localmodels/Cargo.toml` — quitar `thiserror` (nunca se usa)
- [x] `enterprise/Cargo.toml` — quitar `thiserror` (nunca se usa)
- [x] `osint/Cargo.toml` — quitar `thiserror` (nunca se usa)

### 1.2 Unificar versión de thiserror
- [x] `rust/Cargo.toml` — agregar `thiserror = "2"` a `[workspace.dependencies]`
- [x] Migrar `cache`, `offline` a `thiserror = { workspace = true }`
- [x] Verificar que `enterprise`, `osint`, `vulnscan` no necesitan thiserror

### 1.3 Eliminar supresiones blanket de clippy
- [x] `api/src/lib.rs` — quitar `#![allow(clippy::all, ...)]`
- [x] `enterprise/src/retry.rs` — quitar `#[allow(clippy::all)]`
- [x] Compilar, fixear o suprimir individualmente los warnings resultantes

### 1.4 Traducir mensajes de error en español
- [x] `cache/src/error.rs` — traducir a inglés
- [x] `offline/src/error.rs` — traducir a inglés

### 1.5 Verificación
- [x] `cargo check --workspace` — sin errores
- [x] `cargo clippy --workspace` — warnings minimizados

---

## Fase 2: Integrar C2 con Security ✅ COMPLETADA

**Objetivo:** Eliminar duplicación de crypto, mejorar seguridad de keys, unificar error handling.
**Riesgo:** Bajo | **Esfuerzo:** 1 hora

### 2.1 Agregar `security` como dependencia de `c2`
- [x] `c2/Cargo.toml` — agregar `security = { path = "../security" }`
- [x] Verificar que no hay dependencia circular (DAG: c2 → security, runtime → security)

### 2.2 Reemplazar `c2crypto.rs`
- [x] `c2/src/c2crypto.rs` — delegar a `Encryptor` y `Key` de security
- [x] Ganancias: zeroize automático, constant-time comparison, algorithm agility
- [x] Mantener `encrypt_json`/`decrypt_json` como wrappers específicos de c2

### 2.3 Limpiar dependencias de `c2/Cargo.toml`
- [x] Eliminar `aes-gcm` (ya viene via security)
- [x] Eliminar `sha2` directo (usar via security o mantener solo para payload checksum)
- [x] Mantener `hex`, `base64`, `rand` (necesarios para malleable profiles)

### 2.4 Crear tipo `C2Error` estructurado
- [x] `c2/src/error.rs` (nuevo) — enum con variantes: `Crypto`, `Transport`, `Protocol`, `Io`
- [x] Reemplazar los 16 `Result<T, String>` del crate c2

### 2.5 Verificación
- [x] `cargo check -p c2` — sin errores
- [x] `cargo test -p c2` — todos pasan
- [x] `cargo clippy -p c2` — limpio

---

## Fase 3: Descomponer el God Crate `runtime` ✅ COMPLETADA

**Objetivo:** Dividir `runtime` (48K LOC) en ~8 crates enfocados.
**Riesgo:** Medio | **Esfuerzo:** 3-4 horas
**Resultado:** 8 crates creados, 49 módulos extraídos, 704 tests, 0 clippy warnings.

Estrategia: Extraer en orden de dependencia (hojas primero).

### 3.1 `kraken-infra` — Infraestructura utilitaria (13 módulos hoja) ✅
- [x] Crear `crates/kraken-infra/` con Cargo.toml
- [x] Mover: `circuit_breaker`, `health_probe`, `rate_limiter`, `concurrency`, `file_ops`, `path_traversal`, `sanitizer`, `sandbox`, `forensic`, `fingerprint`, `size_budget`, `summary_compression`, `bootstrap`
- [x] Dependencias externas: `serde`, `tokio`, `glob`, `regex`, `walkdir`, `sha2`
- [x] Tests: 147 unit + 7 doc tests

### 3.2 `kraken-git` — Contexto de source control (4 módulos hoja) ✅
- [x] Crear `crates/kraken-git/`
- [x] Mover: `git_context`, `stale_base`, `stale_branch`, `branch_lock`
- [x] Dependencias: `serde`, `std`
- [x] Tests: 34

### 3.3 `kraken-events` — Eventos y tareas (4 módulos) ✅
- [x] Crear `crates/kraken-events/`
- [x] Mover: `lane_events`, `task_packet`, `task_registry`, `team_cron_registry`
- [x] `task_registry` depende de `task_packet`, los demás son hojas
- [x] Tests: 54 unit + 6 doc tests

### 3.4 `kraken-config` — Configuración (3 módulos) ✅
- [x] Crear `crates/kraken-config/`
- [x] Mover: `config`, `config_validate`, `json`
- [x] `config` depende de `json` + `sandbox` (sandbox viene de kraken-infra)
- [x] Tests: 45

### 3.5 `kraken-policy` — Políticas y permisos (5 módulos) ✅
- [x] Crear `crates/kraken-policy/`
- [x] Mover: `policy_engine`, `green_contract`, `trust_resolver`, `permissions`, `permission_enforcer`
- [x] `permission_enforcer` depende de `permissions`; `permissions` depende de `kraken-config`
- [x] Tests: 50 unit + 4 doc tests

### 3.6 `kraken-mcp` — Subsistema MCP (7 módulos) ✅
- [x] Crear `crates/kraken-mcp/`
- [x] Mover: `mcp`, `mcp_client`, `mcp_stdio`, `mcp_server`, `mcp_tool_bridge`, `mcp_lifecycle_hardened`, `oauth`
- [x] Cadena lineal limpia
- [x] Tests: 70

### 3.7 `kraken-session` — Sesiones (6 módulos) ✅
- [x] Crear `crates/kraken-session/`
- [x] Mover: `session`, `session_control`, `compact`, `usage`, `prompt`, `hooks`
- [x] `session` ↔ `usage` circular (mismo crate); `prompt` depende de `kraken-config` + `kraken-git`
- [x] Tests: 62

### 3.8 `kraken-conversation` — Loop de conversación (1 módulo) ✅
- [x] Crear `crates/kraken-conversation/`
- [x] Mover: `conversation` (depende de 6 módulos → importa de kraken-* crates)

### 3.9 Módulos restantes en `runtime` ✅
- [x] Quedan en runtime (~15 módulos): `bash`, `bash_validation`, `heuristic_engine`, `adaptive_engine`, `audit_integration`, `siem_export`, `self_healing`, `recovery_recipes`, `provider_chain`, `meta_agent`, `remote`, `sse`, `lsp_client`, `plugin_lifecycle`, `worker_boot`
- [x] Runtime funciona como fachada delgada re-exportando desde los nuevos crates

### 3.10 Actualizar workspace ✅
- [x] `rust/Cargo.toml` — workspace `crates/*` detecta automáticamente
- [x] Re-exports en `runtime/lib.rs` mantienen backward compatibility con `crate::`
- [x] 20 archivos .rs eliminados de runtime (movidos a nuevos crates)

### 3.11 Verificación ✅
- [x] `cargo check --workspace` — sin errores (excepto pre-existing openssl)
- [x] `cargo test` — 704 tests (479 nuevos crates + 225 runtime)
- [x] `cargo clippy` — 0 warnings

---

## Fase 4: Error Handling Estandarizado ✅ COMPLETADA

**Objetivo:** Eliminar `Result<T, String>` de los crates más críticos, crear tipos de error estructurados.
**Riesgo:** Medio | **Esfuerzo:** 2-3 horas
**Resultado:** ~200 `Result<T, String>` migrados, 7 tipos de error creados, 295+ tests, 0 clippy warnings.

### 4.1 Crear `kraken-errors` crate ✅
- [x] Crear `crates/kraken-errors/` con 6 enums de error por dominio + `KrakenError` unificado
- [x] `ToolError` (12 variantes), `SandboxError` (11 variantes), `SecurityError` (10 variantes), `WirelessError` (5 variantes), `ForensicsError` (4 variantes), `NetworkError` (4 variantes)
- [x] Usar `thiserror` y `#[from]` para conversión ergonómica
- [x] Tests: 7

### 4.2 Migrar crates críticos (prioridad ALTA) ✅
- [x] `tools/src/lib.rs` — 119 funciones migradas a `Result<T, ToolError>`
- [x] `sandbox/` — 18 funciones migradas a `Result<T, SandboxError>` (9 archivos)
- [x] `security/` — 18 funciones migradas a `Result<T, SecurityError>` (3 archivos)

### 4.3 Migrar crates medios (prioridad MEDIA) ✅
- [x] `wireless/` — migrado a `Result<T, WirelessError>` (111 tests pasan)
- [x] `forensics/` — migrado a `Result<T, ForensicsError>` (8 archivos, 80 tests)
- [x] `sniffer/` — migrado a `Result<T, NetworkError>`
- [x] `network/` — migrado a `Result<T, NetworkError>`

### 4.4 Migrar binario ✅
- [x] `rusty-claude-cli/src/main.rs` — ya estaba limpio (0 `Box<dyn Error>`)

### 4.5 Corregir `let _ =` críticos ✅
- [x] `vulnscan/src/db.rs` — 6 instancias DB/commands → `if let Err(e) = ... { eprintln!(...) }`
- [x] `vulnscan/src/disclosure.rs` — 1 instancia dir creation → eprintln!
- [x] `vulnscan/src/resume.rs` — 3 instancias checkpoint I/O → eprintln!
- [x] `vulnscan/src/memory.rs` — 2 instancias memory I/O → eprintln!

### 4.6 Verificación ✅
- [x] `cargo test` — 295 tests (kraken-errors: 7, sandbox: 51, security: 46, wireless: 111, forensics: 80)
- [x] `cargo clippy` — 0 warnings

---

## Fase 5: Verificación Final

**Objetivo:** Confirmar que todo compila, pasa tests, y cumple estándares.
**Riesgo:** Ninguno | **Esfuergo:** 30 min

### 5.1 Compilación completa
- [ ] `cargo build --release` — sin errores

### 5.2 Tests completos
- [ ] `cargo test --workspace` — todos pasan

### 5.3 Clippy limpio
- [ ] `cargo clippy --workspace -- -D warnings` — sin warnings

### 5.4 Verificar zero unsafe
- [ ] `grep -r "unsafe {" crates/ --include="*.rs" | grep -v "sandbox\|seccomp\|landlock"` — solo en módulos de OS

### 5.5 Actualizar documentación
- [ ] `progress.txt` — documentar cada fase completada
- [ ] `README.md` — actualizar métricas y tabla de estados
- [ ] `ROADMAP.md` — marcar todas las tareas completadas

---

## Métricas de Éxito

| Métrica | Antes | Después |
|---------|-------|---------|
| God crates (>30K LOC) | 1 (`runtime` 48K) | 0 (`runtime` ~15K, 8 sub-crates) |
| Crates con `Result<T, String>` | 20+ | <10 (migrados: tools, sandbox, security, wireless, forensics, sniffer, network) |
| Dead thiserror dependencies | 3 | 0 |
| Blanket clippy suppressions | 2 | 0 |
| Error messages en español | 2 crates | 0 |
| `let _ =` descartando errores críticos | ~25 | <13 (12 fixes en vulnscan) |
| C2 duplica crypto de security | Sí | No |
| Tests totales | 417+ | 1000+ |
| Sub-crates de runtime | 0 | 8 |
| Tipos de error estructurados | 0 | 7 (Tool, Sandbox, Security, Wireless, Forensics, Network, Kraken) |

---

## Timeline

| Fase | Duración | Dependencia |
|------|----------|-------------|
| 1. Higiene | 30 min | Ninguna |
| 2. C2+Security | 1 hora | Fase 1 |
| 3. Runtime decomposition | 3-4 horas | Fase 1 |
| 4. Error handling | 2-3 horas | Fases 2, 3 |
| 5. Verificación | 30 min | Fases 1-4 |
| **Total** | **~7-9 horas** | |

---

## Dependencias entre Fases

```
Fase 1 (Higiene)
  ├──→ Fase 2 (C2+Security)
  │      └──→ Fase 4 (Error handling)
  └──→ Fase 3 (Runtime decomposition)
         └──→ Fase 4 (Error handling)
                └──→ Fase 5 (Verificación)
```
