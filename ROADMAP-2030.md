# Roadmap 2030 — Kraken Ultra: Performance, InfraSec, Secrets & Garantías

Extender Kraken con 4 fases: optimización de performance/binario, escaneo de infraestructura como código (IaC), detección unificada de secretos con entropía y git history, y testing basado en propiedades para blindaje formal.

---

## ✅ Fase 11 — Performance & Binary Size (Completada)

**Goal:** Reducir binary size ~150MB → ~40MB, startup más rápido, benchmarks reproducibles.

| Componente | Implementación |
|---|---|
| **Release profile tuneado** | `rust/Cargo.toml`: `lto = "fat"`, `strip = true`, `panic = "abort"`, `codegen-units = 1`, `opt-level = "z"` |
| **Criterion benchmarks** | `rust/benches/kraken_bench.rs` (nuevo) — ML inference latency, sandbox overhead, startup time, scan throughput |
| **Allocator global** | Opcional: `mimalloc` como global allocator via `rust/Cargo.toml` + `rusty-claude-cli/src/main.rs` |
| **KPI** | Binary < 50MB (release). Startup < 500ms. Benchmarks en CI. |

### Archivos clave
- `rust/Cargo.toml` — `[profile.release]` section (nuevo)
- `rust/benches/kraken_bench.rs` (nuevo)
- `rust/crates/rusty-claude-cli/src/main.rs` — mimalloc global

---

## ✅ Fase 12 — IaC + Container Scanning (Completada)

**Goal:** Escanear Dockerfiles, Kubernetes manifests, Terraform, CloudFormation con los mismos estándares que el code scanning.

| Componente | Implementación |
|---|---|
| **Docker analyzer** | `vulnscan/src/analyzers/docker.rs` (nuevo) — `USER root`, `apt-get sin --no-install-recommends`, `COPY --from=root`, `EXPOSE 0.0.0.0`, `ADD` vs `COPY`, secrets en ENV, version pinning, `curl | bash` patterns |
| **Kubernetes analyzer** | `vulnscan/src/analyzers/kubernetes.rs` (nuevo) — `privileged: true`, `runAsRoot`, `hostNetwork`, `hostPID`, `cluster-admin` RBAC, `securityContext` ausente, `allowPrivilegeEscalation`, containers sin resource limits |
| **Terraform analyzer** | `vulnscan/src/analyzers/terraform.rs` (nuevo) — S3 público (`acl = "public-read"`), IAM `"*:*"`, security group `0.0.0.0/0`, `admin = true`, version pinning ausente, secrets en variables |
| **CloudFormation** | `vulnscan/src/analyzers/cloudformation.rs` (nuevo) — Mismos patrones que Terraform en JSON/YAML |
| **Container image scan** | `vulnscan/src/scan.rs` — implementar `enable_container_scan` + `container_image` (hoy dead code) |
| **Language enum extendido** | `vulnscan/src/lib.rs` — `Language::Docker`, `Language::Kubernetes`, `Language::Terraform` + extensiones |
| **Detect por filename** | `vulnscan/src/analyzers/mod.rs` — detectar `Dockerfile` (sin extensión), `*.yaml` con content sniffing K8s/Terraform |
| **KPI** | 40+ tests nuevos. Cobertura de 8+ vulnerabilidades por analizador. |

### Archivos clave (nuevos/modificados)
- `vulnscan/src/analyzers/docker.rs` (nuevo, ~300 líneas)
- `vulnscan/src/analyzers/kubernetes.rs` (nuevo, ~300 líneas)
- `vulnscan/src/analyzers/terraform.rs` (nuevo, ~300 líneas)
- `vulnscan/src/analyzers/cloudformation.rs` (nuevo, ~250 líneas)
- `vulnscan/src/analyzers/mod.rs` — detect_language() extendido + load_all_analyzers()
- `vulnscan/src/lib.rs` — Language::Docker/Kubernetes/Terraform
- `vulnscan/src/scan.rs` — container_image scan implementation

---

## ✅ Fase 13 — Secret Scanning Unificado (Completada)

**Goal:** Unificar las 2 implementaciones actuales de detección de secretos, agregar entropía, escaneo de git history, pre-commit hooks y scanning de binarios.

| Componente | Implementación |
|---|---|
| **Unificación detect + redact** | `vulnscan/src/secrets.rs` (refactor mayor) — Fusionar `SecretsDetector` (detección + findings) con `SecretsRedactor` (redacción de output). Un solo canonical pattern set. |
| **Entropía Shannon** | `vulnscan/src/secrets.rs` — `entropy_bits()` compute Shannon entropy por línea/string. Threshold > 4.5 bits/byte = probable secret. Detecta tokens/keys que regex no conoce. |
| **Git history scanning** | `vulnscan/src/secrets.rs` — `git log -p --all` parsing para detectar secrets committed y luego borrados. `--follow` para renames. |
| **Binary scanning** | `vulnscan/src/secrets.rs` — `strings`-like extraction de strings legibles de archivos binarios, aplicar regex + entropía. |
| **Pre-commit hook** | `scripts/install-pre-commit.sh` (nuevo) — Template de pre-commit hook que corre `kraken vulnscan --secrets` sobre los archivos staged. |
| **Re-export desde security** | `security/src/secrets.rs` — Delegar a vulnscan, mantener API pública (`redact_secrets()`, `contains_secrets()`). |
| **KPI** | >99% recall en detección de secrets. 0 secrets en git history. 15+ tests nuevos. |

### Archivos clave (nuevos/modificados)
- `vulnscan/src/secrets.rs` — refactor mayor (~400 líneas, entropía + git + binarios)
- `security/src/secrets.rs` — delegar a vulnscan, mantener API
- `scripts/install-pre-commit.sh` (nuevo)
- `vulnscan/src/lib.rs` — exportar nuevas funciones

---

## ✅ Fase 14 — Property-Based Testing (Completada)

**Goal:** Garantías formales para los módulos críticos de seguridad usando `proptest`. Cada propiedad documenta un invariante de seguridad.

| Componente | Propiedad |
|---|---|
| **Sanitizer** | "Para todo path input (Unicode, traversal, vacío, absoluto, relativo), el output canonicalizado está dentro del workspace" |
| **Path Traversal** | "Ningún bypass conocido (doble encoding, unicode normalization, symlinks, null bytes, device files) es detectado como seguro" |
| **Permission Enforcer** | "Para toda combinación de tool + reglas, la decisión (allow/deny/prompt) es determinista y consistente" |
| **Fingerprint** | "Dos secuencias de tool calls idénticas producen el mismo fingerprint hash" |

| Dependencia | `proptest` en `[dev-dependencies]` de `runtime/Cargo.toml` |
|---|---|
| Archivos de test | `runtime/tests/proptest_sanitizer.rs` |
| | `runtime/tests/proptest_path_traversal.rs` |
| | `runtime/tests/proptest_permissions.rs` |
| | `runtime/tests/proptest_fingerprint.rs` |

**KPI:** 4 property test files, ~6-8 propiedades cada uno = ~30 propiedades generativas (cada una corre cientos de casos). 0 regresiones de seguridad no detectadas.

### Archivos clave (nuevos)
- `runtime/tests/proptest_sanitizer.rs`
- `runtime/tests/proptest_path_traversal.rs`
- `runtime/tests/proptest_permissions.rs`
- `runtime/tests/proptest_fingerprint.rs`
- `runtime/Cargo.toml` — `[dev-dependencies]` con `proptest`

---

## Resumen

| Fase | Área | Archivos nuevos | Archivos modificados | Tests nuevos | Esfuerzo estimado |
|---|---|---|---|---|---|
| 11 | ✅ Performance & Binary Size | 1 | 2 | 5 (benchmarks) | ~2h |
| 12 | ✅ IaC + Container Scanning | 5 | 4 | 52 | ~8h |
| 13 | ✅ Secret Scanning Unificado | 1 | 3 | 72 | ~4h |
| 14 | ✅ Property-Based Testing | 4 | 1 | 23 (proptests) | ~6h |

**Total:** 4 fases completadas, 152 tests nuevos, ~22h de implementación.

**Después de Fase 14:** Posibles extensiones — escaneo de Helm charts, Docker Compose, Ansible playbooks, escaneo de imágenes Docker vía layers, integración con trivy/grype para vulnerabilidades de sistema.
