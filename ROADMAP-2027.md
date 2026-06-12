# Roadmap 2027 — Kraken Hardened: Defense-in-Depth Enterprise Edition

Build an immune system for Kraken: detect, contain, recover, and learn automatically. Each phase has concrete technologies, SLAs, KPIs, and mandatory penetration tests.

---

## Fase 1 — Fortaleza Criptográfica y Zero Trust Secrets

**Goal:** Nadie puede leer secretos ni siquiera con acceso al disco — ni root, ni backup, ni forensic analyst sin la clave maestra.

| Componente | Implementación |
|---|---|
| **Keychain cifrado** | Reemplazar `credentials.json` plano por `SecureConfig` ya existente en `security/` — XChaCha20Poly1305 + Argon2id (mem=64MB, time=3, parallel=4 — parámetros OWASP 2024) |
| **Clave maestra** | Derivada vía: `SOFTHSM2` + `TPM 2.0` si disponible, fallback a `$KRAKEN_MASTER_KEY` en variable de entorno con `mlock()` + `mprotect(PROT_NONE)` |
| **Session vault** | Cifrar segmentos sensibles de JSONL de sesión con claves efímeras por sesión (wrap con master key) |
| **Secrets redaction** | Regex engine + transformer ML (modelo BPE small tipo `tiktoken`) para detectar y redactar API keys, JWT, tokens en outputs con recall >99% |
| **Hardening post-mortem** | `zeroize` en panic handlers (`std::panic::set_hook`), `madvise(MADV_DONTDUMP)` en regiones sensibles, `SIGBUS` handler para memory locking |
| **KPI** | 0 secretos en texto plano en disco. Latencia < 5ms por operación de cifrado. |

**Penetration test:** Atacar el almacenamiento de credenciales con acceso físico al disco — debe requerir la clave maestra.

### Archivos clave
- `security/src/crypto.rs` — encryptor primitives (XChaCha20Poly1305, AES-256-GCM)
- `security/src/config.rs` — SecureConfig, Zeroize on drop
- `runtime/src/oauth.rs:333-388` — credential storage (hoy plano, migrar a cifrado)
- `runtime/src/session.rs` — session persistence (cifrar segmentos sensibles)
- `runtime/src/session_control.rs` — session management

---

## Fase 2 — Input Fortress: Validación y Anti-Abuse con Fuzzing

**Goal:** Cero exploits de path traversal, injection o resource exhaustion. Fuzzing continuo.

| Componente | Implementación |
|---|---|
| **Sanitizer pipeline** | 7-stage: normalization → canonicalization → symlink resolution → scope check → encoding detection → size check → allowlist |
| **Fuzzing infrastructure** | `cargo-fuzz` con corpus generado por LLM (1000+ casos adversariales por tool). CI job que ejecuta 1h de fuzzing por PR |
| **Path traversal matrix** | Detectar: symlinks, `..`, double encoding, unicode normalization (NFC/NFD), `/proc/self/fd/`, `\\.\`, `::$data`, null bytes, FIFO pipes, device files |
| **Size budgets dinámicos** | Por tool, por sesión, por ventana de tiempo. Configurable vía `policy_engine`. Default: read=10MB, write=5MB, glob=1000 entries, grep=1MB output |
| **Rate limiting granular** | Token bucket por tool + por sesión + global. Tokens se recargan según `heuristic_score` (menos tokens si hay actividad anómala) |
| **Fingerprinting** | Hash de tool call sequences para detectar patrones de escaneo/reconnaissance |
| **KPI** | 0 path traversal exits en fuzzing (24h). Latencia del sanitizer < 1ms. |

**Penetration test:** 100 casos de path traversal conocidos (CVE list) — 100% bloqueados.

### Archivos clave
- `runtime/src/file_ops.rs` — path validation, size limits (MAX_READ_SIZE, MAX_WRITE_SIZE)
- `runtime/src/bash_validation.rs` — command validation pipeline
- `runtime/src/permission_enforcer.rs` — is_read_only_command() (duplicado, unificar)
- `runtime/src/config_validate.rs` — config diagnostics

---

## Fase 3 — Heuristic Anomaly Engine (HAE)

**Goal:** Detectar comportamiento malicioso en tiempo real con scoring multi-factor, sin ML (puramente heurístico y determinista).

| Componente | Implementación |
|---|---|
| **Rule engine** | DSL en Rust: `if [tool=write] AND [path=/etc/*] AND [mode=danger-full-access] then score += 0.8`. 50+ reglas iniciales. Compiladas a FSM determinista |
| **Behavioral profiles** | Per-session profile: frecuencia de tools, tipos de bash, archivos accedidos, hora del día, tasa de error. Ventana deslizante de 5min/30min/2h |
| **Risk scoring** | `score = Σ(rule_weight * severity) + (profile_deviation * 0.3)`. Thresholds: >0.6 → warn, >0.8 → prompt, >0.95 → block |
| **Context-aware** | El mismo `rm -rf` tiene score diferente si es en `./build/` vs `/etc/` vs `.git/` |
| **Bash intent classification** | Mejorar `CommandIntent` actual (8 categorías) a 15+ categorías con regex deterministic classifier |
| **Feedback loop** | Cada approve/reject del usuario ajusta los pesos de las reglas (online learning sin ML) |
| **KPI** | Detectar 95% de ataques simulados con <5% false positives. Decisión en <2ms. |

**Penetration test:** 10 escenarios de ataque (crypto miner, reverse shell, exfiltration, ransomware simulado) — todos detectados antes de ejecución.

### Archivos clave
- `runtime/src/bash_validation.rs` — CommandIntent classification
- `runtime/src/permissions.rs` — permission escalation hooks
- `enterprise/src/enterprise_features.rs` — feature flag integration

---

## Fase 4 — Circuit Breakers Platinados y Rate Limiting Adaptativo

**Goal:** El sistema nunca falla en cascada. Cada servicio externo tiene protección multi-capa con auto-recuperación.

| Componente | Implementación |
|---|---|
| **Circuit breaker jerárquico** | Por provider + por tool + por MCP server + global. Estados: Closed → Half-Open → Open, con recovery exponencial (1s, 2s, 4s, ... 60s max) |
| **Health probes** | Ping cada 5s a providers con latencia percentil (p50, p95, p99). Si p95 > 5s → degradar. Si p99 > 10s → abrir circuito |
| **Token bucket adaptativo** | Capacidad base + bonus por confianza + malus por errores. Se ajusta en caliente cada 30s |
| **Concurrency semaphores** | Extender `SemaphoreLimiter` de `osint/` a runtime completo. Límites: bash=5, read=20, write=3, search=2, MCP=10 |
| **Graceful degradation 2.0** | Provider chain: Anthropic → DeepSeek → Ollama → offline. Tool chain: online → cached → degraded (resultado parcial) |
| **KPI** | 0 fallos en cascada. Latencia p99 con circuit breaker < 100ms overhead. Recovery < 5s. |

**Chaos test:** Apagar cada provider externo uno por uno — el sistema sigue funcionando sin crash.

### Archivos clave
- `enterprise/src/enterprise_features.rs` — RateLimitBucket (token-bucket, no conectado)
- `enterprise/src/circuit_breaker.rs` — CircuitBreaker (Closed/Open/Half-Open)
- `enterprise/src/graceful_degradation.rs` — provider fallback chain
- `osint/src/throttle.rs` — SemaphoreLimiter existente
- `runtime/src/mcp_client.rs` — MCP connection lifecycle

---

## Fase 5 — Audit Fort Knox: Inmutabilidad y Forensics

**Goal:** Cada acción es registrada, firmada y verificable. No-repudio completo.

| Componente | Implementación |
|---|---|
| **Audit hash chain** | Conectar `AuditLog` existente (SHA-256) al runtime. Encadenar cada entrada: `hash_i = SHA256(hash_i-1 \|\| entry_i)` |
| **Signed audit** | Firmar cada bloque de 100 entradas con `Ed25519` (clave por sesión). Verificar al exportar |
| **Tamper detection** | Verificar integridad de toda la cadena al inicio de sesión. Si hay truncamiento o modificación → alerta + archivo cuarentena |
| **Forensic capture** | Modo forense: captura stdout/stderr completo, environment variables, network connections, file descriptors, stack traces |
| **SIEM export** | JSON estructurado compatible con: Elastic Common Schema (ECS), OpenTelemetry, Splunk HEC |
| **Retention policies** | Configurable: 7d default, 30d enterprise, forever forense. Compresión zstd con ratio ~5:1 |
| **KPI** | 100% de tool calls auditadas. Verificación de cadena < 100ms. Overhead de storage < 10KB/tool call. |

**Penetration test:** Intentar modificar un audit log sin detección — 0% de éxito.

### Archivos clave
- `security/src/audit.rs` — AuditLog + AuditAction + hash chain
- `enterprise/src/enterprise_features.rs` — EnterpriseAuditEntry
- `telemetry/src/lib.rs` — session tracing
- `runtime/src/session.rs` — session persistence

---

## Fase 6 — Sandbox Real con Seccomp + Landlock + NSJail

**Goal:** Cada comando bash se ejecuta en un contenedor mínimo con syscalls restringidas y sin acceso a la red (a menos que se permita explícitamente).

| Componente | Implementación |
|---|---|
| **Seccomp BPF** | Lista blanca de ~50 syscalls para operaciones read-only, ~80 para write. Bloquear: `clone`, `fork`, `execveat` (excepto controlado), `ptrace`, `perf_event_open`, `bpf` |
| **Landlock (Linux 5.13+)** | Restringir acceso a filesystem: read-only en workspace, write-only en temp dir, bloqueado todo lo demás |
| **Namespace isolation** | PID namespace (procesos no ven el host), mount namespace (pivot_root a tmpfs), network namespace (loopback-only a menos que network_isolation=false), UTS namespace |
| **Resource limits** | rlimit: CPU=60s, AS=1GB, FSIZE=100MB, NOFILE=256, NPROC=16. cgroup2 si está disponible: memory.max, cpu.max, io.max |
| **Tmpfs ephemeral** | Cada ejecución obtiene un tmpfs fresco. Write operations se hacen ahí, luego se copian al workspace con verificación de checksum |
| **NSJail wrapper** | Si está instalado, usar NSJail como backend con perfiles de seguridad. Fallback a landlock + seccomp nativo |
| **macOS / Windows** | En macOS: sandbox_init() + Seatbelt profiles. En Windows: AppContainer + JobObject + Desktop Restriction |
| **KPI** | 0 escapes de sandbox en pruebas. Latencia de setup < 50ms. Overhead de ejecución < 10%. |

**Penetration test:** 20 técnicas de escape de contenedores conocidas — 100% bloqueadas.

### Archivos clave
- `sandbox/src/lib.rs` — placeholder actual (reemplazar)
- `runtime/src/sandbox.rs` — SandboxConfig, FilesystemIsolationMode
- `runtime/src/bash.rs` — sandbox integration flags, dangerouslyDisableSandbox

---

## Fase 7 — ML Local para Detección de Amenazas

**Goal:** Modelo pequeño (<100MB, <10ms inferencia) que clasifica comandos y secuencias como benignos/sospechosos/maliciosos.

| Componente | Implementación |
|---|---|
| **Modelo base** | `tract` (ONNX runtime en Rust) con modelo tipo `microsoft/codebert-base` o `qwen2.5-coder-0.5b` quantizado (INT8). Alternativa: `candle` con pesos GGUF |
| **Clasificador de comandos** | Modelo secuencial: tokenize bash command → transformer encoder → 3-class (benign/suspicious/malicious). Dataset: 50K+ comandos etiquetados |
| **Sequence classifier** | LSTM sobre secuencias de N tool calls. Detecta: reconnaissance → exploitation → exfiltration chain |
| **Feature engineering** | 50+ features heurísticas como input al modelo: entropy del comando, rareza de flags, frecuencia de archivos críticos, hora del día, tasa de error |
| **Ensemble** | Score final = 0.4 * heuristic_engine + 0.4 * ML_classifier + 0.2 * sequence_model |
| **Online learning** | Feedback del usuario (approve/reject) como fine-tuning en caliente via LoRA adapters |
| **Model distribution** | Modelo empaquetado en el binario (incluido vía include_bytes!). Actualización vía plugin/descarga opcional |
| **KPI** | Precisión >95%, recall >90% en detección de ataques. Inferencia <10ms en CPU sin GPU. |

**Penetration test:** 100 ataques reales (Metasploit payloads, reverse shells, crypto miners reales) — >90% detectados.

### Archivos clave
- `localmodels/` crate (ya existe en workspace)
- `runtime/src/heuristic_engine.rs` — integration point con ML scores

---

## Fase 8 — Supply Chain Fortress y SBOM

**Goal:** Cada dependencia es verificada, firmada y escaneada. SLSA Level 3+.

| Componente | Implementación |
|---|---|
| **cargo-deny + cargo-vet** | CI job que verifica: licencias (allowlist), vulnerabilidades (OSV database), confianza (cargo-vet audits). Bloquea PR si hay advisory crítico |
| **SBOM generación** | `cargo cyclonedx` o `cargo sbom` en cada release. Formato: CycloneDX JSON. Incluye: dependencias transitivas, licencias, checksums, vulnerabilidades conocidas |
| **SLSA provenance** | Generar provenance attestation (formato in-toto). Firma con `sigstore` / Fulcio |
| **Dependency fuzzing** | Fuzzear interfaces con dependencias críticas: reqwest, tokio, serde_json. 1h en CI semanal |
| **Vendoring crítico** | Vendorizar dependencias sin alternativas seguras: `ring`, `rustls` (no OpenSSL), `hickory-resolver` (no libc resolv) |
| **Unsafe audit** | Escanear `#![allow(unsafe_code)]` en dependencias. Política: prohibir unsafe en crates de terceros (excepto crypto y FFI) |
| **KPI** | 0 advisories críticos en producción. SBOM generado en cada release. SLSA Level 3. |

**Penetration test:** Simular un advisory crítico en dependencia — CI bloquea el PR en <5min.

### Archivos clave
- `audit.toml` — ignored advisories actuales
- `rust/Cargo.toml` — workspace lints, dependencias
- `.github/` — CI/CD workflows

---

## Fase 9 — Self-Healing Immune System

**Goal:** El sistema se recupera automáticamente de cualquier fallo — crash, corrupción, red caída, OOM — sin perder estado ni datos.

| Componente | Implementación |
|---|---|
| **Session checkpointing** | Checkpoint completo cada 5 tool calls o cada minuto. Formato: snapshot + WAL (write-ahead log). Replay desde último checkpoint válido |
| **Health monitor** | Thread watchdog con heartbeats. Monitorea: runtime thread, worker pool, MCP connections, provider health, disk space, memory usage |
| **Auto-restart por capa** | Si MCP server muere → restart con backoff (1s, 2s, 4s). Si runtime thread crash → recover session desde checkpoint. Si worker pool deadlock → spawn fresh pool |
| **Corruption repair** | Checksums en todos los archivos de estado. Si detecta corrupción: intentar repair desde WAL, fallback a último checkpoint, fallback a sesión nueva |
| **Graceful shutdown** | Signal handler (SIGTERM, SIGINT, SIGHUP): flush audit log, checkpoint session, close MCP connections, zeroize secrets, then exit |
| **Chaos testing** | Semanal: inyectar fallos aleatorios (OOM, network loss, disk full, SIGKILL) y verificar recuperación. Marco: chaosd o litmus |
| **KPI** | Recovery de crash < 1s. 0 pérdida de datos en fallos. Chaos tests: 95%+ recovery rate. |

**Chaos test:** `kill -9` al proceso en medio de una tool call — al reiniciar, la sesión se recupera y la operación se puede reanudar.

### Archivos clave
- `runtime/src/recovery_recipes.rs` — FailureScenario, RecoveryRecipe, RecoveryStep
- `runtime/src/worker_boot.rs` — worker process recovery
- `runtime/src/session.rs` — session persistence
- `enterprise/src/graceful_degradation.rs` — provider fallback
- `runtime/src/mcp_client.rs` — MCP connection management

---

## Fase 10 — Adaptive Security Engine: Auto-Defensa con ML

**Goal:** El sistema aprende, se adapta y evoluciona sus defensas sin intervención humana. Es el sistema inmune definitivo.

| Componente | Implementación |
|---|---|
| **Policy evolution** | Las políticas de seguridad se ajustan automáticamente según: patrón de uso, threat intelligence feed, feedback del usuario, hora del día, tipo de proyecto |
| **Threat intelligence feed** | Consumir feeds OSINT: CVE feeds, known bad IPs/domains (AlienVault OTX, AbuseIPDB), malware hashes. Actualización diaria |
| **Honeytokens** | Sembrar archivos honeypot en el workspace (config/credentials.yml, .env.production, .ssh/id_rsa). Si el agente los lee → threat score += 0.9 |
| **Auto-threshold tuning** | Si false positives > 5%/día → subir umbrales. Si detección rate < 80% → bajar umbrales. Ajuste automático nocturno |
| **Incident response auto** | Si threat score > 0.95: bloquear operación, snapshot del workspace, aislar sesión, registrar incidente, notificar al usuario |
| **Post-mortem automático** | Después de cada incidente: generar reporte con timeline, evidencias, recomendaciones de política |
| **A/B security policies** | Probar dos conjuntos de políticas en paralelo (por sesión), medir FP/FN rate, elegir la mejor automáticamente |
| **KPI** | FP rate < 3%, FN rate < 5%. Tiempo de respuesta a incidentes < 100ms (automático). Mejora semanal de precisión > 1%. |

**Penetration test:** Campaña de 100 ataques simulados durante 1 semana — el sistema debe mejorar su tasa de detección entre día 1 y día 7.

### Archivos clave
- `runtime/src/heuristic_engine.rs` — core engine (nuevo)
- `runtime/src/permissions.rs` — PermissionMode, permission escalation
- `runtime/src/permission_enforcer.rs` — authorization
- `runtime/src/trust_resolver.rs` — TrustPolicy

---

## Resumen de Métricas y KPIs

| Métrica | Objetivo | Fase |
|---------|----------|------|
| Secretos en texto plano | 0 | 1 |
| Path traversal bypass | 0% en fuzzing 24h | 2 |
| Detección de ataques (heurística) | >95% con <5% FP | 3 |
| Fallos en cascada | 0 | 4 |
| Tool calls auditadas | 100% | 5 |
| Sandbox escapes | 0 | 6 |
| Detección ML de ataques | >90% recall | 7 |
| Advisories críticos en prod | 0 | 8 |
| Recovery de crash | <1s | 9 |
| FP rate final | <3% | 10 |

---

## Matriz de Tecnologías por Fase

| Tecnología | Fase | Propósito |
|---|---|---|
| `XChaCha20Poly1305` + `Argon2id` | 1 | Cifrado de credenciales |
| `TPM 2.0` / `SOFTHSM2` | 1 | Clave maestra hardware-backed |
| `cargo-fuzz` | 2 | Fuzzing continuo de inputs |
| `Seccomp BPF` | 6 | Restricción de syscalls |
| `Landlock` | 6 | Filesystem isolation |
| `cgroup2` | 6 | Resource limits |
| `NSJail` | 6 | Sandbox container |
| `tract` / `candle` | 7 | ONNX runtime en Rust |
| `LoRA adapters` | 7 | Fine-tuning en caliente |
| `cargo-deny` / `cargo-vet` | 8 | Supply chain security |
| `sigstore` / `Fulcio` | 8 | SLSA provenance |
| `CycloneDX` | 8 | SBOM generation |
| `chaosd` / `litmus` | 9 | Chaos engineering |
| `AlienVault OTX` | 10 | Threat intelligence |
| `LoRA` | 10 | Online policy learning |

---

## Temas Transversales

### Testing
- Tests de penetración automatizados por fase
- Fuzz testing de inputs de herramientas (cargo-fuzz)
- Property-based testing para políticas de permisos
- Chaos engineering semanal (chaosd/litmus)
- Benchmarks de rendimiento con nuevas capas de seguridad

### Documentación
- Documentación de seguridad por fase
- Guía de configuración segura
- Playbook de respuesta a incidentes
- Políticas de retención y privacidad

### Métricas globales
- Tiempo medio entre fallos (MTBF)
- Tiempo medio de recuperación (MTTR)
- Falsos positivos / falsos negativos del heuristic engine
- Cobertura de tests de seguridad
- Latencia añadida por las capas de seguridad
