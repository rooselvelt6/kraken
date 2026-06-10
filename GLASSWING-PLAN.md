# Plan Kraken — Seguridad Ofensiva

Funciones para elevar el nivel del sistema de seguridad de kraken.

---

## Diagnóstico actual

| Aspecto | Estado |
|---------|--------|
| `vulnscan` crate existe | ✅ En `crates/vulnscan/` |
| Integrado al workspace | ✅ Vía `crates/*` |
| Integrado a tools/CLI | ❌ No es dependencia de `tools`, `commands`, ni `rusty-claude-cli` |
| Usa solo Ollama | ❌ `agent.rs` hardcodea `llama3.2` local |
| Tree-sitter AST | ✅ C, C++, Rust, Python, Ruby, JS |
| Generación de exploits | ❌ No existe |
| Chaining de bugs | ❌ No existe |
| Reverse engineering | ❌ No existe |
| Triage pipeline | ❌ No existe |

---

## Fase 1 — Mejoras inmediatas (bajo esfuerzo, alto impacto)

| # | Archivo | Qué hacer |
|---|---------|-----------|
| 1.1 | `vulnscan/src/lib.rs` | Extender `Finding` con `exploit_code: Option<String>`, `exploit_type: Option<String>` (ROP, heap_spray, privilege_escalation), `chained_findings: Vec<String>`, `poC_validated: bool` |
| 1.2 | `vulnscan/src/agent.rs` | Reemplazar `VulnerabilityAgent` hardcodeado a Ollama por un `SecurityAgent` que use el `api` crate (DeepSeek, BigPickle, Ollama). Añadir config de provider vía `ScanConfig` |
| 1.3 | `vulnscan/src/agent.rs` | Implementar `build_kraken_prompt()` mejorado: contexto CWE, severity-estimation, solicitud de exploit PoC, formato estructurado de salida |
| 1.4 | `vulnscan/src/scan.rs` | Añadir `rank_files_by_bug_probability()` — antes de escanear, pedir al LLM rankear archivos 1-5 |
| 1.5 | `vulnscan/src/scan.rs` | Añadir `validate_findings()` — segundo pase del LLM para confirmar hallazgos |
| 1.6 | `vulnscan/src/db.rs` | Migrar de SQLite in-memory a persistente (`.kraken/vulnscan/db/`). Añadir columnas: `severity_confidence`, `discovery_method`, `validated`, `status` (open/fixed/patched), `cve_id`, `cvss_score`, `exploitability` |
| 1.7 | `vulnscan/src/report.rs` | Añadir reportes HTML (Kraken-style) con gráficos de severidad, CVSS scoring, timeline de descubrimiento |
| 1.8 | `vulnscan/Cargo.toml` | Añadir `api` como dependencia (para multi-provider LLM) |
| 1.9 | `crates/tools/src/` | Crear tool `vulnerability_scan` que expone el escáner como comando `/vulnscan` |
| 1.10 | `crates/commands/src/` | Crear comando `/bughunter` que ejecuta escaneo completo con todas las fases |
| 1.11 | `rusty-claude-cli/src/` | Integrar `--vulnscan` flag para escaneo directo desde CLI |
| 1.12 | `Cargo.toml` (workspace) | Añadir `vulnscan` a dependencias de tools y CLI si no está ya |
| 1.13 | `vulnscan/src/analyzers/` | Añadir analizador para Go, Java, y Swift (lenguajes de infraestructura crítica) |
| 1.14 | `vulnscan/src/crypto.rs` (nuevo) | Analizador de vulnerabilidades criptográficas (TLS, AES-GCM, SSH logic) |

---

## Fase 2 — Seguridad ofensiva-defensiva

| # | Archivo | Qué hacer |
|---|---------|-----------|
| 2.1 | `vulnscan/src/exploit.rs` (nuevo) | Módulo de **generación autónoma de exploits**. Usar LLM para generar PoC funcionales: ROP chains, heap sprays, shellcode. Estructura: `ExploitGenerator` con métodos `generate_rop_chain()`, `generate_heap_spray()`, `generate_privilege_escalation()` |
| 2.2 | `vulnscan/src/chaining.rs` (nuevo) | Módulo de **encadenamiento de vulnerabilidades**. Detecta cuando múltiples hallazgos pueden combinarse (ej: KASLR bypass + heap write → root). Algoritmo: grafo de dependencias entre findings |
| 2.3 | `vulnscan/src/agent.rs` | Añadir `generate_exploit()` al SecurityAgent — dado un finding, pedir al LLM que genere exploit completo |
| 2.4 | `vulnscan/src/agent.rs` | Añadir `overnight_bughunt()` — modo autónomo: rankea → escanea → valida → explota → reporta. Corre en background y guarda resultados |
| 2.5 | `vulnscan/src/logic.rs` (nuevo) | Analizador de **vulnerabilidades lógicas**: bypass de autenticación, business logic flaws, CSRF, SSRF, IDOR |
| 2.6 | `vulnscan/src/supply_chain.rs` (nuevo) | Análisis profundo de supply chain: grafo de dependencias, versiones vulnerables, sugerencias de actualización |
| 2.7 | `vulnscan/src/secrets.rs` (nuevo) | Detección de secretos hardcodeados: API keys, tokens, passwords, private keys (usando regex + entropía) |
| 2.8 | `vulnscan/src/scan.rs` | Añadir `prioritize_exploitable()` — ordena findings por explotabilidad estimada |

---

## Fase 3 — Funciones avanzadas

| # | Archivo | Qué hacer |
|---|---------|-----------|
| 3.1 | `vulnscan/src/reverse.rs` (nuevo) | **Reverse engineering** de binarios: usar LLM para reconstruir pseudo-source, luego escanear el pseudo-source. Soporte para ELF, PE, Mach-O |
| 3.2 | `vulnscan/src/sandbox.rs` (nuevo) | Integración con `sandbox` crate para **escaneo en contenedores aislados**. Lanzar container Docker/Podman, copiar código, ejecutar scan, extraer resultados |
| 3.3 | `vulnscan/src/disclosure.rs` (nuevo) | **Pipeline de divulgación responsable**: generar SHA-3 commitments, CVSS scoring, templates de reporte para maintainers, tracking de status (reported → accepted → patched → public) |
| 3.4 | `vulnscan/src/agent.rs` | Añadir `generate_patch()` — dado un finding y proof-of-concept, generar código de fix listo para PR |
| 3.5 | `vulnscan/src/fuzz.rs` (nuevo) | **Fuzzing inteligente**: usar LLM para guiar AFL/libFuzzer hacia rutas de código prometedoras, analizar crashes, clasificar severity |
| 3.6 | `vulnscan/src/mitigation.rs` (nuevo) | Verificador de **defense-in-depth**: detectar si ASLR, stack canaries, RELRO, PIE, CFI están habilitados. Sugerir hardening flags |
| 3.7 | `vulnscan/src/webapp.rs` (nuevo) | Escáner de **aplicaciones web**: SQLi, XSS, CSRF, SSRF, XXE, open redirect, template injection. Versión simplificada de un web scanner |
| 3.8 | `vulnscan/src/container.rs` (nuevo) | Escáner de **seguridad en contenedores**: Dockerfile analysis, image layer scanning, misconfiguraciones, privileged mode detection |

---

## Arquitectura de integración

```
┌─────────────────────────────────────────────────────────────────┐
│                      kraken CLI                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  /vulnscan [paths]  |  /bughunter  |  --vulnscan         │  │
│  └──────────┬────────────────────────────────────────────────┘  │
│             │                                                    │
│  ┌──────────▼────────────────────────────────────────────────┐  │
│  │  tools crate → vulnscan_tool.rs                           │  │
│  │  Usa runtime para orquestación + api para LLM providers   │  │
│  └──────────┬────────────────────────────────────────────────┘  │
│             │                                                    │
│  ┌──────────▼────────────────────────────────────────────────┐  │
│  │  vulnscan crate                                            │  │
│  │  ┌──────────┬───────────┬──────────┬──────────┬────────┐  │  │
│  │  │ scan.rs  │ agent.rs  │exploit.rs│ reverse  │ fuzz.rs│  │  │
│  │  │ chaining │ disclosure│ sandbox  │ logic.rs │ webapp │  │  │
│  │  └──────────┴───────────┴──────────┴──────────┴────────┘  │  │
│  │  ┌──────────────────────────────────────────────────────┐  │  │
│  │  │ api crate (DeepSeek, BigPickle, Ollama, Anthropic)   │  │  │
│  │  │ security crate (encryption, audit)                   │  │  │
│  │  │ sandbox crate (container isolation)                  │  │  │
│  │  └──────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Nuevas dependencias

| Crate | Para qué |
|-------|----------|
| `api` (ya existe) | Multi-provider LLM (Fase 1.2) |
| `sandbox` (ya existe) | Aislamiento de contenedores (Fase 3.2) |
| `sha3` | Commitment hashing para disclosure (Fase 3.3) |
| `goblin` o `object` | Parsing de binarios ELF/PE (Fase 3.1) |
| `capstone` | Disassembly para reverse engineering (Fase 3.1) |

---

## Esfuerzo estimado

| Fase | Items | Esfuerzo | Impacto |
|------|-------|----------|---------|
| **Fase 1** | 14 | Bajo (días) | Alto — uso diario |
| **Fase 2** | 8 | Medio (1-2 semanas) | Alto — capacidades únicas |
| **Fase 3** | 8 | Alto (2-4 semanas) | Medio — nicho pero potente |
