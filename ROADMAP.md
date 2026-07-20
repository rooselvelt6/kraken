# Kraken v2.0 — Roadmap Consolidado

> **Visión:** Plataforma de ciberseguridad ofensiva todo-en-uno en Rust, con análisis de kernel Mythos-level, 8 LLMs frontier (incluye Kimi K3 1M context), y agente autónomo.
>
> **Stack:** 35 crates · ~210K líneas · 378+ tests unitarios + 74 doc-tests · 0 unsafe · 0 clippy warnings

---

## Estado Actual

| Módulo | Líneas | Estado | Notas |
|--------|--------|--------|-------|
| Runtime + Tools | 1295+ | ✅ Producción | CLI completo, 82 slash commands del CLI |
| API/LLM (7 providers) | 1318+ | ✅ Producción | Anthropic, OpenAI, DeepSeek, Groq, Mistral, Google, Ollama |
| Seguridad (crypto/vault/audit) | 1400+ | ✅ Producción | AES-256-GCM, key rotation, memory locking |
| Forensics (10 módulos) | 3300+ | ✅ Sólido | PCAP, memory, disk, browser, email, registry, timeline, YARA |
| VulnScan core + pipeline | 4000+ | ✅ Sólido | 3 modos: Fast/Deep/Overnight |
| Kernel analysis (6 fases) | 6000+ | ✅ Completo | 14 AST checkers, 4 LLM classes, 4 chain types |
| Exploit engine | 1810 | ⚠️ Parcial | Linux x64 real, ARM/ARM64/Win/Mac placeholders |
| Local ML | 1300+ | ⚠️ Parcial | Pesos hand-tuned, no entrenado |
| C2 | 500+ | ⚠️ Parcial | HTTP beacon funcional, SMB/DNS stubs |
| Wireless | 1000+ | ⚠️ Parcial | WiFi scan real, deauth/beacon fire-and-forget |
| Hardware/IoT | 800+ | ⚠️ Parcial | Firmware analysis real, GPIO/JTAG stubs |
| Supply chain | 600+ | ⚠️ Parcial | Typosquat + OSV, sin SBOM/graph/trust |

---

## Lo Completado

### Roadmap-100 (Fases A-E)
| Fase | Estado | Detalle |
|------|--------|---------|
| A. Quality Purge | ✅ | 0 clippy warnings, 164 archivos |
| B. Testing Deepening | ⏳ | Pendiente (5000+ tests) |
| C. AST Profundo | ✅ | 11 checkers AST tree-sitter |
| D. Fuzzing & Sanitizers | ✅ | syzkaller, KASAN/KCSAN/KMSAN, crash triage |
| E. Madurez Comercial | ✅ | CI/CD, releases, Cosign, Docker, Homebrew |

### Roadmap-2079 (Fases 21-26)
| Fase | Estado | Detalle |
|------|--------|---------|
| 21. Kernel Foundations | ✅ | Language enum, kconfig, mitigations |
| 22. Kernel Static Patterns | ✅ | 14 checkers AST, 103 tests |
| 23. LLM Kernel Classes | ✅ | 4 clases kernel, KernelBuildContext |
| 24. Kernel Pipeline & Agent | ✅ | ScanPhase::KernelAnalysis, kernel-aware agent |
| 25. Kernel Exploitation | ✅ | PhysmapSpray, DirtyPipe, BPF, modprobe_path |
| 26. Fuzzing & Sanitizers | ✅ | syzkaller wrapper, 3 sanitizer parsers |

**Total features completadas: ~53**

---

## Stubs/TODOs Identificados (24 reales)

| # | Crate | Archivo | Problema |
|---|-------|---------|----------|
| 1 | `vulnscan` | `exploit.rs:122` | WIN_X64_WINEXEC = padding placeholder |
| 2 | `vulnscan` | `exploit.rs:184,189,190` | ARM/ARM64 gadgets = texto descriptivo |
| 3 | `vulnscan` | `exploit.rs:294-308` | Reverse/bind shells x64 = ASCII placeholder |
| 4 | `vulnscan` | `exploit.rs:500,583` | Shell fallbacks para OS/arch no soportados = TODO |
| 5 | `vulnscan` | `exploit.rs:680-683` | XOR decoder non-x64 = ASCII placeholder |
| 6 | `vulnscan` | `exploit.rs:1096,1104` | Metasploit template con TODO markers |
| 7 | `vulnscan` | `fuzz.rs:68-69` | Fuzz target generator = `let _ = data` |
| 8 | `vulnscan` | `kernel/fuzz.rs:582-585` | Kernel PoC body vacío |
| 9 | `mobile` | `frida.rs:285,296` | Frida scripts = placeholder log |
| 10 | `sandbox` | `platform_windows.rs:70-71` | AppContainer = warn + return Ok |
| 11 | `runtime` | `lsp_client.rs:285-296` | LSP dispatch = JSON placeholder |
| 12 | `c2` | `beacon_smb.rs:82-84` | SMB beacon = error en non-Windows |
| 13 | `c2` | `proxy.rs:127-131` | DNS proxy test = error |
| 14 | `network` | `web.rs:841-853` | detect_wp_plugins/detect_cms_themes = vec vacío |
| 15 | `network` | `web.rs:833-839` | detect_cms_plugins ignora URL |
| 16 | `forensics` | `network.rs:187` | Byte-swap flag computado pero no usado |
| 17 | `rusty-claude-cli` | `main.rs:8430-8541` | 82 slash commands registrados sin implementar |
| 18 | `rusty-claude-cli` | `main.rs:1330` | OMC/plugin loading no implementado |
| 19 | `rusty-claude-cli` | `main.rs:6362` | ACP/Zed integration = no-op |

---

## Fase 1: Foundation — Cerrar Deuda Técnica

**Objetivo:** Eliminar todos los stubs reales, implementar shellcode multi-arch, generar fuzz targets funcionales, y agregar tests de integración.

**Esfuerzo:** 1-2 semanas

### 1.1 Shellcode Multi-Arch (exploit.rs)
- [ ] Linux ARM reverse shell real (syscall-based)
- [ ] Linux ARM64 reverse shell real
- [ ] Windows x64 WinExec real (PE header + shellcode)
- [ ] macOS x64/ARM64 reverse shell real
- [ ] Reverse shell genérico x64 Linux real (syscall `connect+dup2+execve`)
- [ ] Bind shell genérico x64 Linux real
- [ ] XOR decoder para ARM/ARM64
- [ ] ROP gadgets reales para ARM/ARM64

### 1.2 Fuzz Target Generator (fuzz.rs)
- [ ] Generar fuzz target C real con `LLVMFuzzerTestOneInput`
- [ ] Parsear función objetivo del source code
- [ ] Generar harness que llama a la función con datos fuzzed
- [ ] Soporte para structs de entrada

### 1.3 Kernel PoC Generator (kernel/fuzz.rs)
- [ ] Generar PoC C que mapea kernel symbols de `/proc/kallsyms`
- [ ] Trigger real basado en crash type (UAF/OOB/overflow)
- [ ] Incluir setup de /dev/ para kernel exploits

### 1.4 Frida Scripts (mobile/frida.rs)
- [ ] SSL bypass real para Android (SSLContext bypass)
- [ ] Root bypass real para Android (SU detection bypass)
- [ ] Pinning bypass para iOS

### 1.5 Metasploit Templates (exploit.rs)
- [ ] Template sin TODO markers
- [ ] Auto-fill de target info

### 1.6 Tests de Integración (50+)
- [ ] Pipeline completo: recon → scan → exploit → report (10 tests)
- [ ] VulnScan → Chaining → Exploit generation (10 tests)
- [ ] API providers round-trip mock (10 tests)
- [ ] Kernel analysis end-to-end (10 tests)
- [ ] C2 beacon → command → response (5 tests)
- [ ] Supply chain scan → finding (5 tests)

---

## Fase 2: Intelligence — Kimi K3 + Innovación

**Objetivo:** Integrar Kimi K3 como 8vo provider, pipeline de 1M context, program-slice analysis, multi-agent.

**Esfuerzo:** 1-2 semanas

### 2.1 Kimi K3 Integration (api/)
- [ ] Provider `Kimi` en enum (OpenAI-compatible)
- [ ] Client con 1M context window
- [ ] Pricing: $0.30/MTok cached, $0.60/MTok input
- [ ] Benchmark vs DeepSeek en cyber tasks

### 2.2 1M Context Pipeline
- [ ] Chunker de codebase completo por relevancia
- [ ] Program-slice analysis: call graph → focused prompts
- [ ] Selective context: enviar solo lo relevante al LLM
- [ ] Cache de contexto para re-análisis

### 2.3 Program-Slice Analysis
- [ ] Call graph builder con tree-sitter
- [ ] Slice extractor: dada una función, extraer todo lo necesario
- [ ] Risk-ranked slices: primero los más peligrosos
- [ ] Integration con kernel patterns

### 2.4 Multi-Agent Research
- [ ] Meta-agente que coordina sub-agentes
- [ ] Sub-agente 1: Static analysis
- [ ] Sub-agente 2: LLM semantic analysis
- [ ] Sub-agente 3: Exploit generation
- [ ] Cross-validation entre agentes

---

## Fase 3: Supply Chain + Compliance

**Objetivo:** SBOM, dependency graph, compliance, MCP trust.

**Esfuerzo:** 1 semana

### 3.1 SBOM Generation
- [ ] CycloneDX format
- [ ] SPDX format
- [ ] Dependency tree completo
- [ ] License compliance check

### 3.2 Dependency Risk Scoring
- [ ] Graph de dependencias
- [ ] Risk score por dependencia (edad, mantenimiento, CVEs)
- [ ] Transitive dependency analysis
- [ ] Visualización del grafo

### 3.3 MCP Trust Scoring
- [ ] Evaluar seguridad de MCP servers
- [ ] Permissions audit
- [ ] Data flow analysis
- [ ] Trust score generation

### 3.4 Compliance
- [ ] CIS benchmarks para Linux
- [ ] CIS benchmarks para Docker
- [ ] Dockerfile best practices
- [ ] Kubernetes security baselines

---

## Fase 4: Offensive Depth — C2, Wireless, Firmware

**Objetivo:** C2 funcional, malleable profiles, WiFi real, firmware analysis con LLM.

**Esfuerzo:** 2 semanas

### 4.1 C2 Server
- [ ] HTTP beacon funcional (ya existe parcialmente)
- [ ] WebSocket beacon
- [ ] DNS beacon
- [ ] Malleable C2 profiles (tipo Cobalt Strike)
- [ ] Encrypted comms (AES-256-GCM)

### 4.2 Wireless
- [ ] WiFi handshake capture real (aircrack-ng integration)
- [ ] Bluetooth LE enumeration
- [ ] Deauthentication real (aireplay-ng)
- [ ] Evil twin AP

### 4.3 Firmware Analysis
- [ ] Firmware extraction (binwalk integration)
- [ ] Filesystem analysis
- [ ] Hardcoded credentials detection
- [ ] LLM-powered firmware audit

### 4.4 Metasploit Integration
- [ ] Generar módulos Metasploit funcionales
- [ ] Auto-configurar target
- [ ] Session management

---

## Fase 5: Enterprise — Dashboard, MCP Server, Reporting

**Objetivo:** Dashboard en vivo, reportes PDF, MCP tool server, CLI polish.

**Esfuerzo:** 1 semana

### 5.1 Dashboard en Vivo
- [ ] WebSocket streaming de findings en tiempo real
- [ ] Gráfico de progreso de scan
- [ ] Mapa de calor de vulnerabilidades
- [ ] Historial de scans

### 5.2 Reportes PDF
- [ ] Template profesional
- [ ] Executive summary
- [ ] Technical details
- [ ] Remediation steps
- [ ] Charts y graphs

### 5.3 MCP Tool Server
- [ ] Kraken como herramienta MCP para otros agents
- [ ] Exponer: scan, analyze, exploit, report
- [ ] Authentication y rate limiting

### 5.4 CLI Polish
- [ ] Colores consistentes
- [ ] Progress bars reales
- [ ] Output formatting
- [ ] Error messages helpful

---

## Métricas de Éxito

| Métrica | Actual | v2.0 Target |
|---------|--------|-------------|
| LLM providers | 7 | 8 (+Kimi K3) |
| Shellcode architectures | 1 (Linux x64) | 6 |
| Tests de integración | 0 | 50+ |
| Stubs/TODOs reales | ~24 | 0 |
| Supply chain features | 2 | 8 |
| C2 transports | 1 (HTTP) | 4 |
| Compliance frameworks | 0 | 3 |
| Slash commands implemented | 0/82 | 10+ |

---

## Timeline

| Semana | Fase | Entregable |
|--------|------|------------|
| 1-2 | F1: Foundation | Shellcode multi-arch, fuzz generator, kernel PoC, 50+ tests |
| 3-4 | F2: Intelligence | Kimi K3, 1M context, program-slice, multi-agent |
| 5 | F3: Supply Chain | SBOM, dependency graph, compliance, MCP trust |
| 6-7 | F4: Offensive | C2 server, malleable profiles, WiFi real, firmware LLM |
| 8 | F5: Enterprise | Dashboard, PDF reports, MCP server, CLI polish |
