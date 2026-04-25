# 🦞 Claw Code — Implementación en Rust

Una reescritura de alto rendimiento en Rust del harness del agente CLI Claw Code. Construido para velocidad, seguridad y ejecución nativa de herramientas.

Para una guía orientada a tareas con ejemplos de copiar y pegar, consulta [`../USAGE.md`](../USAGE.md).

## Inicio Rápido

```bash
# Inspeccionar comandos disponibles
cd rust/
cargo run -p rusty-claude-cli -- --help

# Construir el workspace
cargo build --workspace

# Ejecutar el REPL interactivo
cargo run -p rusty-claude-cli -- --model claude-opus-4-6

# Prompt de un solo uso
cargo run -p rusty-claude-cli -- prompt "explica esta base de código"

# Salida JSON para automatización
cargo run -p rusty-claude-cli -- --output-format json prompt "resumir src/main.rs"
```

## Configuración

Configura tus credenciales API:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
# O usar un proxy
export ANTHROPIC_BASE_URL="https://tu-proxy.com"
```

O proporciona un token bearer OAuth directamente:

```bash
export ANTHROPIC_AUTH_TOKEN="token-bearer-de-oauth-o-proxy"
```

## Harness de paridad mock

El workspace ahora incluye un servicio mock determinista compatible con Anthropic y un harness CLI de entorno limpio para verificaciones de paridad end-to-end.

```bash
cd rust/

# Ejecutar el harness scriptado de entorno limpio
./scripts/run_mock_parity_harness.sh

# O iniciar el servicio mock manualmente para ejecuciones CLI ad hoc
cargo run -p mock-anthropic-service -- --bind 127.0.0.1:0
```

Cobertura del harness:

- `streaming_text`
- `read_file_roundtrip`
- `grep_chunk_assembly`
- `write_file_allowed`
- `write_file_denied`
- `multi_tool_turn_roundtrip`
- `bash_stdout_roundtrip`
- `bash_permission_prompt_approved`
- `bash_permission_prompt_denied`
- `plugin_tool_roundtrip`

Artefactos principales:

- `crates/mock-anthropic-service/` — servicio mock reutilizable compatible con Anthropic
- `crates/rusty-claude-cli/tests/mock_parity_harness.rs` — harness CLI de entorno limpio
- `scripts/run_mock_parity_harness.sh` — wrapper reproducible
- `scripts/run_mock_parity_diff.py` — lista de verificación de escenarios + ejecutor de mapeo PARITY
- `mock_parity_scenarios.json` — manifest de escenario a PARITY

## Características

| Característica | Estado |
|----------------|--------|
| Flujos compatibles con Anthropic / OpenAI + streaming | ✅ |
| Autenticación directa con token bearer vía `ANTHROPIC_AUTH_TOKEN` | ✅ |
| REPL interactivo (rustyline) | ✅ |
| Sistema de herramientas (bash, read, write, edit, grep, glob) | ✅ |
| Herramientas web (search, fetch) | ✅ |
| Superficies de sub-agente / agente | ✅ |
| Seguimiento de tareas | ✅ |
| Edición de notebooks | ✅ |
| CLAUDE.md / memoria del proyecto | ✅ |
| Jerarquía de archivos de configuración (`.claw.json` + secciones de config fusionadas) | ✅ |
| Sistema de permisos | ✅ |
| Ciclo de vida de servidor MCP + inspección | ✅ |
| Persistencia y resumen de sesiones | ✅ |
| Superficies de costo / uso / estadísticas | ✅ |
| Integración con Git | ✅ |
| Renderizado de terminal markdown (ANSI) | ✅ |
| Alias de modelo (opus/sonnet/haiku) | ✅ |
| Subcomandos CLI directos (`status`, `sandbox`, `agents`, `mcp`, `skills`, `doctor`) | ✅ |
| Comandos slash (incluyendo `/skills`, `/agents`, `/mcp`, `/doctor`, `/plugin`, `/subagent`) | ✅ |
| Hooks (`/hooks`, hooks de ciclo de vida respaldados por configuración) | ✅ |
| Superficies de gestión de plugins | ✅ |
| Superficie de inventario/instalación de skills | ✅ |
| Salida JSON legible por máquina a través de las superficies CLI principales | ✅ |

## Alias de Modelo

Los nombres cortos se resuelven a las últimas versiones de modelo:

| Alias | Se Resuelve a |
|-------|---------------|
| `opus` | `claude-opus-4-6` |
| `sonnet` | `claude-sonnet-4-6` |
| `haiku` | `claude-haiku-4-5-20251213` |

## Flags y Comandos CLI

Superficie actual representativa:

```text
claw [OPTIONS] [COMMAND]

Flags:
  --model MODEL
  --output-format text|json
  --permission-mode MODE
  --dangerously-skip-permissions
  --allowedTools TOOLS
  --resume [SESSION.jsonl|session-id|latest]
  --version, -V

Comandos de nivel superior:
  prompt <text>
  help
  version
  status
  sandbox
  acp [serve]
  dump-manifests
  bootstrap-plan
  agents
  mcp
  skills
  system-prompt
  init
```

`claw acp` es una superficie de descubrimiento local para usuarios editor-first: reporta el estado actual de ACP/Zed sin iniciar el runtime. A partir del 16 de abril de 2026, claw-code **todavía no** incluye un punto de entrada de daemon ACP/Zed, y `claw acp serve` es solo un alias de estado hasta que la superficie real del protocolo llegue.

La superficie de comandos está cambiando rápidamente. Para el texto de ayuda canónico en vivo, ejecuta:

```bash
cargo run -p rusty-claude-cli -- --help
```

## Comandos Slash (REPL)

La tabulación completa expande comandos slash, alias de modelo, modos de permisos y IDs de sesión recientes.

El REPL ahora expone una superficie mucho más amplia que el shell original mínimo:

- sesión / visibilidad: `/help`, `/status`, `/sandbox`, `/cost`, `/resume`, `/session`, `/version`, `/usage`, `/stats`
- workspace / git: `/compact`, `/clear`, `/config`, `/memory`, `/init`, `/diff`, `/commit`, `/pr`, `/issue`, `/export`, `/hooks`, `/files`, `/release-notes`
- descubrimiento / depuración: `/mcp`, `/agents`, `/skills`, `/doctor`, `/tasks`, `/context`, `/desktop`
- automatización / análisis: `/review`, `/advisor`, `/insights`, `/security-review`, `/subagent`, `/team`, `/telemetry`, `/providers`, `/cron`, y más
- gestión de plugins: `/plugin` (con alias `/plugins`, `/marketplace`)

Superficies claw-first notables ahora disponibles directamente en forma slash:
- `/skills [list|install <path>|help]`
- `/agents [list|help]`
- `/mcp [list|show <server>|help]`
- `/doctor`
- `/plugin [list|install <path>|enable <name>|disable <name>|uninstall <id>|update <id>]`
- `/subagent [list|steer <target> <msg>|kill <id>]`

Consulta [`../USAGE.md`](../USAGE.md) para ejemplos de uso y ejecuta `cargo run -p rusty-claude-cli -- --help` para la lista canónica de comandos en vivo.

## Estructura del Workspace

```text
rust/
├── Cargo.toml              # Raíz del workspace
├── Cargo.lock
└── crates/
    ├── api/                # Clientes de provider + streaming + prefiltro de solicitud
    ├── commands/           # Registro compartido de comandos slash + renderizado de ayuda
    ├── compat-harness/     # Harness de extracción de manifestos TS
    ├── mock-anthropic-service/ # Mock determinista compatible con Anthropic
    ├── plugins/            # Metadatos de plugins, manager, superficies de install/enable/disable
    ├── runtime/            # Sesión, config, permisos, MCP, prompts, bucle de auth/runtime
    ├── rusty-claude-cli/   # Binario CLI principal (`claw`)
    ├── telemetry/          # Tipos de trazado de sesión y telemetría
    └── tools/              # Herramientas integradas, resolución de skills, búsqueda de herramientas, superficies de runtime de agente
```

### Responsabilidades de los Crates

- **api** — clientes de providers, streaming SSE, tipos de request/response, autenticación (`ANTHROPIC_API_KEY` + soporte de token bearer), prefiltro de tamaño de solicitud/ventana de contexto
- **commands** — definiciones de comandos slash, parsing, generación de texto de ayuda, renderizado de comandos JSON/texto
- **compat-harness** — extrae tool/prompt manifests desde la fuente TS upstream
- **mock-anthropic-service** — mock determinista de `/v1/messages` para tests de paridad CLI y ejecuciones de harness local
- **plugins** — metadatos de plugins, flujos de install/enable/disable/update, definiciones de herramientas de plugin, superficies de integración de hooks
- **runtime** — `ConversationRuntime`, carga de configuración, persistencia de sesiones, política de permisos, ciclo de vida del cliente MCP, ensamblaje de prompts del sistema, seguimiento de uso
- **rusty-claude-cli** — REPL, prompt de un solo uso, subcomandos CLI directos, display de streaming, renderizado de llamadas de herramientas, parsing de argumentos CLI
- **telemetry** — eventos de trace de sesión y payloads de telemetría soportados
- **tools** — specs + ejecución de herramientas: Bash, ReadFile, WriteFile, EditFile, GlobSearch, GrepSearch, WebSearch, WebFetch, Agent, TodoWrite, NotebookEdit, Skill, ToolSearch, y descubrimiento de herramientas orientado al runtime

## Estadísticas

- **~20K líneas** de Rust
- **9 crates** en el workspace
- **Nombre del binario:** `claw`
- **Modelo por defecto:** `claude-opus-4-6`
- **Permisos por defecto:** `danger-full-access`

## Licencia

Ver raíz del repositorio.