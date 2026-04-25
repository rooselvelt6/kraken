# Claw Code

<p align="center">
  <a href="https://github.com/ultraworkers/claw-code">ultraworkers/claw-code</a>
  ·
  <a href="./USAGE.md">Uso</a>
  ·
  <a href="./rust/README.md">Workspace Rust</a>
  ·
  <a href="./PARITY.md">Paridad</a>
  ·
  <a href="./ROADMAP.md">Hoja de ruta</a>
  ·
  <a href="https://discord.gg/5TUQKqFWd">Discord de UltraWorkers</a>
</p>

<p align="center">
  <a href="https://star-history.com/#ultraworkers/claw-code&Date">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=ultraworkers/claw-code&type=Date&theme=dark" />
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=ultraworkers/claw-code&type=Date" />
      <img alt="Historial de estrellas para ultraworkers/claw-code" src="https://api.star-history.com/svg?repos=ultraworkers/claw-code&type=Date" width="600" />
    </picture>
  </a>
</p>

<p align="center">
  <img src="assets/claw-hero.jpeg" alt="Claw Code" width="300" />
</p>

Claw Code es la implementación pública en Rust del harness del agente CLI `claw`.
La implementación canónica vive en [`rust/`](./rust), y la fuente de verdad actual de este repositorio es **ultraworkers/claw-code**.

> [!IMPORTANT]
> Comienza con [`USAGE.md`](./USAGE.md) para flujos de construcción, autenticación, CLI, sesión y paridad-harness. Haz de `claw doctor` tu primera verificación después de construir, usa [`rust/README.md`](./rust/README.md) para detalles a nivel de crate, lee [`PARITY.md`](./PARITY.md) para el punto de control actual del puerto a Rust, y consulta [`docs/container.md`](./docs/container.md) para el flujo de trabajo container-first.
>
> **Estado de ACP / Zed:** `claw-code` todavía no incluye un punto de entrada de daemon ACP/Zed. Ejecuta `claw acp` (o `claw --acp`) para el estado actual en lugar de adivinar desde la estructura del código fuente; `claw acp serve` actualmente es solo un alias de descubrimiento, y el soporte real de ACP se rastrea por separado en `ROADMAP.md`.

## Estructura actual del repositorio

- **`rust/`** — Workspace canónico de Rust y el binario CLI `claw`
- **`USAGE.md`** — Guía de uso orientada a tareas para la superficie actual del producto
- **`PARITY.md`** — Estado de paridad del puerto a Rust y notas de migración
- **`ROADMAP.md`** — Hoja de ruta activa y backlog de limpieza
- **`PHILOSOPHY.md`** — Intención del proyecto y marco de diseño del sistema
- **`src/` + `tests/`** — Workspace companion de Python/referencia y helpers de auditoría; no es la superficie principal de ejecución

## Inicio rápido

> [!NOTE]
> [!WARNING]
> **`cargo install claw-code` instala la cosa equivocada.** El crate `claw-code` en crates.io es un stub obsoleto que coloca `claw-code-deprecated.exe` — no `claw`. Ejecutarlo solo imprime `"claw-code ha sido renombrado a agent-code"`. **No uses `cargo install claw-code`.** Construye desde el código fuente (este repositorio) o instala el binario upstream:
> ```bash
> cargo install agent-code   # binario upstream — instala 'agent.exe' (Windows) / 'agent' (Unix), NO 'agent-code'
> ```
> Este repositorio (`ultraworkers/claw-code`) es **solo construcción desde código fuente** — sigue los pasos abajo.

```bash
# 1. Clonar y construir
git clone https://github.com/ultraworkers/claw-code
cd claw-code/rust
cargo build --workspace

# 2. Configura tu clave API (clave API de Anthropic — no una suscripción a Claude)
export ANTHROPIC_API_KEY="sk-ant-..."

# 3. Verifica que todo esté conectado correctamente
./target/debug/claw doctor

# 4. Ejecuta un prompt
./target/debug/claw prompt "di hola"
```

> [!NOTE]
> **Windows (PowerShell):** el binario es `claw.exe`, no `claw`. Usa `.\target\debug\claw.exe` o ejecuta `cargo run -- prompt "say hello"` para evitar la búsqueda de ruta.

### Configuración en Windows

**PowerShell es un camino soportado en Windows.** Usa la shell que prefieras. Los problemas comunes de onboarding en Windows son:

1. **Instala Rust primero** — descarga desde <https://rustup.rs/> y ejecuta el instalador. Cierra y reopen tu terminal cuando termine.
2. **Verifica que Rust esté en el PATH:**
   ```powershell
   cargo --version
   ```
   Si esto falla, reopen tu terminal o ejecuta la configuración del PATH desde la salida del instalador de Rust, luego reintenta.
3. **Clonar y construir** (funciona en PowerShell, Git Bash, o WSL):
   ```powershell
   git clone https://github.com/ultraworkers/claw-code
   cd claw-code/rust
   cargo build --workspace
   ```
4. **Ejecutar** (PowerShell — nota el `.exe` y la barra invertida):
   ```powershell
   $env:ANTHROPIC_API_KEY = "sk-ant-..."
   .\target\debug\claw.exe prompt "say hello"
   ```

**Git Bash / WSL** son alternativas opcionales, no requisitos. Si prefieres rutas estilo bash (`/c/Users/you/...` en lugar de `C:\Users\you\...`), Git Bash (incluido con Git para Windows) funciona bien. En Git Bash, el prompt `MINGW64` es esperado y normal — no es una instalación rota.

## Post-construcción: localizar el binario y verificar

Después de ejecutar `cargo build --workspace`, el binario `claw` está construido pero **no** se instala automáticamente en tu sistema. Aquí está dónde encontrarlo y cómo verificar que la construcción fue exitosa.

### Ubicación del binario

Después de `cargo build --workspace` en `claw-code/rust/`:

**Construcción debug (por defecto, compilación más rápida):**
- **macOS/Linux:** `rust/target/debug/claw`
- **Windows:** `rust/target/debug/claw.exe`

**Construcción release (optimizada, compilación más lenta):**
- **macOS/Linux:** `rust/target/release/claw`
- **Windows:** `rust/target/release/claw.exe`

Si ejecutaste `cargo build` sin `--release`, el binario está en la carpeta `debug/`.

### Verificar que la construcción fue exitosa

Prueba el binario directamente usando su ruta:

```bash
# macOS/Linux (build debug)
./rust/target/debug/claw --help
./rust/target/debug/claw doctor

# Windows PowerShell (build debug)
.\rust\target\debug\claw.exe --help
.\rust\target\debug\claw.exe doctor
```

Si estos comandos succeeden, la construcción está funcionando. `claw doctor` es tu primera verificación de salud — valida tu clave API, acceso al modelo y configuración de herramientas.

### Opcional: Agregar al PATH

Si quieres ejecutar `claw` desde cualquier directorio sin la ruta completa, elige una de estas opciones:

**Opción 1: Enlace simbólico (macOS/Linux)**
```bash
ln -s $(pwd)/rust/target/debug/claw /usr/local/bin/claw
```
Luego recarga tu shell y prueba:
```bash
claw --help
```

**Opción 2: Usar `cargo install` (todas las plataformas)**

Construir e instalar en la ubicación predeterminada de Cargo (`~/.cargo/bin/`, que usualmente está en el PATH):
```bash
# Desde el directorio claw-code/rust/
cargo install --path . --force

# Luego desde cualquier lugar
claw --help
```

**Opción 3: Actualizar perfil de shell (bash/zsh)**

Agrega esta línea a `~/.bashrc` o `~/.zshrc`:
```bash
export PATH="$(pwd)/rust/target/debug:$PATH"
```

Recarga tu shell:
```bash
source ~/.bashrc  # o source ~/.zshrc
claw --help
```

### Solución de problemas

- **"command not found: claw"** — El binario está en `rust/target/debug/claw`, pero no está en tu PATH. Usa la ruta completa `./rust/target/debug/claw` o crea un enlace/instala como se indicó arriba.
- **"permission denied"** — En macOS/Linux, podrías necesitar `chmod +x rust/target/debug/claw` si el bit ejecutable no está establecido (raro).
- **Debug vs. release** — Si la construcción es lenta, estás en modo debug (por defecto). Agrega `--release` a `cargo build` para un tiempo de ejecución más rápido, pero la construcción misma tardará 5–10 minutos.

> [!NOTE]
> **Autenticación:** claw requiere una **clave API** (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.) — el inicio de sesión con suscripción a Claude no es un camino de autenticación soportado.

Ejecuta la suite de tests del workspace después de verificar que el binario funciona:

```bash
cd rust
cargo test --workspace
```

## Mapa de documentación

- [`USAGE.md`](./USAGE.md) — comandos rápidos, autenticación, sesiones, configuración, harness de paridad
- [`rust/README.md`](./rust/README.md) — mapa de crates, superficie CLI, características, estructura del workspace
- [`PARITY.md`](./PARITY.md) — estado de paridad para el puerto a Rust
- [`rust/MOCK_PARITY_HARNESS.md`](./rust/MOCK_PARITY_HARNESS.md) — detalles del harness de servicio mock determinista
- [`ROADMAP.md`](./ROADMAP.md) — hoja de ruta activa y trabajo de limpieza abierto
- [`PHILOSOPHY.md`](./PHILOSOPHY.md) — por qué existe el proyecto y cómo se opera

## Ecosistema

Claw Code se construye abiertamente junto con la herramienta más amplia de UltraWorkers:

- [clawhip](https://github.com/Yeachan-Heo/clawhip)
- [oh-my-openagent](https://github.com/code-yeongyu/oh-my-openagent)
- [oh-my-claudecode](https://github.com/Yeachan-Heo/oh-my-claudecode)
- [oh-my-codex](https://github.com/Yeachan-Heo/oh-my-codex)
- [Discord de UltraWorkers](https://discord.gg/5TUQKqFWd)

## Aviso de propiedad / afiliación

- Este repositorio **no** reclama propiedad del material de código fuente original de Claude Code.
- Este repositorio **no está afiliado con, respaldado por, o mantenido por Anthropic**.