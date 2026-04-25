# 🦞 Claw Code Venezuela

<p align="center">
  <a href="https://github.com/rooselvelt6/claw-vzla">rooselvelt6/claw-vzla</a>
  ·
  <a href="./USAGE.md">Usage</a>
  ·
  <a href="./rust/README.md">Rust workspace</a>
  ·
  <a href="./PARITY.md">Parity</a>
  ·
  <a href="./ROADMAP.md">Roadmap</a>
  ·
  <a href="./docs/GRATIS.md">Modelos Gratuitos</a>
  ·
  <a href="https://discord.gg/5TUQKqFWd">Discord</a>
</p>

<p align="center">
  <img src="assets/claw-hero.jpeg" alt="Claw Code Venezuela" width="300" />
</p>

## 🇻🇪 Para Venezuela

Este es un fork de **Claw Code** adaptado para usuarios venezolanos y países con restricciones.

### ✨ Características especiales para Venezuela

| Característica | Descripción |
|----------------|-------------|
| **Modelos gratuitos** | DeepSeek (5M tokens gratis), Big Pickle, Ollama local |
| **Sin dependencia USD** | Modelos económicos que no requieren dólares |
| **Adaptado para LATAM** | Documentación en español, proveedores chinos |
| **100% compatible** | Mantiene compatibilidad con el upstream |

---

## Modelos Soportados

### Modelos Gratuitos/Económicos

| Modelo | Costo | Contexto | Uso recomendado |
|--------|-------|----------|-----------------|
| **DeepSeek V3** | 5M gratis, luego $0.14/M | 128K | Chat general |
| **DeepSeek R1** | 5M gratis, luego $0.55/M | 128K | Razonamiento |
| **DeepSeek Coder** | $0.28/M input | 64K | Programación |
| **Big Pickle** | Gratis* | 200K | Coding |
| **Ollama local** | Gratis | Variable | Offline |

### Modelos Originales

| Modelo | Proveedor | Costo |
|--------|-----------|-------|
| Claude (opus/sonnet/haiku) | Anthropic | Pago |
| Grok (grok-3) | xAI | Pago |
| Qwen (qwen-max) | DashScope | Pago |
| Kimi (kimi-k2.5) | DashScope | Pago |

---

## Inicio Rápido

### Opción 1: DeepSeek (Recomendado)

```bash
# 1. Clonar y construir
git clone https://github.com/rooselvelt6/claw-vzla
cd claw-vzla/rust
cargo build --workspace

# 2. Configurar DeepSeek (5M tokens gratis)
# Regístrate en https://platform.deepseek.com
export DEEPSEEK_API_KEY="sk-tu-api-key"

# 3. Usar DeepSeek
./target/debug/claw --model deepseek prompt "hola"

# O usar R1 para razonamiento
./target/debug/claw --model r1 prompt "resuelve esto"
```

### Opción 2: Big Pickle (Gratis)

```bash
# Configurar OpenCode Zen
export OPENCODE_API_KEY="tu-api-key"  # Obténla en https://opencode.ai/zen

./target/debug/claw --model big-pickle prompt "crea un API REST"
```

### Opción 3: Ollama Local

```bash
# Instalar Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Descargar modelos
ollama pull qwen2.5-coder:7b
ollama pull deepseek-coder:6.7b

# Configurar
export OPENAI_BASE_URL="http://localhost:11434/v1"
export OPENAI_API_KEY="ollama"

# Usar modelo local
./target/debug/claw --model qwen2.5-coder:7b prompt "hola"
```

---

## Configuración de Variables de Entorno

### Modelos DeepSeek
```bash
export DEEPSEEK_API_KEY="sk-..."
export DEEPSEEK_BASE_URL="https://api.deepseek.com/v1"  # opcional
```

### Modelos OpenCode (Big Pickle)
```bash
export OPENCODE_API_KEY="tu-api-key"
export OPENCODE_BASE_URL="https://opencode.ai/zen/v1"  # opcional
```

### Ollama / OpenAI Compatible
```bash
export OPENAI_BASE_URL="http://localhost:11434/v1"
export OPENAI_API_KEY="ollama"  # o tu API key
```

### Modelos Originales (Anthropic)
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## Alias de Modelos Disponibles

```bash
# DeepSeek
claw --model deepseek        # deepseek-chat
claw --model r1              # deepseek-reasoner
claw --model deepseek-r1     # deepseek-reasoner
claw --model deepseek-coder  # deepseek-coder

# OpenCode
claw --model big-pickle      # Big Pickle (GLM-4.6)

# Anthropic
claw --model opus            # claude-opus-4-6
claw --model sonnet          # claude-sonnet-4-6
claw --model haiku           # claude-haiku-4-5-20251213

# xAI
claw --model grok            # grok-3
claw --model grok-mini       # grok-3-mini

# DashScope (Qwen/Kimi)
claw --model qwen-max        # Qwen max
claw --model kimi            # Kimi k2.5
```

---

## Comandos Útiles

```bash
# Verificar configuración
./target/debug/claw doctor

# Estado del sistema
./target/debug/claw status

# Usar modelo específico
./target/debug/claw --model deepseek prompt "tu prompt aquí"

# Salida JSON para scripting
./target/debug/claw --output-format json status
```

---

## Documentación

| Archivo | Descripción |
|---------|-------------|
| [`USAGE.md`](./USAGE.md) | Guía de uso completa |
| [`docs/GRATIS.md`](./docs/GRATIS.md) | Guía de modelos gratuitos para Venezuela |
| [`rust/README.md`](./rust/README.md) | Documentación técnica |
| [`PARITY.md`](./PARITY.md) | Estado del puerto a Rust |
| [`ROADMAP.md`](./ROADMAP.md) | Hoja de ruta del proyecto |

---

## Diferencias con el Original

Este fork incluye:

1. ✅ **Proveedor DeepSeek** - Modelos económicos (5M tokens gratis)
2. ✅ **Proveedor OpenCode Zen** - Big Pickle gratuito
3. ✅ **Soporte Ollama** - Modelos locales gratis
4. ✅ **Documentación en español** - README.es.md, docs/GRATIS.md
5. ✅ **Alias de modelos** - deepseek, r1, big-pickle, etc.

---

## Requisitos

- **Rust** (1.70+): https://rustup.rs/
- **Git**
- **API Key** del proveedor elegido

---

## Solución de Problemas

### "Missing API key"
Asegúrate de tener la variable correcta:
```bash
# Verifica que está configurada
echo $DEEPSEEK_API_KEY
```

### "Connection refused" (Ollama)
```bash
# Inicia Ollama primero
ollama serve
```

### Necesitas VPN?
Algunos proveedores pueden requerir VPN desde Venezuela. DeepSeek generalmente funciona sin VPN.

---

## Comparativa de Precios (USD)

| Modelo | Input/M | Output/M | Notas |
|--------|---------|----------|-------|
| Claude 4 Opus | $15.00 | $75.00 | Premium |
| GPT-4o | $2.50 | $10.00 | Pago |
| **DeepSeek V3** | **$0.14** | **$0.28** | 5M gratis |
| **DeepSeek R1** | **$0.55** | **$2.19** | 5M gratis |
| **DeepSeek Coder** | **$0.28** | **$0.56** | Económico |
| **Big Pickle** | **Gratis** | **Gratis** | Límites |

---

## Enlaces Útiles

- [DeepSeek API](https://platform.deepseek.com) - 5M tokens gratis
- [OpenCode Zen](https://opencode.ai/zen) - Big Pickle gratis
- [Ollama](https://ollama.com) - Modelos locales
- [DashScope](https://dashscope.console.aliyun.com) - Qwen/Kimi
- [Rust](https://rustup.rs/) - Instalar Rust

---

## Licencia

Ver repositorio original: [ultraworkers/claw-code](https://github.com/ultraworkers/claw-code)

---

## Notas

- Este es un fork mantenido por la comunidad venezolana
- Compatible con el upstream ultraworkers/claw-code
- Para contribuciones, issues y PRs, usar GitHub