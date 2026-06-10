# Modelos Gratuitos para Venezuela

Esta guía te ayuda a configurar modelos de IA gratuitos o económicos en Kraken Code para usuarios en Venezuela.

## Tabla de Comparación

| Modelo | Costo | Contexto | Mejor para |
|--------|-------|----------|------------|
| **DeepSeek V3** | 5M tokens gratis, luego $0.14/M | 128K | Chat general |
| **DeepSeek R1** | 5M tokens gratis, luego $0.55/M | 128K | Razonamiento |
| **DeepSeek Coder** | $0.28/M input | 64K | Programación |
| **Big Pickle** | Gratis (límites) | 200K | Coding |
| **Ollama local** | Gratis | Variable | Offline |

---

## DeepSeek (Recomendado)

### 注册 (Regístrate)
1. Ve a [platform.deepseek.com](https://platform.deepseek.com)
2. Crea una cuenta (no requiere tarjeta)
3. Obtén tu API key en el dashboard

### Configuración

```bash
# Exporta tu API key
export DEEPSEEK_API_KEY="sk-xxxxxxxxxxxxxxxx"

# Usa DeepSeek V3 (chat)
kraken --model deepseek prompt "hola mundo"

# Usa DeepSeek R1 (razonamiento)
kraken --model r1 prompt "resuelve este problema de algoritmos"

# Usa DeepSeek Coder
kraken --model deepseek-coder prompt "escribe una función en Rust"
```

### Alias disponibles

| Alias | Modelo real |
|-------|-------------|
| `deepseek` | deepseek-chat |
| `deepseek-v3` | deepseek-chat |
| `r1` | deepseek-reasoner |
| `deepseek-r1` | deepseek-reasoner |
| `deepseek-coder` | deepseek-coder |

---

## Big Pickle (OpenCode Zen)

### Acerca de
Big Pickle es un modelo gratuito creado por OpenCode. Es GLM-4.6 optimizado para coding.

### Configuración

```bash
# Obtén tu API key en https://opencode.ai/zen
export OPENCODE_API_KEY="tu-api-key"

# Usar Big Pickle
kraken --model big-pickle prompt "crea un API REST en Python"
```

### Notas
- Es gratuito pero tiene límites de uso
- Disponible mientras OpenCode lo ofrezca
- Buena opción para proyectos personales

---

## Ollama (Local)

### Instalación

```bash
# Instalar Ollama (Linux/macOS)
curl -fsSL https://ollama.com/install.sh | sh

# Ver modelos disponibles
ollama list
```

### Modelos populares

```bash
# Descargar modelos recomendados
ollama pull qwen2.5-coder:7b    # Coding - 4GB
ollama pull deepseek-coder:6.7b # Coding - 4GB  
ollama pull llama3.1:8b         # General - 5GB
ollama pull mistral:7b          # General - 4GB
```

### Configuración

```bash
# Configurar endpoint local
export OPENAI_BASE_URL="http://localhost:11434/v1"
export OPENAI_API_KEY="ollama"  # Ollama no requiere clave real

# Usar modelo local
kraken --model qwen2.5-coder:7b prompt "hola"
```

---

## DashScope (Alibaba - Qwen/Kimi)

### Modelos disponibles
- **Qwen**: `qwen-max`, `qwen-plus`, `qwen-turbo`
- **Kimi**: `kimi-k2.5`, `kimi-k1.5`

### Configuración

```bash
# Regístrate en https://dashscope.console.aliyun.com/
export DASHSCOPE_API_KEY="sk-xxxxxxxxxxxxxxxx"

# Usar Qwen
kraken --model qwen-max prompt "explica esto"

# Usar Kimi
kraken --model kimi prompt "ayúdame con este código"
```

---

## Solución de problemas

### "Missing API key"
Asegúrate de exportar la variable correcta:
```bash
# DeepSeek
echo $DEEPSEEK_API_KEY

# OpenCode
echo $OPENCODE_API_KEY

# Ollama
echo $OPENAI_BASE_URL
```

### "Connection refused" (Ollama)
Inicia Ollama primero:
```bash
ollama serve
```

### VPN requerida
Algunos proveedores pueden requerir VPN desde Venezuela:
- DeepSeek: Generalmente accesible
- DashScope: Puede requerir VPN
- OpenCode Zen: Puede requerir VPN

---

## Recomendaciones

| Caso de uso | Modelo recomendado |
|-------------|-------------------|
| Coding diario | `deepseek-coder` o `qwen2.5-coder:7b` (Ollama) |
| Razonamiento complejo | `r1` (DeepSeek R1) |
| Budget cero | Ollama local |
| Proyectos rápidos | `big-pickle` |

---

## Notas para Venezuela

1. **DeepSeek** es la opción más económica y accesible
2. **Ollama** es completamente gratis si tienes hardware adecuado
3. **VPN** puede ser necesaria para algunos servicios
4. Los precios de API están en USD pero funcionan con tarjetas internacionales

---

## Enlaces útiles

- [DeepSeek API](https://platform.deepseek.com)
- [OpenCode Zen](https://opencode.ai/zen)
- [Ollama](https://ollama.com)
- [DashScope](https://dashscope.console.aliyun.com)