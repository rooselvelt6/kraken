# Filosofía de Kraken

## Deja de Mirar Solo los Archivos

Si solo miras los archivos generados en este repositorio, estás mirando la capa equivocada.

Lo que vale la pena estudiar es el **sistema que los produjo**: un bucle de coordinación donde los humanos dan dirección y los agentes autónomos ejecutan el trabajo.

Kraken no es solo un codebase. Es una demostración de lo que sucede cuando:

- un humano da dirección clara,
- múltiples agentes de código coordinan en paralelo,
- la planificación, ejecución, revisión y reintentos se automatizan,
- y el humano **no** se sienta en una terminal microgestionando cada paso.

## Principios

### 1. Offline-first, Venezuela-first

Kraken nace en Venezuela, donde internet no es garantía. Todo el sistema está diseñado para funcionar con conectividad intermitente: cola de operaciones offline, caché multi-nivel, sync cuando hay conexión.

### 2. Seguridad por defecto, no por configuración

- `unsafe` prohibido en todo el workspace
- Sandbox obligatorio para ejecución de herramientas
- Criptografía autenticada en todos los planos
- Zeroize en memoria para datos sensibles

### 3. Unix Philosophy aplicada a LLMs

- **Una cosa bien**: 18 crates, cada uno con una responsabilidad clara
- **Composición sobre configuración**: pipelines de herramientas que se combinan
- **Texto como interfaz universal**: output JSON machine-readable en todos los comandos
- **La terminal es la API**: cada comando es un endpoint

### 4. Autonomía sobre automatización

No se trata de automatizar tareas repetitivas. Se trata de que un agente pueda:

1. Recibir un objetivo difuso ("encuentra vulnerabilidades en este proyecto")
2. Descomponerlo en tareas concretas
3. Ejecutarlas con juicio contextual
4. Reportar resultados accionables

### 5. Sin bloqueo de proveedor

Kraken funciona con cualquier LLM: Anthropic, OpenAI, DeepSeek, Ollama, DashScope, OpenRouter, modelos locales. No hay dependencia de un solo proveedor.


