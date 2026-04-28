# 🦀 ROADMAP: Eliminación Completa de Python

## Estado Actual

| Componente | Ubicación | Estado |
|-----------|-----------|--------|
| CLI activo | `/rust/crates/rusty-claude-cli/` | ✅ Produção (~150MB) |
| Runtime | `/rust/crates/runtime/` | ✅ En Rust |
| API providers | `/rust/crates/api/` | ✅ DeepSeek, Ollama, BigPickle |
| Security | `/rust/crates/security/` | ✅ AES-256-GCM, Argon2id, XChaCha20 |
| Enterprise | `/rust/crates/enterprise/` | ✅ 27 features |
| Python placeholders | `/src/*/__init__.py` | ❌ 31 idénticos |
| Python mirrors | `/src/*.py` | ❌ ~30 archivos legacy |
| JSON metadata | `/src/reference_data/` | ❌ 31 archivos |

---

## Análisis: `/src/` es Legacy

Los archivos en `/src/` son **referencias históricas** (mirrors), NO código activo:

- `commands.py` → carga `commands_snapshot.json`
- `tools.py` → carga `tools_snapshot.json`
- `main.py` → CLI de auditoría de porting
- 31 directorios `*/__init__.py` → placeholders idénticos

**El CLI real de usuario ya está 100% en Rust.**

---

## Roadmap de Eliminación

### Fase 1: Verificación (DONE)

- [x] Confirmar CLI activo está en `/rust/`
- [x] Verificar 465+ tests passing
- [x] Confirmar implementación Rust completa

### Fase 2: Limpieza de Placeholders ⏱️ Semana 1

| Task | Status |
|------|--------|
| Eliminar 31 `*/__init__.py` placeholders | ⏳ Pending |
| Eliminar `/src/reference_data/subsystems/*.json` (31 archivos) | ⏳ Pending |
| Eliminar `/src/_archive_helper.py` | ⏳ Pending |
| Verificar Rust build | ⏳ Pending |

**Ahorro: ~62 archivos inútiles**

### Fase 3: Limpieza de Código Legacy ⏱️ Semana 1-2

| Task | Status |
|------|--------|
| Eliminar `/src/main.py` (CLI auditoría) | ⏳ Pending |
| Eliminar `/src/runtime.py` (mirrored) | ⏳ Pending |
| Eliminar `/src/query_engine.py` (mirrored) | ⏳ Pending |
| Eliminar `/src/commands.py` (mirrored) | ⏳ Pending |
| Eliminar `/src/tools.py` (mirrored) | ⏳ Pending |
| Eliminar `/src/models.py` | ⏳ Pending |
| Eliminar `/src/*.py` restantes | ⏳ Pending |
| Eliminar `/src/reference_data/` completo | ⏳ Pending |

### Fase 4: Limpieza de Directorios ⏱️ Semana 2

| Task | Status |
|------|--------|
| Eliminar `/src/assistant/` | ⏳ Pending |
| Eliminar `/src/bootstrap/` | ⏳ Pending |
| Eliminar `/src/bridge/` | ⏳ Pending |
| Eliminar `/src/buddy/` | ⏳ Pending |
| Eliminar `/src/cli/` | ⏳ Pending |
| Eliminar `/src/components/` | ⏳ Pending |
| Eliminar `/src/coordinator/` | ⏳ Pending |
| Eliminar `/src/entrypoints/` | ⏳ Pending |
| Eliminar `/src/hooks/` | ⏳ Pending |
| Eliminar `/src/keybindings/` | ⏳ Pending |
| Eliminar `/src/memdir/` | ⏳ Pending |
| Eliminar `/src/migrations/` | ⏳ Pending |
| Eliminar `/src/moreright/` | ⏳ Pending |
| Eliminar `/src/native_ts/` | ⏳ Pending |
| Eliminar `/src/outputStyles/` | ⏳ Pending |
| Eliminar `/src/plugins/` | ⏳ Pending |
| Eliminar `/src/remote/` | ⏳ Pending |
| Eliminar `/src/schemas/` | ⏳ Pending |
| Eliminar `/src/screens/` | ⏳ Pending |
| Eliminar `/src/server/` | ⏳ Pending |
| Eliminar `/src/services/` | ⏳ Pending |
| Eliminar `/src/skills/` | ⏳ Pending |
| Eliminar `/src/state/` | ⏳ Pending |
| Eliminar `/src/types/` | ⏳ Pending |
| Eliminar `/src/upstreamproxy/` | ⏳ Pending |
| Eliminar `/src/utils/` | ⏳ Pending |
| Eliminar `/src/vim/` | ⏳ Pending |
| Eliminar `/src/voice/` | ⏳ Pending |
| Eliminar `/src/constants/` | ⏳ Pending |
| Eliminar `/src/__init__.py` | ⏳ Pending |

### Fase 5: Validación ⏱️ Semana 2

| Task | Status |
|------|--------|
| `cargo test --workspace` | ⏳ Pending |
| `cargo build --release` | ⏳ Pending |
| Verificar CLI funciona | ⏳ Pending |
| Actualizar CLAUDE.md | ⏳ Pending |

### Fase 6: Release ⏱️ Semana 2-3

| Milestone | Descripción |
|----------|---------|
| **v1.0-Rust-Only** | 100% Rust, 0% Python |
| Binary ~150MB | CLI standalone |
| 465+ tests passing | Full coverage |

---

## Comandos de Verificación

```bash
# Antes de limpiar
cd rust && cargo test --workspace

# VerificarPython eliminado
ls src/

# Después de limpiar  
cd rust && cargo test --workspace
./target/release/claw run "test" --model deepseek/deepseek-chat
```

---

## Objetivos del Release v1.0-Rust-Only

| Objetivo | Estado |
|---------|--------|
| 0% Python | ⏳ Pending |
| 100% Rust | ✅ Listo |
| CLI funcional | ✅ Listo |
| Tests passing | ✅ Listo |
| Sin dependencias Python | ⏳ Pending |

---

## Notas

- El CLI original de Claw Code fue escrito en Python como **reference implementation**
- El puerto a Rust está **completo y en producción**
- `/src/` contiene **legacy de auditoría** - no código activo
- Después de esta limpieza: **Rust es el único lenguaje**