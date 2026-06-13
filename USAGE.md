# Kraken Usage Guide

## Quick start

```bash
# Install (binary, seconds)
curl -fsSL https://raw.githubusercontent.com/rooselvelt6/kraken/main/scripts/get-kraken.sh | sh

# Run doctor health check
kraken doctor

# Start interactive REPL
kraken

# One-shot prompt
kraken prompt "analyze this repository"
```

## Prerequisites

- An API key for your preferred LLM provider

Set your key:

```bash
# Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."

# DeepSeek
export DEEPSEEK_API_KEY="sk-..."

# Ollama (local, free)
kraken --provider ollama
```

## Modes

### REPL mode
```bash
kraken
```
Opens an interactive shell with tab completion, history, and 140+ slash commands.

### Prompt mode
```bash
kraken prompt "refactor this function"
kraken prompt --output-format json "analyze"  # machine-readable output
```

### Resume mode
```bash
kraken --resume latest
kraken --resume latest /doctor
```

## Common tasks

```bash
# Vulnerability scan
kraken vulnscan --dir . --html report.html

# OSINT framework
kraken prompt "run osint on example.com"
kraken prompt "find social media profiles for username"

# Secret detection
kraken vulnscan --dir . --secrets

# Pre-commit hook for secrets
bash scripts/install-pre-commit.sh
```

## Slash commands

| Command | Description |
|---------|-------------|
| `/bash` | Execute shell commands (sandboxed) |
| `/read` | Read workspace files |
| `/write` | Write files |
| `/edit` | Edit files with structural diff |
| `/glob` | Find files by pattern |
| `/grep` | Search content with regex |
| `/web_search` | Search the web |
| `/web_fetch` | Fetch URL content |
| `/vulnscan` | Vulnerability scanner |
| `/osint` | OSINT framework |
| `/doctor` | Health check and diagnostics |
| `/status` | Session status |
| `/session` | Session management |
| `/skill` | Load specialized skills |

## JSON output

```bash
kraken doctor --output-format json
kraken status --output-format json
kraken prompt --output-format json "analyze"
```

## Configuration

Kraken reads `.kraken.json` from the current directory or `~/.config/kraken/`.
See the [README](README.md) for config schema.

## Troubleshooting

- Run `/doctor` first for health check
- Ensure your API key is set in the environment
- Check that `kraken --version` matches the latest release
- For build issues, see `install.sh` troubleshooting section
