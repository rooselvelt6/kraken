#!/usr/bin/env bash
# Generate man pages for Kraken from --help output
# Requires: pandoc
#
# Usage:
#   ./scripts/generate-man-pages.sh [binary_path]

set -euo pipefail

BINARY="${1:-rust/target/release/kraken}"
OUT_DIR="man"

if [ ! -f "$BINARY" ]; then
  echo "ERROR: Binary not found at $BINARY"
  echo "Build first: cargo build --release -p rusty-claude-cli"
  exit 1
fi

if ! command -v pandoc &>/dev/null; then
  echo "ERROR: pandoc is required. Install: apt-get install pandoc"
  exit 1
fi

mkdir -p "$OUT_DIR"

# Generate main page from --help
echo "Generating kraken(1)..."
HELP_OUTPUT=$("$BINARY" --help 2>&1 || true)

pandoc --from=markdown --to=man -o "$OUT_DIR/kraken.1" <<MANPAGE
---
title: KRAKEN
section: 1
header: User Manual
footer: Kraken 0.1.0
date: $(date +%Y-%m-%d)
---

# NAME

kraken - autonomous AI agent for cybersecurity operations

# SYNOPSIS

**kraken** [*OPTIONS*] [*PROMPT*]

# DESCRIPTION

**Kraken** is an autonomous AI agent for cybersecurity. It provides vulnerability scanning, OSINT, exploit generation, kernel analysis, and multi-provider LLM integration with sandboxed execution.

# OPTIONS

$(echo "$HELP_OUTPUT" | sed 's/^/    /')

# MODES

**Interactive mode (REPL):**
:   Run without arguments to enter the interactive session.

**One-shot mode:**
:   Pass a prompt as argument to execute and exit.

**Doctor mode:**
:   Run \`kraken doctor\` to check system requirements.

# FILES

~/.kraken/config.json
:   User configuration file.

.kraken.json
:   Project-level configuration file.

~/.kraken/sessions/
:   Session storage directory.

# ENVIRONMENT

ANTHROPIC_API_KEY
:   API key for Anthropic Claude provider.

OPENAI_API_KEY
:   API key for OpenAI-compatible provider.

DEEPSEEK_API_KEY
:   API key for DeepSeek provider.

# EXIT STATUS

**0**
:   Success.

**1**
:   General error.

**2**
:   Configuration error.

# EXAMPLES

    kraken                          # Interactive mode
    kraken "scan this codebase"     # One-shot mode
    kraken doctor                   # System check
    kraken --output-format json     # JSON output

# SEE ALSO

kraken(5)

# AUTHORS

Kraken Contributors.
MANPAGE

echo "Generated: $OUT_DIR/kraken.1"
echo "View with: man ./man/kraken.1"
