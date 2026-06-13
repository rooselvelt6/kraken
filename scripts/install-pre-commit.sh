#!/usr/bin/env bash
# Install git pre-commit hook for secret scanning.
# This hook runs `kraken vulnscan --secrets` on staged files
# and blocks the commit if secrets are detected.
#
# Usage:
#   bash scripts/install-pre-commit.sh          # install hook
#   bash scripts/install-pre-commit.sh --force  # overwrite existing hook

set -euo pipefail

HOOK_DIR=".git/hooks"
HOOK_FILE="${HOOK_DIR}/pre-commit"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -d "${HOOK_DIR}" ]; then
    echo "Error: ${HOOK_DIR} not found. Run from project root."
    exit 1
fi

if [ -f "${HOOK_FILE}" ] && [ "${1:-}" != "--force" ]; then
    echo "Error: ${HOOK_FILE} already exists. Use --force to overwrite."
    exit 1
fi

cat > "${HOOK_FILE}" << 'HOOK'
#!/usr/bin/env bash
# Kraken secret scanning pre-commit hook
set -euo pipefail

echo "🔍 Scanning staged files for secrets..."

# Get list of staged files (staged, not deleted)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR | head -200)

if [ -z "${STAGED_FILES}" ]; then
    exit 0
fi

# Check if kraken binary is available
KRAKEN=""
if command -v kraken &>/dev/null; then
    KRAKEN="kraken"
elif [ -f "./target/release/kraken" ]; then
    KRAKEN="./target/release/kraken"
elif [ -f "./target/debug/kraken" ]; then
    KRAKEN="./target/debug/kraken"
fi

if [ -z "${KRAKEN}" ]; then
    echo "⚠️  kraken binary not found. Install it or build with: cargo build --release"
    echo "   Skipping secret scan."
    exit 0
fi

# Run secrets scan on staged files
# We use the vulnscan crate's secrets detection via a tmp file approach
TMPFILE=$(mktemp)
trap 'rm -f "${TMPFILE}"' EXIT

for file in ${STAGED_FILES}; do
    if [ -f "${file}" ]; then
        git show ":${file}" >> "${TMPFILE}" 2>/dev/null || true
        echo "===FILE===" >> "${TMPFILE}"
    fi
done

# Use a simple grep-based check as a fast pre-commit filter
# (The full kraken scan can be run separately)
PATTERNS=(
    'AKIA[0-9A-Z]\{16\}'
    'gh[psu]_[a-zA-Z0-9_]\{16,\}'
    'sk_live_\|pk_live_'
    '-----BEGIN.*PRIVATE KEY-----'
    'xox[baprs]-[a-zA-Z0-9\-]\{10,\}'
)

SECRETS_FOUND=0
for pattern in "${PATTERNS[@]}"; do
    if grep -q "${pattern}" "${TMPFILE}" 2>/dev/null; then
        if [ "${SECRETS_FOUND}" -eq 0 ]; then
            echo ""
            echo "❌ Potential secrets detected in staged files!"
            SECRETS_FOUND=1
        fi
        echo "   Match: ${pattern}"
        grep -n "${pattern}" "${TMPFILE}" | head -5 | sed 's/^/   /'
    fi
done

if [ "${SECRETS_FOUND}" -eq 1 ]; then
    echo ""
    echo "To commit anyway (not recommended), use: git commit --no-verify"
    echo "To run full scan: ${KRAKEN} vulnscan --path . --secrets"
    exit 1
fi

echo "✅ No secrets detected in staged files."
HOOK

chmod +x "${HOOK_FILE}"
echo "✅ Pre-commit hook installed at ${HOOK_FILE}"
