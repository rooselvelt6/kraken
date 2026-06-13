#!/usr/bin/env bash
set -euo pipefail

# SBOM generation script for Kraken
# Requires: cargo-cyclonedx (install via: cargo install cargo-cyclonedx --locked)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${PROJECT_ROOT}/sbom"
RUST_DIR="${PROJECT_ROOT}/rust"

echo "=== Kraken SBOM Generator ==="
echo "Output: ${OUTPUT_DIR}"

# Ensure cargo-cyclonedx is installed
if ! command -v cargo-cyclonedx &>/dev/null; then
    echo "Installing cargo-cyclonedx..."
    cargo install cargo-cyclonedx --locked
fi

mkdir -p "${OUTPUT_DIR}"

cd "${RUST_DIR}"

echo ""
echo "Generating CycloneDX SBOM for all workspace crates..."
cargo cyclonedx --all --output-dir "${OUTPUT_DIR}"

echo ""
echo "Generating flattened SBOM..."
# Merge all individual SBOMs into a single workspace-level SBOM
# (cargo-cyclonedx supports --all but generates per-crate; we create a summary)
cat > "${OUTPUT_DIR}/WORKSPACE-SBOM.md" << EOSBOM
# Kraken Workspace SBOM

Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Tool: cargo-cyclonedx
Format: CycloneDX JSON

## Contents

$(for f in "${OUTPUT_DIR}"/*.json; do
    if [ -f "$f" ]; then
        crate=$(basename "$f" .json)
        deps=$(python3 -c "import json; d=json.load(open('$f')); print(len(d.get('components',[])))" 2>/dev/null || echo "?")
        echo "- **${crate}**: ${deps} dependencies"
    fi
done)

## Dependency Summary

$(python3 -c "
import json, glob, collections
all_deps = collections.Counter()
for f in glob.glob('${OUTPUT_DIR}/*.json'):
    d = json.load(open(f))
    for comp in d.get('components', []):
        name = comp.get('name', 'unknown')
        ver = comp.get('version', 'unknown')
        lic = '|'.join([l.get('license',{}).get('id','N/A') for l in comp.get('licenses',[])])
        all_deps[f'{name}@{ver} ({lic})'] += 1
print(f'Total unique dependencies: {len(all_deps)}')
for dep, count in all_deps.most_common(10):
    print(f'  {dep} (in {count} crates)')
" 2>/dev/null || echo "Dependency parsing skipped")
EOSBOM

echo ""
echo "SBOM generated in ${OUTPUT_DIR}:"
ls -lh "${OUTPUT_DIR}/"
echo ""
echo "Done."
