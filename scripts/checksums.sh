#!/usr/bin/env sh
# checksums.sh — Generate SHA256SUMS for all Kraken release artifacts
#
# Usage:
#   ./scripts/checksums.sh [directory]
#
# If no directory is given, looks for artifacts in ./dist/ and ./artifacts/.

set -eu

ARTIFACT_DIR="${1:-}"

if [ -z "$ARTIFACT_DIR" ]; then
    for DIR in "./dist" "./artifacts"; do
        if [ -d "$DIR" ]; then
            ARTIFACT_DIR="$DIR"
            break
        fi
    done
fi

if [ -z "$ARTIFACT_DIR" ] || [ ! -d "$ARTIFACT_DIR" ]; then
    printf '\033[31m  error\033[0m No artifact directory found.\n' 1>&2
    printf '       Place build artifacts in ./dist/ or ./artifacts/, or pass a path.\n' 1>&2
    exit 1
fi

CHECKSUMS_FILE="${ARTIFACT_DIR}/SHA256SUMS"

printf 'Generating SHA256 checksums...\n'
printf '  Directory: %s\n' "${ARTIFACT_DIR}"
printf '  Output:    %s\n' "${CHECKSUMS_FILE}"

cd "${ARTIFACT_DIR}"

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum * | tee SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 * | tee SHA256SUMS
elif command -v openssl >/dev/null 2>&1; then
    for f in *; do
        [ -f "$f" ] && printf '%s  %s\n' "$(openssl dgst -sha256 "$f" | cut -d' ' -f2)" "$f"
    done | tee SHA256SUMS
else
    printf '\033[31m  error\033[0m No SHA-256 tool found (sha256sum, shasum, or openssl).\n' 1>&2
    exit 1
fi

printf '\n\033[32m  ok\033[0m Checksums written to %s\n' "${CHECKSUMS_FILE}"
