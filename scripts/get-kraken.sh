#!/usr/bin/env sh
# get-kraken.sh — Universal Kraken binary installer
#
# Downloads the pre-compiled Kraken binary for your OS/architecture
# from GitHub Releases and installs it to your PATH.
#
# Usage:
#   curl -fsSL https://git.io/get-kraken | sh
#   curl -fsSL https://git.io/get-kraken | sh -s -- --version v0.2.0
#   curl -fsSL https://git.io/get-kraken | sh -s -- --dir ~/.local/bin
#
# Environment:
#   KRAKEN_VERSION   version tag to install (default: latest)
#   KRAKEN_BIN_DIR   installation directory (default: auto-detect)
#   KRAKEN_SKIP_VERIFY  set to 1 to skip binary verification

set -eu

REPO="rooselvelt6/kraken"
BINARY_NAME="kraken"
VERSION="${KRAKEN_VERSION:-latest}"
INSTALL_DIR="${KRAKEN_BIN_DIR:-}"
SKIP_VERIFY="${KRAKEN_SKIP_VERIFY:-0}"

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

info()  { printf '\033[36m  ->\033[0m %s\n' "$1"; }
ok()    { printf '\033[32m  ok\033[0m %s\n' "$1"; }
warn()  { printf '\033[33m  warn\033[0m %s\n' "$1"; }
error() { printf '\033[31m  error\033[0m %s\n' "$1" 1>&2; }
title() { printf '\n\033[1m%s\033[0m\n' "$1"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1
}

cleanup() {
    if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Step 1: Detect OS and architecture
# ---------------------------------------------------------------------------

title "Detecting platform"

UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
UNAME_M="$(uname -m 2>/dev/null || echo unknown)"

OS=""
ARCH=""
EXT=""

case "$UNAME_S" in
    Linux*)
        OS="linux"
        ;;
    Darwin*)
        OS="macos"
        ;;
    FreeBSD*)
        OS="freebsd"
        ;;
    OpenBSD*)
        OS="openbsd"
        ;;
    NetBSD*)
        OS="netbsd"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        OS="windows"
        EXT=".exe"
        ;;
    *)
        error "Unsupported OS: $UNAME_S"
        error "Kraken supports: Linux, macOS, Windows, FreeBSD, OpenBSD, NetBSD"
        exit 1
        ;;
esac

case "$UNAME_M" in
    x86_64|amd64)
        ARCH="x86_64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        ;;
    armv7l|armv7)
        ARCH="armv7"
        ;;
    i386|i686)
        ARCH="i686"
        ;;
    *)
        error "Unsupported architecture: $UNAME_M"
        error "Kraken supports: x86_64, aarch64, armv7"
        exit 1
        ;;
esac

# x86_64 on macOS is always "x86_64" in asset name
if [ "$OS" = "macos" ] && [ "$ARCH" = "x86_64" ]; then
    ARCH_LONG="x86_64"
elif [ "$OS" = "macos" ] && [ "$ARCH" = "aarch64" ]; then
    ARCH_LONG="aarch64"
elif [ "$OS" = "linux" ] && [ "$ARCH" = "x86_64" ]; then
    ARCH_LONG="x86_64"
elif [ "$OS" = "linux" ] && [ "$ARCH" = "aarch64" ]; then
    ARCH_LONG="aarch64"
elif [ "$OS" = "linux" ] && [ "$ARCH" = "armv7" ]; then
    ARCH_LONG="armv7"
elif [ "$OS" = "freebsd" ] && [ "$ARCH" = "x86_64" ]; then
    ARCH_LONG="x86_64"
elif [ "$OS" = "openbsd" ] && [ "$ARCH" = "x86_64" ]; then
    ARCH_LONG="x86_64"
elif [ "$OS" = "netbsd" ] && [ "$ARCH" = "x86_64" ]; then
    ARCH_LONG="x86_64"
elif [ "$OS" = "windows" ] && [ "$ARCH" = "x86_64" ]; then
    ARCH_LONG="x86_64"
elif [ "$OS" = "windows" ] && [ "$ARCH" = "aarch64" ]; then
    ARCH_LONG="aarch64"
else
    error "Unsupported combination: $OS $ARCH"
    exit 1
fi

ASSET_NAME="${BINARY_NAME}-${OS}-${ARCH_LONG}${EXT}"
info "Detected: $OS $ARCH_LONG"
info "Asset:    $ASSET_NAME"

# ---------------------------------------------------------------------------
# Step 2: Resolve version
# ---------------------------------------------------------------------------

title "Resolving version"

RELEASE_URL="https://api.github.com/repos/${REPO}/releases"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download"

if [ "$VERSION" = "latest" ]; then
    info "Fetching latest release from $REPO..."
    if require_cmd curl; then
        TAG="$(curl -fsSL "${RELEASE_URL}/latest" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')"
    elif require_cmd wget; then
        TAG="$(wget -qO- "${RELEASE_URL}/latest" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')"
    else
        error "Neither curl nor wget found — cannot download Kraken."
        error "Install curl or wget and try again."
        exit 1
    fi

    if [ -z "$TAG" ]; then
        error "Failed to determine latest release tag."
        error "Check your internet connection or set KRAKEN_VERSION manually."
        exit 1
    fi
else
    TAG="$VERSION"
fi

ok "Version: $TAG"

# ---------------------------------------------------------------------------
# Step 3: Determine install directory
# ---------------------------------------------------------------------------

title "Setting up installation path"

if [ -z "$INSTALL_DIR" ]; then
    if [ "$(id -u)" = "0" ]; then
        INSTALL_DIR="/usr/local/bin"
    elif [ -d "${HOME}/.local/bin" ] && echo ":$PATH:" | grep -q ":${HOME}/.local/bin:"; then
        INSTALL_DIR="${HOME}/.local/bin"
    elif [ -d "${HOME}/bin" ] && echo ":$PATH:" | grep -q ":${HOME}/bin:"; then
        INSTALL_DIR="${HOME}/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
    fi
fi

# Attempt to create install dir
if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
    error "Cannot create install directory: $INSTALL_DIR"
    exit 1
fi

INSTALL_PATH="${INSTALL_DIR}/${BINARY_NAME}${EXT}"
info "Target: $INSTALL_PATH"

# ---------------------------------------------------------------------------
# Step 4: Download binary
# ---------------------------------------------------------------------------

title "Downloading Kraken ${TAG}"

BINARY_URL="${DOWNLOAD_URL}/${TAG}/${ASSET_NAME}"
CHECKSUMS_URL="${DOWNLOAD_URL}/${TAG}/SHA256SUMS"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t kraken-install)"
TMP_BIN="${TMP_DIR}/${ASSET_NAME}"

info "Downloading: ${ASSET_NAME}"
if require_cmd curl; then
    HTTP_CODE="$(curl -fsSL -w '%{http_code}' -o "$TMP_BIN" "$BINARY_URL" 2>/dev/null)"
elif require_cmd wget; then
    HTTP_CODE="$(wget -qO "$TMP_BIN" "$BINARY_URL" 2>&1 && echo 200 || echo 000)"
else
    error "Neither curl nor wget found."
    exit 1
fi

if [ "$HTTP_CODE" != "200" ]; then
    error "Download failed (HTTP $HTTP_CODE)"
    error "URL: $BINARY_URL"
    error "Check that the release exists: https://github.com/$REPO/releases"
    exit 1
fi

ok "Downloaded ($(du -h "$TMP_BIN" | cut -f1))"

# ---------------------------------------------------------------------------
# Step 5: Verify checksum
# ---------------------------------------------------------------------------

if [ "$SKIP_VERIFY" != "1" ]; then
    title "Verifying checksum"

    if require_cmd sha256sum; then
        CHECK_CMD="sha256sum"
    elif require_cmd shasum; then
        CHECK_CMD="shasum -a 256"
    elif require_cmd sha256; then
        CHECK_CMD="sha256"
    else
        warn "No SHA-256 tool found — skipping checksum verification"
        SKIP_VERIFY=1
    fi

    if [ "$SKIP_VERIFY" != "1" ]; then
        TMP_CHECKSUMS="${TMP_DIR}/SHA256SUMS"
        if require_cmd curl; then
            curl -fsSL -o "$TMP_CHECKSUMS" "$CHECKSUMS_URL" 2>/dev/null || true
        elif require_cmd wget; then
            wget -qO "$TMP_CHECKSUMS" "$CHECKSUMS_URL" 2>/dev/null || true
        fi

        if [ -f "$TMP_CHECKSUMS" ] && [ -s "$TMP_CHECKSUMS" ]; then
            EXPECTED="$(grep "  ${ASSET_NAME}$" "$TMP_CHECKSUMS" | awk '{print $1}')"
            if [ -n "$EXPECTED" ]; then
                COMPUTED="$($CHECK_CMD "$TMP_BIN" | awk '{print $1}')"
                if [ "$EXPECTED" = "$COMPUTED" ]; then
                    ok "Checksum matches: $COMPUTED"
                else
                    error "Checksum mismatch!"
                    error "  Expected: $EXPECTED"
                    error "  Computed: $COMPUTED"
                    exit 1
                fi
            else
                warn "No checksum found for $ASSET_NAME in SHA256SUMS"
            fi
        else
            warn "No SHA256SUMS file for this release — skipping verification"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 6: Install binary
# ---------------------------------------------------------------------------

title "Installing"

chmod +x "$TMP_BIN"

if [ -f "$INSTALL_PATH" ]; then
    OLD_BIN="$INSTALL_PATH"
    INSTALL_PATH_TMP="${INSTALL_PATH}.new"
    if ! mv "$TMP_BIN" "$INSTALL_PATH_TMP" 2>/dev/null; then
        error "Permission denied: $INSTALL_DIR"
        error "Try running with sudo or set KRAKEN_BIN_DIR to a writable directory"
        exit 1
    fi
    mv "$INSTALL_PATH_TMP" "$INSTALL_PATH" 2>/dev/null || true
    ok "Updated existing installation at $INSTALL_PATH"
else
    if ! mv "$TMP_BIN" "$INSTALL_PATH" 2>/dev/null; then
        error "Permission denied: $INSTALL_DIR"
        error "Try running with sudo or set KRAKEN_BIN_DIR to a writable directory"
        exit 1
    fi
    ok "Installed to $INSTALL_PATH"
fi

# ---------------------------------------------------------------------------
# Step 7: Verify installation
# ---------------------------------------------------------------------------

title "Verifying installation"

if [ -x "$INSTALL_PATH" ]; then
    VERSION_OUT="$("$INSTALL_PATH" --version 2>&1 || true)"
    if [ -n "$VERSION_OUT" ]; then
        ok "kraken --version: $VERSION_OUT"
    else
        ok "Binary installed successfully"
    fi
else
    warn "Binary not executable at $INSTALL_PATH"
fi

# ---------------------------------------------------------------------------
# Step 8: Next steps
# ---------------------------------------------------------------------------

title "Kraken is ready!"

cat <<EOF

  Binary: $(ok "$INSTALL_PATH")

  Try it out:
    kraken
    kraken --help
    kraken vulnscan --dir .

  Set your API key:
    export ANTHROPIC_API_KEY="sk-ant-..."
    # or use Ollama (free, local):
    kraken --provider ollama

EOF

if echo ":$PATH:" | grep -qv ":${INSTALL_DIR}:"; then
    warn "${INSTALL_DIR} is not in your PATH"
    warn "Add it by running:"
    info "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    info "(Add the above line to ~/.bashrc, ~/.zshrc, or ~/.profile)"
fi

trap - EXIT
