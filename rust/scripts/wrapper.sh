#!/bin/bash
# Claw Code Wrapper - Allows running with custom names
# Usage: Create symlinks with different names pointing to this script

# Get the name this script was invoked as
INVOKED_NAME="$(basename "$0")"

# Build path to actual binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_DIR="$(dirname "$SCRIPT_DIR")/target/debug"

# Determine which binary to use
case "$INVOKED_NAME" in
    claw|kaken|kaken-cli)
        BINARY="$BINARY_DIR/claw"
        ;;
    *)
        BINARY="$BINARY_DIR/claw"
        ;;
esac

# If symlink to actual binary exists, use it
if [ -L "$0" ]; then
    REAL_PATH="$(readlink -f "$0")"
    REAL_NAME="$(basename "$REAL_PATH")"
    case "$REAL_NAME" in
        claw|kaken|kaken-cli)
            BINARY="$BINARY_DIR/$REAL_NAME"
            ;;
    esac
fi

# Check if custom name is provided via environment
if [ -n "$CLI_NAME" ]; then
    BINARY="$BINARY_DIR/$CLI_NAME"
fi

# Fallback to claw
if [ ! -f "$BINARY" ]; then
    BINARY="$BINARY_DIR/claw"
fi

# Execute with all arguments
exec "$BINARY" "$@"