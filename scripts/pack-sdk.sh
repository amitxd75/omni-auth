#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Get the root directory of the project (one level up from scripts/)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Define paths
SDK_CORE_DIR="$ROOT_DIR/sdk/core"
SDK_REACT_DIR="$ROOT_DIR/sdk/react"
DIST_DIR="$ROOT_DIR/dist"

echo "=== Packaging OmniAuth SDKs ==="

# Check package manager (prefer bun)
if command -v bun >/dev/null 2>&1; then
    PACK_CMD="bun pm pack"
else
    echo "Warning: 'bun' not found, falling back to 'npm pack'"
    PACK_CMD="npm pack"
fi

# Prepare dist directory
mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR"/*.tgz

# Pack Core SDK
echo "Packing @omni-auth/core..."
cd "$SDK_CORE_DIR"
$PACK_CMD
# Find and move the generated tarball
TARBALL_CORE=$(ls -t *.tgz | head -n 1)
mv "$TARBALL_CORE" "$DIST_DIR/"

# Pack React SDK
echo "Packing @omni-auth/react..."
cd "$SDK_REACT_DIR"
$PACK_CMD
# Find and move the generated tarball
TARBALL_REACT=$(ls -t *.tgz | head -n 1)
mv "$TARBALL_REACT" "$DIST_DIR/"

echo ""
echo "=== Packaging Complete! ==="
echo "Tarballs generated in: $DIST_DIR"
echo "  - $DIST_DIR/$TARBALL_CORE"
echo "  - $DIST_DIR/$TARBALL_REACT"
echo ""
echo "To install these packages locally in your application, run:"
echo "  bun add $DIST_DIR/$TARBALL_CORE"
echo "  bun add $DIST_DIR/$TARBALL_REACT"
echo "or"
echo "  npm install $DIST_DIR/$TARBALL_CORE $DIST_DIR/$TARBALL_REACT"
