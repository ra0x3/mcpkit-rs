#!/bin/bash
# Build script for v2

set -e

echo "Building v2..."

# Build v2 for wasm32-wasip1
cargo build --bin v2 --target wasm32-wasip1 --release

# Create component with WASI adapter
echo "Creating WASM component..."
wasm-tools component new ../../target/wasm32-wasip1/release/v2.wasm \
    -o v2-component.wasm \
    --adapt wasi_snapshot_preview1.command.wasm

echo "✅ Build complete: v2-component.wasm"
echo ""
echo "Run with:"
echo "  wasmtime run v2-component.wasm"
echo "  OR"
echo "  npx @modelcontextprotocol/inspector wasmtime run v2-component.wasm"