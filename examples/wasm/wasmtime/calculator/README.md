# Calculator (Wasmtime Example)

A minimal MCP server compiled to WebAssembly using the WASI Component Model (preview 2) for Wasmtime runtime.

## Prerequisites

- Rust with `wasm32-wasip2` target: `rustup target add wasm32-wasip2`
- Wasmtime runtime (optional): [Installation guide](https://wasmtime.dev/install.sh)

## Build

```bash
# Using the build script
./build.sh

# Or manually
cargo build --target wasm32-wasip2 --release
```

Output: `calculator.wasm` (copied from `../../../../target/wasm32-wasip2/release/calculator.wasm`)

## Run

```bash
# With MCP Inspector and Wasmtime
npx @modelcontextprotocol/inspector wasmtime run ./calculator.wasm

# Or run directly with Wasmtime
wasmtime run ./calculator.wasm
```

## Tools

| Tool | Parameters | Returns |
|------|-----------|---------|
| `add` | `a: f64, b: f64` | Sum |
| `subtract` | `a: f64, b: f64` | Difference |
| `multiply` | `a: f64, b: f64` | Product |
| `divide` | `a: f64, b: f64` | Quotient (error if b=0) |

## Technical Details

- Runtime: WASI Preview 2
- Protocol: MCP over stdio
- Binary size: ~2.5 MB (release)
- Limitations: No networking (WASI constraint)