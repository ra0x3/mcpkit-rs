# WASM Examples

This directory contains WebAssembly (WASM) examples demonstrating how to run MCP servers in different WASM runtimes.

## Directory Structure

```
wasm/
├── wasmtime/      # Examples for Wasmtime runtime
│   └── calculator/  # Simple calculator MCP server using WASI Component Model
└── wasmedge/      # Examples for WasmEdge runtime
    └── fullstack/   # Full-featured MCP server with PostgreSQL support
```

## Runtimes

### Wasmtime
[Wasmtime](https://wasmtime.dev/) is a standalone runtime for WebAssembly and WASI. The examples in the `wasmtime/` directory use the WASI Component Model (preview 2) which provides a more modular and composable approach.

### WasmEdge
[WasmEdge](https://wasmedge.org/) is a lightweight, high-performance WebAssembly runtime optimized for cloud-native and edge computing. The examples in the `wasmedge/` directory leverage WasmEdge's extensions for networking and database support.

## Examples

### Calculator (Wasmtime)
A simple calculator MCP server demonstrating basic WASM integration using the WASI Component Model.

**Location:** `wasmtime/calculator/`
**Features:**
- Basic arithmetic operations
- WASI Component Model (preview 2)
- Minimal dependencies

[View Calculator README](wasmtime/calculator/README.md)

### Fullstack (WasmEdge)
A comprehensive MCP server with PostgreSQL database integration, showcasing WasmEdge's advanced capabilities.

**Location:** `wasmedge/fullstack/`
**Features:**
- PostgreSQL integration
- Multiple transport options (stdio, HTTP)
- Todo list management
- Real networking support

[View Fullstack README](wasmedge/fullstack/README.md)

## Getting Started

### Prerequisites

#### For Wasmtime examples:
```bash
# Install Rust with WASI target
rustup target add wasm32-wasip2

# Install Wasmtime (optional, for running directly)
curl https://wasmtime.dev/install.sh -sSf | bash
```

#### For WasmEdge examples:
```bash
# Install Rust with WASI target
rustup target add wasm32-wasip1

# Install WasmEdge
curl -sSf https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh | bash
```

### Building and Running

Each example includes a `build.sh` script for easy compilation:

```bash
# Build calculator example
cd wasmtime/calculator
./build.sh

# Build fullstack example
cd wasmedge/fullstack
./build.sh
```

Run examples using the MCP Inspector:
```bash
# Run calculator with Wasmtime
npx @modelcontextprotocol/inspector wasmtime run ./calculator.wasm

# Run fullstack with WasmEdge
npx @modelcontextprotocol/inspector wasmedge ./fullstack-stdio.wasm
```

## Key Differences

| Feature | Wasmtime | WasmEdge |
|---------|----------|----------|
| WASI Version | Preview 2 (Component Model) | Preview 1 |
| Networking | Limited | Full support with patches |
| Database Support | No | Yes (PostgreSQL) |
| Use Case | Lightweight, sandboxed | Full-featured, cloud-native |

## Learn More

- [WebAssembly](https://webassembly.org/)
- [WASI](https://wasi.dev/)
- [Wasmtime Documentation](https://docs.wasmtime.dev/)
- [WasmEdge Documentation](https://wasmedge.org/docs/)
- [Model Context Protocol](https://modelcontextprotocol.io/)