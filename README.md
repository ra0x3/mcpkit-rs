# mcpkit-rs

> ⚠️
> This project is a fork of the official [Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk) with added **WASI support** for portable, sandboxed tool execution.

[![Crates.io Version](https://img.shields.io/crates/v/rmcp)](https://crates.io/crates/rmcp)
<!-- ![Release status](https://github.com/modelcontextprotocol/rust-sdk/actions/workflows/release.yml/badge.svg) -->
<!-- [![docs.rs](todo)](todo) -->
![Coverage](docs/coverage.svg)

## Table of Contents

- [Overview](#overview)
- [WASI Support](#wasi-support)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [OAuth Support](#oauth-support)
- [Development](#development)
- [Related Resources](#related-resources)

## Overview

An official Rust Model Context Protocol SDK implementation with tokio async runtime, extended with WebAssembly System Interface (WASI) support for building portable, sandboxed MCP tools.

## WASI Support

This fork extends the original RMCP SDK with WASI (WebAssembly System Interface) support to enable a **portable tool marketplace** for MCP. The vision is to create an ecosystem where MCP tools are distributed as portable WebAssembly binaries that work across any compatible MCP server.

### Why WASI?

The integration of WASI addresses a critical challenge in the MCP ecosystem: **tool portability and reusability**. Currently, everyone is writing their own tools to do the same things—a massive duplication of effort. These tools are largely deterministic, non-differentiating, and expensive to maintain relative to their value.

Key benefits:
- **Portability**: Tools compile to `wasm32-wasip2` and run anywhere
- **Security**: WASM provides sandboxed execution with explicit capabilities
- **No FFI complexity**: Tools use standard WASI interfaces for filesystem, networking, and environment
- **Reproducibility**: Same tool version = same behavior across all environments
- **Community reuse**: Share tools as binaries, not services or libraries

The marketplace model treats tools as **opinionated, atomic, deterministic executables**—similar to GitHub Actions or Docker images, but at CLI-level granularity. As AI increases leverage, differentiation moves to the domain layer, making community-driven tool infrastructure both rational and inevitable.

For detailed technical rationale, see the [Tool Pool Technical Design](docs/TOOL_POOL_TECH_DESIGN_v1.md).

## Installation

Add to your `Cargo.toml`:

```toml
rmcp = { version = "0.13.0", features = ["server"] }
# For WASI compilation, also add:
[target.wasm32-wasip2.dependencies]
rmcp = { version = "0.13.0", features = ["server", "wasi"] }
```

### Prerequisites

- **Rust**: 1.75 or higher
- **WASI runtime**: [wasmtime](https://wasmtime.dev/) or compatible runtime
- **wasm32-wasip2 target**: Install with `rustup target add wasm32-wasip2`

## Usage

### Building a WASI Tool

Here's a complete hello-world example of a portable MCP tool compiled to WASI:

```rust
use rmcp::{handler::server::ServerHandler, protocol::*, ServiceExt};
use serde_json::Value;
use tokio::io::{stdin, stdout};

#[derive(Clone)]
struct HelloWorldTool;

#[rmcp::async_trait]
impl ServerHandler for HelloWorldTool {
    async fn list_tools(&self) -> ServerResult<ListToolsResponse> {
        Ok(ListToolsResponse {
            tools: vec![Tool {
                name: "hello".into(),
                description: Some("Say hello to someone".into()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Name to greet"
                        }
                    },
                    "required": ["name"]
                }),
            }],
            ..Default::default()
        })
    }

    async fn call_tool(&self, params: CallToolParams) -> ServerResult<CallToolResponse> {
        if params.name == "hello" {
            let name = params.arguments
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("World");

            Ok(CallToolResponse {
                content: vec![Content::Text(TextContent {
                    text: format!("Hello, {}!", name),
                    annotations: None,
                })],
                ..Default::default()
            })
        } else {
            Err(ServerError::MethodNotFound)
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = (stdin(), stdout());
    let service = HelloWorldTool;
    let server = service.serve(transport).await?;
    server.waiting().await?;
    Ok(())
}
```

### Compiling to WASI

```bash
# Add the WASI target if you haven't already
rustup target add wasm32-wasip2

# Build your tool
cargo build --target wasm32-wasip2 --release

# Run with wasmtime
wasmtime target/wasm32-wasip2/release/your_tool.wasm
```

### Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector wasmtime target/wasm32-wasip2/release/your_tool.wasm
```

## Examples

### WASI Example

The [`examples/wasi`](examples/wasi) directory contains a complete WASI-compatible MCP server example:

```bash
# Build the WASI example
cargo build -p wasi-mcp-example --target wasm32-wasip2

# Run with MCP Inspector
npx @modelcontextprotocol/inspector wasmtime target/wasm32-wasip2/debug/wasi_mcp_example.wasm
```

For more examples including traditional client/server implementations, see the [examples directory](examples/README.md).

## OAuth Support

This fork includes OAuth 2.1 support specifically designed for WASI environments. Key features:

- **WASI-compatible OAuth flow**: OAuth implementation that works within WASI's sandboxed environment
- **Credential injection**: Tools declare OAuth requirements in their manifest; MCP servers handle credential resolution and injection
- **Automatic token refresh**: Transparent token management without tool intervention
- **Provider abstraction**: Tools reference OAuth providers by name, servers manage the actual configuration

### OAuth in WASI Tools

Tools declare their OAuth requirements in their manifest:

```toml
[credentials.google]
type = "oauth2"
provider = "google"
scopes = ["https://www.googleapis.com/auth/calendar.events"]
```

The MCP server automatically:
1. Resolves the OAuth provider configuration
2. Handles the OAuth flow (including refresh)
3. Injects access tokens as environment variables
4. Tools simply read `GOOGLE_ACCESS_TOKEN` from the environment

For detailed OAuth implementation and examples, see the [OAuth Support documentation](docs/OAUTH_SUPPORT.md).

## Related Resources

- [MCP Specification](https://modelcontextprotocol.io/specification/2025-11-25)
- [Original Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk)
- [Tool Pool Technical Design](docs/TOOL_POOL_TECH_DESIGN_v1.md)
- [WebAssembly System Interface (WASI)](https://wasi.dev/)

## Development

### Tips for Contributors

See [docs/CONTRIBUTE.MD](docs/CONTRIBUTE.MD) to get some tips for contributing.

### Using Dev Container

If you want to use dev container, see [docs/DEVCONTAINER.md](docs/DEVCONTAINER.md) for instructions on using Dev Container for development.
