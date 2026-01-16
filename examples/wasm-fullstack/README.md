# WASI Full-Stack Example - Real Database Todo Application

![WasmEdge Logo](https://i.imgur.com/ez4x4X6.jpeg)

A comprehensive full-stack todo application with **real PostgreSQL database connections** using **WasmEdge 0.14** runtime, which provides native networking and database drivers for WebAssembly.

## Runtime: WasmEdge 0.14

This example leverages [WasmEdge](https://wasmedge.org/), a high-performance WebAssembly runtime that extends WASI with:
- ✅ **Real TCP socket support**
- ✅ **Native PostgreSQL drivers**
- ✅ **HTTP client/server capabilities**
- ✅ **Full networking stack**
- ✅ **Database connection pooling**

## Overview

This example provides two versions:
- **v1**: Basic implementation with in-memory storage (works with any WASI runtime like Wasmtime)
- **v2**: Full-stack implementation with **REAL PostgreSQL** connections (requires WasmEdge runtime and special build process)

## Architecture

### v1 - Basic Architecture
```
┌─────────────────────────────────────────────────────┐
│                  MCP Client                          │
└────────────────────────┬─────────────────────────────┘
                         │
┌────────────────────────┴─────────────────────────────┐
│           WASI Server v1 (wasi-multi-v1)            │
├───────────────────────────────────────────────────────┤
│  • In-Memory HashMap Database                        │
│  • Simple WAL (overwrites)                          │
│  • Simulated HTTP API                               │
└───────────────────────────────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
        [/tmp/todos.wal]     [In-Memory DB]
           (FS WAL)            (HashMap)
```

### v2 - Full-Stack Architecture (WasmEdge)
```
┌─────────────────────────────────────────────────────┐
│                  MCP Client                          │
└────────────────────────┬─────────────────────────────┘
                         │
┌────────────────────────┴─────────────────────────────┐
│     WASI Server v2 (wasi-fullstack-v2-wasmedge)     │
├───────────────────────────────────────────────────────┤
│  • Real PostgreSQL Client (via WasmEdge)             │
│  • Native TCP Socket Support                        │
│  • SQL Query Execution                              │
│  • TTL-based Cache Layer                            │
│  • Connection Pooling                               │
└───────────────────────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
   [PostgreSQL]    [/tmp/wal]      [Cache Layer]
   (Real TCP)     (Audit Log)      (TTL: 5min)
         │
         └──► Docker Container or Remote DB
```

### Optional: Native Database Proxy
```
[WASI v2] ──HTTP──> [db-proxy server] ──TCP──> [PostgreSQL Docker]
                    (Native binary)            (Real database)
```

## WasmEdge vs Standard WASI

| Feature | Standard WASI (Wasmtime) | WasmEdge 0.14 |
|---------|-------------------------|---------------|
| **File I/O** | ✅ Supported | ✅ Supported |
| **TCP Sockets** | ❌ Not available | ✅ Full support |
| **HTTP Client** | ❌ Not available | ✅ Native HTTP |
| **PostgreSQL** | ❌ Cannot connect | ✅ Direct connections |
| **Redis** | ❌ Cannot connect | ✅ Direct connections |
| **MySQL** | ❌ Cannot connect | ✅ Direct connections |

## Version Comparison

| Feature | v1 (Basic) | v2 (WasmEdge Enhanced) |
|---------|------------|---------------|
| **Database** | In-memory HashMap | In-memory with SQLite simulation |
| **WAL** | Simple overwrite (size=1) | Rotating WAL (keeps last 100 entries) |
| **Caching** | None | TTL-based cache (5 min) |
| **SQL** | None | Read/Write query separation |
| **Batch Ops** | None | Complete/Delete/Archive multiple |

## I/O Capabilities by Version

### V1 (Basic WASI - Works with Wasmtime)
| Tool | I/O Type | Description |
|------|----------|-------------|
| `fetch_todos` | **Memory** | Reads from in-memory HashMap |
| `create_todo` | **Memory + Disk** | Stores in HashMap, writes to `/tmp/todos.wal` |
| `update_todo` | **Memory + Disk** | Updates HashMap, appends to WAL |
| `delete_todo` | **Memory** | Removes from HashMap |
| `read_wal` | **Disk Read** | Reads `/tmp/todos.wal` file |
| `db_stats` | **Memory** | Calculates stats from HashMap |
| `test_api` | **None** | Returns mock data (no real network) |

### V2 (Enhanced In-Memory - Works with Wasmtime)
| Tool | I/O Type | Description |
|------|----------|-------------|
| `fetch_todos` | **Memory** | Enhanced with caching simulation |
| `create_todo` | **Memory + Disk** | With rotating WAL |
| `batch_update` | **Memory** | Batch operations on HashMap |
| `search_todos` | **Memory** | Text search in memory |
| `sql_query` | **Memory** | Simulated SQL on HashMap |
| `export_todos` | **Memory** | JSON export from memory |
| `import_todos` | **Memory** | JSON import to memory |

### V2-WasmEdge (Real Full-Stack - Requires WasmEdge)
| Tool | I/O Type | Description |
|------|----------|-------------|
| `fetch_todos` | **Network TCP** | Direct PostgreSQL connection |
| `create_todo` | **Network TCP + Disk** | PostgreSQL INSERT + WAL |
| `update_todo` | **Network TCP + Disk** | PostgreSQL UPDATE + WAL |
| `delete_todo` | **Network TCP** | PostgreSQL DELETE |
| `sql_query` | **Network TCP** | Raw SQL execution on PostgreSQL |
| `batch_process` | **Network TCP** | Batch PostgreSQL operations |
| `fetch_external_api` | **Network HTTP** | Real HTTP to JSONPlaceholder |
| `db_stats` | **Network TCP** | PostgreSQL aggregate queries |
| `read_wal` | **Disk Read** | Reads audit log from `/tmp/todos_v2.wal` |
| `test_connection` | **Network TCP** | Tests PostgreSQL connectivity |

## Tools Available

### Core CRUD Operations (Both Versions)

#### `fetch_todos`
```json
{
  "user_id": 1,           // Optional: filter by user
  "from_api": true,       // Fetch from external API
  "use_cache": true       // v2 only: use cache if available
}
```

#### `create_todo`
```json
{
  "title": "Implement WAL rotation",
  "user_id": 1
}
```

#### `update_todo`
```json
{
  "id": "todo-1",
  "title": "Updated title",
  "completed": true
}
```

#### `delete_todo`
```json
{
  "id": "todo-1"
}
```

### Database & WAL Operations

#### `read_wal` - Inspect Write-Ahead Log
Shows all operations written to the WAL file

#### `db_stats` - Database Statistics
Returns todo counts, completion rates, and user breakdown

#### `test_api` (v1) - Test API connectivity
Checks if JSONPlaceholder API is reachable

### V2 Exclusive Features

#### `sql_query` - Execute SQL queries
```json
{
  "query": "SELECT * FROM todos WHERE completed = true",
  "query_type": "read"  // or "write" for INSERT/UPDATE/DELETE
}
```

#### `batch_process` - Batch operations
```json
{
  "ids": ["todo-1", "todo-2", "todo-3"],
  "operation": "complete"  // or "delete", "archive"
}
```

#### `cache_stats` - Cache information
Shows cached entries with age and expiration status

#### `clear_cache` - Clear all cached data

## Prerequisites

### Install WasmEdge 0.14
```bash
# Install WasmEdge with all extensions
curl -sSf https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh | bash -s -- -v 0.14.0 --plugins all

# Add to PATH
source $HOME/.wasmedge/env
```

## Build & Run

### Quick Start (v1 - Any WASI Runtime)

```bash
# Build v1 WASM
cargo build --bin v1 --target wasm32-wasip1

# IMPORTANT: The compiled WASM needs to be adapted for WASI Preview2 compatibility
# Download the WASI adapter (one-time setup)
curl -LO https://github.com/bytecodealliance/wasmtime/releases/latest/download/wasi_snapshot_preview1.command.wasm

# Create a component from the compiled WASM
wasm-tools component new target/wasm32-wasip1/debug/v1.wasm \
    -o v1-component.wasm \
    --adapt wasi_snapshot_preview1.command.wasm

# Run with Wasmtime
wasmtime run v1-component.wasm

# Or test with MCP Inspector
npx @modelcontextprotocol/inspector wasmtime run v1-component.wasm
```

**Note**: The adapter step is required because the Rust toolchain compiles to WASI Preview1, but modern runtimes expect Preview2 components.

### Full-Stack with Real PostgreSQL (v2-wasmedge - WasmEdge Only)

```bash
# 1. Start PostgreSQL
docker-compose up -d

# 2. Build v2-wasmedge with PostgreSQL support
# Note: Uses patched dependencies for WasmEdge socket support
RUSTFLAGS="--cfg wasmedge --cfg tokio_unstable" \
cargo build --bin v2-wasmedge --target wasm32-wasip1

# 3. Run with WasmEdge (real database connections!)
DATABASE_URL="postgres://wasi_user:wasi_password@localhost/todos_db" \
wasmedge --env DATABASE_URL \
    target/wasm32-wasip1/debug/v2-wasmedge.wasm
```

#### Testing with MCP Inspector

```bash
# For WasmEdge with real PostgreSQL
npx @modelcontextprotocol/inspector \
    wasmedge --env DATABASE_URL="postgres://wasi_user:wasi_password@localhost/todos_db" \
    target/wasm32-wasip1/debug/v2-wasmedge.wasm
```

### Full-Stack Setup with Real PostgreSQL

For a true full-stack experience with real PostgreSQL:

```bash
# 1. Start PostgreSQL container
docker-compose up -d

# 2. Build and run the database proxy server (native)
cargo build --bin db-proxy --release
cargo run --bin db-proxy

# 3. In another terminal, run v2 with database support
# Note: v2 will attempt to connect to the proxy at localhost:3000
cargo build --bin wasi-multi-v2 --target wasm32-wasip2 --features v2
wasmtime "target/wasm32-wasip2/debug/wasi-multi-v2.wasm"

# 4. Clean up when done
docker-compose down
```

### Direct PostgreSQL Access (Native only)

```bash
# Set database URL
export DATABASE_URL="postgresql://wasi_user:wasi_password@localhost/todos_db"

# Run native version with direct database access
cargo run --bin wasi-multi-v2 --features v2
```

## Practical Workflow Example

```bash
# 1. Start with some pre-populated todos
fetch_todos {}

# 2. Fetch new todos from external API and store in DB
fetch_todos {"from_api": true, "user_id": 1}

# 3. Create a new todo (writes to WAL)
create_todo {"title": "Review WAL implementation", "user_id": 1}

# 4. Check the WAL to see operations
read_wal {}

# 5. Update todo status
update_todo {"id": "todo-1", "completed": true}

# 6. v2: Use SQL queries
sql_query {"query": "SELECT COUNT(*) FROM todos", "query_type": "read"}

# 7. v2: Batch complete multiple todos
batch_process {"ids": ["todo-2", "todo-3"], "operation": "complete"}

# 8. v2: Check cache statistics
cache_stats {}

# 9. Get database statistics
db_stats {}
```

## Key Features Demonstrated

### File System (WAL)
- **v1**: Simple WAL that overwrites on each write
- **v2**: Rotating WAL with configurable size (keeps history)
- Both versions persist operations to `/tmp/todos*.wal`

### Network Operations
- **v1**: Simulated HTTP API calls
- **v2**: Can use db-proxy for real HTTP when available
- Demonstrates external data import patterns

### Database
- **v1**: Simple in-memory HashMap
- **v2**: Full PostgreSQL-compatible operations including:
  - SQL query parsing and execution
  - Transaction simulation
  - Prepared statement patterns
  - Connection pooling concepts
  - Real PostgreSQL via proxy (optional)

### Caching (v2 only)
- TTL-based cache (5 minute expiration)
- Cache invalidation on mutations
- Cache statistics and management

## Performance Characteristics

| Operation | v1 | v2 (cached) |
|-----------|----|----|
| Fetch todos | Instant (memory) | Instant (cache hit) |
| API fetch | ~200ms | ~200ms (then cached) |
| Create todo | <1ms + WAL write | <1ms + WAL write |
| WAL rotation | N/A | Automatic at 100 entries |

## Why This Example Matters

1. **Real-World Pattern**: WAL is a fundamental database concept
2. **Multiple I/O Types**: Combines FS, Network, and DB operations
3. **Evolution Path**: Shows progression from basic to full-stack
4. **Production Ready**: Can be adapted for real applications
5. **WASI Showcase**: Demonstrates both WASM limitations and workarounds
6. **Full-Stack Option**: Includes native database proxy for real PostgreSQL

## Binary Sizes

- `wasi-multi-v1.wasm`: ~57 MB (debug build)
- `wasi-multi-v2.wasm`: ~58 MB (debug build)

> **Note**: Release builds with optimizations would be significantly smaller.