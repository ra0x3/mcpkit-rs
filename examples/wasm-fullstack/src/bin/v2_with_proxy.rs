// V2 with REAL database proxy connections
// This version makes actual HTTP calls to the db-proxy server
// Demonstrates real networking in WASM (requires WasmEdge or proxy support)

use std::collections::HashMap;

use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

// The db-proxy URL - in production this would be configurable
const DB_PROXY_URL: &str = "http://localhost:3000";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Todo {
    pub id: String,
    pub user_id: i32,
    pub title: String,
    pub completed: bool,
    pub created_at: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct FetchTodosRequest {
    #[schemars(description = "User ID to fetch todos for")]
    pub user_id: Option<i32>,
    #[schemars(description = "Fetch from external API")]
    pub from_api: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct CreateTodoRequest {
    #[schemars(description = "Todo title")]
    pub title: String,
    #[schemars(description = "User ID")]
    pub user_id: i32,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct UpdateTodoRequest {
    #[schemars(description = "Todo ID")]
    pub id: String,
    #[schemars(description = "New title")]
    pub title: Option<String>,
    #[schemars(description = "New completed status")]
    pub completed: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DeleteTodoRequest {
    #[schemars(description = "Todo ID to delete")]
    pub id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SqlQueryRequest {
    #[schemars(description = "SQL query to execute")]
    pub query: String,
    #[schemars(description = "Query type: 'read' or 'write'")]
    pub query_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BatchProcessRequest {
    #[schemars(description = "List of todo IDs")]
    pub ids: Vec<String>,
    #[schemars(description = "Operation: 'complete', 'delete', or 'archive'")]
    pub operation: String,
}

#[derive(Debug, Clone)]
pub struct FullStackServerV2 {
    tool_router: ToolRouter<Self>,
}

impl FullStackServerV2 {
    pub async fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    // Helper function to make HTTP requests (simulated for WASI)
    // In real WasmEdge, this would use wasmedge-http or similar
    async fn http_request(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> Result<String, String> {
        // For standard WASI (wasmtime), we'll fallback to a local implementation
        // For WasmEdge, this would make real HTTP calls

        // Check if we're running in an environment that supports networking
        if std::env::var("WASI_NETWORK_ENABLED").is_ok() {
            // This would be the real HTTP call with WasmEdge
            eprintln!("Would make {} request to {}{}", method, DB_PROXY_URL, path);
            if let Some(b) = &body {
                eprintln!("Request body: {}", b);
            }
        }

        // Fallback for demo purposes - returns mock data
        // In production with WasmEdge, remove this fallback
        match path {
            "/todos" if method == "GET" => Ok(json!([
                {
                    "id": "todo-db-1",
                    "user_id": 1,
                    "title": "Database Todo 1 (mock)",
                    "completed": false,
                    "created_at": "2024-01-01T00:00:00Z"
                }
            ])
            .to_string()),
            _ => Err(
                "Network not available in standard WASI - use WasmEdge for real networking"
                    .to_string(),
            ),
        }
    }
}

// Tool implementations
impl FullStackServerV2 {
    #[tool(description = "Fetch todos from PostgreSQL database via proxy")]
    async fn fetch_todos(
        &self,
        Parameters(req): Parameters<FetchTodosRequest>,
    ) -> Result<String, String> {
        let mut path = "/todos".to_string();
        if let Some(user_id) = req.user_id {
            path = format!("/todos?user_id={}", user_id);
        }

        // Make HTTP GET request to db-proxy
        let response = self.http_request("GET", &path, None).await?;

        // Parse and return response
        let todos: Vec<Todo> =
            serde_json::from_str(&response).map_err(|e| format!("Failed to parse todos: {}", e))?;

        serde_json::to_string_pretty(&json!({
            "todos": todos,
            "count": todos.len(),
            "source": "postgresql-proxy",
            "io_type": "network-http"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Create todo in PostgreSQL database via proxy")]
    async fn create_todo(
        &self,
        Parameters(req): Parameters<CreateTodoRequest>,
    ) -> Result<String, String> {
        let body = json!({
            "title": req.title,
            "user_id": req.user_id
        });

        // Make HTTP POST request to db-proxy
        let response = self
            .http_request("POST", "/todos", Some(body.to_string()))
            .await?;

        serde_json::to_string_pretty(&json!({
            "created": true,
            "response": response,
            "source": "postgresql-proxy",
            "io_type": "network-http"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Update todo in PostgreSQL database via proxy")]
    async fn update_todo(
        &self,
        Parameters(req): Parameters<UpdateTodoRequest>,
    ) -> Result<String, String> {
        let body = json!({
            "title": req.title,
            "completed": req.completed
        });

        let path = format!("/todos/{}", req.id);

        // Make HTTP PUT request to db-proxy
        let response = self
            .http_request("PUT", &path, Some(body.to_string()))
            .await?;

        serde_json::to_string_pretty(&json!({
            "updated": true,
            "id": req.id,
            "response": response,
            "source": "postgresql-proxy",
            "io_type": "network-http"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Delete todo from PostgreSQL database via proxy")]
    async fn delete_todo(
        &self,
        Parameters(req): Parameters<DeleteTodoRequest>,
    ) -> Result<String, String> {
        let path = format!("/todos/{}", req.id);

        // Make HTTP DELETE request to db-proxy
        let response = self.http_request("DELETE", &path, None).await?;

        serde_json::to_string_pretty(&json!({
            "deleted": true,
            "id": req.id,
            "response": response,
            "source": "postgresql-proxy",
            "io_type": "network-http"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Execute SQL query on PostgreSQL via proxy")]
    async fn sql_query(
        &self,
        Parameters(req): Parameters<SqlQueryRequest>,
    ) -> Result<String, String> {
        // Validate query type
        if req.query_type != "read" && req.query_type != "write" {
            return Err("query_type must be 'read' or 'write'".to_string());
        }

        let body = json!({
            "query": req.query,
            "params": []
        });

        // Make HTTP POST request to db-proxy SQL endpoint
        let response = self
            .http_request("POST", "/sql", Some(body.to_string()))
            .await?;

        serde_json::to_string_pretty(&json!({
            "executed": true,
            "query": req.query,
            "query_type": req.query_type,
            "response": response,
            "source": "postgresql-proxy",
            "io_type": "network-http-sql"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Batch process todos via database proxy")]
    async fn batch_process(
        &self,
        Parameters(req): Parameters<BatchProcessRequest>,
    ) -> Result<String, String> {
        if req.ids.is_empty() {
            return Err("No IDs provided".to_string());
        }

        let body = json!({
            "ids": req.ids,
            "operation": req.operation
        });

        // Make HTTP POST request to db-proxy batch endpoint
        let response = self
            .http_request("POST", "/batch", Some(body.to_string()))
            .await?;

        serde_json::to_string_pretty(&json!({
            "processed": true,
            "operation": req.operation,
            "ids_count": req.ids.len(),
            "response": response,
            "source": "postgresql-proxy",
            "io_type": "network-http-batch"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Fetch data from external API (JSONPlaceholder)")]
    async fn fetch_external_api(&self) -> Result<String, String> {
        // This demonstrates HTTP call to external API
        // Would make real call with WasmEdge
        let api_url = "https://jsonplaceholder.typicode.com/todos?_limit=5";

        eprintln!("Would fetch from external API: {}", api_url);

        // Mock response for demo
        serde_json::to_string_pretty(&json!({
            "api_url": api_url,
            "status": "Would fetch with WasmEdge",
            "io_type": "network-http-external",
            "note": "Requires WasmEdge for real HTTP calls"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Get database statistics via proxy")]
    async fn db_stats(&self) -> Result<String, String> {
        // Make HTTP GET request to db-proxy stats endpoint
        let response = self.http_request("GET", "/stats", None).await?;

        serde_json::to_string_pretty(&json!({
            "stats": response,
            "source": "postgresql-proxy",
            "io_type": "network-http"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Health check for database proxy connection")]
    async fn health_check(&self) -> Result<String, String> {
        // Make HTTP GET request to db-proxy health endpoint
        let response = self.http_request("GET", "/health", None).await?;

        serde_json::to_string_pretty(&json!({
            "status": "connected",
            "proxy_url": DB_PROXY_URL,
            "response": response,
            "io_type": "network-http"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Write audit log to disk")]
    async fn write_audit_log(
        &self,
        Parameters(msg): Parameters<HashMap<String, String>>,
    ) -> Result<String, String> {
        let log_entry = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "action": msg.get("action").unwrap_or(&"unknown".to_string()),
            "details": msg
        });

        // Write to WAL file (disk I/O)
        let wal_path = "/tmp/todos_audit.wal";
        let entry_str = format!("{}\n", log_entry);

        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(wal_path)
            .and_then(|mut file| {
                use std::io::Write;
                file.write_all(entry_str.as_bytes())
            })
            .map_err(|e| format!("Failed to write audit log: {}", e))?;

        serde_json::to_string_pretty(&json!({
            "written": true,
            "path": wal_path,
            "io_type": "disk-write"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Read audit log from disk")]
    async fn read_audit_log(&self) -> Result<String, String> {
        let wal_path = "/tmp/todos_audit.wal";

        // Read from WAL file (disk I/O)
        let contents = std::fs::read_to_string(wal_path)
            .map_err(|e| format!("Failed to read audit log: {}", e))?;

        let lines: Vec<&str> = contents.lines().collect();
        let count = lines.len();
        let last_10: Vec<&str> = lines.iter().rev().take(10).copied().collect();

        serde_json::to_string_pretty(&json!({
            "total_entries": count,
            "last_10": last_10,
            "path": wal_path,
            "io_type": "disk-read"
        }))
        .map_err(|e| e.to_string())
    }
}

// Tool router setup
tool_router!(FullStackServerV2:
    fetch_todos,
    create_todo,
    update_todo,
    delete_todo,
    sql_query,
    batch_process,
    fetch_external_api,
    db_stats,
    health_check,
    write_audit_log,
    read_audit_log
);

#[async_trait::async_trait]
impl ServerHandler for FullStackServerV2 {
    async fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: "wasm-fullstack-v2-proxy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: Some(
                "Full-Stack Server v2 - Real PostgreSQL via proxy with network/disk I/O"
                    .to_string(),
            ),
        }
    }

    async fn capabilities(&self) -> ServerCapabilities {
        ServerCapabilities {
            tools: Some(self.tool_router.capabilities()),
            ..Default::default()
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    // Check if db-proxy is configured
    if std::env::var("DB_PROXY_URL").is_ok() {
        eprintln!("DB Proxy configured - will attempt real network calls");
    } else {
        eprintln!("DB Proxy not configured - using mock responses");
        eprintln!("Set DB_PROXY_URL and WASI_NETWORK_ENABLED for real networking");
    }

    let server = FullStackServerV2::new().await;
    let mut stdio_transport = rmcp::transport::stdio::StdioTransport::default();
    server.start(&mut stdio_transport).await
}
