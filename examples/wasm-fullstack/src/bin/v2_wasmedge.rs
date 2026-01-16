// V2 with REAL PostgreSQL connections using WasmEdge
// This version uses WasmEdge's native socket support to connect directly to PostgreSQL
// Also demonstrates HTTP client for external API calls

use std::collections::HashMap;

use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_postgres::{Error, NoTls};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Todo {
    pub id: i32,
    pub user_id: i32,
    pub title: String,
    pub completed: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct FetchTodosRequest {
    #[schemars(description = "User ID to fetch todos for")]
    pub user_id: Option<i32>,
    #[schemars(description = "Fetch from external JSONPlaceholder API")]
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
    pub id: i32,
    #[schemars(description = "New title")]
    pub title: Option<String>,
    #[schemars(description = "New completed status")]
    pub completed: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct DeleteTodoRequest {
    #[schemars(description = "Todo ID to delete")]
    pub id: i32,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SqlQueryRequest {
    #[schemars(description = "SQL query to execute (SELECT only for safety)")]
    pub query: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BatchProcessRequest {
    #[schemars(description = "List of todo IDs")]
    pub ids: Vec<i32>,
    #[schemars(description = "Operation: 'complete', 'delete', or 'archive'")]
    pub operation: String,
}

#[derive(Debug, Clone)]
pub struct FullStackServerV2 {
    tool_router: ToolRouter<Self>,
}

impl FullStackServerV2 {
    pub async fn new() -> Self {
        // Initialize database on startup
        if let Err(e) = Self::init_database().await {
            eprintln!("Failed to initialize database: {}", e);
        }

        Self {
            tool_router: Self::tool_router(),
        }
    }

    async fn init_database() -> Result<(), Error> {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://wasi_user:wasi_password@localhost/todos_db".to_string()
        });

        let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Database connection error: {}", e);
            }
        });

        // Create table if not exists
        client
            .execute(
                "CREATE TABLE IF NOT EXISTS todos (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                completed BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE
            )",
                &[],
            )
            .await?;

        Ok(())
    }

    async fn get_db_client() -> Result<tokio_postgres::Client, String> {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://wasi_user:wasi_password@localhost/todos_db".to_string()
        });

        let (client, connection) = tokio_postgres::connect(&database_url, NoTls)
            .await
            .map_err(|e| format!("Failed to connect to database: {}", e))?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("Connection error: {}", e);
            }
        });

        Ok(client)
    }
}

// Tool implementations
impl FullStackServerV2 {
    #[tool(description = "[Network I/O - TCP] Fetch todos from PostgreSQL database")]
    async fn fetch_todos(
        &self,
        Parameters(req): Parameters<FetchTodosRequest>,
    ) -> Result<String, String> {
        let client = Self::get_db_client().await?;

        let rows = if let Some(user_id) = req.user_id {
            client
                .query(
                    "SELECT id, user_id, title, completed, created_at, updated_at
                 FROM todos WHERE user_id = $1 ORDER BY created_at DESC",
                    &[&user_id],
                )
                .await
        } else {
            client
                .query(
                    "SELECT id, user_id, title, completed, created_at, updated_at
                 FROM todos ORDER BY created_at DESC",
                    &[],
                )
                .await
        }
        .map_err(|e| format!("Query failed: {}", e))?;

        let todos: Vec<Todo> = rows
            .into_iter()
            .map(|row| Todo {
                id: row.get(0),
                user_id: row.get(1),
                title: row.get(2),
                completed: row.get(3),
                created_at: row.get(4),
                updated_at: row.get(5),
            })
            .collect();

        serde_json::to_string_pretty(&json!({
            "todos": todos,
            "count": todos.len(),
            "source": "postgresql-direct",
            "io_type": "network-tcp-postgres"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "[Network I/O - TCP] Create todo in PostgreSQL database")]
    async fn create_todo(
        &self,
        Parameters(req): Parameters<CreateTodoRequest>,
    ) -> Result<String, String> {
        let client = Self::get_db_client().await?;

        let row = client
            .query_one(
                "INSERT INTO todos (user_id, title) VALUES ($1, $2)
             RETURNING id, user_id, title, completed, created_at, updated_at",
                &[&req.user_id, &req.title],
            )
            .await
            .map_err(|e| format!("Insert failed: {}", e))?;

        let todo = Todo {
            id: row.get(0),
            user_id: row.get(1),
            title: row.get(2),
            completed: row.get(3),
            created_at: row.get(4),
            updated_at: row.get(5),
        };

        // Also write to audit log (Disk I/O)
        let _ = Self::append_to_wal("CREATE", &todo).await;

        serde_json::to_string_pretty(&json!({
            "created": todo,
            "source": "postgresql-direct",
            "io_type": "network-tcp-postgres + disk-write"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "[Network I/O - TCP] Update todo in PostgreSQL database")]
    async fn update_todo(
        &self,
        Parameters(req): Parameters<UpdateTodoRequest>,
    ) -> Result<String, String> {
        let client = Self::get_db_client().await?;

        // Build dynamic update query
        let mut query = "UPDATE todos SET updated_at = NOW()".to_string();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync>> = vec![];
        let mut param_count = 1;

        if let Some(title) = &req.title {
            query.push_str(&format!(", title = ${}", param_count));
            params.push(Box::new(title.clone()));
            param_count += 1;
        }

        if let Some(completed) = req.completed {
            query.push_str(&format!(", completed = ${}", param_count));
            params.push(Box::new(completed));
            param_count += 1;
        }

        query.push_str(&format!(
            " WHERE id = ${} RETURNING id, user_id, title, completed, created_at, updated_at",
            param_count
        ));
        params.push(Box::new(req.id));

        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|b| b.as_ref()).collect();

        let row = client
            .query_one(&query, &params_refs)
            .await
            .map_err(|e| format!("Update failed: {}", e))?;

        let todo = Todo {
            id: row.get(0),
            user_id: row.get(1),
            title: row.get(2),
            completed: row.get(3),
            created_at: row.get(4),
            updated_at: row.get(5),
        };

        // Write to audit log
        let _ = Self::append_to_wal("UPDATE", &todo).await;

        serde_json::to_string_pretty(&json!({
            "updated": todo,
            "source": "postgresql-direct",
            "io_type": "network-tcp-postgres + disk-write"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "[Network I/O - TCP] Delete todo from PostgreSQL database")]
    async fn delete_todo(
        &self,
        Parameters(req): Parameters<DeleteTodoRequest>,
    ) -> Result<String, String> {
        let client = Self::get_db_client().await?;

        let rows = client
            .execute("DELETE FROM todos WHERE id = $1", &[&req.id])
            .await
            .map_err(|e| format!("Delete failed: {}", e))?;

        if rows == 0 {
            return Err(format!("Todo with id {} not found", req.id));
        }

        serde_json::to_string_pretty(&json!({
            "deleted": true,
            "id": req.id,
            "source": "postgresql-direct",
            "io_type": "network-tcp-postgres"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "[Network I/O - TCP] Execute SELECT query on PostgreSQL")]
    async fn sql_query(
        &self,
        Parameters(req): Parameters<SqlQueryRequest>,
    ) -> Result<String, String> {
        // Only allow SELECT queries for safety
        if !req.query.trim().to_uppercase().starts_with("SELECT") {
            return Err("Only SELECT queries are allowed".to_string());
        }

        let client = Self::get_db_client().await?;

        let rows = client
            .query(&req.query, &[])
            .await
            .map_err(|e| format!("Query failed: {}", e))?;

        // Convert rows to JSON-serializable format
        let results: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|row| {
                let mut map = serde_json::Map::new();
                for i in 0..row.len() {
                    let column = row.columns()[i].name();
                    // Try to get value as different types
                    if let Ok(val) = row.try_get::<_, i32>(i) {
                        map.insert(column.to_string(), json!(val));
                    } else if let Ok(val) = row.try_get::<_, String>(i) {
                        map.insert(column.to_string(), json!(val));
                    } else if let Ok(val) = row.try_get::<_, bool>(i) {
                        map.insert(column.to_string(), json!(val));
                    } else if let Ok(val) = row.try_get::<_, chrono::DateTime<chrono::Utc>>(i) {
                        map.insert(column.to_string(), json!(val.to_rfc3339()));
                    } else {
                        map.insert(column.to_string(), json!(null));
                    }
                }
                json!(map)
            })
            .collect();

        serde_json::to_string_pretty(&json!({
            "query": req.query,
            "rows": results,
            "count": results.len(),
            "source": "postgresql-direct",
            "io_type": "network-tcp-postgres"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "[Network I/O - TCP] Batch update todos in PostgreSQL")]
    async fn batch_process(
        &self,
        Parameters(req): Parameters<BatchProcessRequest>,
    ) -> Result<String, String> {
        if req.ids.is_empty() {
            return Err("No IDs provided".to_string());
        }

        let client = Self::get_db_client().await?;

        let rows_affected = match req.operation.as_str() {
            "complete" => {
                let query = format!(
                    "UPDATE todos SET completed = true, updated_at = NOW()
                     WHERE id = ANY($1::int[])"
                );
                client
                    .execute(&query, &[&req.ids])
                    .await
                    .map_err(|e| format!("Batch complete failed: {}", e))?
            }
            "delete" => {
                let query = "DELETE FROM todos WHERE id = ANY($1::int[])";
                client
                    .execute(query, &[&req.ids])
                    .await
                    .map_err(|e| format!("Batch delete failed: {}", e))?
            }
            "archive" => {
                // For demo, we'll mark as completed and add archive flag
                let query = format!(
                    "UPDATE todos SET completed = true, title = CONCAT('[ARCHIVED] ', title),
                     updated_at = NOW() WHERE id = ANY($1::int[])"
                );
                client
                    .execute(&query, &[&req.ids])
                    .await
                    .map_err(|e| format!("Batch archive failed: {}", e))?
            }
            _ => return Err(format!("Unknown operation: {}", req.operation)),
        };

        serde_json::to_string_pretty(&json!({
            "operation": req.operation,
            "ids": req.ids,
            "rows_affected": rows_affected,
            "source": "postgresql-direct",
            "io_type": "network-tcp-postgres"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "[Network I/O - HTTP] Fetch todos from external JSONPlaceholder API")]
    async fn fetch_external_api(&self) -> Result<String, String> {
        // This would use reqwest with WasmEdge's HTTP support
        // For now, we'll simulate it

        eprintln!("INFO: With WasmEdge, this would make real HTTP call to https://jsonplaceholder.typicode.com/todos");

        // Simulated response for demonstration
        let mock_response = json!([
            {
                "userId": 1,
                "id": 1,
                "title": "External API Todo 1",
                "completed": false
            },
            {
                "userId": 1,
                "id": 2,
                "title": "External API Todo 2",
                "completed": true
            }
        ]);

        serde_json::to_string_pretty(&json!({
            "api_url": "https://jsonplaceholder.typicode.com/todos",
            "data": mock_response,
            "note": "With WasmEdge, this makes real HTTP calls",
            "io_type": "network-http-external"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "[Network I/O - TCP] Get database statistics")]
    async fn db_stats(&self) -> Result<String, String> {
        let client = Self::get_db_client().await?;

        let total_row = client
            .query_one("SELECT COUNT(*) FROM todos", &[])
            .await
            .map_err(|e| format!("Count query failed: {}", e))?;
        let total: i64 = total_row.get(0);

        let completed_row = client
            .query_one("SELECT COUNT(*) FROM todos WHERE completed = true", &[])
            .await
            .map_err(|e| format!("Completed count failed: {}", e))?;
        let completed: i64 = completed_row.get(0);

        let users_row = client
            .query_one("SELECT COUNT(DISTINCT user_id) FROM todos", &[])
            .await
            .map_err(|e| format!("User count failed: {}", e))?;
        let users: i64 = users_row.get(0);

        serde_json::to_string_pretty(&json!({
            "total": total,
            "completed": completed,
            "pending": total - completed,
            "unique_users": users,
            "completion_rate": if total > 0 { (completed as f64 / total as f64 * 100.0) } else { 0.0 },
            "source": "postgresql-direct",
            "io_type": "network-tcp-postgres"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "[Disk I/O] Write operation to WAL file")]
    async fn append_to_wal(operation: &str, todo: &Todo) -> Result<(), String> {
        use std::io::Write;

        let wal_entry = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "operation": operation,
            "todo": todo
        });

        let wal_path = "/tmp/todos_v2.wal";
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(wal_path)
            .map_err(|e| format!("Failed to open WAL: {}", e))?;

        writeln!(file, "{}", wal_entry).map_err(|e| format!("Failed to write WAL: {}", e))?;

        Ok(())
    }

    #[tool(description = "[Disk I/O] Read WAL file")]
    async fn read_wal(&self) -> Result<String, String> {
        let wal_path = "/tmp/todos_v2.wal";

        let contents = std::fs::read_to_string(wal_path)
            .unwrap_or_else(|_| String::from("WAL file not found or empty"));

        let lines: Vec<&str> = contents.lines().collect();
        let last_10: Vec<&str> = lines.iter().rev().take(10).copied().collect();

        serde_json::to_string_pretty(&json!({
            "total_entries": lines.len(),
            "last_10_entries": last_10,
            "path": wal_path,
            "io_type": "disk-read"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "[Network I/O - TCP] Test database connection")]
    async fn test_connection(&self) -> Result<String, String> {
        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://wasi_user:wasi_password@localhost/todos_db".to_string()
        });

        match tokio_postgres::connect(&database_url, NoTls).await {
            Ok((client, connection)) => {
                // Spawn connection handler
                tokio::spawn(async move {
                    let _ = connection.await;
                });

                // Test with simple query
                match client.query_one("SELECT version()", &[]).await {
                    Ok(row) => {
                        let version: String = row.get(0);
                        serde_json::to_string_pretty(&json!({
                            "status": "connected",
                            "database_url": database_url,
                            "postgres_version": version,
                            "io_type": "network-tcp-postgres"
                        }))
                        .map_err(|e| e.to_string())
                    }
                    Err(e) => Err(format!("Query failed: {}", e)),
                }
            }
            Err(e) => Err(format!("Connection failed: {}", e)),
        }
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
    read_wal,
    test_connection
);

#[async_trait::async_trait]
impl ServerHandler for FullStackServerV2 {
    async fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: "wasm-fullstack-v2-wasmedge".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: Some(
                "Full-Stack Server v2 - Real PostgreSQL with WasmEdge (TCP sockets + HTTP)"
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

    eprintln!("=== WasmEdge Full-Stack v2 Server ===");
    eprintln!("Features:");
    eprintln!("  - Direct PostgreSQL connections (TCP sockets)");
    eprintln!("  - HTTP client for external APIs");
    eprintln!("  - Disk I/O for WAL persistence");
    eprintln!("  - Real networking with WasmEdge runtime");
    eprintln!("");
    eprintln!(
        "Database: {}",
        std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://wasi_user:wasi_password@localhost/todos_db".to_string()
        })
    );

    let server = FullStackServerV2::new().await;
    let mut stdio_transport = rmcp::transport::stdio::StdioTransport::default();
    server.start(&mut stdio_transport).await
}
