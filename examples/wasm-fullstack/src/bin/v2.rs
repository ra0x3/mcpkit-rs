// V2 - Enhanced in-memory version for WasmEdge runtime
// Note: Direct PostgreSQL connections require special WasmEdge builds
// This version demonstrates advanced in-memory features

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Todo {
    pub id: i32,
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
pub struct BatchProcessRequest {
    #[schemars(description = "List of todo IDs")]
    pub ids: Vec<i32>,
    #[schemars(description = "Operation: 'complete', 'delete', or 'archive'")]
    pub operation: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SearchRequest {
    #[schemars(description = "Search term to look for in todo titles")]
    pub title_contains: String,
}

#[derive(Debug, Clone)]
pub struct FullStackServerV2 {
    tool_router: ToolRouter<Self>,
    todos: Arc<Mutex<HashMap<i32, Todo>>>,
    next_id: Arc<Mutex<i32>>,
}

impl FullStackServerV2 {
    pub async fn new() -> Self {
        // Pre-populate with some sample data
        let todos = Arc::new(Mutex::new(HashMap::new()));
        let next_id = Arc::new(Mutex::new(1));

        // Add sample todos
        {
            let mut todos_map = todos.lock().unwrap();
            let mut id = next_id.lock().unwrap();

            todos_map.insert(
                *id,
                Todo {
                    id: *id,
                    user_id: 1,
                    title: "Complete WASM fullstack example".to_string(),
                    completed: false,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    updated_at: None,
                },
            );
            *id += 1;

            todos_map.insert(
                *id,
                Todo {
                    id: *id,
                    user_id: 1,
                    title: "Test with WasmEdge runtime".to_string(),
                    completed: false,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    updated_at: None,
                },
            );
            *id += 1;
        }

        Self {
            tool_router: Self::tool_router(),
            todos,
            next_id,
        }
    }

    fn write_wal_sync(operation: &str, todo: &Todo) {
        use std::io::Write;

        let wal_entry = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "operation": operation,
            "todo": todo
        });

        let wal_path = "/tmp/todos_v2.wal";
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(wal_path)
        {
            let _ = writeln!(file, "{}", wal_entry);
        }
    }
}

// Tool implementations
#[tool_router]
impl FullStackServerV2 {
    #[tool(description = "Fetch todos from in-memory storage")]
    async fn fetch_todos(
        &self,
        Parameters(req): Parameters<FetchTodosRequest>,
    ) -> Result<String, String> {
        let todos = self.todos.lock().map_err(|e| e.to_string())?;

        let mut filtered: Vec<&Todo> = if let Some(user_id) = req.user_id {
            todos.values().filter(|t| t.user_id == user_id).collect()
        } else {
            todos.values().collect()
        };

        // Sort by ID descending
        filtered.sort_by(|a, b| b.id.cmp(&a.id));

        serde_json::to_string_pretty(&json!({
            "todos": filtered,
            "count": filtered.len(),
            "source": "in-memory-v2"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Create todo in memory")]
    async fn create_todo(
        &self,
        Parameters(req): Parameters<CreateTodoRequest>,
    ) -> Result<String, String> {
        let todo = {
            let mut todos = self.todos.lock().map_err(|e| e.to_string())?;
            let mut next_id = self.next_id.lock().map_err(|e| e.to_string())?;

            let todo = Todo {
                id: *next_id,
                user_id: req.user_id,
                title: req.title,
                completed: false,
                created_at: chrono::Utc::now().to_rfc3339(),
                updated_at: None,
            };

            todos.insert(*next_id, todo.clone());
            *next_id += 1;
            todo
        }; // Release locks before writing WAL

        // Write to audit log
        Self::write_wal_sync("CREATE", &todo);

        serde_json::to_string_pretty(&json!({
            "created": todo,
            "source": "in-memory-v2"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Update todo in memory")]
    async fn update_todo(
        &self,
        Parameters(req): Parameters<UpdateTodoRequest>,
    ) -> Result<String, String> {
        let updated_todo = {
            let mut todos = self.todos.lock().map_err(|e| e.to_string())?;

            match todos.get_mut(&req.id) {
                Some(todo) => {
                    if let Some(title) = req.title {
                        todo.title = title;
                    }
                    if let Some(completed) = req.completed {
                        todo.completed = completed;
                    }
                    todo.updated_at = Some(chrono::Utc::now().to_rfc3339());
                    Ok(todo.clone())
                }
                None => Err(format!("Todo with id {} not found", req.id)),
            }
        }?; // Release lock before writing WAL

        // Write to audit log
        Self::write_wal_sync("UPDATE", &updated_todo);

        serde_json::to_string_pretty(&json!({
            "updated": updated_todo,
            "source": "in-memory-v2"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Delete todo from memory")]
    async fn delete_todo(
        &self,
        Parameters(req): Parameters<DeleteTodoRequest>,
    ) -> Result<String, String> {
        let deleted_todo = {
            let mut todos = self.todos.lock().map_err(|e| e.to_string())?;
            todos.remove(&req.id)
        };

        if let Some(todo) = deleted_todo {
            // Write to audit log before deletion
            Self::write_wal_sync("DELETE", &todo);

            serde_json::to_string_pretty(&json!({
                "deleted": true,
                "id": req.id,
                "source": "in-memory-v2"
            }))
            .map_err(|e| e.to_string())
        } else {
            Err(format!("Todo with id {} not found", req.id))
        }
    }

    #[tool(description = "Batch process todos")]
    async fn batch_process(
        &self,
        Parameters(req): Parameters<BatchProcessRequest>,
    ) -> Result<String, String> {
        if req.ids.is_empty() {
            return Err("No IDs provided".to_string());
        }

        let mut todos = self.todos.lock().map_err(|e| e.to_string())?;
        let mut rows_affected = 0;

        match req.operation.as_str() {
            "complete" => {
                for id in &req.ids {
                    if let Some(todo) = todos.get_mut(id) {
                        todo.completed = true;
                        todo.updated_at = Some(chrono::Utc::now().to_rfc3339());
                        rows_affected += 1;
                    }
                }
            }
            "delete" => {
                for id in &req.ids {
                    if todos.remove(id).is_some() {
                        rows_affected += 1;
                    }
                }
            }
            "archive" => {
                for id in &req.ids {
                    if let Some(todo) = todos.get_mut(id) {
                        todo.completed = true;
                        todo.title = format!("[ARCHIVED] {}", todo.title);
                        todo.updated_at = Some(chrono::Utc::now().to_rfc3339());
                        rows_affected += 1;
                    }
                }
            }
            _ => return Err(format!("Unknown operation: {}", req.operation)),
        }

        serde_json::to_string_pretty(&json!({
            "operation": req.operation,
            "ids": req.ids,
            "rows_affected": rows_affected,
            "source": "in-memory-v2"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Get statistics")]
    async fn db_stats(&self) -> Result<String, String> {
        let todos = self.todos.lock().map_err(|e| e.to_string())?;

        let total = todos.len();
        let completed = todos.values().filter(|t| t.completed).count();
        let unique_users: std::collections::HashSet<i32> =
            todos.values().map(|t| t.user_id).collect();

        serde_json::to_string_pretty(&json!({
            "total": total,
            "completed": completed,
            "pending": total - completed,
            "unique_users": unique_users.len(),
            "completion_rate": if total > 0 {
                completed as f64 / total as f64 * 100.0
            } else {
                0.0
            },
            "source": "in-memory-v2"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Read WAL file")]
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
            "source": "disk"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Search todos by title")]
    async fn search_todos(
        &self,
        Parameters(req): Parameters<SearchRequest>,
    ) -> Result<String, String> {
        let todos = self.todos.lock().map_err(|e| e.to_string())?;

        let filtered: Vec<&Todo> = todos
            .values()
            .filter(|t| {
                t.title
                    .to_lowercase()
                    .contains(&req.title_contains.to_lowercase())
            })
            .collect();

        serde_json::to_string_pretty(&json!({
            "search_term": req.title_contains,
            "results": filtered,
            "count": filtered.len(),
            "source": "in-memory-v2"
        }))
        .map_err(|e| e.to_string())
    }
}

#[tool_handler]
impl ServerHandler for FullStackServerV2 {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("Full-Stack Server v2 - Enhanced for WasmEdge".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    eprintln!("=== Full-Stack v2 Server (WasmEdge) ===");
    eprintln!("Features:");
    eprintln!("  - Enhanced in-memory storage");
    eprintln!("  - WAL persistence to /tmp");
    eprintln!("  - Batch operations");
    eprintln!("  - Search functionality");
    eprintln!("");

    let server = FullStackServerV2::new().await;
    match server.serve(wasm_fullstack::wasi_io()).await {
        Ok(service) => {
            tracing::info!("Full-Stack Server v2 running");
            if let Err(e) = service.waiting().await {
                tracing::error!("Server error: {:?}", e);
            }
        }
        Err(e) => {
            tracing::error!("Failed to start server: {:?}", e);
        }
    }

    Ok(())
}
