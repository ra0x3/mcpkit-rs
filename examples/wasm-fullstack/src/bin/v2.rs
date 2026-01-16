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
    pub id: String,
    pub user_id: i32,
    pub title: String,
    pub completed: bool,
    pub created_at: String,
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
pub struct BatchUpdateRequest {
    #[schemars(description = "List of todo IDs to update")]
    pub ids: Vec<String>,
    #[schemars(description = "New title for all todos")]
    pub title: Option<String>,
    #[schemars(description = "New completed status for all todos")]
    pub completed: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct SearchTodosRequest {
    #[schemars(description = "Keyword to search in todo titles")]
    pub keyword: String,
    #[schemars(description = "User ID to filter by")]
    pub user_id: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct GetStatsRequest {
    #[schemars(description = "User ID to get stats for")]
    pub user_id: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExportTodosRequest {
    #[schemars(description = "User ID to export todos for")]
    pub user_id: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct ImportTodosRequest {
    #[schemars(description = "JSON array of todos to import")]
    pub todos: String,
}

#[derive(Debug, Clone)]
pub struct FullStackServerV2 {
    tool_router: ToolRouter<Self>,
    todos: Arc<Mutex<HashMap<String, Todo>>>,
}

impl FullStackServerV2 {
    pub async fn new() -> Self {
        let server = Self {
            tool_router: Self::tool_router(),
            todos: Arc::new(Mutex::new(HashMap::new())),
        };

        let mut todos = HashMap::new();
        todos.insert(
            "todo-1".to_string(),
            Todo {
                id: "todo-1".to_string(),
                user_id: 1,
                title: "Setup PostgreSQL database".to_string(),
                completed: true,
                created_at: chrono::Utc::now().to_rfc3339(),
            },
        );
        if let Ok(mut t) = server.todos.lock() {
            *t = todos;
        }

        server
    }
}

#[tool_router]
impl FullStackServerV2 {
    #[tool(description = "Fetch todos")]
    async fn fetch_todos(
        &self,
        Parameters(req): Parameters<FetchTodosRequest>,
    ) -> Result<String, String> {
        let todos = self.todos.lock().map_err(|e| e.to_string())?;
        let filtered: Vec<Todo> = if let Some(user_id) = req.user_id {
            todos
                .values()
                .filter(|t| t.user_id == user_id)
                .cloned()
                .collect()
        } else {
            todos.values().cloned().collect()
        };

        serde_json::to_string_pretty(&json!({
            "todos": filtered,
            "count": filtered.len(),
            "source": "in-memory"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Create a new todo")]
    async fn create_todo(
        &self,
        Parameters(req): Parameters<CreateTodoRequest>,
    ) -> Result<String, String> {
        let todo_id = format!("todo-{}", uuid::new_v4());

        let todo = Todo {
            id: todo_id.clone(),
            user_id: req.user_id,
            title: req.title.clone(),
            completed: false,
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        let mut todos = self.todos.lock().map_err(|e| e.to_string())?;
        todos.insert(todo.id.clone(), todo.clone());

        serde_json::to_string_pretty(&json!({
            "id": todo_id,
            "title": req.title,
            "user_id": req.user_id,
            "source": "in-memory"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Update a todo")]
    async fn update_todo(
        &self,
        Parameters(req): Parameters<UpdateTodoRequest>,
    ) -> Result<String, String> {
        let mut todos = self.todos.lock().map_err(|e| e.to_string())?;
        if let Some(todo) = todos.get_mut(&req.id) {
            if let Some(title) = req.title {
                todo.title = title;
            }
            if let Some(completed) = req.completed {
                todo.completed = completed;
            }
            return serde_json::to_string_pretty(&json!({
                "id": req.id,
                "updated": true,
                "source": "in-memory"
            }))
            .map_err(|e| e.to_string());
        }

        Err(format!("Todo {} not found", req.id))
    }

    #[tool(description = "Delete a todo")]
    async fn delete_todo(
        &self,
        Parameters(req): Parameters<DeleteTodoRequest>,
    ) -> Result<String, String> {
        let mut todos = self.todos.lock().map_err(|e| e.to_string())?;
        if todos.remove(&req.id).is_some() {
            return serde_json::to_string_pretty(&json!({
                "id": req.id,
                "deleted": true,
                "source": "in-memory"
            }))
            .map_err(|e| e.to_string());
        }

        Err(format!("Todo {} not found", req.id))
    }

    #[tool(description = "Update multiple todos at once")]
    async fn batch_update(
        &self,
        Parameters(req): Parameters<BatchUpdateRequest>,
    ) -> Result<String, String> {
        if req.ids.is_empty() {
            return Err("No todo IDs provided".to_string());
        }

        if req.title.is_none() && req.completed.is_none() {
            return Err("No updates specified".to_string());
        }

        let mut updated_count = 0;
        let mut todos = self.todos.lock().map_err(|e| e.to_string())?;
        for id in &req.ids {
            if let Some(todo) = todos.get_mut(id) {
                if let Some(title) = &req.title {
                    todo.title = title.clone();
                }
                if let Some(completed) = req.completed {
                    todo.completed = completed;
                }
                updated_count += 1;
            }
        }

        serde_json::to_string_pretty(&json!({
            "updated": updated_count,
            "total": req.ids.len(),
            "source": "in-memory"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Search todos by title keyword")]
    async fn search_todos(
        &self,
        Parameters(req): Parameters<SearchTodosRequest>,
    ) -> Result<String, String> {
        let keyword_lower = req.keyword.to_lowercase();
        let todos = self.todos.lock().map_err(|e| e.to_string())?;
        let mut filtered: Vec<Todo> = todos
            .values()
            .filter(|t| t.title.to_lowercase().contains(&keyword_lower))
            .cloned()
            .collect();

        if let Some(user_id) = req.user_id {
            filtered.retain(|t| t.user_id == user_id);
        }

        serde_json::to_string_pretty(&json!({
            "todos": filtered,
            "count": filtered.len(),
            "keyword": req.keyword,
            "source": "in-memory"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Get statistics about todos")]
    async fn get_stats(
        &self,
        Parameters(req): Parameters<GetStatsRequest>,
    ) -> Result<String, String> {
        let todos = self.todos.lock().map_err(|e| e.to_string())?;
        let filtered: Vec<&Todo> = if let Some(user_id) = req.user_id {
            todos.values().filter(|t| t.user_id == user_id).collect()
        } else {
            todos.values().collect()
        };

        let total = filtered.len() as i64;
        let completed = filtered.iter().filter(|t| t.completed).count() as i64;
        let pending = total - completed;

        serde_json::to_string_pretty(&json!({
            "total": total,
            "completed": completed,
            "pending": pending,
            "completion_rate": if total > 0 { completed as f64 / total as f64 * 100.0 } else { 0.0 },
            "source": "in-memory"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Export todos as CSV format")]
    async fn export_todos(
        &self,
        Parameters(req): Parameters<ExportTodosRequest>,
    ) -> Result<String, String> {
        let todos = self.todos.lock().map_err(|e| e.to_string())?;
        let todos_list: Vec<Todo>;
        todos_list = if let Some(user_id) = req.user_id {
            todos
                .values()
                .filter(|t| t.user_id == user_id)
                .cloned()
                .collect()
        } else {
            todos.values().cloned().collect()
        };

        let mut csv = String::from("id,user_id,title,completed,created_at\n");
        for todo in &todos_list {
            csv.push_str(&format!(
                "{},{},\"{}\",{},{}\n",
                todo.id,
                todo.user_id,
                todo.title.replace("\"", "\"\""),
                todo.completed,
                todo.created_at
            ));
        }

        serde_json::to_string_pretty(&json!({
            "csv": csv,
            "count": todos_list.len(),
            "source": "in-memory"
        }))
        .map_err(|e| e.to_string())
    }

    #[tool(description = "Import todos from JSON array")]
    async fn import_todos(
        &self,
        Parameters(req): Parameters<ImportTodosRequest>,
    ) -> Result<String, String> {
        #[derive(Deserialize)]
        struct ImportTodo {
            title: String,
            user_id: i32,
            completed: Option<bool>,
        }

        let import_todos: Vec<ImportTodo> = serde_json::from_str(&req.todos)
            .map_err(|e| format!("Invalid JSON: {}", e))?;

        if import_todos.is_empty() {
            return Err("No todos to import".to_string());
        }

        let mut imported_count = 0;
        let failed_count = 0;
        let mut todos = self.todos.lock().map_err(|e| e.to_string())?;

        for import_todo in import_todos {
            let todo_id = format!("todo-{}", uuid::new_v4());
            let todo = Todo {
                id: todo_id.clone(),
                user_id: import_todo.user_id,
                title: import_todo.title,
                completed: import_todo.completed.unwrap_or(false),
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            todos.insert(todo_id, todo);
            imported_count += 1;
        }

        serde_json::to_string_pretty(&json!({
            "imported": imported_count,
            "failed": failed_count,
            "source": "in-memory"
        }))
        .map_err(|e| e.to_string())
    }
}

#[tool_handler]
impl ServerHandler for FullStackServerV2 {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Full-Stack Server v2 - PostgreSQL via WasmEdge with extended operations"
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

mod uuid {
    pub fn new_v4() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let random = (timestamp * 1103515245 + 12345) & 0x7fffffff;
        format!("{:x}-{:x}", timestamp & 0xffffffff, random)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

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
