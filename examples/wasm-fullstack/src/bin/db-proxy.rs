// Database proxy server that WASI v2 can call via HTTP
// This runs as a native binary, not WASM

use std::time::Duration;

use axum::{
    extract::Query,
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, FromRow, Pool, Postgres};
use tower_http::cors::CorsLayer;

#[derive(Debug, FromRow, Serialize, Deserialize)]
struct Todo {
    id: String,
    user_id: i32,
    title: String,
    completed: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
struct CreateTodo {
    title: String,
    user_id: i32,
}

#[derive(Debug, Deserialize)]
struct UpdateTodo {
    title: Option<String>,
    completed: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct TodoQuery {
    user_id: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct SqlQuery {
    query: String,
    params: Option<Vec<Value>>,
}

type DbPool = Pool<Postgres>;

async fn get_todos(
    Query(params): Query<TodoQuery>,
    pool: axum::extract::State<DbPool>,
) -> Result<Json<Vec<Todo>>, StatusCode> {
    let todos = if let Some(user_id) = params.user_id {
        sqlx::query_as::<_, Todo>("SELECT * FROM todos WHERE user_id = $1 ORDER BY created_at DESC")
            .bind(user_id)
            .fetch_all(&*pool)
            .await
    } else {
        sqlx::query_as::<_, Todo>("SELECT * FROM todos ORDER BY created_at DESC")
            .fetch_all(&*pool)
            .await
    };

    match todos {
        Ok(todos) => Ok(Json(todos)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn create_todo(
    pool: axum::extract::State<DbPool>,
    Json(todo): Json<CreateTodo>,
) -> Result<Json<Todo>, StatusCode> {
    let id = format!("todo-{}", uuid::Uuid::new_v4());

    let result = sqlx::query_as::<_, Todo>(
        "INSERT INTO todos (id, user_id, title) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(&id)
    .bind(todo.user_id)
    .bind(todo.title)
    .fetch_one(&*pool)
    .await;

    match result {
        Ok(todo) => Ok(Json(todo)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn update_todo(
    pool: axum::extract::State<DbPool>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(update): Json<UpdateTodo>,
) -> Result<Json<Todo>, StatusCode> {
    let mut query = String::from("UPDATE todos SET updated_at = NOW()");
    let mut param_count = 1;

    if update.title.is_some() {
        param_count += 1;
        query.push_str(&format!(", title = ${}", param_count));
    }
    if update.completed.is_some() {
        param_count += 1;
        query.push_str(&format!(", completed = ${}", param_count));
    }

    query.push_str(" WHERE id = $1 RETURNING *");

    let mut q = sqlx::query_as::<_, Todo>(&query).bind(&id);

    if let Some(title) = update.title {
        q = q.bind(title);
    }
    if let Some(completed) = update.completed {
        q = q.bind(completed);
    }

    match q.fetch_one(&*pool).await {
        Ok(todo) => Ok(Json(todo)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn delete_todo(
    pool: axum::extract::State<DbPool>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query("DELETE FROM todos WHERE id = $1")
        .bind(&id)
        .execute(&*pool)
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => Ok(StatusCode::NO_CONTENT),
        Ok(_) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn execute_sql(
    pool: axum::extract::State<DbPool>,
    Json(sql): Json<SqlQuery>,
) -> Result<Json<Value>, StatusCode> {
    // For safety, only allow SELECT queries through this endpoint
    if !sql.query.trim().to_uppercase().starts_with("SELECT") {
        return Ok(Json(json!({
            "error": "Only SELECT queries are allowed through this endpoint"
        })));
    }

    let result = sqlx::query(&sql.query).fetch_all(&*pool).await;

    match result {
        Ok(rows) => {
            // Convert rows to JSON
            let json_rows: Vec<Value> = rows
                .iter()
                .map(|row| {
                    // This is simplified - in production you'd properly serialize the row
                    json!({
                        "data": "row data"
                    })
                })
                .collect();

            Ok(Json(json!({
                "rows": json_rows,
                "count": json_rows.len()
            })))
        }
        Err(e) => Ok(Json(json!({
            "error": e.to_string()
        }))),
    }
}

async fn get_stats(pool: axum::extract::State<DbPool>) -> Result<Json<Value>, StatusCode> {
    let result = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT total, completed, pending, unique_users FROM todo_stats",
    )
    .fetch_one(&*pool)
    .await;

    match result {
        Ok((total, completed, pending, unique_users)) => Ok(Json(json!({
            "total": total,
            "completed": completed,
            "pending": pending,
            "unique_users": unique_users,
            "completion_rate": if total > 0 {
                (completed as f64 / total as f64 * 100.0) as i32
            } else { 0 }
        }))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://wasi_user:wasi_password@localhost/todos_db".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let app = Router::new()
        .route("/todos", get(get_todos).post(create_todo))
        .route(
            "/todos/:id",
            axum::routing::put(update_todo).delete(delete_todo),
        )
        .route("/sql", post(execute_sql))
        .route("/stats", get(get_stats))
        .layer(CorsLayer::permissive())
        .with_state(pool);

    let addr = "127.0.0.1:3000";
    println!("Database proxy server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}

// Add uuid module
mod uuid {
    pub struct Uuid;

    impl Uuid {
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
}
