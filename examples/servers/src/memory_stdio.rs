use std::error::Error;
mod common;
use common::generic_service::{GenericService, MemoryDataService};
use mcpkit_rs::serve_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let memory_service = MemoryDataService::new("initial data");

    let generic_service = GenericService::new(memory_service);

    println!("start server, connect to standard input/output");

    let io = (tokio::io::stdin(), tokio::io::stdout());

    serve_server(generic_service, io).await?;
    Ok(())
}
