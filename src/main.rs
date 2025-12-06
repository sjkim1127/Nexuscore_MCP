use anyhow::Result;
use dotenv::dotenv;
use tokio::io::{stdin, stdout};
use nexuscore_mcp::server::NexusCoreServer;
use rmcp::ServiceExt;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    // Logging to file purely, or stderr? Stdio transport uses stdout, so NO LOGS to stdout!
    // We must log to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting NexusCore MCP Server (RMCP Standard)...");

    // Initialize the Service (Server Handler)
    let service = NexusCoreServer::new();
    
    // Transport: Stdio
    let transport = (stdin(), stdout());

    // Run Server
    tracing::info!("Listening on Stdio...");
    let _ = service.serve(transport).await?;

    Ok(())
}
