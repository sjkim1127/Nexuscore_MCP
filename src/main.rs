use anyhow::Result;
use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    // Logging to file purely, or stderr? Stdio transport uses stdout, so NO LOGS to stdout!
    // We must log to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting NexusCore MCP Server (RMCP Standard)...");
    nexuscore_mcp::server::run_server().await
}
