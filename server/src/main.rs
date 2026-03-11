//! Binary entry point for the stdio MCP server.

use std::{env, sync::Arc};

use audit::InMemoryAuditSink;
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::ReadOrchestrator;
use transport::{ForgejoMcpConfig, serve_stdio};

fn server_version() -> String {
    format!("{}+{}", env!("CARGO_PKG_VERSION"), env!("GIT_COMMIT_SHORT"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let forgejo_base_url = env::var("FORGEJO_BASE_URL")
        .expect("FORGEJO_BASE_URL environment variable must be set");
    let forgejo_token = env::var("FORGEJO_TOKEN").ok();
    let agent_id = env::var("FORGE_MCP_AGENT_ID").unwrap_or_else(|_| "codex".to_string());
    let session_id =
        env::var("FORGE_MCP_SESSION_ID").unwrap_or_else(|_| "stdio-session".to_string());

    let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
        base_url: forgejo_base_url.clone(),
        token: forgejo_token,
    }));
    let audit_sink = Arc::new(InMemoryAuditSink::new());
    let read_service = Arc::new(ReadOrchestrator::new(adapter, audit_sink));
    let config = ForgejoMcpConfig {
        forgejo_base_url,
        agent_id,
        session_id,
        server_name: "forge-mcp".to_string(),
        server_version: server_version(),
    };

    serve_stdio(config, read_service).await?;
    Ok(())
}
