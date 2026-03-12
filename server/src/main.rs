//! Binary entry point for the HTTP control plane.

use std::sync::Arc;

use audit::InMemoryAuditSink;
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use server::{auth::AgentRegistry, build_router, config::parse_config, handlers::AppState};

fn server_version() -> String {
    let commit = env!("GIT_COMMIT_SHORT");
    format!("{}+{commit}", env!("CARGO_PKG_VERSION"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "forge-mcp.toml".to_string());

    let config_str = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read config file {config_path}: {e}"));

    let config = parse_config(&config_str)
        .unwrap_or_else(|e| panic!("failed to parse config file {config_path}: {e}"));

    eprintln!(
        "forge-mcp {} — listening on {}",
        server_version(),
        config.server.listen
    );

    let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
        base_url: config.forge.forgejo.base_url.clone(),
        token: Some(config.forge.forgejo.token.clone()),
    }));
    let audit_sink = Arc::new(InMemoryAuditSink::new());

    let read_service = Arc::new(ReadOrchestrator::new(
        Arc::clone(&adapter),
        Arc::clone(&audit_sink),
    ));

    let write_service = Arc::new(WriteOrchestrator::new(
        adapter,
        audit_sink,
        Some(config.forge.forgejo.token.clone()),
        domain::policy::PolicyConfig::default(),
    ));

    let agent_registry = AgentRegistry::from_configs(&config.agents);
    let state = AppState {
        agent_registry,
        forgejo_base_url: config.forge.forgejo.base_url,
        read_service,
        write_service,
    };

    let app = build_router(state, config.server.enable_docs);

    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    eprintln!("forge-mcp ready");
    axum::serve(listener, app).await?;

    Ok(())
}
