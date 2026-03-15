//! Binary entry point for the HTTP control plane.

use std::collections::HashMap;
use std::sync::Arc;

use audit::InMemoryAuditSink;
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use server::{
    auth::AgentRegistry,
    build_router,
    config::{parse_config, validate_config},
    handlers::AppState,
    registry::{ForgeInstance, ForgeRegistry},
};

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

    validate_config(&config).unwrap_or_else(|e| panic!("invalid configuration: {e}"));

    eprintln!(
        "forge-mcp {} — listening on {}",
        server_version(),
        config.server.listen
    );

    let audit_sink = Arc::new(InMemoryAuditSink::new());
    let client = reqwest::Client::new();
    let mut forges = HashMap::new();

    for forge_config in &config.forges {
        match forge_config.forge_type.as_str() {
            "forgejo" => {
                let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
                    base_url: forge_config.base_url.clone(),
                    token: forge_config.token.clone(),
                }));

                let read_service = Arc::new(ReadOrchestrator::new(
                    Arc::clone(&adapter),
                    Arc::clone(&audit_sink),
                ));

                let write_service = Arc::new(WriteOrchestrator::new(
                    Arc::clone(&adapter),
                    Arc::clone(&audit_sink),
                    forge_config.token.clone(),
                ));

                forges.insert(
                    forge_config.alias.clone(),
                    ForgeInstance {
                        adapter,
                        alias: forge_config.alias.clone(),
                        base_url: forge_config.base_url.clone(),
                        client: client.clone(),
                        forge_type: forge_config.forge_type.clone(),
                        git_auth_user: forge_config.git_auth_user.clone(),
                        read_service,
                        token: forge_config.token.clone(),
                        write_service,
                    },
                );
            }
            other => panic!(
                "unsupported forge type '{other}' for alias '{}'",
                forge_config.alias
            ),
        }

        eprintln!(
            "  forge '{}' → {}",
            forge_config.alias, forge_config.base_url
        );
    }

    let agent_registry = AgentRegistry::from_configs(&config.agents);
    let state = AppState {
        agent_registry,
        audit_sink,
        forge_registry: Arc::new(ForgeRegistry::new(forges)),
    };

    let app = build_router(state, config.server.enable_docs);

    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    eprintln!("forge-mcp ready");
    axum::serve(listener, app).await?;

    Ok(())
}
