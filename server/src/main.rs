//! Binary entry point for the HTTP control plane.

use std::collections::HashMap;
use std::sync::Arc;

use audit::InMemoryAuditSink;
use domain::ForgeKind;
use forge::gitlab::{GitLabAdapter, GitLabConfig};
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use server::{
    auth::AgentRegistry,
    build_router,
    config::{ForgeConfig, parse_config, validate_config},
    events::EventBus,
    handlers::AppState,
    registry::{ForgeInstance, ForgeRegistry},
};

fn server_version() -> String {
    let commit = env!("GIT_COMMIT_SHORT");
    format!("{}+{commit}", env!("CARGO_PKG_VERSION"))
}

#[allow(clippy::needless_pass_by_value)]
fn build_forge_instance<A>(
    adapter: Arc<A>,
    audit_sink: &Arc<InMemoryAuditSink>,
    client: &reqwest::Client,
    forge_config: &ForgeConfig,
    forge_kind: ForgeKind,
) -> ForgeInstance
where
    A: forge::ForgeAdapter + forge::ForgeWebhookAdapter + 'static,
{
    let rest_adapter: Arc<dyn forge::ForgeAdapter> = adapter.clone();
    let webhook_adapter: Arc<dyn forge::ForgeWebhookAdapter> = adapter.clone();

    let read_service = Arc::new(ReadOrchestrator::new(
        Arc::clone(&adapter),
        Arc::clone(audit_sink),
    ));

    let write_service = Arc::new(WriteOrchestrator::new(
        Arc::clone(&adapter),
        Arc::clone(audit_sink),
    ));

    ForgeInstance {
        adapter: rest_adapter,
        alias: forge_config.alias.clone(),
        base_url: forge_config.base_url.clone(),
        client: client.clone(),
        forge_kind,
        forge_type: forge_config.forge_type.clone(),
        git_auth_user: forge_config.git_auth_user.clone(),
        read_service,
        token: forge_config.token.clone(),
        webhook: forge_config.webhook.clone(),
        webhook_adapter,
        write_service,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "forge-mcp.toml".to_string());

    let config_str = std::fs::read_to_string(&config_path)
        .map_err(|e| format!("failed to read config file {config_path}: {e}"))?;

    let config = parse_config(&config_str)
        .map_err(|e| format!("failed to parse config file {config_path}: {e}"))?;

    validate_config(&config).map_err(|e| format!("invalid configuration: {e}"))?;

    tracing::info!(version = %server_version(), listen = %config.server.listen, "forge-mcp starting");

    let audit_sink = Arc::new(InMemoryAuditSink::new());
    let client = reqwest::Client::new();
    let mut forges = HashMap::new();

    for forge_config in &config.forges {
        let instance = match forge_config.forge_type.as_str() {
            "forgejo" => {
                let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
                    base_url: forge_config.base_url.clone(),
                    token: forge_config.token.clone(),
                })?);
                build_forge_instance(
                    adapter,
                    &audit_sink,
                    &client,
                    forge_config,
                    ForgeKind::Forgejo,
                )
            }
            "gitlab" => {
                let adapter = Arc::new(GitLabAdapter::new(GitLabConfig {
                    base_url: forge_config.base_url.clone(),
                    token: forge_config.token.clone(),
                })?);
                build_forge_instance(
                    adapter,
                    &audit_sink,
                    &client,
                    forge_config,
                    ForgeKind::GitLab,
                )
            }
            other => {
                return Err(format!(
                    "unsupported forge type '{other}' for alias '{}'",
                    forge_config.alias
                )
                .into());
            }
        };

        forges.insert(forge_config.alias.clone(), instance);
        tracing::info!(alias = %forge_config.alias, url = %forge_config.base_url, "registered forge");
    }

    let agent_registry = AgentRegistry::from_configs(&config.agents);
    let event_bus = EventBus::new();
    let forge_registry = Arc::new(ForgeRegistry::new(forges));
    let auto_merge_service = Arc::new(server::auto_merge::AutoMergeService::new(
        event_bus.clone(),
        forge_registry.clone(),
    ));
    let state = AppState {
        agent_registry,
        audit_sink,
        auto_merge_service,
        event_bus,
        forge_registry,
    };

    let app = build_router(state, config.server.enable_docs);

    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    tracing::info!("forge-mcp ready");
    axum::serve(listener, app).await?;

    Ok(())
}
