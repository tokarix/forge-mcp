//! Binary entry point for the HTTP control plane.

use std::collections::HashMap;
use std::sync::Arc;

use audit::InMemoryAuditSink;
use domain::ForgeKind;
use forge::github::{
    GitHubAdapter, GitHubAppConfig as AdapterGitHubAppConfig, GitHubAppCredential, GitHubConfig,
};
use forge::gitlab::{GitLabAdapter, GitLabConfig};
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use server::{
    auth::AgentRegistry,
    build_router,
    config::{ForgeConfig, ServerConfig, parse_config, validate_config},
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
    let git_auth_user = if forge_kind == ForgeKind::GitHub && forge_config.git_auth_user.is_empty()
    {
        "x-access-token".to_string()
    } else {
        forge_config.git_auth_user.clone()
    };

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
        git_auth_user,
        read_service,
        token: forge_config.token.clone(),
        webhook: forge_config.webhook.clone(),
        webhook_adapter,
        write_service,
    }
}

async fn configured_forge_instance(
    forge_config: &ForgeConfig,
    audit_sink: &Arc<InMemoryAuditSink>,
    client: &reqwest::Client,
    agent_app_credentials: Vec<GitHubAppCredential>,
) -> Result<ForgeInstance, Box<dyn std::error::Error>> {
    let instance = match forge_config.forge_type.as_str() {
        "forgejo" => {
            let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
                base_url: forge_config.base_url.clone(),
                token: forge_config.token.clone(),
                woodpecker_url: forge_config.woodpecker_url.clone(),
                woodpecker_token: forge_config.woodpecker_token.clone(),
            })?);
            build_forge_instance(
                adapter,
                audit_sink,
                client,
                forge_config,
                ForgeKind::Forgejo,
            )
        }
        "gitlab" => {
            let adapter = Arc::new(GitLabAdapter::new(GitLabConfig {
                base_url: forge_config.base_url.clone(),
                token: forge_config.token.clone(),
            })?);
            build_forge_instance(adapter, audit_sink, client, forge_config, ForgeKind::GitLab)
        }
        "github" => {
            let github_config = GitHubConfig {
                api_url: forge_config.github_api_url(),
                token: forge_config.token.clone(),
            };
            let mut adapter = if let Some(app) = &forge_config.github_app {
                let private_key_pem =
                    std::fs::read_to_string(&app.private_key_path).map_err(|error| {
                        format!(
                            "failed to read GitHub App private key '{}' for forge '{}': {error}",
                            app.private_key_path, forge_config.alias
                        )
                    })?;
                GitHubAdapter::new_app(
                    github_config,
                    AdapterGitHubAppConfig {
                        app_id: app.app_id,
                        installation_id: app.installation_id,
                        private_key_pem,
                    },
                )
                .await?
            } else {
                GitHubAdapter::new(github_config)?
            };
            adapter.extend_managed_app_credentials(agent_app_credentials);
            build_forge_instance(
                Arc::new(adapter),
                audit_sink,
                client,
                forge_config,
                ForgeKind::GitHub,
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
    Ok(instance)
}

async fn configured_agent_github_apps(
    config: &ServerConfig,
) -> Result<HashMap<String, HashMap<String, GitHubAppCredential>>, Box<dyn std::error::Error>> {
    let mut credentials = HashMap::new();
    for agent in &config.agents {
        let mut agent_credentials = HashMap::new();
        for (forge_alias, app) in &agent.github_app {
            let forge_config = config
                .forges
                .iter()
                .find(|forge| forge.alias == *forge_alias)
                .ok_or_else(|| {
                    format!(
                        "agent '{}' references unknown GitHub forge '{forge_alias}'",
                        agent.agent_id
                    )
                })?;
            let private_key_pem =
                std::fs::read_to_string(&app.private_key_path).map_err(|error| {
                    format!(
                        "failed to read GitHub App private key '{}' for agent '{}' on forge '{}': {error}",
                        app.private_key_path, agent.agent_id, forge_alias
                    )
                })?;
            let credential = GitHubAppCredential::new(
                &forge_config.github_api_url(),
                AdapterGitHubAppConfig {
                    app_id: app.app_id,
                    installation_id: app.installation_id,
                    private_key_pem,
                },
            )
            .await?;
            agent_credentials.insert(forge_alias.clone(), credential);
            tracing::info!(
                agent_id = %agent.agent_id,
                forge = %forge_alias,
                app_id = app.app_id,
                installation_id = app.installation_id,
                "registered per-agent GitHub App identity"
            );
        }
        if !agent_credentials.is_empty() {
            credentials.insert(agent.token.clone(), agent_credentials);
        }
    }
    Ok(credentials)
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
    let agent_github_apps = configured_agent_github_apps(&config).await?;

    for forge_config in &config.forges {
        let agent_app_credentials = agent_github_apps
            .values()
            .filter_map(|credentials| credentials.get(&forge_config.alias).cloned())
            .collect();
        let instance =
            configured_forge_instance(forge_config, &audit_sink, &client, agent_app_credentials)
                .await?;

        forges.insert(forge_config.alias.clone(), instance);
        tracing::info!(alias = %forge_config.alias, url = %forge_config.base_url, "registered forge");
    }

    let agent_registry =
        AgentRegistry::from_configs_with_github_apps(&config.agents, agent_github_apps);
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
