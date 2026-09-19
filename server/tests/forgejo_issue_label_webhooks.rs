#[path = "../../forge/tests/support/forgejo.rs"]
mod forgejo;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use std::time::Duration;

use domain::ForgeKind;
use forge::{ForgejoAdapter, ForgejoConfig};
use forgejo::{Context, bounded_preview, combine_results, unique_name};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use reqwest::{Method, Url};
use rmcp::{
    ClientHandler, ServiceExt,
    model::{CallToolRequestParams, ClientConfig},
    service::{RoleClient, RunningService},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use server::auth::AgentRegistry;
use server::auto_merge::AutoMergeService;
use server::config::{AgentConfig, AgentPolicyConfig, ForgeWebhookConfig};
use server::events::EventBus;
use server::handlers::AppState;
use server::registry::{ForgeInstance, ForgeRegistry};
use transport::{GatewayConfig, McpShim, ShimConfig};

type WireHeaders = Arc<Mutex<HashMap<String, (String, String)>>>;

const CALLBACK_BASE_URL_ENV: &str = "FORGEJO_TEST_WEBHOOK_CALLBACK_BASE_URL";
const LISTEN_ADDR_ENV: &str = "FORGEJO_TEST_WEBHOOK_LISTEN_ADDR";
const FORGE_ALIAS: &str = "forgejo-test";
const AGENT_TOKEN: &str = "forge-mcp-ci-agent-token";

#[derive(Debug, Deserialize)]
struct HookResponse {
    id: u64,
}

#[derive(Debug, Deserialize)]
struct IssueResponse {
    number: u64,
}

#[derive(Debug, Deserialize)]
struct LabelResponse {
    id: u64,
}

#[derive(Clone, Debug, Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .map_err(|_| format!("provider test configuration is missing; set {name}"))
        .and_then(|value| {
            if value.is_empty() {
                Err(format!(
                    "provider test configuration variable {name} is empty"
                ))
            } else {
                Ok(value)
            }
        })
}

async fn request_success_redacted(
    context: &Context,
    method: Method,
    path: &str,
    body: Option<Value>,
    secrets: &[&str],
) -> Result<String, String> {
    let url = context
        .base_url
        .join(path.trim_start_matches('/'))
        .map_err(|error| format!("could not join Forgejo API path {path}: {error}"))?;
    let mut request = context
        .client
        .request(method.clone(), url)
        .bearer_auth(context.token());
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(|error| {
        bounded_preview(
            &format!(
                "Forgejo version={}: {method} {path} status=transport-error: {error}",
                context.version
            ),
            1024,
            secrets,
        )
    })?;
    let status = response.status();
    let response_body = response.text().await.map_err(|error| {
        bounded_preview(
            &format!(
                "Forgejo version={}: {method} {path} status={status} response read error: {error}",
                context.version
            ),
            1024,
            secrets,
        )
    })?;
    if !status.is_success() {
        return Err(bounded_preview(
            &format!(
                "Forgejo version={}: {method} {path} status={status} response={response_body}",
                context.version
            ),
            1024,
            secrets,
        ));
    }
    Ok(response_body)
}

async fn request_json_redacted<T: DeserializeOwned>(
    context: &Context,
    method: Method,
    path: &str,
    body: Option<Value>,
    secrets: &[&str],
) -> Result<T, String> {
    let response = request_success_redacted(context, method, path, body, secrets).await?;
    serde_json::from_str(&response).map_err(|error| {
        bounded_preview(
            &format!(
                "Forgejo version={}: {path} returned invalid JSON: {error}; response={response}",
                context.version
            ),
            1024,
            secrets,
        )
    })
}

async fn wait_for_subscriber(bus: &EventBus, phase: &str) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if bus.subscriber_count() > 0 {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "phase={phase} timed out waiting for SSE subscriber; subscriber_count={}",
                bus.subscriber_count()
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn poll_once(client: &RunningService<RoleClient, TestClient>) -> Result<Vec<Value>, String> {
    let result = client
        .call_tool(CallToolRequestParams::new("poll_events"))
        .await
        .map_err(|error| format!("poll_events failed: {error}"))?;
    let text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|content| content.text.as_str())
        .ok_or_else(|| "poll_events did not return text content".to_string())?;
    serde_json::from_str(text).map_err(|error| format!("invalid poll_events JSON: {error}"))
}

async fn poll_one_event(
    client: &RunningService<RoleClient, TestClient>,
    phase: &str,
) -> Result<Value, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let events = poll_once(client).await?;
        if events.len() == 1 {
            return events
                .into_iter()
                .next()
                .ok_or_else(|| "poll_events lost its single event".to_string());
        }
        if events.len() > 1 {
            return Err(format!(
                "phase={phase} expected one event, received {}",
                events.len()
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "phase={phase} timed out waiting for labels_changed event"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn validate_event(event: &Value, owner: &str, repo: &str, issue: u64) -> Result<String, String> {
    let meta = &event["meta"];
    if event["kind"] != "issue"
        || meta["event_kind"] != "issue"
        || meta["action"] != "labels_changed"
        || meta["forge_alias"] != FORGE_ALIAS
        || meta["owner"] != owner
        || meta["repo"] != repo
        || meta["issue"] != issue
        || !meta["change_request"].is_null()
        || !meta["head_sha"].is_null()
        || !meta["issue_comment"].is_null()
        || !meta["review_state"].is_null()
    {
        return Err(format!("unexpected labels_changed envelope: {event}"));
    }
    let delivery_id = meta["delivery_id"]
        .as_str()
        .filter(|delivery_id| !delivery_id.is_empty())
        .ok_or_else(|| "labels_changed event had an empty delivery ID".to_string())?;
    Ok(delivery_id.to_string())
}

fn build_state(
    context: &Context,
    repo: &str,
    webhook_secret: &str,
) -> Result<(AppState, EventBus), String> {
    let adapter = Arc::new(
        ForgejoAdapter::new(ForgejoConfig {
            base_url: context.base_url.to_string(),
            token: Some(context.token().to_string()),
            woodpecker_url: None,
            woodpecker_token: None,
        })
        .map_err(|error| format!("could not build Forgejo adapter: {error}"))?,
    );
    let audit_sink = Arc::new(audit::InMemoryAuditSink::new());
    let read_service = Arc::new(ReadOrchestrator::new(
        Arc::clone(&adapter),
        Arc::clone(&audit_sink),
    ));
    let write_service = Arc::new(WriteOrchestrator::new(
        Arc::clone(&adapter),
        Arc::clone(&audit_sink),
        None,
    ));
    let instance = ForgeInstance {
        adapter: adapter.clone(),
        alias: FORGE_ALIAS.to_string(),
        base_url: context.base_url.to_string(),
        client: server::http_client::client_builder()
            .build()
            .map_err(|error| format!("could not build HTTP client: {error}"))?,
        forge_kind: ForgeKind::Forgejo,
        forge_type: "forgejo".to_string(),
        git_auth_user: String::new(),
        read_service,
        token: Some(context.token().to_string()),
        webhook: Some(ForgeWebhookConfig {
            auto_merge: false,
            secret: webhook_secret.to_string(),
        }),
        webhook_adapter: adapter,
        write_service,
    };
    let forge_registry = Arc::new(ForgeRegistry::new(HashMap::from([(
        FORGE_ALIAS.to_string(),
        instance,
    )])));
    let event_bus = EventBus::new();
    let auto_merge_service = Arc::new(AutoMergeService::new(
        event_bus.clone(),
        Arc::clone(&forge_registry),
    ));
    let agents = [AgentConfig {
        agent_id: "ci-agent".to_string(),
        forge_identity: HashMap::new(),
        github_app: HashMap::new(),
        policy: AgentPolicyConfig {
            allowed_repos: vec![format!("{FORGE_ALIAS}/{}/{repo}", context.username)],
            branch_prefix: Some("agent/ci/".to_string()),
            protected_paths: vec![],
        },
        session_id: "forgejo-label-webhook-test".to_string(),
        token: AGENT_TOKEN.to_string(),
    }];
    Ok((
        AppState {
            agent_registry: AgentRegistry::from_configs(&agents),
            audit_sink,
            auto_merge_service,
            event_bus: event_bus.clone(),
            forge_registry,
        },
        event_bus,
    ))
}

#[tokio::test]
#[ignore = "runs only in the CI-provided disposable Forgejo webhook lane"]
#[allow(clippy::too_many_lines)]
async fn forgejo_issue_label_changes_reach_poll_events() -> Result<(), String> {
    let listen_addr = required_env(LISTEN_ADDR_ENV)?
        .parse::<SocketAddr>()
        .map_err(|error| format!("{LISTEN_ADDR_ENV} is invalid: {error}"))?;
    let callback_base = Url::parse(&required_env(CALLBACK_BASE_URL_ENV)?)
        .map_err(|error| format!("{CALLBACK_BASE_URL_ENV} is invalid: {error}"))?;
    if !matches!(callback_base.scheme(), "http" | "https") || callback_base.host().is_none() {
        return Err(format!(
            "{CALLBACK_BASE_URL_ENV} must be an absolute HTTP(S) URL"
        ));
    }

    let repo = unique_name("forge-mcp-label-webhook")?;
    let label_name = unique_name("wake-hint")?;
    let webhook_secret = unique_name("webhook-secret")?;
    let context = Context::connect_from_env().await?;
    let mut created_repository = false;
    let mut hook_id = None;
    let mut server_handle = None;
    let mut shim_handle = None;
    let mut mcp_client = None;
    let wire_headers = WireHeaders::default();

    let primary: Result<(), String> = async {
        context
            .request_success(
                Method::POST,
                "/api/v1/user/repos",
                Some(json!({
                    "auto_init": true,
                    "name": repo,
                    "private": true,
                })),
            )
            .await?;
        created_repository = true;

        let issue: IssueResponse = context
            .request_json(
                Method::POST,
                &format!("/api/v1/repos/{}/{repo}/issues", context.username),
                Some(json!({
                    "body": "observe label webhook delivery through poll_events",
                    "title": "label wake hint"
                })),
            )
            .await?;
        let label: LabelResponse = context
            .request_json(
                Method::POST,
                &format!("/api/v1/repos/{}/{repo}/labels", context.username),
                Some(json!({"color": "fbca04", "name": label_name})),
            )
            .await?;

        let (state, event_bus) = build_state(&context, &repo, &webhook_secret)?;
        let listener = tokio::net::TcpListener::bind(listen_addr)
            .await
            .map_err(|error| format!("could not bind {LISTEN_ADDR_ENV}: {error}"))?;
        let local_addr = listener
            .local_addr()
            .map_err(|error| format!("could not inspect gateway listener: {error}"))?;
        let captured = Arc::clone(&wire_headers);
        let router = server::build_router(state, false).layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let captured = Arc::clone(&captured);
                async move {
                    {
                        let header = |name: &str| {
                            request
                                .headers()
                                .get(name)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_string()
                        };
                        if let Ok(mut wire) = captured.lock() {
                            wire.insert(
                                header("x-forgejo-delivery"),
                                (header("x-forgejo-event"), header("x-forgejo-event-type")),
                            );
                        }
                    }
                    next.run(request).await
                }
            },
        ));
        server_handle = Some(tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .map_err(|error| format!("gateway server failed: {error}"))
        }));

        let gateway_url = format!("http://127.0.0.1:{}", local_addr.port());
        let shim_config = ShimConfig {
            channel_startup_spike: false,
            enable_channels: false,
            gateways: vec![GatewayConfig {
                name: "forgejo-ci".to_string(),
                token: AGENT_TOKEN.to_string(),
                url: gateway_url,
            }],
            read_only: false,
            server_name: "forge-mcp-shim-test".to_string(),
            server_version: "0.1.0-test".to_string(),
        };
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        shim_handle = Some(tokio::spawn(async move {
            McpShim::new(shim_config)
                .serve(server_transport)
                .await
                .map_err(|error| format!("could not initialize MCP shim: {error}"))?
                .waiting()
                .await
                .map_err(|error| format!("MCP shim failed: {error}"))?;
            Ok::<(), String>(())
        }));
        mcp_client = Some(
            TestClient
                .serve(client_transport)
                .await
                .map_err(|error| format!("could not initialize MCP client: {error}"))?,
        );
        wait_for_subscriber(&event_bus, "before-label-add").await?;

        let callback_url = callback_base
            .join(&format!("/api/v1/forges/{FORGE_ALIAS}/webhook"))
            .map_err(|error| format!("could not build webhook callback URL: {error}"))?;
        let hook: HookResponse = request_json_redacted(
            &context,
            Method::POST,
            &format!("/api/v1/repos/{}/{repo}/hooks", context.username),
            Some(json!({
                "active": true,
                "config": {
                    "content_type": "json",
                    "secret": webhook_secret,
                    "url": callback_url.to_string(),
                },
                "events": ["issues", "pull_request_label"],
                "type": "forgejo"
            })),
            &[context.token(), &webhook_secret],
        )
        .await?;
        hook_id = Some(hook.id);

        context
            .request_success(
                Method::POST,
                &format!(
                    "/api/v1/repos/{}/{repo}/issues/{}/labels",
                    context.username, issue.number
                ),
                Some(json!({"labels": [label.id]})),
            )
            .await?;
        let client = mcp_client
            .as_ref()
            .ok_or_else(|| "MCP client was not started".to_string())?;
        let added = poll_one_event(client, "label-add").await?;
        let added_delivery = validate_event(&added, &context.username, &repo, issue.number)?;
        if !poll_once(client).await?.is_empty() {
            return Err("label-add delivery did not drain exactly once".to_string());
        }

        wait_for_subscriber(&event_bus, "before-label-remove").await?;
        context
            .request_success(
                Method::DELETE,
                &format!(
                    "/api/v1/repos/{}/{repo}/issues/{}/labels/{}",
                    context.username, issue.number, label.id
                ),
                None,
            )
            .await?;
        let removed = poll_one_event(client, "label-remove").await?;
        let removed_delivery = validate_event(&removed, &context.username, &repo, issue.number)?;
        if removed_delivery == added_delivery {
            return Err("label mutations reused the same delivery ID".to_string());
        }
        if !poll_once(client).await?.is_empty() {
            return Err("label-remove delivery did not drain exactly once".to_string());
        }
        let replacement: LabelResponse = context
            .request_json(
                Method::POST,
                &format!("/api/v1/repos/{}/{repo}/labels", context.username),
                Some(json!({"color":"0055ff","name":unique_name("replacement-label")?})),
            )
            .await?;
        // Forgejo 16.0.3 CI is the wire-provenance authority for these hints.
        let issue_path = format!(
            "/api/v1/repos/{}/{repo}/issues/{}",
            context.username, issue.number
        );
        let mut deliveries = std::collections::HashSet::from([added_delivery, removed_delivery]);
        for (phase, method, path, body, action) in [
            (
                "issue-close",
                Method::PATCH,
                issue_path.clone(),
                Some(json!({"state":"closed"})),
                "closed",
            ),
            (
                "issue-reopen",
                Method::PATCH,
                issue_path.clone(),
                Some(json!({"state":"open"})),
                "reopened",
            ),
            (
                "issue-title",
                Method::PATCH,
                issue_path.clone(),
                Some(json!({"title":"Edited issue title"})),
                "edited",
            ),
            (
                "issue-body",
                Method::PATCH,
                issue_path.clone(),
                Some(json!({"body":"Edited issue body"})),
                "edited",
            ),
            (
                "issue-label-add",
                Method::POST,
                format!("{issue_path}/labels"),
                Some(json!({"labels":[label.id]})),
                "labels_changed",
            ),
            (
                "issue-label-replace",
                Method::PUT,
                format!("{issue_path}/labels"),
                Some(json!({"labels":[replacement.id]})),
                "labels_changed",
            ),
            (
                "issue-label-restore",
                Method::POST,
                format!("{issue_path}/labels"),
                Some(json!({"labels":[label.id]})),
                "labels_changed",
            ),
            (
                "issue-label-clear",
                Method::DELETE,
                format!("{issue_path}/labels"),
                None,
                "labels_changed",
            ),
        ] {
            context.request_success(method, &path, body).await?;
            let event = poll_one_event(client, phase).await?;
            let meta = &event["meta"];
            if meta["event_kind"] != "issue"
                || meta["action"] != action
                || meta["issue"] != issue.number
            {
                return Err(format!("phase={phase} unexpected issue identity/action"));
            }
            let id = meta["delivery_id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .ok_or("missing issue delivery ID")?;
            if !deliveries.insert(id.to_string()) {
                return Err(format!("phase={phase} reused delivery ID"));
            }
            let wire = wire_headers
                .lock()
                .map_err(|_| "wire headers poisoned")?
                .get(id)
                .cloned()
                .ok_or("missing wire headers")?;
            eprintln!(
                "Forgejo {} phase={phase} Event={} Event-Type={}",
                context.version, wire.0, wire.1
            );
            if wire.0 != "issues" {
                return Err(format!("phase={phase} unexpected issue event header"));
            }
            if !poll_once(client).await?.is_empty() {
                return Err(format!("phase={phase} did not drain once"));
            }
        }
        verify_pr_labels(&context, client, &repo, label.id, &wire_headers).await?;
        Ok(())
    }
    .await;

    drop(mcp_client.take());
    if let Some(handle) = shim_handle.take() {
        handle.abort();
        drop(handle.await);
    }
    if let Some(handle) = server_handle.take() {
        handle.abort();
        drop(handle.await);
    }

    let mut cleanup = Vec::new();
    if let Some(id) = hook_id {
        cleanup.push(
            request_success_redacted(
                &context,
                Method::DELETE,
                &format!("/api/v1/repos/{}/{repo}/hooks/{id}", context.username),
                None,
                &[context.token(), &webhook_secret],
            )
            .await
            .map(|_| ()),
        );
    }
    if created_repository {
        cleanup.push(context.delete_repository(&repo).await);
    }
    cleanup.push(context.revoke_token().await);
    combine_results(primary, cleanup)
}

// Same ignored CI target: no extra provider lane or local service is needed.
// Forgejo v16.0.3 uses X-Forgejo-Event=pull_request and
// X-Forgejo-Event-Type=pull_request_label (shared/payloader.go + type.go).
async fn verify_pr_labels(
    context: &Context,
    client: &RunningService<RoleClient, TestClient>,
    repo: &str,
    first_label: u64,
    wire_headers: &WireHeaders,
) -> Result<(), String> {
    let base = format!("/api/v1/repos/{}/{repo}", context.username);
    let repository: Value = context.request_json(Method::GET, &base, None).await?;
    let default_branch = repository["default_branch"]
        .as_str()
        .ok_or_else(|| "repository default branch missing".to_string())?;
    context
        .request_success(
            Method::POST,
            &format!("{base}/branches"),
            Some(json!({"new_branch_name": "label-fixture", "old_branch_name": default_branch})),
        )
        .await?;
    context.request_success(Method::POST, &format!("{base}/contents/label-fixture.txt"),
        Some(json!({"branch": "label-fixture", "content": "Zml4dHVyZQo=", "message": "Add PR fixture"}))).await?;
    let pr: IssueResponse = context.request_json(Method::POST, &format!("{base}/pulls"),
        Some(json!({"base": default_branch, "head": "label-fixture", "title": "PR label fixture"}))).await?;
    let second: LabelResponse = context
        .request_json(
            Method::POST,
            &format!("{base}/labels"),
            Some(json!({"color": "0055ff", "name": unique_name("unrelated-label")?})),
        )
        .await?;
    let path = format!("{base}/issues/{}/labels", pr.number);
    let mut deliveries = HashSet::new();
    for (phase, method, path, body) in [
        (
            "pr-label-add",
            Method::POST,
            path.clone(),
            Some(json!({"labels": [first_label]})),
        ),
        (
            "pr-label-remove",
            Method::DELETE,
            format!("{path}/{first_label}"),
            None,
        ),
        (
            "pr-label-multiple",
            Method::PUT,
            path.clone(),
            Some(json!({"labels": [first_label, second.id]})),
        ),
        (
            "pr-label-replace",
            Method::PUT,
            path.clone(),
            Some(json!({"labels": [second.id]})),
        ),
        ("pr-label-clear", Method::DELETE, path, None),
    ] {
        context.request_success(method, &path, body).await?;
        let event = poll_one_event(client, phase).await?;
        let meta = &event["meta"];
        if event["kind"] != "change_request"
            || meta["event_kind"] != "change_request"
            || meta["action"] != "labels_changed"
            || meta["labels_changed"] != true
            || meta["change_request"] != pr.number
            || !meta["issue"].is_null()
            || !meta["issue_comment"].is_null()
            || meta["forge_alias"] != FORGE_ALIAS
            || meta["owner"] != context.username
            || meta["repo"] != repo
        {
            return Err(format!("phase={phase} unexpected PR label hint: {event}"));
        }
        let id = meta["delivery_id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| format!("phase={phase} missing delivery ID"))?;
        let wire = wire_headers
            .lock()
            .map_err(|_| "wire header capture poisoned".to_string())?
            .get(id)
            .cloned()
            .ok_or_else(|| format!("phase={phase} missing wire headers"))?;
        if wire != ("pull_request".into(), "pull_request_label".into()) {
            return Err(format!(
                "phase={phase} unexpected Forgejo {} wire headers: {wire:?}",
                context.version
            ));
        }
        if !deliveries.insert(id.to_string()) {
            return Err(format!("phase={phase} reused PR label delivery ID"));
        }
        if !poll_once(client).await?.is_empty() {
            return Err(format!("phase={phase} did not drain exactly once"));
        }
    }
    Ok(())
}
