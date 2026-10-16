//! Authenticated inline reads exercise the real HTTP, audit and provider paths.
#![allow(clippy::expect_used)]

use std::{collections::HashMap, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use domain::ForgeKind;
use forge::github::{GitHubAdapter, GitHubAppConfig, GitHubAppCredential, GitHubConfig};
use forge::{ForgeAdapter, ForgeWebhookAdapter, ForgejoAdapter, ForgejoConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use serde_json::{Value, json};
use server::{
    auth::AgentRegistry,
    auto_merge::AutoMergeService,
    config::{AgentConfig, AgentPolicyConfig, ForgeIdentityConfig},
    events::EventBus,
    handlers::AppState,
    registry::{ForgeInstance, ForgeRegistry},
};
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

fn app_config() -> GitHubAppConfig {
    GitHubAppConfig {
        app_id: 1,
        installation_id: 2,
        private_key_pem: include_str!("../src/test-app-key.pem").into(),
    }
}

fn router<A: ForgeAdapter + ForgeWebhookAdapter + 'static>(
    adapter: A,
    kind: ForgeKind,
    apps: HashMap<String, GitHubAppCredential>,
    caller_identity: bool,
) -> (Router, Arc<audit::InMemoryAuditSink>) {
    let adapter = Arc::new(adapter);
    let audit = Arc::new(audit::InMemoryAuditSink::new());
    let instance = ForgeInstance {
        adapter: adapter.clone(),
        alias: "provider".into(),
        base_url: "https://provider.invalid".into(),
        client: server::http_client::client_builder()
            .build()
            .expect("client"),
        forge_kind: kind,
        forge_type: "test".into(),
        git_auth_user: String::new(),
        read_service: Arc::new(ReadOrchestrator::new(adapter.clone(), audit.clone())),
        write_service: Arc::new(WriteOrchestrator::new(adapter.clone(), audit.clone(), None)),
        token: None,
        webhook_adapter: adapter,
        webhook: None,
    };
    let registry = Arc::new(ForgeRegistry::new(HashMap::from([(
        "provider".into(),
        instance,
    )])));
    let bus = EventBus::new();
    let state = AppState {
        agent_registry: AgentRegistry::from_configs_with_github_apps(
            &[AgentConfig {
                agent_id: "reader".into(),
                session_id: "inline-test".into(),
                token: "gateway-token".into(),
                forge_identity: if caller_identity {
                    HashMap::from([(
                        "provider".into(),
                        ForgeIdentityConfig {
                            token: "caller-token".into(),
                        },
                    )])
                } else {
                    HashMap::new()
                },
                github_app: HashMap::new(),
                policy: AgentPolicyConfig {
                    allowed_repos: vec!["provider/org/repo".into()],
                    branch_prefix: None,
                    protected_paths: vec![],
                },
            }],
            HashMap::from([("gateway-token".into(), apps)]),
        ),
        audit_sink: audit.clone(),
        auto_merge_service: Arc::new(AutoMergeService::new(bus.clone(), registry.clone())),
        event_bus: bus,
        forge_registry: registry,
    };
    (server::build_router(state, false), audit)
}

async fn read(app: &Router, token: &str, repo: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/repos/provider/org/{repo}/pulls/7/inline-comments"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&body).expect("JSON"))
}

#[tokio::test]
async fn inline_http_forwards_agent_and_managed_app_credentials_after_access_checks() {
    for mode in ["agent-token", "agent-app", "forge-app"] {
        let server = MockServer::start().await;
        let config = GitHubConfig {
            api_url: format!("{}/api/v3", server.uri()),
            token: Some("unused-fallback".into()),
        };
        if mode != "agent-token" {
            Mock::given(method("GET"))
                .and(path("/api/v3/app"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"slug":"reader"})))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/api/v3/app/installations/2/access_tokens"))
                .respond_with(
                    ResponseTemplate::new(201).set_body_json(json!({"token":"installation-token"})),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        let mut apps = HashMap::new();
        let adapter = if mode == "forge-app" {
            GitHubAdapter::new_app(config, app_config())
                .await
                .expect("forge App")
        } else {
            let mut adapter = GitHubAdapter::new(config.clone()).expect("adapter");
            if mode == "agent-app" {
                let app = GitHubAppCredential::new(&config.api_url, app_config())
                    .await
                    .expect("agent App");
                adapter.extend_managed_app_credentials([app.clone()]);
                apps.insert("provider".into(), app);
            }
            adapter
        };
        // A managed agent App has priority over a caller PAT; a forge App
        // supplies the credential when no per-agent identity is configured.
        let expected = if mode == "agent-token" {
            "Bearer caller-token"
        } else {
            "Bearer installation-token"
        };
        let payload: Value = serde_json::from_str(include_str!(
            "../../forge/tests/fixtures/github-inline-comments.json"
        ))
        .expect("fixture");
        Mock::given(method("GET"))
            .and(path("/api/v3/repos/org/repo/pulls/7/comments"))
            .and(header("authorization", expected))
            .and(header("x-github-api-version", "2022-11-28"))
            .respond_with(ResponseTemplate::new(200).set_body_json(payload.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let (app, audit) = router(adapter, ForgeKind::GitHub, apps, mode != "forge-app");
        let before = server.received_requests().await.expect("requests").len();
        for (token, repo, status) in [
            ("bad-token", "repo", StatusCode::UNAUTHORIZED),
            ("gateway-token", "denied", StatusCode::FORBIDDEN),
        ] {
            assert_eq!(read(&app, token, repo).await.0, status);
            assert_eq!(
                server.received_requests().await.expect("requests").len(),
                before
            );
            assert!(audit.records().expect("records").is_empty());
        }
        let (status, comments) = read(&app, "gateway-token", "repo").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(comments.as_array().expect("comments").len(), 4);
        assert_eq!(comments[0]["body"], payload[0]["body"]);
        assert_eq!(comments[1]["in_reply_to_id"], 101);
        assert!(comments[1]["line"].is_null());
        assert_eq!(comments[1]["original_line"], 12);
        let records = audit.records().expect("audit");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "get_change_request_inline_comments");
        assert_eq!(records[0].agent.agent_id, "reader");
        assert_eq!(records[0].repository.alias, "provider");
        assert_eq!(records[0].target, "7");
        assert_eq!(
            server.received_requests().await.expect("requests").len(),
            before + 1
        );
    }
}

#[tokio::test]
async fn unsupported_inline_http_is_an_explicit_error() {
    let server = MockServer::start().await;
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        base_url: server.uri(),
        token: None,
        woodpecker_url: None,
        woodpecker_token: None,
    })
    .expect("forgejo");
    let (app, audit) = router(adapter, ForgeKind::Forgejo, HashMap::new(), true);
    let (status, body) = read(&app, "gateway-token", "repo").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("operation not supported")
    );
    assert_eq!(audit.records().expect("records").len(), 1);
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}
