//! Deterministic signed-provider -> HTTP -> authorized `EventBus` envelope proof.
//! No provider process or credentials are needed.
#![allow(clippy::expect_used, clippy::panic)]

use std::{collections::HashMap, fmt::Write, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use domain::{ForgeKind, PublishableEvent, WebhookEvent};
use forge::github::{GitHubAdapter, GitHubConfig};
use forge::gitlab::{GitLabAdapter, GitLabConfig};
use forge::{ForgeWebhookAdapter, ForgeWebhookError, ForgejoAdapter, ForgejoConfig};
use hmac::{Hmac, Mac};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use serde_json::{Value, json};
use server::{
    auth::AgentRegistry,
    auto_merge::AutoMergeService,
    config::{AgentPolicyConfig, ForgeWebhookConfig},
    events::{EventBus, QueuedEvent},
    handlers::AppState,
    registry::{ForgeInstance, ForgeRegistry},
};
use sha2::Sha256;
use tokio::sync::mpsc::Receiver;
use tower::ServiceExt;

const SECRET: &str = "review-fixture-secret";

fn github() -> GitHubAdapter {
    GitHubAdapter::new(GitHubConfig {
        api_url: "https://provider.invalid".to_string(),
        token: None,
    })
    .expect("adapter")
}

fn payload(action: &str) -> Value {
    json!({"action": action, "repository": {"name":"repo", "owner":{"login":"org"}},
        "issue":{"number":42,"title":"Issue","body":"private body","html_url":"https://provider.invalid/org/repo/issues/42"}})
}

fn signature(body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("HMAC");
    mac.update(body);
    mac.finalize()
        .into_bytes()
        .iter()
        .fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").expect("string write");
            output
        })
}

fn headers(body: &[u8], delivery: &str) -> Vec<(String, String)> {
    vec![
        ("x-github-event".into(), "issues".into()),
        ("x-github-delivery".into(), delivery.into()),
        (
            "x-hub-signature-256".into(),
            format!("sha256={}", signature(body)),
        ),
    ]
}

fn parse(value: &Value, delivery: &str) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let body = serde_json::to_vec(value).expect("JSON");
    github().verify_and_parse_webhook_event(
        &headers(&body, delivery),
        &body,
        "github",
        ForgeKind::GitHub,
        "https://provider.invalid",
        SECRET,
    )
}

fn policy(repo: &str) -> AgentPolicyConfig {
    AgentPolicyConfig {
        allowed_repos: vec![repo.to_string()],
        branch_prefix: None,
        protected_paths: vec![],
    }
}

fn subscribe(
    bus: &EventBus,
    agent: &str,
    repo: &str,
    after: Option<&str>,
) -> Receiver<QueuedEvent> {
    bus.subscribe(agent.into(), policy(repo), agent.into(), after)
}

fn app(provider: &str) -> (Router, EventBus) {
    match provider {
        "forgejo" => app_with(
            Arc::new(
                ForgejoAdapter::new(ForgejoConfig {
                    base_url: "https://provider.invalid".into(),
                    token: None,
                    woodpecker_url: None,
                    woodpecker_token: None,
                })
                .expect("adapter"),
            ),
            ForgeKind::Forgejo,
        ),
        "gitlab" => app_with(
            Arc::new(
                GitLabAdapter::new(GitLabConfig {
                    base_url: "https://provider.invalid".into(),
                    token: None,
                })
                .expect("adapter"),
            ),
            ForgeKind::GitLab,
        ),
        _ => app_with(Arc::new(github()), ForgeKind::GitHub),
    }
}

fn app_with<A: forge::ForgeAdapter + ForgeWebhookAdapter + 'static>(
    adapter: Arc<A>,
    kind: ForgeKind,
) -> (Router, EventBus) {
    let audit = Arc::new(audit::InMemoryAuditSink::new());
    let instance = ForgeInstance {
        adapter: adapter.clone(),
        alias: "github".into(),
        base_url: "https://provider.invalid".into(),
        client: server::http_client::client_builder()
            .build()
            .expect("HTTP client"),
        forge_kind: kind,
        forge_type: "github".into(),
        git_auth_user: String::new(),
        read_service: Arc::new(ReadOrchestrator::new(adapter.clone(), audit.clone())),
        write_service: Arc::new(WriteOrchestrator::new(adapter.clone(), audit.clone(), None)),
        token: None,
        webhook_adapter: adapter,
        webhook: Some(ForgeWebhookConfig {
            auto_merge: false,
            secret: SECRET.into(),
        }),
    };
    let registry = Arc::new(ForgeRegistry::new(HashMap::from([(
        "github".into(),
        instance,
    )])));
    let bus = EventBus::new();
    let state = AppState {
        agent_registry: AgentRegistry::from_configs(&[]),
        audit_sink: audit,
        auto_merge_service: Arc::new(AutoMergeService::new(bus.clone(), registry.clone())),
        event_bus: bus.clone(),
        forge_registry: registry,
    };
    (server::build_router(state, false), bus)
}

async fn post(
    app: &Router,
    provider: &str,
    value: &Value,
    delivery: &str,
    signing: Option<&str>,
) -> StatusCode {
    let body = serde_json::to_vec(value).expect("JSON");
    let (event_header, event, delivery_header, auth_header) = match provider {
        "forgejo" => (
            "x-forgejo-event",
            "issues",
            "x-forgejo-delivery",
            "x-forgejo-signature",
        ),
        "gitlab" => (
            "x-gitlab-event",
            "Issue Hook",
            "x-gitlab-event-uuid",
            "x-gitlab-token",
        ),
        _ => (
            "x-github-event",
            "issues",
            "x-github-delivery",
            "x-hub-signature-256",
        ),
    };
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/forges/github/webhook")
        .header(event_header, event)
        .header(delivery_header, delivery);
    if let Some(signing) = signing {
        let auth = if signing == "valid" {
            match provider {
                "gitlab" => SECRET.into(),
                "forgejo" => signature(&body),
                _ => format!("sha256={}", signature(&body)),
            }
        } else {
            signing.into()
        };
        request = request.header(auth_header, auth);
    }
    app.clone()
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("response")
        .status()
}

#[allow(clippy::needless_pass_by_value)]
fn fixture(provider: &str, action: &str, changes: Value) -> Value {
    if provider == "gitlab" {
        json!({"object_kind":"issue", "project":{"name":"repo", "namespace":"org", "path_with_namespace":"org/repo"},
            "object_attributes":{"action":action,"iid":42,"title":"Issue","url":"https://provider.invalid/org/repo/issues/42"},"changes":changes})
    } else {
        payload(action)
    }
}

#[tokio::test]
async fn issue_lifecycle_signed_http_identity_auth_dedupe_and_replay() {
    for provider in ["forgejo", "github", "gitlab"] {
        let (app, bus) = app(provider);
        let mut allowed = subscribe(&bus, "allowed", "github/org/repo", None);
        let mut denied = subscribe(&bus, "denied", "github/no/repo", None);
        let actions = if provider == "gitlab" {
            vec![
                ("open", "opened"),
                ("close", "closed"),
                ("reopen", "reopened"),
                ("update", "edited"),
            ]
        } else {
            vec![
                ("opened", "opened"),
                ("closed", "closed"),
                ("reopened", "reopened"),
                ("edited", "edited"),
            ]
        };
        let mut first = None;
        for (i, (action, expected)) in actions.into_iter().enumerate() {
            let value = fixture(
                provider,
                action,
                json!({"description":{"previous":"old","current":null}}),
            );
            for signing in [None, Some("bad")] {
                assert_eq!(
                    post(&app, provider, &value, "invalid", signing).await,
                    StatusCode::UNAUTHORIZED
                );
                assert!(allowed.try_recv().is_err());
            }
            let id = format!("delivery-{i}");
            assert_eq!(
                post(&app, provider, &value, &id, Some("valid")).await,
                StatusCode::ACCEPTED
            );
            let event = allowed.try_recv().expect("event");
            first.get_or_insert(event.id.clone());
            assert_eq!(event.event_name, "issue");
            assert_eq!(event.envelope.meta.action, expected);
            assert_eq!(event.envelope.meta.issue, Some(42));
            assert_eq!(event.envelope.meta.delivery_id, id);
            assert_eq!(event.envelope.meta.forge_alias, "github");
            assert_eq!(event.envelope.meta.owner, "org");
            assert_eq!(event.envelope.meta.repo, "repo");
            assert!(event.envelope.meta.change_request.is_none());
            assert!(!event.data.contains("private body"));
            assert!(!event.data.contains("payload_fingerprint"));
            assert_eq!(
                post(&app, provider, &value, &id, Some("valid")).await,
                StatusCode::ACCEPTED
            );
            assert!(allowed.try_recv().is_err());
            assert!(denied.try_recv().is_err());
        }
        let mut replay = subscribe(&bus, "replay", "github/org/repo", first.as_deref());
        for _ in 0..3 {
            assert_eq!(replay.try_recv().expect("replay").event_name, "issue");
        }
        assert!(replay.try_recv().is_err());
        assert!(
            subscribe(&bus, "no-replay", "github/no/repo", first.as_deref())
                .try_recv()
                .is_err()
        );
        let action = if provider == "gitlab" {
            "update"
        } else {
            "edited"
        };
        for content in ["one", "one", "two"] {
            let mut value = fixture(
                provider,
                action,
                json!({"title":{"previous":"old","current":content}}),
            );
            value["extra"] = json!(content);
            assert_eq!(
                post(&app, provider, &value, "", Some("valid")).await,
                StatusCode::ACCEPTED
            );
        }
        assert!(allowed.try_recv().is_ok());
        assert!(allowed.try_recv().is_ok());
        assert!(allowed.try_recv().is_err());
    }
}

#[test]
fn github_issue_labels_and_negative_payloads() {
    for action in [
        "reopened",
        "edited",
        "labeled",
        "unlabeled",
        "opened",
        "closed",
    ] {
        let value = payload(action);
        let Some(WebhookEvent::Issue(event)) = parse(&value, "id").expect("parse") else {
            panic!("issue");
        };
        assert_eq!(event.repository.host, "https://provider.invalid");
        assert_eq!(
            event.to_channel_event().meta.labels_changed,
            matches!(action, "labeled" | "unlabeled")
        );
        let mut pr = value.clone();
        pr["issue"]["pull_request"] = json!({});
        assert!(parse(&pr, "id").expect("parse").is_none());
        let mut invalid = value;
        invalid["issue"]["number"] = json!(0);
        assert!(parse(&invalid, "id").is_err());
    }
    for action in ["assigned", "replaced", "cleared"] {
        assert!(
            parse(&json!({"action":action}), "id")
                .expect("unsupported")
                .is_none()
        );
    }
}

#[tokio::test]
async fn issue_labels_and_unsupported_deliveries() {
    for provider in ["forgejo", "github", "gitlab"] {
        let (app, bus) = app(provider);
        let mut events = subscribe(&bus, "labels", "github/org/repo", None);
        let actions = match provider {
            "forgejo" => vec![
                "label_updated",
                "label_cleared",
                "label_updated",
                "label_cleared",
            ],
            "gitlab" => vec!["update"; 4],
            _ => vec!["labeled", "unlabeled", "labeled", "unlabeled"],
        };
        for (i, action) in actions.into_iter().enumerate() {
            let delta = if i % 2 == 0 {
                json!({"previous":[],"current":[{"id":1,"title":"private-label"}]})
            } else {
                json!({"previous":[{"id":1,"title":"private-label"}],"current":[]})
            };
            let mut value = fixture(provider, action, json!({"labels":delta}));
            value["label"] = json!({"name":"private-label"});
            assert_eq!(
                post(&app, provider, &value, &format!("label-{i}"), Some("valid")).await,
                StatusCode::ACCEPTED
            );
            let event = events.try_recv().expect("label event");
            assert_eq!(event.envelope.meta.action, "labels_changed");
            assert!(event.envelope.meta.labels_changed);
            assert!(!event.data.contains("private-label"));
            assert!(events.try_recv().is_err());
        }
        let unsupported = if provider == "gitlab" {
            json!({"object_attributes":{"action":"unsupported"}})
        } else {
            json!({"action":"unsupported"})
        };
        assert_eq!(
            post(&app, provider, &unsupported, "unsupported", Some("valid")).await,
            StatusCode::ACCEPTED
        );
        assert!(events.try_recv().is_err());
        if provider == "gitlab" {
            let value = fixture(
                provider,
                "update",
                json!({"title":{"previous":"old","current":"new"},"labels":{"previous":[],"current":[{"id":1,"title":"label"}]}}),
            );
            assert_eq!(
                post(&app, provider, &value, "combined", Some("valid")).await,
                StatusCode::ACCEPTED
            );
            let event = events.try_recv().expect("combined");
            assert_eq!(event.envelope.meta.action, "edited");
            assert!(event.envelope.meta.labels_changed);
            assert!(events.try_recv().is_err());
        }
    }
}
