//! Deterministic signed-provider -> HTTP -> authorized `EventBus` envelope proof.
//! No provider process or credentials are needed.
#![allow(clippy::expect_used, clippy::panic)]

use std::{collections::HashMap, fmt::Write, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use domain::{ForgeKind, PublishableEvent, PullRequestReviewEvent, WebhookEvent};
use forge::github::{GitHubAdapter, GitHubConfig};
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

fn payload(action: &str, state: Value) -> Value {
    let mut value = json!({
        "action": action,
        "repository": {"name": "repo", "owner": {"login": "org"}},
        "pull_request": {
            "number": 42, "head": {"ref": "feature", "sha": "live-head"},
            "title": "Change", "html_url": "https://provider.invalid/org/repo/pull/42"
        },
        "review": {"id": 71, "state": null, "commit_id": "older-reviewed-commit", "body": "review"}
    });
    value["review"]["state"] = state;
    value
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
        ("x-github-event".into(), "pull_request_review".into()),
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

fn review(value: &Value, delivery: &str) -> PullRequestReviewEvent {
    let Some(WebhookEvent::PullRequestReview(event)) = parse(value, delivery).expect("valid")
    else {
        panic!("expected review");
    };
    event
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

fn app() -> (Router, EventBus) {
    let adapter = Arc::new(github());
    let audit = Arc::new(audit::InMemoryAuditSink::new());
    let instance = ForgeInstance {
        adapter: adapter.clone(),
        alias: "github".into(),
        base_url: "https://provider.invalid".into(),
        client: server::http_client::client_builder()
            .build()
            .expect("HTTP client"),
        forge_kind: ForgeKind::GitHub,
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

async fn post(app: &Router, value: &Value, delivery: &str, signing: Option<&str>) -> StatusCode {
    let body = serde_json::to_vec(value).expect("JSON");
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/forges/github/webhook")
        .header("x-github-event", "pull_request_review")
        .header("x-github-delivery", delivery);
    if let Some(signing) = signing {
        request = request.header(
            "x-hub-signature-256",
            if signing == "valid" {
                format!("sha256={}", signature(&body))
            } else {
                signing.to_string()
            },
        );
    }
    app.clone()
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("response")
        .status()
}

#[tokio::test]
async fn review_lifecycle_signed_http_preserves_identity_verdict_and_authorization() {
    let (app, bus) = app();
    let mut allowed = subscribe(&bus, "allowed", "github/org/repo", None);
    let mut denied = subscribe(&bus, "denied", "github/other/repo", None);
    let mut first_id = None;
    let fixtures = [
        ("submitted", "approved", Some("approved")),
        ("edited", "approved", Some("approved")),
        ("edited", "changes_requested", Some("request_changes")),
        ("edited", "commented", Some("comment")),
        ("dismissed", "approved", None),
        ("dismissed", "changes_requested", None),
        ("dismissed", "dismissed", None),
    ];
    for (i, (action, state, verdict)) in fixtures.iter().copied().enumerate() {
        let value = payload(action, json!(state));
        assert_eq!(
            post(&app, &value, &format!("delivery-{i}"), Some("valid")).await,
            StatusCode::ACCEPTED
        );
        let queued = allowed.try_recv().expect("synchronous publication");
        if first_id.is_none() {
            first_id = Some(queued.id.clone());
        }
        let envelope: Value = serde_json::from_str(&queued.data).expect("envelope");
        assert_eq!(queued.event_name, "pull_request_review");
        assert_eq!(envelope["kind"], "pull_request_review");
        let meta = &envelope["meta"];
        assert_eq!(meta["event_kind"], "pull_request_review");
        assert_eq!(meta["action"], action);
        assert_eq!(meta["provider_action"], action);
        assert_eq!(meta["forge_alias"], "github");
        assert_eq!(meta["owner"], "org");
        assert_eq!(meta["repo"], "repo");
        assert_eq!(meta["change_request"], 42);
        assert_eq!(meta["review_id"], 71);
        assert_eq!(meta["reviewed_commit_id"], "older-reviewed-commit");
        assert_eq!(meta["head_sha"], "older-reviewed-commit");
        assert_eq!(meta["review_state"], json!(verdict));
        assert!(!queued.data.contains("payload_fingerprint"));
        assert!(denied.try_recv().is_err());
    }
    let mut replay = subscribe(&bus, "replay", "github/org/repo", first_id.as_deref());
    let mut denied_replay = subscribe(&bus, "denied-replay", "github/no/repo", first_id.as_deref());
    for (i, (action, _, verdict)) in fixtures.into_iter().enumerate().skip(1) {
        let event = replay.try_recv().expect("authorized replay");
        assert_eq!(event.envelope.meta.review_id, Some(71));
        assert_eq!(event.envelope.meta.delivery_id, format!("delivery-{i}"));
        assert_eq!(event.envelope.meta.action, action);
        assert_eq!(event.envelope.meta.provider_action.as_deref(), Some(action));
        assert_eq!(event.envelope.meta.review_state.as_deref(), verdict);
    }
    assert!(replay.try_recv().is_err());
    assert!(denied_replay.try_recv().is_err());
}

#[tokio::test]
async fn review_lifecycle_unknown_action_ignores_unusable_fields_after_verification() {
    let (app, bus) = app();
    let mut events = subscribe(&bus, "allowed", "github/org/repo", None);
    // Valid JSON with an unknown action does not need a supported payload schema.
    let mut value = json!({
        "action": "unsupported", "repository": false, "pull_request": [], "review": null
    });
    for signing in [None, Some("sha256=00")] {
        assert_eq!(
            post(&app, &value, "", signing).await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        post(&app, &value, "", Some("valid")).await,
        StatusCode::ACCEPTED
    );
    for action in ["submitted", "edited", "dismissed"] {
        value["action"] = json!(action);
        assert_eq!(
            post(&app, &value, "", Some("valid")).await,
            StatusCode::BAD_REQUEST
        );
    }
    assert!(events.try_recv().is_err());
    let mut replay = subscribe(&bus, "replay", "github/org/repo", Some("unknown-id"));
    assert!(replay.try_recv().is_err());
}

#[tokio::test]
async fn review_lifecycle_identity_only_hints_do_not_use_live_head() {
    let (app, bus) = app();
    let mut events = subscribe(&bus, "allowed", "github/org/repo", None);
    for action in ["edited", "dismissed"] {
        for commit in [None, Some(Value::Null), Some(json!(""))] {
            let mut value = payload(action, Value::Null);
            value["review"]
                .as_object_mut()
                .expect("review")
                .remove("state");
            value["review"]
                .as_object_mut()
                .expect("review")
                .remove("body");
            if let Some(commit) = commit {
                value["review"]["commit_id"] = commit;
            } else {
                value["review"]
                    .as_object_mut()
                    .expect("review")
                    .remove("commit_id");
            }
            value["pull_request"]
                .as_object_mut()
                .expect("PR")
                .remove("title");
            value["pull_request"]["html_url"] = Value::Null;
            assert_eq!(
                post(&app, &value, "", Some("valid")).await,
                StatusCode::ACCEPTED
            );
            let event = events.try_recv().expect("hint");
            assert_eq!(event.envelope.meta.review_state, None);
            assert_eq!(event.envelope.meta.head_sha, None);
            assert_eq!(event.envelope.meta.reviewed_commit_id, None);
            assert!(!event.envelope.content.contains(" at "));
            assert!(!event.envelope.content.contains("()"));
            assert_eq!(event.envelope.meta.review_id, Some(71));
        }
    }
}

#[tokio::test]
async fn review_lifecycle_invalid_identity_and_signatures_publish_nothing() {
    let (app, bus) = app();
    let mut events = subscribe(&bus, "allowed", "github/org/repo", None);
    for action in ["edited", "dismissed"] {
        for pointer in ["/review/id", "/pull_request/number"] {
            for invalid in [
                Value::Null,
                json!(0),
                json!(-1),
                json!("71"),
                json!(true),
                json!({}),
                json!([]),
                json!(1.5),
                json!(18_446_744_073_709_551_616.0),
            ] {
                let mut value = payload(action, json!("approved"));
                *value.pointer_mut(pointer).expect("field") = invalid;
                assert!(matches!(
                    parse(&value, ""),
                    Err(ForgeWebhookError::InvalidPayload(_))
                ));
                assert_eq!(
                    post(&app, &value, "", Some("valid")).await,
                    StatusCode::BAD_REQUEST
                );
            }
            let mut value = payload(action, json!("approved"));
            let (parent, field) = if pointer == "/review/id" {
                ("review", "id")
            } else {
                ("pull_request", "number")
            };
            value[parent].as_object_mut().expect("object").remove(field);
            assert_eq!(
                post(&app, &value, "", Some("valid")).await,
                StatusCode::BAD_REQUEST
            );
        }
        for pointer in ["/repository/name", "/repository/owner/login"] {
            for invalid in [Value::Null, json!(""), json!("  "), json!(1), json!({})] {
                let mut value = payload(action, json!("approved"));
                *value.pointer_mut(pointer).expect("field") = invalid;
                assert_eq!(
                    post(&app, &value, "", Some("valid")).await,
                    StatusCode::BAD_REQUEST
                );
            }
        }
        for commit in [json!(1), json!(true), json!([]), json!({})] {
            let mut value = payload(action, json!("approved"));
            value["review"]["commit_id"] = commit;
            assert_eq!(
                post(&app, &value, "", Some("valid")).await,
                StatusCode::BAD_REQUEST
            );
        }
        for number in [Value::Null, json!(0), json!(43), json!("42"), json!(-1)] {
            let mut value = payload(action, json!("approved"));
            value["number"] = number;
            assert_eq!(
                post(&app, &value, "", Some("valid")).await,
                StatusCode::BAD_REQUEST
            );
        }
        let value = payload(action, json!("approved"));
        for signing in [None, Some("sha256=00"), Some("bad")] {
            assert_eq!(
                post(&app, &value, "", signing).await,
                StatusCode::UNAUTHORIZED
            );
        }
    }
    assert!(events.try_recv().is_err());
    let mut replay = subscribe(&bus, "replay", "github/org/repo", Some("unknown-id"));
    assert!(replay.try_recv().is_err());
}

#[tokio::test]
async fn review_lifecycle_delivery_and_fallback_deduplication() {
    let (app, bus) = app();
    let mut events = subscribe(&bus, "allowed", "github/org/repo", None);
    let submitted = payload("submitted", json!("approved"));
    let edited = payload("edited", json!("approved"));
    let dismissed = payload("dismissed", json!("approved"));
    for (value, delivery, emitted) in [
        (&submitted, "submission", true),
        (&edited, "edit", true),
        (&dismissed, "dismiss", true),
        (&submitted, "submission", false),
        (&edited, "edit", false),
        (&edited, "edit-two", true),
        (&submitted, "", true),
        (&edited, "", true),
        (&edited, "", false),
        (&dismissed, "", true),
        (&dismissed, "", false),
        (&submitted, "", false),
    ] {
        assert_eq!(
            post(&app, value, delivery, Some("valid")).await,
            StatusCode::ACCEPTED
        );
        assert_eq!(events.try_recv().is_ok(), emitted, "{delivery} {value}");
    }
    let mut changed = edited.clone();
    changed["review"]["body"] = json!("second edit");
    assert_eq!(
        post(&app, &changed, "", Some("valid")).await,
        StatusCode::ACCEPTED
    );
    assert!(events.try_recv().is_ok());
    let original = review(&edited, "");
    assert_eq!(original.payload_fingerprint.len(), 64);
    let mut another_repo = original.clone();
    another_repo.repository.name = "other".into();
    let mut another_alias = original.clone();
    another_alias.repository.alias = "other".into();
    assert_ne!(original.dedupe_key(), another_repo.dedupe_key());
    assert_ne!(original.dedupe_key(), another_alias.dedupe_key());
    assert_eq!(
        review(&submitted, "").dedupe_key(),
        "github:org/repo/42:pull_request_review:71"
    );
}

#[test]
fn review_lifecycle_submitted_compatibility_and_optional_display() {
    for (state, expected) in [
        ("approved", "approved"),
        ("changes_requested", "request_changes"),
        ("commented", "comment"),
    ] {
        let event = review(&payload("submitted", json!(state)), "");
        assert_eq!(
            event.to_channel_event().meta.review_state.as_deref(),
            Some(expected)
        );
        assert_eq!(event.head_sha, "older-reviewed-commit");
        assert_eq!(
            event.to_channel_event().content,
            format!(
                "pull_request_review submitted ({expected}) on github/org/repo#42 at older-reviewed-commit"
            )
        );
    }
    for state in ["pending", "unknown"] {
        assert!(
            parse(&payload("submitted", json!(state)), "")
                .expect("ignored")
                .is_none()
        );
        assert_eq!(
            review(&payload("edited", json!(state)), "").review_state,
            None
        );
    }
    assert!(
        parse(&json!({"action": "unsupported"}), "")
            .expect("ignored")
            .is_none()
    );
    for (header, action, resource) in [
        (
            "pull_request_review_comment",
            "created",
            json!({"comment": {"id": 9}}),
        ),
        (
            "pull_request_review_thread",
            "resolved",
            json!({"thread": {"node_id": "opaque"}}),
        ),
    ] {
        let mut value = payload(action, json!("approved"));
        value
            .as_object_mut()
            .expect("object")
            .extend(resource.as_object().expect("object").clone());
        let body = serde_json::to_vec(&value).expect("JSON");
        let mut headers = headers(&body, "");
        headers[0].1 = header.into();
        let event = github()
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "github",
                ForgeKind::GitHub,
                "https://provider.invalid",
                SECRET,
            )
            .expect("inline");
        assert!(matches!(
            event,
            Some(
                WebhookEvent::PullRequestReviewComment(_)
                    | WebhookEvent::PullRequestReviewThread(_)
            )
        ));
    }
    let mut value = payload("edited", json!("approved"));
    value["number"] = json!(42);
    value["review"]["body"] = json!({});
    value["pull_request"] = json!({"number": 42});
    value["review"]["commit_id"] = json!("full-provider-commit-without-truncation");
    assert_eq!(
        review(&value, "").reviewed_commit_id.as_deref(),
        Some("full-provider-commit-without-truncation")
    );
    value["action"] = json!("submitted");
    assert!(matches!(
        parse(&value, ""),
        Err(ForgeWebhookError::InvalidPayload(_))
    ));
}

#[test]
fn review_lifecycle_forgejo_v15_gaps_do_not_invent_formal_events() {
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        base_url: "https://provider.invalid".into(),
        token: None,
        woodpecker_url: None,
        woodpecker_token: None,
    })
    .expect("adapter");
    // Source-shaped fixture: v15 services/webhook/notifier.go::UpdateComment
    // populates pull_request, changes.body.from and sender for PR comment edits.
    // v15 text edits use issue_comment/edited; synthetic GitHub-shaped
    // review actions and an invented dismissal header are unsupported.
    for (header, value) in [
        (
            "issue_comment",
            json!({
                "action": "edited", "issue": {"number": 42, "title": "Change", "html_url": "url"},
                "pull_request": {
                    "number": 42, "title": "Change", "html_url": "url",
                    "head": {"ref": "feature", "sha": "live-head"}
                },
                "comment": {"id": 99, "body": "edited review text"}, "is_pull": true,
                "changes": {"body": {"from": "original review text"}},
                "sender": {"id": 7, "login": "reviewer"},
                "repository": {"name": "repo", "owner": {"login": "org"}}
            }),
        ),
        ("pull_request_review", payload("edited", json!("approved"))),
        (
            "pull_request_review",
            payload("dismissed", json!("approved")),
        ),
        ("pull_request_dismissed", json!({"action": "dismissed"})),
        (
            "pull_request_review",
            json!({
                "action": "unsupported", "repository": false, "pull_request": [], "review": null
            }),
        ),
    ] {
        let body = serde_json::to_vec(&value).expect("JSON");
        let headers = vec![
            ("x-forgejo-event".into(), header.into()),
            ("x-forgejo-signature".into(), signature(&body)),
        ];
        let result = adapter
            .verify_and_parse_webhook_event(
                &headers,
                &body,
                "fj",
                ForgeKind::Forgejo,
                "https://provider.invalid",
                SECRET,
            )
            .expect("ignored");
        assert!(result.is_none(), "{header}");
    }
}

#[test]
fn review_lifecycle_gitlab_notes_and_unapproval_are_not_formal_reviews() {
    use forge::gitlab::{GitLabAdapter, GitLabConfig};
    let adapter = GitLabAdapter::new(GitLabConfig {
        base_url: "https://provider.invalid".into(),
        token: None,
    })
    .expect("adapter");
    for action in ["create", "update"] {
        let body = serde_json::to_vec(&json!({
            "object_attributes": {"action": action, "id": 71, "note": "discussion", "noteable_type": "MergeRequest"},
            "merge_request": {"iid": 42, "title": "Change", "url": "url", "last_commit": {"id": "live-head"}},
            "project": {"name": "repo", "namespace": "org", "path_with_namespace": "org/repo"}
        })).expect("JSON");
        for token in [None, Some("wrong"), Some(SECRET)] {
            let mut headers = vec![("x-gitlab-event".into(), "Note Hook".into())];
            if let Some(token) = token {
                headers.push(("x-gitlab-token".into(), token.into()));
            }
            let result = adapter.verify_and_parse_webhook_event(
                &headers,
                &body,
                "gl",
                ForgeKind::GitLab,
                "https://provider.invalid",
                SECRET,
            );
            if token != Some(SECRET) {
                assert!(result.is_err());
                continue;
            }
            let Some(WebhookEvent::PullRequestReview(event)) = result.expect("legacy note") else {
                panic!("legacy review comment");
            };
            let meta = event.to_channel_event().meta;
            assert_eq!(meta.action, "submitted");
            assert_eq!(meta.provider_action.as_deref(), Some(action));
            assert_eq!(meta.review_state.as_deref(), Some("comment"));
            assert_eq!(meta.head_sha.as_deref(), Some("live-head"));
            assert_eq!(event.review_id, 71); // historical note identity only
            assert_eq!(meta.review_id, None);
            assert_eq!(meta.reviewed_commit_id, None);
        }
    }
    for action in ["approval", "approved", "unapproval", "unapproved", "update"] {
        let body = serde_json::to_vec(&json!({
            "object_attributes": {"action": action, "iid": 42, "state": "opened", "title": "Change", "url": "url"},
            "project": {"name": "repo", "namespace": "org", "path_with_namespace": "org/repo"}
        })).expect("JSON");
        let headers = vec![
            ("x-gitlab-event".into(), "Merge Request Hook".into()),
            ("x-gitlab-token".into(), SECRET.into()),
        ];
        assert!(!matches!(
            adapter
                .verify_and_parse_webhook_event(
                    &headers,
                    &body,
                    "gl",
                    ForgeKind::GitLab,
                    "https://provider.invalid",
                    SECRET,
                )
                .expect("no formal review action"),
            Some(WebhookEvent::PullRequestReview(_))
        ));
    }
}

#[test]
fn review_lifecycle_forgejo_submitted_identity_omissions_remain_truthful() {
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        base_url: "https://provider.invalid".into(),
        token: None,
        woodpecker_url: None,
        woodpecker_token: None,
    })
    .expect("adapter");
    for (header, review_type, verdict) in [
        (
            "pull_request_approved",
            "pull_request_review_approved",
            "approved",
        ),
        (
            "pull_request_rejected",
            "pull_request_review_rejected",
            "request_changes",
        ),
        (
            "pull_request_comment",
            "pull_request_review_comment",
            "comment",
        ),
    ] {
        for action in ["reviewed", "submitted"] {
            for id in [None, Some(0), Some(71)] {
                let mut value = payload(action, Value::Null);
                value["review"] = json!({"type": review_type, "content": "review"});
                value["repository"]["owner"] = json!({"username": "org"});
                if let Some(id) = id {
                    value["review"]["id"] = json!(id);
                }
                let body = serde_json::to_vec(&value).expect("JSON");
                let headers = vec![
                    ("x-forgejo-event".into(), header.into()),
                    ("x-forgejo-signature".into(), signature(&body)),
                ];
                let WebhookEvent::PullRequestReview(event) = adapter
                    .verify_and_parse_webhook_event(
                        &headers,
                        &body,
                        "fj",
                        ForgeKind::Forgejo,
                        "https://provider.invalid",
                        SECRET,
                    )
                    .expect("submitted")
                    .expect("event")
                else {
                    panic!("review");
                };
                let meta = event.to_channel_event().meta;
                assert_eq!(meta.action, "submitted");
                assert_eq!(meta.provider_action.as_deref(), Some(action));
                assert_eq!(meta.review_id, id.filter(|id| *id > 0));
                assert_eq!(meta.reviewed_commit_id, None);
                assert_eq!(meta.review_state.as_deref(), Some(verdict));
                assert_eq!(meta.head_sha.as_deref(), Some("live-head"));
            }
        }
    }
}
