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
use forge::{ForgeWebhookAdapter, ForgeWebhookError};
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

fn payload(action: &str, _state: Value) -> Value {
    json!({"action": action,
        "repository": {"name": "repo", "owner": {"login": "org"}},
        "pull_request": {"number": 42, "head": {"sha": "live-head"}},
        "comment": {"id": 7},
        "thread": {"node_id": "PRRT_opaque", "comments": []}})
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

fn headers(body: &[u8], delivery: &str, kind: &str) -> Vec<(String, String)> {
    vec![
        ("x-github-event".into(), kind.into()),
        ("x-github-delivery".into(), delivery.into()),
        (
            "x-hub-signature-256".into(),
            format!("sha256={}", signature(body)),
        ),
    ]
}

fn parse(
    value: &Value,
    delivery: &str,
    kind: &str,
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let body = serde_json::to_vec(value).expect("JSON");
    github().verify_and_parse_webhook_event(
        &headers(&body, delivery, kind),
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

fn app() -> (Router, EventBus) {
    app_with(github(), ForgeKind::GitHub)
}

fn app_with<A: forge::ForgeAdapter + ForgeWebhookAdapter + 'static>(
    adapter: A,
    kind: ForgeKind,
) -> (Router, EventBus) {
    let adapter = Arc::new(adapter);
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
            auto_merge: true,
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
    value: &Value,
    delivery: &str,
    signing: Option<&str>,
    kind: &str,
) -> StatusCode {
    let body = serde_json::to_vec(value).expect("JSON");
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/forges/github/webhook")
        .header("x-github-event", kind)
        .header("x-github-delivery", delivery);
    if kind == "Note Hook" {
        request = request
            .header("x-gitlab-event", kind)
            .header("x-gitlab-token", signing.unwrap_or_default())
            .header("webhook-id", delivery);
    }
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

const COMMENT: &str = "pull_request_review_comment";
const THREAD: &str = "pull_request_review_thread";
fn channel(value: &Value, delivery: &str, kind: &str) -> domain::ChannelEvent {
    match parse(value, delivery, kind).expect("valid").expect("event") {
        WebhookEvent::PullRequestReviewComment(e) => e.to_channel_event(),
        WebhookEvent::PullRequestReviewThread(e) => e.to_channel_event(),
        _ => panic!("not an inline hint"),
    }
}

#[tokio::test]
async fn lifecycle_delivery_dedupe_and_authorized_replay() {
    let (app, bus) = app();
    let mut allowed = subscribe(&bus, "allowed", "github/org/repo", None);
    let mut denied = subscribe(&bus, "denied", "github/no/repo", None);
    let verdict = json!({"action":"submitted", "repository":{"name":"repo","owner":{"login":"org"}},
        "pull_request":{"number":42,"head":{"ref":"feature","sha":"head"},"title":"PR","html_url":"https://provider.invalid/pr/42"},
        "review":{"id":99,"state":"changes_requested","body":"changes needed","commit_id":"head"}});
    assert_eq!(
        post(
            &app,
            &verdict,
            "verdict",
            Some("valid"),
            "pull_request_review"
        )
        .await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        allowed
            .try_recv()
            .expect("formal verdict")
            .envelope
            .meta
            .review_state
            .as_deref(),
        Some("request_changes")
    );
    let mut ids = Vec::new();
    for (i, (kind, action)) in [
        (COMMENT, "created"),
        (COMMENT, "edited"),
        (COMMENT, "deleted"),
        (THREAD, "unresolved"),
        (THREAD, "resolved"),
        (THREAD, "unresolved"),
        (THREAD, "resolved"),
    ]
    .into_iter()
    .enumerate()
    {
        let value = payload(action, Value::Null);
        let delivery = format!("delivery-{i}");
        assert_eq!(
            post(&app, &value, &delivery, Some("valid"), kind).await,
            StatusCode::ACCEPTED
        );
        let e = allowed.try_recv().expect("event");
        ids.push(e.id.clone());
        assert_eq!(e.event_name, kind);
        assert_eq!(e.envelope.meta, channel(&value, &delivery, kind).meta);
        assert_eq!(e.envelope.meta.review_state, None);
        assert_eq!(e.envelope.meta.review_id, None);
        assert_eq!(e.envelope.meta.reviewed_commit_id, None);
        assert!(!e.data.contains("fingerprint"));
        assert_eq!(
            post(&app, &value, &delivery, Some("valid"), kind).await,
            StatusCode::ACCEPTED
        );
        assert!(allowed.try_recv().is_err());
        assert!(denied.try_recv().is_err());
    }
    let mut replay = subscribe(&bus, "replay", "github/org/repo", Some(&ids[0]));
    for id in &ids[1..] {
        assert_eq!(&replay.try_recv().expect("replay").id, id);
    }
    assert!(
        subscribe(&bus, "no-replay", "github/no/repo", Some(&ids[0]))
            .try_recv()
            .is_err()
    );
    for (i, action) in ["unresolved", "resolved", "unresolved", "resolved"]
        .into_iter()
        .enumerate()
    {
        let mut value = payload(action, Value::Null);
        value["updated_at"] = json!(i);
        post(&app, &value, "", Some("valid"), THREAD).await;
        assert_eq!(
            allowed
                .try_recv()
                .expect("recurring no-ID action")
                .envelope
                .meta
                .action,
            action
        );
        post(&app, &value, "", Some("valid"), THREAD).await;
        assert!(allowed.try_recv().is_err());
    }
    let mut edit = payload("edited", Value::Null);
    for body in ["first", "second", "third"] {
        edit["comment"]["body"] = json!(body);
        assert_eq!(
            post(&app, &edit, "", Some("valid"), COMMENT).await,
            StatusCode::ACCEPTED
        );
        allowed.try_recv().expect("changed body survives");
        post(&app, &edit, "", Some("valid"), COMMENT).await;
        assert!(allowed.try_recv().is_err());
    }
}

#[test]
fn independent_comment_metadata_and_minimal_identity() {
    let mut value = payload("edited", Value::Null);
    value["comment"] = json!({"id": 7,"node_id":"comment-node","pull_request_review_id":12,
        "in_reply_to_id":6,"commit_id":"old","original_commit_id":"older","path":"src/lib.rs",
        "line":12,"start_line":10,"side":"RIGHT","start_side":"LEFT",
        "original_line":9,"original_start_line":8,"position":3,"original_position":2,
        "body":"do not publish","diff_hunk":"do not publish"});
    let c = channel(&value, "", COMMENT);
    let d = c.meta.inline_review.expect("details");
    let first = d.comment.expect("comment");
    assert_eq!(first.comment_id, Some(7));
    assert_eq!(first.review_id, Some(12));
    assert_eq!(first.in_reply_to_id, Some(6));
    assert_eq!(first.line, Some(12));
    assert_eq!(first.position, Some(3));
    assert_eq!(first.original_start_line, Some(8));
    assert_eq!(first.start_side, Some(domain::InlineReviewSide::Left));
    assert_eq!(first.commit_id.as_deref(), Some("old"));
    assert_eq!(c.meta.head_sha.as_deref(), Some("live-head"));
    assert!(d.thread_id.is_none());
    value["action"] = json!("resolved");
    value["thread"]["comments"] =
        json!([value["comment"],{"id":8,"pull_request_review_id":13,"commit_id":"different"},{}]);
    let thread = channel(&value, "", THREAD)
        .meta
        .inline_review
        .expect("thread");
    assert_eq!(thread.comments.len(), 3);
    assert_eq!(thread.comments[0], first);
    assert_eq!(thread.comments[1].review_id, Some(13));
    assert_eq!(thread.comments[2].comment_id, None);
    assert!(thread.comment.is_none());
    for kind in [COMMENT, THREAD] {
        value["action"] = json!(if kind == COMMENT {
            "deleted"
        } else {
            "unresolved"
        });
        value["pull_request"] = json!({"number":42});
        value["comment"] = json!({"id":7,"line":null,"commit_id":""});
        value["thread"] = json!({"node_id":"opaque"});
        let meta = channel(&value, "", kind).meta;
        assert_eq!(meta.head_sha, None);
        assert_eq!(meta.review_state, None);
        assert_eq!(meta.change_request, Some(42));
    }
}

#[tokio::test]
async fn invalid_payloads_and_verification_precedence() {
    let (app, bus) = app();
    let mut rx = subscribe(&bus, "allowed", "github/org/repo", None);
    for (pointer, bad) in [
        ("/comment/id", json!(0)),
        ("/comment/id", Value::Null),
        ("/pull_request/number", json!(0)),
        ("/repository/name", json!("")),
        ("/repository/owner/login", json!("")),
        ("/comment/id", json!("7")),
    ] {
        let mut value = payload("created", Value::Null);
        *value.pointer_mut(pointer).expect("field") = bad;
        assert!(parse(&value, "", COMMENT).is_err(), "{pointer}");
        assert_eq!(
            post(&app, &value, "", Some("sha256=00"), COMMENT).await,
            StatusCode::UNAUTHORIZED
        );
    }
    for (field, bad) in [
        ("line", json!("12")),
        ("side", json!("OTHER")),
        ("pull_request_review_id", json!(0)),
        ("path", json!({})),
        ("node_id", json!("a".repeat(257))),
        ("position", json!(-1)),
    ] {
        let mut value = payload("edited", Value::Null);
        value["comment"][field] = bad;
        assert!(parse(&value, "", COMMENT).is_err(), "{field}");
    }
    for thread in [
        json!({"node_id":""}),
        json!({"id":1}),
        json!({"node_id":1}),
        json!({"node_id":"ok","comments":[{"id":0}]}),
    ] {
        let mut value = payload("resolved", Value::Null);
        value["thread"] = thread;
        assert!(parse(&value, "", THREAD).is_err());
    }
    for kind in [COMMENT, THREAD] {
        assert!(
            parse(&json!({"action":"unsupported"}), "", kind)
                .expect("ignored")
                .is_none()
        );
    }
    assert!(rx.try_recv().is_err());
}

fn gitlab_parse(value: &Value, secret: &str) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let adapter = forge::gitlab::GitLabAdapter::new(forge::gitlab::GitLabConfig {
        base_url: "https://provider.invalid".into(),
        token: None,
    })
    .expect("adapter");
    adapter.verify_and_parse_webhook_event(
        &[
            ("x-gitlab-event".into(), "Note Hook".into()),
            ("x-gitlab-token".into(), secret.into()),
        ],
        &serde_json::to_vec(value).expect("JSON"),
        "gitlab",
        ForgeKind::GitLab,
        "https://provider.invalid",
        SECRET,
    )
}

#[test]
fn gitlab_source_shaped_diff_notes_and_legacy_discussion() {
    // GitLab v18.3.0-ee NoteBuilder + DataBuilder::Note and Notes services.
    // See fixtures/inline-review-provenance.md for exact source paths.
    let mut value = json!({"object_kind":"note", "project":{"name":"repo","namespace":"org/sub","path_with_namespace":"org/sub/repo"},
        "merge_request":{"iid":42,"title":"MR","url":"https://provider.invalid/mr/42","last_commit":{"id":"live"}},
        "object_attributes":{"action":"create","id":8,"noteable_type":"MergeRequest","type":"DiffNote",
            "note":"private body","discussion_id":"opaque","commit_id":null,
            "position":{"base_sha":"base","start_sha":"start","head_sha":"old-head","old_path":"old.rs","new_path":"new.rs",
                "old_line":null,"new_line":12,"position_type":"text","line_range":{"start":{"type":"new","old_line":null,"new_line":10},"end":{"type":"new","new_line":12}}},
            "original_position":{"new_line":9,"head_sha":"older-head"}}});
    for (native, normalized) in [("create", "created"), ("update", "edited")] {
        value["object_attributes"]["action"] = json!(native);
        let Some(WebhookEvent::PullRequestReviewComment(e)) =
            gitlab_parse(&value, SECRET).expect("valid")
        else {
            panic!("inline");
        };
        let meta = e.to_channel_event().meta;
        assert_eq!(meta.action, normalized);
        assert_eq!(meta.provider_action.as_deref(), Some(native));
        assert_eq!(meta.owner, "org/sub");
        assert_eq!(meta.head_sha, None);
        assert_eq!(meta.review_state, None);
        let details = meta.inline_review.expect("details");
        assert_eq!(details.thread_id.as_deref(), Some("opaque"));
        let comment = details.comment.expect("comment");
        assert_eq!(comment.comment_id, Some(8));
        assert_eq!(comment.commit_id, None);
        assert_eq!(comment.review_id, None);
        assert_eq!(
            comment.gitlab_position.expect("position").new_line,
            Some(12)
        );
        assert_eq!(
            comment
                .gitlab_original_position
                .expect("original")
                .head_sha
                .as_deref(),
            Some("older-head")
        );
    }
    for action in ["delete", "resolve", "unresolve", "approved"] {
        value["object_attributes"]["action"] = json!(action);
        assert!(gitlab_parse(&value, SECRET).expect("unsupported").is_none());
    }
    value["object_attributes"]["action"] = json!("update");
    for kind in [
        Value::Null,
        json!("DiscussionNote"),
        json!("LegacyDiffNote"),
    ] {
        value["object_attributes"]["type"] = kind;
        assert!(matches!(
            gitlab_parse(&value, SECRET).expect("legacy"),
            Some(WebhookEvent::PullRequestReview(_))
        ));
    }
    value["object_attributes"]["type"] = json!("DiffNote");
    for (pointer, bad) in [
        ("/object_attributes/id", json!(0)),
        ("/merge_request/iid", json!(0)),
        ("/object_attributes/discussion_id", json!(9)),
        ("/object_attributes/position/new_line", json!("12")),
    ] {
        let mut invalid = value.clone();
        *invalid.pointer_mut(pointer).expect("field") = bad;
        assert!(gitlab_parse(&invalid, SECRET).is_err());
        assert!(matches!(
            gitlab_parse(&invalid, "bad"),
            Err(ForgeWebhookError::InvalidSignature)
        ));
    }
}

#[test]
fn forgejo_has_no_invented_inline_or_thread_headers() {
    let adapter = forge::ForgejoAdapter::new(forge::ForgejoConfig {
        woodpecker_url: None,
        woodpecker_token: None,
        base_url: "https://provider.invalid".into(),
        token: None,
    })
    .expect("adapter");
    for kind in [
        COMMENT,
        THREAD,
        "pull_request_resolved",
        "pull_request_unresolved",
    ] {
        let body = serde_json::to_vec(&payload("resolved", Value::Null)).expect("JSON");
        let headers = vec![
            ("x-forgejo-event".into(), kind.into()),
            ("x-forgejo-signature".into(), signature(&body)),
        ];
        assert!(
            adapter
                .verify_and_parse_webhook_event(
                    &headers,
                    &body,
                    "forgejo",
                    ForgeKind::Forgejo,
                    "https://provider.invalid",
                    SECRET
                )
                .expect("unsupported")
                .is_none()
        );
    }
}

#[tokio::test]
async fn gitlab_diff_note_http_and_bad_token() {
    let adapter = forge::gitlab::GitLabAdapter::new(forge::gitlab::GitLabConfig {
        base_url: "https://provider.invalid".into(),
        token: None,
    })
    .expect("adapter");
    let (app, bus) = app_with(adapter, ForgeKind::GitLab);
    let mut rx = subscribe(&bus, "allowed", "github/org/repo", None);
    let mut denied = subscribe(&bus, "denied", "github/no/repo", None);
    for action in ["create", "update"] {
        let value = json!({"project":{"path_with_namespace":"org/repo"},"merge_request":{"iid":42},
            "object_attributes":{"id":8,"type":"DiffNote","noteable_type":"MergeRequest","action":action,"discussion_id":"opaque"}});
        assert_eq!(
            post(&app, &value, action, Some("bad"), "Note Hook").await,
            StatusCode::UNAUTHORIZED
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(
            post(&app, &value, action, Some(SECRET), "Note Hook").await,
            StatusCode::ACCEPTED
        );
        let e = rx.try_recv().expect("inline");
        assert_eq!(e.event_name, COMMENT);
        assert_eq!(e.envelope.meta.provider_action.as_deref(), Some(action));
        assert_eq!(
            e.envelope
                .meta
                .inline_review
                .expect("details")
                .comment
                .expect("comment")
                .comment_id,
            Some(8)
        );
        assert!(denied.try_recv().is_err());
        post(&app, &value, action, Some(SECRET), "Note Hook").await;
        assert!(rx.try_recv().is_err());
    }
}

#[test]
fn aggregate_gitlab_resolution_and_approval_are_not_thread_events() {
    let adapter = forge::gitlab::GitLabAdapter::new(forge::gitlab::GitLabConfig {
        base_url: "https://provider.invalid".into(),
        token: None,
    })
    .expect("adapter");
    for action in ["update", "approved", "unapproved"] {
        let value = json!({"object_kind":"merge_request","project":{"name":"repo","namespace":"org","path_with_namespace":"org/repo"},
            "object_attributes":{"iid":42,"action":action,"title":"MR","url":"https://provider.invalid/mr/42","blocking_discussions_resolved":true},
            "changes":{"blocking_discussions_resolved":{"previous":false,"current":true}}});
        let e = adapter
            .verify_and_parse_webhook_event(
                &[
                    ("x-gitlab-event".into(), "Merge Request Hook".into()),
                    ("x-gitlab-token".into(), SECRET.into()),
                ],
                &serde_json::to_vec(&value).expect("JSON"),
                "gitlab",
                ForgeKind::GitLab,
                "https://provider.invalid",
                SECRET,
            )
            .expect("known family");
        assert!(matches!(e, None | Some(WebhookEvent::ChangeRequest(_))));
    }
}

#[test]
fn projection_bounds_preserve_exact_utf8_fields() {
    for (field, limit) in [
        ("node_id", 256),
        ("path", 4096),
        ("commit_id", 256),
        ("original_commit_id", 256),
    ] {
        let mut value = payload("created", Value::Null);
        value["comment"][field] = json!("é".repeat(limit / 2));
        assert!(parse(&value, "", COMMENT).is_ok());
        value["comment"][field] = json!(format!("{}x", "é".repeat(limit / 2)));
        assert!(parse(&value, "", COMMENT).is_err());
    }
    let mut value = payload("resolved", Value::Null);
    value["thread"]["comments"] = json!(vec![json!({}); 1024]);
    assert!(parse(&value, "", THREAD).is_ok());
    value["thread"]["comments"] = json!(vec![json!({}); 1025]);
    assert!(parse(&value, "", THREAD).is_err());
}
