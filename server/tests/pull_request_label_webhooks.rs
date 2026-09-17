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
use forge::{ForgeAdapter, ForgeWebhookAdapter, ForgeWebhookError, ForgejoAdapter, ForgejoConfig};
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

// Synthetic projections verified against Forgejo v16.0.3 notifier.go,
// modules/webhook/type.go, modules/structs/hook.go and shared/payloader.go;
// GitHub pull_request and GitLab merge-request-events documentation (2026-09-07).
// Real wire proof belongs to forgejo_issue_label_webhooks in its CI-owned lane.
const SECRET: &str = "pr-label-fixture-secret";

fn forgejo() -> ForgejoAdapter {
    ForgejoAdapter::new(ForgejoConfig {
        base_url: "https://provider.invalid".into(),
        token: None,
        woodpecker_url: None,
        woodpecker_token: None,
    })
    .expect("adapter")
}
fn github() -> GitHubAdapter {
    GitHubAdapter::new(GitHubConfig {
        api_url: "https://provider.invalid".into(),
        token: None,
    })
    .expect("adapter")
}
fn gitlab() -> GitLabAdapter {
    GitLabAdapter::new(GitLabConfig {
        base_url: "https://provider.invalid".into(),
        token: None,
    })
    .expect("adapter")
}

fn payload(family: &str, action: &str) -> Value {
    if family == "Merge Request Hook" {
        json!({
            "object_kind": "merge_request",
            "project": {"name": "repo", "namespace": "org/sub", "path_with_namespace": "org/sub/repo"},
            "object_attributes": {"action": action, "iid": 42, "title": "PR", "url": "https://provider.invalid/pr/42",
                "state": "opened", "last_commit": {"id": "source-head"}},
            "changes": {"labels": {"previous": [], "current": [{"id": 1, "title": "arbitrary"}]}},
            "labels": [{"id": 1, "title": "arbitrary"}]
        })
    } else {
        json!({
            "action": action, "number": 42,
            "repository": {"name": "repo", "owner": {"login": "org"}},
            "pull_request": {"number": 42, "title": "PR", "html_url": "https://provider.invalid/pr/42",
                "head": {"sha": "source-head", "ref": "feature"}}
        })
    }
}
fn headers(family: &str, body: &[u8], delivery: &str) -> Vec<(String, String)> {
    if family == "Merge Request Hook" {
        vec![
            ("x-gitlab-event".into(), family.into()),
            ("x-gitlab-token".into(), SECRET.into()),
            ("x-gitlab-event-uuid".into(), delivery.into()),
        ]
    } else if family == "github" {
        vec![
            ("x-github-event".into(), "pull_request".into()),
            ("x-github-delivery".into(), delivery.into()),
            (
                "x-hub-signature-256".into(),
                format!("sha256={}", signature(body)),
            ),
        ]
    } else {
        vec![
            ("x-forgejo-event".into(), family.into()),
            ("x-forgejo-delivery".into(), delivery.into()),
            ("x-forgejo-signature".into(), signature(body)),
        ]
    }
}
fn parse_headers(
    family: &str,
    body: &[u8],
    headers: &[(String, String)],
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let (adapter, kind): (Box<dyn ForgeWebhookAdapter>, _) = match family {
        "github" => (Box::new(github()), ForgeKind::GitHub),
        "Merge Request Hook" => (Box::new(gitlab()), ForgeKind::GitLab),
        _ => (Box::new(forgejo()), ForgeKind::Forgejo),
    };
    adapter.verify_and_parse_webhook_event(
        headers,
        body,
        "labels-forge",
        kind,
        "https://provider.invalid",
        SECRET,
    )
}
fn parse(
    family: &str,
    p: &Value,
    delivery: &str,
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let body = serde_json::to_vec(p).expect("JSON");
    parse_headers(family, &body, &headers(family, &body, delivery))
}
fn change(family: &str, p: &Value, delivery: &str) -> domain::ChangeRequestEvent {
    let Some(WebhookEvent::ChangeRequest(event)) = parse(family, p, delivery).expect("valid")
    else {
        panic!("PR event")
    };
    event
}
fn signature(body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("HMAC");
    mac.update(body);
    mac.finalize()
        .into_bytes()
        .iter()
        .fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").expect("string");
            s
        })
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

fn app<A: ForgeAdapter + ForgeWebhookAdapter + 'static>(
    adapter: A,
    kind: ForgeKind,
    auto_merge: bool,
) -> (Router, EventBus) {
    let adapter = Arc::new(adapter);
    let audit = Arc::new(audit::InMemoryAuditSink::new());
    let instance = ForgeInstance {
        adapter: adapter.clone(),
        alias: "labels-forge".into(),
        base_url: "https://provider.invalid".into(),
        client: server::http_client::client_builder()
            .build()
            .expect("HTTP client"),
        forge_kind: kind,
        forge_type: "labels-forge".into(),
        git_auth_user: String::new(),
        read_service: Arc::new(ReadOrchestrator::new(adapter.clone(), audit.clone())),
        write_service: Arc::new(WriteOrchestrator::new(adapter.clone(), audit.clone(), None)),
        token: None,
        webhook_adapter: adapter,
        webhook: Some(ForgeWebhookConfig {
            auto_merge,
            secret: SECRET.into(),
        }),
    };
    let registry = Arc::new(ForgeRegistry::new(HashMap::from([(
        "labels-forge".into(),
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

async fn post(app: &Router, family: &str, body: Vec<u8>, delivery: &str, auth: bool) -> StatusCode {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/forges/labels-forge/webhook");
    for (k, mut v) in headers(family, &body, delivery) {
        if !auth && (k.contains("signature") || k.contains("token")) {
            v = "bad".into();
        }
        request = request.header(k, v);
    }
    app.clone()
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("response")
        .status()
}

const FAMILIES: &[(&str, &str)] = &[
    ("github", "labeled"),
    ("pull_request", "label_updated"),
    ("pull_request_label", "label_updated"),
    ("Merge Request Hook", "update"),
];

#[tokio::test]
async fn signed_labels_http_authorization_replay_and_dedupe() {
    for &(family, action) in FAMILIES {
        let gl = family == "Merge Request Hook";
        let (app, bus) = match family {
            "github" => app(github(), ForgeKind::GitHub, true),
            "Merge Request Hook" => app(gitlab(), ForgeKind::GitLab, true),
            _ => app(forgejo(), ForgeKind::Forgejo, true),
        };
        let owner = if gl { "org/sub" } else { "org" };
        let repo = format!("labels-forge/{owner}/repo");
        let mut allowed = subscribe(&bus, "allowed", &repo, None);
        let mut denied = subscribe(&bus, "denied", "labels-forge/private/repo", None);
        let p = payload(family, action);
        let mut ids = Vec::new();
        for delivery in ["first", "second", ""] {
            let body = serde_json::to_vec(&p).expect("JSON");
            assert_eq!(
                post(&app, family, body.clone(), delivery, true).await,
                StatusCode::ACCEPTED
            );
            let e = allowed.try_recv().expect("PR hint");
            ids.push(e.id);
            assert_eq!(e.event_name, "change_request");
            let expected = json!({
                "kind": "change_request",
                "content": format!("change_request {} on labels-forge/{owner}/repo#42 at source-head", if gl { "synchronize" } else { "labels_changed" }),
                "meta": {"action": if gl { "synchronize" } else { "labels_changed" },
                    "labels_changed": true, "event_kind": "change_request", "change_request": 42,
                    "delivery_id": delivery, "forge_alias": "labels-forge", "owner": owner, "repo": "repo",
                    "head_sha": "source-head", "issue": null, "issue_comment": null, "review_state": null}
            });
            assert_eq!(
                serde_json::from_str::<Value>(&e.data).expect("envelope"),
                expected
            );
            assert_eq!(
                post(&app, family, body, delivery, true).await,
                StatusCode::ACCEPTED
            );
            assert!(allowed.try_recv().is_err());
            assert!(denied.try_recv().is_err());
        }
        let mut replay = subscribe(&bus, "replay", &repo, Some(&ids[0]));
        let mut denied_replay = subscribe(
            &bus,
            "denied-replay",
            "labels-forge/private/repo",
            Some(&ids[0]),
        );
        for id in ids.iter().skip(1) {
            assert_eq!(&replay.try_recv().expect("replay").id, id);
        }
        assert!(replay.try_recv().is_err());
        assert!(denied_replay.try_recv().is_err());
        assert_eq!(
            post(
                &app,
                family,
                serde_json::to_vec(&p).expect("JSON"),
                "bad-auth",
                false
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post(&app, family, b"{}".to_vec(), "bad-schema", true).await,
            StatusCode::BAD_REQUEST
        );
        assert!(allowed.try_recv().is_err());
    }
}

#[test]
fn label_hints_accept_optional_heads_and_bound_large_label_snapshots() {
    for &(family, action) in FAMILIES {
        let mut p = payload(family, action);
        if family == "Merge Request Hook" {
            p["object_attributes"]
                .as_object_mut()
                .expect("attrs")
                .remove("last_commit");
        } else {
            p["pull_request"]
                .as_object_mut()
                .expect("PR")
                .remove("head");
        }
        let expected =
            serde_json::to_value(change(family, &p, "id").to_channel_event()).expect("envelope");
        assert!(expected["meta"]["head_sha"].is_null());
        for labels in [
            Value::Null,
            json!([]),
            json!([{"name": "ready-for-code-review"}]),
            json!(
                (0..5000)
                    .map(|id| json!({"id": id, "name": "never-forward"}))
                    .collect::<Vec<_>>()
            ),
        ] {
            p["labels"] = labels.clone();
            if family != "Merge Request Hook" {
                p["pull_request"]["labels"] = labels;
            }
            let event = change(family, &p, "id");
            assert_eq!(
                serde_json::to_value(event.to_channel_event()).expect("envelope"),
                expected
            );
            assert_eq!(event.payload_fingerprint.len(), 64);
            assert!(
                !serde_json::to_string(&event)
                    .expect("JSON")
                    .contains("payload_fingerprint")
            );
        }
    }
}

#[test]
fn labels_require_unambiguous_pr_identity_and_valid_authentication() {
    for &(family, action) in FAMILIES {
        let p = payload(family, action);
        let gl = family == "Merge Request Hook";
        for pointer in if gl {
            vec!["/object_attributes/iid", "/project/path_with_namespace"]
        } else {
            vec![
                "/number",
                "/pull_request/number",
                "/repository/name",
                "/repository/owner/login",
            ]
        } {
            let mut invalid = p.clone();
            *invalid.pointer_mut(pointer).expect("field") =
                if pointer.ends_with("number") || pointer.ends_with("iid") {
                    json!(0)
                } else if gl {
                    json!("org/")
                } else {
                    json!("")
                };
            assert!(parse(family, &invalid, "").is_err(), "{family}: {pointer}");
        }
        let body = serde_json::to_vec(&p).expect("JSON");
        let mut h = headers(family, &body, "id");
        h.retain(|(k, _)| !k.contains("signature") && !k.contains("token"));
        assert!(parse_headers(family, &body, &h).is_err());
        if gl {
            for kind in [Value::Null, json!("issue"), json!("note")] {
                let mut invalid = p.clone();
                invalid["object_kind"] = kind;
                assert!(parse(family, &invalid, "").is_err());
            }
        }
        if !gl {
            let mut invalid = p.clone();
            invalid["pull_request"]["number"] = json!(43);
            assert!(parse(family, &invalid, "").is_err());
            invalid
                .as_object_mut()
                .expect("payload")
                .remove("pull_request");
            invalid["issue"] = json!({"number": 42, "title": "issue", "html_url": "url"});
            assert!(parse(family, &invalid, "").is_err());
            let mut missing = p.clone();
            missing.as_object_mut().expect("payload").remove("number");
            missing["pull_request"]
                .as_object_mut()
                .expect("PR")
                .remove("number");
            assert!(parse(family, &missing, "").is_err());
        }
    }
}

#[test]
fn forgejo_label_headers_actions_aliases_and_issue_separation() {
    for family in ["pull_request", "pull_request_label"] {
        for action in ["label_updated", "label_cleared"] {
            let p = payload(family, action);
            assert!(change(family, &p, "id").labels_changed);
            let body = serde_json::to_vec(&p).expect("JSON");
            let aliases: Vec<_> = headers(family, &body, "id")
                .into_iter()
                .map(|(k, v)| (k.replace("forgejo", "gitea"), v))
                .collect();
            assert!(matches!(
                parse_headers(family, &body, &aliases).expect("alias"),
                Some(WebhookEvent::ChangeRequest(_))
            ));
            for number in ["number", "pull_request"] {
                let mut one = p.clone();
                if number == "number" {
                    one.as_object_mut().expect("payload").remove("number");
                } else {
                    one["pull_request"]
                        .as_object_mut()
                        .expect("PR")
                        .remove("number");
                }
                assert_eq!(change(family, &one, "").index, 42);
            }
        }
    }
    // Exact v16 wire grouping and legacy alias restrict the dedicated type.
    for prefix in ["forgejo", "gitea"] {
        for (action, publishes) in [("label_updated", true), ("opened", false)] {
            let p = payload("pull_request", action);
            let body = serde_json::to_vec(&p).expect("JSON");
            let mut h: Vec<_> = headers("pull_request", &body, "id")
                .into_iter()
                .map(|(k, v)| (k.replace("forgejo", prefix), v))
                .collect();
            h.push((
                format!("x-{prefix}-event-type"),
                "pull_request_label".into(),
            ));
            assert_eq!(
                parse_headers("pull_request", &body, &h)
                    .expect("v16 wire")
                    .is_some(),
                publishes
            );
        }
    }
    for action in [
        "opened",
        "closed",
        "labeled",
        "unlabeled",
        "replace",
        "clear",
        "unknown",
    ] {
        assert!(
            parse(
                "pull_request_label",
                &payload("pull_request_label", action),
                ""
            )
            .expect("unsupported")
            .is_none()
        );
    }
    assert!(
        parse("unknown", &payload("pull_request", "label_updated"), "")
            .expect("unsupported")
            .is_none()
    );
    for action in ["label_updated", "label_cleared"] {
        let mut p = payload("issues", action);
        p.as_object_mut().expect("payload").remove("pull_request");
        p["issue"] = json!({"number": 42, "title": "issue", "html_url": "url"});
        let Some(WebhookEvent::Issue(issue)) = parse("issues", &p, "").expect("issue") else {
            panic!("issue hint")
        };
        assert_eq!(issue.to_channel_event().meta.issue, Some(42));
        assert!(issue.to_channel_event().meta.labels_changed);
        assert_ne!(
            issue.dedupe_key(),
            change("pull_request", &payload("pull_request", action), "").dedupe_key()
        );
        p["issue"]["pull_request"] = json!({"url": "PR"});
        assert!(parse("issues", &p, "").expect("PR discriminator").is_none());
    }
    for action in ["labeled", "unlabeled"] {
        assert!(change("github", &payload("github", action), "").labels_changed);
    }
    let p = payload("github", "created");
    let body = serde_json::to_vec(&p).expect("JSON");
    let mut h = headers("github", &body, "");
    h[0].1 = "label".into();
    assert!(
        parse_headers("github", &body, &h)
            .expect("label definition")
            .is_none()
    );
}

#[test]
fn gitlab_label_membership_deltas_preserve_lifecycle_and_ignore_cosmetics() {
    let a = json!({"id": 1, "title": "arbitrary", "color": "red"});
    let b = json!({"id": 2, "title": "ready-for-code-review"});
    for (previous, current) in [
        (json!([]), json!([a])),
        (json!([a, b]), json!([b])),
        (json!([a]), json!([b])),
        (json!([a, b]), json!([])),
        (json!([a]), json!([{"id": 1, "title": "renamed"}])),
    ] {
        for (action, state, normalized) in [
            ("update", "opened", "synchronize"),
            ("open", "opened", "opened"),
            ("reopen", "opened", "reopened"),
            ("close", "closed", "closed"),
            ("merge", "merged", "merged"),
        ] {
            let mut p = payload("Merge Request Hook", action);
            p["object_attributes"]["state"] = json!(state);
            p["changes"]["labels"] = json!({"previous": previous, "current": current});
            p["changes"]["last_commit"] =
                json!({"previous": {"id": "old"}, "current": {"id": "source-head"}});
            let e = change("Merge Request Hook", &p, "");
            assert!(e.labels_changed);
            assert_eq!(e.action.as_str(), normalized);
            assert_eq!(e.head_sha, "source-head");
        }
    }
    for delta in [
        Value::Null,
        json!({}),
        json!("bad"),
        json!({"previous": [], "current": "bad"}),
        json!({"previous": [], "current": [{}]}),
        json!({"previous": [a,b], "current": [b,a]}),
        json!({"previous": [a], "current": [{"id": 1, "title": "arbitrary", "color": "blue"}]}),
    ] {
        for (action, state) in [
            ("update", "opened"),
            ("close", "closed"),
            ("merge", "merged"),
        ] {
            let mut p = payload("Merge Request Hook", action);
            p["object_attributes"]["state"] = json!(state);
            p["changes"]["labels"] = delta.clone();
            let e = change("Merge Request Hook", &p, "");
            assert!(!e.labels_changed);
            assert!(e.payload_fingerprint.is_empty());
            assert!(
                serde_json::to_value(e.to_channel_event()).expect("JSON")["meta"]
                    .get("labels_changed")
                    .is_none()
            );
        }
    }
    for changes in [
        Value::Null,
        json!({}),
        json!("malformed"),
        json!({"title": {"previous": "old", "current": "new"}}),
    ] {
        let mut p = payload("Merge Request Hook", "update");
        p["changes"] = changes;
        assert!(!change("Merge Request Hook", &p, "").labels_changed);
        p.as_object_mut().expect("payload").remove("changes");
        assert!(!change("Merge Request Hook", &p, "").labels_changed);
    }
    let mut invalid = payload("Merge Request Hook", "merge");
    invalid["object_attributes"]["state"] = json!("closed");
    assert!(parse("Merge Request Hook", &invalid, "").is_err());
}

#[test]
fn label_fingerprints_distinguish_unchanged_head_mutations_and_preserve_legacy() {
    for &(family, action) in FAMILIES {
        let p = payload(family, action);
        let first = change(family, &p, "");
        let mut mutation = p.clone();
        if family == "Merge Request Hook" {
            mutation["changes"]["labels"] =
                json!({"previous": [{"id": 1, "title": "arbitrary"}], "current": []});
        } else {
            mutation["action"] = json!(if family == "github" {
                "unlabeled"
            } else {
                "label_cleared"
            });
        }
        let second = change(family, &mutation, "");
        assert_eq!(first.head_sha, second.head_sha);
        let bus = EventBus::new();
        let publish = |event: &domain::ChangeRequestEvent| {
            matches!(
                bus.publish(event).expect("publish"),
                server::events::PublishStatus::Enqueued { .. }
            )
        };
        assert!(publish(&first));
        assert!(!publish(&first));
        assert!(publish(&second));
        let mut separated = first.clone();
        separated.repository.alias = "another-forge".into();
        assert!(publish(&separated));
        separated.repository = first.repository.clone();
        separated.repository.name = "another-repo".into();
        assert!(publish(&separated));
        let mut legacy = first.clone();
        legacy.labels_changed = false;
        legacy.action = domain::ChangeRequestEventAction::Synchronized;
        assert_eq!(
            legacy.dedupe_key(),
            format!(
                "labels-forge:{}/repo/42:source-head:synchronize",
                first.repository.owner
            )
        );
        assert_eq!(change(family, &p, "id").dedupe_key(), "labels-forge:id");
        assert_eq!(
            change(family, &mutation, "id").dedupe_key(),
            "labels-forge:id"
        );
    }
}
