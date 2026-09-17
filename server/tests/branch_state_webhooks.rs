//! Deterministic signed-provider -> HTTP -> authorized `EventBus` envelope proof.
//! No provider process or credentials are needed.
#![allow(clippy::expect_used, clippy::panic)]

use std::{collections::HashMap, fmt::Write, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use domain::ForgeKind;
use forge::github::{GitHubAdapter, GitHubConfig};
use forge::gitlab::{GitLabAdapter, GitLabConfig};
use forge::{ForgeAdapter, ForgeWebhookAdapter, ForgejoAdapter, ForgejoConfig};
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

// Source-derived subsets; see fixtures/branch-state/README.md for provenance.
const SECRET: &str = "branch-fixture-secret";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ZERO: &str = "0000000000000000000000000000000000000000";

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
        alias: "hint-forge".into(),
        base_url: "https://provider.invalid".into(),
        client: server::http_client::client_builder()
            .build()
            .expect("HTTP client"),
        forge_kind: kind,
        forge_type: "hint-forge".into(),
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
        "hint-forge".into(),
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

fn forgejo() -> ForgejoAdapter {
    ForgejoAdapter::new(ForgejoConfig {
        woodpecker_url: None,
        woodpecker_token: None,
        base_url: "https://provider.invalid".into(),
        token: None,
    })
    .expect("adapter")
}
fn harness(provider: &str) -> (Router, EventBus) {
    match provider {
        "gitlab" => app(gitlab(), ForgeKind::GitLab, true),
        "forgejo" | "gitea" => app(forgejo(), ForgeKind::Forgejo, true),
        _ => app(github(), ForgeKind::GitHub, true),
    }
}
fn push() -> Value {
    json!({"object_kind": "push", "repository": {"name": "repo", "owner": {"login": "org"}},
        "project": {"path_with_namespace": "org/sub/repo", "name": "repo", "namespace": "org/sub"},
        "ref": "refs/heads/main", "before": SHA, "after": OTHER_SHA,
        "commits": [{"message": "never-forward"}]})
}
fn pr(provider: &str) -> Value {
    if provider == "gitlab" {
        json!({"object_kind": "merge_request", "project": {"path_with_namespace": "org/sub/repo", "name": "repo", "namespace": "org/sub"},
            "object_attributes": {"iid": 7, "action": "update", "title": "PR", "url": "https://provider.invalid/pr/7",
                "target_branch": "release/next", "draft": false, "last_commit": {"id": SHA}},
            "changes": {"target_branch": {"previous": "main", "current": "release/next"},
                "draft": {"previous": true, "current": false}}})
    } else {
        let mut p = json!({"action": "edited", "number": 7, "repository": {"name": "repo", "owner": {"login": "org"}},
            "pull_request": {"number": 7, "title": "PR", "html_url": "https://provider.invalid/pr/7",
                "head": {"ref": "feature", "sha": SHA}, "base": {"ref": "release/next"}, "draft": false},
            "changes": {"base": {"ref": {"from": "main"}, "sha": {"from": OTHER_SHA}}}});
        if provider == "forgejo" || provider == "gitea" {
            p["changes"] = json!({"ref": {"from": "main"}});
        }
        p
    }
}
fn repo(provider: &str) -> &'static str {
    if provider == "gitlab" {
        "hint-forge/org/sub/repo"
    } else {
        "hint-forge/org/repo"
    }
}
async fn post(
    app: &Router,
    provider: &str,
    push: bool,
    p: &Value,
    extra: &[(&str, &str)],
    auth: bool,
) -> StatusCode {
    let body = serde_json::to_vec(p).expect("JSON");
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/forges/hint-forge/webhook");
    if provider == "gitlab" {
        request = request
            .header(
                "X-Gitlab-Event",
                if push {
                    "Push Hook"
                } else {
                    "Merge Request Hook"
                },
            )
            .header("X-Gitlab-Token", if auth { SECRET } else { "bad" });
    } else {
        let sig = if auth { signature(&body) } else { "bad".into() };
        let event = if push { "push" } else { "pull_request" };
        request = match provider {
            "forgejo" => request
                .header("X-Forgejo-Event", event)
                .header("X-Forgejo-Signature", sig),
            "gitea" => request
                .header("X-Gitea-Event", event)
                .header("X-Gitea-Signature", sig),
            _ => request
                .header("X-GitHub-Event", event)
                .header("X-Hub-Signature-256", format!("sha256={sig}")),
        };
    }
    for (k, v) in extra {
        request = request.header(*k, *v);
    }
    app.clone()
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("response")
        .status()
}
fn envelope(rx: &mut Receiver<QueuedEvent>, kind: &str, delivery: &str) -> QueuedEvent {
    let e = rx.try_recv().expect("published hint");
    let serialized: Value = serde_json::from_str(&e.data).expect("envelope JSON");
    assert_eq!(serialized["kind"], kind);
    assert_eq!(serialized["meta"]["delivery_id"], delivery);
    assert!(!e.data.contains("payload_fingerprint"));
    assert!(!e.data.contains("never-forward"));
    e
}

#[tokio::test]
async fn signed_pushes_keep_repository_ref_and_object_ids() {
    for provider in ["github", "gitlab", "forgejo", "gitea"] {
        let (app, bus) = harness(provider);
        let mut rx = subscribe(&bus, "allowed", repo(provider), None);
        let mut second = subscribe(&bus, "second", repo(provider), None);
        let mut denied = subscribe(&bus, "denied", "hint-forge/else/repo", None);
        let mut ids = Vec::new();
        for (branch, before, after, forced) in [
            ("main", SHA, OTHER_SHA, None),
            ("release/next", SHA, OTHER_SHA, None),
            ("created", ZERO, SHA, None),
            ("deleted", SHA, ZERO, None),
            ("main", OTHER_SHA, SHA, Some(true)),
            ("feature/unrelated", SHA, OTHER_SHA, None),
        ] {
            let mut p = push();
            p["ref"] = json!(format!("refs/heads/{branch}"));
            p["before"] = json!(before);
            p["after"] = json!(after);
            if provider == "github" {
                p["deleted"] = json!(after == ZERO);
                p["forced"] = json!(forced);
            }
            assert_eq!(
                post(&app, provider, true, &p, &[], true).await,
                StatusCode::ACCEPTED
            );
            let e = envelope(&mut rx, "branch_push", "");
            ids.push(e.id.clone());
            let m = &e.envelope.meta;
            assert_eq!(m.action, "pushed");
            assert_eq!(m.head_sha, None);
            assert_eq!(m.change_request, None);
            assert_eq!(m.issue, None);
            assert_eq!(m.issue_comment, None);
            let d = m.branch_push.as_ref().expect("push details");
            assert_eq!(d.r#ref, format!("refs/heads/{branch}"));
            assert_eq!(d.before_sha, before);
            assert_eq!(d.after_sha, after);
            assert_eq!(d.deleted, Some(after == ZERO));
            assert_eq!(d.forced, if provider == "github" { forced } else { None });
            assert_eq!(second.try_recv().expect("second subscriber").data, e.data);
            assert_eq!(
                post(&app, provider, true, &p, &[], true).await,
                StatusCode::ACCEPTED
            );
            assert!(rx.try_recv().is_err());
            assert!(denied.try_recv().is_err());
        }
        let mut replay = subscribe(&bus, "replay", repo(provider), Some(&ids[0]));
        for id in ids.iter().skip(1) {
            assert_eq!(&replay.try_recv().expect("replay").id, id);
        }
        assert!(replay.try_recv().is_err());
        assert!(
            subscribe(&bus, "denied-replay", "hint-forge/else/repo", Some(&ids[0]))
                .try_recv()
                .is_err()
        );
        for reference in ["refs/tags/v1", "refs/notes/test", "refs/pull/7/head"] {
            let mut p = push();
            p["ref"] = json!(reference);
            assert_eq!(
                post(&app, provider, true, &p, &[], false).await,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                post(&app, provider, true, &p, &[], true).await,
                StatusCode::ACCEPTED
            );
            assert!(rx.try_recv().is_err());
        }
    }
}

#[tokio::test]
async fn state_hints_keep_identity_and_accept_missing_source_heads() {
    for provider in ["github", "gitlab", "forgejo", "gitea"] {
        for head in [json!({"ref": "feature", "sha": SHA}), Value::Null] {
            let (app, bus) = harness(provider);
            let mut rx = subscribe(&bus, "allowed", repo(provider), None);
            let mut payload = pr(provider);
            if provider == "gitlab" {
                payload["object_attributes"]["last_commit"] = if head.is_null() {
                    Value::Null
                } else {
                    json!({"id": SHA})
                };
            } else {
                payload["pull_request"]["head"] = head.clone();
            }
            assert_eq!(
                post(&app, provider, false, &payload, &[], true).await,
                StatusCode::ACCEPTED
            );
            let event = envelope(&mut rx, "change_request", "");
            let meta = event.envelope.meta;
            assert_eq!(meta.action, "updated");
            assert_eq!(meta.change_request, Some(7));
            assert_eq!(
                meta.head_sha,
                if head.is_null() {
                    None
                } else {
                    Some(SHA.into())
                }
            );
            let changes = meta.change_request_changes.expect("state");
            let base = changes.base.expect("base");
            assert_eq!(base.previous.as_deref(), Some("main"));
            assert_eq!(base.current, "release/next");
            assert_eq!(
                meta.provider_action.as_deref(),
                Some(if provider == "gitlab" {
                    "update"
                } else {
                    "edited"
                })
            );
        }
    }
    for provider in ["github", "gitlab"] {
        let (app, bus) = harness(provider);
        let mut rx = subscribe(&bus, "allowed", repo(provider), None);
        for current in [true, false] {
            let mut payload = pr(provider);
            if provider == "github" {
                payload["action"] = json!(if current {
                    "converted_to_draft"
                } else {
                    "ready_for_review"
                });
                payload["pull_request"]["draft"] = json!(current);
                payload["pull_request"]["head"] = Value::Null;
            } else {
                payload["changes"] = json!({"draft": {"previous": !current,"current": current}});
                payload["object_attributes"]["draft"] = json!(current);
            }
            assert_eq!(
                post(&app, provider, false, &payload, &[], true).await,
                StatusCode::ACCEPTED
            );
            let event = envelope(&mut rx, "change_request", "");
            let changes = event
                .envelope
                .meta
                .change_request_changes
                .expect("state")
                .draft
                .expect("draft");
            assert_eq!(changes.current, current);
            assert_eq!(
                changes.previous,
                if provider == "gitlab" {
                    Some(!current)
                } else {
                    None
                }
            );
        }
    }
}

fn compound() -> Value {
    let mut p = pr("gitlab");
    p["object_attributes"]["oldrev"] = json!(OTHER_SHA);
    p["changes"]["labels"] = json!({"previous": [], "current": [{"id": 2,"title": "ready"}]});
    p
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One matrix checks the same identity contract across projections.
async fn gitlab_delivery_identity_survives_shared_correlation_and_retries() {
    for (is_push, initial) in [(true, push()), (false, pr("gitlab")), (false, compound())] {
        for actual in [true, false] {
            let (app, bus) = harness("gitlab");
            let mut rx = subscribe(&bus, "allowed", repo("gitlab"), None);
            assert_eq!(
                post(
                    &app,
                    "gitlab",
                    true,
                    &push(),
                    &[("webhook-id", "replay-anchor")],
                    true
                )
                .await,
                StatusCode::ACCEPTED
            );
            let anchor = envelope(&mut rx, "branch_push", "replay-anchor").id;
            let mut ids = Vec::new();
            for n in 0..2 {
                let mut p = initial.clone();
                // Both distinct bodies retain the same ref/head/state; fingerprint includes authenticated bytes.
                p["fixture_sequence"] = json!(n);
                let delivery = format!("delivery-{n}");
                let mut h = vec![("X-Gitlab-Event-UUID", "correlation-A")];
                if actual {
                    h.push(("webhook-id", &delivery));
                }
                assert_eq!(
                    post(&app, "gitlab", is_push, &p, &h, true).await,
                    StatusCode::ACCEPTED
                );
                let e = envelope(
                    &mut rx,
                    if is_push {
                        "branch_push"
                    } else {
                        "change_request"
                    },
                    if actual { &delivery } else { "" },
                );
                if !is_push {
                    assert_eq!(e.envelope.meta.head_sha.as_deref(), Some(SHA));
                    let sync = initial["object_attributes"]["oldrev"].is_string();
                    assert_eq!(
                        e.envelope.meta.action,
                        if sync { "synchronize" } else { "updated" }
                    );
                    assert_eq!(e.envelope.meta.labels_changed, sync);
                    assert!(
                        e.envelope
                            .meta
                            .change_request_changes
                            .as_ref()
                            .expect("state")
                            .draft
                            .is_some()
                    );
                }
                assert!(!e.data.contains("correlation-A"));
                ids.push(e.id);
                assert_eq!(
                    post(&app, "gitlab", is_push, &p, &h, true).await,
                    StatusCode::ACCEPTED
                );
                assert!(rx.try_recv().is_err());
            }
            let mut replay = subscribe(&bus, "replay", repo("gitlab"), Some(&anchor));
            for id in ids {
                assert_eq!(replay.try_recv().expect("retained hint").id, id);
            }
            assert!(replay.try_recv().is_err());
        }
        // Stable modern message IDs win even if the legacy delivery UUID changes.
        for preferred in ["WeBhOoK-Id", "Idempotency-Key"] {
            let (app, bus) = harness("gitlab");
            let mut rx = subscribe(&bus, "allowed", repo("gitlab"), None);
            for legacy in ["legacy-1", "legacy-2"] {
                let mut h = vec![
                    (preferred, "stable"),
                    ("X-Gitlab-Webhook-UUID", legacy),
                    ("X-Gitlab-Event-UUID", "correlation-A"),
                ];
                if preferred == "WeBhOoK-Id" {
                    h.push(("Idempotency-Key", "other"));
                } else {
                    h.push(("webhook-id", "   "));
                }
                assert_eq!(
                    post(&app, "gitlab", is_push, &initial, &h, true).await,
                    StatusCode::ACCEPTED
                );
            }
            envelope(
                &mut rx,
                if is_push {
                    "branch_push"
                } else {
                    "change_request"
                },
                "stable",
            );
            assert!(rx.try_recv().is_err());
        }
        for (h, expected) in [
            (
                vec![
                    ("webhook-id", " "),
                    ("Idempotency-Key", " "),
                    ("x-GITLAB-webhook-UUID", "legacy"),
                ],
                "legacy",
            ),
            (
                vec![
                    ("webhook-id", " "),
                    ("Idempotency-Key", " "),
                    ("X-Gitlab-Webhook-UUID", " "),
                    ("X-Gitlab-Event-UUID", "correlation-A"),
                ],
                "",
            ),
            (vec![], ""),
        ] {
            let (app, bus) = harness("gitlab");
            let mut rx = subscribe(&bus, "allowed", repo("gitlab"), None);
            assert_eq!(
                post(&app, "gitlab", is_push, &initial, &h, true).await,
                StatusCode::ACCEPTED
            );
            envelope(
                &mut rx,
                if is_push {
                    "branch_push"
                } else {
                    "change_request"
                },
                expected,
            );
        }
        for name in ["webhook-id", "Idempotency-Key", "X-Gitlab-Webhook-UUID"] {
            let (app, bus) = harness("gitlab");
            let mut rx = subscribe(&bus, "allowed", repo("gitlab"), None);
            let oversized = "x".repeat(257);
            assert_eq!(
                post(
                    &app,
                    "gitlab",
                    is_push,
                    &initial,
                    &[(name, &oversized)],
                    true
                )
                .await,
                StatusCode::BAD_REQUEST
            );
            assert!(rx.try_recv().is_err());
        }
    }
}

#[tokio::test]
async fn gitlab_new_hints_do_not_collide_with_legacy_synchronize_in_either_order() {
    let mut legacy = pr("gitlab");
    legacy["changes"] = json!({});
    for (is_push, p) in [(true, push()), (false, pr("gitlab")), (false, compound())] {
        for reverse in [false, true] {
            for actual in [false, true] {
                let (app, bus) = harness("gitlab");
                let mut rx = subscribe(&bus, "allowed", repo("gitlab"), None);
                let mut h = vec![("X-Gitlab-Event-UUID", "correlation-A")];
                if actual {
                    h.push(("webhook-id", "actual"));
                }
                let mut deliveries = vec![
                    (is_push, &p, h),
                    (
                        false,
                        &legacy,
                        vec![("X-Gitlab-Event-UUID", "correlation-A")],
                    ),
                ];
                if reverse {
                    deliveries.reverse();
                }
                for (push, p, h) in deliveries {
                    assert_eq!(
                        post(&app, "gitlab", push, p, &h, true).await,
                        StatusCode::ACCEPTED
                    );
                }
                let events = [
                    rx.try_recv().expect("first"),
                    rx.try_recv().expect("second"),
                ];
                let old = events
                    .iter()
                    .find(|e| e.envelope.meta.delivery_id == "correlation-A")
                    .expect("legacy identity");
                assert_eq!(old.envelope.meta.action, "synchronize");
                assert_eq!(old.envelope.meta.head_sha.as_deref(), Some(SHA));
                assert!(old.envelope.meta.change_request_changes.is_none());
                assert!(old.envelope.meta.provider_action.is_none());
                let new = events.iter().find(|e| e.id != old.id).expect("new");
                assert_eq!(
                    new.envelope.meta.delivery_id,
                    if actual { "actual" } else { "" }
                );
                assert!(!new.data.contains("correlation-A"));
                assert!(rx.try_recv().is_err());
            }
        }
    }
}

#[tokio::test]
async fn targeted_invalid_fields_never_publish() {
    for provider in ["github", "gitlab", "forgejo", "gitea"] {
        let (app, bus) = harness(provider);
        let mut rx = subscribe(&bus, "allowed", repo(provider), None);
        for (field, value) in [
            ("ref", json!("refs/heads/")),
            ("ref", json!("refs/heads/a..b")),
            ("ref", json!("refs/heads/a/.hidden")),
            ("ref", json!("refs/heads/a.lock")),
            ("before", json!("bad")),
            ("after", json!("a".repeat(41))),
            ("after", json!(false)),
            ("forced", json!("true")),
        ] {
            if field == "forced" && provider != "github" {
                continue;
            }
            let mut p = push();
            p[field] = value;
            assert_eq!(
                post(&app, provider, true, &p, &[], true).await,
                StatusCode::BAD_REQUEST,
                "{provider} {field}"
            );
        }
        for name in ["", "..", "bad/repo"] {
            let mut p = push();
            if provider == "gitlab" {
                p["project"]["path_with_namespace"] = json!(format!("org/{name}"));
            } else {
                p["repository"]["name"] = json!(name);
            }
            // A slash in GitLab's namespace is supported; use invalid final component instead.
            if provider == "gitlab" && name == "bad/repo" {
                p["project"]["path_with_namespace"] = json!("org//repo");
            }
            assert_eq!(
                post(&app, provider, true, &p, &[], true).await,
                StatusCode::BAD_REQUEST
            );
        }
        for value in [json!(0), json!("7"), Value::Null] {
            let mut p = pr(provider);
            if provider == "gitlab" {
                p["object_attributes"]["iid"] = value;
            } else {
                p["number"] = value.clone();
                p["pull_request"]["number"] = value;
            }
            assert_eq!(
                post(&app, provider, false, &p, &[], true).await,
                StatusCode::BAD_REQUEST
            );
        }
        let mut p = pr(provider);
        if provider == "gitlab" {
            p["object_kind"] = json!("issue");
        } else {
            p["pull_request"]["number"] = json!(8);
        }
        assert_eq!(
            post(&app, provider, false, &p, &[], true).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post(&app, provider, false, &pr(provider), &[], false).await,
            StatusCode::UNAUTHORIZED
        );
        assert!(rx.try_recv().is_err());
    }
    for (pointer, value) in [
        ("/changes/target_branch/previous", json!(false)),
        ("/changes/target_branch/current", Value::Null),
        ("/object_attributes/target_branch", json!("contradiction")),
        ("/changes/draft/previous", json!("true")),
        ("/object_attributes/draft", json!(true)),
        ("/object_attributes/oldrev", json!("")),
        ("/object_attributes/oldrev", json!(ZERO)),
        ("/object_attributes/oldrev", json!(SHA)),
        ("/object_attributes/oldrev", json!(false)),
    ] {
        let (app, bus) = harness("gitlab");
        let mut rx = subscribe(&bus, "allowed", repo("gitlab"), None);
        let mut p = pr("gitlab");
        p["object_attributes"]["oldrev"] = Value::Null;
        *p.pointer_mut(pointer).expect("fixture field") = value;
        assert_eq!(
            post(&app, "gitlab", false, &p, &[], true).await,
            StatusCode::BAD_REQUEST,
            "{pointer}"
        );
        assert!(rx.try_recv().is_err());
    }
    let (app, bus) = harness("github");
    let mut rx = subscribe(&bus, "allowed", repo("github"), None);
    let mut p = pr("github");
    p["action"] = json!("converted_to_draft");
    assert_eq!(
        post(&app, "github", false, &p, &[], true).await,
        StatusCode::BAD_REQUEST
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn generic_snapshots_and_unsupported_signals_have_no_state_metadata() {
    for provider in ["github", "gitlab", "forgejo", "gitea"] {
        let (app, bus) = harness(provider);
        let mut rx = subscribe(&bus, "allowed", repo(provider), None);
        for changes in [
            json!({}),
            json!({"title":{"from":"old"}}),
            json!({"body":{"from":"old"}}),
            json!({"base":{"sha":{"from":OTHER_SHA}}}),
        ] {
            let mut p = pr(provider);
            p["changes"] = changes;
            assert_eq!(
                post(&app, provider, false, &p, &[], true).await,
                StatusCode::ACCEPTED
            );
            if provider == "gitlab" {
                let e = envelope(&mut rx, "change_request", "");
                assert!(e.envelope.meta.change_request_changes.is_none());
            }
            assert!(rx.try_recv().is_err());
            // Legacy no-ID synchronize retries at one head collapse, so use a distinct head each iteration below.
            if provider == "gitlab" {
                break;
            }
        }
        if provider == "forgejo" || provider == "gitea" {
            for action in ["ready_for_review", "converted_to_draft"] {
                let mut p = pr(provider);
                p["action"] = json!(action);
                assert_eq!(
                    post(&app, provider, false, &p, &[], true).await,
                    StatusCode::ACCEPTED
                );
                assert!(rx.try_recv().is_err());
            }
        }
    }
}

#[tokio::test]
async fn equal_deltas_unknown_actions_and_lifecycle_compounds() {
    for provider in ["github", "gitlab", "forgejo", "gitea"] {
        let (app, bus) = harness(provider);
        let mut rx = subscribe(&bus, "allowed", repo(provider), None);
        let mut p = pr(provider);
        if provider == "gitlab" {
            p["changes"]["target_branch"]["previous"] = json!("release/next");
            p["changes"]["draft"]["previous"] = json!(false);
        } else if provider == "github" {
            p["changes"]["base"]["ref"]["from"] = json!("release/next");
        } else {
            p["changes"]["ref"]["from"] = json!("release/next");
        }
        assert_eq!(
            post(&app, provider, false, &p, &[], true).await,
            StatusCode::ACCEPTED
        );
        if provider == "gitlab" {
            assert!(
                envelope(&mut rx, "change_request", "")
                    .envelope
                    .meta
                    .change_request_changes
                    .is_none()
            );
        }
        assert!(rx.try_recv().is_err());
        let mut p = pr(provider);
        if provider == "gitlab" {
            p["object_attributes"]["action"] = json!("unknown");
        } else {
            p["action"] = json!("unknown");
        }
        assert_eq!(
            post(&app, provider, false, &p, &[], true).await,
            StatusCode::ACCEPTED
        );
        assert!(rx.try_recv().is_err());
    }
    for (action, state, expected) in [
        ("open", "opened", "opened"),
        ("reopen", "opened", "reopened"),
        ("close", "closed", "closed"),
        ("merge", "merged", "merged"),
    ] {
        let (app, bus) = harness("gitlab");
        let mut rx = subscribe(&bus, "allowed", repo("gitlab"), None);
        let mut p = pr("gitlab");
        p["object_attributes"]["action"] = json!(action);
        p["object_attributes"]["state"] = json!(state);
        p["object_attributes"]["last_commit"] = Value::Null;
        assert_eq!(
            post(
                &app,
                "gitlab",
                false,
                &p,
                &[
                    ("webhook-id", "actual"),
                    ("X-Gitlab-Event-UUID", "correlation-A")
                ],
                true
            )
            .await,
            StatusCode::ACCEPTED
        );
        let e = envelope(&mut rx, "change_request", "actual");
        assert_eq!(e.envelope.meta.action, expected);
        assert!(e.envelope.meta.head_sha.is_none());
        assert!(e.envelope.meta.change_request_changes.is_some());
    }
}

#[tokio::test]
async fn push_object_formats_and_repository_isolation() {
    for provider in ["github", "gitlab", "forgejo", "gitea"] {
        let (app, bus) = harness(provider);
        let mut rx = subscribe(&bus, "allowed", repo(provider), None);
        let other_repo = if provider == "gitlab" {
            "hint-forge/org/sub/other"
        } else {
            "hint-forge/org/other"
        };
        let mut other = subscribe(&bus, "other", other_repo, None);
        let mut p = push();
        p["before"] = json!("A".repeat(64));
        p["after"] = json!("B".repeat(64));
        assert_eq!(
            post(&app, provider, true, &p, &[], true).await,
            StatusCode::ACCEPTED
        );
        let e = envelope(&mut rx, "branch_push", "");
        let d = e.envelope.meta.branch_push.expect("push");
        assert_eq!(d.before_sha, "A".repeat(64));
        assert_eq!(d.after_sha, "B".repeat(64));
        assert!(other.try_recv().is_err());
        if provider == "gitlab" {
            p["project"]["path_with_namespace"] = json!("org/sub/other");
        } else {
            p["repository"]["name"] = json!("other");
        }
        assert_eq!(
            post(&app, provider, true, &p, &[], true).await,
            StatusCode::ACCEPTED
        );
        envelope(&mut other, "branch_push", "");
        assert!(rx.try_recv().is_err());
    }
}

#[tokio::test]
async fn missing_auth_and_missing_synchronized_heads_do_not_publish() {
    for provider in ["github", "gitlab", "forgejo", "gitea"] {
        let (app, bus) = harness(provider);
        let mut rx = subscribe(&bus, "allowed", repo(provider), None);
        for is_push in [false, true] {
            let (header, event) = match provider {
                "gitlab" => (
                    "X-Gitlab-Event",
                    if is_push {
                        "Push Hook"
                    } else {
                        "Merge Request Hook"
                    },
                ),
                "forgejo" => (
                    "X-Forgejo-Event",
                    if is_push { "push" } else { "pull_request" },
                ),
                "gitea" => (
                    "X-Gitea-Event",
                    if is_push { "push" } else { "pull_request" },
                ),
                _ => (
                    "X-GitHub-Event",
                    if is_push { "push" } else { "pull_request" },
                ),
            };
            let mut p = if is_push { push() } else { pr(provider) };
            p["ref"] = json!("refs/tags/v1");
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/forges/hint-forge/webhook")
                .header(header, event)
                .body(Body::from(serde_json::to_vec(&p).expect("JSON")))
                .expect("request");
            assert_eq!(
                app.clone()
                    .oneshot(request)
                    .await
                    .expect("response")
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            assert!(rx.try_recv().is_err());
        }
    }
    let (app, bus) = harness("gitlab");
    let mut rx = subscribe(&bus, "allowed", repo("gitlab"), None);
    let mut p = compound();
    p["object_attributes"]["last_commit"] = Value::Null;
    assert_eq!(
        post(&app, "gitlab", false, &p, &[], true).await,
        StatusCode::BAD_REQUEST
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn gitlab_push_ignores_deprecated_repository_shape() {
    let (app, bus) = harness("gitlab");
    let mut rx = subscribe(&bus, "allowed", repo("gitlab"), None);
    let mut p = push();
    // GitLab DataBuilder::Push includes this deprecated object without owner.
    p["repository"] = json!({"name":"legacy-name","url":"git@example.invalid:legacy/repo.git","homepage":"https://example.invalid/legacy/repo"});
    assert_eq!(
        post(&app, "gitlab", true, &p, &[], true).await,
        StatusCode::ACCEPTED
    );
    let e = envelope(&mut rx, "branch_push", "");
    assert_eq!(e.envelope.meta.owner, "org/sub");
    assert_eq!(e.envelope.meta.repo, "repo");
}
