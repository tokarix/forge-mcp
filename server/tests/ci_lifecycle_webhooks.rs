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

// Compact synthetic projections based on GitHub webhook-events-and-payloads
// and GitLab webhook_events (pipeline-events/job-events), read 2026-09-07.
// They prove adapter behavior, not live delivery. Forgejo exclusions correspond
// to v16.0.3 modules/webhook/type.go and services/webhook/notifier.go.
const SECRET: &str = "ci-fixture-secret";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
fn payload(family: &str, state: &str) -> Value {
    let mut p = json!({
        "repository": {"name": "repo", "owner": {"login": "org"}},
        "project": {"id": 7, "path_with_namespace": "org/sub/repo"},
        "project_id": 7,
        "pull_requests": [{"number": 1, "head": {"sha": OTHER_SHA}}, {"number": 2}],
        "merge_request": {"source_project_id": 999, "head_sha": OTHER_SHA},
        "source_pipeline": {"project": {"path_with_namespace": "wrong/repo"}},
        "variables": [{"key": "SECRET", "value": "never-forward"}],
        "jobs": [{"status": "failed"}, {"status": "pending"}],
        "logs": "never-forward"
    });
    match family {
        "status" => {
            p["sha"] = json!(SHA);
            p["id"] = json!(11);
            p["context"] = json!("test");
            p["state"] = json!(state);
        }
        "check_run" | "check_suite" => {
            p["action"] = json!("completed");
            p[family] = json!({"id": 11, "head_sha": SHA, "head_branch": null,
                "name": "test", "status": state, "conclusion": null,
                "pull_requests": [], "started_at": "2026-09-07T00:00:00Z"});
            if family == "check_run" {
                p[family]["check_suite"] = json!({"id": 12});
            }
        }
        "Pipeline Hook" => {
            p["object_kind"] = json!("pipeline");
            p["object_attributes"] = json!({"sha": SHA, "id": 11, "status": state});
            p["commit"] = json!({"id": SHA});
        }
        "Job Hook" => {
            p["object_kind"] = json!("build");
            p["sha"] = json!(SHA);
            p["build_id"] = json!(11);
            p["pipeline_id"] = json!(12);
            p["build_status"] = json!(state);
            p["commit"] = json!({"id": 12});
        }
        _ => panic!("fixture family"),
    }
    p
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
fn headers(family: &str, body: &[u8], delivery: &str) -> Vec<(String, String)> {
    if family.ends_with("Hook") {
        vec![
            ("X-Gitlab-Event".into(), family.into()),
            ("X-Gitlab-Token".into(), SECRET.into()),
            ("webhook-id".into(), delivery.into()),
        ]
    } else {
        vec![
            ("X-GitHub-Event".into(), family.into()),
            ("X-GitHub-Delivery".into(), delivery.into()),
            (
                "X-Hub-Signature-256".into(),
                format!("sha256={}", signature(body)),
            ),
        ]
    }
}
fn parse(
    family: &str,
    p: &Value,
    extra: &[(&str, &str)],
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let body = serde_json::to_vec(p).expect("JSON");
    let mut h = headers(family, &body, "");
    h.retain(|(_, v)| !v.is_empty());
    h.extend(extra.iter().map(|(k, v)| ((*k).into(), (*v).into())));
    if family.ends_with("Hook") {
        gitlab().verify_and_parse_webhook_event(
            &h,
            &body,
            "ci-forge",
            ForgeKind::GitLab,
            "https://provider.invalid",
            SECRET,
        )
    } else {
        github().verify_and_parse_webhook_event(
            &h,
            &body,
            "ci-forge",
            ForgeKind::GitHub,
            "https://provider.invalid",
            SECRET,
        )
    }
}
fn ci(family: &str, p: &Value, extra: &[(&str, &str)]) -> domain::CiChangeEvent {
    let Some(WebhookEvent::CiChange(e)) = parse(family, p, extra).expect("valid") else {
        panic!("CI hint")
    };
    e
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
        alias: "ci-forge".into(),
        base_url: "https://provider.invalid".into(),
        client: server::http_client::client_builder()
            .build()
            .expect("HTTP client"),
        forge_kind: kind,
        forge_type: "ci-forge".into(),
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
        "ci-forge".into(),
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
        .uri("/api/v1/forges/ci-forge/webhook");
    for (k, mut v) in headers(family, &body, delivery) {
        if !auth && (k.contains("Signature") || k.contains("Token")) {
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

#[tokio::test]
async fn ci_signed_http_lifecycle_authorization_replay_and_retry() {
    for auto_merge in [false, true] {
        for family in [
            "status",
            "check_run",
            "check_suite",
            "Pipeline Hook",
            "Job Hook",
        ] {
            let gl = family.ends_with("Hook");
            let (app, bus) = if gl {
                app(gitlab(), ForgeKind::GitLab, auto_merge)
            } else {
                app(github(), ForgeKind::GitHub, auto_merge)
            };
            let repo = if gl {
                "ci-forge/org/sub/repo"
            } else {
                "ci-forge/org/repo"
            };
            let mut allowed = subscribe(&bus, "allowed", repo, None);
            let mut denied = subscribe(&bus, "denied", "ci-forge/other/repo", None);
            let states: &[&str] = match family {
                "status" => &["pending", "success", "failure", "error"],
                "check_run" | "check_suite" => {
                    &["queued", "in_progress", "completed", "in_progress"]
                }
                _ => &["pending", "running", "success", "failed", "canceled"],
            };
            let mut ids = Vec::new();
            for (i, state) in states.iter().enumerate() {
                let mut p = payload(family, state);
                if family.starts_with("check_") {
                    p["action"] = json!(if *state == "completed" {
                        "completed"
                    } else if family == "check_run" {
                        "created"
                    } else {
                        "requested"
                    });
                }
                let body = serde_json::to_vec(&p).expect("JSON");
                let delivery = format!("delivery-{i}");
                assert_eq!(
                    post(&app, family, body.clone(), &delivery, true).await,
                    StatusCode::ACCEPTED
                );
                let e = allowed.try_recv().expect("synchronous hint");
                ids.push(e.id);
                let meta = &e.envelope.meta;
                assert_eq!(e.event_name, "ci");
                assert_eq!(e.envelope.kind, "ci");
                assert_eq!(meta.head_sha.as_deref(), Some(SHA));
                assert_eq!(meta.action, "changed");
                assert_eq!(meta.change_request, None);
                assert_eq!(meta.issue, None);
                assert_eq!(meta.review_state, None);
                assert_eq!(
                    meta.ci.as_ref().expect("details").status.as_deref(),
                    Some(*state)
                );
                assert!(!e.data.contains("never-forward"));
                assert!(!e.data.contains("aggregate_state"));
                assert_eq!(
                    post(&app, family, body, &delivery, true).await,
                    StatusCode::ACCEPTED
                );
                assert!(allowed.try_recv().is_err());
                assert!(denied.try_recv().is_err());
            }
            let mut replay = subscribe(&bus, "replay", repo, Some(&ids[0]));
            let mut denied_replay =
                subscribe(&bus, "denied-replay", "ci-forge/other/repo", Some(&ids[0]));
            for id in ids.iter().skip(1) {
                assert_eq!(&replay.try_recv().expect("replay").id, id);
            }
            assert!(replay.try_recv().is_err());
            assert!(denied_replay.try_recv().is_err());
            assert_eq!(
                post(&app, family, b"{".to_vec(), "bad-json", true).await,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                post(&app, family, b"{}".to_vec(), "bad-schema", true).await,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                post(
                    &app,
                    family,
                    serde_json::to_vec(&payload(family, "success")).expect("JSON"),
                    "bad-auth",
                    false
                )
                .await,
                StatusCode::UNAUTHORIZED
            );
            assert!(allowed.try_recv().is_err());
        }
    }
}

#[test]
fn ci_checks_actions_conclusions_and_pr_associations_are_source_scoped() {
    for family in ["check_run", "check_suite"] {
        let actions: &[&str] = if family == "check_run" {
            &["created", "completed", "rerequested", "requested_action"]
        } else {
            &["completed", "requested", "rerequested"]
        };
        for action in actions {
            for conclusion in [
                Value::Null,
                json!("success"),
                json!("failure"),
                json!("cancelled"),
                json!("neutral"),
                json!("skipped"),
                json!("unknown-new-state"),
            ] {
                for prs in [
                    Value::Null,
                    json!([]),
                    json!([{"number": 1}, {"number": 2}]),
                ] {
                    let mut p = payload(family, "completed");
                    p["action"] = json!(action);
                    p[family]["conclusion"] = conclusion.clone();
                    p[family]["pull_requests"] = prs;
                    let e = ci(family, &p, &[]);
                    assert_eq!(e.provider_action.as_deref(), Some(*action));
                    assert_eq!(
                        serde_json::to_value(&e.details.conclusion).expect("conclusion"),
                        conclusion
                    );
                    assert_eq!(e.head_sha, SHA);
                    assert_eq!(e.to_channel_event().meta.change_request, None);
                    assert_eq!(
                        e.details.parent_id,
                        if family == "check_run" {
                            Some(12)
                        } else {
                            None
                        }
                    );
                }
            }
        }
        assert!(
            parse(
                family,
                &json!({"action": "in_progress", "repository": false}),
                &[]
            )
            .expect("unsupported")
            .is_none()
        );
    }
}

#[test]
fn ci_gitlab_authority_and_legacy_payloads() {
    for family in ["Pipeline Hook", "Job Hook"] {
        let p = payload(family, "success");
        let e = ci(family, &p, &[]);
        assert_eq!(e.repository.owner, "org/sub");
        assert_eq!(e.repository.name, "repo");
        assert_eq!(e.provider_action, None);
        for pointer in ["/project/path_with_namespace", "/object_kind"] {
            for bad in [Value::Null, json!(""), json!(false)] {
                let mut p = p.clone();
                *p.pointer_mut(pointer).expect("field") = bad;
                assert!(parse(family, &p, &[]).is_err());
            }
        }
        for path in [
            "org//repo",
            "../repo",
            "org/./repo",
            "org/repo/",
            "org/\nrepo",
            "repo",
        ] {
            let mut p = p.clone();
            p["project"]["path_with_namespace"] = json!(path);
            assert!(parse(family, &p, &[]).is_err());
        }
        let mut bad = p.clone();
        bad["project_id"] = json!(8);
        assert!(parse(family, &bad, &[]).is_err());
        bad = p.clone();
        bad["commit"]["sha"] = json!(OTHER_SHA);
        assert!(parse(family, &bad, &[]).is_err());
        if family == "Pipeline Hook" {
            bad = p.clone();
            bad["commit"]["id"] = json!(OTHER_SHA);
            assert!(parse(family, &bad, &[]).is_err());
        }
        let mut legacy = p.clone();
        legacy["project"]
            .as_object_mut()
            .expect("project")
            .remove("path_with_namespace");
        assert!(parse(family, &legacy, &[]).expect("unsupported").is_none());
        legacy.as_object_mut().expect("payload").remove("project");
        assert!(parse(family, &legacy, &[]).expect("unsupported").is_none());
    }
    let mut p = payload("Job Hook", "running");
    p["sha"] = json!(12);
    assert!(parse("Job Hook", &p, &[]).is_err());
}

#[test]
fn ci_native_ids_and_exact_sha_validation() {
    for (family, id, sha) in [
        ("status", "/id", "/sha"),
        ("check_run", "/check_run/id", "/check_run/head_sha"),
        ("check_suite", "/check_suite/id", "/check_suite/head_sha"),
        (
            "Pipeline Hook",
            "/object_attributes/id",
            "/object_attributes/sha",
        ),
        ("Job Hook", "/build_id", "/sha"),
    ] {
        for bad in [json!(0), json!(-1), json!("11"), json!(1.5), json!(true)] {
            let mut p = payload(family, "pending");
            *p.pointer_mut(id).expect("id") = bad;
            assert!(parse(family, &p, &[]).is_err());
        }
        for bad in [
            json!(""),
            json!("a".repeat(39)),
            json!("a".repeat(41)),
            json!("0".repeat(40)),
            json!("g".repeat(40)),
            Value::Null,
        ] {
            let mut p = payload(family, "pending");
            *p.pointer_mut(sha).expect("sha") = bad;
            assert!(parse(family, &p, &[]).is_err());
        }
        let mut p = payload(family, "pending");
        *p.pointer_mut(id).expect("id") = Value::Null;
        assert_eq!(ci(family, &p, &[]).details.id, None);
    }
}

#[tokio::test]
async fn ci_no_id_retries_changes_and_gitlab_delivery_precedence() {
    for family in [
        "status",
        "check_run",
        "check_suite",
        "Pipeline Hook",
        "Job Hook",
    ] {
        let bus = EventBus::new();
        let p = payload(family, "pending");
        let e = ci(family, &p, &[]);
        assert!(publish(&bus, &e));
        assert!(!publish(&bus, &e));
        assert!(publish(&bus, &ci(family, &payload(family, "running"), &[])));
        let mut other = p.clone();
        let sha = match family {
            "check_run" => "/check_run/head_sha",
            "check_suite" => "/check_suite/head_sha",
            "Pipeline Hook" => "/object_attributes/sha",
            _ => "/sha",
        };
        *other.pointer_mut(sha).expect("sha") = json!(OTHER_SHA);
        if family == "Pipeline Hook" {
            other["commit"]["id"] = json!(OTHER_SHA);
        }
        assert!(publish(&bus, &ci(family, &other, &[])));
        if family == "status" {
            let mut other = p.clone();
            other["context"] = json!("second");
            assert!(publish(&bus, &ci(family, &other, &[])));
        }
    }
    let p = payload("Job Hook", "success");
    let bus = EventBus::new();
    for delivery in ["first", "second"] {
        let e = ci(
            "Job Hook",
            &p,
            &[
                ("webhook-id", delivery),
                ("Idempotency-Key", "idem"),
                ("X-Gitlab-Webhook-UUID", "native"),
                ("X-Gitlab-Event-UUID", "recursive"),
            ],
        );
        assert_eq!(e.delivery_id, delivery);
        assert_eq!(e.details.delivery_id_source.as_deref(), Some("webhook-id"));
        assert_eq!(e.details.provider_delivery_id.as_deref(), Some("native"));
        assert_eq!(e.details.provider_event_id.as_deref(), Some("recursive"));
        assert!(publish(&bus, &e));
    }
    for (h, expected, source) in [
        (
            vec![("webhook-id", " "), ("Idempotency-Key", "idem")],
            "idem",
            Some("Idempotency-Key"),
        ),
        (
            vec![("X-Gitlab-Webhook-UUID", "native")],
            "native",
            Some("X-Gitlab-Webhook-UUID"),
        ),
        (vec![("X-Gitlab-Event-UUID", "recursive")], "", None),
    ] {
        let e = ci("Job Hook", &p, &h);
        assert_eq!(e.delivery_id, expected);
        assert_eq!(e.details.delivery_id_source.as_deref(), source);
    }
}

#[test]
fn ci_forgejo_does_not_inherit_github_ci_dispatch() {
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        woodpecker_url: None,
        woodpecker_token: None,
        base_url: "https://provider.invalid".into(),
        token: None,
    })
    .expect("adapter");
    for family in [
        "status",
        "check_run",
        "check_suite",
        "action_run_success",
        "action_run_failure",
        "action_run_recover",
    ] {
        let body = serde_json::to_vec(&payload("status", "success")).expect("JSON");
        let h = vec![
            ("X-Forgejo-Event".into(), family.into()),
            ("X-Forgejo-Signature".into(), signature(&body)),
        ];
        assert!(
            adapter
                .verify_and_parse_webhook_event(
                    &h,
                    &body,
                    "ci-forge",
                    ForgeKind::Forgejo,
                    "https://provider.invalid",
                    SECRET
                )
                .expect("verified")
                .is_none()
        );
        assert!(
            adapter
                .verify_and_parse_webhook_event(
                    &h,
                    b"tampered",
                    "ci-forge",
                    ForgeKind::Forgejo,
                    "https://provider.invalid",
                    SECRET
                )
                .is_err()
        );
    }
}

fn publish(bus: &EventBus, event: &domain::CiChangeEvent) -> bool {
    matches!(
        bus.publish(event).expect("publication"),
        server::events::PublishStatus::Enqueued { .. }
    )
}

#[test]
fn ci_minimal_payloads_keep_missing_fields_absent_and_bound_semantics() {
    for (family, p) in [
        (
            "status",
            json!({"repository": {"owner": {"login": "org"}, "name": "repo"}, "sha": SHA}),
        ),
        (
            "check_run",
            json!({"action": "created", "repository": {"owner": {"login": "org"}, "name": "repo"}, "check_run": {"head_sha": SHA}}),
        ),
        (
            "check_suite",
            json!({"action": "requested", "repository": {"owner": {"login": "org"}, "name": "repo"}, "check_suite": {"head_sha": SHA}}),
        ),
        (
            "Pipeline Hook",
            json!({"object_kind": "pipeline", "project": {"path_with_namespace": "org/repo"}, "object_attributes": {"sha": SHA}}),
        ),
        (
            "Job Hook",
            json!({"object_kind": "build", "project": {"path_with_namespace": "org/repo"}, "sha": SHA}),
        ),
    ] {
        let e = ci(family, &p, &[]);
        assert_eq!(e.details.status, None);
        assert_eq!(e.details.conclusion, None);
        assert_eq!(e.details.id, None);
        assert_eq!(e.details.name, None);
        assert_eq!(e.to_channel_event().meta.change_request, None);
        let header = if family.ends_with("Hook") {
            "webhook-id"
        } else {
            "X-GitHub-Delivery"
        };
        assert!(parse(family, &p, &[(header, &"x".repeat(257))]).is_err());
    }
    for (field, limit) in [("context", 1024), ("state", 128), ("updated_at", 64)] {
        let mut p = payload("status", "pending");
        p[field] = json!("é".repeat(limit / 2));
        assert!(parse("status", &p, &[]).is_ok());
        p[field] = json!(format!("{}a", "é".repeat(limit / 2)));
        assert!(parse("status", &p, &[]).is_err());
    }
}
