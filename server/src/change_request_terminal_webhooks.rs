// SPDX-License-Identifier: Apache-2.0
//! In-process provider fixtures; provenance is recorded in README.md.
#![allow(clippy::expect_used)]

use std::fmt::Write as _;
use std::sync::{Arc, atomic::Ordering};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use domain::{ForgeKind, PublishableEvent, WebhookEvent};
use forge::{ForgeWebhookAdapter, ForgeWebhookError};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tower::ServiceExt;

use super::AppState;
use super::tests::{FakeWriteService, test_forge_instance};
use crate::{
    auth::AgentRegistry,
    config::{AgentPolicyConfig, ForgeWebhookConfig},
    events::EventBus,
    registry::ForgeRegistry,
};

const SECRET: &str = "terminal-test-secret";

fn adapter(kind: &ForgeKind) -> Arc<dyn ForgeWebhookAdapter> {
    match kind {
        ForgeKind::Forgejo => Arc::new(
            forge::ForgejoAdapter::new(forge::ForgejoConfig {
                base_url: "https://forge.example".into(),
                token: None,
                woodpecker_url: None,
                woodpecker_token: None,
            })
            .expect("adapter"),
        ),
        ForgeKind::GitHub => Arc::new(
            forge::github::GitHubAdapter::new(forge::github::GitHubConfig {
                api_url: "https://forge.example".into(),
                token: None,
            })
            .expect("adapter"),
        ),
        ForgeKind::GitLab => Arc::new(
            forge::gitlab::GitLabAdapter::new(forge::gitlab::GitLabConfig {
                base_url: "https://forge.example".into(),
                token: None,
            })
            .expect("adapter"),
        ),
    }
}

fn fixture(kind: &ForgeKind, merged: bool) -> Value {
    if *kind == ForgeKind::GitLab {
        json!({
            "project": {"name": "repo", "namespace": "org/sub", "path_with_namespace": "org/sub/repo"},
            "object_attributes": {
                "action": if merged { "merge" } else { "close" },
                "state": if merged { "merged" } else { "closed" },
                "id": 999, "iid": 42, "title": "Change", "url": "https://forge.example/pr/42",
                "last_commit": {"id": "source-sha"},
                "source": {"path_with_namespace": "fork/repo"},
                "merge_commit_sha": "merge-sha"
            }
        })
    } else {
        json!({
            "action": "closed", "number": 42,
            "repository": {"owner": {"login": "org/sub"}, "name": "repo"},
            "pull_request": {
                "number": 43, "merged": merged, "title": "Change",
                "html_url": "https://forge.example/pr/42",
                "head": {"ref": "feature", "sha": "source-sha", "repo": {"owner": {"login": "fork"}}},
                "base": {"sha": "target-sha"}, "merge_commit_sha": "merge-sha"
            }
        })
    }
}

fn headers(kind: &ForgeKind, body: &[u8], delivery: &str) -> Vec<(String, String)> {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("HMAC");
    mac.update(body);
    let signature = mac
        .finalize()
        .into_bytes()
        .iter()
        .fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").expect("string");
            s
        });
    let (event_header, event, auth_header, auth, delivery_header) = match kind {
        ForgeKind::Forgejo => (
            "x-forgejo-event",
            "pull_request",
            "x-forgejo-signature",
            signature,
            "x-forgejo-delivery",
        ),
        ForgeKind::GitHub => (
            "x-github-event",
            "pull_request",
            "x-hub-signature-256",
            format!("sha256={signature}"),
            "x-github-delivery",
        ),
        ForgeKind::GitLab => (
            "x-gitlab-event",
            "Merge Request Hook",
            "x-gitlab-token",
            SECRET.to_string(),
            "x-gitlab-event-uuid",
        ),
    };
    let mut headers = vec![
        (event_header.into(), event.into()),
        (auth_header.into(), auth),
    ];
    if !delivery.is_empty() {
        headers.push((delivery_header.into(), delivery.into()));
    }
    headers
}

fn parse(kind: &ForgeKind, payload: &Value) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let body = serde_json::to_vec(payload).expect("fixture JSON");
    adapter(kind).verify_and_parse_webhook_event(
        &headers(kind, &body, "delivery"),
        &body,
        "test-forge",
        kind.clone(),
        "https://forge.example",
        SECRET,
    )
}

fn policy(allowed: bool) -> AgentPolicyConfig {
    AgentPolicyConfig {
        allowed_repos: vec![
            if allowed {
                "test-forge/org/sub/repo"
            } else {
                "test-forge/other/repo"
            }
            .into(),
        ],
        branch_prefix: None,
        protected_paths: vec![],
    }
}

#[tokio::test]
async fn terminal_webhooks_reach_authorized_envelopes_without_writes() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        for merged in [false, true] {
            for missing_head in [false, true] {
                for delivery in ["delivery", ""] {
                    exercise_delivery(&kind, merged, missing_head, delivery).await;
                }
            }
        }
    }
}

fn test_state(kind: &ForgeKind, writes: Arc<FakeWriteService>, bus: &EventBus) -> AppState {
    let mut instance = test_forge_instance("test-forge", "https://forge.example", writes);
    instance.forge_kind = kind.clone();
    instance.webhook_adapter = adapter(kind);
    instance.webhook = Some(ForgeWebhookConfig {
        auto_merge: true,
        secret: SECRET.into(),
    });
    let registry = Arc::new(ForgeRegistry::new(std::collections::HashMap::from([(
        "test-forge".into(),
        instance,
    )])));
    AppState {
        agent_registry: AgentRegistry::from_configs(&[]),
        audit_sink: Arc::new(audit::InMemoryAuditSink::new()),
        auto_merge_service: Arc::new(crate::auto_merge::AutoMergeService::new(
            bus.clone(),
            registry.clone(),
        )),
        event_bus: bus.clone(),
        forge_registry: registry,
    }
}

async fn exercise_delivery(kind: &ForgeKind, merged: bool, missing_head: bool, delivery: &str) {
    let writes = Arc::new(FakeWriteService::new());
    let bus = EventBus::new();
    let WebhookEvent::ChangeRequest(mut seed) = parse(kind, &fixture(kind, false))
        .expect("seed")
        .expect("event")
    else {
        unreachable!()
    };
    seed.delivery_id = "seed".into();
    bus.publish(&seed).expect("replay cursor");

    let mut allowed = bus.subscribe("allowed".into(), policy(true), "live".into(), None);
    let mut denied = bus.subscribe("denied".into(), policy(false), "live".into(), None);
    let app = crate::build_router(test_state(kind, writes.clone(), &bus), false);
    let mut payload = fixture(kind, merged);
    if missing_head {
        if *kind == ForgeKind::GitLab {
            payload["object_attributes"]
                .as_object_mut()
                .expect("attrs")
                .remove("last_commit");
        } else {
            payload["pull_request"]
                .as_object_mut()
                .expect("PR")
                .remove("head");
        }
    }
    let normalized = parse(kind, &payload).expect("parse").expect("event");
    let WebhookEvent::ChangeRequest(normalized) = normalized else {
        unreachable!()
    };
    assert_eq!(normalized.title, "Change");
    assert_eq!(normalized.url, "https://forge.example/pr/42");
    let body = serde_json::to_vec(&payload).expect("JSON");
    for duplicate in [false, true] {
        let mut request = Request::post("/api/v1/forges/test-forge/webhook");
        for (name, value) in headers(kind, &body, delivery) {
            request = request.header(name, value);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body.clone())).expect("request"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        if !duplicate {
            let event = allowed.try_recv().expect("synchronous publication");
            let envelope: Value = serde_json::from_str(&event.data).expect("envelope JSON");
            assert_eq!(envelope["kind"], "change_request");
            assert_eq!(envelope["meta"]["event_kind"], "change_request");
            assert_eq!(
                envelope["meta"]["action"],
                if merged { "merged" } else { "closed" }
            );
            assert_eq!(envelope["meta"]["forge_alias"], "test-forge");
            assert_eq!(envelope["meta"]["owner"], "org/sub");
            assert_eq!(envelope["meta"]["repo"], "repo");
            assert_eq!(envelope["meta"]["change_request"], 42);
            assert_eq!(envelope["meta"]["delivery_id"], delivery);
            assert_eq!(
                envelope["meta"]["head_sha"],
                if missing_head {
                    Value::Null
                } else {
                    json!("source-sha")
                }
            );
            for field in ["issue", "issue_comment", "review_state"] {
                assert!(envelope["meta"][field].is_null());
            }
            let mut replay = bus.subscribe(
                "replay".into(),
                policy(true),
                "replay".into(),
                Some("test-forge:seed"),
            );
            assert_eq!(replay.try_recv().expect("replay").data, event.data);
            let mut denied_replay = bus.subscribe(
                "denied-replay".into(),
                policy(false),
                "replay".into(),
                Some("test-forge:seed"),
            );
            assert!(denied_replay.try_recv().is_err());
        }
        assert!(allowed.try_recv().is_err());
        assert!(denied.try_recv().is_err());
    }
    tokio::task::yield_now().await;
    assert_eq!(writes.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn terminal_webhooks_reject_ambiguous_evidence_and_identity() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        let original = fixture(&kind, false);
        let (object, evidence, index) = if kind == ForgeKind::GitLab {
            ("object_attributes", "state", "iid")
        } else {
            ("pull_request", "merged", "number")
        };
        for value in [Value::Null, json!(1), json!({}), json!("invalid")] {
            let mut payload = original.clone();
            payload[object][evidence] = value;
            assert!(matches!(
                parse(&kind, &payload),
                Err(ForgeWebhookError::InvalidPayload(_))
            ));
        }
        let mut payload = original.clone();
        payload[object]
            .as_object_mut()
            .expect("object")
            .remove(evidence);
        assert!(matches!(
            parse(&kind, &payload),
            Err(ForgeWebhookError::InvalidPayload(_))
        ));
        for value in [Value::Null, json!(0), json!("42")] {
            let mut payload = original.clone();
            if kind == ForgeKind::GitLab {
                payload[object][index] = value;
            } else {
                payload[index] = value.clone();
                payload[object][index] = value;
            }
            assert!(matches!(
                parse(&kind, &payload),
                Err(ForgeWebhookError::InvalidPayload(_))
            ));
        }
        for field in [
            object,
            if kind == ForgeKind::GitLab {
                "project"
            } else {
                "repository"
            },
        ] {
            let mut payload = original.clone();
            payload.as_object_mut().expect("object").remove(field);
            assert!(matches!(
                parse(&kind, &payload),
                Err(ForgeWebhookError::InvalidPayload(_))
            ));
        }
        for owner_empty in [false, true] {
            let mut payload = original.clone();
            if kind == ForgeKind::GitLab {
                payload["project"]["path_with_namespace"] =
                    json!(if owner_empty { "/repo" } else { "org/" });
            } else if owner_empty {
                payload["repository"]["owner"]["login"] = json!(" ");
            } else {
                payload["repository"]["name"] = json!("");
            }
            assert!(matches!(
                parse(&kind, &payload),
                Err(ForgeWebhookError::InvalidPayload(_))
            ));
        }
        if kind == ForgeKind::GitLab {
            for (action, state) in [
                ("close", "merged"),
                ("merge", "closed"),
                ("merge", "opened"),
            ] {
                let mut payload = original.clone();
                payload[object]["action"] = json!(action);
                payload[object]["state"] = json!(state);
                assert!(matches!(
                    parse(&kind, &payload),
                    Err(ForgeWebhookError::InvalidPayload(_))
                ));
            }
        }
    }
}

#[test]
fn terminal_webhooks_preserve_nonterminal_actions_and_provider_identity() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        let object = if kind == ForgeKind::GitLab {
            "object_attributes"
        } else {
            "pull_request"
        };
        let actions = if kind == ForgeKind::GitLab {
            ["open", "reopen", "update"]
        } else {
            ["opened", "reopened", "synchronize"]
        };
        for (action, expected) in actions
            .into_iter()
            .zip(["opened", "reopened", "synchronize"])
        {
            for evidence in [true, false] {
                let mut payload = fixture(&kind, true);
                if kind == ForgeKind::GitLab {
                    payload[object]["action"] = json!(action);
                } else {
                    payload["action"] = json!(action);
                }
                if !evidence {
                    payload[object].as_object_mut().expect("object").remove(
                        if kind == ForgeKind::GitLab {
                            "state"
                        } else {
                            "merged"
                        },
                    );
                }
                let WebhookEvent::ChangeRequest(event) =
                    parse(&kind, &payload).expect("parse").expect("event")
                else {
                    unreachable!()
                };
                assert_eq!(event.action.as_str(), expected);
                if kind != ForgeKind::GitLab {
                    payload[object]
                        .as_object_mut()
                        .expect("object")
                        .remove("head");
                    assert!(parse(&kind, &payload).is_err());
                }
            }
        }
        for action in if kind == ForgeKind::GitLab {
            ["approved", "unknown", "approval"]
        } else {
            ["merge", "merged", "edited"]
        } {
            let mut payload = fixture(&kind, true);
            if kind == ForgeKind::GitLab {
                payload[object]["action"] = json!(action);
            } else {
                payload["action"] = json!(action);
            }
            assert!(parse(&kind, &payload).expect("ignored").is_none());
        }
        for head in [
            Value::Null,
            json!({}),
            json!({"sha": null}),
            json!({"sha": "source-sha"}),
        ] {
            if kind == ForgeKind::GitLab {
                continue;
            }
            let mut payload = fixture(&kind, true);
            payload[object]["head"] = head;
            assert!(
                parse(&kind, &payload)
                    .expect("terminal optional head")
                    .is_some()
            );
        }
    }
    let mut payload = fixture(&ForgeKind::Forgejo, true);
    payload.as_object_mut().expect("object").remove("number");
    payload["repository"]["owner"] = json!({"username": "org/sub"});
    payload["action"] = json!("synchronized");
    let WebhookEvent::ChangeRequest(event) = parse(&ForgeKind::Forgejo, &payload)
        .expect("parse")
        .expect("event")
    else {
        unreachable!()
    };
    assert_eq!(event.index, 43);
    assert_eq!(event.repository.owner, "org/sub");
    assert_eq!(event.action.as_str(), "synchronize");
}

#[test]
fn terminal_webhooks_authenticate_before_parsing() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        let adapter = adapter(&kind);
        let body = serde_json::to_vec(&fixture(&kind, true)).expect("JSON");
        for invalid in [false, true] {
            let mut h = headers(&kind, &body, "delivery");
            if invalid {
                h[1].1 = "bad".into();
            } else {
                h.remove(1);
            }
            assert!(
                adapter
                    .verify_and_parse_webhook_event(
                        &h,
                        &body,
                        "test-forge",
                        kind.clone(),
                        "https://forge.example",
                        SECRET
                    )
                    .is_err()
            );
        }
        let malformed = b"{";
        assert!(matches!(
            adapter.verify_and_parse_webhook_event(
                &headers(&kind, malformed, "d"),
                malformed,
                "test-forge",
                kind.clone(),
                "https://forge.example",
                SECRET
            ),
            Err(ForgeWebhookError::InvalidPayload(_))
        ));
        let mut h = headers(&kind, &body, "d");
        h[0].1 = "unsupported".into();
        assert!(
            adapter
                .verify_and_parse_webhook_event(
                    &h,
                    &body,
                    "test-forge",
                    kind.clone(),
                    "https://forge.example",
                    SECRET
                )
                .expect("unsupported event")
                .is_none()
        );
    }
}

#[test]
fn terminal_fallback_keys_distinguish_close_from_merge() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        let mut keys = vec![];
        for merged in [false, true] {
            let WebhookEvent::ChangeRequest(mut event) = parse(&kind, &fixture(&kind, merged))
                .expect("parse")
                .expect("event")
            else {
                unreachable!()
            };
            event.delivery_id.clear();
            keys.push(event.dedupe_key());
        }
        assert_ne!(keys[0], keys[1]);
    }
}

#[tokio::test]
async fn terminal_webhooks_invalid_http_deliveries_publish_nothing() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        let writes = Arc::new(FakeWriteService::new());
        let bus = EventBus::new();
        let mut receiver = bus.subscribe("allowed".into(), policy(true), "live".into(), None);
        let app = crate::build_router(test_state(&kind, writes.clone(), &bus), false);
        let mut ambiguous = fixture(&kind, true);
        if kind == ForgeKind::GitLab {
            ambiguous["object_attributes"]["state"] = Value::Null;
        } else {
            ambiguous["pull_request"]["merged"] = Value::Null;
        }
        let valid = serde_json::to_vec(&fixture(&kind, true)).expect("JSON");
        for case in 0..5 {
            let body = match case {
                2 => b"{".to_vec(),
                3 => serde_json::to_vec(&ambiguous).expect("JSON"),
                _ => valid.clone(),
            };
            let mut h = headers(&kind, &body, "bad-delivery");
            match case {
                0 => {
                    h.remove(1);
                }
                1 => h[1].1 = "invalid".into(),
                4 => h[0].1 = "unsupported".into(),
                _ => {}
            }
            let mut request = Request::post("/api/v1/forges/test-forge/webhook");
            for (name, value) in h {
                request = request.header(name, value);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(body)).expect("request"))
                .await
                .expect("response");
            if case == 4 {
                assert_eq!(response.status(), StatusCode::ACCEPTED);
            } else {
                assert!(response.status().is_client_error());
            }
            assert!(receiver.try_recv().is_err());
        }
        assert_eq!(writes.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn terminal_fallback_dedupe_publishes_both_distinct_actions() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        let bus = EventBus::new();
        let mut receiver = bus.subscribe("allowed".into(), policy(true), "live".into(), None);
        for merged in [false, true] {
            let WebhookEvent::ChangeRequest(mut event) = parse(&kind, &fixture(&kind, merged))
                .expect("parse")
                .expect("event")
            else {
                unreachable!()
            };
            event.delivery_id.clear();
            assert_eq!(
                bus.publish(&event).expect("publish"),
                crate::events::PublishStatus::Enqueued { delivered: 1 }
            );
            assert_eq!(
                receiver
                    .try_recv()
                    .expect("distinct event")
                    .envelope
                    .meta
                    .action,
                if merged { "merged" } else { "closed" }
            );
            assert_eq!(
                bus.publish(&event).expect("duplicate"),
                crate::events::PublishStatus::Duplicate
            );
            assert!(receiver.try_recv().is_err());
        }
    }
}

#[test]
fn terminal_webhooks_reject_missing_or_mistyped_target_fields() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        let mut payload = fixture(&kind, true);
        if kind == ForgeKind::GitLab {
            payload["object_attributes"]
                .as_object_mut()
                .expect("attrs")
                .remove("iid");
        } else {
            payload.as_object_mut().expect("payload").remove("number");
            payload["pull_request"]
                .as_object_mut()
                .expect("PR")
                .remove("number");
        }
        assert!(matches!(
            parse(&kind, &payload),
            Err(ForgeWebhookError::InvalidPayload(_))
        ));
        let (object, fields) = if kind == ForgeKind::GitLab {
            ("project", &["path_with_namespace", "namespace", "name"][..])
        } else {
            ("repository", &["owner", "name"][..])
        };
        for &field in fields {
            for value in [None, Some(json!(42)), Some(Value::Null)] {
                let mut payload = fixture(&kind, true);
                if let Some(value) = value {
                    payload[object][field] = value;
                } else {
                    payload[object]
                        .as_object_mut()
                        .expect("repository")
                        .remove(field);
                }
                assert!(matches!(
                    parse(&kind, &payload),
                    Err(ForgeWebhookError::InvalidPayload(_))
                ));
            }
        }
    }
}

#[test]
fn forgejo_terminal_webhooks_preserve_header_and_identity_fallbacks() {
    let kind = ForgeKind::Forgejo;
    for merged in [false, true] {
        let mut payload = fixture(&kind, merged);
        payload.as_object_mut().expect("payload").remove("number");
        payload["repository"]["owner"] = json!({"username": "org/sub"});
        let body = serde_json::to_vec(&payload).expect("JSON");
        let h: Vec<_> = headers(&kind, &body, "gitea-delivery")
            .into_iter()
            .map(|(name, value)| (name.replace("x-forgejo-", "x-gitea-"), value))
            .collect();
        let WebhookEvent::ChangeRequest(event) = adapter(&kind)
            .verify_and_parse_webhook_event(
                &h,
                &body,
                "test-forge",
                kind.clone(),
                "https://forge.example",
                SECRET,
            )
            .expect("parse")
            .expect("event")
        else {
            unreachable!()
        };
        assert_eq!(event.index, 43);
        assert_eq!(event.repository.owner, "org/sub");
        assert_eq!(event.delivery_id, "gitea-delivery");
        assert_eq!(
            event.action.as_str(),
            if merged { "merged" } else { "closed" }
        );
    }
}
