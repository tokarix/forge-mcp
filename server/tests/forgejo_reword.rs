//! Consumes the dedicated CI service; never starts a provider process.
#[path = "../../forge/tests/support/forgejo.rs"]
mod forgejo;

use std::collections::HashMap;
use std::sync::Arc;

use axum::{Router, body::Body, http::Request};
use base64::Engine;
use domain::ForgeKind;
use forge::{ForgejoAdapter, ForgejoConfig};
use forgejo::{Context, combine_results, unique_name};
use http_body_util::BodyExt;
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use server::auth::AgentRegistry;
use server::auto_merge::AutoMergeService;
use server::config::{AgentConfig, AgentPolicyConfig};
use server::events::EventBus;
use server::handlers::AppState;
use server::registry::{ForgeInstance, ForgeRegistry};
use tower::ServiceExt;

const BRANCH: &str = "agent/ci/reword";
const AGENT_TOKEN: &str = "disposable-reword-test-agent";

fn gateway(context: &Context, repo: &str) -> Result<Router, String> {
    let adapter = Arc::new(
        ForgejoAdapter::new(ForgejoConfig {
            base_url: context.base_url.to_string(),
            token: Some(context.token().into()),
            woodpecker_url: None,
            woodpecker_token: None,
        })
        .map_err(|e| e.to_string())?,
    );
    let audit = Arc::new(audit::InMemoryAuditSink::new());
    let instance = ForgeInstance {
        adapter: adapter.clone(),
        alias: "ci".into(),
        base_url: context.base_url.to_string(),
        client: server::http_client::client_builder()
            .build()
            .map_err(|e| e.to_string())?,
        forge_kind: ForgeKind::Forgejo,
        forge_type: "forgejo".into(),
        git_auth_user: String::new(),
        read_service: Arc::new(ReadOrchestrator::new(adapter.clone(), audit.clone())),
        write_service: Arc::new(WriteOrchestrator::new(
            adapter.clone(),
            audit.clone(),
            Some(domain::CommitAuthor {
                name: "Gateway CI".into(),
                email: "gateway@example.invalid".into(),
            }),
        )),
        token: Some(context.token().into()),
        webhook: None,
        webhook_adapter: adapter,
    };
    let registry = Arc::new(ForgeRegistry::new(HashMap::from([("ci".into(), instance)])));
    let events = EventBus::new();
    let agents = [AgentConfig {
        agent_id: "ci".into(),
        session_id: "reword".into(),
        token: AGENT_TOKEN.into(),
        forge_identity: HashMap::new(),
        github_app: HashMap::new(),
        policy: AgentPolicyConfig {
            allowed_repos: vec![format!("ci/{}/{repo}", context.username)],
            branch_prefix: Some("agent/ci/".into()),
            protected_paths: vec![],
        },
    }];
    Ok(server::build_router(
        AppState {
            agent_registry: AgentRegistry::from_configs(&agents),
            audit_sink: audit,
            auto_merge_service: Arc::new(AutoMergeService::new(events.clone(), registry.clone())),
            event_bus: events,
            forge_registry: registry,
        },
        false,
    ))
}

async fn reword(
    app: &Router,
    context: &Context,
    repo: &str,
    target: &str,
) -> Result<(axum::http::StatusCode, Value), String> {
    let body = json!({"base_branch":"main", "branch":BRANCH, "operations":[{"type":"reword", "commit":target, "message":"Reword through gateway\n\nKeep this PR attached.\n"}]});
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/repos/ci/{}/{repo}/rebase",
                    context.username
                ))
                .header("authorization", format!("Bearer {AGENT_TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    let value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    Ok((status, value))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing string field {key}"))
}

// Forgejo's commit endpoint nests Git metadata under `commit`; top-level
// author fields describe provider accounts rather than the original Git author.
#[derive(Debug, Deserialize)]
struct ProviderCommit {
    commit: CommitMetadata,
    parents: Vec<CommitReference>,
}

#[derive(Debug, Deserialize)]
struct CommitMetadata {
    tree: CommitReference,
    author: CommitIdentity,
    message: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct CommitReference {
    sha: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct CommitIdentity {
    name: String,
    email: String,
    date: String,
}

async fn commit(context: &Context, path: &str, sha: &str) -> Result<ProviderCommit, String> {
    context
        .request_json(Method::GET, &format!("{path}/git/commits/{sha}"), None)
        .await
}

#[derive(Debug, Deserialize)]
struct ProviderTree {
    tree: Vec<TreeEntry>,
    truncated: bool,
    total_count: usize,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct TreeEntry {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    object_type: String,
    sha: String,
}

impl ProviderTree {
    fn complete_entries(self) -> Result<Vec<TreeEntry>, String> {
        if self.truncated || self.tree.len() != self.total_count {
            return Err("provider returned an incomplete tree".into());
        }
        Ok(self.tree)
    }
}

// Forgejo 16 reports the requested commit ID in both commit.tree.sha and
// the tree response's root sha. Compare complete entries instead: paths,
// modes and object IDs determine the tree, including any nested subtrees.
async fn tree(context: &Context, path: &str, reference: &str) -> Result<Vec<TreeEntry>, String> {
    let response: ProviderTree = context
        .request_json(Method::GET, &format!("{path}/git/trees/{reference}"), None)
        .await?;
    response.complete_entries()
}

#[test]
fn provider_tree_requires_complete_entries() -> Result<(), Box<dyn std::error::Error>> {
    let response = json!({
        "sha": "commit-reference",
        "tree": [{"path": "file", "mode": "100644", "type": "blob", "sha": "blob-id"}],
        "truncated": false,
        "total_count": 1
    });
    let parsed: ProviderTree = serde_json::from_value(response.clone())?;
    let entries = parsed.complete_entries()?;
    assert_eq!(entries[0].sha, "blob-id");

    let mut rewritten = response.clone();
    rewritten["sha"] = json!("rewritten-commit-reference");
    let parsed: ProviderTree = serde_json::from_value(rewritten)?;
    assert_eq!(entries, parsed.complete_entries()?);

    for (field, value) in [("truncated", json!(true)), ("total_count", json!(2))] {
        let mut incomplete = response.clone();
        incomplete[field] = value;
        let parsed: ProviderTree = serde_json::from_value(incomplete)?;
        assert!(parsed.complete_entries().is_err());
    }
    Ok(())
}

#[test]
fn provider_commit_requires_nested_git_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let response = json!({
        "sha": "tip",
        "author": null,
        "commit": {
            "tree": {"sha": "tip"},
            "author": {
                "name": "Original Author",
                "email": "author@example.invalid",
                "date": "2026-09-18T10:00:00+03:00"
            },
            "message": "Subject\n\nBody.\n"
        },
        "parents": [{"sha": "parent"}]
    });
    let parsed: ProviderCommit = serde_json::from_value(response.clone())?;
    assert_eq!(parsed.commit.tree.sha, "tip");
    assert_eq!(parsed.commit.author.name, "Original Author");
    assert_eq!(parsed.commit.author.email, "author@example.invalid");
    assert_eq!(parsed.commit.author.date, "2026-09-18T10:00:00+03:00");
    assert_eq!(parsed.commit.message, "Subject\n\nBody.\n");
    assert_eq!(parsed.parents[0].sha, "parent");

    for field in ["tree", "author", "message"] {
        let mut missing = response.clone();
        missing["commit"]
            .as_object_mut()
            .ok_or("missing commit object")?
            .remove(field);
        assert!(serde_json::from_value::<ProviderCommit>(missing).is_err());
        let mut null = response.clone();
        null["commit"][field] = Value::Null;
        assert!(serde_json::from_value::<ProviderCommit>(null).is_err());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn exercise(context: &Context, repo: &str) -> Result<(), String> {
    let path = format!("/api/v1/repos/{}/{repo}", context.username);
    context
        .request_success(
            Method::POST,
            &format!("{path}/branches"),
            Some(json!({"new_branch_name":BRANCH, "old_branch_name":"main"})),
        )
        .await?;
    let mut old_ids = Vec::new();
    for index in 0..3 {
        let result: Value = context.request_json(Method::POST, &format!("{path}/contents/file{index}"), Some(json!({
            "branch":BRANCH, "content":base64::engine::general_purpose::STANDARD.encode(format!("file {index}\n")), "message":format!("Original {index}")
        }))).await?;
        old_ids.push(string(&result["commit"], "sha")?.to_owned());
    }
    let before: Value = context
        .request_json(
            Method::POST,
            &format!("{path}/pulls"),
            Some(json!({"base":"main", "head":BRANCH, "title":"Reword continuity"})),
        )
        .await?;
    let number = before["number"].as_u64().ok_or("missing PR number")?;
    let app = gateway(context, repo)?;
    let (status, result) = reword(&app, context, repo, &old_ids[1]).await?;
    if !status.is_success() {
        return Err(format!("gateway reword failed: {status} {result}"));
    }
    assert_eq!(result["branch"], BRANCH);
    assert_eq!(result["old_commit_sha"], old_ids[2]);
    let new_head = string(&result, "commit_sha")?;
    assert_ne!(new_head, old_ids[2]);
    let pairs = result["commit_mapping"]
        .as_array()
        .ok_or("missing mapping")?;
    assert_eq!(pairs.len(), old_ids.len());
    for (index, pair) in pairs.iter().enumerate() {
        assert_eq!(pair["old_commit_sha"], old_ids[index]);
        let new_id = string(pair, "new_commit_sha")?;
        let old = commit(context, &path, &old_ids[index]).await?;
        let new = commit(context, &path, new_id).await?;
        let old_tree = tree(context, &path, &old.commit.tree.sha).await?;
        let new_tree = tree(context, &path, &new.commit.tree.sha).await?;
        assert_eq!(old_tree, new_tree);
        assert_eq!(old.commit.author, new.commit.author);
        if index == 0 {
            assert_eq!(new_id, old_ids[0]);
            assert_eq!(old.parents, new.parents);
        } else {
            assert_eq!(new.parents[0].sha, pairs[index - 1]["new_commit_sha"]);
        }
        if index == 1 {
            assert_eq!(
                new.commit.message,
                "Reword through gateway\n\nKeep this PR attached.\n"
            );
        } else {
            assert_eq!(new.commit.message, old.commit.message);
        }
    }
    // Forgejo updates PR heads asynchronously after push processing.
    let mut after = Value::Null;
    for _ in 0..100 {
        after = context
            .request_json(Method::GET, &format!("{path}/pulls/{number}"), None)
            .await?;
        if after["head"]["sha"] == new_head {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(after["number"], before["number"]);
    assert_eq!(after["head"]["ref"], before["head"]["ref"]);
    assert_eq!(after["base"]["ref"], before["base"]["ref"]);
    assert_eq!(after["state"], "open");
    assert_eq!(after["head"]["sha"], new_head);

    context
        .request_success(
            Method::POST,
            &format!("{path}/branch_protections"),
            Some(json!({
                "branch_name":BRANCH, "rule_name":BRANCH, "enable_push":true,
                "enable_force_push":false, "enable_push_whitelist":false
            })),
        )
        .await?;
    let (status, _) = reword(&app, context, repo, new_head).await?;
    assert!(
        !status.is_success(),
        "protected branch rewrite must be rejected"
    );
    let unchanged: Value = context
        .request_json(Method::GET, &format!("{path}/pulls/{number}"), None)
        .await?;
    assert_eq!(unchanged["head"]["sha"], new_head);
    assert_eq!(unchanged["state"], "open");
    Ok(())
}

#[tokio::test]
#[ignore = "requires the CI-provided disposable Forgejo service and credentials"]
async fn forgejo_reword_preserves_pr_and_rejects_protected_push() -> Result<(), String> {
    let context = Context::connect_from_env().await?;
    let repo = unique_name("forge-mcp-reword")?;
    let created = context
        .request_success(
            Method::POST,
            "/api/v1/user/repos",
            Some(json!({"name":repo, "auto_init":true, "default_branch":"main", "private":true})),
        )
        .await;
    if let Err(error) = created {
        return combine_results(Err(error), vec![context.revoke_token().await]);
    }
    // Await a task so cleanup also runs when an assertion panics.
    let shared = Arc::new(context);
    let task_context = shared.clone();
    let task_repo = repo.clone();
    let result = tokio::spawn(async move { exercise(&task_context, &task_repo).await })
        .await
        .map_err(|e| format!("provider assertion failed: {e}"))
        .and_then(std::convert::identity);
    combine_results(
        result,
        vec![
            shared.delete_repository(&repo).await,
            shared.revoke_token().await,
        ],
    )
}
