//! Capture bounded provider evidence before choosing original-source semantics.
use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde_json::{Map, Value, json};

use super::support::forgejo::{Context, combine_results, unique_name};

// Copy only present keys: absence and explicit null must remain distinguishable.
fn fields(value: &Value, keys: &[&str]) -> Value {
    let mut result = Map::new();
    for key in keys {
        if let Some(value) = value.get(key) {
            result.insert((*key).into(), value.clone());
        }
    }
    Value::Object(result)
}

fn repository(value: &Value) -> Value {
    if value.is_null() {
        return Value::Null;
    }
    let mut result = fields(value, &["id", "name", "full_name"]);
    if let Some(owner) = value.get("owner") {
        result["owner"] = if owner.is_null() {
            Value::Null
        } else {
            fields(owner, &["id", "login", "username"])
        };
    }
    result
}

fn branch(value: &Value) -> Value {
    if value.is_null() {
        return Value::Null;
    }
    let mut result = fields(value, &["label", "ref", "sha", "repo_id"]);
    if let Some(repo) = value.get("repo") {
        result["repo"] = repository(repo);
    }
    result
}

fn pull(value: &Value) -> Value {
    let mut result = fields(value, &["number", "state", "merged"]);
    for key in ["head", "base"] {
        if let Some(value) = value.get(key) {
            result[key] = branch(value);
        }
    }
    result
}

async fn capture(context: &Context, base: &str, index: u64, phase: &str) -> Result<(), String> {
    let detail: Value = context
        .request_json(Method::GET, &format!("{base}/pulls/{index}"), None)
        .await?;
    let list: Vec<Value> = context
        .request_json(
            Method::GET,
            &format!("{base}/pulls?state=all&limit=50"),
            None,
        )
        .await?;
    let row = list
        .iter()
        .find(|row| row["number"] == index)
        .ok_or_else(|| format!("evidence listing omitted PR {index} during {phase}"))?;
    let evidence =
        json!({"version":context.version,"phase":phase,"detail":pull(&detail),"list":pull(row)});
    let output = serde_json::to_string(&evidence).map_err(|error| error.to_string())?;
    if output.len() > 32768 {
        return Err("allowlisted source evidence exceeded 32 KiB".into());
    }
    println!("SOURCE_IDENTITY_EVIDENCE {output}");
    Ok(())
}

async fn create_pull(
    context: &Context,
    source: &str,
    target: &str,
    head: &str,
) -> Result<u64, String> {
    context
        .request_success(
            Method::POST,
            &format!("{source}/branches"),
            Some(json!({"new_branch_name":head,"old_branch_name":"main"})),
        )
        .await?;
    context
        .request_success(
            Method::POST,
            &format!(
                "{source}/contents/{}.txt",
                urlencoding::encode(&head.replace('/', "-"))
            ),
            Some(json!({"branch":head,"content":"ZXZpZGVuY2UK","message":"Add source evidence"})),
        )
        .await?;
    let qualified = if source == target {
        head.to_string()
    } else {
        let owner = source
            .trim_start_matches("/api/v1/repos/")
            .split('/')
            .next()
            .ok_or_else(|| "source repository has no owner".to_string())?;
        format!("{owner}:{head}")
    };
    let pr: Value = context
        .request_json(
            Method::POST,
            &format!("{target}/pulls"),
            Some(json!({"base":"main","head":qualified,"title":"Source identity evidence"})),
        )
        .await?;
    let index = pr["number"]
        .as_u64()
        .ok_or_else(|| "created PR lacks number".to_string())?;
    println!(
        "SOURCE_IDENTITY_GROUND_TRUTH {}",
        json!({"index":index,"source":source,"target":target,"branch":head})
    );
    Ok(index)
}

async fn terminal(context: &Context, base: &str, index: u64, merge: bool) -> Result<(), String> {
    if !merge {
        context
            .request_success(
                Method::PATCH,
                &format!("{base}/pulls/{index}"),
                Some(json!({"state":"closed"})),
            )
            .await?;
        return Ok(());
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let pr: Value = context
                .request_json(Method::GET, &format!("{base}/pulls/{index}"), None)
                .await?;
            if pr["mergeable"] == true {
                return Ok::<_, String>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| format!("PR {index} mergeability timed out"))??;
    context
        .request_success(
            Method::POST,
            &format!("{base}/pulls/{index}/merge"),
            Some(json!({"do":"merge","delete_branch_after_merge":false})),
        )
        .await?;
    Ok(())
}

async fn delete_branch(context: &Context, source: &str, name: &str) -> Result<(), String> {
    let path = format!("{source}/branches/{}", urlencoding::encode(name));
    context.request_success(Method::DELETE, &path, None).await?;
    let (status, _) = context.request(Method::GET, &path, None).await?;
    if status != StatusCode::NOT_FOUND {
        return Err(format!("deleted source branch remained readable: {status}"));
    }
    Ok(())
}

async fn lifecycle(context: &Context, base: &str) -> Result<(), String> {
    for (name, merge) in [
        ("evidence/closed/Case+λ", false),
        ("evidence/merged/Case+λ", true),
    ] {
        let index = create_pull(context, base, base, name).await?;
        capture(context, base, index, "open").await?;
        terminal(context, base, index, merge).await?;
        capture(context, base, index, "terminal-retained-source").await?;
        delete_branch(context, base, name).await?;
        capture(context, base, index, "terminal-deleted-source").await?;
    }
    let index = create_pull(context, base, base, "evidence/open/Case+λ").await?;
    capture(context, base, index, "retained-open-control").await
}

#[tokio::test]
#[ignore = "runs only in the CI-provided disposable Forgejo lane"]
async fn forgejo_source_identity_evidence() -> Result<(), String> {
    let context = Context::connect_from_env().await?;
    let name = unique_name("forge-mcp-source")?;
    let organization = unique_name("source-org")?;
    let mut created = false;
    let mut org_created = false;
    let mut fork_created = false;
    let fork = format!("/api/v1/repos/{organization}/{name}");
    let base = format!("/api/v1/repos/{}/{name}", context.username);
    let primary = async {
        context
            .request_success(
                Method::POST,
                "/api/v1/user/repos",
                Some(json!({"auto_init":true,"default_branch":"main","name":name,"private":true})),
            )
            .await?;
        created = true;
        lifecycle(&context, &base).await?;
        context
            .request_success(
                Method::POST,
                "/api/v1/orgs",
                Some(json!({"username":organization,"visibility":"private"})),
            )
            .await?;
        org_created = true;
        context
            .request_success(
                Method::POST,
                &format!("{base}/forks"),
                Some(json!({"organization":organization})),
            )
            .await?;
        fork_created = true;
        let index = create_pull(&context, &fork, &base, "evidence/fork/Case+λ").await?;
        capture(&context, &base, index, "fork-open").await?;
        terminal(&context, &base, index, false).await?;
        capture(&context, &base, index, "fork-closed-retained-source").await?;
        delete_branch(&context, &fork, "evidence/fork/Case+λ").await?;
        capture(&context, &base, index, "fork-closed-deleted-source").await?;
        context.request_success(Method::DELETE, &fork, None).await?;
        fork_created = false;
        let (status, _) = context.request(Method::GET, &fork, None).await?;
        if status != StatusCode::NOT_FOUND {
            return Err("deleted fork remained readable".into());
        }
        capture(&context, &base, index, "fork-closed-deleted-repository").await
    }
    .await;
    let mut cleanup = Vec::new();
    if fork_created {
        cleanup.push(
            context
                .request_success(Method::DELETE, &fork, None)
                .await
                .map(|_| ()),
        );
    }
    if org_created {
        cleanup.push(
            context
                .request_success(
                    Method::DELETE,
                    &format!("/api/v1/orgs/{organization}"),
                    None,
                )
                .await
                .map(|_| ()),
        );
    }
    if created {
        cleanup.push(context.delete_repository(&name).await);
    }
    cleanup.push(context.revoke_token().await);
    combine_results(primary, cleanup)
}

#[test]
fn evidence_projection_preserves_absence_and_null_and_excludes_secrets() {
    let value = json!({"number":1,"state":"closed","body":"secret body","head":{
        "ref":"refs/pull/1/head","label":null,"repo":{"id":7,"name":"source",
        "clone_url":"https://user:secret@example.invalid/repo","owner":{"login":"ci","email":"secret"}}}});
    let projected = pull(&value);
    assert!(projected.get("base").is_none());
    assert!(projected["head"].get("sha").is_none());
    assert_eq!(projected["head"]["label"], Value::Null);
    assert_eq!(projected["head"]["repo"]["id"], 7);
    assert!(!projected.to_string().contains("secret"));
    assert_eq!(branch(&Value::Null), Value::Null);
    assert_eq!(repository(&json!({"owner":null}))["owner"], Value::Null);
}
