# Phase 3: HTTP Control Plane + MCP Shim — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the monolithic stdio MCP server into an HTTP control plane (axum) that holds credentials and enforces policy, and a lightweight MCP shim that agents spawn locally.

**Architecture:** The `server` crate becomes an axum HTTP server exposing a REST API at `/api/v1/`. The `transport` crate becomes a standalone MCP shim binary that translates MCP tool calls into HTTP requests to the control plane. Bearer tokens authenticate callers and map them to agent identities with per-agent policy configs. TOML config file at startup.

**Tech Stack:** axum, tower-http, utoipa + utoipa-scalar, toml, serde, clap, reqwest

---

## File Structure

### Modified

- **`domain/Cargo.toml`** — add `serde` dependency
- **`domain/src/lib.rs`** — add `Serialize` derives to response types for JSON serialization
- **`server/Cargo.toml`** — replace `transport` dependency with axum, tower-http, utoipa, utoipa-scalar, toml, serde, serde_json
- **`server/src/main.rs`** — rewrite: load TOML config, build axum router, start HTTP server
- **`transport/Cargo.toml`** — add reqwest, clap; keep rmcp
- **`transport/src/lib.rs`** — rewrite: MCP shim that makes HTTP requests to control plane

### Created

- **`server/src/auth.rs`** — bearer token extractor, token-to-agent resolution
- **`server/src/config.rs`** — TOML config types, parsing, validation
- **`server/src/handlers.rs`** — axum route handler functions for each REST endpoint
- **`server/src/api.rs`** — HTTP request/response types with serde + utoipa derives
- **`server/src/lib.rs`** — re-export modules, build router function

---

## Chunk 1: Domain Serialization + Server Config

### Task 1: Add Serialize to domain types

**Files:**
- Modify: `domain/Cargo.toml`
- Modify: `domain/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add a test to `domain/src/lib.rs` that serializes a `ChangeRequest` to JSON:

```rust
#[test]
fn change_request_serializes_to_json() {
    let cr = ChangeRequest {
        base_branch: "main".to_string(),
        body: "fix".to_string(),
        head_branch: "agent/fix".to_string(),
        index: 1,
        state: ChangeRequestState::Open,
        title: "Fix".to_string(),
        url: "https://example.com/pulls/1".to_string(),
    };
    let json = serde_json::to_value(&cr).expect("should serialize");
    assert_eq!(json["index"], 1);
    assert_eq!(json["state"], "Open");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p domain change_request_serializes_to_json`
Expected: FAIL — `Serialize` not derived on `ChangeRequest`

- [ ] **Step 3: Add serde dependency to domain**

In `domain/Cargo.toml`, add:

```toml
serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0.149"
```

Note: `serde_json` is only needed for the test. Add it under `[dev-dependencies]`:

```toml
[dev-dependencies]
serde_json = "1.0.149"
```

- [ ] **Step 4: Add Serialize derives to domain types**

In `domain/src/lib.rs`, add `use serde::Serialize;` and derive `Serialize` on these types (alphabetical):

- `ChangeRequest`
- `ChangeRequestState`
- `CommitPatchResponse`
- `ForgeKind`
- `OpenChangeRequestResponse`
- `ReadRepositoryFileResponse`
- `RepositoryRef`

Do NOT add `Serialize` to request types or `AgentIdentity` — those are inbound, not outbound.

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p domain change_request_serializes_to_json`
Expected: PASS

- [ ] **Step 6: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 7: Commit**

```bash
git add domain/Cargo.toml domain/src/lib.rs
git commit -m "domain: derive Serialize on response types for JSON serialization"
```

---

### Task 2: Server config module

**Files:**
- Create: `server/src/config.rs`
- Modify: `server/Cargo.toml`

- [ ] **Step 1: Add dependencies to server/Cargo.toml**

Replace the current dependencies with:

```toml
[dependencies]
audit = { version = "0.1.0", path = "../audit" }
domain = { version = "0.1.0", path = "../domain" }
forge = { version = "0.1.0", path = "../forge" }
orchestrator = { version = "0.1.0", path = "../orchestrator" }
serde = { version = "1.0.228", features = ["derive"] }
tokio = { version = "1.50.0", features = ["macros", "net", "rt-multi-thread"] }
toml = "0.8"
```

Remove the `transport` dependency. The `axum`, `tower-http`, `utoipa`, `utoipa-scalar`, and `serde_json` dependencies will be added in later tasks when needed.

- [ ] **Step 2: Write the failing tests for config parsing**

Create `server/src/config.rs` with test stubs first:

```rust
//! TOML configuration for the HTTP control plane.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub agents: Vec<AgentConfig>,
    pub forge: ForgeSection,
    pub server: ListenConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListenConfig {
    #[serde(default)]
    pub enable_docs: bool,
    pub listen: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ForgeSection {
    pub forgejo: ForgejoSection,
}

#[derive(Clone, Deserialize)]
pub struct ForgejoSection {
    pub base_url: String,
    pub token: String,
}

impl std::fmt::Debug for ForgejoSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgejoSection")
            .field("base_url", &self.base_url)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub policy: AgentPolicyConfig,
    pub session_id: String,
    pub token: String,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentConfig")
            .field("agent_id", &self.agent_id)
            .field("policy", &self.policy)
            .field("session_id", &self.session_id)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AgentPolicyConfig {
    #[serde(default)]
    pub allowed_repos: Vec<String>,
    pub branch_prefix: Option<String>,
    #[serde(default)]
    pub protected_paths: Vec<String>,
}

impl AgentPolicyConfig {
    /// Converts to the domain policy config type.
    #[must_use]
    pub fn to_policy_config(&self) -> domain::policy::PolicyConfig {
        domain::policy::PolicyConfig {
            branch_prefix: self.branch_prefix.clone(),
            protected_paths: self.protected_paths.clone(),
        }
    }

    /// Returns whether the agent is allowed to access the given `owner/repo`.
    #[must_use]
    pub fn is_repo_allowed(&self, owner: &str, repo: &str) -> bool {
        if self.allowed_repos.is_empty() {
            return true; // empty list = unrestricted (backwards compat)
        }
        let full = format!("{owner}/{repo}");
        self.allowed_repos.iter().any(|r| r == &full)
    }
}

/// Parses a TOML configuration string into a `ServerConfig`.
///
/// # Errors
///
/// Returns an error if the TOML is malformed or missing required fields.
pub fn parse_config(toml_str: &str) -> Result<ServerConfig, toml::de::Error> {
    toml::from_str(toml_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
[server]
listen = "0.0.0.0:8443"

[forge.forgejo]
base_url = "https://forge.example"
token = "forgejo-api-token"

[[agents]]
token = "bearer-token-for-codex"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["org/repo", "org/other-repo"]
branch_prefix = "agent/codex/"
protected_paths = [".forgejo/", ".github/"]

[[agents]]
token = "bearer-token-for-claude"
agent_id = "claude"
session_id = "default"

[agents.policy]
allowed_repos = ["org/repo"]
branch_prefix = "agent/claude/"
protected_paths = [".forgejo/", ".github/"]
"#;

    #[test]
    fn parses_valid_config() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert_eq!(config.server.listen, "0.0.0.0:8443");
        assert_eq!(config.forge.forgejo.base_url, "https://forge.example");
        assert_eq!(config.forge.forgejo.token, "forgejo-api-token");
        assert_eq!(config.agents.len(), 2);
        assert_eq!(config.agents[0].agent_id, "codex");
        assert_eq!(config.agents[0].token, "bearer-token-for-codex");
        assert_eq!(
            config.agents[0].policy.branch_prefix.as_deref(),
            Some("agent/codex/")
        );
        assert_eq!(config.agents[1].agent_id, "claude");
    }

    #[test]
    fn converts_policy_to_domain_type() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        let policy = config.agents[0].policy.to_policy_config();
        assert_eq!(policy.branch_prefix.as_deref(), Some("agent/codex/"));
        assert_eq!(policy.protected_paths, vec![".forgejo/", ".github/"]);
    }

    #[test]
    fn repo_allowlist_enforced() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert!(config.agents[0].policy.is_repo_allowed("org", "repo"));
        assert!(config.agents[0].policy.is_repo_allowed("org", "other-repo"));
        assert!(!config.agents[0].policy.is_repo_allowed("org", "secret-repo"));
    }

    #[test]
    fn empty_allowlist_permits_all() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("any", "repo"));
    }

    #[test]
    fn rejects_missing_server_section() {
        let toml_str = r#"
[forge.forgejo]
base_url = "https://forge.example"
token = "tok"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        assert!(parse_config(toml_str).is_err());
    }

    #[test]
    fn rejects_missing_forge_token() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[forge.forgejo]
base_url = "https://forge.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        assert!(parse_config(toml_str).is_err());
    }

    #[test]
    fn debug_redacts_tokens() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        let debug = format!("{config:?}");
        assert!(!debug.contains("forgejo-api-token"));
        assert!(!debug.contains("bearer-token-for-codex"));
        assert!(!debug.contains("bearer-token-for-claude"));
        assert!(debug.contains("[REDACTED]"));
    }
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p server config`
Expected: PASS (all tests should pass since the implementation is included)

- [ ] **Step 4: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`

Note: `main.rs` may have compile errors since we removed the `transport` dependency. Temporarily comment out the `main.rs` body or add a `todo!()` placeholder:

```rust
//! Binary entry point for the HTTP control plane.

mod config;

fn main() {
    todo!("HTTP server wiring — implemented in Task 6")
}
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add server/Cargo.toml server/src/config.rs server/src/main.rs
git commit -m "server: add TOML config parsing module

Parses server listen address, forge credentials, and per-agent
token-to-policy mappings from a TOML config file. Tokens are
redacted in Debug output."
```

---

### Task 3: Bearer token auth extractor

**Files:**
- Create: `server/src/auth.rs`
- Modify: `server/Cargo.toml`

This task adds axum as a dependency and implements the bearer token extractor.

- [ ] **Step 1: Add axum and serde_json to server/Cargo.toml**

```toml
axum = "0.8"
serde_json = "1.0.149"
```

(Add alphabetically to `[dependencies]`.)

- [ ] **Step 2: Write auth.rs with tests**

Create `server/src/auth.rs`:

```rust
//! Bearer token authentication for the HTTP control plane.

use std::collections::HashMap;

use domain::{AgentIdentity, policy::PolicyConfig};

/// Resolved agent identity and policy from a bearer token.
#[derive(Clone, Debug)]
pub struct ResolvedAgent {
    pub identity: AgentIdentity,
    pub policy: PolicyConfig,
    pub policy_config: crate::config::AgentPolicyConfig,
}

/// Registry mapping bearer tokens to agent identities and policies.
#[derive(Clone, Debug)]
pub struct AgentRegistry {
    agents: HashMap<String, ResolvedAgent>,
}

impl AgentRegistry {
    /// Creates a registry from a list of agent configs.
    #[must_use]
    pub fn from_configs(configs: &[crate::config::AgentConfig]) -> Self {
        let mut agents = HashMap::new();
        for agent in configs {
            agents.insert(
                agent.token.clone(),
                ResolvedAgent {
                    identity: AgentIdentity {
                        agent_id: agent.agent_id.clone(),
                        session_id: agent.session_id.clone(),
                    },
                    policy: agent.policy.to_policy_config(),
                    policy_config: agent.policy.clone(),
                },
            );
        }
        Self { agents }
    }

    /// Resolves a bearer token to an agent identity and policy.
    #[must_use]
    pub fn resolve(&self, token: &str) -> Option<&ResolvedAgent> {
        self.agents.get(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, AgentPolicyConfig};

    fn test_configs() -> Vec<AgentConfig> {
        vec![AgentConfig {
            agent_id: "codex".to_string(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["org/repo".to_string()],
                branch_prefix: Some("agent/codex/".to_string()),
                protected_paths: vec![".github/".to_string()],
            },
            session_id: "default".to_string(),
            token: "test-token-123".to_string(),
        }]
    }

    #[test]
    fn resolves_valid_token() {
        let registry = AgentRegistry::from_configs(&test_configs());
        let agent = registry.resolve("test-token-123").expect("should resolve");
        assert_eq!(agent.identity.agent_id, "codex");
        assert_eq!(agent.identity.session_id, "default");
        assert_eq!(
            agent.policy.branch_prefix.as_deref(),
            Some("agent/codex/")
        );
    }

    #[test]
    fn returns_none_for_invalid_token() {
        let registry = AgentRegistry::from_configs(&test_configs());
        assert!(registry.resolve("wrong-token").is_none());
    }

    #[test]
    fn returns_none_for_empty_token() {
        let registry = AgentRegistry::from_configs(&test_configs());
        assert!(registry.resolve("").is_none());
    }
}
```

- [ ] **Step 3: Add `mod auth;` to main.rs**

Update `server/src/main.rs`:

```rust
//! Binary entry point for the HTTP control plane.

mod auth;
mod config;

fn main() {
    todo!("HTTP server wiring — implemented in Task 6")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p server auth`
Expected: PASS

- [ ] **Step 5: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add server/Cargo.toml server/src/auth.rs server/src/main.rs
git commit -m "server: add bearer token agent registry

Maps bearer tokens to AgentIdentity + PolicyConfig. Tokens are
loaded from the TOML config at startup."
```

---

## Chunk 2: HTTP API Types + Route Handlers

### Task 4: HTTP API request/response types

**Files:**
- Create: `server/src/api.rs`

- [ ] **Step 1: Write api.rs with request/response types and tests**

Create `server/src/api.rs`:

```rust
//! HTTP API request and response types.

use serde::{Deserialize, Serialize};

/// POST /api/v1/repos/{owner}/{repo}/patches
#[derive(Debug, Deserialize)]
pub struct CommitPatchBody {
    pub base_branch: String,
    pub commit_message: String,
    pub new_branch: String,
    pub patch: String,
}

/// Response for POST /patches
#[derive(Debug, Serialize)]
pub struct CommitPatchResult {
    pub branch: String,
    pub commit_sha: String,
}

/// POST /api/v1/repos/{owner}/{repo}/pulls
#[derive(Debug, Deserialize)]
pub struct OpenPullBody {
    pub base_branch: String,
    pub body: String,
    pub head_branch: String,
    pub title: String,
}

/// GET /api/v1/repos/{owner}/{repo}/contents/{path}
#[derive(Debug, Deserialize)]
pub struct ContentsQuery {
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
}

/// Response for GET /contents/{path}
#[derive(Debug, Serialize)]
pub struct ContentsResult {
    pub content: String,
    pub git_ref: Option<String>,
    pub path: String,
}

/// GET /api/v1/repos/{owner}/{repo}/pulls
#[derive(Debug, Deserialize)]
pub struct ListPullsQuery {
    pub state: Option<String>,
}

/// Shared path parameters for repo-scoped endpoints.
#[derive(Debug, Deserialize)]
pub struct RepoPath {
    pub owner: String,
    pub repo: String,
}

/// Path parameters for pull request endpoints.
#[derive(Debug, Deserialize)]
pub struct PullPath {
    pub index: u64,
    pub owner: String,
    pub repo: String,
}

/// Path parameters for contents endpoint. The `path` field captures
/// the remainder of the URL path after `/contents/`.
#[derive(Debug, Deserialize)]
pub struct ContentsPath {
    pub owner: String,
    pub path: String,
    pub repo: String,
}

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_patch_body_deserializes() {
        let json = serde_json::json!({
            "base_branch": "main",
            "commit_message": "fix typo",
            "new_branch": "agent/fix",
            "patch": "diff..."
        });
        let body: CommitPatchBody =
            serde_json::from_value(json).expect("should deserialize");
        assert_eq!(body.base_branch, "main");
        assert_eq!(body.new_branch, "agent/fix");
    }

    #[test]
    fn contents_query_deserializes_with_ref() {
        let json = serde_json::json!({"ref": "main"});
        let query: ContentsQuery =
            serde_json::from_value(json).expect("should deserialize");
        assert_eq!(query.git_ref.as_deref(), Some("main"));
    }

    #[test]
    fn contents_query_deserializes_without_ref() {
        let json = serde_json::json!({});
        let query: ContentsQuery =
            serde_json::from_value(json).expect("should deserialize");
        assert!(query.git_ref.is_none());
    }

    #[test]
    fn error_body_serializes() {
        let body = ErrorBody {
            error: "not found".to_string(),
        };
        let json = serde_json::to_value(&body).expect("should serialize");
        assert_eq!(json["error"], "not found");
    }
}
```

- [ ] **Step 2: Add `mod api;` to main.rs**

- [ ] **Step 3: Run tests**

Run: `cargo test -p server api`
Expected: PASS

- [ ] **Step 4: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add server/src/api.rs server/src/main.rs
git commit -m "server: add HTTP API request/response types"
```

---

### Task 5: Route handlers

**Files:**
- Create: `server/src/handlers.rs`
- Create: `server/src/lib.rs`
- Modify: `server/Cargo.toml`

- [ ] **Step 1: Write handler functions**

Create `server/src/handlers.rs`. Each handler extracts the bearer token, resolves the agent, builds the domain request, calls the orchestrator, and returns JSON.

The handlers are generic over the orchestrator types, but for simplicity we use `dyn` trait objects in the app state:

```rust
//! Axum route handlers for the REST API.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use domain::{
    AgentIdentity, CommitPatchRequest, ForgeKind, GetChangeRequestRequest,
    ListChangeRequestsRequest, OpenChangeRequestRequest, ReadRepositoryFileRequest,
    RepositoryReadService, RepositoryRef, RepositoryWriteService, ServiceError,
};

use crate::api::{
    CommitPatchBody, CommitPatchResult, ContentsPath, ContentsQuery, ContentsResult, ErrorBody,
    ListPullsQuery, OpenPullBody, PullPath, RepoPath,
};
use crate::auth::AgentRegistry;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub agent_registry: AgentRegistry,
    pub forgejo_base_url: String,
    pub read_service: Arc<dyn RepositoryReadService>,
    pub write_service: Arc<dyn RepositoryWriteService>,
}

/// Extracts the bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Maps a `ServiceError` to an HTTP status code and error body.
fn map_service_error(err: ServiceError) -> (StatusCode, Json<ErrorBody>) {
    let (status, message) = match &err {
        ServiceError::Audit(_) | ServiceError::GitExec(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
        ServiceError::PolicyDenied { .. } | ServiceError::Validation(_) => {
            (StatusCode::BAD_REQUEST, err.to_string())
        }
        ServiceError::Upstream(_) => (StatusCode::BAD_GATEWAY, err.to_string()),
    };
    (status, Json(ErrorBody { error: message }))
}

/// Resolves bearer token to agent identity or returns 401.
/// Also checks repository authorization (403 if not allowed).
fn resolve_agent(
    headers: &HeaderMap,
    registry: &AgentRegistry,
    owner: &str,
    repo: &str,
) -> Result<(AgentIdentity, domain::policy::PolicyConfig), (StatusCode, Json<ErrorBody>)> {
    let token = extract_bearer_token(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing or invalid Authorization header".to_string(),
            }),
        )
    })?;
    let agent = registry.resolve(token).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "invalid bearer token".to_string(),
            }),
        )
    })?;

    // Check repository authorization
    if !agent.policy_config.is_repo_allowed(owner, repo) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorBody {
                error: format!("agent '{}' is not authorized for repository '{owner}/{repo}'", agent.identity.agent_id),
            }),
        ));
    }

    Ok((agent.identity.clone(), agent.policy.clone()))
}

fn repo_ref(owner: &str, repo: &str, base_url: &str) -> RepositoryRef {
    RepositoryRef {
        forge: ForgeKind::Forgejo,
        host: base_url.to_string(),
        name: repo.to_string(),
        owner: owner.to_string(),
    }
}

/// GET /api/v1/repos/{owner}/{repo}/contents/{path}
pub async fn get_contents(
    State(state): State<AppState>,
    Path(path): Path<ContentsPath>,
    Query(query): Query<ContentsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (identity, _policy) = resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let result = state
        .read_service
        .read_repository_file(ReadRepositoryFileRequest {
            agent: identity,
            git_ref: query.git_ref.clone(),
            path: path.path.clone(),
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(ContentsResult {
        content: result.content,
        git_ref: result.git_ref,
        path: result.path,
    }))
}

/// POST /api/v1/repos/{owner}/{repo}/patches
pub async fn post_patches(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    headers: HeaderMap,
    Json(body): Json<CommitPatchBody>,
) -> impl IntoResponse {
    let (identity, _policy) = resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let result = state
        .write_service
        .commit_patch(CommitPatchRequest {
            agent: identity,
            base_branch: body.base_branch,
            commit_message: body.commit_message,
            new_branch: body.new_branch,
            patch: body.patch,
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>((
        StatusCode::CREATED,
        Json(CommitPatchResult {
            branch: result.branch,
            commit_sha: result.commit_sha,
        }),
    ))
}

/// POST /api/v1/repos/{owner}/{repo}/pulls
pub async fn post_pulls(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    headers: HeaderMap,
    Json(body): Json<OpenPullBody>,
) -> impl IntoResponse {
    let (identity, _policy) = resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let result = state
        .write_service
        .open_change_request(OpenChangeRequestRequest {
            agent: identity,
            base_branch: body.base_branch,
            body: body.body,
            head_branch: body.head_branch,
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
            title: body.title,
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>((
        StatusCode::CREATED,
        Json(serde_json::to_value(&result.change_request).expect("serializable")),
    ))
}

/// GET /api/v1/repos/{owner}/{repo}/pulls
pub async fn list_pulls(
    State(state): State<AppState>,
    Path(path): Path<RepoPath>,
    Query(query): Query<ListPullsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (identity, _policy) = resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let state_filter = query.state.as_deref().map(|s| match s {
        "closed" => domain::ChangeRequestState::Closed,
        "merged" => domain::ChangeRequestState::Merged,
        _ => domain::ChangeRequestState::Open,
    });

    let result = state
        .read_service
        .list_change_requests(ListChangeRequestsRequest {
            agent: identity,
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
            state: state_filter,
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(
        serde_json::to_value(&result).expect("serializable"),
    ))
}

/// GET /api/v1/repos/{owner}/{repo}/pulls/{index}
pub async fn get_pull(
    State(state): State<AppState>,
    Path(path): Path<PullPath>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (identity, _policy) = resolve_agent(&headers, &state.agent_registry, &path.owner, &path.repo)?;

    let result = state
        .read_service
        .get_change_request(GetChangeRequestRequest {
            agent: identity,
            index: path.index,
            repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(
        serde_json::to_value(&result).expect("serializable"),
    ))
}
```

**Important:** This task requires `list_change_requests` and `get_change_request` methods on `RepositoryReadService`. These don't exist yet. We need to add them to the domain trait first. See Step 2.

- [ ] **Step 2: Extend RepositoryReadService with list/get change request methods**

In `domain/src/lib.rs`, add to `RepositoryReadService`:

```rust
async fn list_change_requests(
    &self,
    request: ListChangeRequestsRequest,
) -> Result<Vec<ChangeRequest>, ServiceError>;

async fn get_change_request(
    &self,
    request: GetChangeRequestRequest,
) -> Result<ChangeRequest, ServiceError>;
```

Also add `Serialize` to `ChangeRequest` and `ChangeRequestState` if not already done in Task 1.

Then implement these in `orchestrator/src/lib.rs` on `ReadOrchestrator`:

```rust
async fn list_change_requests(
    &self,
    request: ListChangeRequestsRequest,
) -> Result<Vec<ChangeRequest>, ServiceError> {
    self.audit_sink
        .record(AuditRecord {
            agent: request.agent,
            action: "list_change_requests".to_string(),
            repository: request.repository.clone(),
            target: request
                .state
                .as_ref()
                .map_or("all".to_string(), |s| format!("{s:?}")),
        })
        .await
        .map_err(|e| ServiceError::Audit(e.to_string()))?;

    self.adapter
        .list_change_requests(&request.repository, request.state.as_ref())
        .await
        .map_err(|e| ServiceError::Upstream(e.to_string()))
}

async fn get_change_request(
    &self,
    request: GetChangeRequestRequest,
) -> Result<ChangeRequest, ServiceError> {
    self.audit_sink
        .record(AuditRecord {
            agent: request.agent,
            action: "get_change_request".to_string(),
            repository: request.repository.clone(),
            target: request.index.to_string(),
        })
        .await
        .map_err(|e| ServiceError::Audit(e.to_string()))?;

    self.adapter
        .get_change_request(&request.repository, request.index)
        .await
        .map_err(|e| ServiceError::Upstream(e.to_string()))
}
```

Update any existing fake implementations in test code (`transport/src/lib.rs` tests, `orchestrator/src/lib.rs` tests) to include the new trait methods.

- [ ] **Step 3: Create server/src/lib.rs with router builder**

Create `server/src/lib.rs`:

```rust
//! HTTP control plane for forge-mcp.

pub mod api;
pub mod auth;
pub mod config;
pub mod handlers;

use axum::{Router, routing::get, routing::post};
use handlers::AppState;

/// Builds the axum router with all API routes.
/// When `enable_docs` is true, serves Scalar UI at `/api/v1/docs`.
#[must_use]
pub fn build_router(state: AppState, enable_docs: bool) -> Router {
    let mut router = Router::new()
        .route(
            "/api/v1/repos/{owner}/{repo}/contents/{*path}",
            get(handlers::get_contents),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/patches",
            post(handlers::post_patches),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls",
            get(handlers::list_pulls).post(handlers::post_pulls),
        )
        .route(
            "/api/v1/repos/{owner}/{repo}/pulls/{index}",
            get(handlers::get_pull),
        );

    if enable_docs {
        router = add_docs_routes(router);
    }

    router.with_state(state)
}
```

Note: Use `{*path}` (wildcard) for the contents path to capture nested paths like `src/main.rs`.

- [ ] **Step 4: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 5: Commit domain trait extension separately**

```bash
git add domain/src/lib.rs orchestrator/src/lib.rs transport/src/lib.rs
git commit -m "domain: add list_change_requests and get_change_request to RepositoryReadService

Extends the read service trait with change request listing and
retrieval. Implements in ReadOrchestrator with audit recording."
```

- [ ] **Step 6: Commit handler + lib + api**

```bash
git add server/src/handlers.rs server/src/lib.rs server/src/main.rs server/Cargo.toml
git commit -m "server: add axum route handlers and router builder

Five REST endpoints: GET /contents/{path}, POST /patches,
POST /pulls, GET /pulls, GET /pulls/{index}. Bearer token
auth resolves agent identity before calling orchestrator."
```

---

### Task 6: Handler tests

**Files:**
- Modify: `server/src/handlers.rs`

- [ ] **Step 1: Write handler integration tests using axum test utilities**

Add tests at the bottom of `server/src/handlers.rs`. Use `axum::body::Body` and `tower::ServiceExt` to send requests directly to the router without binding a port:

```rust
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use domain::{
        ChangeRequest, ChangeRequestState, CommitPatchResponse, GetChangeRequestRequest,
        ListChangeRequestsRequest, OpenChangeRequestResponse, ReadRepositoryFileResponse,
        ServiceError,
    };
    use tower::ServiceExt;

    use crate::auth::AgentRegistry;
    use crate::config::AgentPolicyConfig;

    use super::*;

    struct FakeReadService;

    #[async_trait::async_trait]
    impl RepositoryReadService for FakeReadService {
        async fn read_repository_file(
            &self,
            request: ReadRepositoryFileRequest,
        ) -> Result<ReadRepositoryFileResponse, ServiceError> {
            Ok(ReadRepositoryFileResponse {
                content: "file-content".to_string(),
                git_ref: request.git_ref,
                path: request.path,
                repository: request.repository,
            })
        }

        async fn list_change_requests(
            &self,
            _request: ListChangeRequestsRequest,
        ) -> Result<Vec<ChangeRequest>, ServiceError> {
            Ok(vec![])
        }

        async fn get_change_request(
            &self,
            request: GetChangeRequestRequest,
        ) -> Result<ChangeRequest, ServiceError> {
            Ok(ChangeRequest {
                base_branch: "main".to_string(),
                body: "body".to_string(),
                head_branch: "agent/fix".to_string(),
                index: request.index,
                state: ChangeRequestState::Open,
                title: "Fix".to_string(),
                url: "https://example.com/pulls/1".to_string(),
            })
        }
    }

    struct FakeWriteService;

    #[async_trait::async_trait]
    impl RepositoryWriteService for FakeWriteService {
        async fn commit_patch(
            &self,
            _request: CommitPatchRequest,
        ) -> Result<CommitPatchResponse, ServiceError> {
            Ok(CommitPatchResponse {
                branch: "agent/fix".to_string(),
                commit_sha: "abc123".to_string(),
                repository: _request.repository,
            })
        }

        async fn open_change_request(
            &self,
            _request: OpenChangeRequestRequest,
        ) -> Result<OpenChangeRequestResponse, ServiceError> {
            Ok(OpenChangeRequestResponse {
                change_request: ChangeRequest {
                    base_branch: "main".to_string(),
                    body: "body".to_string(),
                    head_branch: "agent/fix".to_string(),
                    index: 1,
                    state: ChangeRequestState::Open,
                    title: "Fix".to_string(),
                    url: "https://example.com/pulls/1".to_string(),
                },
                repository: _request.repository,
            })
        }
    }

    fn test_state() -> AppState {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["org/repo".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];
        AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            forgejo_base_url: "https://forge.example".to_string(),
            read_service: Arc::new(FakeReadService),
            write_service: Arc::new(FakeWriteService),
        }
    }

    #[tokio::test]
    async fn get_contents_returns_file() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/org/repo/contents/README.md")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["content"], "file-content");
        assert_eq!(json["path"], "README.md");
    }

    #[tokio::test]
    async fn returns_401_without_token() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/org/repo/contents/README.md")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn returns_403_for_unauthorized_repo() {
        let configs = vec![crate::config::AgentConfig {
            agent_id: "codex".to_string(),
            policy: AgentPolicyConfig {
                allowed_repos: vec!["org/allowed-repo".to_string()],
                branch_prefix: Some("agent/".to_string()),
                protected_paths: vec![],
            },
            session_id: "default".to_string(),
            token: "test-token".to_string(),
        }];
        let state = AppState {
            agent_registry: AgentRegistry::from_configs(&configs),
            forgejo_base_url: "https://forge.example".to_string(),
            read_service: Arc::new(FakeReadService),
            write_service: Arc::new(FakeWriteService),
        };
        let app = crate::build_router(state, false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/org/secret-repo/contents/README.md")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_401_with_bad_token() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/org/repo/contents/README.md")
                    .header("authorization", "Bearer wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_patches_returns_201() {
        let app = crate::build_router(test_state(), false);
        let body = serde_json::json!({
            "base_branch": "main",
            "commit_message": "fix",
            "new_branch": "agent/fix",
            "patch": "diff..."
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/repos/org/repo/patches")
                    .header("authorization", "Bearer test-token")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["branch"], "agent/fix");
        assert_eq!(json["commit_sha"], "abc123");
    }

    #[tokio::test]
    async fn get_pull_returns_change_request() {
        let app = crate::build_router(test_state(), false);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/repos/org/repo/pulls/1")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["index"], 1);
    }
}
```

- [ ] **Step 2: Add tower to dev-dependencies**

In `server/Cargo.toml`:

```toml
[dev-dependencies]
async-trait = "0.1.89"
tower = { version = "0.5", features = ["util"] }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p server handlers`
Expected: PASS

- [ ] **Step 4: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add server/src/handlers.rs server/Cargo.toml
git commit -m "server: add handler integration tests

Tests GET /contents, POST /patches, GET /pulls/{index} with bearer
token auth. Verifies 401 for missing and invalid tokens."
```

---

## Chunk 3: Server Wiring + MCP Shim

### Task 7: Wire up axum server in main.rs

**Files:**
- Modify: `server/src/main.rs`

- [ ] **Step 1: Rewrite main.rs to load config and start axum**

```rust
//! Binary entry point for the HTTP control plane.

use std::sync::Arc;

use audit::InMemoryAuditSink;
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};

mod api;
mod auth;
mod config;
mod handlers;

use auth::AgentRegistry;
use config::parse_config;
use handlers::AppState;

fn server_version() -> String {
    format!("{}+{}", env!("CARGO_PKG_VERSION"), env!("GIT_COMMIT_SHORT"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "forge-mcp.toml".to_string());

    let config_str = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read config file {config_path}: {e}"));

    let config = parse_config(&config_str)
        .unwrap_or_else(|e| panic!("failed to parse config file {config_path}: {e}"));

    eprintln!(
        "forge-mcp {} — listening on {}",
        server_version(),
        config.server.listen
    );

    let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
        base_url: config.forge.forgejo.base_url.clone(),
        token: Some(config.forge.forgejo.token.clone()),
    }));
    let audit_sink = Arc::new(InMemoryAuditSink::new());

    let read_service = Arc::new(ReadOrchestrator::new(
        Arc::clone(&adapter),
        Arc::clone(&audit_sink),
    ));

    // Use default policy for the write service — per-agent policy is
    // enforced by the handlers through the agent registry, not here.
    // The write orchestrator's policy config is a fallback.
    let write_service = Arc::new(WriteOrchestrator::new(
        adapter,
        audit_sink,
        Some(config.forge.forgejo.token.clone()),
        domain::policy::PolicyConfig::default(),
    ));

    let agent_registry = AgentRegistry::from_configs(&config.agents);
    let state = AppState {
        agent_registry,
        forgejo_base_url: config.forge.forgejo.base_url,
        read_service,
        write_service,
    };

    let app = forge_mcp_server::build_router(state);

    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    eprintln!("forge-mcp ready");
    axum::serve(listener, app).await?;

    Ok(())
}
```

**Wait** — `main.rs` uses both `mod` declarations and `forge_mcp_server::build_router`. This won't work: you can't have modules in both a `main.rs` binary and a `lib.rs` library simultaneously sharing the same source files. The solution: move all modules into `lib.rs` and only have the binary logic in `main.rs`.

Revised approach:
- `server/src/lib.rs` exports all modules and `build_router`
- `server/src/main.rs` only contains the `main` function, importing from the library crate

Update `server/src/main.rs`:

```rust
//! Binary entry point for the HTTP control plane.

use std::sync::Arc;

use audit::InMemoryAuditSink;
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use server::{auth::AgentRegistry, build_router, config::parse_config, handlers::AppState};

fn server_version() -> String {
    format!("{}+{}", env!("CARGO_PKG_VERSION"), env!("GIT_COMMIT_SHORT"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "forge-mcp.toml".to_string());

    let config_str = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read config file {config_path}: {e}"));

    let config = parse_config(&config_str)
        .unwrap_or_else(|e| panic!("failed to parse config file {config_path}: {e}"));

    eprintln!(
        "forge-mcp {} — listening on {}",
        server_version(),
        config.server.listen
    );

    let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
        base_url: config.forge.forgejo.base_url.clone(),
        token: Some(config.forge.forgejo.token.clone()),
    }));
    let audit_sink = Arc::new(InMemoryAuditSink::new());

    let read_service = Arc::new(ReadOrchestrator::new(
        Arc::clone(&adapter),
        Arc::clone(&audit_sink),
    ));

    let write_service = Arc::new(WriteOrchestrator::new(
        adapter,
        audit_sink,
        Some(config.forge.forgejo.token.clone()),
        domain::policy::PolicyConfig::default(),
    ));

    let agent_registry = AgentRegistry::from_configs(&config.agents);
    let state = AppState {
        agent_registry,
        forgejo_base_url: config.forge.forgejo.base_url,
        read_service,
        write_service,
    };

    let app = build_router(state, config.server.enable_docs);

    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    eprintln!("forge-mcp ready");
    axum::serve(listener, app).await?;

    Ok(())
}
```

- [ ] **Step 2: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 3: Commit**

```bash
git add server/src/main.rs server/src/lib.rs
git commit -m "server: wire up axum HTTP server with TOML config

Loads config from file path (CLI arg or 'forge-mcp.toml' default),
builds agent registry, starts axum on configured listen address."
```

---

### Task 8: OpenAPI docs with utoipa + Scalar (optional in production)

**Files:**
- Modify: `server/Cargo.toml`
- Modify: `server/src/lib.rs`
- Modify: `server/src/config.rs`
- Modify: `server/src/api.rs`
- Modify: `server/src/handlers.rs`

Note: The Scalar UI should be gated behind a config flag (e.g. `[server] enable_docs = true`) so production deployments can disable it. Add an `enable_docs` field to `ListenConfig` (defaulting to `false`).

- [ ] **Step 1: Add utoipa and utoipa-scalar to server/Cargo.toml**

```toml
utoipa = { version = "5", features = ["axum_extras"] }
utoipa-scalar = { version = "0.2", features = ["axum"] }
```

- [ ] **Step 2: Add utoipa derives to API types in api.rs**

Add `use utoipa::ToSchema;` and derive `ToSchema` on all request/response types:

- `CommitPatchBody`
- `CommitPatchResult`
- `ContentsQuery`
- `ContentsResult`
- `ErrorBody`
- `ListPullsQuery`
- `OpenPullBody`

- [ ] **Step 3: Add utoipa path annotations to handlers**

Add `#[utoipa::path(...)]` annotations above each handler function. Example for `get_contents`:

```rust
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/contents/{path}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("path" = String, Path, description = "File path"),
        ("ref" = Option<String>, Query, description = "Git ref"),
    ),
    responses(
        (status = 200, description = "File contents", body = ContentsResult),
        (status = 401, description = "Unauthorized", body = ErrorBody),
    ),
    security(("bearer" = []))
)]
```

Add similar annotations for all five handlers.

- [ ] **Step 4: Add OpenAPI doc and Scalar route in lib.rs**

```rust
use utoipa::OpenApi;
use utoipa_scalar::{Scalar, Servable};

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::get_contents,
        handlers::get_pull,
        handlers::list_pulls,
        handlers::post_patches,
        handlers::post_pulls,
    ),
    components(schemas(
        api::CommitPatchBody,
        api::CommitPatchResult,
        api::ContentsResult,
        api::ErrorBody,
        api::OpenPullBody,
    )),
    modifiers(&SecurityAddon),
)]
struct ApiDoc;

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .build(),
            ),
        );
    }
}
```

Add an `add_docs_routes` function in `lib.rs` (called conditionally from `build_router`):

```rust
fn add_docs_routes(router: Router<AppState>) -> Router<AppState> {
    router.route("/api/v1/docs", Scalar::with_url("/api/v1/docs", ApiDoc::openapi()))
}
```

- [ ] **Step 5: Add test that docs route is absent when disabled**

```rust
#[tokio::test]
async fn docs_route_absent_when_disabled() {
    let app = crate::build_router(test_state(), false);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/docs")
                .header("authorization", "Bearer test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 6: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 7: Commit**

```bash
git add server/Cargo.toml server/src/api.rs server/src/config.rs server/src/handlers.rs server/src/lib.rs
git commit -m "server: add OpenAPI docs with Scalar UI, gated by config

Annotates all endpoints with utoipa path metadata. Serves interactive
API documentation via Scalar at /api/v1/docs when enable_docs is true
in the server config section. Disabled by default."
```

---

### Task 9: Rewrite transport as MCP shim

**Files:**
- Modify: `transport/Cargo.toml`
- Modify: `transport/src/lib.rs`

The transport crate becomes a thin MCP shim that translates tool calls into HTTP requests to the control plane.

- [ ] **Step 1: Update transport/Cargo.toml**

Replace dependencies:

```toml
[dependencies]
domain = { version = "0.1.0", path = "../domain" }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
rmcp = { version = "1.2.0", features = ["transport-io"] }
schemars = "1.2.1"
serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0.149"
thiserror = "2.0.18"
tokio = { version = "1.50.0", features = ["io-util", "macros", "rt-multi-thread"] }

[dev-dependencies]
rmcp = { version = "1.2.0", features = ["client", "transport-io"] }
wiremock = "0.6"
```

Note: `async-trait` is no longer needed since we don't implement domain service traits. Added `reqwest` for HTTP calls and `wiremock` for testing.

- [ ] **Step 2: Rewrite transport/src/lib.rs as HTTP shim**

The shim still uses rmcp for MCP protocol, but each tool call makes an HTTP request to the gateway URL instead of calling orchestrator directly:

```rust
//! MCP shim — translates MCP tool calls into HTTP requests to the control plane.

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::Deserialize;
use thiserror::Error;

/// Configuration for the MCP shim.
#[derive(Clone, Debug)]
pub struct ShimConfig {
    pub gateway_url: String,
    pub server_name: String,
    pub server_version: String,
    pub token: String,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("mcp server initialization failed: {0}")]
    Initialize(Box<rmcp::service::ServerInitializeError>),
    #[error("mcp server task failed: {0}")]
    Runtime(#[from] tokio::task::JoinError),
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommitPatchTool {
    /// Base branch to create from (e.g. "main").
    pub base_branch: String,
    /// Commit message.
    pub commit_message: String,
    /// New branch name (must start with "agent/").
    pub new_branch: String,
    /// Repository owner or organization.
    pub owner: String,
    /// Unified diff patch to apply.
    pub patch: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetChangeRequestTool {
    /// Change request index number.
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListChangeRequestsTool {
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Optional state filter: open, closed, merged.
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenChangeRequestTool {
    /// Base branch for the change request.
    pub base_branch: String,
    /// Description body.
    pub body: String,
    /// Head branch with the changes.
    pub head_branch: String,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Title of the change request.
    pub title: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadRepositoryFileTool {
    /// Optional git ref such as a branch, tag, or commit SHA.
    pub git_ref: Option<String>,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository-relative file path.
    pub path: String,
    /// Repository name.
    pub repo: String,
}

pub struct McpShim {
    client: reqwest::Client,
    config: ShimConfig,
    tool_router: ToolRouter<Self>,
}

impl McpShim {
    #[must_use]
    pub fn new(config: ShimConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
            tool_router: Self::tool_router(),
        }
    }

    /// Makes an HTTP request to the control plane and returns the response body
    /// as a string, or maps errors to MCP errors.
    async fn gateway_get(&self, path: &str) -> Result<String, McpError> {
        let url = format!("{}{path}", self.config.gateway_url.trim_end_matches('/'));
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.config.token)
            .send()
            .await
            .map_err(|e| McpError::internal_error(format!("HTTP request failed: {e}"), None))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| McpError::internal_error(format!("failed to read response: {e}"), None))?;

        if !status.is_success() {
            return Err(if status.as_u16() == 401 {
                McpError::invalid_params("authentication failed".to_string(), None)
            } else if status.is_client_error() {
                McpError::invalid_params(body, None)
            } else {
                McpError::internal_error(body, None)
            });
        }

        Ok(body)
    }

    async fn gateway_post(&self, path: &str, json_body: &impl serde::Serialize) -> Result<String, McpError> {
        let url = format!("{}{path}", self.config.gateway_url.trim_end_matches('/'));
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.config.token)
            .json(json_body)
            .send()
            .await
            .map_err(|e| McpError::internal_error(format!("HTTP request failed: {e}"), None))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| McpError::internal_error(format!("failed to read response: {e}"), None))?;

        if !status.is_success() {
            return Err(if status.as_u16() == 401 {
                McpError::invalid_params("authentication failed".to_string(), None)
            } else if status.is_client_error() {
                McpError::invalid_params(body, None)
            } else {
                McpError::internal_error(body, None)
            });
        }

        Ok(body)
    }
}

#[tool_router]
impl McpShim {
    /// Apply a unified diff patch to a new branch and push it.
    #[tool(
        name = "commit_patch",
        description = "Apply a unified diff patch to a new branch and push it."
    )]
    async fn commit_patch(
        &self,
        Parameters(request): Parameters<CommitPatchTool>,
    ) -> Result<String, McpError> {
        let path = format!(
            "/api/v1/repos/{}/{}/patches",
            request.owner, request.repo
        );
        let body = serde_json::json!({
            "base_branch": request.base_branch,
            "commit_message": request.commit_message,
            "new_branch": request.new_branch,
            "patch": request.patch,
        });
        self.gateway_post(&path, &body).await
    }

    /// Get a single change request by index.
    #[tool(
        name = "get_change_request",
        description = "Get a single change request (pull request) by index."
    )]
    async fn get_change_request(
        &self,
        Parameters(request): Parameters<GetChangeRequestTool>,
    ) -> Result<String, McpError> {
        let path = format!(
            "/api/v1/repos/{}/{}/pulls/{}",
            request.owner, request.repo, request.index
        );
        self.gateway_get(&path).await
    }

    /// List change requests for a repository.
    #[tool(
        name = "list_change_requests",
        description = "List change requests (pull requests) for a repository."
    )]
    async fn list_change_requests(
        &self,
        Parameters(request): Parameters<ListChangeRequestsTool>,
    ) -> Result<String, McpError> {
        let mut path = format!(
            "/api/v1/repos/{}/{}/pulls",
            request.owner, request.repo
        );
        if let Some(state) = &request.state {
            path.push_str(&format!("?state={state}"));
        }
        self.gateway_get(&path).await
    }

    /// Open a change request (pull request) on the forge.
    #[tool(
        name = "open_change_request",
        description = "Open a change request (pull request) on the forge."
    )]
    async fn open_change_request(
        &self,
        Parameters(request): Parameters<OpenChangeRequestTool>,
    ) -> Result<String, McpError> {
        let path = format!(
            "/api/v1/repos/{}/{}/pulls",
            request.owner, request.repo
        );
        let body = serde_json::json!({
            "base_branch": request.base_branch,
            "body": request.body,
            "head_branch": request.head_branch,
            "title": request.title,
        });
        self.gateway_post(&path, &body).await
    }

    /// Read a single UTF-8 text file from a repository.
    #[tool(
        name = "read_repository_file",
        description = "Read a single UTF-8 text file from a repository."
    )]
    async fn read_repository_file(
        &self,
        Parameters(request): Parameters<ReadRepositoryFileTool>,
    ) -> Result<String, McpError> {
        let encoded_path = request.path.replace('/', "%2F");
        let mut path = format!(
            "/api/v1/repos/{}/{}/contents/{encoded_path}",
            request.owner, request.repo
        );
        if let Some(git_ref) = &request.git_ref {
            path.push_str(&format!("?ref={git_ref}"));
        }
        let response = self.gateway_get(&path).await?;

        // Extract just the content field from the JSON response
        let parsed: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| McpError::internal_error(format!("invalid JSON response: {e}"), None))?;
        parsed["content"]
            .as_str()
            .map(ToString::to_string)
            .ok_or_else(|| McpError::internal_error("missing content field".to_string(), None))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpShim {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "MCP shim for forge-mcp control plane. Proxies tool calls to the HTTP API.",
            )
            .with_server_info(Implementation::new(
                self.config.server_name.clone(),
                self.config.server_version.clone(),
            ))
    }
}

/// Serve the MCP shim over stdio.
///
/// # Errors
///
/// Returns an error if the MCP server cannot initialize or if the runtime task
/// exits unexpectedly.
pub async fn serve_stdio(config: ShimConfig) -> Result<(), TransportError> {
    McpShim::new(config)
        .serve(stdio())
        .await
        .map_err(Box::new)
        .map_err(TransportError::Initialize)?
        .waiting()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rmcp::{
        ClientHandler,
        ServiceExt,
        model::{CallToolRequestParams, ClientInfo},
    };

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct DummyClientHandler;

    impl ClientHandler for DummyClientHandler {
        fn get_info(&self) -> ClientInfo {
            ClientInfo::default()
        }
    }

    fn test_config(gateway_url: &str) -> ShimConfig {
        ShimConfig {
            gateway_url: gateway_url.to_string(),
            server_name: "forge-mcp-shim".to_string(),
            server_version: "0.1.0-test".to_string(),
            token: "test-token".to_string(),
        }
    }

    async fn spawn_shim_and_client(
        config: ShimConfig,
    ) -> Result<
        (
            rmcp::service::RunningService<rmcp::service::RoleClient, DummyClientHandler>,
            tokio::task::JoinHandle<Result<(), TransportError>>,
        ),
        Box<dyn std::error::Error>,
    > {
        let (server_transport, client_transport) = tokio::io::duplex(4096);

        let server_handle = tokio::spawn(async move {
            McpShim::new(config)
                .serve(server_transport)
                .await
                .map_err(Box::new)
                .map_err(TransportError::Initialize)?
                .waiting()
                .await
                .map_err(TransportError::Runtime)?;
            Ok::<(), TransportError>(())
        });

        let client = DummyClientHandler.serve(client_transport).await?;
        Ok((client, server_handle))
    }

    #[tokio::test]
    async fn read_repository_file_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(r"/api/v1/repos/.+/contents/.+"))
            .and(wiremock::matchers::header("authorization", "Bearer test-token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "content": "hello world",
                        "git_ref": "main",
                        "path": "README.md"
                    })),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "owner": "org",
            "repo": "repo",
            "path": "README.md",
            "git_ref": "main"
        })
        .as_object()
        .unwrap()
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("read_repository_file").with_arguments(args))
            .await?;

        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert_eq!(text, "hello world");

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn commit_patch_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path_regex(r"/api/v1/repos/.+/patches"))
            .and(wiremock::matchers::header("authorization", "Bearer test-token"))
            .respond_with(
                wiremock::ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({
                        "branch": "agent/fix",
                        "commit_sha": "abc123"
                    })),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "owner": "org",
            "repo": "repo",
            "base_branch": "main",
            "new_branch": "agent/fix",
            "commit_message": "fix",
            "patch": "diff..."
        })
        .as_object()
        .unwrap()
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("commit_patch").with_arguments(args))
            .await?;

        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("agent/fix"));

        drop(client);
        server_handle.await??;
        Ok(())
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p transport`
Expected: PASS

- [ ] **Step 4: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add transport/Cargo.toml transport/src/lib.rs
git commit -m "transport: rewrite as MCP shim over HTTP

Translates MCP tool calls into HTTP requests to the control plane.
Holds no forge credentials or business logic. Adds two new tools:
list_change_requests and get_change_request."
```

---

### Task 10: Transport binary entry point

**Files:**
- Create: `transport/src/main.rs`
- Modify: `transport/Cargo.toml`

The transport crate needs a binary entry point so it can be run as a standalone MCP shim.

- [ ] **Step 1: Add binary target and clap to transport/Cargo.toml**

Add to `[dependencies]`:

```toml
clap = { version = "4", features = ["derive"] }
```

The `[[bin]]` section is implicit if `src/main.rs` exists alongside `src/lib.rs`.

- [ ] **Step 2: Create transport/src/main.rs**

```rust
//! Binary entry point for the MCP shim.

use clap::Parser;
use transport::{ShimConfig, serve_stdio};

/// MCP shim for forge-mcp control plane.
#[derive(Parser)]
#[command(name = "forge-mcp-shim", version)]
struct Cli {
    /// Control plane gateway URL (e.g. https://forge-mcp.example:8443).
    #[arg(long, env = "FORGE_MCP_GATEWAY_URL")]
    gateway_url: String,

    /// Path to a file containing the bearer token. The token is never
    /// accepted as a CLI value to avoid leaking it in process listings.
    #[arg(long)]
    token_file: Option<std::path::PathBuf>,
}

fn read_token(cli: &Cli) -> Result<String, Box<dyn std::error::Error>> {
    // 1. --token-file flag
    if let Some(path) = &cli.token_file {
        return Ok(std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read token file {}: {e}", path.display()))?
            .trim()
            .to_string());
    }
    // 2. FORGE_MCP_TOKEN env var
    if let Ok(token) = std::env::var("FORGE_MCP_TOKEN") {
        return Ok(token);
    }
    Err("bearer token required: set FORGE_MCP_TOKEN env var or use --token-file".into())
}

fn server_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let token = read_token(&cli)?;

    let config = ShimConfig {
        gateway_url: cli.gateway_url,
        server_name: "forge-mcp-shim".to_string(),
        server_version: server_version(),
        token,
    };

    serve_stdio(config).await?;
    Ok(())
}
```

- [ ] **Step 3: Verify both binaries build**

Run: `cargo build --all-targets`
Expected: both `server` and `transport` binaries compile

- [ ] **Step 4: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add transport/Cargo.toml transport/src/main.rs
git commit -m "transport: add binary entry point for MCP shim

CLI args and env vars: --gateway-url / FORGE_MCP_GATEWAY_URL,
FORGE_MCP_TOKEN env var or --token-file. Runs MCP shim over stdio."
```

---

## Chunk 4: Per-Agent Policy + Cleanup

### Task 11: Per-agent policy enforcement in handlers

Currently the `WriteOrchestrator` uses a single `PolicyConfig`. In Phase 3, each agent has its own policy loaded from the TOML config. The handlers need to pass the agent's policy to the orchestrator.

**Design decision:** Rather than making the orchestrator accept per-request policy configs (which would require changing its interface), we create per-agent `WriteOrchestrator` instances. But that's complex. A simpler approach: the handlers already resolve the agent's policy from the registry. Pass the policy config into the domain request, and have the orchestrator use it if provided.

Actually, the simplest approach: make `WriteOrchestrator` accept the `PolicyConfig` as a parameter on each method call rather than at construction time. This is a small refactor.

**Alternative (simpler, chosen):** Create a new field on `CommitPatchRequest` and `OpenChangeRequestRequest` for `policy_override: Option<PolicyConfig>`, and have the orchestrator use it if present. But this pollutes domain types.

**Simplest approach (chosen):** Keep the current orchestrator as-is with its default policy. For Phase 3, the handler validates policy BEFORE calling the orchestrator by running `domain::policy::evaluate()` directly. The orchestrator's policy check becomes a defense-in-depth fallback. This requires no changes to domain types or orchestrator.

**Files:**
- Modify: `server/src/handlers.rs`

- [ ] **Step 1: Add per-agent policy check to post_patches handler**

Before calling `state.write_service.commit_patch(...)`, add:

```rust
// Per-agent policy check (the orchestrator has its own default policy as defense-in-depth)
let diff_result = domain::diff::validate_diff(&body.patch)
    .map_err(|e| map_service_error(ServiceError::Validation(e.to_string())))?;

let touched_paths: Vec<String> = diff_result
    .files
    .iter()
    .flat_map(|f| {
        let mut paths = vec![f.path.clone()];
        if let Some(ref source) = f.source_path {
            paths.push(source.clone());
        }
        paths
    })
    .collect();

let policy_context = domain::policy::PolicyContext {
    action: "commit_patch".to_string(),
    agent: identity.clone(),
    repository: repo_ref(&path.owner, &path.repo, &state.forgejo_base_url),
    target_branch: body.new_branch.clone(),
    touched_paths,
};
let decision = domain::policy::evaluate(&policy, &policy_context)
    .map_err(|e| map_service_error(ServiceError::Validation(e.to_string())))?;
if !decision.is_allowed() {
    return Err(map_service_error(ServiceError::PolicyDenied {
        reasons: decision.reasons.join("; "),
    }));
}
```

Similarly for `post_pulls`, add branch prefix check using the agent's policy.

- [ ] **Step 2: Add tests for per-agent policy enforcement**

```rust
#[tokio::test]
async fn post_patches_rejects_wrong_branch_per_agent_policy() {
    let configs = vec![crate::config::AgentConfig {
        agent_id: "codex".to_string(),
        policy: AgentPolicyConfig {
            allowed_repos: vec!["org/repo".to_string()],
            branch_prefix: Some("agent/codex/".to_string()),
            protected_paths: vec![],
        },
        session_id: "default".to_string(),
        token: "test-token".to_string(),
    }];
    let state = AppState {
        agent_registry: AgentRegistry::from_configs(&configs),
        forgejo_base_url: "https://forge.example".to_string(),
        read_service: Arc::new(FakeReadService),
        write_service: Arc::new(FakeWriteService),
    };
    let app = crate::build_router(state, false);

    let body = serde_json::json!({
        "base_branch": "main",
        "commit_message": "fix",
        "new_branch": "agent/claude/fix",
        "patch": "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n # Hello\n+World\n"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/repos/org/repo/patches")
                .header("authorization", "Bearer test-token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("does not start with"));
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p server handlers`
Expected: PASS

- [ ] **Step 4: Run full checks**

Run: `cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add server/src/handlers.rs
git commit -m "server: enforce per-agent policy in HTTP handlers

Each agent's policy config from the TOML file is evaluated before
calling the orchestrator. The orchestrator's default policy remains
as defense-in-depth."
```

---

### Task 12: Build script for GIT_COMMIT_SHORT

The `server/src/main.rs` uses `env!("GIT_COMMIT_SHORT")` which requires a build script. Check if it already exists; if not, create one.

**Files:**
- Check/Create: `server/build.rs`

- [ ] **Step 1: Check if build.rs exists**

Run: `ls server/build.rs`

If it exists, skip this task. If not:

- [ ] **Step 2: Create server/build.rs**

```rust
use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_COMMIT_SHORT={output}");
    println!("cargo:rerun-if-changed=../.git/HEAD");
}
```

- [ ] **Step 3: Commit if created**

```bash
git add server/build.rs
git commit -m "server: add build script for GIT_COMMIT_SHORT env var"
```

---

### Task 13: Example config file

**Files:**
- Create: `forge-mcp.example.toml`

- [ ] **Step 1: Create example config**

```toml
# forge-mcp control plane configuration

[server]
listen = "0.0.0.0:8443"

[forge.forgejo]
base_url = "https://forge.example"
token = "your-forgejo-api-token"

# Each [[agents]] entry defines a bearer token that maps to an agent
# identity and policy. Agents authenticate to the control plane with
# their bearer token; the control plane never exposes forge credentials.

[[agents]]
token = "bearer-token-for-codex"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["org/repo", "org/other-repo"]
branch_prefix = "agent/codex/"
protected_paths = [".forgejo/", ".github/"]

[[agents]]
token = "bearer-token-for-claude"
agent_id = "claude"
session_id = "default"

[agents.policy]
allowed_repos = ["org/repo"]
branch_prefix = "agent/claude/"
protected_paths = [".forgejo/", ".github/"]
```

- [ ] **Step 2: Add to .gitignore**

Add `forge-mcp.toml` (not the `.example`) to `.gitignore` so real configs with secrets aren't committed:

```
forge-mcp.toml
```

- [ ] **Step 3: Commit**

```bash
git add forge-mcp.example.toml .gitignore
git commit -m "add example TOML config file for the HTTP control plane"
```
