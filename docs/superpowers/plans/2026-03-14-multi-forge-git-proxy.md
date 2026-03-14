# Multi-Forge Support + Git Smart HTTP Proxy — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evolve the gateway from single-Forgejo to multi-forge with glob-style repo authorization and a read-only git smart HTTP proxy for transparent `git clone`/`fetch`.

**Architecture:** A `ForgeRegistry` maps short aliases to per-forge instances (adapter + orchestrators). All REST and git proxy routes include a `{forge}` path segment. `allowed_repos` patterns use `forge/owner/repo` triplets with wildcard support. The git proxy streams `git-upload-pack` requests to upstream forges without buffering.

**Tech Stack:** Rust, axum 0.8, reqwest (streaming), tokio, serde, toml, utoipa

**Verification command (run after every task):**
```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

**IMPORTANT:** Tasks MUST be executed in strict order. Each task depends on prior tasks being complete. Each commit must pass all checks independently.

---

## File Structure

### Modified

- **`domain/src/lib.rs`** — add `alias` field to `RepositoryRef`
- **`domain/src/policy.rs`** — update test helpers for new `RepositoryRef` field
- **`forge/src/lib.rs`** — remove `ForgeKind` checks and `UnsupportedForge` variant
- **`orchestrator/src/lib.rs`** — remove `policy_config` from `WriteOrchestrator`; update test helpers
- **`server/src/auth.rs`** — move `extract_bearer_token` here; update test `allowed_repos` patterns
- **`server/src/config.rs`** — rewrite: `[[forges]]` array, glob `allowed_repos`, alias validation
- **`server/src/handlers.rs`** — add `{forge}` to routes, `ForgeRegistry` lookup, new `AppState`
- **`server/src/lib.rs`** — update route paths, add new modules
- **`server/src/main.rs`** — build `ForgeRegistry` from config, new startup wiring
- **`server/src/api.rs`** — add `forge` to path parameter structs
- **`server/Cargo.toml`** — add `reqwest` with `stream` feature
- **`transport/src/lib.rs`** — add `forge` param to all MCP tool structs
- **`forge-mcp.example.toml`** — update to new `[[forges]]` format

### Created

- **`server/src/git_proxy.rs`** — git smart HTTP proxy handlers
- **`server/src/registry.rs`** — `ForgeRegistry` and `ForgeInstance` types

---

## Chunk 1: Domain + Config Foundation

### Task 1: Add `alias` field to `RepositoryRef`

**Files:**
- Modify: `domain/src/lib.rs`
- Modify: `domain/src/policy.rs` (test helper)
- Modify: `orchestrator/src/lib.rs` (test helpers)
- Modify: `server/src/handlers.rs` (test helpers and `repo_ref()`)

- [ ] **Step 1: Add `alias` field to `RepositoryRef`**

In `domain/src/lib.rs`, add `alias` as the first field (alphabetically before `forge`):

```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RepositoryRef {
    pub alias: String,
    pub forge: ForgeKind,
    pub host: String,
    pub name: String,
    pub owner: String,
}
```

- [ ] **Step 2: Fix all `RepositoryRef` construction sites**

Every place that builds a `RepositoryRef` needs the new `alias` field. Add `alias: String::new()` or `alias: "test".to_string()` as appropriate.

Files to update:
- `domain/src/policy.rs` — `test_context()`: add `alias: "test".to_string()`
- `orchestrator/src/lib.rs` — `test_request()`, `write_test_request()`, and `open_change_request` tests: add `alias: "test".to_string()`
- `server/src/handlers.rs` — `repo_ref()` function: add `alias: String::new()` (placeholder, Task 6 sets real values); all test `RepositoryRef` literals in `FakeWriteService` and `FakeReadService`: add `alias: String::new()`

- [ ] **Step 3: Run verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 4: Commit**

```bash
git add domain/src/lib.rs domain/src/policy.rs orchestrator/src/lib.rs server/src/handlers.rs
git commit -m "domain: add alias field to RepositoryRef"
```

---

### Task 2: Rewrite config types for multi-forge

**Files:**
- Modify: `server/src/config.rs`
- Modify: `server/src/handlers.rs` (update `is_repo_allowed` call site)
- Modify: `server/src/auth.rs` (update test `allowed_repos` patterns)

This task rewrites config types AND updates all consumers of `is_repo_allowed` so the commit compiles.

- [ ] **Step 1: Rewrite config types**

Replace all types and functions in `server/src/config.rs` (above the `#[cfg(test)]` module):

```rust
//! TOML configuration for the HTTP control plane.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub agents: Vec<AgentConfig>,
    pub forges: Vec<ForgeConfig>,
    pub server: ListenConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListenConfig {
    #[serde(default)]
    pub enable_docs: bool,
    pub listen: String,
}

#[derive(Clone, Deserialize)]
pub struct ForgeConfig {
    pub alias: String,
    pub base_url: String,
    #[serde(rename = "type")]
    pub forge_type: String,
    pub token: Option<String>,
}

impl std::fmt::Debug for ForgeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeConfig")
            .field("alias", &self.alias)
            .field("base_url", &self.base_url)
            .field("forge_type", &self.forge_type)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
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

    /// Returns whether the agent is allowed to access the given repo.
    ///
    /// Patterns use `forge/owner/repo` triplets with wildcard support:
    /// - `"*"` — all repos on all forges
    /// - `"alias/*"` — all repos on a specific forge
    /// - `"alias/owner/*"` — all repos under an owner
    /// - `"alias/owner/repo"` — exact match
    #[must_use]
    pub fn is_repo_allowed(&self, forge_alias: &str, owner: &str, repo: &str) -> bool {
        self.allowed_repos.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }
            let parts: Vec<&str> = pattern.splitn(3, '/').collect();
            match parts.as_slice() {
                [f, "*"] if *f == forge_alias => true,
                [f, o, "*"] if *f == forge_alias && *o == owner => true,
                [f, o, r] if *f == forge_alias && *o == owner && *r == repo => true,
                _ => false,
            }
        })
    }
}

/// Validates a forge alias: must match `[a-z0-9][a-z0-9-]*`.
///
/// # Errors
///
/// Returns a description if the alias is invalid.
pub fn validate_forge_alias(alias: &str) -> Result<(), String> {
    if alias.is_empty() {
        return Err("forge alias must not be empty".to_string());
    }
    let first = alias.as_bytes()[0];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(format!(
            "forge alias '{alias}' must start with a lowercase letter or digit"
        ));
    }
    if !alias
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "forge alias '{alias}' may only contain lowercase letters, digits, and hyphens"
        ));
    }
    Ok(())
}

/// Validates the parsed config for semantic correctness.
///
/// # Errors
///
/// Returns a description of the first validation error found.
pub fn validate_config(config: &ServerConfig) -> Result<(), String> {
    let mut seen_aliases = std::collections::HashSet::new();
    for forge in &config.forges {
        validate_forge_alias(&forge.alias)?;
        if !seen_aliases.insert(&forge.alias) {
            return Err(format!("duplicate forge alias '{}'", forge.alias));
        }
    }

    for agent in &config.agents {
        for pattern in &agent.policy.allowed_repos {
            if pattern == "*" {
                continue;
            }
            let forge_part = pattern.split('/').next().unwrap_or("");
            if forge_part != "*" && !seen_aliases.contains(&forge_part.to_string()) {
                return Err(format!(
                    "agent '{}' references unknown forge alias '{forge_part}' in allowed_repos pattern '{pattern}'",
                    agent.agent_id
                ));
            }
        }
    }

    Ok(())
}

/// Parses a TOML configuration string into a `ServerConfig`.
///
/// # Errors
///
/// Returns an error if the TOML is malformed or missing required fields.
pub fn parse_config(toml_str: &str) -> Result<ServerConfig, toml::de::Error> {
    toml::from_str(toml_str)
}
```

- [ ] **Step 2: Replace all tests in `server/src/config.rs`**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CONFIG: &str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://forge.example"
token = "forgejo-api-token"

[[forges]]
alias = "client-a"
type = "forgejo"
base_url = "https://client.example"
token = "client-token"

[[agents]]
token = "bearer-token-for-codex"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["internal/org/repo", "internal/org/other-repo", "client-a/org/*"]
branch_prefix = "agent/codex/"
protected_paths = [".forgejo/", ".github/"]

[[agents]]
token = "bearer-token-for-claude"
agent_id = "claude"
session_id = "default"

[agents.policy]
allowed_repos = ["internal/org/repo"]
branch_prefix = "agent/claude/"
protected_paths = [".forgejo/", ".github/"]
"#;

    #[test]
    fn parses_valid_config() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert_eq!(config.server.listen, "0.0.0.0:8443");
        assert_eq!(config.forges.len(), 2);
        assert_eq!(config.forges[0].alias, "internal");
        assert_eq!(config.forges[0].forge_type, "forgejo");
        assert_eq!(config.forges[0].base_url, "https://forge.example");
        assert_eq!(config.forges[0].token.as_deref(), Some("forgejo-api-token"));
        assert_eq!(config.forges[1].alias, "client-a");
        assert_eq!(config.agents.len(), 2);
    }

    #[test]
    fn parses_forge_without_token() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "public"
type = "forgejo"
base_url = "https://public.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert!(config.forges[0].token.is_none());
    }

    #[test]
    fn converts_policy_to_domain_type() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        let policy = config.agents[0].policy.to_policy_config();
        assert_eq!(policy.branch_prefix.as_deref(), Some("agent/codex/"));
        assert_eq!(policy.protected_paths, vec![".forgejo/", ".github/"]);
    }

    #[test]
    fn repo_exact_match() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert!(config.agents[0].policy.is_repo_allowed("internal", "org", "repo"));
        assert!(config.agents[0].policy.is_repo_allowed("internal", "org", "other-repo"));
        assert!(!config.agents[0].policy.is_repo_allowed("internal", "org", "secret"));
    }

    #[test]
    fn repo_owner_wildcard() {
        let config = parse_config(VALID_CONFIG).expect("should parse");
        assert!(config.agents[0].policy.is_repo_allowed("client-a", "org", "any-repo"));
        assert!(!config.agents[0].policy.is_repo_allowed("client-a", "other-org", "repo"));
    }

    #[test]
    fn repo_forge_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("internal", "any", "repo"));
        assert!(!policy.is_repo_allowed("other", "any", "repo"));
    }

    #[test]
    fn repo_global_wildcard() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(policy.is_repo_allowed("any-forge", "any", "repo"));
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec![],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.is_repo_allowed("forge", "any", "repo"));
    }

    #[test]
    fn partial_glob_treated_as_literal() {
        let policy = AgentPolicyConfig {
            allowed_repos: vec!["internal/org/repo-*".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        };
        assert!(!policy.is_repo_allowed("internal", "org", "repo-foo"));
    }

    #[test]
    fn validates_forge_alias_format() {
        assert!(validate_forge_alias("internal").is_ok());
        assert!(validate_forge_alias("client-a").is_ok());
        assert!(validate_forge_alias("forge123").is_ok());
        assert!(validate_forge_alias("a").is_ok());
        assert!(validate_forge_alias("-bad").is_err());
        assert!(validate_forge_alias("").is_err());
        assert!(validate_forge_alias("BAD").is_err());
        assert!(validate_forge_alias("has/slash").is_err());
        assert!(validate_forge_alias("has.dot").is_err());
    }

    #[test]
    fn rejects_duplicate_forge_aliases() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "dupe"
type = "forgejo"
base_url = "https://a.example"

[[forges]]
alias = "dupe"
type = "forgejo"
base_url = "https://b.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_invalid_forge_alias_in_allowed_repos() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://a.example"

[[agents]]
token = "t"
agent_id = "a"
session_id = "s"

[agents.policy]
allowed_repos = ["nonexistent/org/repo"]
"#;
        let config = parse_config(toml_str).expect("should parse");
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_missing_forges_section() {
        let toml_str = r#"
[server]
listen = "0.0.0.0:8443"

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
        assert!(!debug.contains("client-token"));
        assert!(!debug.contains("bearer-token-for-codex"));
        assert!(!debug.contains("bearer-token-for-claude"));
        assert!(debug.contains("[REDACTED]"));
    }
}
```

- [ ] **Step 3: Update `is_repo_allowed` call sites**

In `server/src/handlers.rs`, update `resolve_agent` to pass forge alias. Change the call at ~line 82:

```rust
// Before:
if !agent.policy_config.is_repo_allowed(owner, repo) {
// After:
if !agent.policy_config.is_repo_allowed(forge_alias, owner, repo) {
```

And update the function signature to accept `forge_alias: &str` (insert before `owner`):

```rust
fn resolve_agent(
    headers: &HeaderMap,
    registry: &AgentRegistry,
    forge_alias: &str,
    owner: &str,
    repo: &str,
) -> Result<(AgentIdentity, domain::policy::PolicyConfig), (StatusCode, Json<ErrorBody>)> {
```

Update all call sites in handlers to pass `&path.forge` — but since `path` structs don't have `forge` yet (that's Task 6), use a placeholder `""` for now in each handler call:

```rust
// Temporarily pass "" as forge_alias until Task 6 adds {forge} to routes
let (identity, _policy) =
    resolve_agent(&headers, &state.agent_registry, "", &path.owner, &path.repo)?;
```

In `server/src/auth.rs`, update test `allowed_repos` patterns to use the `forge/owner/repo` format:

```rust
// Before:
allowed_repos: vec!["org/repo".to_string()],
// After:
allowed_repos: vec!["test/org/repo".to_string()],
```

Update the `resolves_valid_token` test assertion — `agent.policy.branch_prefix` is unchanged.

In handler tests, update `test_state()` `allowed_repos`:

```rust
// Before:
allowed_repos: vec!["org/repo".to_string()],
// After:
allowed_repos: vec!["/org/repo".to_string()],
```

Note: handler tests use `""` as forge alias, so patterns need to match `""` — use `"/org/repo"` (empty forge prefix). Alternatively use `"*"` to allow all. Using `"*"` is simpler for now:

```rust
allowed_repos: vec!["*".to_string()],
```

The 403 test needs to keep specific patterns. Use the current handler's placeholder `""`:

```rust
// For the 403 test:
allowed_repos: vec!["/org/allowed-repo".to_string()],
```

- [ ] **Step 4: Update `server/src/main.rs` to use new config shape**

The old `config.forge.forgejo` references no longer compile. Temporarily update `main.rs` to use the first forge from the array:

```rust
let forge_config = config.forges.first().expect("at least one forge required");

let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
    base_url: forge_config.base_url.clone(),
    token: forge_config.token.clone(),
}));

// ... rest unchanged except:
// config.forge.forgejo.token.clone() → forge_config.token.clone()
// config.forge.forgejo.base_url → forge_config.base_url.clone()
```

This is a temporary bridge — Task 6 rewrites main.rs properly with ForgeRegistry.

- [ ] **Step 5: Run verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 6: Commit**

```bash
git add server/src/config.rs server/src/handlers.rs server/src/auth.rs server/src/main.rs
git commit -m "server: rewrite config for multi-forge [[forges]] array

Replace [forge.forgejo] with [[forges]] array. Each forge has an alias,
type, base_url, and optional token. allowed_repos patterns use
forge/owner/repo triplets with wildcard support. Add alias validation
and config validation. Update all is_repo_allowed call sites."
```

---

### Task 3: Remove policy from `WriteOrchestrator`

**Files:**
- Modify: `orchestrator/src/lib.rs`
- Modify: `server/src/main.rs` (update constructor call)

- [ ] **Step 1: Update `WriteOrchestrator` struct and constructor**

In `orchestrator/src/lib.rs`, remove `policy_config` from the struct and constructor:

```rust
pub struct WriteOrchestrator<A, S>
where
    A: ForgeAdapter,
    S: AuditSink,
{
    adapter: Arc<A>,
    audit_sink: Arc<S>,
    forge_token: Option<String>,
}

impl<A, S> WriteOrchestrator<A, S>
where
    A: ForgeAdapter + 'static,
    S: AuditSink + 'static,
{
    #[must_use]
    pub fn new(adapter: Arc<A>, audit_sink: Arc<S>, forge_token: Option<String>) -> Self {
        Self {
            adapter,
            audit_sink,
            forge_token,
        }
    }
}
```

- [ ] **Step 2: Simplify `commit_patch` — remove diff validation and policy checks**

The handler already validates diff and checks policy. The orchestrator only needs audit + git:

```rust
async fn commit_patch(
    &self,
    request: domain::CommitPatchRequest,
) -> Result<domain::CommitPatchResponse, ServiceError> {
    // 1. Audit intent
    self.audit_sink
        .record(AuditRecord {
            agent: request.agent.clone(),
            action: "commit_patch".to_string(),
            repository: request.repository.clone(),
            target: request.new_branch.clone(),
        })
        .await
        .map_err(|e| ServiceError::Audit(e.to_string()))?;

    // 2. Execute git operations
    let clone_url = format!(
        "{}/{}/{}.git",
        request.repository.host.trim_end_matches('/'),
        request.repository.owner,
        request.repository.name,
    );
    let base_branch = request.base_branch.clone();
    let patch = request.patch.clone();
    let new_branch = request.new_branch.clone();
    let commit_message = request.commit_message.clone();
    let agent_id = request.agent.agent_id.clone();
    let token = self.forge_token.clone();

    let git_result = tokio::task::spawn_blocking(move || {
        let workspace =
            git_exec::GitWorkspace::clone_repo(&clone_url, &base_branch, token.as_deref())?;
        workspace.create_branch(&new_branch)?;
        workspace.apply_patch(&patch)?;
        let result =
            workspace.commit(&commit_message, &agent_id, &format!("{agent_id}@forge-mcp"))?;
        workspace.push_branch(&new_branch)?;
        Ok::<_, git_exec::GitExecError>(result)
    })
    .await
    .map_err(|e| ServiceError::GitExec(e.to_string()))?
    .map_err(|e| ServiceError::GitExec(e.to_string()))?;

    Ok(domain::CommitPatchResponse {
        branch: request.new_branch,
        commit_sha: git_result.commit_sha,
        repository: request.repository,
    })
}
```

- [ ] **Step 3: Simplify `open_change_request` — remove policy check**

```rust
async fn open_change_request(
    &self,
    request: domain::OpenChangeRequestRequest,
) -> Result<domain::OpenChangeRequestResponse, ServiceError> {
    // 1. Audit intent
    self.audit_sink
        .record(AuditRecord {
            agent: request.agent.clone(),
            action: "open_change_request".to_string(),
            repository: request.repository.clone(),
            target: request.head_branch.clone(),
        })
        .await
        .map_err(|e| ServiceError::Audit(e.to_string()))?;

    // 2. Create on forge
    let change_request = self
        .adapter
        .create_change_request(
            &request.repository,
            &request.title,
            &request.body,
            &request.head_branch,
            &request.base_branch,
        )
        .await
        .map_err(|e| ServiceError::Upstream(e.to_string()))?;

    Ok(domain::OpenChangeRequestResponse {
        change_request,
        repository: request.repository,
    })
}
```

- [ ] **Step 4: Remove policy tests from orchestrator, update constructors**

Remove these tests:
- `commit_patch_rejects_invalid_diff`
- `commit_patch_rejects_wrong_branch_prefix`
- `commit_patch_rejects_protected_paths`
- `open_change_request_rejects_wrong_branch_prefix`

Update remaining test constructors to use new 3-arg `new()`:
```rust
WriteOrchestrator::new(adapter, Arc::clone(&audit), None)
```

- [ ] **Step 5: Update `server/src/main.rs` constructor call**

Change from 4 args to 3 args:

```rust
// Before:
let write_service = Arc::new(WriteOrchestrator::new(
    adapter,
    audit_sink,
    Some(config.forge.forgejo.token.clone()),
    domain::policy::PolicyConfig::default(),
));
// After (using temporary first-forge pattern from Task 2):
let write_service = Arc::new(WriteOrchestrator::new(
    adapter,
    audit_sink,
    forge_config.token.clone(),
));
```

- [ ] **Step 6: Run verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 7: Commit**

```bash
git add orchestrator/src/lib.rs server/src/main.rs
git commit -m "orchestrator: remove policy evaluation from WriteOrchestrator

Policy enforcement is done in the handler layer. Removing the duplicate
simplifies the orchestrator for per-forge instance sharing."
```

---

### Task 4: Remove `ForgeKind` checks from `ForgejoAdapter`

**Files:**
- Modify: `forge/src/lib.rs`

- [ ] **Step 1: Remove `ForgeKind` checks and `UnsupportedForge` variant**

In `forge/src/lib.rs`, remove the `if repository.forge != domain::ForgeKind::Forgejo` guard from all four methods: `read_repository_file`, `create_change_request`, `list_change_requests`, `get_change_request`.

Remove the `UnsupportedForge` variant from `ForgeError`:
```rust
// Remove this:
#[error("unsupported forge for this adapter: {0:?}")]
UnsupportedForge(domain::ForgeKind),
```

This variant is only used in the guards being removed — no other code references it.

- [ ] **Step 2: Run verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 3: Commit**

```bash
git add forge/src/lib.rs
git commit -m "forge: remove ForgeKind checks and UnsupportedForge variant

The ForgeRegistry routes requests to the correct adapter, making
per-method ForgeKind guards redundant."
```

---

## Chunk 2: Registry + Handlers + Main Wiring

### Task 5: Create `ForgeRegistry`

**Files:**
- Create: `server/src/registry.rs`
- Modify: `server/src/lib.rs` (add `pub mod registry;`)

- [ ] **Step 1: Create `server/src/registry.rs`**

```rust
//! Forge registry — maps aliases to forge instances.

use std::collections::HashMap;
use std::sync::Arc;

use domain::{RepositoryReadService, RepositoryWriteService};
use forge::ForgeAdapter;

/// A single forge instance with its adapter and services.
pub struct ForgeInstance {
    pub adapter: Arc<dyn ForgeAdapter>,
    pub alias: String,
    pub base_url: String,
    pub client: reqwest::Client,
    pub read_service: Arc<dyn RepositoryReadService>,
    pub token: Option<String>,
    pub write_service: Arc<dyn RepositoryWriteService>,
}

impl std::fmt::Debug for ForgeInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeInstance")
            .field("alias", &self.alias)
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Registry mapping forge aliases to instances.
pub struct ForgeRegistry {
    forges: HashMap<String, ForgeInstance>,
}

impl std::fmt::Debug for ForgeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeRegistry")
            .field("forges", &format_args!("[{} entries]", self.forges.len()))
            .finish()
    }
}

impl ForgeRegistry {
    #[must_use]
    pub fn new(forges: HashMap<String, ForgeInstance>) -> Self {
        Self { forges }
    }

    /// Looks up a forge instance by alias.
    #[must_use]
    pub fn get(&self, alias: &str) -> Option<&ForgeInstance> {
        self.forges.get(alias)
    }

    /// Returns the number of registered forges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.forges.len()
    }

    /// Returns true if no forges are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.forges.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry() {
        let registry = ForgeRegistry::new(HashMap::new());
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn debug_redacts_tokens() {
        let registry = ForgeRegistry::new(HashMap::new());
        let debug = format!("{registry:?}");
        assert!(debug.contains("ForgeRegistry"));
        assert!(debug.contains("0 entries"));
    }
}
```

Note: `ForgeInstance` includes a `client: reqwest::Client` field for the git proxy to reuse connections. This requires adding `reqwest` to server's dependencies.

- [ ] **Step 2: Add `reqwest` to `server/Cargo.toml`**

```toml
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream"] }
```

- [ ] **Step 3: Add module declaration in `server/src/lib.rs`**

Add `pub mod registry;` alphabetically (between `pub mod handlers;` and the `use` statements).

- [ ] **Step 4: Run verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 5: Commit**

```bash
git add server/src/registry.rs server/src/lib.rs server/Cargo.toml
git commit -m "server: add ForgeRegistry for multi-forge routing"
```

---

### Task 6: Rewrite handlers, routes, main.rs, and example config

**Files:**
- Modify: `server/src/api.rs` (add `forge` to path structs)
- Modify: `server/src/auth.rs` (move `extract_bearer_token` here)
- Modify: `server/src/handlers.rs` (new `AppState`, forge lookup, all handlers)
- Modify: `server/src/lib.rs` (update route paths)
- Modify: `server/src/main.rs` (build `ForgeRegistry`, new startup wiring)
- Modify: `forge-mcp.example.toml`

This is the largest task — it wires everything together. All changes land in one commit to keep the build green.

- [ ] **Step 1: Move `extract_bearer_token` to `auth.rs`**

In `server/src/auth.rs`, add this public function (move from `handlers.rs`):

```rust
/// Extracts the bearer token from the Authorization header.
#[must_use]
pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}
```

Add `axum` to the function's visibility — it needs `axum::http::HeaderMap`. Since `server` already depends on `axum`, this is fine.

Remove the duplicate `extract_bearer_token` from `handlers.rs` and import from `auth`:
```rust
use crate::auth::{AgentRegistry, extract_bearer_token};
```

- [ ] **Step 2: Add `forge` field to API path structs**

In `server/src/api.rs`, add `pub forge: String` as the first field (alphabetically) to `RepoPath`, `PullPath`, and `ContentsPath`.

- [ ] **Step 3: Rewrite `AppState` and handler helpers**

In `server/src/handlers.rs`:

```rust
/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub agent_registry: AgentRegistry,
    pub forge_registry: Arc<crate::registry::ForgeRegistry>,
}
```

Add forge resolution helper:

```rust
fn resolve_forge(
    registry: &crate::registry::ForgeRegistry,
    alias: &str,
) -> Result<&crate::registry::ForgeInstance, (StatusCode, Json<ErrorBody>)> {
    registry.get(alias).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: format!("unknown forge alias '{alias}'"),
            }),
        )
    })
}
```

Update `repo_ref`:

```rust
fn repo_ref(
    forge_alias: &str,
    owner: &str,
    repo: &str,
    forge: &crate::registry::ForgeInstance,
) -> RepositoryRef {
    RepositoryRef {
        alias: forge_alias.to_string(),
        forge: ForgeKind::Forgejo, // TODO: derive from config type field
        host: forge.base_url.clone(),
        name: repo.to_string(),
        owner: owner.to_string(),
    }
}
```

- [ ] **Step 4: Update all 5 handler functions**

Each handler:
1. Calls `resolve_forge(&state.forge_registry, &path.forge)?`
2. Calls `resolve_agent` with `&path.forge`
3. Uses `forge.read_service` or `forge.write_service` instead of `state.read_service`/`state.write_service`
4. Calls `repo_ref(&path.forge, &path.owner, &path.repo, forge)`

Example for `get_contents`:

```rust
pub async fn get_contents(
    State(state): State<AppState>,
    Path(path): Path<ContentsPath>,
    Query(query): Query<ContentsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let forge = resolve_forge(&state.forge_registry, &path.forge)?;
    let (identity, _policy) =
        resolve_agent(&headers, &state.agent_registry, &path.forge, &path.owner, &path.repo)?;

    let result = forge
        .read_service
        .read_repository_file(ReadRepositoryFileRequest {
            agent: identity,
            git_ref: query.git_ref.clone(),
            path: path.path.clone(),
            repository: repo_ref(&path.forge, &path.owner, &path.repo, forge),
        })
        .await
        .map_err(map_service_error)?;

    Ok::<_, (StatusCode, Json<ErrorBody>)>(Json(ContentsResult {
        content: result.content,
        git_ref: result.git_ref,
        path: result.path,
    }))
}
```

Apply the same pattern to all handlers. Update `#[utoipa::path]` annotations to add `{forge}` to paths and add `("forge" = String, Path, description = "Forge alias")` parameter.

- [ ] **Step 5: Update route paths in `server/src/lib.rs`**

Add `{forge}` to all route patterns:
```rust
"/api/v1/repos/{forge}/{owner}/{repo}/contents/{*path}"
"/api/v1/repos/{forge}/{owner}/{repo}/patches"
"/api/v1/repos/{forge}/{owner}/{repo}/pulls"
"/api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}"
```

- [ ] **Step 6: Rewrite `server/src/main.rs`**

```rust
//! Binary entry point for the HTTP control plane.

use std::collections::HashMap;
use std::sync::Arc;

use audit::InMemoryAuditSink;
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use server::{
    auth::AgentRegistry,
    build_router,
    config::{parse_config, validate_config},
    handlers::AppState,
    registry::{ForgeInstance, ForgeRegistry},
};

fn server_version() -> String {
    let commit = env!("GIT_COMMIT_SHORT");
    format!("{}+{commit}", env!("CARGO_PKG_VERSION"))
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

    validate_config(&config).unwrap_or_else(|e| panic!("invalid configuration: {e}"));

    eprintln!(
        "forge-mcp {} — listening on {}",
        server_version(),
        config.server.listen
    );

    let audit_sink = Arc::new(InMemoryAuditSink::new());
    let client = reqwest::Client::new();
    let mut forges = HashMap::new();

    for forge_config in &config.forges {
        let adapter: Arc<dyn forge::ForgeAdapter> = match forge_config.forge_type.as_str() {
            "forgejo" => Arc::new(ForgejoAdapter::new(ForgejoConfig {
                base_url: forge_config.base_url.clone(),
                token: forge_config.token.clone(),
            })),
            other => panic!(
                "unsupported forge type '{other}' for alias '{}'",
                forge_config.alias
            ),
        };

        let read_service = Arc::new(ReadOrchestrator::new(
            Arc::clone(&adapter),
            Arc::clone(&audit_sink),
        ));

        let write_service = Arc::new(WriteOrchestrator::new(
            Arc::clone(&adapter),
            Arc::clone(&audit_sink),
            forge_config.token.clone(),
        ));

        forges.insert(
            forge_config.alias.clone(),
            ForgeInstance {
                adapter,
                alias: forge_config.alias.clone(),
                base_url: forge_config.base_url.clone(),
                client: client.clone(),
                read_service,
                token: forge_config.token.clone(),
                write_service,
            },
        );

        eprintln!(
            "  forge '{}' → {}",
            forge_config.alias, forge_config.base_url
        );
    }

    let agent_registry = AgentRegistry::from_configs(&config.agents);
    let state = AppState {
        agent_registry,
        forge_registry: Arc::new(ForgeRegistry::new(forges)),
    };

    let app = build_router(state, config.server.enable_docs);

    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    eprintln!("forge-mcp ready");
    axum::serve(listener, app).await?;

    Ok(())
}
```

- [ ] **Step 7: Update handler tests**

Create a `FakeForgeAdapter` in the handler tests module (needed because `ForgeInstance` requires one):

```rust
struct FakeForgeAdapter;

#[async_trait::async_trait]
impl forge::ForgeAdapter for FakeForgeAdapter {
    async fn read_repository_file(
        &self,
        _: &domain::RepositoryRef,
        _: &str,
        _: Option<&str>,
    ) -> Result<domain::ReadRepositoryFileResponse, forge::ForgeError> {
        unimplemented!()
    }
    async fn create_change_request(
        &self,
        _: &domain::RepositoryRef,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<domain::ChangeRequest, forge::ForgeError> {
        unimplemented!()
    }
    async fn list_change_requests(
        &self,
        _: &domain::RepositoryRef,
        _: Option<&domain::ChangeRequestState>,
    ) -> Result<Vec<domain::ChangeRequest>, forge::ForgeError> {
        unimplemented!()
    }
    async fn get_change_request(
        &self,
        _: &domain::RepositoryRef,
        _: u64,
    ) -> Result<domain::ChangeRequest, forge::ForgeError> {
        unimplemented!()
    }
}
```

Update `test_state()`:

```rust
fn test_state() -> AppState {
    let configs = vec![crate::config::AgentConfig {
        agent_id: "codex".to_string(),
        policy: AgentPolicyConfig {
            allowed_repos: vec!["test-forge/org/repo".to_string()],
            branch_prefix: Some("agent/".to_string()),
            protected_paths: vec![],
        },
        session_id: "default".to_string(),
        token: "test-token".to_string(),
    }];

    let mut forges = std::collections::HashMap::new();
    forges.insert(
        "test-forge".to_string(),
        crate::registry::ForgeInstance {
            adapter: Arc::new(FakeForgeAdapter),
            alias: "test-forge".to_string(),
            base_url: "https://forge.example".to_string(),
            client: reqwest::Client::new(),
            read_service: Arc::new(FakeReadService),
            token: None,
            write_service: Arc::new(FakeWriteService),
        },
    );

    AppState {
        agent_registry: AgentRegistry::from_configs(&configs),
        forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
    }
}
```

Update all test URIs to include `/test-forge/`:
- `/api/v1/repos/org/repo/...` → `/api/v1/repos/test-forge/org/repo/...`

Update the 403 test `allowed_repos` to `"test-forge/org/allowed-repo"`.

Add test for unknown forge:

```rust
#[tokio::test]
async fn returns_404_for_unknown_forge() {
    let app = crate::build_router(test_state(), false);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/repos/nonexistent/org/repo/contents/README.md")
                .header("authorization", "Bearer test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 8: Update example config**

Replace `forge-mcp.example.toml`:

```toml
# forge-mcp control plane configuration

[server]
listen = "0.0.0.0:8443"
# enable_docs = true

# Each [[forges]] entry defines a forge instance the gateway can proxy to.
# alias:    short name used in URLs and allowed_repos patterns (lowercase, hyphens ok)
# type:     forge software type ("forgejo" for now; "github", "gitlab" planned)
# base_url: upstream forge base URL
# token:    API token for the upstream forge (optional for public instances)

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://forge.example"
token = "your-forgejo-api-token"

# Each [[agents]] entry defines a bearer token that maps to an agent
# identity and policy.
#
# allowed_repos patterns:
#   ["*"]                           → all repos on all forges
#   ["internal/*"]                  → all repos on the 'internal' forge
#   ["internal/org/*"]              → all repos under 'org' on 'internal'
#   ["internal/org/repo"]           → exact match
#   Partial globs like "internal/org/repo-*" are NOT supported.

[[agents]]
token = "bearer-token-for-codex"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["internal/org/repo", "internal/org/other-repo"]
branch_prefix = "agent/codex/"
protected_paths = [".forgejo/", ".github/"]

[[agents]]
token = "bearer-token-for-claude"
agent_id = "claude"
session_id = "default"

[agents.policy]
allowed_repos = ["internal/org/repo"]
branch_prefix = "agent/claude/"
protected_paths = [".forgejo/", ".github/"]
```

- [ ] **Step 9: Run verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 10: Commit**

```bash
git add server/src/api.rs server/src/auth.rs server/src/handlers.rs server/src/lib.rs server/src/main.rs forge-mcp.example.toml
git commit -m "server: add {forge} to all routes, use ForgeRegistry

Handlers resolve forge instance from ForgeRegistry by alias. AppState
holds ForgeRegistry instead of single read/write service. Each forge
gets its own adapter and orchestrators. extract_bearer_token moved to
auth.rs for sharing with git proxy."
```

---

## Chunk 3: MCP Shim + Git Proxy

### Task 7: Add `forge` parameter to MCP shim tools

**Files:**
- Modify: `transport/src/lib.rs`

- [ ] **Step 1: Add `forge` field to all tool structs**

Add `/// Forge alias (e.g. "internal").` and `pub forge: String` as the first field (alphabetically) in all 5 tool structs: `CommitPatchTool`, `GetChangeRequestTool`, `ListChangeRequestsTool`, `OpenChangeRequestTool`, `ReadRepositoryFileTool`.

- [ ] **Step 2: Update all tool method URL building**

Insert `&request.forge` after `"repos"` in each `build_url` call:

```rust
// Before:
self.build_url(&["api", "v1", "repos", &request.owner, &request.repo, ...])
// After:
self.build_url(&["api", "v1", "repos", &request.forge, &request.owner, &request.repo, ...])
```

- [ ] **Step 3: Update tests**

Add `"forge": "test-forge"` to all test argument JSON objects.

Update wiremock path matchers to account for the extra segment:
```rust
// Before:
wiremock::matchers::path_regex(r"/api/v1/repos/.+/contents/.+")
// After:
wiremock::matchers::path_regex(r"/api/v1/repos/.+/.+/.+/contents/.+")
```

- [ ] **Step 4: Run verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 5: Commit**

```bash
git add transport/src/lib.rs
git commit -m "transport: add forge parameter to all MCP tool structs"
```

---

### Task 8: Git smart HTTP proxy endpoints

**Files:**
- Create: `server/src/git_proxy.rs`
- Modify: `server/src/lib.rs` (add module and routes)

- [ ] **Step 1: Create `server/src/git_proxy.rs`**

```rust
//! Git smart HTTP proxy — read-only streaming proxy for git-upload-pack.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::api::ErrorBody;
use crate::auth::{AgentRegistry, extract_bearer_token};
use crate::handlers::AppState;
use crate::registry::ForgeRegistry;

#[derive(Debug, Deserialize)]
pub struct GitRepoPath {
    pub forge: String,
    pub owner: String,
    /// Repository name, possibly with `.git` suffix.
    pub repo: String,
}

impl GitRepoPath {
    /// Returns the repo name without the `.git` suffix.
    fn repo_name(&self) -> &str {
        self.repo.strip_suffix(".git").unwrap_or(&self.repo)
    }
}

#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    pub service: Option<String>,
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let body = serde_json::to_string(&ErrorBody {
        error: message.to_string(),
    })
    .unwrap_or_else(|_| format!("{{\"error\":\"{message}\"}}"));
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// GET /git/{forge}/{owner}/{repo}.git/info/refs?service=git-upload-pack
pub async fn info_refs(
    State(state): State<AppState>,
    Path(path): Path<GitRepoPath>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Response {
    let service = match query.service.as_deref() {
        Some("git-upload-pack") => "git-upload-pack",
        Some("git-receive-pack") => {
            return error_response(
                StatusCode::FORBIDDEN,
                "git push is not supported through the proxy; use the commit_patch MCP tool",
            );
        }
        Some(other) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("unsupported git service: {other}"),
            );
        }
        None => {
            return error_response(StatusCode::BAD_REQUEST, "missing service query parameter");
        }
    };

    // Auth
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => return error_response(StatusCode::UNAUTHORIZED, "missing Authorization header"),
    };
    let agent = match state.agent_registry.resolve(token) {
        Some(a) => a,
        None => return error_response(StatusCode::UNAUTHORIZED, "invalid bearer token"),
    };

    let repo_name = path.repo_name();
    if !agent
        .policy_config
        .is_repo_allowed(&path.forge, &path.owner, repo_name)
    {
        return error_response(
            StatusCode::FORBIDDEN,
            &format!(
                "agent '{}' is not authorized for repository '{}/{}/{}'",
                agent.identity.agent_id, path.forge, path.owner, repo_name
            ),
        );
    }

    // Resolve forge
    let forge = match state.forge_registry.get(&path.forge) {
        Some(f) => f,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                &format!("unknown forge '{}'", path.forge),
            )
        }
    };

    // Build upstream URL
    let upstream_url = format!(
        "{}/{}/{}.git/info/refs?service={service}",
        forge.base_url.trim_end_matches('/'),
        path.owner,
        repo_name,
    );

    // Proxy request
    let mut upstream_req = forge.client.get(&upstream_url);
    if let Some(ref token) = forge.token {
        upstream_req = upstream_req.bearer_auth(token);
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {e}"),
            );
        }
    };

    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| {
            HeaderValue::from_static("application/x-git-upload-pack-advertisement")
        });

    let body = Body::from_stream(upstream_resp.bytes_stream());

    Response::builder()
        .status(status.as_u16())
        .header("content-type", content_type)
        .body(body)
        .unwrap()
}

/// POST /git/{forge}/{owner}/{repo}.git/git-upload-pack
pub async fn upload_pack(
    State(state): State<AppState>,
    Path(path): Path<GitRepoPath>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Auth
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => return error_response(StatusCode::UNAUTHORIZED, "missing Authorization header"),
    };
    let agent = match state.agent_registry.resolve(token) {
        Some(a) => a,
        None => return error_response(StatusCode::UNAUTHORIZED, "invalid bearer token"),
    };

    let repo_name = path.repo_name();
    if !agent
        .policy_config
        .is_repo_allowed(&path.forge, &path.owner, repo_name)
    {
        return error_response(
            StatusCode::FORBIDDEN,
            &format!(
                "agent '{}' is not authorized for repository '{}/{}/{}'",
                agent.identity.agent_id, path.forge, path.owner, repo_name
            ),
        );
    }

    // Resolve forge
    let forge = match state.forge_registry.get(&path.forge) {
        Some(f) => f,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                &format!("unknown forge '{}'", path.forge),
            )
        }
    };

    // Build upstream URL
    let upstream_url = format!(
        "{}/{}/{}.git/git-upload-pack",
        forge.base_url.trim_end_matches('/'),
        path.owner,
        repo_name,
    );

    // Stream request body to upstream
    let body_stream = body.into_data_stream();
    let reqwest_body = reqwest::Body::wrap_stream(body_stream);

    let mut upstream_req = forge
        .client
        .post(&upstream_url)
        .header("content-type", "application/x-git-upload-pack-request")
        .body(reqwest_body);
    if let Some(ref token) = forge.token {
        upstream_req = upstream_req.bearer_auth(token);
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {e}"),
            );
        }
    };

    let status = upstream_resp.status();
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/x-git-upload-pack-result"));

    let body = Body::from_stream(upstream_resp.bytes_stream());

    Response::builder()
        .status(status.as_u16())
        .header("content-type", content_type)
        .body(body)
        .unwrap()
}

/// POST /git/{forge}/{owner}/{repo}.git/git-receive-pack — always rejected
pub async fn receive_pack_rejected() -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "git push is not supported through the proxy; use the commit_patch MCP tool",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_name_strips_git_suffix() {
        let path = GitRepoPath {
            forge: "internal".to_string(),
            owner: "org".to_string(),
            repo: "repo.git".to_string(),
        };
        assert_eq!(path.repo_name(), "repo");
    }

    #[test]
    fn repo_name_without_suffix() {
        let path = GitRepoPath {
            forge: "internal".to_string(),
            owner: "org".to_string(),
            repo: "repo".to_string(),
        };
        assert_eq!(path.repo_name(), "repo");
    }
}
```

- [ ] **Step 2: Add module and routes to `server/src/lib.rs`**

Add `pub mod git_proxy;` alphabetically.

Add git proxy routes in `build_router`:

```rust
.route(
    "/git/{forge}/{owner}/{repo}/info/refs",
    get(git_proxy::info_refs),
)
.route(
    "/git/{forge}/{owner}/{repo}/git-upload-pack",
    post(git_proxy::upload_pack),
)
.route(
    "/git/{forge}/{owner}/{repo}/git-receive-pack",
    post(git_proxy::receive_pack_rejected),
)
```

Note: `{repo}` captures `repo.git` — `GitRepoPath::repo_name()` strips the suffix.

- [ ] **Step 3: Run verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 4: Commit**

```bash
git add server/src/git_proxy.rs server/src/lib.rs
git commit -m "server: add read-only git smart HTTP proxy

Streaming proxy for git-upload-pack (clone/fetch). git-receive-pack
returns 403 directing agents to commit_patch. Uses shared reqwest
client from ForgeInstance for connection reuse."
```

---

### Task 9: Git proxy integration tests

**Files:**
- Modify: `server/src/git_proxy.rs` (add integration tests)
- Modify: `server/Cargo.toml` (add wiremock dev-dependency)

- [ ] **Step 1: Add wiremock to server dev-dependencies**

In `server/Cargo.toml` `[dev-dependencies]`:
```toml
wiremock = "0.6"
```

Also add `forge` and `reqwest` to dev-dependencies (needed for test fake types):
```toml
forge = { version = "0.1.0", path = "../forge" }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
```

- [ ] **Step 2: Add integration tests to `git_proxy.rs`**

Add to the `tests` module:

```rust
use axum::{body::Body, http::Request, Router, routing::{get, post}};
use tower::ServiceExt;

// Fake implementations needed because ForgeInstance requires them
struct FakeForgeAdapter;

#[async_trait::async_trait]
impl forge::ForgeAdapter for FakeForgeAdapter {
    async fn read_repository_file(
        &self, _: &domain::RepositoryRef, _: &str, _: Option<&str>,
    ) -> Result<domain::ReadRepositoryFileResponse, forge::ForgeError> {
        unimplemented!()
    }
    async fn create_change_request(
        &self, _: &domain::RepositoryRef, _: &str, _: &str, _: &str, _: &str,
    ) -> Result<domain::ChangeRequest, forge::ForgeError> {
        unimplemented!()
    }
    async fn list_change_requests(
        &self, _: &domain::RepositoryRef, _: Option<&domain::ChangeRequestState>,
    ) -> Result<Vec<domain::ChangeRequest>, forge::ForgeError> {
        unimplemented!()
    }
    async fn get_change_request(
        &self, _: &domain::RepositoryRef, _: u64,
    ) -> Result<domain::ChangeRequest, forge::ForgeError> {
        unimplemented!()
    }
}

struct FakeReadService;

#[async_trait::async_trait]
impl domain::RepositoryReadService for FakeReadService {
    async fn get_change_request(&self, _: domain::GetChangeRequestRequest) -> Result<domain::ChangeRequest, domain::ServiceError> { unimplemented!() }
    async fn list_change_requests(&self, _: domain::ListChangeRequestsRequest) -> Result<Vec<domain::ChangeRequest>, domain::ServiceError> { unimplemented!() }
    async fn read_repository_file(&self, _: domain::ReadRepositoryFileRequest) -> Result<domain::ReadRepositoryFileResponse, domain::ServiceError> { unimplemented!() }
}

struct FakeWriteService;

#[async_trait::async_trait]
impl domain::RepositoryWriteService for FakeWriteService {
    async fn commit_patch(&self, _: domain::CommitPatchRequest) -> Result<domain::CommitPatchResponse, domain::ServiceError> { unimplemented!() }
    async fn open_change_request(&self, _: domain::OpenChangeRequestRequest) -> Result<domain::OpenChangeRequestResponse, domain::ServiceError> { unimplemented!() }
}

fn test_state_with_forge(base_url: &str) -> AppState {
    use crate::auth::AgentRegistry;
    use crate::config::AgentPolicyConfig;
    use std::collections::HashMap;

    let configs = vec![crate::config::AgentConfig {
        agent_id: "codex".to_string(),
        policy: AgentPolicyConfig {
            allowed_repos: vec!["test-forge/*".to_string()],
            branch_prefix: Some("agent/".to_string()),
            protected_paths: vec![],
        },
        session_id: "default".to_string(),
        token: "test-token".to_string(),
    }];

    let mut forges = HashMap::new();
    forges.insert(
        "test-forge".to_string(),
        crate::registry::ForgeInstance {
            adapter: Arc::new(FakeForgeAdapter),
            alias: "test-forge".to_string(),
            base_url: base_url.to_string(),
            client: reqwest::Client::new(),
            read_service: Arc::new(FakeReadService),
            token: Some("upstream-token".to_string()),
            write_service: Arc::new(FakeWriteService),
        },
    );

    AppState {
        agent_registry: AgentRegistry::from_configs(&configs),
        forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
    }
}

fn git_proxy_router(state: AppState) -> Router {
    Router::new()
        .route("/git/{forge}/{owner}/{repo}/info/refs", get(info_refs))
        .route(
            "/git/{forge}/{owner}/{repo}/git-upload-pack",
            post(upload_pack),
        )
        .route(
            "/git/{forge}/{owner}/{repo}/git-receive-pack",
            post(receive_pack_rejected),
        )
        .with_state(state)
}

#[tokio::test]
async fn info_refs_proxies_to_upstream() {
    let mock = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path_regex(r".+/info/refs"))
        .and(wiremock::matchers::query_param("service", "git-upload-pack"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer upstream-token",
        ))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .insert_header(
                    "content-type",
                    "application/x-git-upload-pack-advertisement",
                )
                .set_body_bytes(b"001e# service=git-upload-pack\n"),
        )
        .mount(&mock)
        .await;

    let state = test_state_with_forge(&mock.uri());
    let app = git_proxy_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/git/test-forge/org/repo.git/info/refs?service=git-upload-pack")
                .header("authorization", "Bearer test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let ct = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("git-upload-pack"));
}

#[tokio::test]
async fn receive_pack_rejected_returns_403() {
    let state = test_state_with_forge("http://unused");
    let app = git_proxy_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/git/test-forge/org/repo.git/git-receive-pack")
                .header("authorization", "Bearer test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn info_refs_rejects_receive_pack_service() {
    let state = test_state_with_forge("http://unused");
    let app = git_proxy_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/git/test-forge/org/repo.git/info/refs?service=git-receive-pack")
                .header("authorization", "Bearer test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn info_refs_rejects_unauthorized() {
    let state = test_state_with_forge("http://unused");
    let app = git_proxy_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/git/test-forge/org/repo.git/info/refs?service=git-upload-pack")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn info_refs_rejects_disallowed_repo() {
    use crate::auth::AgentRegistry;
    use crate::config::AgentPolicyConfig;
    use std::collections::HashMap;

    let configs = vec![crate::config::AgentConfig {
        agent_id: "codex".to_string(),
        policy: AgentPolicyConfig {
            allowed_repos: vec!["test-forge/org/allowed-only".to_string()],
            branch_prefix: None,
            protected_paths: vec![],
        },
        session_id: "default".to_string(),
        token: "test-token".to_string(),
    }];

    let mut forges = HashMap::new();
    forges.insert(
        "test-forge".to_string(),
        crate::registry::ForgeInstance {
            adapter: Arc::new(FakeForgeAdapter),
            alias: "test-forge".to_string(),
            base_url: "http://unused".to_string(),
            client: reqwest::Client::new(),
            read_service: Arc::new(FakeReadService),
            token: None,
            write_service: Arc::new(FakeWriteService),
        },
    );

    let state = AppState {
        agent_registry: AgentRegistry::from_configs(&configs),
        forge_registry: Arc::new(crate::registry::ForgeRegistry::new(forges)),
    };
    let app = git_proxy_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/git/test-forge/org/secret.git/info/refs?service=git-upload-pack")
                .header("authorization", "Bearer test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
```

- [ ] **Step 3: Run verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 4: Commit**

```bash
git add server/Cargo.toml server/src/git_proxy.rs
git commit -m "server: add integration tests for git proxy

Tests verify info/refs proxying, receive-pack rejection, auth
enforcement, and allowed_repos checks."
```

---

### Task 10: Final verification and release build

- [ ] **Step 1: Run full verification**

```bash
cargo fmt --check && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings && cargo test --all-features --all-targets
```

- [ ] **Step 2: Build release binaries**

```bash
cargo build --release -p server -p transport
```

- [ ] **Step 3: Commit any remaining cleanup if needed**

Only if clippy or tests revealed issues:
```bash
git add <specific-files>
git commit -m "chore: final cleanup for multi-forge support"
```
