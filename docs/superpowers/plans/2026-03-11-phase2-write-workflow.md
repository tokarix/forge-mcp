# Phase 2: Write Workflow Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the safe write workflow to forge-mcp: branch creation, patch application, commit, push, change request creation — all gated by policy enforcement, diff validation, and audit.

**Architecture:** The write path flows through the orchestrator as the sole composition root. It validates the diff, evaluates policy, records audit intent, executes git operations via CLI subprocess, pushes the branch, and opens a change request on the forge. All new domain logic (policy, diff validation) is pure and synchronous. Git operations shell out to the `git` CLI behind `spawn_blocking`. HTTPS-only push with token auth via `http.extraHeader` environment variable (never in argv or URLs). Policy is enforced on both `commit_patch` and `open_change_request`.

**Tech Stack:** Rust, tokio, git CLI (subprocess), Forgejo API v1, rmcp, thiserror, serde, base64

**Conventions:**
- Order enum variants, struct fields, imports, and module declarations alphabetically
- Each commit must pass `cargo fmt --check && cargo build --all-features --all-targets && cargo test --all-features --all-targets && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings`
- First commit a module without wiring it; follow-up commit wires consumers
- Tests must be stable — do not modify tests to fix breakage later
- Use `thiserror` for all error types
- Keep policy denials type-distinct from infrastructure errors

**Deferred items (not in this plan):**
- Transport tests asserting MCP error codes (tracked: memory 2301263f)
- Workspace Cargo.toml inheritance cleanup

---

## Chunk 1: Domain Types and Diff Validation

### Task 1: Add write-path domain types

**Files:**
- Modify: `domain/src/lib.rs`

These types represent the write workflow's request/response shapes and the change request model.

- [ ] **Step 1: Add domain types for the write path**

Add the following types to `domain/src/lib.rs`, keeping all types and variants in alphabetical order. Insert them after the existing read types but before `ServiceError`:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeRequest {
    pub base_branch: String,
    pub body: String,
    pub head_branch: String,
    pub index: u64,
    pub state: ChangeRequestState,
    pub title: String,
    pub url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangeRequestState {
    Closed,
    Merged,
    Open,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPatchRequest {
    pub agent: AgentIdentity,
    pub base_branch: String,
    pub commit_message: String,
    pub new_branch: String,
    pub patch: String,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitPatchResponse {
    pub branch: String,
    pub commit_sha: String,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetChangeRequestRequest {
    pub agent: AgentIdentity,
    pub index: u64,
    pub repository: RepositoryRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListChangeRequestsRequest {
    pub agent: AgentIdentity,
    pub repository: RepositoryRef,
    pub state: Option<ChangeRequestState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenChangeRequestRequest {
    pub agent: AgentIdentity,
    pub base_branch: String,
    pub body: String,
    pub head_branch: String,
    pub repository: RepositoryRef,
    pub title: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenChangeRequestResponse {
    pub change_request: ChangeRequest,
    pub repository: RepositoryRef,
}
```

- [ ] **Step 2: Extend ServiceError for policy denials**

Replace the existing `ServiceError` enum with:

```rust
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("audit failure: {0}")]
    Audit(String),
    #[error("git execution failed: {0}")]
    GitExec(String),
    #[error("policy denied: {reasons}")]
    PolicyDenied { reasons: String },
    #[error("upstream forge error: {0}")]
    Upstream(String),
    #[error("validation failed: {0}")]
    Validation(String),
}
```

- [ ] **Step 3: Add write service trait**

Add after the `RepositoryReadService` trait:

```rust
#[async_trait]
pub trait RepositoryWriteService: Send + Sync {
    /// Applies a patch to a new branch and pushes it.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, policy, git execution, or audit fails.
    async fn commit_patch(
        &self,
        request: CommitPatchRequest,
    ) -> Result<CommitPatchResponse, ServiceError>;

    /// Opens a change request (pull request) on the forge.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, the upstream forge request, or audit fails.
    async fn open_change_request(
        &self,
        request: OpenChangeRequestRequest,
    ) -> Result<OpenChangeRequestResponse, ServiceError>;
}
```

- [ ] **Step 4: Run checks**

Run: `cargo fmt && cargo build --all-features --all-targets && cargo test --all-features --all-targets && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings`
Expected: All pass. Some existing tests may need `ServiceError` match arms updated if they pattern-match exhaustively — update only the match patterns, not the test logic.

- [ ] **Step 5: Commit**

```bash
git add domain/src/lib.rs
git commit -m "domain: add write-path types and RepositoryWriteService trait

Add ChangeRequest, CommitPatchRequest/Response, OpenChangeRequestRequest/Response,
GetChangeRequestRequest, ListChangeRequestsRequest domain types.
Add RepositoryWriteService trait with commit_patch and open_change_request.
Extend ServiceError with GitExec and PolicyDenied variants."
```

---

### Task 2: Diff validation module in domain

**Files:**
- Create: `domain/src/diff.rs`
- Modify: `domain/src/lib.rs` (add `pub mod diff;`)

The diff validator is a security boundary. It parses unified diff headers to extract file paths, then validates each path. It rejects binary files, symlinks, submodules, paths outside the repository, and patches that exceed a configurable size budget.

- [ ] **Step 1: Create diff.rs with error types and validation function signature**

Create `domain/src/diff.rs`:

```rust
//! Diff validation — a first-class security boundary.
//!
//! Parses unified diff headers to extract touched file paths and validates
//! them against the repository path rules. Rejects binary markers, symlink
//! mode changes, submodule diffs, and patches exceeding a size budget.

use thiserror::Error;

use crate::validate_repository_path;

/// Maximum number of files allowed in a single patch.
const MAX_DIFF_FILES: usize = 100;

/// Maximum total bytes allowed in a single patch.
const MAX_DIFF_BYTES: usize = 1_048_576; // 1 MiB

#[derive(Debug, Error)]
pub enum DiffError {
    #[error("binary file detected: {path}")]
    BinaryFile { path: String },
    #[error("diff exceeds maximum size of {max} bytes")]
    ExceedsBudget { max: usize },
    #[error("invalid diff header: {reason}")]
    InvalidHeader { reason: String },
    #[error("invalid path in diff: {reason}")]
    InvalidPath { reason: String },
    #[error("submodule change detected: {path}")]
    SubmoduleChange { path: String },
    #[error("symlink mode change detected: {path}")]
    SymlinkChange { path: String },
    #[error("too many files in diff: {count} exceeds limit of {max}")]
    TooManyFiles { count: usize, max: usize },
}

/// A single file touched by the diff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffFileSummary {
    pub path: String,
    pub is_new: bool,
    pub is_deleted: bool,
}

/// Result of validating a unified diff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffValidationResult {
    pub files: Vec<DiffFileSummary>,
    pub total_bytes: usize,
}

/// Validates a unified diff patch string.
///
/// Parses diff headers, extracts file paths, and checks each path against
/// repository path rules. Rejects binary content, symlink mode changes,
/// submodule diffs, oversized patches, and patches touching too many files.
///
/// # Errors
///
/// Returns a `DiffError` if the patch violates any validation rule.
pub fn validate_diff(patch: &str) -> Result<DiffValidationResult, DiffError> {
    let total_bytes = patch.len();
    if total_bytes > MAX_DIFF_BYTES {
        return Err(DiffError::ExceedsBudget {
            max: MAX_DIFF_BYTES,
        });
    }

    let mut files = Vec::new();

    for line in patch.lines() {
        // Detect binary file markers
        if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            return Err(DiffError::BinaryFile {
                path: line.to_string(),
            });
        }

        // Detect submodule changes
        if line.starts_with("Subproject commit ") {
            let path = files
                .last()
                .map(|f: &DiffFileSummary| f.path.clone())
                .unwrap_or_else(|| "<unknown>".to_string());
            return Err(DiffError::SubmoduleChange { path });
        }

        // Detect symlink mode changes (mode 120000)
        if (line.starts_with("old mode 120000") || line.starts_with("new mode 120000"))
            || (line.starts_with("new file mode 120000")
                || line.starts_with("deleted file mode 120000"))
        {
            let path = files
                .last()
                .map(|f: &DiffFileSummary| f.path.clone())
                .unwrap_or_else(|| "<unknown>".to_string());
            return Err(DiffError::SymlinkChange { path });
        }

        // Parse diff headers: "diff --git a/path b/path"
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let (a_path, b_path) = parse_diff_header(rest)?;
            let is_new = false; // Will be updated by subsequent lines
            let is_deleted = false;
            // Use b_path as the canonical path (destination)
            let path = if b_path == "/dev/null" {
                a_path
            } else {
                b_path
            };
            files.push(DiffFileSummary {
                path,
                is_new,
                is_deleted,
            });
        }

        // Detect new/deleted files from subsequent header lines
        if line.starts_with("new file mode") {
            if let Some(last) = files.last_mut() {
                last.is_new = true;
            }
        }
        if line.starts_with("deleted file mode") {
            if let Some(last) = files.last_mut() {
                last.is_deleted = true;
            }
        }
    }

    if files.len() > MAX_DIFF_FILES {
        return Err(DiffError::TooManyFiles {
            count: files.len(),
            max: MAX_DIFF_FILES,
        });
    }

    // Validate all paths
    for file in &files {
        validate_repository_path(&file.path).map_err(|reason| DiffError::InvalidPath { reason })?;
    }

    Ok(DiffValidationResult { files, total_bytes })
}

/// Parses "a/path b/path" from a diff --git header line.
fn parse_diff_header(header: &str) -> Result<(String, String), DiffError> {
    // Handle quoted paths (git uses quotes for special characters)
    // Simple case: "a/foo b/bar"
    // The a/ and b/ prefixes are standard git diff prefixes
    let parts: Vec<&str> = header.splitn(2, " b/").collect();
    if parts.len() != 2 {
        return Err(DiffError::InvalidHeader {
            reason: format!("cannot parse diff header: {header}"),
        });
    }

    let a_path = parts[0]
        .strip_prefix("a/")
        .unwrap_or(parts[0])
        .to_string();
    let b_path = parts[1].to_string();

    Ok((a_path, b_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_simple_patch() {
        let patch = "\
diff --git a/README.md b/README.md
index abc123..def456 100644
--- a/README.md
+++ b/README.md
@@ -1,3 +1,4 @@
 # Hello
+New line
 World
";
        let result = validate_diff(patch).expect("should be valid");
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "README.md");
        assert!(!result.files[0].is_new);
        assert!(!result.files[0].is_deleted);
    }

    #[test]
    fn validates_new_file_patch() {
        let patch = "\
diff --git a/new.txt b/new.txt
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+content
";
        let result = validate_diff(patch).expect("should be valid");
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].is_new);
    }

    #[test]
    fn validates_deleted_file_patch() {
        let patch = "\
diff --git a/old.txt b/old.txt
deleted file mode 100644
index abc1234..0000000
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-content
";
        let result = validate_diff(patch).expect("should be valid");
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "old.txt");
        assert!(result.files[0].is_deleted);
    }

    #[test]
    fn validates_multi_file_patch() {
        let patch = "\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-old
+new
diff --git a/b.txt b/b.txt
--- a/b.txt
+++ b/b.txt
@@ -1 +1 @@
-old
+new
";
        let result = validate_diff(patch).expect("should be valid");
        assert_eq!(result.files.len(), 2);
        assert_eq!(result.files[0].path, "a.txt");
        assert_eq!(result.files[1].path, "b.txt");
    }

    #[test]
    fn rejects_binary_file() {
        let patch = "\
diff --git a/image.png b/image.png
Binary files /dev/null and b/image.png differ
";
        let err = validate_diff(patch).expect_err("binary should be rejected");
        assert!(matches!(err, DiffError::BinaryFile { .. }));
    }

    #[test]
    fn rejects_git_binary_patch() {
        let patch = "\
diff --git a/data.bin b/data.bin
GIT binary patch
literal 1234
";
        let err = validate_diff(patch).expect_err("git binary should be rejected");
        assert!(matches!(err, DiffError::BinaryFile { .. }));
    }

    #[test]
    fn rejects_symlink() {
        let patch = "\
diff --git a/link b/link
new file mode 120000
";
        let err = validate_diff(patch).expect_err("symlink should be rejected");
        assert!(matches!(err, DiffError::SymlinkChange { .. }));
    }

    #[test]
    fn rejects_submodule() {
        let patch = "\
diff --git a/vendor/lib b/vendor/lib
index abc..def 160000
--- a/vendor/lib
+++ b/vendor/lib
@@ -1 +1 @@
-Subproject commit aaaaaaa
+Subproject commit bbbbbbb
";
        let err = validate_diff(patch).expect_err("submodule should be rejected");
        assert!(matches!(err, DiffError::SubmoduleChange { .. }));
    }

    #[test]
    fn rejects_path_traversal_in_diff() {
        let patch = "\
diff --git a/../../../etc/passwd b/../../../etc/passwd
--- a/../../../etc/passwd
+++ b/../../../etc/passwd
@@ -1 +1 @@
-old
+new
";
        let err = validate_diff(patch).expect_err("traversal should be rejected");
        assert!(matches!(err, DiffError::InvalidPath { .. }));
    }

    #[test]
    fn rejects_oversized_patch() {
        let patch = "x".repeat(MAX_DIFF_BYTES + 1);
        let err = validate_diff(&patch).expect_err("oversized should be rejected");
        assert!(matches!(err, DiffError::ExceedsBudget { .. }));
    }

    #[test]
    fn rejects_too_many_files() {
        let mut patch = String::new();
        for i in 0..=MAX_DIFF_FILES {
            patch.push_str(&format!(
                "diff --git a/file{i}.txt b/file{i}.txt\n--- a/file{i}.txt\n+++ b/file{i}.txt\n"
            ));
        }
        let err = validate_diff(&patch).expect_err("too many files should be rejected");
        assert!(matches!(err, DiffError::TooManyFiles { .. }));
    }

    #[test]
    fn rejects_invalid_diff_header() {
        let patch = "diff --git broken\n";
        let err = validate_diff(patch).expect_err("invalid header should be rejected");
        assert!(matches!(err, DiffError::InvalidHeader { .. }));
    }
}
```

- [ ] **Step 2: Wire diff module into domain**

Add to `domain/src/lib.rs` after the existing imports, before the `ForgeKind` enum:

```rust
pub mod diff;
```

- [ ] **Step 3: Run checks**

Run: `cargo fmt && cargo build --all-features --all-targets && cargo test --all-features --all-targets && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings`
Expected: All pass, including 12+ new diff validation tests.

- [ ] **Step 4: Commit**

```bash
git add domain/src/diff.rs domain/src/lib.rs
git commit -m "domain: add diff validation as a security boundary

Parse unified diff headers to extract touched file paths. Reject
binary files, symlink mode changes, submodule diffs, path traversal,
oversized patches, and patches touching too many files.

Includes 12 unit tests covering all rejection cases and valid diffs."
```

---

### Task 3: Policy engine module in domain

**Files:**
- Create: `domain/src/policy.rs`
- Modify: `domain/src/lib.rs` (add `pub mod policy;`)

The policy engine is pure and deterministic. For Phase 2 it enforces:
- Branch name prefix (e.g. agent branches must start with `agent/`)
- Protected path rejection (e.g. `.github/`, `.forgejo/`)
- Maximum diff size already handled by diff validation

- [ ] **Step 1: Create policy.rs**

Create `domain/src/policy.rs`:

```rust
//! Policy engine — pure, deterministic policy evaluation.
//!
//! Evaluates whether an agent action is allowed based on configurable
//! rules. The engine is synchronous and has no side effects.

use thiserror::Error;

use crate::{AgentIdentity, RepositoryRef};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    pub reasons: Vec<String>,
}

impl PolicyDecision {
    #[must_use]
    pub fn allow() -> Self {
        Self {
            effect: PolicyEffect::Allow,
            reasons: Vec::new(),
        }
    }

    #[must_use]
    pub fn deny(reasons: Vec<String>) -> Self {
        Self {
            effect: PolicyEffect::Deny,
            reasons,
        }
    }

    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.effect == PolicyEffect::Allow
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyContext {
    pub action: String,
    pub agent: AgentIdentity,
    pub repository: RepositoryRef,
    pub target_branch: String,
    pub touched_paths: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy configuration error: {0}")]
    Configuration(String),
}

/// Policy rule configuration.
#[derive(Clone, Debug)]
pub struct PolicyConfig {
    /// Required prefix for agent-created branches (e.g. "agent/").
    pub branch_prefix: Option<String>,
    /// Paths that agents are not allowed to modify.
    pub protected_paths: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            branch_prefix: Some("agent/".to_string()),
            protected_paths: vec![
                ".forgejo/".to_string(),
                ".gitea/".to_string(),
                ".github/".to_string(),
                ".gitlab/".to_string(),
            ],
        }
    }
}

/// Evaluates a policy context against the given configuration.
///
/// # Errors
///
/// Returns a `PolicyError` if the configuration is invalid.
pub fn evaluate(
    config: &PolicyConfig,
    context: &PolicyContext,
) -> Result<PolicyDecision, PolicyError> {
    let mut deny_reasons = Vec::new();

    // Check branch prefix
    if let Some(prefix) = &config.branch_prefix {
        if !context.target_branch.starts_with(prefix.as_str()) {
            deny_reasons.push(format!(
                "branch '{}' does not start with required prefix '{prefix}'",
                context.target_branch
            ));
        }
    }

    // Check protected paths
    for touched in &context.touched_paths {
        for protected in &config.protected_paths {
            if touched.starts_with(protected.as_str()) || touched == protected.trim_end_matches('/') {
                deny_reasons.push(format!(
                    "path '{touched}' is under protected path '{protected}'"
                ));
            }
        }
    }

    if deny_reasons.is_empty() {
        Ok(PolicyDecision::allow())
    } else {
        Ok(PolicyDecision::deny(deny_reasons))
    }
}

#[cfg(test)]
mod tests {
    use crate::{AgentIdentity, ForgeKind, RepositoryRef};

    use super::*;

    fn test_context(branch: &str, paths: Vec<&str>) -> PolicyContext {
        PolicyContext {
            action: "commit_patch".to_string(),
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            repository: RepositoryRef {
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                owner: "org".to_string(),
                name: "repo".to_string(),
            },
            target_branch: branch.to_string(),
            touched_paths: paths.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn allows_valid_branch_and_paths() {
        let config = PolicyConfig::default();
        let ctx = test_context("agent/fix-typo", vec!["README.md", "src/main.rs"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(decision.is_allowed());
    }

    #[test]
    fn denies_wrong_branch_prefix() {
        let config = PolicyConfig::default();
        let ctx = test_context("main", vec!["README.md"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(!decision.is_allowed());
        assert!(decision.reasons[0].contains("does not start with"));
    }

    #[test]
    fn denies_protected_github_path() {
        let config = PolicyConfig::default();
        let ctx = test_context("agent/fix", vec![".github/workflows/ci.yml"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(!decision.is_allowed());
        assert!(decision.reasons[0].contains("protected path"));
    }

    #[test]
    fn denies_protected_forgejo_path() {
        let config = PolicyConfig::default();
        let ctx = test_context("agent/fix", vec![".forgejo/workflows/ci.yml"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(!decision.is_allowed());
    }

    #[test]
    fn allows_when_no_branch_prefix_configured() {
        let config = PolicyConfig {
            branch_prefix: None,
            protected_paths: Vec::new(),
        };
        let ctx = test_context("main", vec!["anything.txt"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(decision.is_allowed());
    }

    #[test]
    fn collects_multiple_deny_reasons() {
        let config = PolicyConfig::default();
        let ctx = test_context("main", vec![".github/workflows/ci.yml"]);
        let decision = evaluate(&config, &ctx).expect("should not error");
        assert!(!decision.is_allowed());
        assert!(decision.reasons.len() >= 2); // branch + path
    }

    #[test]
    fn default_config_has_expected_protected_paths() {
        let config = PolicyConfig::default();
        assert_eq!(config.protected_paths.len(), 4);
        assert!(config.protected_paths.contains(&".forgejo/".to_string()));
        assert!(config.protected_paths.contains(&".gitea/".to_string()));
        assert!(config.protected_paths.contains(&".github/".to_string()));
        assert!(config.protected_paths.contains(&".gitlab/".to_string()));
    }
}
```

- [ ] **Step 2: Wire policy module into domain**

Add to `domain/src/lib.rs` after `pub mod diff;`:

```rust
pub mod policy;
```

- [ ] **Step 3: Run checks**

Run: `cargo fmt && cargo build --all-features --all-targets && cargo test --all-features --all-targets && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings`
Expected: All pass, including 7 new policy tests.

- [ ] **Step 4: Commit**

```bash
git add domain/src/policy.rs domain/src/lib.rs
git commit -m "domain: add policy engine with branch prefix and protected path rules

Pure, deterministic policy evaluation. Enforces agent branch name
prefix (default: agent/) and protected path rejection (default:
.forgejo/, .gitea/, .github/, .gitlab/). Collects all deny reasons.

Includes 7 unit tests for allow, deny, and multi-reason scenarios."
```

---

## Chunk 2: Git Execution and Forge Adapter Extensions

### Task 4: Implement git-exec with CLI subprocess

**Files:**
- Create: `git-exec/src/lib.rs` (replace placeholder)
- Modify: `git-exec/Cargo.toml` (add dependencies)

The git-exec crate shells out to the `git` CLI for all git operations. It provides a `GitWorkspace` that works in ephemeral temporary directories. HTTPS-only, token auth via `http.extraHeader` environment variable — the token never appears in process arguments or URLs.

- [ ] **Step 1: Update git-exec/Cargo.toml**

```toml
[package]
name = "git-exec"
version = "0.1.0"
edition = "2024"

[dependencies]
base64 = "0.22.1"
tempfile = "3.19"
thiserror = "2.0.18"
```

- [ ] **Step 2: Implement git-exec/src/lib.rs**

```rust
//! Git execution via CLI subprocess.
//!
//! All operations run in ephemeral temporary directories and use HTTPS
//! with token authentication via http.extraHeader (never in argv or URLs).
//! Designed to be called behind `tokio::task::spawn_blocking`.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use tempfile::TempDir;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitExecError {
    #[error("git command failed: {command}\nstderr: {stderr}")]
    CommandFailed { command: String, stderr: String },
    #[error("failed to spawn git: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("failed to create temporary directory: {0}")]
    TempDir(String),
}

/// Result of a successful commit + push operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCommitResult {
    pub commit_sha: String,
}

/// Builds the `http.extraHeader` value for git token authentication.
/// Uses HTTP Basic auth with "forge-mcp" as the username.
fn auth_header(token: &str) -> String {
    let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("forge-mcp:{token}"));
    format!("Authorization: Basic {credentials}")
}

/// A workspace backed by a temporary directory for git operations.
pub struct GitWorkspace {
    _temp_dir: TempDir,
    repo_path: PathBuf,
    auth_env: Vec<(String, String)>,
}

impl GitWorkspace {
    /// Clones a repository into a temporary directory.
    ///
    /// The `base_branch` parameter specifies which branch to check out.
    /// Authentication is handled via `http.extraHeader` environment
    /// variables — the token never appears in process arguments or URLs.
    ///
    /// # Errors
    ///
    /// Returns an error if cloning fails.
    pub fn clone_repo(
        clone_url: &str,
        base_branch: &str,
        token: Option<&str>,
    ) -> Result<Self, GitExecError> {
        let temp_dir =
            TempDir::new().map_err(|e| GitExecError::TempDir(e.to_string()))?;
        let repo_path = temp_dir.path().join("repo");

        // Build auth environment variables using git config env mechanism.
        // GIT_CONFIG_COUNT + GIT_CONFIG_KEY_N + GIT_CONFIG_VALUE_N sets
        // http.extraHeader without touching argv or the URL.
        let auth_env: Vec<(String, String)> = if let Some(token) = token {
            vec![
                ("GIT_CONFIG_COUNT".to_string(), "1".to_string()),
                ("GIT_CONFIG_KEY_0".to_string(), "http.extraHeader".to_string()),
                ("GIT_CONFIG_VALUE_0".to_string(), auth_header(token)),
            ]
        } else {
            Vec::new()
        };

        run_git(
            temp_dir.path(),
            &["clone", "--branch", base_branch, "--depth=1", clone_url, "repo"],
            &auth_env,
        )?;

        Ok(Self {
            _temp_dir: temp_dir,
            repo_path,
            auth_env,
        })
    }

    /// Creates a new branch from the current HEAD (which is base_branch).
    ///
    /// # Errors
    ///
    /// Returns an error if branch creation fails.
    pub fn create_branch(&self, branch_name: &str) -> Result<(), GitExecError> {
        run_git(
            &self.repo_path,
            &["checkout", "-b", branch_name],
            &self.auth_env,
        )
        .map(|_| ())
    }

    /// Applies a unified diff patch to the working directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the patch cannot be applied.
    pub fn apply_patch(&self, patch: &str) -> Result<(), GitExecError> {
        run_git_with_stdin(
            &self.repo_path,
            &["apply", "--index", "-"],
            patch,
            &self.auth_env,
        )
        .map(|_| ())
    }

    /// Creates a commit with the given message.
    ///
    /// # Errors
    ///
    /// Returns an error if the commit fails.
    pub fn commit(
        &self,
        message: &str,
        author_name: &str,
        author_email: &str,
    ) -> Result<GitCommitResult, GitExecError> {
        run_git(
            &self.repo_path,
            &[
                "-c", &format!("user.name={author_name}"),
                "-c", &format!("user.email={author_email}"),
                "commit",
                "-m", message,
            ],
            &self.auth_env,
        )?;

        let sha = run_git(
            &self.repo_path,
            &["rev-parse", "HEAD"],
            &self.auth_env,
        )?;

        Ok(GitCommitResult {
            commit_sha: sha.trim().to_string(),
        })
    }

    /// Pushes the current branch to the remote.
    ///
    /// # Errors
    ///
    /// Returns an error if the push fails.
    pub fn push_branch(&self, branch_name: &str) -> Result<(), GitExecError> {
        run_git(
            &self.repo_path,
            &["push", "-u", "origin", branch_name],
            &self.auth_env,
        )
        .map(|_| ())
    }
}

fn run_git(
    cwd: &Path,
    args: &[&str],
    extra_env: &[(String, String)],
) -> Result<String, GitExecError> {
    let mut cmd = Command::new("git");
    cmd.current_dir(cwd).args(args);
    cmd.env("GIT_TERMINAL_PROMPT", "0");

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(GitExecError::CommandFailed {
            command: format!("git {}", args.join(" ")),
            stderr,
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_git_with_stdin(
    cwd: &Path,
    args: &[&str],
    stdin_data: &str,
    extra_env: &[(String, String)],
) -> Result<String, GitExecError> {
    use std::io::Write;
    use std::process::Stdio;

    let mut cmd = Command::new("git");
    cmd.current_dir(cwd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.env("GIT_TERMINAL_PROMPT", "0");

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_data.as_bytes())
            .map_err(GitExecError::Spawn)?;
    }

    let output = child.wait_with_output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(GitExecError::CommandFailed {
            command: format!("git {}", args.join(" ")),
            stderr,
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_header_encodes_correctly() {
        let header = auth_header("test-token");
        assert!(header.starts_with("Authorization: Basic "));
        let encoded = header.strip_prefix("Authorization: Basic ").unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "forge-mcp:test-token");
    }

    #[test]
    fn full_workflow_with_local_repo() {
        let empty_env = Vec::new();

        // Create a bare "remote" repo
        let remote_dir = TempDir::new().unwrap();
        run_git(remote_dir.path(), &["init", "--bare", "remote.git"], &empty_env).unwrap();
        let remote_path = remote_dir.path().join("remote.git");

        // Create initial commit in a working copy
        let init_dir = TempDir::new().unwrap();
        let init_path = init_dir.path().join("work");
        run_git(
            init_dir.path(),
            &["clone", remote_path.to_str().unwrap(), "work"],
            &empty_env,
        )
        .unwrap();
        std::fs::write(init_path.join("README.md"), "# Hello\n").unwrap();
        run_git(&init_path, &["add", "README.md"], &empty_env).unwrap();
        run_git(
            &init_path,
            &["-c", "user.name=Test", "-c", "user.email=test@test", "commit", "-m", "init"],
            &empty_env,
        )
        .unwrap();
        run_git(&init_path, &["push", "-u", "origin", "HEAD:main"], &empty_env).unwrap();

        // Now test our workspace — clone from base_branch "main"
        let workspace = GitWorkspace::clone_repo(
            &format!("file://{}", remote_path.display()),
            "main",
            None,
        )
        .unwrap();

        workspace.create_branch("agent/test-branch").unwrap();

        let patch = "\
diff --git a/README.md b/README.md
index 7e59600..1234567 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 # Hello
+World
";
        workspace.apply_patch(patch).unwrap();

        let result = workspace
            .commit("test: add world", "Test Agent", "agent@test")
            .unwrap();
        assert!(!result.commit_sha.is_empty());

        workspace.push_branch("agent/test-branch").unwrap();

        // Verify the branch exists on the remote
        let branches = run_git(&remote_path, &["branch"], &empty_env).unwrap();
        assert!(branches.contains("agent/test-branch"));
    }
}
```

- [ ] **Step 3: Run checks**

Run: `cargo fmt && cargo build --all-features --all-targets && cargo test --all-features --all-targets && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings`
Expected: All pass, including the integration test with local git repos.

- [ ] **Step 4: Commit**

```bash
git add git-exec/Cargo.toml git-exec/src/lib.rs
git commit -m "git-exec: implement CLI-based git operations for write workflow

Shell out to git CLI for clone, branch, apply, commit, and push.
HTTPS-only with token injection into clone URL. Operations run in
ephemeral temporary directories.

Includes integration test with local bare repo for the full
clone -> branch -> apply -> commit -> push workflow."
```

---

### Task 5: Extend forge adapter with write operations

**Files:**
- Modify: `forge/src/lib.rs`

Add methods to `ForgeAdapter` trait for creating change requests and listing/getting them. Implement for Forgejo.

- [ ] **Step 1: Add serde_json dependency to forge/Cargo.toml**

Add to `[dependencies]`:
```toml
serde_json = "1.0.149"
```

- [ ] **Step 2: Add domain types to forge imports**

Update the domain import in `forge/src/lib.rs`:
```rust
use domain::{ChangeRequest, ChangeRequestState, ReadRepositoryFileResponse, RepositoryRef};
```

- [ ] **Step 3: Extend ForgeAdapter trait**

Add these methods to the `ForgeAdapter` trait:

```rust
    /// Creates a change request (pull request) on the forge.
    async fn create_change_request(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        head_branch: &str,
        base_branch: &str,
    ) -> Result<ChangeRequest, ForgeError>;

    /// Lists change requests for a repository.
    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
    ) -> Result<Vec<ChangeRequest>, ForgeError>;

    /// Gets a single change request by index.
    async fn get_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
    ) -> Result<ChangeRequest, ForgeError>;
```

- [ ] **Step 4: Add Forgejo API response types**

Add after `ForgejoContentsResponse`:

```rust
#[derive(Debug, Deserialize)]
struct ForgejoPullRequest {
    base: ForgejoPullBranch,
    body: Option<String>,
    head: ForgejoPullBranch,
    html_url: String,
    number: u64,
    state: String,
    title: String,
}

#[derive(Debug, Deserialize)]
struct ForgejoPullBranch {
    #[serde(rename = "ref")]
    ref_name: String,
}

impl ForgejoPullRequest {
    fn into_change_request(self) -> ChangeRequest {
        let state = match self.state.as_str() {
            "closed" => ChangeRequestState::Closed,
            "open" => ChangeRequestState::Open,
            _ => ChangeRequestState::Merged,
        };
        ChangeRequest {
            base_branch: self.base.ref_name,
            body: self.body.unwrap_or_default(),
            head_branch: self.head.ref_name,
            index: self.number,
            state,
            title: self.title,
            url: self.html_url,
        }
    }
}
```

- [ ] **Step 5: Implement the new trait methods for ForgejoAdapter**

Add the implementations inside the existing `#[async_trait] impl ForgeAdapter for ForgejoAdapter` block:

```rust
    async fn create_change_request(
        &self,
        repository: &RepositoryRef,
        title: &str,
        body: &str,
        head_branch: &str,
        base_branch: &str,
    ) -> Result<ChangeRequest, ForgeError> {
        if repository.forge != domain::ForgeKind::Forgejo {
            return Err(ForgeError::UnsupportedForge(repository.forge.clone()));
        }

        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut request = self.client.post(&url).json(&serde_json::json!({
            "base": base_branch,
            "body": body,
            "head": head_branch,
            "title": title,
        }));
        if let Some(token) = &self.config.token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }

    async fn list_change_requests(
        &self,
        repository: &RepositoryRef,
        state: Option<&ChangeRequestState>,
    ) -> Result<Vec<ChangeRequest>, ForgeError> {
        if repository.forge != domain::ForgeKind::Forgejo {
            return Err(ForgeError::UnsupportedForge(repository.forge.clone()));
        }

        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let state_str = state.map(|s| match s {
            ChangeRequestState::Closed => "closed",
            ChangeRequestState::Merged => "closed",
            ChangeRequestState::Open => "open",
        });

        let mut request = self.client.get(&url);
        if let Some(state_str) = state_str {
            request = request.query(&[("state", state_str)]);
        }
        if let Some(token) = &self.config.token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let prs: Vec<ForgejoPullRequest> = response.json().await?;
        Ok(prs.into_iter().map(ForgejoPullRequest::into_change_request).collect())
    }

    async fn get_change_request(
        &self,
        repository: &RepositoryRef,
        index: u64,
    ) -> Result<ChangeRequest, ForgeError> {
        if repository.forge != domain::ForgeKind::Forgejo {
            return Err(ForgeError::UnsupportedForge(repository.forge.clone()));
        }

        let url = format!(
            "{}/api/v1/repos/{}/{}/pulls/{index}",
            self.config.base_url.trim_end_matches('/'),
            repository.owner,
            repository.name,
        );

        let mut request = self.client.get(&url);
        if let Some(token) = &self.config.token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ForgeError::UnexpectedStatus { status, body });
        }

        let pr: ForgejoPullRequest = response.json().await?;
        Ok(pr.into_change_request())
    }
```

- [ ] **Step 6: Update the FakeForgeAdapter in orchestrator tests**

The orchestrator tests have a `FakeForgeAdapter` that needs stubs for the new trait methods. Add to the `FakeForgeAdapter` impl:

```rust
        async fn create_change_request(
            &self,
            _repository: &RepositoryRef,
            _title: &str,
            _body: &str,
            _head_branch: &str,
            _base_branch: &str,
        ) -> Result<domain::ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&domain::ChangeRequestState>,
        ) -> Result<Vec<domain::ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
        ) -> Result<domain::ChangeRequest, ForgeError> {
            unimplemented!()
        }
```

Do the same for `FailingForgeAdapter`.

- [ ] **Step 7: Run checks**

Run: `cargo fmt && cargo build --all-features --all-targets && cargo test --all-features --all-targets && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings`
Expected: All pass.

- [ ] **Step 8: Commit**

```bash
git add forge/Cargo.toml forge/src/lib.rs orchestrator/src/lib.rs
git commit -m "forge: extend ForgeAdapter with change request operations

Add create_change_request, list_change_requests, and get_change_request
to ForgeAdapter trait. Implement all three for ForgejoAdapter using the
Forgejo pulls API. Add Forgejo pull request response deserialization.

Update test fakes in orchestrator with stubs for new trait methods."
```

---

## Chunk 3: Write Orchestrator and MCP Tools

### Task 6: Implement write orchestrator

**Files:**
- Modify: `orchestrator/Cargo.toml` (add git-exec, domain deps for policy/diff)
- Modify: `orchestrator/src/lib.rs`

The write orchestrator composes: diff validation -> policy evaluation -> audit intent -> git-exec (clone base_branch, create branch, apply, commit, push) -> forge adapter. Policy is enforced on both `commit_patch` and `open_change_request`. The forge token is threaded through to git-exec for authenticated push.

- [ ] **Step 1: Update orchestrator/Cargo.toml**

Add to `[dependencies]`:
```toml
git-exec = { version = "0.1.0", path = "../git-exec" }
```

- [ ] **Step 2: Add WriteOrchestrator to orchestrator/src/lib.rs**

Add after the `ReadOrchestrator` implementation (before the `#[cfg(test)]` block):

```rust
pub struct WriteOrchestrator<A, S>
where
    A: ForgeAdapter,
    S: AuditSink,
{
    adapter: Arc<A>,
    audit_sink: Arc<S>,
    forge_token: Option<String>,
    policy_config: domain::policy::PolicyConfig,
}

impl<A, S> WriteOrchestrator<A, S>
where
    A: ForgeAdapter + 'static,
    S: AuditSink + 'static,
{
    #[must_use]
    pub fn new(
        adapter: Arc<A>,
        audit_sink: Arc<S>,
        forge_token: Option<String>,
        policy_config: domain::policy::PolicyConfig,
    ) -> Self {
        Self {
            adapter,
            audit_sink,
            forge_token,
            policy_config,
        }
    }
}

#[async_trait]
impl<A, S> domain::RepositoryWriteService for WriteOrchestrator<A, S>
where
    A: ForgeAdapter + 'static,
    S: AuditSink + 'static,
{
    async fn commit_patch(
        &self,
        request: domain::CommitPatchRequest,
    ) -> Result<domain::CommitPatchResponse, ServiceError> {
        // 1. Validate the diff
        let diff_result = domain::diff::validate_diff(&request.patch)
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        let touched_paths: Vec<String> = diff_result.files.iter().map(|f| f.path.clone()).collect();

        // 2. Evaluate policy
        let policy_context = domain::policy::PolicyContext {
            action: "commit_patch".to_string(),
            agent: request.agent.clone(),
            repository: request.repository.clone(),
            target_branch: request.new_branch.clone(),
            touched_paths,
        };
        let decision = domain::policy::evaluate(&self.policy_config, &policy_context)
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        if !decision.is_allowed() {
            return Err(ServiceError::PolicyDenied {
                reasons: decision.reasons.join("; "),
            });
        }

        // 3. Audit intent
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent.clone(),
                action: "commit_patch".to_string(),
                repository: request.repository.clone(),
                target: request.new_branch.clone(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // 4. Execute git operations (behind spawn_blocking)
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
            let workspace = git_exec::GitWorkspace::clone_repo(
                &clone_url,
                &base_branch,
                token.as_deref(),
            )?;
            workspace.create_branch(&new_branch)?;
            workspace.apply_patch(&patch)?;
            let result = workspace.commit(
                &commit_message,
                &agent_id,
                &format!("{agent_id}@forge-mcp"),
            )?;
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

    async fn open_change_request(
        &self,
        request: domain::OpenChangeRequestRequest,
    ) -> Result<domain::OpenChangeRequestResponse, ServiceError> {
        // 1. Evaluate policy — enforce branch constraints
        let policy_context = domain::policy::PolicyContext {
            action: "open_change_request".to_string(),
            agent: request.agent.clone(),
            repository: request.repository.clone(),
            target_branch: request.head_branch.clone(),
            touched_paths: Vec::new(), // No diff to validate for PR creation
        };
        let decision = domain::policy::evaluate(&self.policy_config, &policy_context)
            .map_err(|e| ServiceError::Validation(e.to_string()))?;

        if !decision.is_allowed() {
            return Err(ServiceError::PolicyDenied {
                reasons: decision.reasons.join("; "),
            });
        }

        // 2. Audit intent
        self.audit_sink
            .record(AuditRecord {
                agent: request.agent.clone(),
                action: "open_change_request".to_string(),
                repository: request.repository.clone(),
                target: request.head_branch.clone(),
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        // 3. Create on forge
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
}
```

- [ ] **Step 3: Add write orchestrator tests**

Add to the existing `#[cfg(test)] mod tests` block (add the necessary imports and fakes):

```rust
    use domain::{
        ChangeRequest, ChangeRequestState, CommitPatchRequest, RepositoryWriteService,
    };

    // Add to existing FakeForgeAdapter impl:
    // (update the create_change_request stub to return a value)

    struct WriteTestForgeAdapter;

    #[async_trait::async_trait]
    impl ForgeAdapter for WriteTestForgeAdapter {
        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            unimplemented!()
        }

        async fn create_change_request(
            &self,
            repository: &RepositoryRef,
            title: &str,
            body: &str,
            head_branch: &str,
            base_branch: &str,
        ) -> Result<ChangeRequest, ForgeError> {
            Ok(ChangeRequest {
                base_branch: base_branch.to_string(),
                body: body.to_string(),
                head_branch: head_branch.to_string(),
                index: 1,
                state: ChangeRequestState::Open,
                title: title.to_string(),
                url: format!(
                    "https://forge.example/{}/{}/pulls/1",
                    repository.owner, repository.name
                ),
            })
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }
    }

    fn write_test_request() -> CommitPatchRequest {
        CommitPatchRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            base_branch: "main".to_string(),
            commit_message: "test commit".to_string(),
            new_branch: "agent/test-fix".to_string(),
            patch: "\
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 # Hello
+World
"
            .to_string(),
            repository: RepositoryRef {
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                owner: "org".to_string(),
                name: "repo".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn commit_patch_rejects_invalid_diff() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let config = domain::policy::PolicyConfig::default();
        let orchestrator =
            super::WriteOrchestrator::new(adapter, Arc::clone(&audit), None, config);

        let mut request = write_test_request();
        request.patch = "Binary files differ\n".to_string();

        let err = orchestrator
            .commit_patch(request)
            .await
            .expect_err("binary diff should be rejected");
        assert!(matches!(err, ServiceError::Validation(_)));
    }

    #[tokio::test]
    async fn commit_patch_rejects_wrong_branch_prefix() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let config = domain::policy::PolicyConfig::default();
        let orchestrator =
            super::WriteOrchestrator::new(adapter, Arc::clone(&audit), None, config);

        let mut request = write_test_request();
        request.new_branch = "main".to_string();

        let err = orchestrator
            .commit_patch(request)
            .await
            .expect_err("wrong branch prefix should be denied");
        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
    }

    #[tokio::test]
    async fn commit_patch_rejects_protected_paths() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let config = domain::policy::PolicyConfig::default();
        let orchestrator =
            super::WriteOrchestrator::new(adapter, Arc::clone(&audit), None, config);

        let mut request = write_test_request();
        request.patch = "\
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1 +1,2 @@
 name: CI
+new line
"
        .to_string();

        let err = orchestrator
            .commit_patch(request)
            .await
            .expect_err("protected path should be denied");
        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
    }

    #[tokio::test]
    async fn open_change_request_rejects_wrong_branch_prefix() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let config = domain::policy::PolicyConfig::default();
        let orchestrator =
            super::WriteOrchestrator::new(adapter, Arc::clone(&audit), None, config);

        let request = domain::OpenChangeRequestRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            base_branch: "main".to_string(),
            body: "Fix things".to_string(),
            head_branch: "unauthorized-branch".to_string(),
            repository: RepositoryRef {
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                owner: "org".to_string(),
                name: "repo".to_string(),
            },
            title: "Fix typo".to_string(),
        };

        let err = orchestrator
            .open_change_request(request)
            .await
            .expect_err("wrong branch prefix should be denied");
        assert!(matches!(err, ServiceError::PolicyDenied { .. }));
        // No audit recorded because policy denied before audit
        assert_eq!(audit.records().len(), 0);
    }

    #[tokio::test]
    async fn open_change_request_records_audit_and_creates() {
        let adapter = Arc::new(WriteTestForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let config = domain::policy::PolicyConfig::default();
        let orchestrator =
            super::WriteOrchestrator::new(adapter, Arc::clone(&audit), None, config);

        let request = domain::OpenChangeRequestRequest {
            agent: AgentIdentity {
                agent_id: "test-agent".to_string(),
                session_id: "test-session".to_string(),
            },
            base_branch: "main".to_string(),
            body: "Fix things".to_string(),
            head_branch: "agent/fix".to_string(),
            repository: RepositoryRef {
                forge: ForgeKind::Forgejo,
                host: "https://forge.example".to_string(),
                owner: "org".to_string(),
                name: "repo".to_string(),
            },
            title: "Fix typo".to_string(),
        };

        let response = orchestrator
            .open_change_request(request)
            .await
            .expect("should succeed");

        assert_eq!(response.change_request.index, 1);
        assert_eq!(response.change_request.title, "Fix typo");
        assert_eq!(audit.records().len(), 1);
    }
```

- [ ] **Step 4: Run checks**

Run: `cargo fmt && cargo build --all-features --all-targets && cargo test --all-features --all-targets && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings`
Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/Cargo.toml orchestrator/src/lib.rs
git commit -m "orchestrator: add write workflow with policy and diff validation

WriteOrchestrator composes diff validation, policy evaluation, audit,
git-exec, and forge adapter into the commit_patch and open_change_request
workflows. Policy denials are type-distinct from infrastructure errors.

Includes tests for diff rejection, branch prefix denial, protected path
denial, and successful change request creation with audit."
```

---

### Task 7: Add write-path MCP tools to transport

**Files:**
- Modify: `transport/src/lib.rs`

Expose `commit_patch` and `open_change_request` as MCP tools.

- [ ] **Step 1: Update transport to accept both read and write services**

The `ForgejoMcpServer` needs a write service in addition to the read service. Update the struct to be generic over both:

Change the struct and constructor to accept an optional write service:

```rust
pub struct ForgejoMcpServer<R, W>
where
    R: RepositoryReadService + 'static,
    W: RepositoryWriteService + 'static,
{
    config: ForgejoMcpConfig,
    read_service: Arc<R>,
    write_service: Arc<W>,
    tool_router: ToolRouter<Self>,
}
```

Update all the impl blocks, `ServerHandler`, `tool_router`, `serve_stdio`, etc. to use both type parameters.

- [ ] **Step 2: Add MCP tool input types**

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommitPatchTool {
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Base branch to create from (e.g. "main").
    pub base_branch: String,
    /// New branch name (must start with "agent/").
    pub new_branch: String,
    /// Unified diff patch to apply.
    pub patch: String,
    /// Commit message.
    pub commit_message: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenChangeRequestTool {
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Base branch for the change request.
    pub base_branch: String,
    /// Head branch with the changes.
    pub head_branch: String,
    /// Title of the change request.
    pub title: String,
    /// Description body.
    pub body: String,
}
```

- [ ] **Step 3: Add the tool implementations in the tool_router block**

```rust
    #[tool(
        name = "commit_patch",
        description = "Apply a unified diff patch to a new branch and push it."
    )]
    async fn commit_patch(
        &self,
        Parameters(request): Parameters<CommitPatchTool>,
    ) -> Result<String, McpError> {
        let response = self
            .write_service
            .commit_patch(domain::CommitPatchRequest {
                agent: AgentIdentity {
                    agent_id: self.config.agent_id.clone(),
                    session_id: self.config.session_id.clone(),
                },
                base_branch: request.base_branch,
                commit_message: request.commit_message,
                new_branch: request.new_branch,
                patch: request.patch,
                repository: RepositoryRef {
                    forge: ForgeKind::Forgejo,
                    host: self.config.forgejo_base_url.clone(),
                    owner: request.owner,
                    name: request.repo,
                },
            })
            .await
            .map_err(Self::map_service_error)?;
        Ok(format!(
            "Committed to branch '{}' at {}",
            response.branch, response.commit_sha
        ))
    }

    #[tool(
        name = "open_change_request",
        description = "Open a change request (pull request) on the forge."
    )]
    async fn open_change_request(
        &self,
        Parameters(request): Parameters<OpenChangeRequestTool>,
    ) -> Result<String, McpError> {
        let response = self
            .write_service
            .open_change_request(domain::OpenChangeRequestRequest {
                agent: AgentIdentity {
                    agent_id: self.config.agent_id.clone(),
                    session_id: self.config.session_id.clone(),
                },
                base_branch: request.base_branch,
                body: request.body,
                head_branch: request.head_branch,
                repository: RepositoryRef {
                    forge: ForgeKind::Forgejo,
                    host: self.config.forgejo_base_url.clone(),
                    owner: request.owner,
                    name: request.repo,
                },
                title: request.title,
            })
            .await
            .map_err(Self::map_service_error)?;
        Ok(format!(
            "Change request #{} created: {}",
            response.change_request.index, response.change_request.url
        ))
    }
```

- [ ] **Step 4: Update map_service_error for new variants**

```rust
    fn map_service_error(error: ServiceError) -> McpError {
        match error {
            ServiceError::Validation(message) => McpError::invalid_params(message, None),
            ServiceError::PolicyDenied { reasons } => {
                McpError::invalid_params(format!("policy denied: {reasons}"), None)
            }
            ServiceError::Audit(message)
            | ServiceError::GitExec(message)
            | ServiceError::Upstream(message) => McpError::internal_error(message, None),
        }
    }
```

- [ ] **Step 5: Update transport tests**

Update the test fakes to implement both `RepositoryReadService` and `RepositoryWriteService`. Update `spawn_server_and_client` and related test infrastructure.

- [ ] **Step 6: Run checks**

Run: `cargo fmt && cargo build --all-features --all-targets && cargo test --all-features --all-targets && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings`
Expected: All pass.

- [ ] **Step 7: Commit**

```bash
git add transport/src/lib.rs
git commit -m "transport: add commit_patch and open_change_request MCP tools

Expose write workflow through MCP. Policy denials map to
invalid_params, git/upstream errors map to internal_error.
Transport remains wiring-only with no business logic."
```

---

### Task 8: Wire write services in server

**Files:**
- Modify: `server/Cargo.toml`
- Modify: `server/src/main.rs`

Connect the `WriteOrchestrator` to the transport layer.

- [ ] **Step 1: Add domain dependency to server/Cargo.toml**

```toml
domain = { version = "0.1.0", path = "../domain" }
git-exec = { version = "0.1.0", path = "../git-exec" }
```

- [ ] **Step 2: Update server/src/main.rs**

Wire up the `WriteOrchestrator` alongside the existing `ReadOrchestrator`:

```rust
use std::{env, sync::Arc};

use audit::InMemoryAuditSink;
use domain::policy::PolicyConfig;
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use transport::{ForgejoMcpConfig, serve_stdio};

fn server_version() -> String {
    format!("{}+{}", env!("CARGO_PKG_VERSION"), env!("GIT_COMMIT_SHORT"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let forgejo_base_url = env::var("FORGEJO_BASE_URL")
        .expect("FORGEJO_BASE_URL environment variable must be set");
    let forgejo_token = env::var("FORGEJO_TOKEN").ok();
    let agent_id = env::var("FORGE_MCP_AGENT_ID").unwrap_or_else(|_| "codex".to_string());
    let session_id =
        env::var("FORGE_MCP_SESSION_ID").unwrap_or_else(|_| "stdio-session".to_string());

    let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
        base_url: forgejo_base_url.clone(),
        token: forgejo_token,
    }));
    let audit_sink = Arc::new(InMemoryAuditSink::new());
    let policy_config = PolicyConfig::default();

    let read_service = Arc::new(ReadOrchestrator::new(
        Arc::clone(&adapter),
        Arc::clone(&audit_sink),
    ));
    let write_service = Arc::new(WriteOrchestrator::new(
        Arc::clone(&adapter),
        Arc::clone(&audit_sink),
        forgejo_token.clone(),
        policy_config,
    ));

    let config = ForgejoMcpConfig {
        forgejo_base_url,
        agent_id,
        session_id,
        server_name: "forge-mcp".to_string(),
        server_version: server_version(),
    };

    serve_stdio(config, read_service, write_service).await?;
    Ok(())
}
```

- [ ] **Step 3: Run checks**

Run: `cargo fmt && cargo build --all-features --all-targets && cargo test --all-features --all-targets && cargo clippy --all-features --all-targets --no-deps -- -D clippy::pedantic -D warnings`
Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add server/Cargo.toml server/src/main.rs
git commit -m "server: wire write orchestrator into MCP server

Connect WriteOrchestrator with default policy config to the
transport layer. Server remains wiring-only with no business logic."
```

---

### Task 9: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README with Phase 2 status**

Update the current status and add the new MCP tools to the documentation.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README for Phase 2 write workflow"
```

---

## Summary

| Task | Component | New Tests |
|------|-----------|-----------|
| 1 | Domain write types + ServiceError + WriteService trait | 0 (types only) |
| 2 | Diff validation module | ~12 |
| 3 | Policy engine module | 7 |
| 4 | git-exec CLI implementation | 3 |
| 5 | Forge adapter write methods | 0 (integration-tested via orchestrator) |
| 6 | Write orchestrator | 5 |
| 7 | MCP transport write tools | updates to existing |
| 8 | Server wiring | 0 (wiring only) |
| 9 | README | 0 |

**Total new tests:** ~27
**Total tasks:** 9
**Estimated commits:** 9

Tasks 1-3 can be parallelized (no dependencies between them). Task 4 is independent. Task 5 depends on Task 1. Task 6 depends on Tasks 1-5. Tasks 7-8 depend on Task 6. Task 9 is last.
