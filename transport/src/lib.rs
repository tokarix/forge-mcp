//! MCP shim — translates MCP tool calls into HTTP requests to the control plane.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CustomNotification, Implementation, ServerCapabilities, ServerInfo, ServerNotification,
    },
    service::{NotificationContext, RoleServer},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::de;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Deserializes a `u64` from either a JSON number or a string containing a
/// number. LLMs frequently send `"5"` instead of `5` for integer tool
/// parameters.
fn deserialize_u64_lenient<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct U64LenientVisitor;

    impl de::Visitor<'_> for U64LenientVisitor {
        type Value = u64;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a u64 or a string containing a u64")
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom(format!("negative value: {v}")))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
            v.parse().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(U64LenientVisitor)
}

/// Configuration for a single gateway.
#[derive(Clone)]
pub struct GatewayConfig {
    /// Human-readable name for this gateway.
    pub name: String,
    /// Bearer token for authentication.
    pub token: String,
    /// Base URL of the gateway (e.g. `https://forge-mcp.example:8443`).
    pub url: String,
}

impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("name", &self.name)
            .field("token", &"[REDACTED]")
            .field("url", &self.url)
            .finish()
    }
}

/// Configuration for the MCP shim.
#[derive(Clone, Debug)]
pub struct ShimConfig {
    pub channel_startup_spike: bool,
    pub enable_channels: bool,
    pub gateways: Vec<GatewayConfig>,
    pub read_only: bool,
    pub server_name: String,
    pub server_version: String,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("mcp server initialization failed: {0}")]
    Initialize(Box<rmcp::service::ServerInitializeError>),
    #[error("mcp server task failed: {0}")]
    Runtime(#[from] tokio::task::JoinError),
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddIssueDependencyTool {
    /// Index of the issue that this issue depends on (the blocking issue).
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub dependency: u64,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddIssueLabelTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Label name to add. The label will be created on the repository if it
    /// does not already exist.
    pub label: String,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AssignIssueTool {
    /// User to assign the issue to.
    pub assignee: String,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloseChangeRequestTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloseIssueTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommentOnChangeRequestTool {
    /// Comment text.
    pub body: String,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommentOnIssueTool {
    /// Comment body text.
    pub body: String,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommitPatchTool {
    /// Optional commit author email. If omitted, the shim will try to use the
    /// local git author identity.
    pub author_email: Option<String>,
    /// Optional commit author name. If omitted, the shim will try to use the
    /// local git author identity.
    pub author_name: Option<String>,
    /// Base branch to create from (e.g. "main").
    pub base_branch: String,
    /// Commit message.
    pub commit_message: String,
    /// Set to true to push to an existing branch instead of creating a new one.
    /// Requires a configured `branch_prefix` in the agent's policy.
    #[serde(default)]
    pub existing_branch: bool,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// New branch name (must start with "agent/").
    pub new_branch: String,
    /// Repository owner or organization.
    pub owner: String,
    /// Git-format patch to apply. Must be produced by `git diff` or `git show`
    /// and begin with `diff --git`; traditional unified diffs are rejected.
    /// The patch must be generated from a repository with the correct history
    /// (e.g., your workspace clone or worktree). DO NOT generate patches from a newly
    /// `git init`ed directory or a fake repository, as they will be rejected.
    /// Provide either this or `patch_file`.
    pub patch: Option<String>,
    /// Path to a file containing a git-format patch. Use this instead of
    /// `patch` for large diffs that may exceed tool parameter limits.
    pub patch_file: Option<String>,
    /// Repository name.
    pub repo: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommitAuthor {
    email: String,
    name: String,
}

fn parse_git_author_ident(output: &str) -> Option<CommitAuthor> {
    let trimmed = output.trim();
    let email_end = trimmed.rfind('>')?;
    let email_start = trimmed[..email_end].rfind('<')?;
    let name = trimmed[..email_start].trim();
    let email = trimmed[email_start + 1..email_end].trim();
    if name.is_empty() || email.is_empty() {
        return None;
    }
    Some(CommitAuthor {
        email: email.to_string(),
        name: name.to_string(),
    })
}

fn discover_local_commit_author() -> Option<CommitAuthor> {
    let output = Command::new("git")
        .args(["var", "GIT_AUTHOR_IDENT"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    parse_git_author_ident(&stdout)
}

fn resolve_commit_author<F>(
    request: &CommitPatchTool,
    discover: F,
) -> Result<Option<CommitAuthor>, McpError>
where
    F: FnOnce() -> Option<CommitAuthor>,
{
    match (&request.author_name, &request.author_email) {
        (Some(name), Some(email)) => {
            let name = name.trim();
            let email = email.trim();
            if name.is_empty() || email.is_empty() {
                return Err(McpError::invalid_params(
                    "author_name and author_email must be non-empty when provided".to_string(),
                    None,
                ));
            }
            Ok(Some(CommitAuthor {
                email: email.to_string(),
                name: name.to_string(),
            }))
        }
        (None, None) => Ok(discover()),
        _ => Err(McpError::invalid_params(
            "author_name and author_email must be provided together".to_string(),
            None,
        )),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateIssueTool {
    /// Issue body text.
    pub body: String,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Issue title. Check for an existing open issue first to avoid duplicates.
    pub title: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetChangeRequestDiffTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetChangeRequestChecksTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request (pull request) index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetChangeRequestCiDetailsTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request (pull request) index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetChangeRequestCommentsTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetChangeRequestTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetIssueTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetIssueCommentsTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetIssueDependenciesTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListChangeRequestsTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Optional state filter: open, closed, merged.
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListIssuesTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Optional state filter: open, closed.
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListRepositoriesTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Optional owner or organization filter. Required when the agent's
    /// access is scoped to a specific owner (e.g. `alias/owner/*`).
    pub owner: Option<String>,
    /// Optional search query to filter repositories by name.
    pub query: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenChangeRequestTool {
    /// Base branch for the change request.
    pub base_branch: String,
    /// Description body.
    pub body: String,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
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
pub struct RebaseBranchTool {
    /// Base branch to compute merge-base against (e.g. "main").
    pub base_branch: String,
    /// Branch to rebase (must match your configured branch prefix).
    pub branch: String,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// List of rebase operations as JSON objects. Each object must have a
    /// `"type"` field. Supported: `{"type": "fixup", "commit": "<sha>", "into": "<sha>"}`,
    /// `{"type": "drop", "commit": "<sha>"}`,
    /// `{"type": "rebase_onto"}` (rebase all commits onto the latest base branch; must be the sole operation).
    pub operations: Vec<RebaseBranchOperationTool>,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RebaseBranchOperationTool {
    Drop {
        /// Full SHA of the commit to remove.
        commit: String,
    },
    Fixup {
        /// Full SHA of the commit to squash.
        commit: String,
        /// Full SHA of the commit to squash into.
        into: String,
    },
    /// Rebase all branch commits onto the latest base branch head.
    /// Must be the sole operation in the list.
    RebaseOnto {},
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadRepositoryFileTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Optional git ref such as a branch, tag, or commit SHA.
    pub git_ref: Option<String>,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository-relative file path.
    pub path: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveIssueDependencyTool {
    /// Index of the dependency issue to remove.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub dependency: u64,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RemoveIssueLabelTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Label name to remove.
    pub label: String,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScheduleAutoMergeTool {
    /// Optional override for whether to delete the source branch after merge.
    /// If omitted, the repository's default behavior is used.
    pub delete_branch_after_merge: Option<bool>,
    /// Expected head commit SHA -- prevents scheduling on a stale PR.
    pub expected_head_sha: String,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Merge style: rebase, rebase-merge, merge, squash, or fast-forward-only.
    pub merge_style: String,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Serialize)]
struct ScheduleAutoMergeBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    delete_branch_after_merge: Option<bool>,
    expected_head_sha: String,
    merge_style: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateChangeRequestTool {
    /// New PR body/description. Omit to leave unchanged.
    pub body: Option<String>,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// New PR title. Omit to leave unchanged.
    pub title: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateIssueTool {
    /// New issue body/description. Omit to leave unchanged.
    pub body: Option<String>,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Issue index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// New issue title. Omit to leave unchanged.
    pub title: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SubmitChangeRequestReviewTool {
    /// Review body text.
    pub body: String,
    /// Review event: `APPROVED`, `REQUEST_CHANGES`, or `COMMENT`.
    pub event: String,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
    #[serde(deserialize_with = "deserialize_u64_lenient")]
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ChannelEventMetaEnvelope {
    action: String,
    change_request: Option<u64>,
    delivery_id: String,
    event_kind: String,
    forge_alias: String,
    head_sha: Option<String>,
    issue: Option<u64>,
    issue_comment: Option<u64>,
    owner: String,
    repo: String,
    review_state: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AgentEventEnvelope {
    content: String,
    kind: String,
    meta: ChannelEventMetaEnvelope,
}

#[derive(Debug, Default)]
struct PendingSseEvent {
    data_lines: Vec<String>,
    id: Option<String>,
}

#[derive(Debug, Default)]
struct SseParser {
    buffer: Vec<u8>,
    pending: PendingSseEvent,
}

#[derive(Debug)]
struct SseEvent {
    data: String,
    id: Option<String>,
}

impl PendingSseEvent {
    fn process_line(&mut self, line: &str) -> Option<SseEvent> {
        if line.is_empty() {
            return self.finish();
        }
        if line.starts_with(':') {
            return None;
        }

        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };

        match field {
            "data" => self.data_lines.push(value.to_string()),
            "id" => self.id = Some(value.to_string()),
            _ => {}
        }

        None
    }

    fn finish(&mut self) -> Option<SseEvent> {
        if self.data_lines.is_empty() && self.id.is_none() {
            return None;
        }

        let event = SseEvent {
            data: self.data_lines.join("\n"),
            id: self.id.take(),
        };
        self.data_lines.clear();
        Some(event)
    }
}

impl SseParser {
    fn push_chunk(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buffer.extend_from_slice(chunk);

        let mut events = Vec::new();
        while let Some(newline_index) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line = self.buffer.drain(..=newline_index).collect::<Vec<_>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }

            let line = String::from_utf8_lossy(&line);
            if let Some(event) = self.pending.process_line(&line) {
                events.push(event);
            }
        }

        events
    }

    fn finish(&mut self) -> Option<SseEvent> {
        if !self.buffer.is_empty() {
            let line = String::from_utf8_lossy(&self.buffer).to_string();
            self.buffer.clear();
            if let Some(event) = self.pending.process_line(&line) {
                return Some(event);
            }
        }

        self.pending.finish()
    }
}

pub struct McpShim {
    client: reqwest::Client,
    config: ShimConfig,
    event_buffer: Arc<Mutex<VecDeque<AgentEventEnvelope>>>,
    event_forwarder_started: AtomicBool,
    tool_router: ToolRouter<Self>,
}

impl McpShim {
    #[must_use]
    pub fn new(config: ShimConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
            event_buffer: Arc::new(Mutex::new(VecDeque::new())),
            event_forwarder_started: AtomicBool::new(false),
            tool_router: Self::tool_router(),
        }
    }

    /// Return an error if the shim is in read-only mode.
    fn ensure_writable(&self) -> Result<(), McpError> {
        if self.config.read_only {
            return Err(McpError::invalid_params(
                "forge-mcp is in read-only mode: this write operation is disabled".to_string(),
                None,
            ));
        }
        Ok(())
    }

    /// Discover which forge aliases each gateway advertises and build the
    /// routing table.
    ///
    /// Unreachable gateways are logged and skipped so that one down gateway
    /// does not prevent routing to healthy ones.  Returns an error only if
    /// two reachable gateways claim the same alias.
    async fn discover_routes(&self) -> Result<HashMap<String, usize>, McpError> {
        let mut routes: HashMap<String, usize> = HashMap::new();
        for (index, gateway) in self.config.gateways.iter().enumerate() {
            let url = match Self::build_url(&gateway.url, &["api", "v1", "agent", "info"]) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(
                        gateway = gateway.name,
                        error = %e,
                        "skipping gateway with malformed URL during route discovery",
                    );
                    continue;
                }
            };
            let body = match self.gateway_get(url, &gateway.token).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        gateway = gateway.name,
                        error = %e,
                        "skipping unreachable gateway during route discovery",
                    );
                    continue;
                }
            };
            let info: serde_json::Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        gateway = gateway.name,
                        error = %e,
                        "skipping gateway with invalid discovery JSON",
                    );
                    continue;
                }
            };
            if let Some(forges) = info["forges"].as_array() {
                for forge in forges {
                    if let Some(alias) = forge["alias"].as_str() {
                        if let Some(existing_idx) = routes.get(alias).copied() {
                            return Err(McpError::internal_error(
                                format!(
                                    "ambiguous forge alias \'{}\': advertised by gateways \'{}\' and \'{}\'",
                                    alias, self.config.gateways[existing_idx].name, gateway.name,
                                ),
                                None,
                            ));
                        }
                        routes.insert(alias.to_string(), index);
                    }
                }
            }
        }
        Ok(routes)
    }

    /// Resolve a forge alias to the gateway that advertises it.
    ///
    /// Single-gateway configurations skip discovery entirely — all aliases
    /// route to the sole configured gateway.  Multi-gateway configurations
    /// discover routes on every call so that topology changes (added, removed,
    /// or moved forge aliases) and gateway recovery are picked up immediately.
    async fn resolve_gateway(&self, forge: &str) -> Result<&GatewayConfig, McpError> {
        if self.config.gateways.len() == 1 {
            return Ok(&self.config.gateways[0]);
        }

        let routes = self.discover_routes().await?;
        match routes.get(forge) {
            Some(&index) => Ok(&self.config.gateways[index]),
            None => Err(McpError::invalid_params(
                format!("unknown forge alias '{forge}': not advertised by any configured gateway"),
                None,
            )),
        }
    }

    /// Builds a URL by appending percent-encoded path segments to a gateway base URL.
    fn build_url(gateway_url: &str, segments: &[&str]) -> Result<reqwest::Url, McpError> {
        let mut base = gateway_url.to_string();
        if !base.ends_with('/') {
            base.push('/');
        }
        let mut url = reqwest::Url::parse(&base)
            .map_err(|e| McpError::internal_error(format!("invalid gateway URL: {e}"), None))?;
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| McpError::internal_error("cannot-be-a-base URL".to_string(), None))?;
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url)
    }

    /// Sends an HTTP response through the standard error-handling pipeline.
    fn map_http_error(status: reqwest::StatusCode, body: String) -> McpError {
        if status.as_u16() == 401 {
            McpError::invalid_params("authentication failed".to_string(), None)
        } else if status.is_client_error() {
            McpError::invalid_params(body, None)
        } else {
            McpError::internal_error(body, None)
        }
    }

    /// Makes an HTTP GET request to a gateway.
    async fn gateway_get(&self, url: reqwest::Url, token: &str) -> Result<String, McpError> {
        let response = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| McpError::internal_error(format!("HTTP request failed: {e}"), None))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| McpError::internal_error(format!("failed to read response: {e}"), None))?;

        if !status.is_success() {
            return Err(Self::map_http_error(status, body));
        }

        Ok(body)
    }

    /// Makes an HTTP DELETE request to a gateway.
    async fn gateway_delete(&self, url: reqwest::Url, token: &str) -> Result<String, McpError> {
        let response = self
            .client
            .delete(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| McpError::internal_error(format!("HTTP request failed: {e}"), None))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| McpError::internal_error(format!("failed to read response: {e}"), None))?;

        if !status.is_success() {
            return Err(Self::map_http_error(status, body));
        }

        Ok(body)
    }

    /// Makes an HTTP PATCH request to a gateway.
    async fn gateway_patch(
        &self,
        url: reqwest::Url,
        token: &str,
        json_body: &impl serde::Serialize,
    ) -> Result<String, McpError> {
        let response = self
            .client
            .patch(url)
            .bearer_auth(token)
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
            return Err(Self::map_http_error(status, body));
        }

        Ok(body)
    }

    /// Makes an HTTP POST request to a gateway.
    async fn gateway_post(
        &self,
        url: reqwest::Url,
        token: &str,
        json_body: &impl serde::Serialize,
    ) -> Result<String, McpError> {
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
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
            return Err(Self::map_http_error(status, body));
        }

        Ok(body)
    }

    async fn send_channel_notification(
        peer: &rmcp::service::Peer<RoleServer>,
        event: &AgentEventEnvelope,
    ) -> Result<(), rmcp::service::ServiceError> {
        peer.send_notification(ServerNotification::CustomNotification(
            CustomNotification::new(
                "notifications/claude/channel",
                Some(serde_json::json!({
                    "content": event.content,
                    "meta": {
                        "action": event.meta.action,
                        "change_request": event.meta.change_request,
                        "delivery_id": event.meta.delivery_id,
                        "event_kind": event.meta.event_kind,
                        "forge": event.meta.forge_alias,
                        "head_sha": event.meta.head_sha,
                        "issue": event.meta.issue,
                        "issue_comment": event.meta.issue_comment,
                        "owner": event.meta.owner,
                        "repo": event.meta.repo,
                        "review_state": event.meta.review_state,
                    }
                })),
            ),
        ))
        .await
    }

    fn channel_capabilities(&self) -> ServerCapabilities {
        let mut capabilities = ServerCapabilities::builder().enable_tools().build();
        if self.config.enable_channels {
            let mut experimental = rmcp::model::ExperimentalCapabilities::new();
            experimental.insert("claude/channel".to_string(), serde_json::Map::new());
            capabilities.experimental = Some(experimental);
        }
        capabilities
    }

    fn instructions(&self) -> String {
        let mut instructions = String::from(
            "MCP shim for forge-mcp control plane. Proxies tool calls to the HTTP API.\n\
             \n\
             ### Discovery & Identity\n\
             - Use `forge_info` FIRST to discover available forges, gateway URLs, git URL templates, branch prefixes, and auth details.\n\
             - Multi-gateway mode: Always call `forge_info` to map the `forge` alias to its correct gateway entry. \
               Use that gateway's specific git URL template for clone/fetch operations. \
               Do not assume a single global gateway URL when multiple gateways are configured.\n\
             - Repository Discovery: NOT supported. Repository `owner/repo` must come from user input, an existing local checkout / git remote, \
               issue or PR context, or other external context already available to the agent.\n\
             \n\
             ### Git Proxy (Read-Only)\n\
             - Each gateway provides a read-only git smart HTTP proxy for `clone` and `fetch` operations.\n\
             - URL: <gateway_url>/git/{forge}/{owner}/{repo}\n\
             - Auth: HTTP Basic -- any non-empty username, password is your agent token.\n\
             - `git push` is BLOCKED -- use the `commit_patch` tool instead.\n",
        );

        if self.config.gateways.len() == 1 {
            let gw_url = self.config.gateways[0].url.trim_end_matches('/');
            let _ = write!(
                instructions,
                "\nGateway: {gw_url}\n\
                 Git URL template: {gw_url}/git/{{forge}}/{{owner}}/{{repo}}\n",
            );
        } else {
            instructions.push_str("\nConfigured gateways:\n");
            for gw in &self.config.gateways {
                let gw_url = gw.url.trim_end_matches('/');
                let _ = writeln!(instructions, "- {}: {gw_url}", gw.name);
            }
        }

        instructions.push_str(
            "\n\
             ### Write Workflow\n\
             1. **Detached Worktree**: Always work in a detached `git worktree` instead of editing in the main checkout. \
                This keeps the main working tree clean and prevents unrelated changes from being included in patches.\n\
             2. **Generate Patch**: Use git itself (`git diff --no-ext-diff --binary` or `git show`) to produce a `diff --git` format patch. \
                Never hand-write traditional unified diffs.\n\
             3. **Submit**: Use `commit_patch` to apply and push the patch to a branch matching your configured `branch_prefix` (never commit to the default branch directly). \
                The server validates the patch and applies it in a clean clone of the base branch — do NOT run `git apply --check` locally (it will fail because your worktree already contains the changes).\n\
             4. **Open PR**: Use `open_change_request` for the initial PR.\n\
             5. **Update PR**: Push follow-up fixes to the existing branch using `commit_patch(existing_branch=true)`. Do NOT open duplicate PRs.\n\
             6. **Refine**: Use `rebase_branch` for squash/fixup operations on your branch after review feedback.\n",
        );

        if self.config.enable_channels {
            instructions.push_str(
                "\n\
                 ### Channel Events\n\
                 Channel events arrive as review triggers. Always fetch authoritative state with `get_change_request` tools before acting. \
                 If the current PR head differs from the event `head_sha`, treat the event as stale and skip it. \
                 If you already reviewed the same `head_sha` in this session, skip duplicate review.\n",
            );
        }

        instructions
    }

    async fn run_event_forwarder(
        client: reqwest::Client,
        gateway: GatewayConfig,
        channel_startup_spike: bool,
        event_buffer: Arc<Mutex<VecDeque<AgentEventEnvelope>>>,
        subscriber_id: String,
        peer: rmcp::service::Peer<RoleServer>,
    ) {
        if channel_startup_spike {
            let startup_event = AgentEventEnvelope {
                content: "change_request opened on test/org/repo#1 at deadbeef".to_string(),
                kind: "change_request".to_string(),
                meta: ChannelEventMetaEnvelope {
                    action: "opened".to_string(),
                    change_request: Some(1),
                    delivery_id: "startup-spike".to_string(),
                    event_kind: "change_request".to_string(),
                    forge_alias: "test".to_string(),
                    head_sha: Some("deadbeef".to_string()),
                    issue: None,
                    issue_comment: None,
                    owner: "org".to_string(),
                    repo: "repo".to_string(),
                    review_state: None,
                },
            };
            if let Err(error) = Self::send_channel_notification(&peer, &startup_event).await {
                tracing::warn!(error = %error, "failed to send startup channel spike");
            }
        }

        let mut backoff = Duration::from_secs(1);
        let mut last_event_id: Option<String> = None;

        while !peer.is_transport_closed() {
            let response = match send_event_stream_request(
                &client,
                &gateway,
                &subscriber_id,
                last_event_id.as_deref(),
            )
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(error = %error, "event stream connection failed");
                    sleep_with_peer_check(&peer, backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(10));
                    continue;
                }
            };

            if !response.status().is_success() {
                tracing::warn!(status = %response.status(), "event stream returned error");
                sleep_with_peer_check(&peer, backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
                continue;
            }

            backoff = Duration::from_secs(1);
            if !read_event_stream(&peer, &event_buffer, response, &mut last_event_id).await {
                return;
            }

            sleep_with_peer_check(&peer, backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(10));
        }
    }
}

fn generate_subscriber_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("shim-{}-{now}", std::process::id())
}

fn build_event_stream_url(gateway_url: &str, subscriber_id: &str) -> Result<reqwest::Url, String> {
    let mut base = gateway_url.to_string();
    if !base.ends_with('/') {
        base.push('/');
    }

    let mut url =
        reqwest::Url::parse(&base).map_err(|error| format!("invalid gateway URL: {error}"))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| "invalid gateway URL path".to_string())?;
        segments.push("api");
        segments.push("v1");
        segments.push("agent");
        segments.push("events");
    }
    url.query_pairs_mut()
        .append_pair("subscriber_id", subscriber_id);
    Ok(url)
}

async fn send_event_stream_request(
    client: &reqwest::Client,
    gateway: &GatewayConfig,
    subscriber_id: &str,
    last_event_id: Option<&str>,
) -> Result<reqwest::Response, String> {
    let url = build_event_stream_url(&gateway.url, subscriber_id)?;

    let mut request = client
        .get(url)
        .bearer_auth(&gateway.token)
        .header("accept", "text/event-stream");
    if let Some(last_event_id) = last_event_id {
        request = request.header("last-event-id", last_event_id);
    }
    request
        .send()
        .await
        .map_err(|error| format!("HTTP request failed: {error}"))
}

const KNOWN_EVENT_KINDS: &[&str] = &[
    "change_request",
    "issue",
    "issue_comment",
    "pull_request_review",
];

async fn buffer_sse_event(
    peer: &rmcp::service::Peer<RoleServer>,
    event_buffer: &Mutex<VecDeque<AgentEventEnvelope>>,
    event: SseEvent,
    last_event_id: &mut Option<String>,
) {
    if let Some(event_id) = &event.id {
        last_event_id.replace(event_id.clone());
    }

    let envelope = match serde_json::from_str::<AgentEventEnvelope>(&event.data) {
        Ok(envelope) => envelope,
        Err(error) => {
            tracing::warn!(error = %error, "dropping invalid SSE event payload");
            return;
        }
    };

    if !KNOWN_EVENT_KINDS.contains(&envelope.kind.as_str()) {
        return;
    }

    if let Ok(mut buffer) = event_buffer.lock() {
        buffer.push_back(envelope.clone());
    }

    // Also attempt channel notification (currently broken in Claude Code,
    // but will start working once anthropics/claude-code#36411 is fixed).
    {
        if let Err(error) = McpShim::send_channel_notification(peer, &envelope).await {
            tracing::debug!(error = %error, "channel notification failed (expected)");
        }
    }
}

async fn read_event_stream(
    peer: &rmcp::service::Peer<RoleServer>,
    event_buffer: &Mutex<VecDeque<AgentEventEnvelope>>,
    mut response: reqwest::Response,
    last_event_id: &mut Option<String>,
) -> bool {
    let mut parser = SseParser::default();

    loop {
        if peer.is_transport_closed() {
            return false;
        }

        let next_chunk = tokio::select! {
            chunk = response.chunk() => chunk,
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                continue;
            }
        };

        match next_chunk {
            Ok(Some(chunk)) => {
                for event in parser.push_chunk(&chunk) {
                    buffer_sse_event(peer, event_buffer, event, last_event_id).await;
                }
            }
            Ok(None) => {
                if let Some(event) = parser.finish() {
                    buffer_sse_event(peer, event_buffer, event, last_event_id).await;
                }
                return true;
            }
            Err(error) => {
                tracing::warn!(error = %error, "event stream read failed");
                return true;
            }
        }
    }
}

async fn sleep_with_peer_check(peer: &rmcp::service::Peer<RoleServer>, duration: Duration) {
    let step = Duration::from_millis(100);
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        if peer.is_transport_closed() {
            return;
        }
        tokio::time::sleep(step.min(deadline.saturating_duration_since(std::time::Instant::now())))
            .await;
    }
}

#[tool_router]
impl McpShim {
    /// Mark an issue as depending on another issue (blocked-by relationship).
    #[tool(
        name = "add_issue_dependency",
        description = "Mark an issue as depending on another issue. The issue at `index` will be blocked by the issue at `dependency`."
    )]
    async fn add_issue_dependency(
        &self,
        Parameters(request): Parameters<AddIssueDependencyTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
                "dependencies",
            ],
        )?;
        let body = serde_json::json!({"dependency": request.dependency});
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Add a label to an issue, creating the label if it does not exist.
    #[tool(
        name = "add_issue_label",
        description = "Add a label to an issue. Creates the label on the repository if it does not already exist."
    )]
    async fn add_issue_label(
        &self,
        Parameters(request): Parameters<AddIssueLabelTool>,
    ) -> Result<String, McpError> {
        // Enforce read-only mode for adding issue labels
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
                "labels",
            ],
        )?;
        let body = serde_json::json!({"label": request.label});
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Assign an issue to a user.
    #[tool(name = "assign_issue", description = "Assign an issue to a user.")]
    async fn assign_issue(
        &self,
        Parameters(request): Parameters<AssignIssueTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
            ],
        )?;
        let body = serde_json::json!({"assignees": [request.assignee]});
        self.gateway_patch(url, &gw.token, &body).await
    }

    /// Close a change request (pull request) on the forge.
    #[tool(
        name = "close_change_request",
        description = "Close a change request (pull request) on the forge. Only works for PRs whose head branch matches your configured branch prefix."
    )]
    async fn close_change_request(
        &self,
        Parameters(request): Parameters<CloseChangeRequestTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
            ],
        )?;
        self.gateway_delete(url, &gw.token).await
    }

    /// Close an issue.
    #[tool(name = "close_issue", description = "Close an issue.")]
    async fn close_issue(
        &self,
        Parameters(request): Parameters<CloseIssueTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
            ],
        )?;
        let body = serde_json::json!({"state": "closed"});
        self.gateway_patch(url, &gw.token, &body).await
    }

    /// Post a comment on an issue.
    #[tool(
        name = "comment_on_issue",
        description = "Post a comment on an issue. For the body, pass plain Markdown text with real newlines; do NOT pre-escape paragraph breaks as literal `\\n` sequences."
    )]
    async fn comment_on_issue(
        &self,
        Parameters(request): Parameters<CommentOnIssueTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
                "comments",
            ],
        )?;
        let body = serde_json::json!({"body": request.body});
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Create a new issue after checking for an existing open issue.
    #[tool(
        name = "create_issue",
        description = "Create a new issue. Check for an existing open issue first to avoid duplicates. For the body, pass plain Markdown text with real newlines; do NOT pre-escape paragraph breaks as literal `\\n` sequences."
    )]
    async fn create_issue(
        &self,
        Parameters(request): Parameters<CreateIssueTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
            ],
        )?;
        let body = serde_json::json!({"title": request.title, "body": request.body});
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Post a general comment on a change request (pull request).
    #[tool(
        name = "comment_on_change_request",
        description = "Post a general comment on a change request (pull request). This is not a formal review — use submit_change_request_review for that. For the body, pass plain Markdown text with real newlines; do NOT pre-escape paragraph breaks as literal `\\n` sequences."
    )]
    async fn comment_on_change_request(
        &self,
        Parameters(request): Parameters<CommentOnChangeRequestTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
                "comments",
            ],
        )?;
        let body = serde_json::json!({
            "body": request.body,
        });
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Apply a git-format patch to a new branch and push it.
    #[tool(
        name = "commit_patch",
        description = "Apply a git-format patch to a new branch and push it. This is the REQUIRED way to push code (raw `git push` is strictly blocked). Patch must come from git itself (for example `git diff --no-ext-diff --binary` or `git show`) and start with `diff --git`; traditional unified diffs are rejected. New files must use git headers like `new file mode`, `--- /dev/null`, and `+++ b/<path>`. The server validates the patch and applies it in a clean clone of the base branch — do NOT run `git apply --check` locally (it will fail because your worktree already contains the changes)."
    )]
    async fn commit_patch(
        &self,
        Parameters(request): Parameters<CommitPatchTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let commit_author = resolve_commit_author(&request, discover_local_commit_author)?;

        // Resolve patch content from either inline or file
        let patch = match (&request.patch, &request.patch_file) {
            (Some(p), _) => p.clone(),
            (None, Some(path)) => std::fs::read_to_string(path).map_err(|e| {
                McpError::invalid_params(format!("failed to read patch_file '{path}': {e}"), None)
            })?,
            (None, None) => {
                return Err(McpError::invalid_params(
                    "either patch or patch_file must be provided".to_string(),
                    None,
                ));
            }
        };

        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "patches",
            ],
        )?;
        let body = serde_json::json!({
            "author_email": commit_author.as_ref().map(|a| a.email.clone()),
            "author_name": commit_author.as_ref().map(|a| a.name.clone()),
            "base_branch": request.base_branch,
            "commit_message": request.commit_message,
            "existing_branch": request.existing_branch,
            "new_branch": request.new_branch,
            "patch": patch,
        });
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Get all comments and reviews for a change request.
    #[tool(
        name = "get_change_request_comments",
        description = "Get all comments and reviews for a change request (pull request)."
    )]
    async fn get_change_request_comments(
        &self,
        Parameters(request): Parameters<GetChangeRequestCommentsTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
                "comments",
            ],
        )?;
        self.gateway_get(url, &gw.token).await
    }

    /// Get the unified diff for a change request, written to a local file.
    #[tool(
        name = "get_change_request_diff",
        description = "Get the unified diff (patch) for a change request (pull request). The diff is written to a temporary file to avoid truncation of large patches. Returns JSON with `diff_file` (path to the patch file), `index`, and `size_bytes`. Use a file-reading tool to access the full diff content."
    )]
    async fn get_change_request_diff(
        &self,
        Parameters(request): Parameters<GetChangeRequestDiffTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
                "diff",
            ],
        )?;
        let body = self.gateway_get(url, &gw.token).await?;

        // Parse the JSON response to extract the patch text.
        let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            McpError::internal_error(format!("failed to parse diff response: {e}"), None)
        })?;
        let patch = parsed["patch"].as_str().ok_or_else(|| {
            McpError::internal_error("missing patch field in response".to_string(), None)
        })?;

        // Write the patch to a temporary file so large diffs are not
        // truncated by MCP message-size limits.
        let diff_file = std::env::temp_dir().join(format!(
            "forge-mcp-diff-{}-{}-{}-{}.patch",
            request.forge, request.owner, request.repo, request.index,
        ));
        tokio::fs::write(&diff_file, patch).await.map_err(|e| {
            McpError::internal_error(format!("failed to write diff file: {e}"), None)
        })?;

        let result = serde_json::json!({
            "diff_file": diff_file.display().to_string(),
            "index": request.index,
            "size_bytes": patch.len(),
        });
        Ok(result.to_string())
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
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
            ],
        )?;
        self.gateway_get(url, &gw.token).await
    }

    /// Get the combined CI/check status for a change request's current head.
    #[tool(
        name = "get_change_request_checks",
        description = "Get the combined CI/check status for a change request (pull request). Returns the aggregate state (success, pending, failure, error) and per-check details for the current PR head SHA."
    )]
    async fn get_change_request_checks(
        &self,
        Parameters(request): Parameters<GetChangeRequestChecksTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
                "checks",
            ],
        )?;
        self.gateway_get(url, &gw.token).await
    }

    /// Get the detailed CI/check status for a change request's current head.
    #[tool(
        name = "get_change_request_ci_details",
        description = "Get the detailed CI/check status for a change request (pull request). Returns the aggregate state (success, pending, failure, error) and detailed per-check information for the current PR head SHA."
    )]
    async fn get_change_request_ci_details(
        &self,
        Parameters(request): Parameters<GetChangeRequestCiDetailsTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
                "ci-details",
            ],
        )?;
        self.gateway_get(url, &gw.token).await
    }

    /// Get a single issue by index.
    #[tool(name = "get_issue", description = "Get a single issue by index.")]
    async fn get_issue(
        &self,
        Parameters(request): Parameters<GetIssueTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
            ],
        )?;
        self.gateway_get(url, &gw.token).await
    }

    /// Get all comments for an issue.
    #[tool(
        name = "get_issue_comments",
        description = "Get all comments for an issue."
    )]
    async fn get_issue_comments(
        &self,
        Parameters(request): Parameters<GetIssueCommentsTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
                "comments",
            ],
        )?;
        self.gateway_get(url, &gw.token).await
    }

    /// Get the dependency relationships for an issue.
    #[tool(
        name = "get_issue_dependencies",
        description = "Get the dependency relationships for an issue. Returns issues that this issue depends on (blocks it) and issues that it blocks."
    )]
    async fn get_issue_dependencies(
        &self,
        Parameters(request): Parameters<GetIssueDependenciesTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
                "dependencies",
            ],
        )?;
        self.gateway_get(url, &gw.token).await
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
        let gw = self.resolve_gateway(&request.forge).await?;
        let mut url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
            ],
        )?;
        if let Some(state) = &request.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        self.gateway_get(url, &gw.token).await
    }

    /// List issues for a repository.
    #[tool(name = "list_issues", description = "List issues for a repository.")]
    async fn list_issues(
        &self,
        Parameters(request): Parameters<ListIssuesTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let mut url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
            ],
        )?;
        if let Some(state) = &request.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        self.gateway_get(url, &gw.token).await
    }

    /// List repositories on a forge, optionally filtered by owner and/or query.
    #[tool(
        name = "list_repositories",
        description = "List repositories available on a forge instance. Use `owner` to restrict results to a specific organization or user namespace, and `query` to search by name."
    )]
    async fn list_repositories(
        &self,
        Parameters(request): Parameters<ListRepositoriesTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let mut url = Self::build_url(&gw.url, &["api", "v1", "repos", &request.forge])?;
        if let Some(owner) = &request.owner {
            url.query_pairs_mut().append_pair("owner", owner);
        }
        if let Some(query) = &request.query {
            url.query_pairs_mut().append_pair("q", query);
        }
        self.gateway_get(url, &gw.token).await
    }

    /// Open a change request (pull request) on the forge.
    #[tool(
        name = "open_change_request",
        description = "Open a change request (pull request) on the forge.\n\
            Before calling this tool, check if a PR already exists for your branch \
            using list_change_requests. If one exists, do NOT open a new PR — push \
            fixes to the existing branch using commit_patch with existing_branch: true.\n\
            For the body, pass plain Markdown text with real newlines; do NOT pre-escape \
            paragraph breaks as literal `\\n` sequences."
    )]
    async fn open_change_request(
        &self,
        Parameters(request): Parameters<OpenChangeRequestTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
            ],
        )?;
        let body = serde_json::json!({
            "base_branch": request.base_branch,
            "body": request.body,
            "head_branch": request.head_branch,
            "title": request.title,
        });
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Rebase a branch by squashing (fixup) or removing (drop) commits.
    #[tool(
        name = "rebase_branch",
        description = "Rebase a branch by squashing (fixup), removing (drop) commits, or rebasing onto the latest base branch (rebase_onto). This is the REQUIRED way to rewrite history and force-push (raw `git push` is strictly blocked). Use this for squash/fixup after review instead of leaving multiple cleanup commits. Performs a full clone, validates operations, runs the rebase, and force-pushes with lease. Only works on branches matching your configured branch prefix."
    )]
    async fn rebase_branch(
        &self,
        Parameters(request): Parameters<RebaseBranchTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "rebase",
            ],
        )?;

        let operations: Vec<serde_json::Value> = request
            .operations
            .iter()
            .map(|op| match op {
                RebaseBranchOperationTool::Drop { commit } => {
                    serde_json::json!({
                        "type": "drop",
                        "commit": commit,
                    })
                }
                RebaseBranchOperationTool::Fixup { commit, into } => {
                    serde_json::json!({
                        "type": "fixup",
                        "commit": commit,
                        "into": into,
                    })
                }
                RebaseBranchOperationTool::RebaseOnto {} => {
                    serde_json::json!({
                        "type": "rebase_onto",
                    })
                }
            })
            .collect();

        let body = serde_json::json!({
            "base_branch": request.base_branch,
            "branch": request.branch,
            "operations": operations,
        });
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Schedule a pull request for automatic merge when all checks pass.
    #[tool(
        name = "schedule_auto_merge",
        description = "Schedule a pull request for automatic merge when all branch protection requirements are met. Requires the expected head SHA to prevent scheduling on a stale PR."
    )]
    async fn schedule_auto_merge(
        &self,
        Parameters(request): Parameters<ScheduleAutoMergeTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
                "automerge",
            ],
        )?;
        let body = ScheduleAutoMergeBody {
            delete_branch_after_merge: request.delete_branch_after_merge,
            expected_head_sha: request.expected_head_sha,
            merge_style: request.merge_style,
        };
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Poll for pending webhook events. Returns any buffered change request
    /// events that arrived since the last poll, then clears the buffer.
    #[tool(
        name = "poll_events",
        description = "Poll for pending webhook events (change request opened, synchronized, etc.). Returns buffered events since last poll. Call periodically to receive forge notifications."
    )]
    async fn poll_events(&self) -> Result<String, McpError> {
        let events: Vec<AgentEventEnvelope> = {
            let mut buffer = self
                .event_buffer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            buffer.drain(..).collect()
        };
        serde_json::to_string_pretty(&events)
            .map_err(|e| McpError::internal_error(format!("serialization failed: {e}"), None))
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
        let gw = self.resolve_gateway(&request.forge).await?;
        // Each path component is pushed as a separate segment so reqwest
        // percent-encodes reserved characters (?, #, &, etc.) automatically.
        let mut segments: Vec<&str> = vec![
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "contents",
        ];
        let path_parts: Vec<&str> = request.path.split('/').collect();
        segments.extend(path_parts.iter());
        let mut url = Self::build_url(&gw.url, &segments)?;

        if let Some(git_ref) = &request.git_ref {
            url.query_pairs_mut().append_pair("ref", git_ref);
        }
        let response = self.gateway_get(url, &gw.token).await?;

        // Extract just the content field from the JSON response
        let parsed: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| McpError::internal_error(format!("invalid JSON response: {e}"), None))?;
        parsed["content"]
            .as_str()
            .map(ToString::to_string)
            .ok_or_else(|| McpError::internal_error("missing content field".to_string(), None))
    }

    /// Remove a dependency relationship from an issue.
    #[tool(
        name = "remove_issue_dependency",
        description = "Remove a dependency relationship from an issue. The issue at `index` will no longer be blocked by the issue at `dependency`."
    )]
    async fn remove_issue_dependency(
        &self,
        Parameters(request): Parameters<RemoveIssueDependencyTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
                "dependencies",
                &request.dependency.to_string(),
            ],
        )?;
        self.gateway_delete(url, &gw.token).await
    }

    /// Remove a label from an issue.
    #[tool(
        name = "remove_issue_label",
        description = "Remove a label from an issue."
    )]
    async fn remove_issue_label(
        &self,
        Parameters(request): Parameters<RemoveIssueLabelTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
                "labels",
                &request.label,
            ],
        )?;
        self.gateway_delete(url, &gw.token).await
    }

    /// Submit a formal review on a change request (pull request).
    #[tool(
        name = "submit_change_request_review",
        description = "Submit a formal review on a change request (pull request). Event must be APPROVED, REQUEST_CHANGES, or COMMENT. For the body, pass plain Markdown text with real newlines; do NOT pre-escape paragraph breaks as literal `\\n` sequences."
    )]
    async fn submit_change_request_review(
        &self,
        Parameters(request): Parameters<SubmitChangeRequestReviewTool>,
    ) -> Result<String, McpError> {
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
                "reviews",
            ],
        )?;
        let body = serde_json::json!({
            "body": request.body,
            "event": request.event,
        });
        self.gateway_post(url, &gw.token, &body).await
    }

    /// Update a change request's title and/or body.
    #[tool(
        name = "update_change_request",
        description = "Update a change request (pull request) title and/or body. Provide at least one of title or body. For the body, pass plain Markdown text with real newlines; do NOT pre-escape paragraph breaks as literal `\\n` sequences."
    )]
    async fn update_change_request(
        &self,
        Parameters(request): Parameters<UpdateChangeRequestTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "pulls",
                &request.index.to_string(),
            ],
        )?;
        let mut json_body = serde_json::Map::new();
        if let Some(title) = &request.title {
            json_body.insert(
                "title".to_string(),
                serde_json::Value::String(title.clone()),
            );
        }
        if let Some(body) = &request.body {
            json_body.insert("body".to_string(), serde_json::Value::String(body.clone()));
        }
        self.gateway_patch(url, &gw.token, &serde_json::Value::Object(json_body))
            .await
    }

    /// Update an issue's title and/or body.
    #[tool(
        name = "update_issue",
        description = "Update an issue's title and/or body. Provide at least one of title or body. For the body, pass plain Markdown text with real newlines; do NOT pre-escape paragraph breaks as literal `\\n` sequences."
    )]
    async fn update_issue(
        &self,
        Parameters(request): Parameters<UpdateIssueTool>,
    ) -> Result<String, McpError> {
        self.ensure_writable()?;
        let gw = self.resolve_gateway(&request.forge).await?;
        let url = Self::build_url(
            &gw.url,
            &[
                "api",
                "v1",
                "repos",
                &request.forge,
                &request.owner,
                &request.repo,
                "issues",
                &request.index.to_string(),
            ],
        )?;
        let mut json_body = serde_json::Map::new();
        if let Some(title) = &request.title {
            json_body.insert(
                "title".to_string(),
                serde_json::Value::String(title.clone()),
            );
        }
        if let Some(body) = &request.body {
            json_body.insert("body".to_string(), serde_json::Value::String(body.clone()));
        }
        self.gateway_patch(url, &gw.token, &serde_json::Value::Object(json_body))
            .await
    }

    /// Discover available forges across all configured gateways.
    #[tool(
        name = "forge_info",
        description = "Discover dynamic facts like available forge instances, gateway URLs, git URL templates, branch prefixes, and authentication details. Call this FIRST to learn which forges you can access and to map forge aliases to the correct gateway in multi-gateway mode. IMPORTANT: forge-mcp strictly blocks `git push`. You MUST use the `commit_patch` and `rebase_branch` tools for all write operations."
    )]
    async fn forge_info(&self) -> Result<String, McpError> {
        let git_auth = serde_json::json!({
            "scheme": "basic",
            "username": "any non-empty value",
            "password_source": "agent_token"
        });

        // Single gateway: preserve the original flat response shape.
        if self.config.gateways.len() == 1 {
            let gw = &self.config.gateways[0];
            let url = Self::build_url(&gw.url, &["api", "v1", "agent", "info"])?;
            let response = self.gateway_get(url, &gw.token).await?;
            let mut parsed: serde_json::Value = serde_json::from_str(&response).map_err(|e| {
                McpError::internal_error(format!("invalid JSON response: {e}"), None)
            })?;

            let gw_url = gw.url.trim_end_matches('/');
            parsed["gateway_url"] = serde_json::Value::String(gw_url.to_string());
            parsed["git_url_template"] =
                serde_json::Value::String(format!("{gw_url}/git/{{forge}}/{{owner}}/{{repo}}"));
            parsed["git_auth"] = git_auth;

            return serde_json::to_string_pretty(&parsed).map_err(|e| {
                McpError::internal_error(format!("JSON serialization failed: {e}"), None)
            });
        }

        // Multiple gateways: aggregate per-gateway info and merge forges.
        // Unreachable gateways are included with an error note rather than
        // failing the entire response.
        let mut all_forges = Vec::new();
        let mut alias_sources: HashMap<String, String> = HashMap::new();
        let mut ambiguous_aliases: Vec<String> = Vec::new();
        let mut gateway_entries = Vec::new();

        for gw in &self.config.gateways {
            let gw_url = gw.url.trim_end_matches('/');
            let url = match Self::build_url(&gw.url, &["api", "v1", "agent", "info"]) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(
                        gateway = gw.name,
                        error = %e,
                        "skipping gateway with malformed URL during forge_info",
                    );
                    gateway_entries.push(serde_json::json!({
                        "name": gw.name,
                        "gateway_url": gw_url,
                        "error": format!("{e}"),
                    }));
                    continue;
                }
            };
            let response = match self.gateway_get(url, &gw.token).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        gateway = gw.name,
                        error = %e,
                        "gateway unreachable during forge_info",
                    );
                    gateway_entries.push(serde_json::json!({
                        "name": gw.name,
                        "gateway_url": gw_url,
                        "error": format!("{e}"),
                    }));
                    continue;
                }
            };
            let info: serde_json::Value = match serde_json::from_str(&response) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        gateway = gw.name,
                        error = %e,
                        "gateway returned invalid JSON during forge_info",
                    );
                    gateway_entries.push(serde_json::json!({
                        "name": gw.name,
                        "gateway_url": gw_url,
                        "error": format!("invalid JSON: {e}"),
                    }));
                    continue;
                }
            };

            let forges = info["forges"].clone();
            if let Some(forge_arr) = forges.as_array() {
                for forge in forge_arr {
                    if let Some(alias) = forge["alias"].as_str() {
                        if let Some(existing_gw) = alias_sources.get(alias) {
                            ambiguous_aliases.push(format!(
                                "forge alias '{}' advertised by gateways '{}' and '{}'",
                                alias, existing_gw, gw.name,
                            ));
                        } else {
                            alias_sources.insert(alias.to_string(), gw.name.clone());
                        }
                    }
                    all_forges.push(forge.clone());
                }
            }

            gateway_entries.push(serde_json::json!({
                "name": gw.name,
                "gateway_url": gw_url,
                "git_url_template": format!("{gw_url}/git/{{forge}}/{{owner}}/{{repo}}"),
                "agent_id": info["agent_id"],
                "branch_prefix": info["branch_prefix"],
                "forges": forges,
            }));
        }

        let mut result = serde_json::json!({
            "forges": all_forges,
            "gateways": gateway_entries,
            "git_auth": git_auth,
        });
        if !ambiguous_aliases.is_empty() {
            result["ambiguous_aliases"] = serde_json::json!(ambiguous_aliases);
        }

        serde_json::to_string_pretty(&result)
            .map_err(|e| McpError::internal_error(format!("JSON serialization failed: {e}"), None))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpShim {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(self.channel_capabilities())
            .with_instructions(self.instructions())
            .with_server_info(Implementation::new(
                self.config.server_name.clone(),
                self.config.server_version.clone(),
            ))
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        // Always start the event forwarders so poll_events works regardless of
        // whether Claude channel notifications are enabled.
        if self
            .event_forwarder_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        // Start one event forwarder per gateway. Each has its own SSE
        // connection and reconnect state, but they share the event buffer.
        for (i, gateway) in self.config.gateways.iter().enumerate() {
            let peer = context.peer.clone();
            let client = self.client.clone();
            let gw = gateway.clone();
            let event_buffer = self.event_buffer.clone();
            let subscriber_id = generate_subscriber_id();
            // Only send the startup spike on the first gateway.
            let startup_spike = i == 0 && self.config.channel_startup_spike;
            tracing::info!(
                gateway = gw.name,
                channels = self.config.enable_channels,
                "event forwarder started",
            );
            tokio::spawn(async move {
                Self::run_event_forwarder(
                    client,
                    gw,
                    startup_spike,
                    event_buffer,
                    subscriber_id,
                    peer,
                )
                .await;
            });
        }
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
#[allow(clippy::expect_used)]
mod tests {
    use std::fmt::Write;
    use std::sync::Arc;

    use rmcp::{
        ClientHandler, ServiceExt,
        model::{CallToolRequestParams, ClientInfo, CustomNotification},
    };
    use tokio::sync::{Mutex, Notify};

    use super::*;

    #[test]
    fn deserialize_add_issue_label_tool() {
        let json = r#"{"forge":"f","index":5,"label":"needs-input","owner":"o","repo":"r"}"#;
        let tool: AddIssueLabelTool =
            serde_json::from_str(json).expect("deserialize AddIssueLabelTool");
        assert_eq!(tool.forge, "f");
        assert_eq!(tool.index, 5);
        assert_eq!(tool.label, "needs-input");
        assert_eq!(tool.owner, "o");
        assert_eq!(tool.repo, "r");
    }

    #[test]
    fn deserialize_add_issue_label_tool_string_index() {
        let json = r#"{"forge":"f","index":"5","label":"needs-input","owner":"o","repo":"r"}"#;
        let tool: AddIssueLabelTool =
            serde_json::from_str(json).expect("deserialize AddIssueLabelTool from string index");
        assert_eq!(tool.index, 5);
    }

    #[test]
    fn deserialize_remove_issue_label_tool() {
        let json = r#"{"forge":"f","index":3,"label":"needs-input","owner":"o","repo":"r"}"#;
        let tool: RemoveIssueLabelTool =
            serde_json::from_str(json).expect("deserialize RemoveIssueLabelTool");
        assert_eq!(tool.forge, "f");
        assert_eq!(tool.index, 3);
        assert_eq!(tool.label, "needs-input");
        assert_eq!(tool.owner, "o");
        assert_eq!(tool.repo, "r");
    }

    #[test]
    fn deserialize_index_from_number() {
        let json = r#"{"forge":"f","index":5,"owner":"o","repo":"r"}"#;
        let tool: CloseChangeRequestTool =
            serde_json::from_str(json).expect("deserialize index from number");
        assert_eq!(tool.index, 5);
    }

    #[test]
    fn deserialize_index_from_string() {
        let json = r#"{"forge":"f","index":"5","owner":"o","repo":"r"}"#;
        let tool: CloseChangeRequestTool =
            serde_json::from_str(json).expect("deserialize index from string");
        assert_eq!(tool.index, 5);
    }

    #[derive(Debug, Clone, Default)]
    struct DummyClientHandler;

    impl ClientHandler for DummyClientHandler {
        fn get_info(&self) -> ClientInfo {
            ClientInfo::default()
        }
    }

    #[derive(Clone, Debug, Default)]
    struct ChannelCaptureClient {
        payload: Arc<Mutex<Option<CapturedNotification>>>,
        receive_signal: Arc<Notify>,
    }

    type CapturedNotification = (String, Option<serde_json::Value>);

    impl ClientHandler for ChannelCaptureClient {
        fn get_info(&self) -> ClientInfo {
            ClientInfo::default()
        }

        async fn on_custom_notification(
            &self,
            notification: CustomNotification,
            _context: rmcp::service::NotificationContext<rmcp::RoleClient>,
        ) {
            let CustomNotification { method, params, .. } = notification;
            *self.payload.lock().await = Some((method, params));
            self.receive_signal.notify_one();
        }
    }

    fn test_config(gateway_url: &str) -> ShimConfig {
        ShimConfig {
            channel_startup_spike: false,
            enable_channels: false,
            gateways: vec![GatewayConfig {
                name: "test".to_string(),
                token: "test-token".to_string(),
                url: gateway_url.to_string(),
            }],
            read_only: false,
            server_name: "forge-mcp-shim".to_string(),
            server_version: "0.1.0-test".to_string(),
        }
    }

    fn test_channel_config(gateway_url: &str) -> ShimConfig {
        ShimConfig {
            enable_channels: true,
            ..test_config(gateway_url)
        }
    }

    fn test_multi_gateway_config(urls: &[(&str, &str, &str)]) -> ShimConfig {
        ShimConfig {
            channel_startup_spike: false,
            enable_channels: false,
            gateways: urls
                .iter()
                .map(|(name, url, token)| GatewayConfig {
                    name: (*name).to_string(),
                    token: (*token).to_string(),
                    url: (*url).to_string(),
                })
                .collect(),
            read_only: false,
            server_name: "forge-mcp-shim".to_string(),
            server_version: "0.1.0-test".to_string(),
        }
    }

    #[test]
    fn debug_redacts_token() {
        let config = test_config("https://example.com");
        let debug = format!("{config:?}");
        assert!(!debug.contains("test-token"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn gateway_config_debug_redacts_token() {
        let gw = GatewayConfig {
            name: "test".to_string(),
            token: "super-secret".to_string(),
            url: "https://example.com".to_string(),
        };
        let debug = format!("{gw:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn get_info_advertises_claude_channel_when_enabled() {
        let shim = McpShim::new(test_channel_config("https://example.com"));
        let info = shim.get_info();
        let experimental = info
            .capabilities
            .experimental
            .expect("experimental capabilities");
        assert!(experimental.contains_key("claude/channel"));
    }

    #[test]
    fn get_info_returns_updated_instructions() {
        let shim = McpShim::new(test_config("https://example.com"));
        let info = shim.get_info();
        let instructions = info.instructions.expect("instructions");
        assert!(instructions.contains("### Discovery & Identity"));
        assert!(instructions.contains("### Git Proxy (Read-Only)"));
        assert!(instructions.contains("### Write Workflow"));
        assert!(instructions.contains("Detached Worktree"));
        assert!(instructions.contains("Repository Discovery: NOT supported"));
        assert!(instructions.contains("forge_info` FIRST"));
    }

    #[test]
    fn build_url_encodes_reserved_characters() {
        let url = McpShim::build_url(
            "https://example.com",
            &["api", "v1", "repos", "org", "repo", "contents", "a?b#c"],
        )
        .expect("build url with reserved characters");
        let path = url.path();
        // '?' and '#' change URL semantics and must be percent-encoded in paths
        assert!(
            !path.contains('?'),
            "path should not contain raw '?': {path}"
        );
        assert!(
            !path.contains('#'),
            "path should not contain raw '#': {path}"
        );
        assert!(
            path.contains("a%3Fb%23c"),
            "path should encode ? and #: {path}"
        );
    }

    #[test]
    fn build_url_query_params_encoded() {
        let mut url = McpShim::build_url(
            "https://example.com",
            &["api", "v1", "repos", "org", "repo", "contents", "file"],
        )
        .expect("build url for query params test");
        url.query_pairs_mut()
            .append_pair("ref", "feat/branch&evil=1");
        let query = url.query().expect("url should have query string");
        // The & in the ref value should be encoded, not treated as a separator
        assert!(
            !query.contains("evil=1"),
            "query should encode & in values: {query}"
        );
    }

    #[test]
    fn build_url_nested_path_segments() {
        let path_parts: Vec<&str> = "src/main.rs".split('/').collect();
        let mut segments: Vec<&str> = vec!["api", "v1", "repos", "org", "repo", "contents"];
        segments.extend(path_parts.iter());
        let url = McpShim::build_url("https://example.com", &segments)
            .expect("build url with nested path");
        assert_eq!(url.path(), "/api/v1/repos/org/repo/contents/src/main.rs");
    }

    #[test]
    fn parse_git_author_ident_extracts_name_and_email() {
        let ident = "Your Name <you@example.com> 1710853140 +0200";
        let author = parse_git_author_ident(ident).expect("should parse");
        assert_eq!(
            author,
            CommitAuthor {
                email: "you@example.com".to_string(),
                name: "Your Name".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn commit_patch_fails_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = CommitPatchTool {
            author_email: None,
            author_name: None,
            base_branch: "main".to_string(),
            commit_message: "feat: something".to_string(),
            existing_branch: false,
            forge: "test".to_string(),
            new_branch: "agent/task-1".to_string(),
            patch: Some("diff --git ...".to_string()),
            patch_file: None,
            repo: "cockpit".to_string(),
            owner: "tokarix".to_string(),
        };

        let err = shim
            .commit_patch(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn comment_on_issue_allowed_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = CommentOnIssueTool {
            body: "hello".to_string(),
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .comment_on_issue(Parameters(request))
            .await
            .expect_err("should fail at HTTP layer, not writability");
        assert!(!err.message.contains("read-only mode"));
    }

    #[tokio::test]
    async fn add_issue_label_blocked_in_read_only_mode() {
        // Verify that add_issue_label is correctly blocked when read_only is true
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = AddIssueLabelTool {
            forge: "test".to_string(),
            index: 1,
            label: "test".to_string(),
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .add_issue_label(Parameters(request))
            .await
            .expect_err("should be blocked due to read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn submit_change_request_review_allowed_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = SubmitChangeRequestReviewTool {
            body: "looks good".to_string(),
            event: "APPROVED".to_string(),
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .submit_change_request_review(Parameters(request))
            .await
            .expect_err("should fail at HTTP layer, not writability");
        assert!(!err.message.contains("read-only mode"));
    }

    #[tokio::test]
    async fn remove_issue_dependency_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = RemoveIssueDependencyTool {
            dependency: 2,
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .remove_issue_dependency(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn remove_issue_label_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = RemoveIssueLabelTool {
            forge: "test".to_string(),
            index: 1,
            label: "test".to_string(),
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .remove_issue_label(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn add_issue_dependency_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = AddIssueDependencyTool {
            dependency: 2,
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .add_issue_dependency(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn assign_issue_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = AssignIssueTool {
            assignee: "user".to_string(),
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .assign_issue(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn close_change_request_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = CloseChangeRequestTool {
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .close_change_request(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn close_issue_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = CloseIssueTool {
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .close_issue(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn create_issue_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = CreateIssueTool {
            body: "test body".to_string(),
            forge: "test".to_string(),
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            title: "test title".to_string(),
        };

        let err = shim
            .create_issue(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn comment_on_change_request_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = CommentOnChangeRequestTool {
            body: "test body".to_string(),
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .comment_on_change_request(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn open_change_request_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = OpenChangeRequestTool {
            base_branch: "main".to_string(),
            body: "test body".to_string(),
            forge: "test".to_string(),
            head_branch: "agent/branch".to_string(),
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            title: "test title".to_string(),
        };

        let err = shim
            .open_change_request(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn rebase_branch_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = RebaseBranchTool {
            base_branch: "main".to_string(),
            branch: "agent/branch".to_string(),
            forge: "test".to_string(),
            operations: vec![RebaseBranchOperationTool::RebaseOnto {}],
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .rebase_branch(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn schedule_auto_merge_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = ScheduleAutoMergeTool {
            delete_branch_after_merge: None,
            expected_head_sha: "sha".to_string(),
            forge: "test".to_string(),
            index: 1,
            merge_style: "rebase".to_string(),
            owner: "owner".to_string(),
            repo: "repo".to_string(),
        };

        let err = shim
            .schedule_auto_merge(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn update_change_request_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = UpdateChangeRequestTool {
            body: None,
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            title: Some("new title".to_string()),
        };

        let err = shim
            .update_change_request(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[tokio::test]
    async fn update_issue_blocked_in_read_only_mode() {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_config(&mock_server.uri());
        config.read_only = true;
        let shim = McpShim::new(config);

        let request = UpdateIssueTool {
            body: None,
            forge: "test".to_string(),
            index: 1,
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            title: Some("new title".to_string()),
        };

        let err = shim
            .update_issue(Parameters(request))
            .await
            .expect_err("should fail in read-only mode");
        assert!(err.message.contains("read-only mode"));

        let requests = mock_server
            .received_requests()
            .await
            .expect("received requests");
        assert!(
            requests.is_empty(),
            "no requests should reach the gateway in read-only mode"
        );
    }

    #[test]
    fn resolve_commit_author_prefers_explicit_values() {
        let request = CommitPatchTool {
            author_email: Some("explicit@example.com".to_string()),
            author_name: Some("Explicit User".to_string()),
            base_branch: "main".to_string(),
            commit_message: "fix".to_string(),
            existing_branch: false,
            forge: "test-forge".to_string(),
            new_branch: "agent/fix".to_string(),
            owner: "org".to_string(),
            patch: Some("diff...".to_string()),
            patch_file: None,
            repo: "repo".to_string(),
        };
        let author = resolve_commit_author(&request, || None).expect("should resolve");
        assert_eq!(
            author,
            Some(CommitAuthor {
                email: "explicit@example.com".to_string(),
                name: "Explicit User".to_string(),
            })
        );
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

    async fn spawn_shim_and_channel_client(
        config: ShimConfig,
    ) -> Result<
        (
            rmcp::service::RunningService<rmcp::service::RoleClient, ChannelCaptureClient>,
            Arc<Mutex<Option<CapturedNotification>>>,
            Arc<Notify>,
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

        let payload = Arc::new(Mutex::new(None));
        let receive_signal = Arc::new(Notify::new());
        let client = ChannelCaptureClient {
            payload: Arc::clone(&payload),
            receive_signal: Arc::clone(&receive_signal),
        }
        .serve(client_transport)
        .await?;

        Ok((client, payload, receive_signal, server_handle))
    }

    #[tokio::test]
    async fn read_repository_file_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(
                r"/api/v1/repos/.+/.+/.+/contents/.+",
            ))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer test-token",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
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
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "path": "README.md",
            "git_ref": "main"
        })
        .as_object()
        .expect("json args as object")
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
            .and(wiremock::matchers::path_regex(
                r"/api/v1/repos/.+/.+/.+/patches",
            ))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer test-token",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "branch": "agent/fix",
                    "commit_sha": "abc123"
                })),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "base_branch": "main",
            "new_branch": "agent/fix",
            "commit_message": "fix",
            "patch": "diff..."
        })
        .as_object()
        .expect("json args as object")
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

    #[tokio::test]
    async fn schedule_auto_merge_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path_regex(
                r"/api/v1/repos/.+/.+/.+/pulls/\d+/automerge",
            ))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer test-token",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "index": 42,
            "delete_branch_after_merge": true,
            "expected_head_sha": "abc123",
            "merge_style": "rebase"
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("schedule_auto_merge").with_arguments(args))
            .await?;

        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains('{'));

        // Verify the request body sent to the gateway (filter out SSE requests)
        let requests: Vec<_> = mock_server
            .received_requests()
            .await
            .expect("received requests")
            .into_iter()
            .filter(|r| r.url.path().contains("automerge"))
            .collect();
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert_eq!(body["delete_branch_after_merge"], true);
        assert_eq!(body["expected_head_sha"], "abc123");
        assert_eq!(body["merge_style"], "rebase");

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn schedule_auto_merge_omits_delete_branch_when_unspecified()
    -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/test-forge/org/repo/pulls/42/automerge",
            ))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "index": 42,
            "expected_head_sha": "abc123",
            "merge_style": "rebase"
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("schedule_auto_merge").with_arguments(args))
            .await?;

        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains('{'));

        let requests: Vec<_> = mock_server
            .received_requests()
            .await
            .expect("received requests")
            .into_iter()
            .filter(|r| r.url.path().contains("automerge"))
            .collect();
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("valid JSON");
        assert!(body.get("delete_branch_after_merge").is_none());
        assert_eq!(body["expected_head_sha"], "abc123");
        assert_eq!(body["merge_style"], "rebase");

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn get_change_request_comments_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(
                r"/api/v1/repos/.+/.+/.+/pulls/\d+/comments",
            ))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer test-token",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "author": "reviewer",
                        "body": "looks good",
                        "created_at": "2026-03-18T10:00:00Z",
                        "id": 1,
                        "kind": "comment",
                        "review_state": null
                    }
                ])),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "index": 1
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(
                CallToolRequestParams::new("get_change_request_comments").with_arguments(args),
            )
            .await?;

        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("looks good"));

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn startup_channel_spike_reaches_client() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        let mut config = test_channel_config(&mock_server.uri());
        config.channel_startup_spike = true;

        let (client, payload, receive_signal, server_handle) =
            spawn_shim_and_channel_client(config).await?;

        tokio::time::timeout(Duration::from_secs(5), receive_signal.notified()).await?;

        let (method, params) = payload.lock().await.take().expect("payload set");
        assert_eq!(method, "notifications/claude/channel");
        assert_eq!(
            params
                .as_ref()
                .and_then(|value| value["meta"]["forge"].as_str()),
            Some("test")
        );
        assert_eq!(
            params
                .as_ref()
                .and_then(|value| value["meta"]["delivery_id"].as_str()),
            Some("startup-spike")
        );

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn sse_event_is_forwarded_as_channel_notification()
    -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        let event_body = serde_json::json!({
            "kind": "change_request",
            "content": "change_request synchronize on internal/org/repo#24 at 5e4e9ed3",
            "meta": {
                "forge_alias": "internal",
                "owner": "org",
                "repo": "repo",
                "event_kind": "change_request",
                "action": "synchronize",
                "change_request": 24,
                "head_sha": "5e4e9ed3d19c2d7114eb7da1453913a3ab4f56ca",
                "delivery_id": "delivery-123"
            }
        });
        let sse = format!(
            "event: change_request\nid: internal:delivery-123\ndata: {}\n\n",
            serde_json::to_string(&event_body)?
        );

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/events"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer test-token",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse),
            )
            .mount(&mock_server)
            .await;

        let (client, payload, receive_signal, server_handle) =
            spawn_shim_and_channel_client(test_channel_config(&mock_server.uri())).await?;

        tokio::time::timeout(Duration::from_secs(5), receive_signal.notified()).await?;

        let (method, params) = payload.lock().await.take().expect("payload set");
        assert_eq!(method, "notifications/claude/channel");
        assert_eq!(
            params
                .as_ref()
                .and_then(|value| value["meta"]["forge"].as_str()),
            Some("internal")
        );
        assert_eq!(
            params
                .as_ref()
                .and_then(|value| value["meta"]["change_request"].as_u64()),
            Some(24)
        );
        assert_eq!(
            params
                .as_ref()
                .and_then(|value| value["meta"]["delivery_id"].as_str()),
            Some("delivery-123")
        );

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn list_issues_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/test-forge/org/repo/issues",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"number": 1, "title": "Bug"}])),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "state": "open"
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("list_issues").with_arguments(args))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("Bug"));

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn get_issue_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/test-forge/org/repo/issues/42",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"number": 42, "title": "Fix login"})),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "index": 42
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("get_issue").with_arguments(args))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("Fix login"));

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn comment_on_issue_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/test-forge/org/repo/issues/42/comments",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"id": 1, "body": "noted"})),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "index": 42,
            "body": "noted"
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("comment_on_issue").with_arguments(args))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("noted"));

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn create_issue_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/test-forge/org/repo/issues",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "number": 42,
                    "title": "Bug report",
                    "body": "Something is broken",
                    "state": "open",
                    "html_url": "https://forge.example/org/repo/issues/42",
                    "labels": [],
                    "assignees": []
                })),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "title": "Bug report",
            "body": "Something is broken"
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("create_issue").with_arguments(args))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("Bug report"));

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn sse_event_is_buffered_for_polling() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        let event_body = serde_json::json!({
            "kind": "change_request",
            "content": "change_request opened on internal/org/repo#24 at abc123",
            "meta": {
                "forge_alias": "internal",
                "owner": "org",
                "repo": "repo",
                "event_kind": "change_request",
                "action": "opened",
                "change_request": 24,
                "head_sha": "abc123",
                "delivery_id": "delivery-456"
            }
        });
        let sse =
            format!("event: change_request\nid: internal:delivery-456\ndata: {event_body}\n\n",);

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/events"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse),
            )
            .mount(&mock_server)
            .await;

        let (client, _payload, _receive_signal, server_handle) =
            spawn_shim_and_channel_client(test_channel_config(&mock_server.uri())).await?;

        // Wait for the event to be processed
        tokio::time::sleep(Duration::from_millis(500)).await;

        let result = client
            .call_tool(CallToolRequestParams::new("poll_events"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text content");
        let events: Vec<serde_json::Value> = serde_json::from_str(&text)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["meta"]["delivery_id"], "delivery-456");
        assert_eq!(events[0]["meta"]["forge_alias"], "internal");
        assert_eq!(events[0]["meta"]["change_request"], 24);

        // Second poll returns empty
        let result = client
            .call_tool(CallToolRequestParams::new("poll_events"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text content");
        assert_eq!(text, "[]");

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn poll_events_works_without_channels() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        let event_body = serde_json::json!({
            "kind": "change_request",
            "content": "change_request opened on internal/org/repo#24 at abc123",
            "meta": {
                "forge_alias": "internal",
                "owner": "org",
                "repo": "repo",
                "event_kind": "change_request",
                "action": "opened",
                "change_request": 24,
                "head_sha": "abc123",
                "delivery_id": "delivery-no-channels"
            }
        });
        let sse = format!(
            "event: change_request\nid: internal:delivery-no-channels\ndata: {event_body}\n\n",
        );

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/events"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse),
            )
            .mount(&mock_server)
            .await;

        // Use test_config (channels disabled), not test_channel_config.
        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let result = client
            .call_tool(CallToolRequestParams::new("poll_events"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text content");
        let events: Vec<serde_json::Value> = serde_json::from_str(&text)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["meta"]["delivery_id"], "delivery-no-channels");

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn issue_event_is_buffered_for_polling() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        let event_body = serde_json::json!({
            "kind": "issue",
            "content": "issue opened on internal/org/repo#42",
            "meta": {
                "forge_alias": "internal",
                "owner": "org",
                "repo": "repo",
                "event_kind": "issue",
                "action": "opened",
                "change_request": null,
                "head_sha": null,
                "issue": 42,
                "issue_comment": null,
                "delivery_id": "delivery-issue-1"
            }
        });
        let sse = format!("event: issue\nid: internal:delivery-issue-1\ndata: {event_body}\n\n",);

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/events"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse),
            )
            .mount(&mock_server)
            .await;

        let (client, _payload, _receive_signal, server_handle) =
            spawn_shim_and_channel_client(test_channel_config(&mock_server.uri())).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let result = client
            .call_tool(CallToolRequestParams::new("poll_events"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text content");
        let events: Vec<serde_json::Value> = serde_json::from_str(&text)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["meta"]["event_kind"], "issue");
        assert_eq!(events[0]["meta"]["issue"], 42);
        assert!(events[0]["meta"]["change_request"].is_null());

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn issue_comment_event_is_buffered_for_polling() -> Result<(), Box<dyn std::error::Error>>
    {
        let mock_server = wiremock::MockServer::start().await;
        let event_body = serde_json::json!({
            "kind": "issue_comment",
            "content": "issue_comment created on internal/org/repo#42",
            "meta": {
                "forge_alias": "internal",
                "owner": "org",
                "repo": "repo",
                "event_kind": "issue_comment",
                "action": "created",
                "change_request": null,
                "head_sha": null,
                "issue": 42,
                "issue_comment": 99,
                "delivery_id": "delivery-comment-1"
            }
        });
        let sse = format!(
            "event: issue_comment\nid: internal:delivery-comment-1\ndata: {event_body}\n\n",
        );

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/events"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse),
            )
            .mount(&mock_server)
            .await;

        let (client, _payload, _receive_signal, server_handle) =
            spawn_shim_and_channel_client(test_channel_config(&mock_server.uri())).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let result = client
            .call_tool(CallToolRequestParams::new("poll_events"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text content");
        let events: Vec<serde_json::Value> = serde_json::from_str(&text)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["meta"]["event_kind"], "issue_comment");
        assert_eq!(events[0]["meta"]["issue"], 42);
        assert_eq!(events[0]["meta"]["issue_comment"], 99);
        assert!(events[0]["meta"]["change_request"].is_null());

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn pull_request_review_event_is_buffered_for_polling()
    -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        let event_body = serde_json::json!({
            "kind": "pull_request_review",
            "content": "pull_request_review submitted (approved) on internal/org/repo#7 at abc123",
            "meta": {
                "forge_alias": "internal",
                "owner": "org",
                "repo": "repo",
                "event_kind": "pull_request_review",
                "action": "submitted",
                "change_request": 7,
                "head_sha": "abc123",
                "issue": null,
                "issue_comment": null,
                "delivery_id": "delivery-review-1",
                "review_state": "approved"
            }
        });
        let sse = format!(
            "event: pull_request_review\nid: internal:delivery-review-1\ndata: {event_body}\n\n",
        );

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/events"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse),
            )
            .mount(&mock_server)
            .await;

        let (client, _payload, _receive_signal, server_handle) =
            spawn_shim_and_channel_client(test_channel_config(&mock_server.uri())).await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let result = client
            .call_tool(CallToolRequestParams::new("poll_events"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text content");
        let events: Vec<serde_json::Value> = serde_json::from_str(&text)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["meta"]["event_kind"], "pull_request_review");
        assert_eq!(events[0]["meta"]["change_request"], 7);
        assert_eq!(events[0]["meta"]["review_state"], "approved");
        assert!(events[0]["meta"]["issue"].is_null());

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn update_issue_calls_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PATCH"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/test-forge/org/repo/issues/7",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "number": 7,
                    "title": "Updated title",
                    "body": "Updated body",
                    "state": "open",
                    "html_url": "https://forge.example/org/repo/issues/7",
                    "labels": [],
                    "assignees": []
                })),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "index": 7,
            "title": "Updated title",
            "body": "Updated body"
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("update_issue").with_arguments(args))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("Updated title"));

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn get_change_request_diff_writes_file() -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        let patch_text = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n # Hello\n+World\n";
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(
                r"/api/v1/repos/.+/.+/.+/pulls/\d+/diff",
            ))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer test-token",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "index": 1,
                    "patch": patch_text,
                })),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "index": 1
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("get_change_request_diff").with_arguments(args))
            .await?;

        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(parsed["index"], 1);
        assert_eq!(parsed["size_bytes"], patch_text.len());

        let diff_file = parsed["diff_file"].as_str().expect("diff_file path");
        let contents: String = tokio::fs::read_to_string(diff_file).await?;
        assert_eq!(contents, patch_text);

        // Clean up temp file
        let _ = tokio::fs::remove_file(diff_file).await;

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn get_change_request_diff_handles_large_patch() -> Result<(), Box<dyn std::error::Error>>
    {
        let mock_server = wiremock::MockServer::start().await;
        // Build a patch larger than 52KB to reproduce the truncation scenario.
        let mut large_patch = String::from(
            "diff --git a/big.txt b/big.txt\n--- a/big.txt\n+++ b/big.txt\n@@ -1 +1,6001 @@\n",
        );
        for i in 0..6000 {
            let _ = writeln!(large_patch, "+line {i:04} padding to make each line longer");
        }
        let expected_len = large_patch.len();
        assert!(expected_len > 52_000, "patch should exceed 52KB");

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(
                r"/api/v1/repos/.+/.+/.+/pulls/\d+/diff",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "index": 42,
                    "patch": &large_patch,
                })),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let args = serde_json::json!({
            "forge": "test-forge",
            "owner": "org",
            "repo": "repo",
            "index": 42
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("get_change_request_diff").with_arguments(args))
            .await?;

        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        let parsed: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(parsed["index"], 42);
        assert_eq!(parsed["size_bytes"], expected_len);

        // The file must contain the complete diff, not a truncated version.
        let diff_file = parsed["diff_file"].as_str().expect("diff_file path");
        let contents: String = tokio::fs::read_to_string(diff_file).await?;
        assert_eq!(
            contents.len(),
            expected_len,
            "diff file must not be truncated"
        );
        assert_eq!(contents, large_patch);

        let _ = tokio::fs::remove_file(diff_file).await;

        drop(client);
        server_handle.await??;
        Ok(())
    }
    #[tokio::test]
    async fn multi_gateway_routes_to_correct_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let mock_gw_a = wiremock::MockServer::start().await;
        let mock_gw_b = wiremock::MockServer::start().await;

        // Gateway A advertises forge "alpha"
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "forges": [{"alias": "alpha", "type": "forgejo"}]
                })),
            )
            .mount(&mock_gw_a)
            .await;

        // Gateway B advertises forge "beta"
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "forges": [{"alias": "beta", "type": "gitlab"}]
                })),
            )
            .mount(&mock_gw_b)
            .await;

        // Issue endpoint only on gateway A (forge alpha)
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/alpha/org/repo/issues/1",
            ))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer token-a",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"number": 1, "title": "Alpha issue"})),
            )
            .mount(&mock_gw_a)
            .await;

        // Issue endpoint only on gateway B (forge beta)
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/beta/org/repo/issues/2",
            ))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer token-b",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"number": 2, "title": "Beta issue"})),
            )
            .mount(&mock_gw_b)
            .await;

        let config = test_multi_gateway_config(&[
            ("gw-a", &mock_gw_a.uri(), "token-a"),
            ("gw-b", &mock_gw_b.uri(), "token-b"),
        ]);
        let (client, server_handle) = spawn_shim_and_client(config).await?;

        // Request to forge "alpha" should hit gateway A
        let args_alpha = serde_json::json!({
            "forge": "alpha", "owner": "org", "repo": "repo", "index": 1
        })
        .as_object()
        .expect("json args as object")
        .clone();
        let result = client
            .call_tool(CallToolRequestParams::new("get_issue").with_arguments(args_alpha))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("Alpha issue"));

        // Request to forge "beta" should hit gateway B
        let args_beta = serde_json::json!({
            "forge": "beta", "owner": "org", "repo": "repo", "index": 2
        })
        .as_object()
        .expect("json args as object")
        .clone();
        let result = client
            .call_tool(CallToolRequestParams::new("get_issue").with_arguments(args_beta))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("Beta issue"));

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn multi_gateway_ambiguous_alias_returns_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let mock_gw_a = wiremock::MockServer::start().await;
        let mock_gw_b = wiremock::MockServer::start().await;

        // Both gateways advertise forge "shared"
        for mock in [&mock_gw_a, &mock_gw_b] {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/api/v1/agent/info"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({
                        "agent_id": "test",
                        "forges": [{"alias": "shared", "type": "forgejo"}]
                    }),
                ))
                .mount(mock)
                .await;
        }

        let config = test_multi_gateway_config(&[
            ("gw-a", &mock_gw_a.uri(), "token-a"),
            ("gw-b", &mock_gw_b.uri(), "token-b"),
        ]);
        let (client, server_handle) = spawn_shim_and_client(config).await?;

        let args = serde_json::json!({
            "forge": "shared", "owner": "org", "repo": "repo", "index": 1
        })
        .as_object()
        .expect("json args as object")
        .clone();

        // MCP tool errors propagate as Err from call_tool
        let result = client
            .call_tool(CallToolRequestParams::new("get_issue").with_arguments(args))
            .await;
        let err = result.expect_err("expected error for ambiguous alias");
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("ambiguous"),
            "error should mention ambiguity: {err_msg}"
        );

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn multi_gateway_unknown_forge_returns_error() -> Result<(), Box<dyn std::error::Error>> {
        let mock_gw = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "forges": [{"alias": "known", "type": "forgejo"}]
                })),
            )
            .mount(&mock_gw)
            .await;

        // Need a second gateway to trigger multi-gw discovery path
        let mock_gw_b = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "forges": [{"alias": "other", "type": "gitlab"}]
                })),
            )
            .mount(&mock_gw_b)
            .await;

        let config = test_multi_gateway_config(&[
            ("gw-a", &mock_gw.uri(), "token-a"),
            ("gw-b", &mock_gw_b.uri(), "token-b"),
        ]);
        let (client, server_handle) = spawn_shim_and_client(config).await?;

        let args = serde_json::json!({
            "forge": "nonexistent", "owner": "org", "repo": "repo", "index": 1
        })
        .as_object()
        .expect("json args as object")
        .clone();

        // MCP tool errors propagate as Err from call_tool
        let result = client
            .call_tool(CallToolRequestParams::new("get_issue").with_arguments(args))
            .await;
        let err = result.expect_err("expected error for unknown forge");
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("unknown forge alias"),
            "error should mention unknown alias: {err_msg}"
        );

        drop(client);
        server_handle.await??;
        Ok(())
    }

    /// A gateway that was unreachable during initial discovery becomes
    /// reachable later.  The shim should re-discover and route to it.
    #[tokio::test]
    async fn multi_gateway_rediscovers_when_gateway_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        let mock_gw_a = wiremock::MockServer::start().await;
        let mock_gw_b = wiremock::MockServer::start().await;

        // Gateway A advertises forge "alpha" and always responds.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "forges": [{"alias": "alpha", "type": "forgejo"}]
                })),
            )
            .mount(&mock_gw_a)
            .await;

        // Gateway B initially returns 503 (unreachable) for discovery, then
        // responds normally.  We use `up_to(1)` for the 503 so the first
        // discovery hits a failure, then mount a 200 for the retry.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .up_to_n_times(1)
            .expect(1)
            .mount(&mock_gw_b)
            .await;

        // Issue endpoint on gateway A (forge alpha)
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/alpha/org/repo/issues/1",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"number": 1, "title": "Alpha issue"})),
            )
            .mount(&mock_gw_a)
            .await;

        // Issue endpoint on gateway B (forge beta) — will be reachable later.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/beta/org/repo/issues/2",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"number": 2, "title": "Beta issue"})),
            )
            .mount(&mock_gw_b)
            .await;

        let config = test_multi_gateway_config(&[
            ("gw-a", &mock_gw_a.uri(), "token-a"),
            ("gw-b", &mock_gw_b.uri(), "token-b"),
        ]);
        let (client, server_handle) = spawn_shim_and_client(config).await?;

        // First call to forge "alpha" triggers discovery — gateway B is
        // unreachable (503), but alpha works because it's on gateway A.
        let args_alpha = serde_json::json!({
            "forge": "alpha", "owner": "org", "repo": "repo", "index": 1
        })
        .as_object()
        .expect("json args as object")
        .clone();
        let result = client
            .call_tool(CallToolRequestParams::new("get_issue").with_arguments(args_alpha))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("Alpha issue"));

        // Now gateway B "recovers" — mount the 200 response for discovery.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "forges": [{"alias": "beta", "type": "gitlab"}]
                })),
            )
            .mount(&mock_gw_b)
            .await;

        // Request to forge "beta" — should trigger re-discovery since gateway B
        // was unreachable before.
        let args_beta = serde_json::json!({
            "forge": "beta", "owner": "org", "repo": "repo", "index": 2
        })
        .as_object()
        .expect("json args as object")
        .clone();
        let result = client
            .call_tool(CallToolRequestParams::new("get_issue").with_arguments(args_beta))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("Beta issue"));

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn multi_gateway_forge_info_aggregates() -> Result<(), Box<dyn std::error::Error>> {
        let mock_gw_a = wiremock::MockServer::start().await;
        let mock_gw_b = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test-a",
                    "branch_prefix": "agent/test/",
                    "forges": [{"alias": "alpha", "type": "forgejo"}]
                })),
            )
            .mount(&mock_gw_a)
            .await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test-b",
                    "branch_prefix": "agent/test/",
                    "forges": [{"alias": "beta", "type": "gitlab"}]
                })),
            )
            .mount(&mock_gw_b)
            .await;

        let config = test_multi_gateway_config(&[
            ("gw-a", &mock_gw_a.uri(), "token-a"),
            ("gw-b", &mock_gw_b.uri(), "token-b"),
        ]);
        let (client, server_handle) = spawn_shim_and_client(config).await?;

        let result = client
            .call_tool(CallToolRequestParams::new("forge_info"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        let parsed: serde_json::Value = serde_json::from_str(&text)?;

        // Should have merged forges list
        let forges = parsed["forges"].as_array().expect("forges array");
        assert_eq!(forges.len(), 2);
        let aliases: Vec<&str> = forges.iter().filter_map(|f| f["alias"].as_str()).collect();
        assert!(aliases.contains(&"alpha"));
        assert!(aliases.contains(&"beta"));

        // Should have gateways array
        let gateways = parsed["gateways"].as_array().expect("gateways array");
        assert_eq!(gateways.len(), 2);
        assert_eq!(gateways[0]["name"], "gw-a");
        assert_eq!(gateways[1]["name"], "gw-b");

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn single_gateway_forge_info_preserves_flat_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "branch_prefix": "agent/test/",
                    "forges": [{"alias": "internal", "type": "forgejo"}]
                })),
            )
            .mount(&mock_server)
            .await;

        let (client, server_handle) =
            spawn_shim_and_client(test_config(&mock_server.uri())).await?;

        let result = client
            .call_tool(CallToolRequestParams::new("forge_info"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        let parsed: serde_json::Value = serde_json::from_str(&text)?;

        // Single gateway should preserve flat shape with gateway_url
        assert!(parsed["gateway_url"].is_string(), "should have gateway_url");
        assert!(
            parsed["git_url_template"].is_string(),
            "should have git_url_template"
        );
        assert!(parsed["git_auth"].is_object(), "should have git_auth");
        // Should NOT have gateways array in single-gateway mode
        assert!(
            parsed["gateways"].is_null(),
            "should not have gateways array"
        );

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn multi_gateway_skips_unreachable_during_discovery()
    -> Result<(), Box<dyn std::error::Error>> {
        let mock_gw_healthy = wiremock::MockServer::start().await;

        // Healthy gateway advertises forge "healthy"
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "forges": [{"alias": "healthy", "type": "forgejo"}]
                })),
            )
            .mount(&mock_gw_healthy)
            .await;

        // Issue endpoint on healthy gateway
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/healthy/org/repo/issues/1",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"number": 1, "title": "Healthy issue"})),
            )
            .mount(&mock_gw_healthy)
            .await;

        // Second gateway is unreachable (port that nothing listens on)
        let config = test_multi_gateway_config(&[
            ("gw-healthy", &mock_gw_healthy.uri(), "token-h"),
            ("gw-down", "http://127.0.0.1:1", "token-d"),
        ]);
        let (client, server_handle) = spawn_shim_and_client(config).await?;

        // Request to the healthy forge should succeed despite the other gateway being down
        let args = serde_json::json!({
            "forge": "healthy", "owner": "org", "repo": "repo", "index": 1
        })
        .as_object()
        .expect("json args as object")
        .clone();

        let result = client
            .call_tool(CallToolRequestParams::new("get_issue").with_arguments(args))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        assert!(text.contains("Healthy issue"));

        drop(client);
        server_handle.await??;
        Ok(())
    }

    /// A gateway with a malformed URL must be skipped during discovery,
    /// not abort routing to healthy gateways.
    #[tokio::test]
    async fn multi_gateway_skips_malformed_url_during_discovery()
    -> Result<(), Box<dyn std::error::Error>> {
        let mock_gw_healthy = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "forges": [{"alias": "healthy", "type": "forgejo"}]
                })),
            )
            .mount(&mock_gw_healthy)
            .await;

        // "://bad" is not a valid URL — build_url will fail for this gateway.
        let config = test_multi_gateway_config(&[
            ("gw-healthy", &mock_gw_healthy.uri(), "token-h"),
            ("gw-bad", "://bad", "token-b"),
        ]);
        let shim = McpShim::new(config);

        // Discovery should succeed, routing "healthy" to gw-healthy.
        let gw = shim.resolve_gateway("healthy").await?;
        assert_eq!(gw.name, "gw-healthy");

        Ok(())
    }

    #[tokio::test]
    async fn multi_gateway_forge_info_includes_unreachable_gateway()
    -> Result<(), Box<dyn std::error::Error>> {
        let mock_gw_healthy = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "branch_prefix": "agent/test/",
                    "forges": [{"alias": "healthy", "type": "forgejo"}]
                })),
            )
            .mount(&mock_gw_healthy)
            .await;

        let config = test_multi_gateway_config(&[
            ("gw-healthy", &mock_gw_healthy.uri(), "token-h"),
            ("gw-down", "http://127.0.0.1:1", "token-d"),
        ]);
        let (client, server_handle) = spawn_shim_and_client(config).await?;

        let result = client
            .call_tool(CallToolRequestParams::new("forge_info"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        let parsed: serde_json::Value = serde_json::from_str(&text)?;

        // Merged forges should only contain the healthy gateway's forge
        let forges = parsed["forges"].as_array().expect("forges array");
        assert_eq!(forges.len(), 1);
        assert_eq!(forges[0]["alias"], "healthy");

        // Gateways array should contain both entries
        let gateways = parsed["gateways"].as_array().expect("gateways array");
        assert_eq!(gateways.len(), 2);

        // Healthy gateway should have forges, no error
        assert_eq!(gateways[0]["name"], "gw-healthy");
        assert!(
            gateways[0]["error"].is_null(),
            "healthy gw should have no error"
        );

        // Down gateway should have an error field
        assert_eq!(gateways[1]["name"], "gw-down");
        assert!(
            gateways[1]["error"].is_string(),
            "down gw should have error"
        );

        drop(client);
        server_handle.await??;
        Ok(())
    }

    /// A gateway with a malformed URL must be skipped during `forge_info`,
    /// not abort the entire response.
    #[tokio::test]
    async fn multi_gateway_forge_info_skips_malformed_url() -> Result<(), Box<dyn std::error::Error>>
    {
        let mock_gw_healthy = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test",
                    "branch_prefix": "agent/test/",
                    "forges": [{"alias": "healthy", "type": "forgejo"}]
                })),
            )
            .mount(&mock_gw_healthy)
            .await;

        // "://bad" is not a valid URL — build_url will fail for this gateway.
        let config = test_multi_gateway_config(&[
            ("gw-healthy", &mock_gw_healthy.uri(), "token-h"),
            ("gw-bad", "://bad", "token-b"),
        ]);
        let (client, server_handle) = spawn_shim_and_client(config).await?;

        let result = client
            .call_tool(CallToolRequestParams::new("forge_info"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        let parsed: serde_json::Value = serde_json::from_str(&text)?;

        // Merged forges should only contain the healthy gateway's forge
        let forges = parsed["forges"].as_array().expect("forges array");
        assert_eq!(forges.len(), 1);
        assert_eq!(forges[0]["alias"], "healthy");

        // Gateways array should contain both entries
        let gateways = parsed["gateways"].as_array().expect("gateways array");
        assert_eq!(gateways.len(), 2);

        // Healthy gateway should have forges, no error
        assert_eq!(gateways[0]["name"], "gw-healthy");
        assert!(
            gateways[0]["error"].is_null(),
            "healthy gw should have no error"
        );

        // Malformed gateway should have an error field
        assert_eq!(gateways[1]["name"], "gw-bad");
        assert!(
            gateways[1]["error"].is_string(),
            "malformed gw should have error"
        );

        drop(client);
        server_handle.await??;
        Ok(())
    }

    /// When two gateways advertise the same forge alias, `forge_info` must
    /// include an `ambiguous_aliases` field so the caller can see the problem
    /// before tool routing fails.
    #[tokio::test]
    async fn multi_gateway_forge_info_surfaces_ambiguous_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        let mock_gw_a = wiremock::MockServer::start().await;
        let mock_gw_b = wiremock::MockServer::start().await;

        // Both gateways advertise forge "shared"
        for mock in [&mock_gw_a, &mock_gw_b] {
            wiremock::Mock::given(wiremock::matchers::method("GET"))
                .and(wiremock::matchers::path("/api/v1/agent/info"))
                .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({
                        "agent_id": "test",
                        "branch_prefix": "agent/test/",
                        "forges": [{"alias": "shared", "type": "forgejo"}]
                    }),
                ))
                .mount(mock)
                .await;
        }

        let config = test_multi_gateway_config(&[
            ("gw-a", &mock_gw_a.uri(), "token-a"),
            ("gw-b", &mock_gw_b.uri(), "token-b"),
        ]);
        let (client, server_handle) = spawn_shim_and_client(config).await?;

        let result = client
            .call_tool(CallToolRequestParams::new("forge_info"))
            .await?;
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.clone())
            .expect("text result");
        let parsed: serde_json::Value = serde_json::from_str(&text)?;

        let ambiguous = parsed["ambiguous_aliases"]
            .as_array()
            .expect("ambiguous_aliases array");
        assert_eq!(ambiguous.len(), 1);
        let msg = ambiguous[0].as_str().expect("ambiguous alias as string");
        assert!(
            msg.contains("shared"),
            "ambiguity message should mention the alias: {msg}"
        );
        assert!(
            msg.contains("gw-a") && msg.contains("gw-b"),
            "ambiguity message should mention both gateways: {msg}"
        );

        drop(client);
        server_handle.await??;
        Ok(())
    }

    /// When a forge alias moves between gateways, `resolve_gateway` must
    /// pick up the change immediately (no stale cached routing).
    #[tokio::test]
    async fn multi_gateway_picks_up_topology_change() -> Result<(), Box<dyn std::error::Error>> {
        let mock_gw_a = wiremock::MockServer::start().await;
        let mock_gw_b = wiremock::MockServer::start().await;

        // Initial topology: gw-a has "alpha", gw-b has "beta".
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test-a",
                    "forges": [{"alias": "alpha", "type": "forgejo"}]
                })),
            )
            .up_to_n_times(1)
            .mount(&mock_gw_a)
            .await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test-b",
                    "forges": [{"alias": "beta", "type": "gitlab"}]
                })),
            )
            .up_to_n_times(1)
            .mount(&mock_gw_b)
            .await;

        let config = test_multi_gateway_config(&[
            ("gw-a", &mock_gw_a.uri(), "token-a"),
            ("gw-b", &mock_gw_b.uri(), "token-b"),
        ]);
        let shim = McpShim::new(config);

        // First resolve discovers "alpha" on gw-a.
        let gw = shim.resolve_gateway("alpha").await?;
        assert_eq!(gw.name, "gw-a");

        // Change topology: gw-a no longer has "alpha", gw-b now has "alpha".
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test-a",
                    "forges": []
                })),
            )
            .mount(&mock_gw_a)
            .await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/agent/info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "agent_id": "test-b",
                    "forges": [{"alias": "alpha", "type": "forgejo"}, {"alias": "beta", "type": "gitlab"}]
                })),
            )
            .mount(&mock_gw_b)
            .await;

        // Next resolve should immediately discover "alpha" moved to gw-b.
        let gw = shim.resolve_gateway("alpha").await?;
        assert_eq!(gw.name, "gw-b");

        Ok(())
    }

    #[tokio::test]
    async fn get_change_request_ci_details_tool() -> Result<(), Box<dyn std::error::Error>> {
        let mock = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/api/v1/repos/adlevio/tokarix/forge-mcp/pulls/147/ci-details",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "head_sha": "abc123",
                    "state": "failure",
                    "details": [
                        {
                            "context": "ci/woodpecker",
                            "description": "failed",
                            "state": "failure",
                            "target_url": "https://ci.example/1",
                            "resolution": {
                                "type": "resolved",
                                "provider": "woodpecker",
                                "pipeline_url": "https://ci.example/1",
                                "failed_steps": []
                            }
                        }
                    ]
                })),
            )
            .mount(&mock)
            .await;

        let config = test_config(&mock.uri());
        let shim = McpShim::new(config);

        let request = serde_json::json!({
            "forge": "adlevio",
            "owner": "tokarix",
            "repo": "forge-mcp",
            "index": 147
        });

        let result = shim
            .get_change_request_ci_details(Parameters(serde_json::from_value(request)?))
            .await?;

        let json: serde_json::Value = serde_json::from_str(&result)?;
        assert_eq!(json["head_sha"], "abc123");
        assert_eq!(json["state"], "failure");
        assert_eq!(json["details"][0]["context"], "ci/woodpecker");

        Ok(())
    }
}
