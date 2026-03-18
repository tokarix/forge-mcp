//! MCP shim — translates MCP tool calls into HTTP requests to the control plane.

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
#[derive(Clone)]
pub struct ShimConfig {
    pub gateway_url: String,
    pub server_name: String,
    pub server_version: String,
    pub token: String,
}

impl std::fmt::Debug for ShimConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShimConfig")
            .field("gateway_url", &self.gateway_url)
            .field("server_name", &self.server_name)
            .field("server_version", &self.server_version)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("mcp server initialization failed: {0}")]
    Initialize(Box<rmcp::service::ServerInitializeError>),
    #[error("mcp server task failed: {0}")]
    Runtime(#[from] tokio::task::JoinError),
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloseChangeRequestTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
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
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommitPatchTool {
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
    /// Unified diff patch to apply. Provide either this or `patch_file`.
    pub patch: Option<String>,
    /// Path to a file containing the unified diff patch. Use this instead of
    /// `patch` for large diffs that may exceed tool parameter limits.
    pub patch_file: Option<String>,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetChangeRequestDiffTool {
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
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
    /// `"type"` field. Currently supported: `{"type": "fixup", "commit": "<sha>", "into": "<sha>"}`.
    pub operations: Vec<RebaseBranchOperationTool>,
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RebaseBranchOperationTool {
    Fixup {
        /// Full SHA of the commit to squash.
        commit: String,
        /// Full SHA of the commit to squash into.
        into: String,
    },
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
pub struct SubmitChangeRequestReviewTool {
    /// Review body text.
    pub body: String,
    /// Review event: `APPROVED`, `REQUEST_CHANGES`, or `COMMENT`.
    pub event: String,
    /// Forge alias -- use `forge_info` to discover available aliases.
    pub forge: String,
    /// Change request index number.
    pub index: u64,
    /// Repository owner or organization.
    pub owner: String,
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

    /// Parses the gateway base URL, returning an MCP error on failure.
    fn base_url(&self) -> Result<reqwest::Url, McpError> {
        let mut base = self.config.gateway_url.clone();
        if !base.ends_with('/') {
            base.push('/');
        }
        reqwest::Url::parse(&base)
            .map_err(|e| McpError::internal_error(format!("invalid gateway URL: {e}"), None))
    }

    /// Builds a URL by appending percent-encoded path segments to the base.
    fn build_url(&self, segments: &[&str]) -> Result<reqwest::Url, McpError> {
        let mut url = self.base_url()?;
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

    /// Makes an HTTP GET request to the control plane.
    async fn gateway_get(&self, url: reqwest::Url) -> Result<String, McpError> {
        let response = self
            .client
            .get(url)
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
            return Err(Self::map_http_error(status, body));
        }

        Ok(body)
    }

    /// Makes an HTTP DELETE request to the control plane.
    async fn gateway_delete(&self, url: reqwest::Url) -> Result<String, McpError> {
        let response = self
            .client
            .delete(url)
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
            return Err(Self::map_http_error(status, body));
        }

        Ok(body)
    }

    /// Makes an HTTP POST request to the control plane.
    async fn gateway_post(
        &self,
        url: reqwest::Url,
        json_body: &impl serde::Serialize,
    ) -> Result<String, McpError> {
        let response = self
            .client
            .post(url)
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
            return Err(Self::map_http_error(status, body));
        }

        Ok(body)
    }
}

#[tool_router]
impl McpShim {
    /// Close a change request (pull request) on the forge.
    #[tool(
        name = "close_change_request",
        description = "Close a change request (pull request) on the forge. Only works for PRs whose head branch matches your configured branch prefix."
    )]
    async fn close_change_request(
        &self,
        Parameters(request): Parameters<CloseChangeRequestTool>,
    ) -> Result<String, McpError> {
        let url = self.build_url(&[
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "pulls",
            &request.index.to_string(),
        ])?;
        self.gateway_delete(url).await
    }

    /// Post a general comment on a change request (pull request).
    #[tool(
        name = "comment_on_change_request",
        description = "Post a general comment on a change request (pull request). This is not a formal review — use submit_change_request_review for that."
    )]
    async fn comment_on_change_request(
        &self,
        Parameters(request): Parameters<CommentOnChangeRequestTool>,
    ) -> Result<String, McpError> {
        let url = self.build_url(&[
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "pulls",
            &request.index.to_string(),
            "comments",
        ])?;
        let body = serde_json::json!({
            "body": request.body,
        });
        self.gateway_post(url, &body).await
    }

    /// Apply a unified diff patch to a new branch and push it.
    #[tool(
        name = "commit_patch",
        description = "Apply a unified diff patch to a new branch and push it."
    )]
    async fn commit_patch(
        &self,
        Parameters(request): Parameters<CommitPatchTool>,
    ) -> Result<String, McpError> {
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

        let url = self.build_url(&[
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "patches",
        ])?;
        let body = serde_json::json!({
            "base_branch": request.base_branch,
            "commit_message": request.commit_message,
            "existing_branch": request.existing_branch,
            "new_branch": request.new_branch,
            "patch": patch,
        });
        self.gateway_post(url, &body).await
    }

    /// Get the unified diff for a change request.
    #[tool(
        name = "get_change_request_diff",
        description = "Get the unified diff (patch) for a change request (pull request)."
    )]
    async fn get_change_request_diff(
        &self,
        Parameters(request): Parameters<GetChangeRequestDiffTool>,
    ) -> Result<String, McpError> {
        let url = self.build_url(&[
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "pulls",
            &request.index.to_string(),
            "diff",
        ])?;
        self.gateway_get(url).await
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
        let url = self.build_url(&[
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "pulls",
            &request.index.to_string(),
        ])?;
        self.gateway_get(url).await
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
        let mut url = self.build_url(&[
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "pulls",
        ])?;
        if let Some(state) = &request.state {
            url.query_pairs_mut().append_pair("state", state);
        }
        self.gateway_get(url).await
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
        let url = self.build_url(&[
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "pulls",
        ])?;
        let body = serde_json::json!({
            "base_branch": request.base_branch,
            "body": request.body,
            "head_branch": request.head_branch,
            "title": request.title,
        });
        self.gateway_post(url, &body).await
    }

    /// Rebase a branch by squashing (fixup) commits.
    #[tool(
        name = "rebase_branch",
        description = "Rebase a branch by squashing (fixup) commits. Performs a full clone, validates operations, runs interactive rebase, verifies tree integrity, and force-pushes with lease. Only works on branches matching your configured branch prefix."
    )]
    async fn rebase_branch(
        &self,
        Parameters(request): Parameters<RebaseBranchTool>,
    ) -> Result<String, McpError> {
        let url = self.build_url(&[
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "rebase",
        ])?;

        let operations: Vec<serde_json::Value> = request
            .operations
            .iter()
            .map(|op| match op {
                RebaseBranchOperationTool::Fixup { commit, into } => {
                    serde_json::json!({
                        "type": "fixup",
                        "commit": commit,
                        "into": into,
                    })
                }
            })
            .collect();

        let body = serde_json::json!({
            "base_branch": request.base_branch,
            "branch": request.branch,
            "operations": operations,
        });
        self.gateway_post(url, &body).await
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
        let mut url = self.build_url(&segments)?;

        if let Some(git_ref) = &request.git_ref {
            url.query_pairs_mut().append_pair("ref", git_ref);
        }
        let response = self.gateway_get(url).await?;

        // Extract just the content field from the JSON response
        let parsed: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| McpError::internal_error(format!("invalid JSON response: {e}"), None))?;
        parsed["content"]
            .as_str()
            .map(ToString::to_string)
            .ok_or_else(|| McpError::internal_error("missing content field".to_string(), None))
    }

    /// Submit a formal review on a change request (pull request).
    #[tool(
        name = "submit_change_request_review",
        description = "Submit a formal review on a change request (pull request). Event must be APPROVED, REQUEST_CHANGES, or COMMENT."
    )]
    async fn submit_change_request_review(
        &self,
        Parameters(request): Parameters<SubmitChangeRequestReviewTool>,
    ) -> Result<String, McpError> {
        let url = self.build_url(&[
            "api",
            "v1",
            "repos",
            &request.forge,
            &request.owner,
            &request.repo,
            "pulls",
            &request.index.to_string(),
            "reviews",
        ])?;
        let body = serde_json::json!({
            "body": request.body,
            "event": request.event,
        });
        self.gateway_post(url, &body).await
    }

    /// Discover available forges, gateway URL, git proxy pattern, and auth.
    #[tool(
        name = "forge_info",
        description = "Discover available forge instances, gateway URL, git proxy URL template, and authentication details. Call this first to learn which forges you can access and how to clone repositories."
    )]
    async fn forge_info(&self) -> Result<String, McpError> {
        let url = self.build_url(&["api", "v1", "agent", "info"])?;
        let response = self.gateway_get(url).await?;

        let mut parsed: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| McpError::internal_error(format!("invalid JSON response: {e}"), None))?;

        let gateway_url = self.config.gateway_url.trim_end_matches('/');
        parsed["gateway_url"] = serde_json::Value::String(gateway_url.to_string());
        parsed["git_url_template"] =
            serde_json::Value::String(format!("{gateway_url}/git/{{forge}}/{{owner}}/{{repo}}"));
        parsed["git_auth"] = serde_json::json!({
            "scheme": "basic",
            "username": "any non-empty value",
            "password_source": "agent_token"
        });

        serde_json::to_string_pretty(&parsed)
            .map_err(|e| McpError::internal_error(format!("JSON serialization failed: {e}"), None))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpShim {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(format!(
                "MCP shim for forge-mcp control plane. Proxies tool calls to the HTTP API.\n\
                 \n\
                 Git clone/fetch: the gateway provides a read-only git smart HTTP proxy.\n\
                 URL: {gateway_url}/git/{{forge}}/{{owner}}/{{repo}}\n\
                 Auth: HTTP Basic -- any non-empty username, password is your agent token.\n\
                 git push is blocked -- use the commit_patch tool instead.\n\
                 \n\
                 Write workflow: clone via git proxy, make changes, generate a unified diff,\n\
                 submit via commit_patch, then open a PR via open_change_request.\n\
                 \n\
                 Never commit to the default branch directly. Work on branches matching\n\
                 your configured branch_prefix and submit via commit_patch + open_change_request.\n\
                 Use forge_info to discover your available forges.",
                gateway_url = self.config.gateway_url.trim_end_matches('/'),
            ))
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
        ClientHandler, ServiceExt,
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

    #[test]
    fn debug_redacts_token() {
        let config = test_config("https://example.com");
        let debug = format!("{config:?}");
        assert!(!debug.contains("test-token"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn build_url_encodes_reserved_characters() {
        let shim = McpShim::new(test_config("https://example.com"));
        let url = shim
            .build_url(&["api", "v1", "repos", "org", "repo", "contents", "a?b#c"])
            .unwrap();
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
        let shim = McpShim::new(test_config("https://example.com"));
        let mut url = shim
            .build_url(&["api", "v1", "repos", "org", "repo", "contents", "file"])
            .unwrap();
        url.query_pairs_mut()
            .append_pair("ref", "feat/branch&evil=1");
        let query = url.query().unwrap();
        // The & in the ref value should be encoded, not treated as a separator
        assert!(
            !query.contains("evil=1"),
            "query should encode & in values: {query}"
        );
    }

    #[test]
    fn build_url_nested_path_segments() {
        let shim = McpShim::new(test_config("https://example.com"));
        let path_parts: Vec<&str> = "src/main.rs".split('/').collect();
        let mut segments: Vec<&str> = vec!["api", "v1", "repos", "org", "repo", "contents"];
        segments.extend(path_parts.iter());
        let url = shim.build_url(&segments).unwrap();
        assert_eq!(url.path(), "/api/v1/repos/org/repo/contents/src/main.rs");
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
