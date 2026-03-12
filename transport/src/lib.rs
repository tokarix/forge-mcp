//! MCP shim — translates MCP tool calls into HTTP requests to the control plane.

use std::fmt::Write as _;

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

    /// Makes an HTTP GET request to the control plane.
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

    /// Makes an HTTP POST request to the control plane.
    async fn gateway_post(
        &self,
        path: &str,
        json_body: &impl serde::Serialize,
    ) -> Result<String, McpError> {
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
        let path = format!("/api/v1/repos/{}/{}/patches", request.owner, request.repo);
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
        let mut path = format!("/api/v1/repos/{}/{}/pulls", request.owner, request.repo);
        if let Some(state) = &request.state {
            write!(path, "?state={state}").unwrap();
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
        let path = format!("/api/v1/repos/{}/{}/pulls", request.owner, request.repo);
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
            write!(path, "?ref={git_ref}").unwrap();
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
                r"/api/v1/repos/.+/contents/.+",
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
