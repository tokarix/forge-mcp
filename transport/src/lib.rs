//! Stdio MCP transport for the Forgejo server.

use std::sync::Arc;

use domain::{
    AgentIdentity, CommitPatchRequest, ForgeKind, OpenChangeRequestRequest,
    ReadRepositoryFileRequest, RepositoryReadService, RepositoryRef, RepositoryWriteService,
    ServiceError,
};
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

/// Immutable configuration for the stdio MCP server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgejoMcpConfig {
    pub forgejo_base_url: String,
    pub agent_id: String,
    pub session_id: String,
    pub server_name: String,
    pub server_version: String,
}

/// Errors that can occur while serving the MCP transport.
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
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name.
    pub repo: String,
    /// Repository-relative file path.
    pub path: String,
    /// Optional git ref such as a branch, tag, or commit SHA.
    pub git_ref: Option<String>,
}

pub struct ForgejoMcpServer<R, W>
where
    R: RepositoryReadService + 'static,
    W: RepositoryWriteService + 'static,
{
    config: ForgejoMcpConfig,
    read_service: Arc<R>,
    tool_router: ToolRouter<Self>,
    write_service: Arc<W>,
}

impl<R, W> ForgejoMcpServer<R, W>
where
    R: RepositoryReadService + 'static,
    W: RepositoryWriteService + 'static,
{
    #[must_use]
    pub fn new(config: ForgejoMcpConfig, read_service: Arc<R>, write_service: Arc<W>) -> Self {
        Self {
            config,
            read_service,
            tool_router: Self::tool_router(),
            write_service,
        }
    }

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
}

#[tool_router]
impl<R, W> ForgejoMcpServer<R, W>
where
    R: RepositoryReadService + 'static,
    W: RepositoryWriteService + 'static,
{
    /// Apply a unified diff patch to a new branch and push it.
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
            .commit_patch(CommitPatchRequest {
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
                    name: request.repo,
                    owner: request.owner,
                },
            })
            .await
            .map_err(Self::map_service_error)?;
        Ok(format!(
            "Committed to branch '{}' at {}",
            response.branch, response.commit_sha
        ))
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
        let response = self
            .write_service
            .open_change_request(OpenChangeRequestRequest {
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
                    name: request.repo,
                    owner: request.owner,
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

    /// Read a single UTF-8 text file from a Forgejo repository.
    #[tool(
        name = "read_repository_file",
        description = "Read a single UTF-8 text file from a Forgejo repository."
    )]
    async fn read_repository_file(
        &self,
        Parameters(request): Parameters<ReadRepositoryFileTool>,
    ) -> Result<String, McpError> {
        self.read_service
            .read_repository_file(ReadRepositoryFileRequest {
                agent: AgentIdentity {
                    agent_id: self.config.agent_id.clone(),
                    session_id: self.config.session_id.clone(),
                },
                repository: RepositoryRef {
                    forge: ForgeKind::Forgejo,
                    host: self.config.forgejo_base_url.clone(),
                    owner: request.owner,
                    name: request.repo,
                },
                path: request.path,
                git_ref: request.git_ref,
            })
            .await
            .map(|response| response.content)
            .map_err(Self::map_service_error)
    }
}

#[tool_handler(router = self.tool_router)]
impl<R, W> ServerHandler for ForgejoMcpServer<R, W>
where
    R: RepositoryReadService + 'static,
    W: RepositoryWriteService + 'static,
{
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Forgejo-first read-only MCP server. Agents can read repository files but do not receive forge credentials.",
            )
            .with_server_info(Implementation::new(
                self.config.server_name.clone(),
                self.config.server_version.clone(),
            ))
    }
}

/// Serve the Forgejo-backed MCP server over stdio.
///
/// # Errors
///
/// Returns an error if the MCP server cannot initialize or if the runtime task
/// exits unexpectedly.
pub async fn serve_stdio<R, W>(
    config: ForgejoMcpConfig,
    read_service: Arc<R>,
    write_service: Arc<W>,
) -> Result<(), TransportError>
where
    R: RepositoryReadService + 'static,
    W: RepositoryWriteService + 'static,
{
    ForgejoMcpServer::new(config, read_service, write_service)
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
    use std::sync::Arc;

    use async_trait::async_trait;
    use domain::{
        CommitPatchResponse, OpenChangeRequestResponse, ReadRepositoryFileResponse, ServiceError,
    };
    use rmcp::{
        ClientHandler, ServiceExt,
        model::{CallToolRequestParams, ClientInfo, ErrorCode},
    };

    use super::{ForgejoMcpConfig, ForgejoMcpServer, TransportError};

    struct FakeReadService;

    #[async_trait]
    impl domain::RepositoryReadService for FakeReadService {
        async fn get_change_request(
            &self,
            _request: domain::GetChangeRequestRequest,
        ) -> Result<domain::ChangeRequest, ServiceError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _request: domain::ListChangeRequestsRequest,
        ) -> Result<Vec<domain::ChangeRequest>, ServiceError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            request: domain::ReadRepositoryFileRequest,
        ) -> Result<ReadRepositoryFileResponse, ServiceError> {
            Ok(ReadRepositoryFileResponse {
                repository: request.repository,
                path: request.path,
                git_ref: request.git_ref,
                content: "mcp-ok".to_string(),
            })
        }
    }

    #[async_trait]
    impl domain::RepositoryWriteService for FakeReadService {
        async fn commit_patch(
            &self,
            _request: domain::CommitPatchRequest,
        ) -> Result<CommitPatchResponse, ServiceError> {
            unimplemented!()
        }

        async fn open_change_request(
            &self,
            _request: domain::OpenChangeRequestRequest,
        ) -> Result<OpenChangeRequestResponse, ServiceError> {
            unimplemented!()
        }
    }

    struct ValidationFailReadService;

    #[async_trait]
    impl domain::RepositoryReadService for ValidationFailReadService {
        async fn get_change_request(
            &self,
            _request: domain::GetChangeRequestRequest,
        ) -> Result<domain::ChangeRequest, ServiceError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _request: domain::ListChangeRequestsRequest,
        ) -> Result<Vec<domain::ChangeRequest>, ServiceError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            _request: domain::ReadRepositoryFileRequest,
        ) -> Result<ReadRepositoryFileResponse, ServiceError> {
            Err(ServiceError::Validation("bad path".to_string()))
        }
    }

    #[async_trait]
    impl domain::RepositoryWriteService for ValidationFailReadService {
        async fn commit_patch(
            &self,
            _request: domain::CommitPatchRequest,
        ) -> Result<CommitPatchResponse, ServiceError> {
            unimplemented!()
        }

        async fn open_change_request(
            &self,
            _request: domain::OpenChangeRequestRequest,
        ) -> Result<OpenChangeRequestResponse, ServiceError> {
            unimplemented!()
        }
    }

    struct UpstreamFailReadService;

    #[async_trait]
    impl domain::RepositoryReadService for UpstreamFailReadService {
        async fn get_change_request(
            &self,
            _request: domain::GetChangeRequestRequest,
        ) -> Result<domain::ChangeRequest, ServiceError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _request: domain::ListChangeRequestsRequest,
        ) -> Result<Vec<domain::ChangeRequest>, ServiceError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            _request: domain::ReadRepositoryFileRequest,
        ) -> Result<ReadRepositoryFileResponse, ServiceError> {
            Err(ServiceError::Upstream("forge down".to_string()))
        }
    }

    #[async_trait]
    impl domain::RepositoryWriteService for UpstreamFailReadService {
        async fn commit_patch(
            &self,
            _request: domain::CommitPatchRequest,
        ) -> Result<CommitPatchResponse, ServiceError> {
            unimplemented!()
        }

        async fn open_change_request(
            &self,
            _request: domain::OpenChangeRequestRequest,
        ) -> Result<OpenChangeRequestResponse, ServiceError> {
            unimplemented!()
        }
    }

    #[derive(Debug, Clone, Default)]
    struct DummyClientHandler;

    impl ClientHandler for DummyClientHandler {
        fn get_info(&self) -> ClientInfo {
            ClientInfo::default()
        }
    }

    fn test_config() -> ForgejoMcpConfig {
        ForgejoMcpConfig {
            forgejo_base_url: "https://forge.example".to_string(),
            agent_id: "codex".to_string(),
            session_id: "test-session".to_string(),
            server_name: "forge-mcp".to_string(),
            server_version: "0.1.0-test".to_string(),
        }
    }

    fn read_file_args() -> serde_json::Map<String, serde_json::Value> {
        serde_json::json!({
            "owner": "org",
            "repo": "repo",
            "path": "README.md",
            "git_ref": "main",
        })
        .as_object()
        .expect("json object")
        .clone()
    }

    async fn spawn_server_and_client<S>(
        service: Arc<S>,
    ) -> Result<
        (
            rmcp::service::RunningService<rmcp::service::RoleClient, DummyClientHandler>,
            tokio::task::JoinHandle<Result<(), TransportError>>,
        ),
        Box<dyn std::error::Error>,
    >
    where
        S: domain::RepositoryReadService + domain::RepositoryWriteService + 'static,
    {
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let config = test_config();

        let read_service = Arc::clone(&service);
        let write_service = service;
        let server_handle = tokio::spawn(async move {
            ForgejoMcpServer::new(config, read_service, write_service)
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
    async fn serves_read_repository_file_over_mcp() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server_handle) = spawn_server_and_client(Arc::new(FakeReadService)).await?;

        let result = client
            .call_tool(
                CallToolRequestParams::new("read_repository_file").with_arguments(read_file_args()),
            )
            .await?;

        let text = result
            .content
            .first()
            .and_then(|content| content.raw.as_text())
            .map(|text| text.text.clone())
            .expect("text result");
        assert_eq!(text, "mcp-ok");

        drop(client);
        server_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn maps_validation_error_to_invalid_params() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server_handle) =
            spawn_server_and_client(Arc::new(ValidationFailReadService)).await?;

        let err = client
            .call_tool(
                CallToolRequestParams::new("read_repository_file").with_arguments(read_file_args()),
            )
            .await
            .expect_err("validation error should propagate as MCP error");

        match err {
            rmcp::ServiceError::McpError(ref mcp_err) => {
                assert_eq!(mcp_err.code, ErrorCode::INVALID_PARAMS);
            }
            other => panic!("expected McpError, got: {other}"),
        }

        drop(client);
        // Server may exit with an error due to client disconnect; that's fine
        let _ = server_handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn maps_upstream_error_to_internal_error() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server_handle) =
            spawn_server_and_client(Arc::new(UpstreamFailReadService)).await?;

        let err = client
            .call_tool(
                CallToolRequestParams::new("read_repository_file").with_arguments(read_file_args()),
            )
            .await
            .expect_err("upstream error should propagate as MCP error");

        match err {
            rmcp::ServiceError::McpError(ref mcp_err) => {
                assert_eq!(mcp_err.code, ErrorCode::INTERNAL_ERROR);
            }
            other => panic!("expected McpError, got: {other}"),
        }

        drop(client);
        let _ = server_handle.await;
        Ok(())
    }
}
