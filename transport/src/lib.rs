//! Stdio MCP transport for the Phase 1 read-only Forgejo server.

use std::sync::Arc;

use domain::{
    AgentIdentity, ForgeKind, ReadRepositoryFileRequest, RepositoryReadService, RepositoryRef,
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

pub struct ForgejoMcpServer<S>
where
    S: RepositoryReadService + 'static,
{
    config: ForgejoMcpConfig,
    read_service: Arc<S>,
    tool_router: ToolRouter<Self>,
}

impl<S> ForgejoMcpServer<S>
where
    S: RepositoryReadService + 'static,
{
    #[must_use]
    pub fn new(config: ForgejoMcpConfig, read_service: Arc<S>) -> Self {
        Self {
            config,
            read_service,
            tool_router: Self::tool_router(),
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
impl<S> ForgejoMcpServer<S>
where
    S: RepositoryReadService + 'static,
{
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
impl<S> ServerHandler for ForgejoMcpServer<S>
where
    S: RepositoryReadService + 'static,
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
pub async fn serve_stdio<S>(
    config: ForgejoMcpConfig,
    read_service: Arc<S>,
) -> Result<(), TransportError>
where
    S: RepositoryReadService + 'static,
{
    ForgejoMcpServer::new(config, read_service)
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
    use domain::{ReadRepositoryFileResponse, ServiceError};
    use rmcp::{
        ClientHandler, ServiceExt,
        model::{CallToolRequestParams, ClientInfo},
    };

    use super::{ForgejoMcpConfig, ForgejoMcpServer, TransportError};

    struct FakeReadService;

    #[async_trait]
    impl domain::RepositoryReadService for FakeReadService {
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

    struct ValidationFailReadService;

    #[async_trait]
    impl domain::RepositoryReadService for ValidationFailReadService {
        async fn read_repository_file(
            &self,
            _request: domain::ReadRepositoryFileRequest,
        ) -> Result<ReadRepositoryFileResponse, ServiceError> {
            Err(ServiceError::Validation("bad path".to_string()))
        }
    }

    struct UpstreamFailReadService;

    #[async_trait]
    impl domain::RepositoryReadService for UpstreamFailReadService {
        async fn read_repository_file(
            &self,
            _request: domain::ReadRepositoryFileRequest,
        ) -> Result<ReadRepositoryFileResponse, ServiceError> {
            Err(ServiceError::Upstream("forge down".to_string()))
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
        read_service: Arc<S>,
    ) -> Result<
        (
            rmcp::service::RunningService<rmcp::service::RoleClient, DummyClientHandler>,
            tokio::task::JoinHandle<Result<(), TransportError>>,
        ),
        Box<dyn std::error::Error>,
    >
    where
        S: domain::RepositoryReadService + 'static,
    {
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let config = test_config();

        let server_handle = tokio::spawn(async move {
            ForgejoMcpServer::new(config, read_service)
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

        let result = client
            .call_tool(
                CallToolRequestParams::new("read_repository_file").with_arguments(read_file_args()),
            )
            .await;

        assert!(
            result.is_err(),
            "validation error should propagate as MCP error"
        );

        drop(client);
        // Server may exit with an error due to client disconnect; that's fine
        let _ = server_handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn maps_upstream_error_to_internal_error() -> Result<(), Box<dyn std::error::Error>> {
        let (client, server_handle) =
            spawn_server_and_client(Arc::new(UpstreamFailReadService)).await?;

        let result = client
            .call_tool(
                CallToolRequestParams::new("read_repository_file").with_arguments(read_file_args()),
            )
            .await;

        assert!(
            result.is_err(),
            "upstream error should propagate as MCP error"
        );

        drop(client);
        let _ = server_handle.await;
        Ok(())
    }
}
