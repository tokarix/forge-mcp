//! Transport-facing request handlers.

use std::sync::Arc;

use domain::{
    AgentIdentity, ForgeKind, ReadRepositoryFileRequest, RepositoryReadService, RepositoryRef,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRepositoryFileInput {
    pub agent_id: String,
    pub session_id: String,
    pub host: String,
    pub owner: String,
    pub repo: String,
    pub path: String,
    pub git_ref: Option<String>,
}

pub struct ToolHandlers<S>
where
    S: RepositoryReadService,
{
    read_service: Arc<S>,
}

impl<S> ToolHandlers<S>
where
    S: RepositoryReadService,
{
    #[must_use]
    pub fn new(read_service: Arc<S>) -> Self {
        Self { read_service }
    }

    /// Handles the `read_repository_file` tool request.
    ///
    /// # Errors
    ///
    /// Returns an error if request validation, upstream forge access, or audit
    /// recording fails.
    pub async fn read_repository_file(
        &self,
        input: ReadRepositoryFileInput,
    ) -> Result<String, domain::ServiceError> {
        let response = self
            .read_service
            .read_repository_file(ReadRepositoryFileRequest {
                agent: AgentIdentity {
                    agent_id: input.agent_id,
                    session_id: input.session_id,
                },
                repository: RepositoryRef {
                    forge: ForgeKind::Forgejo,
                    host: input.host,
                    owner: input.owner,
                    name: input.repo,
                },
                path: input.path,
                git_ref: input.git_ref,
            })
            .await?;

        Ok(response.content)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use domain::{ReadRepositoryFileResponse, ServiceError};

    use super::{ReadRepositoryFileInput, ToolHandlers};

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
                content: "transport-ok".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn forwards_read_repository_file_requests() {
        let handlers = ToolHandlers::new(Arc::new(FakeReadService));
        let content = handlers
            .read_repository_file(ReadRepositoryFileInput {
                agent_id: "codex".to_string(),
                session_id: "session".to_string(),
                host: "https://forge.example".to_string(),
                owner: "org".to_string(),
                repo: "repo".to_string(),
                path: "README.md".to_string(),
                git_ref: Some("main".to_string()),
            })
            .await
            .expect("transport call should succeed");

        assert_eq!(content, "transport-ok");
    }
}
