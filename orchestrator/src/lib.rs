//! Read workflow orchestration for Phase 1.

use std::sync::Arc;

use async_trait::async_trait;
use audit::{AuditRecord, AuditSink};
use domain::{
    ReadRepositoryFileRequest, ReadRepositoryFileResponse, RepositoryReadService, ServiceError,
};
use forge::ForgeAdapter;

pub struct ReadOrchestrator<A, S>
where
    A: ForgeAdapter,
    S: AuditSink,
{
    adapter: Arc<A>,
    audit_sink: Arc<S>,
}

impl<A, S> ReadOrchestrator<A, S>
where
    A: ForgeAdapter,
    S: AuditSink,
{
    #[must_use]
    pub fn new(adapter: Arc<A>, audit_sink: Arc<S>) -> Self {
        Self {
            adapter,
            audit_sink,
        }
    }
}

#[async_trait]
impl<A, S> RepositoryReadService for ReadOrchestrator<A, S>
where
    A: ForgeAdapter,
    S: AuditSink,
{
    async fn read_repository_file(
        &self,
        request: ReadRepositoryFileRequest,
    ) -> Result<ReadRepositoryFileResponse, ServiceError> {
        if request.path.trim().is_empty() {
            return Err(ServiceError::Validation(
                "path must not be empty".to_string(),
            ));
        }

        let response = self
            .adapter
            .read_repository_file(
                &request.repository,
                &request.path,
                request.git_ref.as_deref(),
            )
            .await
            .map_err(|e| ServiceError::Upstream(e.to_string()))?;

        self.audit_sink
            .record(AuditRecord {
                agent_id: request.agent.agent_id,
                action: "read_repository_file".to_string(),
                repository: format!("{}/{}", request.repository.owner, request.repository.name),
                target: request.path,
            })
            .await
            .map_err(|e| ServiceError::Audit(e.to_string()))?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use audit::InMemoryAuditSink;
    use domain::{AgentIdentity, ForgeKind, RepositoryReadService, RepositoryRef};
    use forge::{ForgeAdapter, ForgeError};

    use super::ReadOrchestrator;

    struct FakeForgeAdapter;

    #[async_trait::async_trait]
    impl ForgeAdapter for FakeForgeAdapter {
        async fn read_repository_file(
            &self,
            repository: &RepositoryRef,
            path: &str,
            git_ref: Option<&str>,
        ) -> Result<domain::ReadRepositoryFileResponse, ForgeError> {
            Ok(domain::ReadRepositoryFileResponse {
                repository: repository.clone(),
                path: path.to_string(),
                git_ref: git_ref.map(ToOwned::to_owned),
                content: "hello".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn reads_a_repository_file_and_records_audit() {
        let adapter = Arc::new(FakeForgeAdapter);
        let audit = Arc::new(InMemoryAuditSink::new());
        let orchestrator = ReadOrchestrator::new(adapter, Arc::clone(&audit));

        let response = orchestrator
            .read_repository_file(domain::ReadRepositoryFileRequest {
                agent: AgentIdentity {
                    agent_id: "codex".to_string(),
                    session_id: "test".to_string(),
                },
                repository: RepositoryRef {
                    forge: ForgeKind::Forgejo,
                    host: "https://forge.example".to_string(),
                    owner: "org".to_string(),
                    name: "repo".to_string(),
                },
                path: "README.md".to_string(),
                git_ref: Some("main".to_string()),
            })
            .await
            .expect("read should succeed");

        assert_eq!(response.content, "hello");
        assert_eq!(audit.records().len(), 1);
    }
}
