//! Lightweight service that schedules auto-merge when a PR receives an
//! approved review.

use std::sync::Arc;

use domain::{
    AgentIdentity, AutoMergeFailedEvent, ForgeCredential, PullRequestReviewEvent,
    ScheduleAutoMergeRequest, ServiceError,
};
use forge::ForgeError;

use crate::events::EventBus;
use crate::registry::ForgeRegistry;

pub struct AutoMergeService {
    event_bus: EventBus,
    forge_registry: Arc<ForgeRegistry>,
}

impl AutoMergeService {
    #[must_use]
    pub fn new(event_bus: EventBus, forge_registry: Arc<ForgeRegistry>) -> Self {
        Self {
            event_bus,
            forge_registry,
        }
    }

    pub async fn handle_review(&self, event: PullRequestReviewEvent) {
        if event.review_state != "approved" {
            return;
        }

        let alias = &event.repository.alias;
        let forge = match self.forge_registry.get(alias) {
            Some(f) => f,
            None => {
                eprintln!("auto-merge: unknown forge alias {alias}");
                return;
            }
        };

        let credential = ForgeCredential {
            token: forge.token.clone(),
        };

        let merge_style =
            match Self::choose_merge_style(&*forge.adapter, &event.repository, &credential).await {
                Ok(s) => s,
                Err(e) => {
                    let msg = e.to_string();
                    eprintln!(
                        "auto-merge: failed for {}/{}/{}#{}: {msg}",
                        event.repository.alias,
                        event.repository.owner,
                        event.repository.name,
                        event.index,
                    );
                    self.publish_failure(&event, &msg);
                    return;
                }
            };

        let agent = AgentIdentity {
            agent_id: "system".to_string(),
            session_id: "auto-merge".to_string(),
        };

        let request = ScheduleAutoMergeRequest {
            agent,
            expected_head_sha: event.head_sha.clone(),
            index: event.index,
            merge_style,
            repository: event.repository.clone(),
        };

        let authorized = domain::policy::AuthorizedWrite {
            policy: domain::policy::PolicyConfig::default(),
        };

        if let Err(e) = forge
            .write_service
            .schedule_auto_merge(request, authorized, &credential)
            .await
        {
            self.handle_error(&event, &e);
        }
    }

    /// Picks a merge style from the repo's allowed set.
    ///
    /// Prefers the repo default when it is in the allowed set, then falls back
    /// to rebase → squash → merge.
    ///
    /// # Errors
    ///
    /// Returns an error if the forge request fails or no merge styles are
    /// allowed.
    async fn choose_merge_style(
        adapter: &dyn forge::ForgeAdapter,
        repository: &domain::RepositoryRef,
        credential: &ForgeCredential,
    ) -> Result<String, ForgeError> {
        let allowed = adapter
            .get_allowed_merge_styles(repository, credential)
            .await?;

        if allowed.is_empty() {
            return Err(ForgeError::InvalidPayload(
                "repository has no allowed merge styles".to_string(),
            ));
        }

        let default = adapter
            .get_default_merge_style(repository, credential)
            .await?;

        if let Some(ref d) = default
            && allowed.contains(d)
        {
            return Ok(d.clone());
        }

        // Fallback preference order.
        for preferred in &["rebase", "squash", "merge"] {
            let s = (*preferred).to_string();
            if allowed.contains(&s) {
                return Ok(s);
            }
        }

        // Last resort: first allowed style.
        Ok(allowed.into_iter().next().unwrap())
    }

    fn handle_error(&self, event: &PullRequestReviewEvent, error: &ServiceError) {
        let msg = error.to_string();
        if msg.contains("does not match current") || msg.contains("head SHA") {
            return;
        }
        eprintln!(
            "auto-merge: failed for {}/{}/{}#{}: {msg}",
            event.repository.alias, event.repository.owner, event.repository.name, event.index,
        );
        self.publish_failure(event, &msg);
    }

    fn publish_failure(&self, event: &PullRequestReviewEvent, error: &str) {
        let fail = AutoMergeFailedEvent {
            error: error.to_string(),
            head_sha: event.head_sha.clone(),
            index: event.index,
            repository: event.repository.clone(),
        };
        if let Err(e) = self.event_bus.publish(&fail) {
            eprintln!("auto-merge: failed to publish failure event: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use domain::{
        ChangeRequest, ChangeRequestComment, ChangeRequestCommentDetail, ChangeRequestReview,
        ChangeRequestState, ForgeCredential, ForgeKind, ForgeUser, Issue, IssueComment,
        ReadRepositoryFileResponse, RepositoryRef,
    };
    use forge::{ForgeError, ForgeWebhookAdapter, ForgeWebhookError};

    use super::AutoMergeService;

    // --- Test adapter for merge style selection ---

    struct MergeStyleTestAdapter {
        allowed: Vec<String>,
        default: Option<String>,
    }

    #[async_trait]
    impl forge::ForgeAdapter for MergeStyleTestAdapter {
        async fn get_authenticated_user(
            &self,
            _credential: &ForgeCredential,
        ) -> Result<ForgeUser, ForgeError> {
            unimplemented!()
        }

        async fn assign_issue(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _assignee: &str,
            _credential: &ForgeCredential,
        ) -> Result<Issue, ForgeError> {
            unimplemented!()
        }

        async fn close_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn close_issue(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &ForgeCredential,
        ) -> Result<Issue, ForgeError> {
            unimplemented!()
        }

        async fn comment_on_issue(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _credential: &ForgeCredential,
        ) -> Result<IssueComment, ForgeError> {
            unimplemented!()
        }

        async fn comment_on_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _credential: &ForgeCredential,
        ) -> Result<ChangeRequestComment, ForgeError> {
            unimplemented!()
        }

        async fn create_change_request(
            &self,
            _repository: &RepositoryRef,
            _title: &str,
            _body: &str,
            _head_branch: &str,
            _base_branch: &str,
            _credential: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn create_issue(
            &self,
            _repository: &RepositoryRef,
            _title: &str,
            _body: &str,
            _credential: &ForgeCredential,
        ) -> Result<Issue, ForgeError> {
            unimplemented!()
        }

        async fn get_allowed_merge_styles(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<Vec<String>, ForgeError> {
            Ok(self.allowed.clone())
        }

        async fn get_change_request_comments(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &ForgeCredential,
        ) -> Result<Vec<ChangeRequestCommentDetail>, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }

        async fn get_change_request_diff(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
        ) -> Result<String, ForgeError> {
            unimplemented!()
        }

        async fn get_default_merge_style(
            &self,
            _repository: &RepositoryRef,
            _credential: &ForgeCredential,
        ) -> Result<Option<String>, ForgeError> {
            Ok(self.default.clone())
        }

        async fn get_issue(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &ForgeCredential,
        ) -> Result<Issue, ForgeError> {
            unimplemented!()
        }

        async fn get_issue_comments(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _credential: &ForgeCredential,
        ) -> Result<Vec<IssueComment>, ForgeError> {
            unimplemented!()
        }

        async fn list_change_requests(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&ChangeRequestState>,
        ) -> Result<Vec<ChangeRequest>, ForgeError> {
            unimplemented!()
        }

        async fn list_issues(
            &self,
            _repository: &RepositoryRef,
            _state: Option<&str>,
            _credential: &ForgeCredential,
        ) -> Result<Vec<Issue>, ForgeError> {
            unimplemented!()
        }

        async fn schedule_auto_merge(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _merge_style: &str,
            _head_commit_id: &str,
            _credential: &ForgeCredential,
        ) -> Result<(), ForgeError> {
            unimplemented!()
        }

        async fn read_repository_file(
            &self,
            _repository: &RepositoryRef,
            _path: &str,
            _git_ref: Option<&str>,
        ) -> Result<ReadRepositoryFileResponse, ForgeError> {
            unimplemented!()
        }

        async fn submit_change_request_review(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _body: &str,
            _event: &str,
            _credential: &ForgeCredential,
        ) -> Result<ChangeRequestReview, ForgeError> {
            unimplemented!()
        }

        async fn update_change_request(
            &self,
            _repository: &RepositoryRef,
            _index: u64,
            _title: Option<&str>,
            _body: Option<&str>,
            _credential: &ForgeCredential,
        ) -> Result<ChangeRequest, ForgeError> {
            unimplemented!()
        }
    }

    impl ForgeWebhookAdapter for MergeStyleTestAdapter {
        fn verify_and_parse_webhook_event(
            &self,
            _headers: &[(String, String)],
            _body: &[u8],
            _forge_alias: &str,
            _forge_kind: ForgeKind,
            _host: &str,
            _secret: &str,
        ) -> Result<Option<domain::WebhookEvent>, ForgeWebhookError> {
            unimplemented!()
        }
    }

    fn test_repo() -> RepositoryRef {
        RepositoryRef {
            alias: "test".to_string(),
            forge: ForgeKind::Forgejo,
            host: "example.com".to_string(),
            name: "repo".to_string(),
            owner: "owner".to_string(),
        }
    }

    fn test_credential() -> ForgeCredential {
        ForgeCredential {
            token: Some("tok".to_string()),
        }
    }

    #[tokio::test]
    async fn choose_merge_style_prefers_default_when_allowed() {
        let adapter = MergeStyleTestAdapter {
            allowed: vec![
                "merge".to_string(),
                "rebase".to_string(),
                "squash".to_string(),
            ],
            default: Some("squash".to_string()),
        };
        let result =
            AutoMergeService::choose_merge_style(&adapter, &test_repo(), &test_credential())
                .await
                .unwrap();
        assert_eq!(result, "squash");
    }

    #[tokio::test]
    async fn choose_merge_style_falls_back_when_default_not_allowed() {
        let adapter = MergeStyleTestAdapter {
            allowed: vec!["merge".to_string(), "squash".to_string()],
            default: Some("rebase".to_string()),
        };
        let result =
            AutoMergeService::choose_merge_style(&adapter, &test_repo(), &test_credential())
                .await
                .unwrap();
        assert_eq!(result, "squash");
    }

    #[tokio::test]
    async fn choose_merge_style_falls_back_to_merge_last() {
        let adapter = MergeStyleTestAdapter {
            allowed: vec!["merge".to_string()],
            default: Some("rebase".to_string()),
        };
        let result =
            AutoMergeService::choose_merge_style(&adapter, &test_repo(), &test_credential())
                .await
                .unwrap();
        assert_eq!(result, "merge");
    }

    #[tokio::test]
    async fn choose_merge_style_errors_when_no_styles_allowed() {
        let adapter = MergeStyleTestAdapter {
            allowed: vec![],
            default: None,
        };
        let result =
            AutoMergeService::choose_merge_style(&adapter, &test_repo(), &test_credential()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn choose_merge_style_prefers_rebase_without_default() {
        let adapter = MergeStyleTestAdapter {
            allowed: vec![
                "merge".to_string(),
                "rebase".to_string(),
                "squash".to_string(),
            ],
            default: None,
        };
        let result =
            AutoMergeService::choose_merge_style(&adapter, &test_repo(), &test_credential())
                .await
                .unwrap();
        assert_eq!(result, "rebase");
    }
}
