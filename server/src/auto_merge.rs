//! Lightweight service that schedules auto-merge when a PR receives an
//! approved review.

use std::sync::Arc;

use domain::{
    AgentIdentity, AutoMergeFailedEvent, ForgeCredential, PullRequestReviewEvent,
    RepositoryMergeSettings, ScheduleAutoMergeRequest, ServiceError,
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
        if event.review_state != domain::ReviewState::Approved {
            return;
        }

        let alias = &event.repository.alias;
        let forge = match self.forge_registry.get(alias) {
            Some(f) => f,
            None => {
                tracing::warn!(alias, "auto-merge: unknown forge");
                return;
            }
        };

        let credential = ForgeCredential {
            token: forge.token.clone(),
        };

        let merge_settings = match forge
            .adapter
            .get_repository_merge_settings(&event.repository, &credential)
            .await
        {
            Ok(settings) => settings,
            Err(e) => {
                let msg = e.to_string();
                tracing::error!(
                    forge = %event.repository.alias,
                    owner = %event.repository.owner,
                    repo = %event.repository.name,
                    pr = event.index,
                    error = %msg,
                    "auto-merge: failed to load merge settings",
                );
                self.publish_failure(&event, &msg);
                return;
            }
        };

        let merge_style = match Self::choose_merge_style(&merge_settings) {
            Ok(s) => s,
            Err(e) => {
                let msg = e.to_string();
                tracing::error!(
                    forge = %event.repository.alias,
                    owner = %event.repository.owner,
                    repo = %event.repository.name,
                    pr = event.index,
                    error = %msg,
                    "auto-merge: failed to choose merge style",
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
            delete_branch_after_merge: merge_settings.default_delete_branch_after_merge,
            expected_head_sha: event.head_sha.clone(),
            index: event.index,
            merge_style,
            repository: event.repository.clone(),
        };

        let authorized = domain::policy::AuthorizedWrite {
            policy: domain::policy::PolicyConfig::default(),
        };

        match forge
            .write_service
            .schedule_auto_merge(request, authorized, &credential)
            .await
        {
            Ok(()) => {
                tracing::info!(
                    forge = %event.repository.alias,
                    owner = %event.repository.owner,
                    repo = %event.repository.name,
                    pr = event.index,
                    head = %event.head_sha,
                    "auto-merge: scheduled",
                );
            }
            Err(e) => self.handle_error(&event, &e),
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
    fn choose_merge_style(settings: &RepositoryMergeSettings) -> Result<String, ForgeError> {
        if settings.allowed_styles.is_empty() {
            return Err(ForgeError::InvalidPayload(
                "repository has no allowed merge styles".to_string(),
            ));
        }

        if let Some(ref d) = settings.default_merge_style
            && settings.allowed_styles.contains(d)
        {
            return Ok(d.clone());
        }

        // Fallback preference order.
        for preferred in &["rebase", "squash", "merge"] {
            let s = (*preferred).to_string();
            if settings.allowed_styles.contains(&s) {
                return Ok(s);
            }
        }

        // Last resort: first allowed style.
        Ok(settings.allowed_styles.first().cloned().unwrap())
    }

    fn handle_error(&self, event: &PullRequestReviewEvent, error: &ServiceError) {
        let msg = error.to_string();
        if msg.contains("does not match current") || msg.contains("head SHA") {
            tracing::debug!(
                forge = %event.repository.alias,
                owner = %event.repository.owner,
                repo = %event.repository.name,
                pr = event.index,
                error = %msg,
                "auto-merge: stale head, skipping",
            );
            return;
        }
        tracing::error!(
            forge = %event.repository.alias,
            owner = %event.repository.owner,
            repo = %event.repository.name,
            pr = event.index,
            error = %msg,
            "auto-merge: failed to schedule",
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
            tracing::warn!(
                forge = %event.repository.alias,
                owner = %event.repository.owner,
                repo = %event.repository.name,
                pr = event.index,
                error = %e,
                "auto-merge: failed to publish failure event",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use domain::RepositoryMergeSettings;

    use super::AutoMergeService;

    fn test_merge_settings(
        allowed_styles: Vec<&str>,
        default_merge_style: Option<&str>,
    ) -> RepositoryMergeSettings {
        RepositoryMergeSettings {
            allowed_styles: allowed_styles.into_iter().map(str::to_string).collect(),
            default_delete_branch_after_merge: None,
            default_merge_style: default_merge_style.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn choose_merge_style_prefers_default_when_allowed() {
        let settings = test_merge_settings(vec!["merge", "rebase", "squash"], Some("squash"));
        let result = AutoMergeService::choose_merge_style(&settings).unwrap();
        assert_eq!(result, "squash");
    }

    #[tokio::test]
    async fn choose_merge_style_falls_back_when_default_not_allowed() {
        let settings = test_merge_settings(vec!["merge", "squash"], Some("rebase"));
        let result = AutoMergeService::choose_merge_style(&settings).unwrap();
        assert_eq!(result, "squash");
    }

    #[tokio::test]
    async fn choose_merge_style_falls_back_to_merge_last() {
        let settings = test_merge_settings(vec!["merge"], Some("rebase"));
        let result = AutoMergeService::choose_merge_style(&settings).unwrap();
        assert_eq!(result, "merge");
    }

    #[tokio::test]
    async fn choose_merge_style_errors_when_no_styles_allowed() {
        let settings = test_merge_settings(vec![], None);
        let result = AutoMergeService::choose_merge_style(&settings);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn choose_merge_style_prefers_rebase_without_default() {
        let settings = test_merge_settings(vec!["merge", "rebase", "squash"], None);
        let result = AutoMergeService::choose_merge_style(&settings).unwrap();
        assert_eq!(result, "rebase");
    }

    #[tokio::test]
    async fn choose_merge_style_prefers_fast_forward_only_default() {
        let settings = test_merge_settings(
            vec!["rebase", "fast-forward-only"],
            Some("fast-forward-only"),
        );
        let result = AutoMergeService::choose_merge_style(&settings).unwrap();
        assert_eq!(result, "fast-forward-only");
    }

    #[tokio::test]
    async fn choose_merge_style_falls_back_to_rebase_merge_when_needed() {
        let settings = test_merge_settings(vec!["rebase-merge"], None);
        let result = AutoMergeService::choose_merge_style(&settings).unwrap();
        assert_eq!(result, "rebase-merge");
    }
}
