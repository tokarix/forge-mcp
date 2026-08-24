//! Lightweight service that schedules auto-merge when a PR receives an
//! approved review.

use std::sync::Arc;

use domain::{
    AgentIdentity, AutoMergeFailedEvent, ForgeCredential, PullRequestReviewEvent,
    ScheduleAutoMergeRequest, ServiceError,
};

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
        let Some(forge) = self.forge_registry.get(alias) else {
            tracing::warn!(alias, "auto-merge: unknown forge");
            return;
        };

        let credential = ForgeCredential {
            token: forge.token.clone(),
        };

        let agent = AgentIdentity {
            agent_id: "system".to_string(),
            session_id: "auto-merge".to_string(),
        };

        let request = ScheduleAutoMergeRequest {
            agent,
            delete_branch_after_merge: None,
            expected_head_sha: event.head_sha.clone(),
            index: event.index,
            merge_style: None,
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
