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

    #[tracing::instrument(skip_all, fields(
        operation = "webhook_auto_merge", agent_id = "system", session_id = "auto-merge",
        forge = %crate::diagnostics::bounded(&event.repository.alias),
        owner = %crate::diagnostics::bounded(&event.repository.owner),
        repo = %crate::diagnostics::bounded(&event.repository.name), target = event.index,
        delivery_id = %crate::diagnostics::bounded(&event.delivery_id),
        credential_source = tracing::field::Empty
    ))]
    pub async fn handle_review(&self, event: PullRequestReviewEvent) {
        if event.action != domain::PullRequestReviewEventAction::Submitted
            || event.review_state != Some(domain::ReviewState::Approved)
        {
            tracing::debug!(
                reason = "review_not_submitted_approval",
                "auto-merge: skipping review"
            );
            return;
        }

        let alias = &event.repository.alias;
        let Some(forge) = self.forge_registry.get(alias) else {
            tracing::warn!(reason = "unknown_forge", "auto-merge: unknown forge");
            return;
        };

        let credential = ForgeCredential {
            token: forge.token.clone(),
        };
        crate::handlers::record_credential_source(
            if forge
                .adapter
                .effective_credential(&credential)
                .token
                .is_some()
            {
                "forge_default"
            } else {
                "none"
            },
        );

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
                tracing::info!("auto-merge: scheduled");
            }
            Err(e) => self.handle_error(&event, &e),
        }
    }

    fn handle_error(&self, event: &PullRequestReviewEvent, error: &ServiceError) {
        let msg = error.to_string();
        if msg.contains("does not match current") || msg.contains("head SHA") {
            tracing::debug!(
                reason = "stale_or_unavailable_head",
                "auto-merge: stale head, skipping",
            );
            return;
        }
        tracing::error!(stage = "scheduling", "auto-merge: failed to schedule",);
        self.publish_failure(event, &msg);
    }

    fn publish_failure(&self, event: &PullRequestReviewEvent, error: &str) {
        let fail = AutoMergeFailedEvent {
            error: error.to_string(),
            head_sha: event.head_sha.clone(),
            index: event.index,
            repository: event.repository.clone(),
        };
        if self.event_bus.publish(&fail).is_err() {
            tracing::warn!(
                stage = "failure_event_publication",
                "auto-merge: failed to publish failure event",
            );
        }
    }
}
