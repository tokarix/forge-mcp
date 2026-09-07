//! Repository-scoped branch refresh hints; object IDs are never PR heads.
use serde::{Deserialize, Serialize};

use crate::{ChannelEvent, ChannelEventMeta, PublishableEvent, RepositoryRef};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BranchPushDetails {
    pub r#ref: String,
    /// A full object ID. All-zero IDs signal creation/deletion, not commits.
    pub before_sha: String,
    pub after_sha: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forced: Option<bool>,
    pub provider_event: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BranchPushEvent {
    pub repository: RepositoryRef,
    pub delivery_id: String,
    pub details: BranchPushDetails,
    #[serde(skip)]
    pub payload_fingerprint: String,
}

impl PublishableEvent for BranchPushEvent {
    fn dedupe_key(&self) -> String {
        if !self.delivery_id.is_empty() {
            return format!("{}:{}", self.repository.alias, self.delivery_id);
        }
        crate::change_request_changes::fingerprint_key(
            "branch_push",
            &[
                &self.repository.alias,
                &self.repository.owner,
                &self.repository.name,
                &self.details.r#ref,
                &self.details.provider_event,
                &self.payload_fingerprint,
            ],
        )
    }

    fn event_name(&self) -> &'static str {
        "branch_push"
    }

    fn repository_ref(&self) -> &RepositoryRef {
        &self.repository
    }

    fn to_channel_event(&self) -> ChannelEvent {
        ChannelEvent {
            content: format!(
                "branch pushed on {}/{}/{} {}",
                self.repository.alias,
                self.repository.owner,
                self.repository.name,
                self.details.r#ref
            ),
            meta: ChannelEventMeta {
                branch_push: Some(self.details.clone()),
                change_request_changes: None,
                labels_changed: false,
                ci: None,
                inline_review: None,
                action: "pushed".into(),
                change_request: None,
                delivery_id: self.delivery_id.clone(),
                event_kind: "branch_push".into(),
                forge_alias: self.repository.alias.clone(),
                head_sha: None,
                issue: None,
                issue_comment: None,
                owner: self.repository.owner.clone(),
                repo: self.repository.name.clone(),
                provider_action: None,
                review_id: None,
                reviewed_commit_id: None,
                review_state: None,
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn branch_projection_omits_unrelated_metadata_and_internal_identity() {
        let event = BranchPushEvent {
            repository: RepositoryRef {
                alias: "forge".into(),
                forge: crate::ForgeKind::GitHub,
                host: "https://example.invalid".into(),
                owner: "org".into(),
                name: "repo".into(),
            },
            delivery_id: String::new(),
            payload_fingerprint: "internal-secret".into(),
            details: BranchPushDetails {
                r#ref: "refs/heads/main".into(),
                before_sha: "a".repeat(40),
                after_sha: "b".repeat(40),
                deleted: None,
                forced: None,
                provider_event: "push".into(),
            },
        };
        let serialized = serde_json::to_value(event.to_channel_event()).expect("JSON");
        for key in [
            "change_request_changes",
            "ci",
            "inline_review",
            "provider_action",
        ] {
            assert!(serialized["meta"].get(key).is_none());
        }
        for key in ["deleted", "forced"] {
            assert!(serialized["meta"]["branch_push"].get(key).is_none());
        }
        assert!(
            !serde_json::to_string(&event)
                .expect("JSON")
                .contains("internal-secret")
        );
        let mut other = event.clone();
        other.repository.name = "other".into();
        assert_ne!(event.dedupe_key(), other.dedupe_key());
        other = event.clone();
        other.repository.alias = "other".into();
        assert_ne!(event.dedupe_key(), other.dedupe_key());
        other = event.clone();
        other.details.r#ref = "refs/heads/other".into();
        assert_ne!(event.dedupe_key(), other.dedupe_key());
    }
}
