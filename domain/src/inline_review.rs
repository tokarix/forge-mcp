//! Inline feedback refresh hints, independent of formal review verdicts.
use crate::{ChannelEvent, ChannelEventMeta, PublishableEvent, RepositoryRef};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum InlineReviewSide {
    Left,
    Right,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InlineReviewComment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitlab_position: Option<GitLabInlinePosition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitlab_original_position: Option<GitLabInlinePosition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_commit_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side: Option<InlineReviewSide>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_side: Option<InlineReviewSide>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_start_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_position: Option<u64>,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InlineReviewDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<InlineReviewComment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<InlineReviewComment>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestReviewCommentAction {
    Created,
    Edited,
    Deleted,
}
impl PullRequestReviewCommentAction {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Edited => "edited",
            Self::Deleted => "deleted",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PullRequestReviewCommentEvent {
    pub repository: RepositoryRef,
    pub index: u64,
    pub action: PullRequestReviewCommentAction,
    pub provider_action: String,
    pub delivery_id: String,
    pub head_sha: Option<String>,
    pub details: InlineReviewDetails,
    #[serde(skip)]
    payload_fingerprint: String,
}
impl PullRequestReviewCommentEvent {
    #[must_use]
    pub fn new(
        repository: RepositoryRef,
        index: u64,
        action: PullRequestReviewCommentAction,
        delivery_id: String,
        head_sha: Option<String>,
        details: InlineReviewDetails,
        payload_fingerprint: String,
    ) -> Self {
        Self {
            repository,
            index,
            provider_action: action.as_str().into(),
            action,
            delivery_id,
            head_sha,
            details,
            payload_fingerprint,
        }
    }
}
impl PublishableEvent for PullRequestReviewCommentEvent {
    fn dedupe_key(&self) -> String {
        if !self.delivery_id.is_empty() {
            return format!("{}:{}", self.repository.alias, self.delivery_id);
        }
        let resource = self
            .details
            .comment
            .as_ref()
            .and_then(|c| c.comment_id)
            .map(|id| id.to_string())
            .unwrap_or_default();
        let mut key = String::from("inline:");
        for part in [
            self.repository.alias.as_str(),
            &self.repository.owner,
            &self.repository.name,
            &self.index.to_string(),
            self.event_name(),
            &resource,
            self.action.as_str(),
            &self.payload_fingerprint,
        ] {
            key.push_str(&part.len().to_string());
            key.push(':');
            key.push_str(part);
        }
        key
    }
    fn event_name(&self) -> &'static str {
        "pull_request_review_comment"
    }
    fn repository_ref(&self) -> &RepositoryRef {
        &self.repository
    }
    fn to_channel_event(&self) -> ChannelEvent {
        ChannelEvent {
            content: format!(
                "{} {} on PR #{}",
                self.event_name(),
                self.action.as_str(),
                self.index
            ),
            meta: ChannelEventMeta {
                requested_reviewer: None,
                sender: None,
                branch_push: None,
                change_request_changes: None,
                inline_review: Some(self.details.clone()),
                labels_changed: false,
                ci: None,
                action: self.action.as_str().into(),
                change_request: Some(self.index),
                delivery_id: self.delivery_id.clone(),
                event_kind: self.event_name().into(),
                forge_alias: self.repository.alias.clone(),
                head_sha: self.head_sha.clone(),
                issue: None,
                issue_comment: None,
                owner: self.repository.owner.clone(),
                repo: self.repository.name.clone(),
                provider_action: Some(self.provider_action.clone()),
                review_id: None,
                reviewed_commit_id: None,
                review_state: None,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestReviewThreadAction {
    Resolved,
    Unresolved,
}
impl PullRequestReviewThreadAction {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Unresolved => "unresolved",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PullRequestReviewThreadEvent {
    pub repository: RepositoryRef,
    pub index: u64,
    pub action: PullRequestReviewThreadAction,
    pub provider_action: String,
    pub delivery_id: String,
    pub head_sha: Option<String>,
    pub details: InlineReviewDetails,
    #[serde(skip)]
    payload_fingerprint: String,
}
impl PullRequestReviewThreadEvent {
    #[must_use]
    pub fn new(
        repository: RepositoryRef,
        index: u64,
        action: PullRequestReviewThreadAction,
        delivery_id: String,
        head_sha: Option<String>,
        details: InlineReviewDetails,
        payload_fingerprint: String,
    ) -> Self {
        Self {
            repository,
            index,
            provider_action: action.as_str().into(),
            action,
            delivery_id,
            head_sha,
            details,
            payload_fingerprint,
        }
    }
}
impl PublishableEvent for PullRequestReviewThreadEvent {
    fn dedupe_key(&self) -> String {
        if !self.delivery_id.is_empty() {
            return format!("{}:{}", self.repository.alias, self.delivery_id);
        }
        let resource = self.details.thread_id.clone().unwrap_or_else(|| {
            self.details
                .comment
                .as_ref()
                .and_then(|c| c.comment_id)
                .map(|id| id.to_string())
                .unwrap_or_default()
        });
        let mut key = String::from("inline:");
        for part in [
            self.repository.alias.as_str(),
            &self.repository.owner,
            &self.repository.name,
            &self.index.to_string(),
            self.event_name(),
            &resource,
            self.action.as_str(),
            &self.payload_fingerprint,
        ] {
            key.push_str(&part.len().to_string());
            key.push(':');
            key.push_str(part);
        }
        key
    }
    fn event_name(&self) -> &'static str {
        "pull_request_review_thread"
    }
    fn repository_ref(&self) -> &RepositoryRef {
        &self.repository
    }
    fn to_channel_event(&self) -> ChannelEvent {
        ChannelEvent {
            content: format!(
                "{} {} on PR #{}",
                self.event_name(),
                self.action.as_str(),
                self.index
            ),
            meta: ChannelEventMeta {
                requested_reviewer: None,
                sender: None,
                branch_push: None,
                change_request_changes: None,
                inline_review: Some(self.details.clone()),
                labels_changed: false,
                ci: None,
                action: self.action.as_str().into(),
                change_request: Some(self.index),
                delivery_id: self.delivery_id.clone(),
                event_kind: self.event_name().into(),
                forge_alias: self.repository.alias.clone(),
                head_sha: self.head_sha.clone(),
                issue: None,
                issue_comment: None,
                owner: self.repository.owner.clone(),
                repo: self.repository.name.clone(),
                provider_action: Some(self.provider_action.clone()),
                review_id: None,
                reviewed_commit_id: None,
                review_state: None,
            },
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GitLabInlinePosition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_range: Option<GitLabInlineRange>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GitLabInlineRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<GitLabInlineLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<GitLabInlineLine>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GitLabInlineLine {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    fn event() -> PullRequestReviewCommentEvent {
        PullRequestReviewCommentEvent::new(
            RepositoryRef {
                alias: "forge".into(),
                forge: crate::ForgeKind::GitHub,
                host: "https://provider.invalid".into(),
                owner: "org".into(),
                name: "repo".into(),
            },
            42,
            PullRequestReviewCommentAction::Edited,
            String::new(),
            None,
            InlineReviewDetails {
                comment: Some(InlineReviewComment {
                    comment_id: Some(7),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "private-fingerprint".into(),
        )
    }
    #[test]
    fn fallback_keys_distinguish_coordinates_action_resource_and_body() {
        let original = event();
        let key = original.dedupe_key();
        let mut variants = Vec::new();
        let mut e = original.clone();
        e.action = PullRequestReviewCommentAction::Created;
        variants.push(e);
        let mut e = original.clone();
        e.payload_fingerprint = "changed".into();
        variants.push(e);
        let mut e = original.clone();
        e.index = 43;
        variants.push(e);
        let mut e = original.clone();
        e.repository.name = "other".into();
        variants.push(e);
        let mut e = original.clone();
        e.details.comment.as_mut().expect("comment").comment_id = Some(8);
        variants.push(e);
        for variant in variants {
            assert_ne!(key, variant.dedupe_key());
        }
        let thread = PullRequestReviewThreadEvent::new(
            original.repository.clone(),
            42,
            PullRequestReviewThreadAction::Resolved,
            String::new(),
            None,
            InlineReviewDetails {
                thread_id: Some("7".into()),
                ..Default::default()
            },
            "private-fingerprint".into(),
        );
        assert_ne!(key, thread.dedupe_key());
        let mut a = original.clone();
        a.repository.owner = "a:b".into();
        a.repository.name = "c".into();
        let mut b = original;
        b.repository.owner = "a".into();
        b.repository.name = "b:c".into();
        assert_ne!(a.dedupe_key(), b.dedupe_key());
        a.delivery_id = "retry".into();
        b.delivery_id = "retry".into();
        assert_eq!(a.dedupe_key(), "forge:retry");
        assert_eq!(a.dedupe_key(), b.dedupe_key());
    }
    #[test]
    fn fingerprints_are_private_and_old_metadata_remains_compatible() {
        let e = event();
        assert!(
            !serde_json::to_string(&e)
                .expect("JSON")
                .contains("fingerprint")
        );
        let mut meta = serde_json::to_value(e.to_channel_event().meta).expect("meta");
        meta.as_object_mut()
            .expect("object")
            .remove("inline_review");
        let old: ChannelEventMeta = serde_json::from_value(meta.clone()).expect("old");
        assert!(old.inline_review.is_none());
        assert_eq!(serde_json::to_value(old).expect("JSON"), meta);
    }
}
