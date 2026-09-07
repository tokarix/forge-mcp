//! Repository/commit scoped CI wake hints. These never express aggregate readiness.
use serde::{Deserialize, Serialize};

use crate::{ChannelEvent, ChannelEventMeta, PublishableEvent, RepositoryRef};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiEventSource {
    CommitStatus,
    CheckRun,
    CheckSuite,
    Pipeline,
    Job,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CiEventDetails {
    pub source: CiEventSource,
    pub provider_event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_delivery_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_id_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conclusion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl CiEventDetails {
    #[must_use]
    pub fn new(source: CiEventSource, provider_event: String) -> Self {
        Self {
            source,
            provider_event,
            provider_event_id: None,
            provider_delivery_id: None,
            delivery_id_source: None,
            id: None,
            parent_id: None,
            name: None,
            context: None,
            status: None,
            conclusion: None,
            started_at: None,
            completed_at: None,
            updated_at: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CiChangeEvent {
    pub repository: RepositoryRef,
    pub head_sha: String,
    pub delivery_id: String,
    pub provider_action: Option<String>,
    pub details: CiEventDetails,
    #[serde(skip)]
    payload_fingerprint: String,
}

impl CiChangeEvent {
    /// Validate only the new CI projection; legacy webhook parsing is unchanged.
    ///
    /// # Errors
    /// Returns a bounded diagnostic for invalid identity or oversized semantics.
    pub fn new(
        repository: RepositoryRef,
        head_sha: String,
        delivery_id: String,
        provider_action: Option<String>,
        details: CiEventDetails,
        payload_fingerprint: String,
    ) -> Result<Self, &'static str> {
        if !matches!(head_sha.len(), 40 | 64)
            || !head_sha.bytes().all(|b| b.is_ascii_hexdigit())
            || head_sha.bytes().all(|b| b == b'0')
        {
            return Err("invalid CI commit object ID");
        }
        let valid_component = |s: &str| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && !s.chars().any(|c| c.is_control() || c == '/' || c == '\\')
        };
        if !repository.owner.split('/').all(valid_component)
            || !valid_component(&repository.name)
            || repository.owner.len() + 1 + repository.name.len() > 1024
        {
            return Err("invalid CI repository path");
        }
        if details.id == Some(0) || details.parent_id == Some(0) {
            return Err("invalid CI native ID");
        }
        for (value, limit) in [
            (Some(repository.alias.as_str()), 256),
            (Some(delivery_id.as_str()), 256),
            (Some(details.provider_event.as_str()), 256),
            (details.provider_event_id.as_deref(), 256),
            (details.provider_delivery_id.as_deref(), 256),
            (details.delivery_id_source.as_deref(), 256),
            (provider_action.as_deref(), 128),
            (details.name.as_deref(), 1024),
            (details.context.as_deref(), 1024),
            (details.status.as_deref(), 128),
            (details.conclusion.as_deref(), 128),
            (details.started_at.as_deref(), 64),
            (details.completed_at.as_deref(), 64),
            (details.updated_at.as_deref(), 64),
        ] {
            if value.is_some_and(|v| v.len() > limit) {
                return Err("oversized CI projection field");
            }
        }
        Ok(Self {
            repository,
            head_sha,
            delivery_id,
            provider_action,
            details,
            payload_fingerprint,
        })
    }
}

impl PublishableEvent for CiChangeEvent {
    fn dedupe_key(&self) -> String {
        if !self.delivery_id.is_empty() {
            return format!("{}:{}", self.repository.alias, self.delivery_id);
        }
        // Length-prefix coordinates so legal punctuation cannot alias another key.
        let mut key = String::from("ci:");
        for part in [
            self.repository.alias.as_str(),
            &self.repository.owner,
            &self.repository.name,
            &format!("{:?}", self.details.source),
            &self.head_sha,
            &self.details.provider_event,
            self.provider_action.as_deref().unwrap_or_default(),
            &self.payload_fingerprint,
        ] {
            key.push_str(&part.len().to_string());
            key.push(':');
            key.push_str(part);
        }
        key
    }

    fn event_name(&self) -> &'static str {
        "ci"
    }
    fn repository_ref(&self) -> &RepositoryRef {
        &self.repository
    }
    fn to_channel_event(&self) -> ChannelEvent {
        ChannelEvent {
            content: format!("ci changed at {}", self.head_sha),
            meta: ChannelEventMeta {
                inline_review: None,
                labels_changed: false,
                ci: Some(self.details.clone()),
                action: "changed".into(),
                change_request: None,
                delivery_id: self.delivery_id.clone(),
                event_kind: "ci".into(),
                forge_alias: self.repository.alias.clone(),
                head_sha: Some(self.head_sha.clone()),
                issue: None,
                issue_comment: None,
                owner: self.repository.owner.clone(),
                repo: self.repository.name.clone(),
                provider_action: self.provider_action.clone(),
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
    use crate::ForgeKind;
    fn event(details: CiEventDetails) -> Result<CiChangeEvent, &'static str> {
        CiChangeEvent::new(
            RepositoryRef {
                alias: "forge".into(),
                forge: ForgeKind::GitHub,
                host: "https://provider.invalid".into(),
                owner: "org".into(),
                name: "repo".into(),
            },
            "a".repeat(40),
            String::new(),
            None,
            details,
            "private-fingerprint".into(),
        )
    }
    #[test]
    fn ci_projection_bounds_are_utf8_bytes() {
        for (field, limit) in [
            ("provider_event", 256),
            ("provider_event_id", 256),
            ("provider_delivery_id", 256),
            ("delivery_id_source", 256),
            ("name", 1024),
            ("context", 1024),
            ("status", 128),
            ("conclusion", 128),
            ("started_at", 64),
            ("completed_at", 64),
            ("updated_at", 64),
        ] {
            for (size, valid) in [(limit, true), (limit + 1, false)] {
                let mut d = serde_json::to_value(CiEventDetails::new(
                    CiEventSource::Job,
                    "Job Hook".into(),
                ))
                .expect("JSON");
                d[field] =
                    serde_json::json!(format!("{}{}", "é".repeat(size / 2), "a".repeat(size % 2)));
                assert_eq!(
                    event(serde_json::from_value(d).expect("details")).is_ok(),
                    valid,
                    "{field}: {size}"
                );
            }
        }
        let e = event(CiEventDetails::new(CiEventSource::Job, "Job Hook".into())).expect("event");
        for size in [256, 257] {
            assert_eq!(
                CiChangeEvent::new(
                    e.repository.clone(),
                    e.head_sha.clone(),
                    "x".repeat(size),
                    None,
                    e.details.clone(),
                    String::new()
                )
                .is_ok(),
                size == 256
            );
        }
        for size in [128, 129] {
            assert_eq!(
                CiChangeEvent::new(
                    e.repository.clone(),
                    e.head_sha.clone(),
                    String::new(),
                    Some("x".repeat(size)),
                    e.details.clone(),
                    String::new()
                )
                .is_ok(),
                size == 128
            );
        }
        for size in [1024, 1025] {
            let mut repo = e.repository.clone();
            repo.owner = "o".into();
            repo.name = "r".repeat(size - 2);
            assert_eq!(
                CiChangeEvent::new(
                    repo,
                    e.head_sha.clone(),
                    String::new(),
                    None,
                    e.details.clone(),
                    String::new()
                )
                .is_ok(),
                size == 1024
            );
        }
    }
    #[test]
    fn ci_contract_has_no_aggregate_or_fingerprint_and_keeps_absence() {
        for source in [
            CiEventSource::CommitStatus,
            CiEventSource::CheckRun,
            CiEventSource::CheckSuite,
            CiEventSource::Pipeline,
            CiEventSource::Job,
        ] {
            let e = event(CiEventDetails::new(source, "native".into())).expect("event");
            let serialized = serde_json::to_string(&e).expect("JSON");
            assert!(!serialized.contains("fingerprint"));
            let c = e.to_channel_event();
            let json = serde_json::to_value(&c).expect("JSON");
            assert_eq!(json["meta"]["head_sha"], "a".repeat(40));
            assert_eq!(json["meta"]["event_kind"], "ci");
            assert_eq!(json["meta"]["action"], "changed");
            for key in ["change_request", "issue", "issue_comment", "review_state"] {
                assert!(json["meta"][key].is_null());
            }
            for key in [
                "all_checks_green",
                "aggregate_state",
                "mergeable",
                "review_id",
                "provider_action",
            ] {
                assert!(json["meta"].get(key).is_none());
            }
            for key in ["id", "parent_id", "status", "conclusion", "name", "context"] {
                assert!(json["meta"]["ci"].get(key).is_none());
            }
            assert!(c.content.len() < 100);
            let mut old = json["meta"].clone();
            old.as_object_mut().expect("meta").remove("ci");
            let old: ChannelEventMeta = serde_json::from_value(old).expect("old metadata");
            assert_eq!(old.ci, None);
            assert!(serde_json::to_value(old).expect("JSON").get("ci").is_none());
        }
    }
    #[test]
    fn ci_full_object_ids_and_repository_components() {
        let e = event(CiEventDetails::new(CiEventSource::Job, "Job Hook".into())).expect("event");
        for sha in ["A".repeat(40), "a".repeat(64)] {
            let new = CiChangeEvent::new(
                e.repository.clone(),
                sha.clone(),
                String::new(),
                None,
                e.details.clone(),
                String::new(),
            )
            .expect("full SHA");
            assert_eq!(new.to_channel_event().meta.head_sha, Some(sha));
        }
        for owner in ["", ".", "..", "org//sub", "org/../sub", "org/\nsub"] {
            let mut repo = e.repository.clone();
            repo.owner = owner.into();
            assert!(
                CiChangeEvent::new(
                    repo,
                    e.head_sha.clone(),
                    String::new(),
                    None,
                    e.details.clone(),
                    String::new()
                )
                .is_err()
            );
        }
    }
}
