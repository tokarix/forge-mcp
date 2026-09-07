//! Explicit provider evidence for changes which need not move the source head.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChangeRequestChanges {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<BaseBranchChange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<DraftChange>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BaseBranchChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    pub current: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DraftChange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<bool>,
    pub current: bool,
}

pub(crate) fn fingerprint_key(namespace: &str, parts: &[&str]) -> String {
    use std::fmt::Write;
    let mut key = format!("{namespace}:");
    for part in parts {
        let _ = write!(key, "{}:{part}", part.len());
    }
    key
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::{ChangeRequestEvent, PublishableEvent};
    #[test]
    fn old_change_requests_default_and_omit_state_metadata() {
        let event: ChangeRequestEvent = serde_json::from_value(serde_json::json!({
            "action": "synchronize", "delivery_id": "old", "head_sha": "head", "index": 7,
            "repository": {"alias": "forge", "forge": "GitLab", "host": "example.invalid", "owner": "org", "name": "repo"},
            "title": "PR", "url": "url"
        })).expect("old event");
        for value in [
            serde_json::to_value(&event).expect("event"),
            serde_json::to_value(event.to_channel_event().meta).expect("meta"),
        ] {
            for key in ["change_request_changes", "provider_action", "branch_push"] {
                assert!(value.get(key).is_none());
            }
        }
    }
}
