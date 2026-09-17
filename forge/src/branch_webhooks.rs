//! Bounded push and explicit PR state projections, after authentication only.
use domain::{
    BaseBranchChange, BranchPushDetails, BranchPushEvent, ChangeRequestChanges, ChangeRequestEvent,
    ChangeRequestEventAction, DraftChange, ForgeKind, PublishableEvent, RepositoryRef,
    WebhookEvent,
};
use serde::Deserialize;

use crate::ForgeWebhookError;

fn invalid() -> ForgeWebhookError {
    ForgeWebhookError::InvalidPayload("invalid branch/state webhook projection".into())
}
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ForgeWebhookError> {
    serde_json::from_slice(body).map_err(|_| invalid())
}
fn fingerprint(body: &[u8]) -> String {
    crate::payload_fingerprint(body)
}
fn valid_sha(sha: &str, allow_zero: bool) -> bool {
    matches!(sha.len(), 40 | 64)
        && sha.bytes().all(|b| b.is_ascii_hexdigit())
        && (allow_zero || !sha.bytes().all(|b| b == b'0'))
}
#[allow(clippy::case_sensitive_file_extension_comparisons)] // Git ref rules are case sensitive.
fn valid_branch(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 1024
        && !branch.ends_with('.')
        && !branch.contains("..")
        && !branch.contains("@{")
        && branch != "@"
        && !branch
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "~^:?*[\\".contains(c))
        && branch
            .split('/')
            .all(|c| !c.is_empty() && !c.starts_with('.') && !c.ends_with(".lock"))
}
fn validate_repository(r: &RepositoryRef, delivery: &str) -> Result<(), ForgeWebhookError> {
    let component = |s: &str| {
        !s.trim().is_empty()
            && s != "."
            && s != ".."
            && !s.chars().any(|c| c.is_control() || c == '/' || c == '\\')
    };
    if r.alias.trim().is_empty()
        || r.alias.len() > 256
        || delivery.len() > 256
        || !r.owner.split('/').all(component)
        || !component(&r.name)
        || r.owner.len() + r.name.len() > 1023
    {
        return Err(invalid());
    }
    Ok(())
}
fn bounded(event: &impl PublishableEvent) -> Result<(), ForgeWebhookError> {
    let c = event.to_channel_event();
    let envelope =
        serde_json::json!({"kind": event.event_name(), "content": c.content, "meta": c.meta});
    if serde_json::to_vec(&envelope).map_err(|_| invalid())?.len() > 16 * 1024 {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Deserialize)]
struct Owner {
    login: Option<String>,
    username: Option<String>,
}
#[derive(Deserialize)]
struct Repository {
    owner: Owner,
    name: String,
}
impl Repository {
    fn into_ref(
        self,
        alias: &str,
        kind: ForgeKind,
        host: &str,
    ) -> Result<RepositoryRef, ForgeWebhookError> {
        let owner = match kind {
            ForgeKind::Forgejo => self.owner.login.or(self.owner.username),
            _ => self.owner.login,
        }
        .ok_or_else(invalid)?;
        Ok(RepositoryRef {
            alias: alias.into(),
            forge: kind,
            host: host.into(),
            owner,
            name: self.name,
        })
    }
}
#[derive(Deserialize)]
struct Project {
    path_with_namespace: String,
}
impl Project {
    fn into_ref(
        self,
        alias: &str,
        kind: ForgeKind,
        host: &str,
    ) -> Result<RepositoryRef, ForgeWebhookError> {
        let (owner, name) = self
            .path_with_namespace
            .rsplit_once('/')
            .ok_or_else(invalid)?;
        Ok(RepositoryRef {
            alias: alias.into(),
            forge: kind,
            host: host.into(),
            owner: owner.into(),
            name: name.into(),
        })
    }
}
#[derive(Deserialize)]
struct Push {
    r#ref: String,
    before: String,
    after: String,
}
#[derive(Deserialize)]
struct GitHubPush {
    repository: Repository,
    deleted: Option<bool>,
    forced: Option<bool>,
}
#[derive(Deserialize)]
struct ForgejoPush {
    repository: Repository,
}
#[derive(Deserialize)]
struct GitLabPush {
    project: Project,
    object_kind: String,
}

pub(crate) fn push(
    body: &[u8],
    delivery_id: String,
    alias: &str,
    kind: ForgeKind,
    host: &str,
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let p: Push = decode(body)?;
    let is_gitlab = kind == ForgeKind::GitLab;
    let after_is_zero = p.after.bytes().all(|b| b == b'0');
    // Provider identity subsets must stay separate: GitLab also sends a
    // deprecated `repository` object which has no GitHub-shaped owner field.
    let (repository, deleted, forced) = match kind {
        ForgeKind::GitHub => {
            let native: GitHubPush = decode(body)?;
            if native.deleted.is_some_and(|value| value != after_is_zero) {
                return Err(invalid());
            }
            (
                native.repository.into_ref(alias, kind, host)?,
                native.deleted,
                native.forced,
            )
        }
        ForgeKind::Forgejo => {
            let native: ForgejoPush = decode(body)?;
            (
                native.repository.into_ref(alias, kind, host)?,
                Some(after_is_zero),
                None,
            )
        }
        ForgeKind::GitLab => {
            let native: GitLabPush = decode(body)?;
            if native.object_kind != "push" {
                return Err(invalid());
            }
            (
                native.project.into_ref(alias, kind, host)?,
                Some(after_is_zero),
                None,
            )
        }
    };
    let Some(branch) = p.r#ref.strip_prefix("refs/heads/") else {
        return Ok(None);
    };
    validate_repository(&repository, &delivery_id)?;
    if !valid_branch(branch) || !valid_sha(&p.before, true) || !valid_sha(&p.after, true) {
        return Err(invalid());
    }
    let event = BranchPushEvent {
        repository,
        delivery_id,
        payload_fingerprint: fingerprint(body),
        details: BranchPushDetails {
            r#ref: p.r#ref,
            before_sha: p.before,
            after_sha: p.after,
            deleted,
            forced,
            provider_event: if is_gitlab { "Push Hook" } else { "push" }.into(),
        },
    };
    bounded(&event)?;
    Ok(Some(WebhookEvent::BranchPush(event)))
}

#[derive(Deserialize)]
struct Action {
    action: String,
}
#[derive(Deserialize)]
struct FromBranch {
    from: String,
}
#[derive(Deserialize)]
struct BaseEdit {
    r#ref: Option<FromBranch>,
}
#[derive(Default, Deserialize)]
struct Edits {
    base: Option<BaseEdit>,
    r#ref: Option<FromBranch>,
}
#[derive(Deserialize)]
struct Branch {
    r#ref: Option<String>,
}
#[derive(Deserialize)]
struct Head {
    sha: Option<String>,
}
#[derive(Deserialize)]
struct PullRequest {
    number: Option<u64>,
    base: Option<Branch>,
    draft: Option<bool>,
    head: Option<Head>,
    #[serde(default)]
    title: String,
    #[serde(default)]
    html_url: String,
}
#[derive(Deserialize)]
struct PullEdit {
    number: Option<u64>,
    repository: Repository,
    pull_request: PullRequest,
}
#[derive(Deserialize)]
struct EditProbe {
    changes: Option<Edits>,
}

pub(crate) fn pull_request(
    body: &[u8],
    delivery: &str,
    alias: &str,
    kind: ForgeKind,
    host: &str,
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let action: Action = decode(body)?;
    let is_github = kind == ForgeKind::GitHub;
    if action.action != "edited"
        && !(is_github
            && matches!(
                action.action.as_str(),
                "ready_for_review" | "converted_to_draft"
            ))
    {
        return Ok(None);
    }
    // Establish an explicit signal before decoding unrelated current snapshots.
    // In particular a title-only edit may have base SHA metadata without a ref.
    let old = if action.action == "edited" {
        let probe: EditProbe = decode(body)?;
        let edits = probe.changes.unwrap_or_default();
        let old = if is_github {
            edits.base.and_then(|b| b.r#ref)
        } else {
            edits.r#ref
        };
        if old.is_none() {
            return Ok(None);
        }
        old
    } else {
        None
    };
    let p: PullEdit = decode(body)?;
    let mut changes = ChangeRequestChanges::default();
    if action.action == "edited" {
        if let Some(old) = old {
            let current = p
                .pull_request
                .base
                .and_then(|base| base.r#ref)
                .ok_or_else(invalid)?;
            if !valid_branch(&old.from) || !valid_branch(&current) {
                return Err(invalid());
            }
            if old.from != current {
                changes.base = Some(BaseBranchChange {
                    previous: Some(old.from),
                    current,
                });
            }
        }
    } else {
        let current = action.action == "converted_to_draft";
        if p.pull_request.draft.is_some_and(|v| v != current) {
            return Err(invalid());
        }
        changes.draft = Some(DraftChange {
            previous: None,
            current,
        });
    }
    if changes == ChangeRequestChanges::default() {
        return Ok(None);
    }
    let index = p.number.or(p.pull_request.number).ok_or_else(invalid)?;
    if index == 0
        || p.number
            .zip(p.pull_request.number)
            .is_some_and(|(a, b)| a != b)
    {
        return Err(invalid());
    }
    let event = ChangeRequestEvent {
        repository: p.repository.into_ref(alias, kind, host)?,
        delivery_id: delivery.into(),
        index,
        action: ChangeRequestEventAction::Updated,
        provider_action: Some(action.action),
        change_request_changes: Some(changes),
        labels_changed: false,
        payload_fingerprint: fingerprint(body),
        head_sha: p.pull_request.head.and_then(|h| h.sha).unwrap_or_default(),
        title: p.pull_request.title,
        url: p.pull_request.html_url,
    };
    finish_state(event)
}

fn finish_state(event: ChangeRequestEvent) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    validate_repository(&event.repository, &event.delivery_id)?;
    if event.index == 0
        || (!event.head_sha.is_empty() && !valid_sha(&event.head_sha, false))
        || (event.action == ChangeRequestEventAction::Synchronized && event.head_sha.is_empty())
        || event.title.len() > 4096
        || event.url.len() > 4096
    {
        return Err(invalid());
    }
    bounded(&event)?;
    Ok(Some(WebhookEvent::ChangeRequest(event)))
}

#[derive(Deserialize)]
struct Delta<T> {
    previous: T,
    current: T,
}
#[derive(Default, Deserialize)]
struct MrChanges {
    target_branch: Option<Delta<String>>,
    draft: Option<Delta<bool>>,
    // Keep legacy label semantics (including malformed-label exclusion).
    labels: Option<serde_json::Value>,
}
// Legacy MR handling tolerates a non-object `changes` container. Preserve that
// behavior without swallowing malformed targeted deltas inside an object or
// materializing unrelated fields. Map decoding retains serde duplicate checks.
struct CompatibleMrChanges(MrChanges);
impl<'de> Deserialize<'de> for CompatibleMrChanges {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ChangesVisitor;
        impl<'de> serde::de::Visitor<'de> for ChangesVisitor {
            type Value = CompatibleMrChanges;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("merge request changes")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Self::Value, A::Error> {
                MrChanges::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(CompatibleMrChanges)
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(CompatibleMrChanges(MrChanges::default()))
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(CompatibleMrChanges(MrChanges::default()))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(CompatibleMrChanges(MrChanges::default()))
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(CompatibleMrChanges(MrChanges::default()))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(CompatibleMrChanges(MrChanges::default()))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(CompatibleMrChanges(MrChanges::default()))
            }
        }
        deserializer.deserialize_any(ChangesVisitor)
    }
}
#[derive(Deserialize)]
struct MrProbe {
    changes: Option<CompatibleMrChanges>,
}
#[derive(Deserialize)]
struct Commit {
    id: String,
}
#[derive(Deserialize)]
struct MrAttrs {
    action: String,
    state: Option<String>,
    iid: u64,
    target_branch: Option<String>,
    draft: Option<bool>,
    oldrev: Option<String>,
    last_commit: Option<Commit>,
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
}
#[derive(Deserialize)]
struct MergeRequest {
    object_kind: String,
    project: Project,
    object_attributes: MrAttrs,
}

pub(crate) fn gitlab_merge_request(
    body: &[u8],
    headers: &[(String, String)],
    alias: &str,
    kind: ForgeKind,
    host: &str,
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let p: MrProbe = decode(body)?;
    let deltas = p.changes.map(|changes| changes.0).unwrap_or_default();
    if deltas.target_branch.is_none() && deltas.draft.is_none() {
        return Ok(None);
    }
    let p: MergeRequest = decode(body)?;
    if p.object_kind != "merge_request" {
        return Err(invalid());
    }
    let a = p.object_attributes;
    let mut changes = ChangeRequestChanges::default();
    if let Some(d) = deltas.target_branch {
        if !valid_branch(&d.previous)
            || !valid_branch(&d.current)
            || a.target_branch.as_ref().is_some_and(|v| *v != d.current)
        {
            return Err(invalid());
        }
        if d.previous != d.current {
            changes.base = Some(BaseBranchChange {
                previous: Some(d.previous),
                current: d.current,
            });
        }
    }
    if let Some(d) = deltas.draft {
        if a.draft.is_some_and(|v| v != d.current) {
            return Err(invalid());
        }
        if d.previous != d.current {
            changes.draft = Some(DraftChange {
                previous: Some(d.previous),
                current: d.current,
            });
        }
    }
    if changes == ChangeRequestChanges::default() {
        return Ok(None);
    }
    if a.oldrev.as_deref().is_some_and(|v| {
        !valid_sha(v, false) || a.last_commit.as_ref().is_some_and(|head| head.id == v)
    }) {
        return Err(invalid());
    }
    let action = match a.action.as_str() {
        "update" if a.oldrev.is_some() => ChangeRequestEventAction::Synchronized,
        "update" => ChangeRequestEventAction::Updated,
        "open" => ChangeRequestEventAction::Opened,
        "reopen" => ChangeRequestEventAction::Reopened,
        "close" if a.state.as_deref() == Some("closed") => ChangeRequestEventAction::Closed,
        "merge" if a.state.as_deref() == Some("merged") => ChangeRequestEventAction::Merged,
        "close" | "merge" => return Err(invalid()),
        _ => return Ok(None),
    };
    let delivery_id = crate::ci_webhooks::gitlab_delivery(headers)?.0;
    let labels_changed =
        crate::gitlab::gitlab_labels_changed(&serde_json::json!({"labels": deltas.labels}));
    finish_state(ChangeRequestEvent {
        repository: p.project.into_ref(alias, kind, host)?,
        delivery_id,
        index: a.iid,
        action,
        provider_action: Some(a.action),
        change_request_changes: Some(changes),
        labels_changed,
        payload_fingerprint: fingerprint(body),
        head_sha: a.last_commit.map(|c| c.id).unwrap_or_default(),
        title: a.title,
        url: a.url,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn delivery_selector_preserves_values_and_validates_every_candidate() {
        let headers = vec![
            ("WEBHOOK-ID".into(), "  actual  ".into()),
            ("idempotency-key".into(), "second".into()),
        ];
        assert_eq!(
            crate::ci_webhooks::gitlab_delivery(&headers)
                .expect("identity")
                .0,
            "  actual  "
        );
        let mut oversized = headers;
        oversized.push(("x-gitlab-webhook-uuid".into(), "x".repeat(257)));
        assert!(crate::ci_webhooks::gitlab_delivery(&oversized).is_err());
    }
    #[test]
    fn ref_validation_follows_git_branch_rules_without_git_execution() {
        for name in ["main", "release/next", "a-b", "branch.LOCK"] {
            assert!(valid_branch(name));
        }
        for name in [
            "",
            "a..b",
            "a b",
            "a/",
            "/a",
            ".hidden",
            "a.lock",
            "a/.hidden",
            "a@{b",
            "a\\b",
            "a~b",
            "a?b",
            "a*b",
            "a[b",
            "a^b",
            "a:b",
            "a.",
        ] {
            assert!(!valid_branch(name), "{name}");
        }
    }
}
