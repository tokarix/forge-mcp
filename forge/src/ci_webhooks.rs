//! Typed, bounded CI projections, called only after provider authentication.
use crate::ForgeWebhookError;
use domain::{
    CiChangeEvent, CiEventDetails, CiEventSource, ForgeKind, PublishableEvent, RepositoryRef,
    WebhookEvent,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

fn invalid() -> ForgeWebhookError {
    ForgeWebhookError::InvalidPayload("invalid CI webhook projection".into())
}
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ForgeWebhookError> {
    // Never include raw payload values or serde diagnostics in errors/logs.
    serde_json::from_slice(body).map_err(|_| invalid())
}
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}
fn optional_header(
    headers: &[(String, String)],
    name: &str,
) -> Result<Option<String>, ForgeWebhookError> {
    let value = header(headers, name);
    if value.is_some_and(|v| v.len() > 256) {
        return Err(invalid());
    }
    Ok(value.filter(|v| !v.trim().is_empty()).map(str::to_owned))
}
fn finish(event: CiChangeEvent) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let channel = event.to_channel_event();
    let envelope =
        serde_json::json!({"kind": "ci", "content": channel.content, "meta": channel.meta});
    if serde_json::to_vec(&envelope).map_err(|_| invalid())?.len() > 16 * 1024 {
        return Err(invalid());
    }
    Ok(Some(WebhookEvent::CiChange(event)))
}

#[derive(Deserialize)]
struct Action {
    action: String,
}
#[derive(Deserialize)]
struct Owner {
    login: String,
}
#[derive(Deserialize)]
struct Repository {
    owner: Owner,
    name: String,
}
#[derive(Deserialize)]
struct Status {
    repository: Repository,
    sha: String,
    id: Option<std::num::NonZeroU64>,
    context: Option<String>,
    state: Option<String>,
    updated_at: Option<String>,
}
#[derive(Deserialize)]
struct NativeId {
    id: Option<std::num::NonZeroU64>,
}
#[derive(Deserialize)]
struct CheckPayload {
    head_sha: String,
    id: Option<std::num::NonZeroU64>,
    check_suite: Option<NativeId>,
    name: Option<String>,
    status: Option<String>,
    conclusion: Option<String>,
    started_at: Option<String>,
    completed_at: Option<String>,
    updated_at: Option<String>,
}
#[derive(Deserialize)]
struct Run {
    repository: Repository,
    check_run: CheckPayload,
}
#[derive(Deserialize)]
struct Suite {
    repository: Repository,
    check_suite: CheckPayload,
}

pub(crate) fn github(
    body: &[u8],
    headers: &[(String, String)],
    event: &str,
    alias: &str,
    kind: ForgeKind,
    host: &str,
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let action = if event == "status" {
        None
    } else {
        let action = decode::<Action>(body)?.action;
        let supported = match event {
            "check_run" => matches!(
                action.as_str(),
                "created" | "completed" | "rerequested" | "requested_action"
            ),
            "check_suite" => matches!(action.as_str(), "completed" | "requested" | "rerequested"),
            _ => false,
        };
        if !supported {
            return Ok(None);
        }
        Some(action)
    };
    let (repo, sha, mut details) = if event == "status" {
        let payload = decode::<Status>(body)?;
        let mut details = CiEventDetails::new(CiEventSource::CommitStatus, event.into());
        details.id = payload.id.map(std::num::NonZeroU64::get);
        details.context = payload.context;
        details.status = payload.state;
        details.updated_at = payload.updated_at;
        (payload.repository, payload.sha, details)
    } else {
        let (repo, check, source) = if event == "check_run" {
            let payload = decode::<Run>(body)?;
            (
                payload.repository,
                payload.check_run,
                CiEventSource::CheckRun,
            )
        } else {
            let payload = decode::<Suite>(body)?;
            (
                payload.repository,
                payload.check_suite,
                CiEventSource::CheckSuite,
            )
        };
        let mut details = CiEventDetails::new(source, event.into());
        details.id = check.id.map(std::num::NonZeroU64::get);
        details.parent_id = check
            .check_suite
            .and_then(|s| s.id)
            .map(std::num::NonZeroU64::get);
        details.name = check.name;
        details.status = check.status;
        details.conclusion = check.conclusion;
        details.started_at = check.started_at;
        details.completed_at = check.completed_at;
        details.updated_at = check.updated_at;
        (repo, check.head_sha, details)
    };
    // GitHub namespaces are one component, unlike GitLab groups.
    if repo.owner.login.contains('/') {
        return Err(invalid());
    }
    let delivery = optional_header(headers, "x-github-delivery")?;
    details.provider_delivery_id.clone_from(&delivery);
    details.delivery_id_source = delivery.as_ref().map(|_| "X-GitHub-Delivery".into());
    let repository = RepositoryRef {
        alias: alias.into(),
        forge: kind,
        host: host.into(),
        owner: repo.owner.login,
        name: repo.name,
    };
    let event = CiChangeEvent::new(
        repository,
        sha,
        delivery.unwrap_or_default(),
        action,
        details,
        format!("{:x}", Sha256::digest(body)),
    )
    .map_err(|_| invalid())?;
    finish(event)
}

// Missing paths identify older unsupported payloads. A supplied null, empty or
// non-string path is malformed, rather than permission to infer coordinates.
#[derive(Default)]
enum ProjectPath {
    #[default]
    Missing,
    Present(String),
}
impl<'de> Deserialize<'de> for ProjectPath {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::Present)
    }
}
#[derive(Default, Deserialize)]
struct Project {
    #[serde(default)]
    path_with_namespace: ProjectPath,
    id: Option<std::num::NonZeroU64>,
}
#[derive(Deserialize)]
struct CommitSha {
    sha: Option<String>,
}
#[derive(Deserialize)]
struct PipelineAttrs {
    sha: String,
    id: Option<std::num::NonZeroU64>,
    status: Option<String>,
    name: Option<String>,
    started_at: Option<String>,
    finished_at: Option<String>,
    updated_at: Option<String>,
}
#[derive(Deserialize)]
struct Pipeline {
    object_kind: String,
    #[serde(default)]
    project: Project,
    project_id: Option<std::num::NonZeroU64>,
    object_attributes: PipelineAttrs,
    commit: Option<PipelineCommit>,
}
#[derive(Deserialize)]
struct PipelineCommit {
    id: Option<String>,
    sha: Option<String>,
}
#[derive(Deserialize)]
struct Job {
    object_kind: String,
    #[serde(default)]
    project: Project,
    project_id: Option<std::num::NonZeroU64>,
    sha: String,
    build_id: Option<std::num::NonZeroU64>,
    pipeline_id: Option<std::num::NonZeroU64>,
    build_name: Option<String>,
    build_status: Option<String>,
    build_started_at: Option<String>,
    build_finished_at: Option<String>,
    build_updated_at: Option<String>,
    // commit.id is a pipeline ID and is deliberately not projected as a SHA.
    commit: Option<CommitSha>,
}

pub(crate) fn gitlab(
    body: &[u8],
    headers: &[(String, String)],
    event: &str,
    alias: &str,
    kind: ForgeKind,
    host: &str,
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let (project, project_id, sha, commit, mut details) = if event == "Pipeline Hook" {
        let p = decode::<Pipeline>(body)?;
        if p.object_kind != "pipeline" {
            return Err(invalid());
        }
        let a = p.object_attributes;
        if p.commit.as_ref().is_some_and(|c| {
            c.id.as_ref().is_some_and(|id| id != &a.sha)
                || c.sha.as_ref().is_some_and(|sha| sha != &a.sha)
        }) {
            return Err(invalid());
        }
        let mut d = CiEventDetails::new(CiEventSource::Pipeline, event.into());
        d.id = a.id.map(std::num::NonZeroU64::get);
        d.status = a.status;
        d.name = a.name;
        d.started_at = a.started_at;
        d.completed_at = a.finished_at;
        d.updated_at = a.updated_at;
        (p.project, p.project_id, a.sha, None, d)
    } else {
        let p = decode::<Job>(body)?;
        if p.object_kind != "build" {
            return Err(invalid());
        }
        let mut d = CiEventDetails::new(CiEventSource::Job, event.into());
        d.id = p.build_id.map(std::num::NonZeroU64::get);
        d.parent_id = p.pipeline_id.map(std::num::NonZeroU64::get);
        d.name = p.build_name;
        d.status = p.build_status;
        d.started_at = p.build_started_at;
        d.completed_at = p.build_finished_at;
        d.updated_at = p.build_updated_at;
        (p.project, p.project_id, p.sha, p.commit, d)
    };
    if project_id.zip(project.id).is_some_and(|(a, b)| a != b)
        || commit.and_then(|c| c.sha).is_some_and(|s| s != sha)
    {
        return Err(invalid());
    }
    let ProjectPath::Present(path) = project.path_with_namespace else {
        tracing::debug!("ignoring legacy GitLab CI webhook without project path");
        return Ok(None);
    };
    let (owner, name) = path.rsplit_once('/').ok_or_else(invalid)?;
    details.provider_event_id = optional_header(headers, "x-gitlab-event-uuid")?;
    details.provider_delivery_id = optional_header(headers, "x-gitlab-webhook-uuid")?;
    let mut delivery = None;
    for name in ["webhook-id", "Idempotency-Key", "X-Gitlab-Webhook-UUID"] {
        let value = optional_header(headers, name)?;
        if delivery.is_none() && value.is_some() {
            delivery = value;
            details.delivery_id_source = Some(name.into());
        }
    }
    let repository = RepositoryRef {
        alias: alias.into(),
        forge: kind,
        host: host.into(),
        owner: owner.into(),
        name: name.into(),
    };
    let event = CiChangeEvent::new(
        repository,
        sha,
        delivery.unwrap_or_default(),
        None,
        details,
        format!("{:x}", Sha256::digest(body)),
    )
    .map_err(|_| invalid())?;
    finish(event)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn ci_serialized_envelope_budget_includes_json_escaping() {
        let mut details = CiEventDetails::new(CiEventSource::Job, "Job Hook".into());
        details.name = Some("\u{1}".repeat(1024));
        details.context = Some("\u{1}".repeat(1024));
        details.provider_event_id = Some("\u{1}".repeat(256));
        details.provider_delivery_id = Some("\u{1}".repeat(256));
        let repository = RepositoryRef {
            alias: "forge".into(),
            forge: ForgeKind::GitLab,
            host: "https://provider.invalid".into(),
            owner: "org".into(),
            name: "repo".into(),
        };
        let event = CiChangeEvent::new(
            repository,
            "a".repeat(40),
            "\u{1}".repeat(256),
            None,
            details,
            String::new(),
        )
        .expect("individual byte bounds");
        assert!(finish(event).is_err());
    }
}
