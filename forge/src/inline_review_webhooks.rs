//! Provider inline webhook projections; called only after verification.
use crate::ForgeWebhookError;
use domain::{InlineReviewComment, InlineReviewDetails, RepositoryRef, WebhookEvent};
use serde::Deserialize;

fn invalid() -> ForgeWebhookError {
    ForgeWebhookError::InvalidPayload("invalid inline review webhook payload".into())
}

#[derive(Deserialize)]
struct Action {
    action: String,
}
#[derive(Deserialize)]
struct Payload {
    repository: Repository,
    pull_request: PullRequest,
    comment: Option<Comment>,
    thread: Option<Thread>,
}
#[derive(Deserialize)]
struct Repository {
    name: String,
    owner: Owner,
}
#[derive(Deserialize)]
struct Owner {
    login: String,
}
#[derive(Deserialize)]
struct PullRequest {
    number: u64,
    head: Option<Head>,
}
#[derive(Deserialize)]
struct Head {
    sha: Option<String>,
}
#[derive(Deserialize)]
struct Thread {
    node_id: String,
    #[serde(default)]
    comments: Vec<Comment>,
}
#[derive(Deserialize)]
struct Comment {
    id: Option<u64>,
    pull_request_review_id: Option<u64>,
    #[serde(flatten)]
    details: InlineReviewComment,
}

fn optional(value: Option<String>, limit: usize) -> Result<Option<String>, ForgeWebhookError> {
    if value.as_ref().is_some_and(|s| s.len() > limit) {
        return Err(invalid());
    }
    Ok(value.filter(|s| !s.trim().is_empty()))
}

impl Comment {
    fn project(self) -> Result<InlineReviewComment, ForgeWebhookError> {
        let mut d = self.details;
        // Only native wire IDs count; similarly named unknown fields never fill them.
        d.gitlab_position = None;
        d.gitlab_original_position = None;
        d.comment_id = self.id;
        d.review_id = self.pull_request_review_id;
        if [
            d.comment_id,
            d.review_id,
            d.in_reply_to_id,
            d.line,
            d.start_line,
            d.original_line,
            d.original_start_line,
        ]
        .contains(&Some(0))
        {
            return Err(invalid());
        }
        d.node_id = optional(d.node_id, 256)?;
        d.commit_id = optional(d.commit_id, 256)?;
        d.original_commit_id = optional(d.original_commit_id, 256)?;
        d.path = optional(d.path, 4096)?;
        Ok(d)
    }
}

pub(crate) fn github(
    body: &[u8],
    kind: &str,
    delivery: String,
    alias: &str,
    forge: domain::ForgeKind,
    host: &str,
) -> Result<Option<WebhookEvent>, ForgeWebhookError> {
    let action: Action = serde_json::from_slice(body).map_err(|_| invalid())?;
    if !matches!(
        (kind, action.action.as_str()),
        (
            "pull_request_review_comment",
            "created" | "edited" | "deleted"
        ) | ("pull_request_review_thread", "resolved" | "unresolved")
    ) {
        return Ok(None);
    }
    let p: Payload = serde_json::from_slice(body).map_err(|_| invalid())?;
    let valid = |s: &str| {
        !s.trim().is_empty()
            && s != "."
            && s != ".."
            && !s.chars().any(|c| c.is_control() || c == '/' || c == '\\')
    };
    if p.pull_request.number == 0
        || !valid(&p.repository.name)
        || !valid(&p.repository.owner.login)
        || p.repository.name.len() + p.repository.owner.login.len() > 1024
        || delivery.len() > 256
        || alias.len() > 256
    {
        return Err(invalid());
    }
    let repository = RepositoryRef {
        alias: alias.into(),
        forge,
        host: host.into(),
        owner: p.repository.owner.login,
        name: p.repository.name,
    };
    let head = optional(p.pull_request.head.and_then(|h| h.sha), 256)?;
    let fingerprint = crate::payload_fingerprint(body);
    if kind == "pull_request_review_comment" {
        let comment = p.comment.ok_or_else(invalid)?.project()?;
        if comment.comment_id.is_none() {
            return Err(invalid());
        }
        let action = match action.action.as_str() {
            "created" => domain::PullRequestReviewCommentAction::Created,
            "edited" => domain::PullRequestReviewCommentAction::Edited,
            _ => domain::PullRequestReviewCommentAction::Deleted,
        };
        Ok(Some(WebhookEvent::PullRequestReviewComment(
            domain::PullRequestReviewCommentEvent::new(
                repository,
                p.pull_request.number,
                action,
                delivery,
                head,
                InlineReviewDetails {
                    comment: Some(comment),
                    ..Default::default()
                },
                fingerprint,
            ),
        )))
    } else {
        let thread = p.thread.ok_or_else(invalid)?;
        let thread_id = optional(Some(thread.node_id), 256)?.ok_or_else(invalid)?;
        // Bound projected storage without selecting a representative comment.
        if thread.comments.len() > 1024 {
            return Err(invalid());
        }
        let comments = thread
            .comments
            .into_iter()
            .map(Comment::project)
            .collect::<Result<Vec<_>, _>>()?;
        let action = if action.action == "resolved" {
            domain::PullRequestReviewThreadAction::Resolved
        } else {
            domain::PullRequestReviewThreadAction::Unresolved
        };
        Ok(Some(WebhookEvent::PullRequestReviewThread(
            domain::PullRequestReviewThreadEvent::new(
                repository,
                p.pull_request.number,
                action,
                delivery,
                head,
                InlineReviewDetails {
                    thread_id: Some(thread_id),
                    comments,
                    comment: None,
                },
                fingerprint,
            ),
        )))
    }
}

#[derive(Deserialize)]
struct GitLabPayload {
    project: GitLabProject,
    merge_request: GitLabMr,
    object_attributes: GitLabNote,
}
#[derive(Deserialize)]
struct GitLabProject {
    path_with_namespace: String,
}
#[derive(Deserialize)]
struct GitLabMr {
    iid: u64,
}
#[derive(Deserialize)]
struct GitLabNote {
    id: u64,
    discussion_id: Option<String>,
    commit_id: Option<String>,
    position: Option<domain::GitLabInlinePosition>,
    original_position: Option<domain::GitLabInlinePosition>,
}
fn gitlab_position(p: &mut domain::GitLabInlinePosition) -> Result<(), ForgeWebhookError> {
    for value in [&mut p.base_sha, &mut p.start_sha, &mut p.head_sha] {
        *value = optional(value.take(), 256)?;
    }
    for value in [&mut p.old_path, &mut p.new_path] {
        *value = optional(value.take(), 4096)?;
    }
    p.position_type = optional(p.position_type.take(), 64)?;
    if [p.old_line, p.new_line].contains(&Some(0)) {
        return Err(invalid());
    }
    if let Some(range) = &mut p.line_range {
        for line in [&mut range.start, &mut range.end].into_iter().flatten() {
            if [line.old_line, line.new_line].contains(&Some(0)) {
                return Err(invalid());
            }
            line.r#type = optional(line.r#type.take(), 64)?;
        }
    }
    Ok(())
}

pub(crate) enum GitLabInlineResult {
    Legacy,
    Handled(Option<Box<WebhookEvent>>),
}

/// A handled result means a proven diff-note family, including ignored actions.
/// Ambiguous/general notes return `Legacy` so the old parser retains ownership.
pub(crate) fn gitlab(
    body: &[u8],
    delivery: &str,
    alias: &str,
    forge: domain::ForgeKind,
    host: &str,
) -> Result<GitLabInlineResult, ForgeWebhookError> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| invalid())?;
    let attrs = &v["object_attributes"];
    if attrs["noteable_type"] != "MergeRequest" || attrs["type"] != "DiffNote" {
        return Ok(GitLabInlineResult::Legacy);
    }
    let action = match attrs["action"].as_str() {
        Some("create") => domain::PullRequestReviewCommentAction::Created,
        Some("update") => domain::PullRequestReviewCommentAction::Edited,
        _ => return Ok(GitLabInlineResult::Handled(None)),
    };
    let p: GitLabPayload = serde_json::from_value(v).map_err(|_| invalid())?;
    let (owner, name) = p
        .project
        .path_with_namespace
        .rsplit_once('/')
        .ok_or_else(invalid)?;
    let valid = |s: &str| {
        !s.trim().is_empty()
            && s != "."
            && s != ".."
            && !s.chars().any(|c| c.is_control() || c == '\\')
    };
    if !owner.split('/').all(valid)
        || !valid(name)
        || p.merge_request.iid == 0
        || p.object_attributes.id == 0
        || p.project.path_with_namespace.len() > 1024
        || delivery.len() > 256
        || alias.len() > 256
    {
        return Err(invalid());
    }
    let mut note = p.object_attributes;
    for position in [&mut note.position, &mut note.original_position]
        .into_iter()
        .flatten()
    {
        gitlab_position(position)?;
    }
    let comment = InlineReviewComment {
        comment_id: Some(note.id),
        commit_id: optional(note.commit_id, 256)?,
        gitlab_position: note.position,
        gitlab_original_position: note.original_position,
        ..Default::default()
    };
    let details = InlineReviewDetails {
        thread_id: optional(note.discussion_id, 256)?,
        comment: Some(comment),
        comments: vec![],
    };
    let repository = RepositoryRef {
        alias: alias.into(),
        forge,
        host: host.into(),
        owner: owner.into(),
        name: name.into(),
    };
    let mut event = domain::PullRequestReviewCommentEvent::new(
        repository,
        p.merge_request.iid,
        action,
        delivery.into(),
        None,
        details,
        crate::payload_fingerprint(body),
    );
    event.provider_action = if event.action == domain::PullRequestReviewCommentAction::Created {
        "create".into()
    } else {
        "update".into()
    };
    Ok(GitLabInlineResult::Handled(Some(Box::new(
        WebhookEvent::PullRequestReviewComment(event),
    ))))
}
