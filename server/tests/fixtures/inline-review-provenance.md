# Inline review webhook fixture provenance

Inventory read on 2026-09-07. `../inline_review_webhooks.rs` constructs
small deterministic source-shaped payloads; these are not captured deliveries.
No provider service was started. No production credentials or CI changes are
needed to run these tests.

## GitHub

The [comment contract](https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request_review_comment)
has created/edited/deleted actions; the
[thread contract](https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request_review_thread)
has resolved/unresolved actions. Provider-maintained Octokit schemas inspected:

- [comment](https://raw.githubusercontent.com/octokit/webhooks/main/payload-schemas/api.github.com/common/pull-request-review-comment.schema.json)
- [resolved](https://raw.githubusercontent.com/octokit/webhooks/main/payload-schemas/api.github.com/pull_request_review_thread/resolved.schema.json)
- [unresolved](https://raw.githubusercontent.com/octokit/webhooks/main/payload-schemas/api.github.com/pull_request_review_thread/unresolved.schema.json)

The thread node ID is opaque, and comments are a list. Comment ID, review ID,
reply ID and commit IDs identify distinct resources. Current/original lines,
multiline sides and legacy diff positions are projected independently. Minimal
fixtures intentionally omit display/body metadata to test refresh-hint tolerance.

## GitLab v18.3.0-ee

Source was fetched directly from the tagged GitLab repository:

- [NoteBuilder](https://gitlab.com/gitlab-org/gitlab/-/blob/v18.3.0-ee/lib/gitlab/hook_data/note_builder.rb)
  whitelists `type`, `id`, `discussion_id`, `commit_id`, `position` and
  `original_position` in note attributes.
- [DataBuilder::Note](https://gitlab.com/gitlab-org/gitlab/-/blob/v18.3.0-ee/lib/gitlab/data_builder/note.rb)
  adds the native action, project and MR data.
- [PostProcessService](https://gitlab.com/gitlab-org/gitlab/-/blob/v18.3.0-ee/app/services/notes/post_process_service.rb)
  emits create hooks for non-system notes.
- [UpdateService](https://gitlab.com/gitlab-org/gitlab/-/blob/v18.3.0-ee/app/services/notes/update_service.rb)
  emits update hooks when the note text changed, not merely when resolution
  state changed.
- [DiffNote](https://gitlab.com/gitlab-org/gitlab/-/blob/v18.3.0-ee/app/models/diff_note.rb)
  establishes the native diff-note class and position semantics;
  [Position](https://gitlab.com/gitlab-org/gitlab/-/blob/v18.3.0-ee/lib/gitlab/diff/position.rb)
  serializes position attributes as an object through `as_json`/`to_json`.

Only explicit MR `type: DiffNote` create/update payloads migrate from the legacy
submitted/comment notification to the new inline-comment family. General,
ambiguous and `LegacyDiffNote` notes retain the old path. Location objects retain
old/new paths and lines, base/start/head commits and multiline endpoints without
interpreting `line_code`. Image pixel coordinates are not projected. Missing
locations remain absent. MR last_commit is never a comment commit. No delete or
individual resolve/unresolve mapping is established. Aggregate MR discussion
status and approval signals cannot identify an individual thread.

## Forgejo v16.0.3 (the CI-pinned version)

- [Review service](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/pull/review.go)
  calls `PullRequestCodeComment` for published code comments.
- [Notify interface](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/notify/notifier.go),
  [dispatcher](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/notify/notify.go),
  [no-op implementation](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/notify/null.go)
  and [webhook notifier](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/webhook/notifier.go):
  the webhook notifier embeds NullNotifier and does not override
  PullRequestCodeComment. This notification emits no webhook there.
- [Comment service](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/issue/comments.go)
  calls UpdateComment/DeleteComment for published comments. Their webhook
  implementations use IssueCommentPayload and
  [ToAPIComment](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/convert/issue_comment.go).
  This conversion has ID/body/URLs/timestamps but no inline discriminator,
  review/thread ID or location. The separate timeline conversion is not used.
  [Hook structs](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/modules/structs/hook.go)
  confirm this payload type.
- [UpdateResolveConversation](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/routers/web/repo/pull_review.go)
  invokes the model's MarkConversation for Resolve/UnResolve. The inspected
  notify interface and webhook notifier have no conversation-resolution event.

Consequently this implementation adds no Forgejo mapping. Existing verdict and
general-comment paths remain intact. Negative fixtures reject invented GitHub
inline/thread headers on Forgejo. This is a versioned source inventory, not a
universal statement about future releases or observed delivery behavior.
