# forge-mcp

Multi-forge, policy-enforcing MCP server for AI coding agents.

Supported forges:

- **Forgejo / Gitea** — full support
- **GitHub** — native REST/GraphQL support with managed GitHub App installation authentication
- **GitLab** — read + write support. The GitLab adapter was autonomously implemented by cockpit-orchestrated agents overnight while I slept — which is kind of the whole point of this project.

MCP tools:

- `read_repository_file` — read a single UTF-8 text file from a repository
- `commit_patch` — apply a git-format patch to a new branch and push it
- `open_change_request` — open a pull request on the forge

Write safety:

- Diff validation rejects binary files, symlinks, submodules, path traversal, oversized patches
- `commit_patch` only accepts git diff format; generate patches with `git diff --no-ext-diff --binary` or `git show`, not hand-written traditional unified diffs
- The server validates and applies patches in a clean clone of the base branch
- Policy engine enforces branch prefix (`agent/`) and protected path rejection
- Audit-before-action on all write operations
- Git auth via `http.extraHeader` — token never in argv or URLs

### Choosing pull request feedback

`get_change_request_comments` remains the mixed chronological discussion/review
feed. Use `get_change_request_discussion_comments` for general discussion alone,
or `get_change_request_reviews` for submitted top-level formal reviews alone.
These narrow reads fetch only their selected provider resource; an error reading
the other resource cannot break them. Empty streams return `[]`. Existing comment
and submit-review writes are unchanged. Inline review comments are not included.

For example, pass `forge="adlevio", owner="tokarix", repo="forge-mcp", index=137`
to these tools (substitute the pull request index for the task):

- A fresh review starts with `get_change_request` and `get_change_request_diff`.
  Read historical feedback only when deliberately needed.
- Rework calls `get_change_request_reviews` and selects the triggering review by
  its `id` and `commit_id`, where supplied by the provider.
- Optional conversation inspection uses `get_change_request_discussion_comments`;
  optional combined history inspection uses `get_change_request_comments`.

The HTTP reads are `GET /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/reviews`
and `GET /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/discussion-comments`.
`GET`/`POST .../comments` and `POST .../reviews` remain available.

Forgejo and GitHub retain review IDs, available commit references, submitted
empty-body reviews, and dismissed reviews. Drafts without `submitted_at` are
omitted. State spellings remain provider-specific: Forgejo uses `REQUEST_CHANGES`
and `COMMENT`; GitHub uses `CHANGES_REQUESTED` and `COMMENTED`. Both also expose
`APPROVED` and `DISMISSED`. Results use stable chronological timestamp ordering;
the mixed feed places discussion before reviews for equal timestamps.

GitLab discussion consists of non-system merge request notes. Its reviews read
exposes **current approvals only**, not a historical formal-review stream:
`kind="review"`, `review_state="APPROVED"`, `id=0`, empty body and timestamp, and
`commit_id=null`. It cannot identify a `REQUEST_CHANGES` event. Discussion text
is never parsed to synthesize review feedback.

GitHub retains bounded pagination and fails the read if a later selected page
fails. Forgejo comments/reviews and GitLab notes currently fetch **one upstream
page**; these APIs do not promise exhaustive historical results. Future pagination
work must preserve isolation between discussion and review resources.

Limitations:

- This thing is not efficient. `commit_patch` and `rebase_branch` do a full clone every time. For small to medium repos, that's fine. For large repos, you'll feel it.
- Repos with many submodules will be painful — but then again, submodules are a vile antipattern and nobody should be using them.
- Scaling to very large monorepos is not a goal right now.

Workspace layout:

- `audit/`: audit sink interfaces and in-memory implementation
- `domain/`: canonical types, service traits, diff validation, policy engine
- `forge/`: forge adapter trait and Forgejo, GitHub, and GitLab implementations
- `git-exec/`: CLI-based git operations for the write path
- `orchestrator/`: read and write workflow composition
- `server/`: binary wiring and MCP entry point
- `transport/`: stdio MCP transport using `rmcp`

How to run:

- Copy `forge-mcp.example.toml` to `forge-mcp.toml` and configure the forges and agents.
- Start the server with `cargo run -p server -- forge-mcp.toml`.

## Global Git commit identity

Operators can make one Git identity authoritative for every forge and every
agent by configuring both fields under `[server]`:

```toml
[server]
listen = "0.0.0.0:8443"
commit_author_name = "forge-mcp"
commit_author_email = "forge-mcp@example.com"
```

These fields belong only under `[server]`, not under `[[agents]]`. For
`commit_patch`, the configured identity becomes both author and committer and
overrides request fields, including identity discovered from a transport's
local Git configuration. For `rebase_branch`, original authors are preserved
while the configured identity becomes the committer of every rewritten
commit; forge-user and agent fallback lookup is skipped.

Both fields are required together. Omitting both preserves the existing
behavior: patch commits use the request author, while rebases use the
authenticated forge user when available and otherwise fall back to the agent
identity.

## GitHub App authentication

For distinct GitHub actors, register one GitHub App per agent and install each
App on the repositories it may access. Configure that App installation under
`[agents.github_app.<forge-alias>]`. For example, Apps whose slugs are
`stintel-codex` and `stintel-qwen` act on GitHub as the separate bot accounts
`stintel-codex[bot]` and `stintel-qwen[bot]`. A pull request created by one bot
can therefore be reviewed by the other; GitHub does not allow a pull-request
author to approve its own pull request. forge-mcp rejects assigning the same
App ID to different agent IDs on one forge because that would collapse them
back to a single GitHub actor.

```toml
[[agents]]
token = "bearer-token-for-codex"
agent_id = "codex"
session_id = "default"

[agents.github_app.github]
app_id = 123456
installation_id = 78901234
private_key_path = "/run/secrets/stintel-codex.pem"

[agents.policy]
allowed_repos = ["github/org/repo"]
```

forge-mcp signs a short-lived App JWT for every configured identity, exchanges
it for an installation access token at startup, and refreshes it automatically.
The caller's managed token is used for API requests, patch pushes, and Git
smart-HTTP clone/fetch operations. Tokens are never placed in command arguments
or repository URLs.

`[forges.github_app]` is an optional fallback/system App. It is useful for
unattended operations that are not initiated by an authenticated agent, such
as webhook-driven auto-merge. A per-agent App always takes precedence. Static
`[agents.forge_identity.<alias>]` tokens remain available, but an agent cannot
configure both identity modes for the same forge.

The GitHub App needs repository access to every repository agents may use and
these repository permissions:

- **Metadata:** read
- **Contents:** read and write
- **Issues:** read and write
- **Pull requests:** read and write
- **Commit statuses:** read and write
- **Checks:** read (discovers check runs)
- **Actions:** read (resolves workflow runs, attempts, jobs, and logs)

Existing GitHub App installations must approve the added **Actions: read**
permission before failed-job resolution works for private repositories.

If webhooks are enabled, subscribe each App to **Issues**, **Issue comments**,
**Pull requests**, and **Pull request reviews**, and configure the same webhook
secret on the Apps and in forge-mcp. Webhook-driven auto-merge additionally
requires a forge-level token or `[forges.github_app]`; auto-merge must also be
enabled in the target repository.

## Issue refresh webhook hints

Authenticated issue deliveries publish one repository-scoped `issue` event.
Subscribe Forgejo to **Issues** (`issues`), GitHub Apps to **Issues** with
Issues read permission, and GitLab to **Issue events** (`Issue Hook`). Subscribe
to the normalized issue channel (or use `poll_events` with channels disabled) and call
`get_issue` for authoritative state, content, and labels before acting.

| Normalized action | Forgejo 16.0.3 | GitHub issues | GitLab Issue Hook |
| --- | --- | --- | --- |
| `opened` | `opened` | `opened` | `open` |
| `closed` | `closed` | `closed` | `close` |
| `reopened` | `reopened` | `reopened` | `reopen` |
| `edited` | `edited` (title/body) | `edited` | `update` with title/description delta |
| `labels_changed` | `label_updated`, `label_cleared` | `labeled`, `unlabeled` | `update` with label membership delta |

The existing Forgejo provider CI lane records actual Event and Event-Type headers
for reopen, separate title/body edits, and label operations. That lane supplies
versioned service evidence; deterministic fixtures alone do not establish wire
compatibility.

Dedicated label changes carry metadata such as:

```json
{"event_kind":"issue","action":"labels_changed","labels_changed":true,"forge_alias":"internal","owner":"org","repo":"repo","issue":42,"delivery_id":"delivery-1"}
```

A GitLab content edit plus label change produces a single envelope with:

```json
{"event_kind":"issue","action":"edited","labels_changed":true,"forge_alias":"internal","owner":"org","repo":"repo","issue":42,"delivery_id":"delivery-2"}
```

These examples show the relevant metadata within the normal channel envelope.
Open/close/reopen remains the primary action when a valid label delta accompanies
it. The marker defaults to false in old events and is omitted when false. New
metadata is limited to finite action strings and a boolean; no body snapshots,
before/after values, label arrays, raw changes, or fingerprints enter the envelope.

GitLab requires `object_kind=issue` for reopen/update. Equal or malformed deltas,
label reordering, snapshot-only and unrelated updates produce no update hint.
Explicit PR/MR-shaped payloads are excluded. Repository label-definition events
and invented replace/clear actions are unsupported on GitHub; bulk membership
operations arrive as individual labeled/unlabeled deliveries.

Nonempty provider delivery IDs retain their existing dedupe and SSE identities.
Without an ID, reopen/edit/label-bearing hints use an internal SHA-256 payload
fingerprint: identical bytes coalesce within the existing dedupe TTL, while
distinct no-ID label bodies now survive. Different serialization can escape this
best-effort dedupe. Ordinary opened/closed fallback keys remain unchanged.
Authorized live/replay delivery and periodic polling remain necessary.

Reopened/edited hints do not recover tasks, invalidate plans automatically, or
authorize workflow mutations. No workflow trigger labels are introduced.


## Change request webhook hints

Subscribe Forgejo to pull request events (including closure), GitHub Apps to
**Pull requests**, and GitLab to **Merge request events**. Configure the shared
secret/token in the provider and forge-mcp; registration is not changed
automatically.

| Provider delivery | Published action |
| --- | --- |
| Forgejo/GitHub `closed`, `pull_request.merged: false` | `closed` |
| Forgejo/GitHub `closed`, `pull_request.merged: true` | `merged` |
| GitLab `close` with state `closed` | `closed` |
| GitLab `merge` with state `merged` | `merged` |

These use the existing `change_request` envelope: both `kind` and
`meta.event_kind` remain `change_request`. Repository identity and PR number/MR
`iid` identify the target. Available source-head SHA is retained; terminal
`meta.head_sha` is omitted when unavailable, never replaced by a merge or target
commit. Terminal deliveries only publish hints, even with webhook auto-merge
enabled; they do not schedule, cancel, or mutate consumer workflows.

Closure requires explicit boolean merge evidence on Forgejo/GitHub, and
GitLab terminal actions require matching state. Ambiguous or malformed payloads
are rejected. Guessed standalone `merge`/`merged` actions on Forgejo/GitHub,
state-only updates, and branch deletion do not create terminal hints.
Existing opening, reopening and head-change actions remain unchanged.

Delivery deduplication is in memory with a five-minute TTL, scoped by forge
alias and delivery ID. Without a delivery ID, the existing repository, index,
head and action fallback key is used. Replay retains the latest 32 events and
uses the same repository authorization as live delivery. These are best-effort
hints: consumers must refetch authoritative state. Polling remains the fallback
for missed, duplicate, out-of-order, or unsupported deliveries and restarts.

The deterministic provider fixtures follow
[GitHub's closure discriminator](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#running-your-pull_request-workflow-when-a-pull-request-merges)
and [GitLab's MR event contract](https://docs.gitlab.com/user/project/integrations/webhook_events/#merge-request-events).
Forgejo provenance is versioned source, not a live delivery observation:
[v15.0.0 notifier](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/services/webhook/notifier.go)
emits `HookIssueClosed` on merge;
[PR conversion](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/services/convert/pull.go)
copies `pr.HasMerged`, and the
[API PR type](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/modules/structs/pull.go)
serializes that boolean as `merged`.

### PR/MR label-change hints

Consumers select `meta.event_kind == "change_request" && meta.labels_changed == true`.
Do **not** require `meta.action == "labels_changed"`: GitLab retains its existing
lifecycle action, including `update` → `synchronize`, when a delivery also changes
labels or code. Open, reopen, close and merge deliveries can carry the marker too.

The additive boolean defaults to false when reading old envelopes and is omitted
when false. It survives SSE, replay, `poll_events` (including channels disabled)
and channel notifications. Channels retain their existing `forge_alias` → `forge`
name mapping. These example **metadata** objects show a dedicated delivery and a
combined GitLab update:

```json
{"event_kind":"change_request","action":"labels_changed","labels_changed":true,"change_request":42,"issue":null,"issue_comment":null,"forge_alias":"forgejo","owner":"org","repo":"repo","delivery_id":"label-1","head_sha":null,"review_state":null}
```

```json
{"event_kind":"change_request","action":"synchronize","labels_changed":true,"change_request":42,"issue":null,"issue_comment":null,"forge_alias":"gitlab","owner":"org/subgroup","repo":"repo","delivery_id":"label-2","head_sha":"source-head","review_state":null}
```

| Provider | Subscription and HTTP headers | Supported label signal |
| --- | --- | --- |
| Forgejo **16.0.3** | Select `pull_request_label`; `X-Forgejo-Event: pull_request`, `X-Forgejo-Event-Type: pull_request_label`. Existing `X-Gitea-*` aliases are accepted. | `label_updated` for add/remove/replace; `label_cleared` for clear. Both normalize to `labels_changed`. |
| Forgejo/Gitea adapter compatibility | `pull_request` dispatch also accepts those two actions without Event-Type; a dedicated `pull_request_label` Event value is accepted only for those actions. | This compatibility input is not a claim that Forgejo 16.0.3 emits a dedicated Event value. Other provider versions/actions are unverified. |
| GitHub | **Pull requests**, `X-GitHub-Event: pull_request`; Apps need Pull requests read permission. | `labeled` / `unlabeled` → `labels_changed`. Bulk operations are individual membership deliveries, not invented replace/clear actions. Repository `label` definition events are excluded. |
| GitLab | **Merge request events**, `X-Gitlab-Event: Merge Request Hook`. | Different `changes.labels.previous/current` sets of label IDs/titles add the marker without replacing the lifecycle action. Current-label snapshots alone do not. Reordering and cosmetic fields are ignored. Absent/null/malformed deltas preserve the original lifecycle event; malformed projections produce a fixed diagnostic. |

Forgejo evidence is pinned to [the v16.0.3 notifier](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/webhook/notifier.go)
(`IssueChangeLabels`, `IssueClearLabels`), [event grouping](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/modules/webhook/type.go),
[HTTP header construction](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/webhook/shared/payloader.go)
and [payload types](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/modules/structs/hook.go).
The ignored `forgejo_issue_label_webhooks` test in the existing Woodpecker
`forgejo-integration` lane verifies real PR add/remove/multiple/replace/clear
mutations through authenticated delivery and MCP polling, including actual Event
and Event-Type headers, distinct delivery IDs and genuine issue-label identity.
CI owns the provider process and credentials; no local service is required.
The [GitHub contract](https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request)
and [GitLab changes contract](https://docs.gitlab.com/user/project/integrations/webhook_events/#merge-request-events)
provide the other deterministic fixture provenance.

Label hints require a positive PR number/MR iid and nonempty target repository
owner/name. Conflicting supplied top-level and nested PR numbers are rejected.
Forgejo accepts either PR number location; GitHub requires its top-level number.
GitLab label deltas also require `object_kind: merge_request`.
Issue-shaped bodies are never converted into PR hints. Explicit PR discriminators
on issue label webhooks suppress source-issue hints. Source heads are retained
when available; label hints need no head/ref or merge discriminator, and missing
heads serialize as null. Target and merge commits never fill a missing source head.
Existing lifecycle and terminal state validation remains in place.

No label lists, names, deltas or provider bodies reach the output. The extra
label-specific output stays constant-size for arbitrarily large label snapshots;
existing webhook body limits remain unchanged. Any label can trigger the hint:
the boolean says only **refetch this PR/MR**, not that labels remain present or
that review is eligible. Cockpit must refetch authoritative PR state and labels
before any workflow mutation. Removal does not authorize review cancellation.
Workflow selection, tasks, claims, re-review and polling changes belong to Cockpit;
these hints do not trigger approvals or auto-merge.

Delivery-ID dedupe remains forge alias + delivery ID (including the existing
GitLab event UUID selection). Without an ID, label-bearing events use a namespaced
repository/PR/action key plus SHA-256 of the original authenticated bytes. Distinct
mutations at an unchanged head survive; identical bodies inside the five-minute
TTL coalesce as best-effort retries. Different serialization can escape dedupe,
and identical separate operations can coalesce. Non-label fallback keys are
unchanged. Delivery may be delayed, missing or out of order; retain periodic
polling and refetch as the fallback.

## CI webhook hints

Authenticated GitHub and GitLab CI notifications publish one repository and
exact-commit wake hint through SSE (`event: ci`), channel notifications and
`poll_events`. No PR/MR association is required or inferred. For example:

```json
{
  "kind": "ci",
  "content": "ci changed at aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "meta": {
    "action": "changed",
    "event_kind": "ci",
    "forge_alias": "github",
    "owner": "org",
    "repo": "repo",
    "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "delivery_id": "delivery-123",
    "change_request": null,
    "issue": null,
    "issue_comment": null,
    "review_state": null,
    "provider_action": "completed",
    "ci": {
      "source": "check_run",
      "provider_event": "check_run",
      "provider_delivery_id": "delivery-123",
      "delivery_id_source": "X-GitHub-Delivery",
      "id": 123,
      "parent_id": 100,
      "name": "unit tests",
      "status": "completed",
      "conclusion": "success"
    }
  }
}
```

`ci.source` is `commit_status`, `check_run`, `check_suite`, `pipeline`, or
`job`. Native `id` and `parent_id` are optional positive integers; parent means
check-suite ID for a run and pipeline ID for a job. Optional `name`, `context`,
`status`, `conclusion`, `started_at`, `completed_at` and `updated_at` preserve
source values. Absent/null lifecycle values stay absent; unknown values remain
opaque. `provider_action` records a native check action separately from status.
Status, pipeline and job notifications have no synthesized provider action.
`provider_event` records the native event header. `provider_event_id` preserves
GitLab's event UUID; `provider_delivery_id` preserves its webhook UUID (or
GitHub's delivery header), even when a different message ID is selected.

| Provider | Subscription and event header | Identity and supported lifecycle |
| --- | --- | --- |
| GitHub | **Statuses**, `X-GitHub-Event: status` | Top-level `sha`, `id`, `context`, `state` |
| GitHub | **Check runs**, `X-GitHub-Event: check_run` | Run `head_sha`; actions `created`, `completed`, `rerequested`, `requested_action` |
| GitHub | **Check suites**, `X-GitHub-Event: check_suite` | Suite `head_sha`; actions `completed`, `requested`, `rerequested` |
| GitLab | **Pipeline events**, `X-Gitlab-Event: Pipeline Hook` | `object_kind=pipeline`; `object_attributes.sha/id/status` |
| GitLab | **Job events**, `X-Gitlab-Event: Job Hook` | `object_kind=build`; top-level `sha/build_id/build_status`, optional `pipeline_id` |
| Forgejo v16.0.3 | Generic status/check ingress unsupported | Keep polling external commit statuses; native Actions completion notifications are separate and unnormalized |

See the [GitHub event contract](https://docs.github.com/en/webhooks/webhook-events-and-payloads#check_run)
(and its `check_suite`/`status` sections). Apps need Commit statuses read access
for statuses and Checks read access for the read-level check subset. Receiving
`requested`/`rerequested`/`requested_action` notifications can require Checks
write access. Repository and organization hooks receive only run `created`/
`completed` and suite `completed` actions; Apps can receive the other actions
with the required permissions. These subscriptions do not promise every intermediate transition. `in_progress`
is a payload status, never an invented action. Existing App permissions,
credentials and webhook registration are unchanged.

GitLab requires authoritative `project.path_with_namespace`, split at the last
slash to retain nested groups. Older jobs without that path are acknowledged as
unsupported; display names and clone URLs cannot supply authorization identity.
Present malformed paths, conflicting project IDs or conflicting commit SHAs
are rejected. Job `commit.id` is a pipeline ID and never supplies the commit SHA.
MR and `source_pipeline` coordinates do not replace the event project.
See [GitLab pipeline and job payloads](https://docs.gitlab.com/user/project/integrations/webhook_events/#pipeline-events).
Original-byte signature verification and GitLab secret-token authentication
remain unchanged. Invalid authentication returns 401, malformed supported
payloads 400, and supported or ignored authenticated deliveries 202.

The new projection limits UTF-8 bytes: identifiers/headers 256, repository path
1024, names/context 1024, lifecycle/action tokens 128, timestamps 64, and the
serialized normalized envelope 16 KiB. Oversized retained fields are rejected,
not truncated. Commit IDs must be nonzero full 40- or 64-digit hexadecimal
object IDs, copied exactly from the CI source. Repository components must be
nonempty, without dot, empty or control components. Typed subset parsing omits
logs, arrays, annotations, variables, users, URLs and other raw payload data.
The router body-size limit remains in force. Fingerprints never serialize.

GitHub uses `X-GitHub-Delivery`. New GitLab CI hints select the first nonempty
`webhook-id`, `Idempotency-Key`, then `X-Gitlab-Webhook-UUID`, recorded in
`delivery_id_source`. GitLab event UUIDs can be shared by recursive events and
are not delivery IDs; see [delivery headers](https://docs.gitlab.com/user/project/integrations/webhooks/#delivery-headers).
Existing MR/issue/note handling is unchanged. Dedupe retains forge plus delivery
ID, with best-effort legacy webhook-UUID retries. Without an ID, `delivery_id`
stays empty, SSE uses its synthetic transport ID, and a namespaced key includes
repository, source, exact SHA, native event/action and verified-body SHA-256.
Byte-identical retries collapse; changed bodies and other SHAs survive.
Different encodings and genuinely repeated identical no-ID actions are
ambiguous. The five-minute in-memory dedupe, 32-event replay and bounded
subscriber channels provide neither persistence, ordering nor lossless delivery.
Live delivery and replay apply the same repository authorization.

A successful job, suite or pipeline is only a source-scoped hint. Consumers
must resolve their repository/exact-SHA bindings, refetch authoritative forge
checks and revalidate the current binding/head before dispatch, failure handling
or merge-readiness changes. Old-SHA and out-of-order hints remain historical.
Periodic polling is mandatory. CI hints only publish; they never schedule,
cancel or modify auto-merge, regardless of `webhook.auto_merge`.
Upgrade the shim to recognize `ci`; older shims ignore the new kind. Polling
works with channels disabled. Channel metadata has identical semantics, with
`forge_alias` renamed to `forge` and no outer `kind`. Old envelopes omit `ci`.

Forgejo capability evidence is source-verified at **v16.0.3**, matching the
pinned integration image, not a claim about a running deployment:
[webhook types](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/modules/webhook/type.go)
have no generic status/check family. The
[status API](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/routers/api/v1/repo/status.go)
calls [CreateCommitStatus](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/repository/commitstatus/commitstatus.go),
which updates status/summary data, caches and native scheduled-merge checking
without publishing a commit-status webhook. The
[Actions notifier](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/webhook/notifier.go)
does expose `action_run_success`, `action_run_failure` and `action_run_recover`.
Those terminal native Actions events do not cover external statuses or a full
pending/running lifecycle and remain ignored by this adapter. Signed negative
fixtures prove that adapter boundary only. Native Actions normalization or a
separate CI connector is follow-up scope; no direct Woodpecker ingress or new
CI credentials are introduced. Dedicated Woodpecker provider lanes own live
service-backed proof; deterministic fixtures do not claim live delivery.

## Review webhook hints

Review submissions, edits and dismissals share `kind`, SSE event name and
`meta.event_kind = "pull_request_review"`. The normalized `meta.action` is
`submitted`, `edited` or `dismissed`; `meta.provider_action` retains the
provider's original action independently. No second event stream is required.
Subscribe to `GET /api/v1/agent/events` with an authorized agent token, or use
the shim's `poll_events` (also available with channels disabled). Channel
notifications carry the same optional identity fields and use `forge` instead
of `forge_alias`.

| Provider and provenance | Webhook subscription / header | Supported review actions | Identity and commit availability |
| --- | --- | --- | --- |
| GitHub, documented webhook contract | **Pull request reviews**, `X-GitHub-Event: pull_request_review`; Apps need Pull requests read permission | `submitted`, `edited`, `dismissed` | Formal `review.id`; `review.commit_id` when supplied. Edits/dismissals require positive integer review ID and PR number, and nonempty repository owner/name. |
| Forgejo **v15.0.0**, source inventory below | **Pull request reviewed** verdict subscriptions; `X-Forgejo-Event: pull_request_approved`, `pull_request_rejected`, `pull_request_comment` | `reviewed` → `submitted`; existing `submitted` and `pull_request_review` header compatibility retained | v15 `ReviewPayload` has only type/content, no review ID or reviewed commit. Existing submitted payloads with a positive formal review ID expose it; ID-less/zero-ID payloads omit `meta.review_id`. No formal lifecycle mapping. |
| GitLab, documented MR/note contract | **Comments**, `X-Gitlab-Event: Note Hook` for legacy MR notes | Existing `submitted`/`comment` notification retained, including note updates; never normalized as formal `edited` or `dismissed` | Note IDs and MR `last_commit` are not formal review identity. New `review_id` and `reviewed_commit_id` stay absent. MR approval/unapproval and reviewer-state updates do not establish formal review edit/dismiss equivalence. |

GitHub's [review webhook contract](https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request_review)
distinguishes formal reviews from inline review comments and ordinary issue
comments. GitLab's [MR and note contracts](https://docs.gitlab.com/user/project/integrations/webhook_events/)
do not demonstrate a stable formal-review mapping for this feature.

The Forgejo inventory is source-verified at **v15.0.0**, not a claim about
unobserved deployments or live-delivery testing:

- [Review services](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/services/pull/review.go)
  call `PullReviewDismiss` for explicit and stale-approval dismissal. The
  [webhook notifier](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/services/webhook/notifier.go)
  inherits the [no-op implementation](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/services/notify/null.go)
  and does not override it: no dismissal webhook is emitted by that notifier.
- [Comment updates](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/services/issue/comments.go)
  notify `UpdateComment` for published review text. The webhook notifier emits
  `IssueCommentPayload` with `action: edited`; the
  [header mapping](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/modules/webhook/type.go)
  maps this to `issue_comment`. Its
  [Comment type](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/modules/structs/issue_comment.go)
  and [conversion](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/services/convert/issue_comment.go)
  expose a comment ID, not a formal review ID or reviewed commit. The separate
  timeline comment type is not the webhook payload.
- Submitted verdict payloads use `action: reviewed` and the
  [ReviewPayload type](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.0/modules/structs/hook.go).
  Guessing GitHub edit/dismiss actions or using comment IDs would invent
  identity; these unsupported payload families remain unnormalized.

`reviewed_commit_id` is the authoritative review commit field. It is never
filled from a PR head, MR last commit, merge commit or target commit. For new
lifecycle actions, missing/null/empty review commits leave both this field and
`head_sha` absent/null even when the live PR head is available. Present malformed
commit types are rejected. Historical submitted `head_sha` retains its
provider-dependent meaning: GitHub review commit, Forgejo PR head, GitLab MR
last commit. Do not use that historical field as proof of formal review binding.

Lifecycle and verdict are independent. Edited reviews keep an explicitly
recognized verdict (`approved`, `request_changes` or `comment`) or null;
dismissed reviews always carry null. Missing display text, verdict or commit
does not prevent an identity-valid lifecycle hint. Unknown/pending submissions
remain ignored. After signature verification, GitHub and Forgejo review
payloads with an unsupported action are ignored (HTTP 202) even if other
fields do not match a supported review schema. Invalid JSON or malformed
supported-action payloads return HTTP 400; invalid signatures still return
HTTP 401. An example identity-only dismissal envelope:

```json
{
  "kind": "pull_request_review",
  "content": "pull_request_review dismissed on github/org/repo#42",
  "meta": {
    "action": "dismissed",
    "provider_action": "dismissed",
    "review_id": 71,
    "event_kind": "pull_request_review",
    "forge_alias": "github",
    "owner": "org",
    "repo": "repo",
    "change_request": 42,
    "delivery_id": "review-dismissal-delivery",
    "head_sha": null,
    "review_state": null,
    "issue": null,
    "issue_comment": null
  }
}
```

New optional fields are omitted when unknown and old envelopes still
deserialize. Delivery-ID deduplication remains scoped to forge alias. Without
a delivery ID, submissions retain their existing fallback; edits/dismissals
use repository/PR/review identity, action and SHA-256 of the verified body.
The fingerprint stays internal. This fallback is best effort: differently
encoded retries can produce extra hints, and byte-identical no-ID actions
within the five-minute TTL cannot be distinguished from retries.

Events can be missed, duplicated or delivered out of order. Consumers must
refetch current formal reviews before invalidating approval/blocker evidence
or mutating workflow state; periodic polling remains the fallback. Edit and
dismiss hints neither schedule nor cancel auto-merge, add workflow-trigger
labels, nor initiate rework/re-review. Cockpit's submitted-only decoder needs
a separate consumer adjustment. Formal review/discussion read separation
(#137) and trade PR #31's marker-comment selection are outside this feature.

Signed/token-verified deterministic fixtures cover normalization, HTTP
publication, authorization/replay, deduplication and transport metadata.
Provider processes and any live-delivery proof remain owned by dedicated CI.

## Auto-merge scheduling

Enqueued submitted approval webhooks schedule auto-merge by default for
compatibility. Operators
can disable only that scheduling side effect while continuing to verify,
normalize, and deliver webhook events:

```toml
[forges.webhook]
secret = "webhook-secret"
auto_merge = false
```

Webhook-triggered scheduling is an unattended system action and therefore uses
the forge-level token or system GitHub App. Authenticated HTTP and MCP callers
instead retain their resolved per-forge identity (including a managed GitHub
App), so the upstream scheduling action is attributed to the caller.

The `schedule_auto_merge` merge style is optional. An explicit value must use a
canonical name: `merge`, `rebase`, `rebase-merge`, `squash`, or
`fast-forward-only`. When omitted, forge-mcp uses the repository default if it
is allowed, then prefers `rebase`, `squash`, and `merge` in that order, and
finally uses the first allowed canonical style. The expected full head SHA
remains required.

For GitHub.com, `base_url = "https://github.com"` automatically selects
`https://api.github.com`. For GitHub Enterprise Server, forge-mcp derives
`<base_url>/api/v3`; set `api_url` explicitly for a nonstandard API endpoint.

Real-Forgejo tests use an all-or-nothing disposable-provider contract:

```text
FORGEJO_TEST_BASE_URL=http://localhost:3000 \
FORGEJO_TEST_USERNAME=forge-mcp-ci \
FORGEJO_TEST_PASSWORD=disposable-password \
cargo test -p forge --test forgejo_ci_smoke -- --ignored --nocapture

FORGEJO_TEST_BASE_URL=http://localhost:3000 \
FORGEJO_TEST_USERNAME=forge-mcp-ci \
FORGEJO_TEST_PASSWORD=disposable-password \
cargo test -p forge --test forgejo_issue_dependencies -- --ignored --nocapture

FORGEJO_TEST_BASE_URL=http://localhost:3000 \
FORGEJO_TEST_USERNAME=forge-mcp-ci \
FORGEJO_TEST_PASSWORD=disposable-password \
FORGEJO_TEST_WEBHOOK_CALLBACK_BASE_URL=http://host-reachable-from-forgejo:38080 \
FORGEJO_TEST_WEBHOOK_LISTEN_ADDR=0.0.0.0:38080 \
cargo test -p server --test forgejo_issue_label_webhooks -- --ignored --nocapture
```

Ordinary local test runs intentionally leave all provider tests ignored.
Missing local Forgejo access or credentials is expected and is not a blocker.
Tests consume the configured service but never start Forgejo or a container
runtime themselves. The label-webhook test additionally needs a listener address
and a callback base URL that the CI-owned Forgejo service can route back to; the
ordinary local Rust gates do not require either value.

Woodpecker is the service-backed integration authority. The separate
`checks` workflow runs the normal Rust gates and lints both workflow files with
Woodpecker CLI 2.8.3. After it succeeds, `forgejo-integration` starts the pinned
`codeberg.org/forgejo/forgejo:16.0.3-rootless` image as a detached `forgejo`
step. Later steps reach it at `http://forgejo:3000`. The fixture uses bounded
readiness polling, authenticates the throwaway user, creates a short-lived API
token, and reports redacted, bounded diagnostics. Repositories and tokens are
logically cleaned up, while the user, SQLite database, repositories, and all
other state disappear with the workflow container. No production credential,
persistent volume, privileged mode, or container socket is used.

Issues & PRs disabled. Development happens on an internal Forgejo instance.
