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
**Pull requests**, **Pull request reviews**, **Pull request review comments**,
and **Pull request review threads**, and configure the same webhook
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
MR hints carrying base/draft deltas also use this selection, including compound
synchronize and lifecycle hints. MR events without these deltas and issue/note
handling retain their legacy event-UUID identity. Dedupe retains forge plus
selected delivery ID, with best-effort legacy webhook-UUID retries. Without an ID, `delivery_id`
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

## Inline review comment and thread hints

Inline feedback uses distinct `kind`, SSE event name and `meta.event_kind`:
`pull_request_review_comment` (`created`, `edited`, `deleted`) and
`pull_request_review_thread` (`resolved`, `unresolved`). Unresolved means a
conversation was reopened, not the PR. The original action remains in
`provider_action`. Both families carry repository/PR identity and delivery ID
through authorized SSE, replay, MCP channels and `poll_events`.

| Provider / evidence | Subscription | Enabled mapping | Gaps |
| --- | --- | --- | --- |
| GitHub documented contract and Octokit schemas, read 2026-09-07 | **Pull request review comments** and **Pull request review threads**; Apps need **Pull requests: read** | Comment created/edited/deleted; thread resolved/unresolved | Absent optional metadata stays absent; thread comments may be empty |
| GitLab **v18.3.0-ee** source | **Comments**, `Note Hook` | MR notes with explicit `object_attributes.type: DiffNote`: create → created, update → edited | No delete or individual thread transition mapping; general/ambiguous and LegacyDiffNote notes keep the legacy path |
| Forgejo **v16.0.3** source (CI-pinned) | Existing review/general-comment subscriptions | No distinct inline mapping established | Code-comment notifier is a no-op; edit/delete webhook payloads lack an inline discriminator; no resolution event in notifier interface |

The [versioned inventory beside the deterministic fixtures](server/tests/fixtures/inline-review-provenance.md)
records emission paths, payload conversion and links. This is source evidence,
not live-provider delivery proof. Only GitLab's proven `DiffNote` create/update
payloads migrate from the legacy `pull_request_review` stream; each delivery
still emits one event. An MR aggregate `blocking_discussions_resolved` change,
approval, arbitrary note update or Forgejo verdict-header lookalike never
becomes an individual thread transition.

`meta.inline_review` contains an optional opaque `thread_id`, optional changed
`comment`, and supplied thread `comments`. Each comment independently retains
its actual `comment_id`, `node_id`, `review_id`, `in_reply_to_id`, current and
original commit/path/line metadata, multiline sides, and legacy diff positions
when supplied. A reply ID is not a thread ID; a diff position is not a file line.
GitLab retains native old/new paths, lines, commit coordinates and multiline
endpoints under `gitlab_position` / `gitlab_original_position`; image pixel
coordinates are omitted. Missing/null/empty strings are absent. There is no
representative first comment or synthesized ID. PR `head_sha` is independent of
comment commits and is null unless explicitly supplied by GitHub; GitLab MR
last_commit is not used. Formal `review_state`, `review_id` and
`reviewed_commit_id` remain unset at the common metadata level.

Projections omit bodies, diff hunks and raw changes. Parser limits are UTF-8
bytes: 256 for IDs/commits/deliveries/alias, 4096 per path, 1024 combined repository
coordinates and 1024 thread comments; GitLab position types use 64 bytes.
The existing HTTP body limit also applies. Recognized malformed identity or
optional field types return HTTP 400 after verification; unknown actions are
ignored. Existing HMAC/token verification and repository policy still apply.

These are best-effort refresh hints. Refetch authoritative feedback and
unresolved-thread state before mutations, retaining periodic polling for missed
hints or unsupported providers. The inline read API is not expanded here.
Resolving a thread does not approve a PR, dismiss a review or remove an
independent REQUEST_CHANGES verdict. These events never schedule/cancel
webhook auto-merge or write reviews or labels.

Nonempty delivery IDs keep existing forge-alias retry deduplication. Without
one, a length-prefixed repository/PR/kind/resource/action key includes SHA-256
of the verified body, which is never serialized. Byte-identical repeated
same-action bodies inside the five-minute TTL are indistinguishable from
retries; changed bodies/timestamps survive, and differently encoded retries
may also survive. Polling remains necessary.

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
| GitLab, documented MR/note contract | **Comments**, `X-Gitlab-Event: Note Hook` for legacy MR notes | Ordinary/ambiguous notes retain `submitted`/`comment`, including updates; explicit MR `DiffNote` create/update now use the inline family below; never normalized as formal `edited` or `dismissed` | Note IDs and MR `last_commit` are not formal review identity. New `review_id` and `reviewed_commit_id` stay absent. MR approval/unapproval and reviewer-state updates do not establish formal review edit/dismiss equivalence. |

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

## Confirmed auto-merge cancellation

`DELETE /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}/automerge`
and MCP `cancel_auto_merge(forge, owner, repo, index)` cancel a scheduled merge
on Forgejo. DELETE has no body, head SHA, merge style, or branch-deletion flag.
Gateway bearer authentication and repository authorization are required.
The caller's forge credential takes precedence over the configured default;
only callers without an override use that default. Rejected caller credentials
are never retried with the default. Read access alone need not grant cancellation
rights. GitHub and GitLab currently return unsupported without provider requests.

| Condition | Gateway response |
| --- | --- |
| Exactly upstream 204 | 200 with JSON `{}` |
| Missing/invalid gateway bearer, or upstream 401 | 401 |
| Repository authorization denial, or upstream 403 | 403 |
| Authorized unknown forge alias | 400 |
| Unsupported backend | 501 |
| Audit failure before the provider write | 500 |
| Any upstream 404, unexpected status (including 200/202/501), redirect, timeout or transport failure | 502 |

Only upstream 204 confirms cancellation. Forgejo 16.0.3 returns the same generic
404 for an absent schedule and a missing PR; every such response remains 502,
even after a successful same-credential PR read. Positive absence proof and
successful never-scheduled/repeated cancellation are deferred. A successful
DELETE whose response is lost can leave subsequent retries conservatively blocked
indefinitely. No receipt or cache converts those retries to success.

Cancellation audits the attempt before one bodyless provider DELETE. It performs
no PR/head/settings reads, scheduling, status updates, branch deletion, or other
PR mutations. Closed/merged state does not prove absence. Cancellation cannot undo
an already completed merge or prevent an independently authorized future schedule.
It is PR-scoped and does not promise head-specific cancellation or uniform success
on repetition.

Cockpit's revocation barrier remains intact: 200 permits the cancellation stage
to proceed to its existing fresh-PR and binding/task-state checks; 401/403 retains
an authorization diagnostic; 400/500/501/502 retains upstream uncertainty and
`RevokePending`. This route removes the missing-method 405 but does not guarantee
recovery of memory-server PR #65. It does not provide authoritative schedule
status, serialized scheduling ownership, or every F2 remote-disarm guarantee.
Provider-backed cancellation tests are ignored locally and run in the existing
Forgejo CI lane; source findings and mock tests are not executed provider proof.

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

### Reword commit messages

Use `rebase_branch` with an exclusive list of `reword` operations to change
messages while preserving every commit's tree, patch order and author metadata:

```json
{
  "forge": "adlevio",
  "owner": "tokarix",
  "repo": "example",
  "base_branch": "main",
  "branch": "agent/codex/example",
  "operations": [
    {"type": "reword", "commit": "2222222222222222222222222222222222222222", "message": "Explain the change\n\nInclude the reason for this change.\n"}
  ]
}
```

For REST, POST the same body without `forge`, `owner` and `repo` to
`/api/v1/repos/{forge}/{owner}/{repo}/rebase`. The IDs below are illustrative:

```json
{
  "branch": "agent/codex/example",
  "commit_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "old_commit_sha": "3333333333333333333333333333333333333333",
  "commit_mapping": [
    {"old_commit_sha": "1111111111111111111111111111111111111111", "new_commit_sha": "1111111111111111111111111111111111111111"},
    {"old_commit_sha": "2222222222222222222222222222222222222222", "new_commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    {"old_commit_sha": "3333333333333333333333333333333333333333", "new_commit_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  ]
}
```

Targets must be distinct exact full object IDs in `merge-base..original-head`.
Abbreviations, refs, revision expressions, the merge base and out-of-range IDs
are rejected. Both SHA-1 and SHA-256 repositories are supported. Request order
selects replacement messages and never reorders commits. Do not mix reword with
`fixup`, `drop` or `rebase_onto`; merges and unsupported commit metadata are
rejected before replay. Empty commits remain in the series.

Each submitted message must be nonblank, contain no NUL, and be at most 65,536
UTF-8 bytes. The limit applies before normalization: supplied trailing newlines
are retained; exactly one LF is appended if the message has none. All other
whitespace, multiline bodies, trailers, comment-looking lines and shell
characters are data, preserved without trimming or shell evaluation.

The complete mapping follows original commit order, including unchanged entries
before the first target. Targets and descendants may receive new IDs. Their
original signatures are removed because the signed payload changes; no new
signing policy is introduced. Author names, emails, dates and timezones remain
unchanged. Recreated commits use the existing global committer configuration
or legacy authenticated-user/agent fallback, with current committer dates.
Legacy rebase modes omit `old_commit_sha` and `commit_mapping`.

Repository authorization, the nonempty agent branch prefix, provider branch
protections and the MCP read-only guard still apply. The gateway verifies the
complete series and final tree, records an intended transition audit without
replacement messages, then publishes once using the original head as a lease.
Validation, replay, verification or audit failures prevent publication. A lease
failure preserves the concurrent remote tip. The branch and existing PR remain
attached; success and mapping are returned only after publication succeeds.

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

FORGEJO_TEST_BASE_URL=http://forgejo:3000 \
FORGEJO_TEST_USERNAME=forge-mcp-ci \
FORGEJO_TEST_PASSWORD=disposable-password \
CARGO_TARGET_DIR=/tmp/target \
cargo test -p server --test forgejo_reword -- --ignored --nocapture

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
The reword test runs in the dedicated CI lane, which installs Git and supplies
the disposable service and credentials. It checks PR continuity, ordered trees,
messages and author metadata, and protected-branch push rejection. Explicitly
running an ignored provider test with missing configuration or an unreachable
service fails; agents do not start a local provider to run it.

Woodpecker is the service-backed integration authority. The separate
`checks` workflow runs the normal Rust gates and lints all workflow files with
Woodpecker CLI 2.8.3. After it succeeds, `forgejo-integration` starts the pinned
`codeberg.org/forgejo/forgejo:16.0.3-rootless` image as a detached `forgejo`
step. This workflow places the checkout directly at the shared `/woodpecker`
volume root, avoiding the nested default checkout path that failed with
`Permission denied` in the rootless service's generated startup wrapper.
A foreground `forgejo-preflight` step uses the same rootless image to check
checkout access, script executability, `/tmp` writability, and the Forgejo binary
before the detached service starts. A workspace failure therefore fails a normal
step instead of being hidden behind the integration readiness timeout. It does
not run Forgejo as root or change host permissions.
Later steps reach the service at `http://forgejo:3000`. The fixture uses bounded
readiness polling, authenticates the throwaway user, creates a short-lived API
token, and reports redacted, bounded diagnostics. Repositories and tokens are
logically cleaned up, while the user, SQLite database, repositories, and all
other state disappear with the workflow container. No production credential,
persistent volume, privileged mode, or container socket is used.

The independent `cargo-audit` workflow runs only for the named `cargo-audit`
cron on `main`. It installs cargo-audit 0.22.2 with its locked tool dependencies
and scans the committed `Cargo.lock` against freshly fetched RustSec data.
It does not update application dependencies, build the application, or start
provider services, and is outside the required PR checks.

After merge, an operator with repository push access should open the repository
in Woodpecker, go to **Settings → Cron**, and create a cron named `cargo-audit`
with schedule `@daily` and branch `main` (see the
[Woodpecker cron documentation](https://woodpecker-ci.org/docs/usage/cron)).
Schedule activation and the first real scheduled run are operator follow-up.
Inspect the resulting cron pipeline in the repository's Woodpecker pipeline
list, then open the `cargo-audit` workflow and step logs. A completed scan with
vulnerabilities prints advisory details and a vulnerability count and fails;
scanner or advisory-fetch errors print their native error diagnostics and also
fail. A failed fetch is not a clean scan. Successful scans end with
`Cargo audit completed successfully.` Existing PR CI must pass before merge.

Issues & PRs disabled. Development happens on an internal Forgejo instance.


### Branch push and PR base/draft refresh hints

`branch_push` has action `pushed` and repository-scoped `meta.branch_push`:

```json
{
  "ref": "refs/heads/release/next",
  "before_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "after_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "deleted": false,
  "provider_event": "push"
}
```

`forced` and `deleted` are optional booleans; omission means unknown. Pushes
have no PR, issue, comment or source-head identity (those metadata values are
null). Full 40/64-digit hexadecimal IDs retain their original spelling; all-zero
before/after IDs signal creation/deletion and must not be treated as commits.
Tags and other ref namespaces produce no hint. Any valid branch, including an
unrelated feature branch, emits only its own hint; ingress never enumerates PRs.

PR envelopes optionally contain typed `meta.change_request_changes`, for example:

```json
{
  "base": {"previous": "main", "current": "release/next"},
  "draft": {"previous": true, "current": false}
}
```

Either delta can occur alone. `previous` is optional for explicit action signals
without an old snapshot. Branch values are provider branch names; consumers add
`refs/heads/` when comparing them to a push ref. State-only events use `updated`;
compound source changes retain `synchronize`, and supported lifecycle actions
remain unchanged. These envelopes also retain `provider_action`, simultaneous
`labels_changed`, and the actual source head when supplied. Missing source heads
on state-only hints remain null; no base or merge SHA substitutes for them.
Current snapshots alone never establish a transition.

| Provider contract | Push subscription | Base retarget | Draft transition | Push status |
| --- | --- | --- | --- | --- |
| GitHub documented webhooks | `push` | `pull_request`: `edited`, `changes.base.ref.from` | `ready_for_review` / `converted_to_draft` | Explicit deleted/forced fields |
| GitLab documented webhooks | Push events (`Push Hook`, object_kind `push`) | Merge request events: unequal `changes.target_branch` | Unequal `changes.draft` | Deleted from zero after ID; forced unknown |
| Forgejo 16.0.3 | `push` | `pull_request`: `edited`, `changes.ref.from` | Unsupported: draft is derived from configured title prefixes | Deleted from zero after ID; forced unknown |

Forgejo's Gitea header aliases accept the same source-verified payload contract;
arbitrary Gitea versions are not asserted equivalent. Title/body-only edits,
base SHA-only changes, equal deltas and unknown actions add no state metadata.
GitLab `update` with state deltas and absent/null `oldrev` is `updated`; valid
nonzero code-change `oldrev` retains `synchronize`. Unrelated legacy updates
retain their previous mapping. See [fixture provenance and exact provider
sources](server/tests/fixtures/branch-state/README.md).

For every GitLab push and base/draft-bearing MR hint, the first nonblank of
`webhook-id`, `Idempotency-Key`, `X-Gitlab-Webhook-UUID` is the delivery identity.
Header names are case insensitive; chosen values retain their bytes, bounded
at 256 bytes. `X-Gitlab-Event-UUID` is correlation only for these hints. With no
actual ID, `delivery_id` is empty even when a correlation UUID is present.
Retry-stable modern IDs win over a changing legacy webhook UUID; that last
fallback remains best effort. CI selection is unchanged. MR events without
base/draft metadata, issues and notes retain legacy identity behavior.

Nonempty delivery IDs dedupe by forge alias plus selected ID. Otherwise these
new hints use an internal authenticated-body SHA-256 with namespaced forge,
repository and resource coordinates (full ref for pushes; index and action for
PRs). Compound label/state changes take this path before label/head fallbacks.
Identical bytes collapse; distinct bodies at one head/ref survive. Equivalent
encodings and genuinely repeated identical no-ID actions remain ambiguous.
Fingerprints never appear in envelopes or log bodies. Existing five-minute
dedupe, bounded subscriber channels and 32-event replay remain in memory;
replay and live delivery apply the same repository authorization.

The new projections validate identities, branch syntax, typed deltas and
snapshot consistency, retaining at most a 16 KiB normalized envelope. Repository
paths and branch names are bounded at 1024 bytes; titles/URLs at 4096. Errors
are bounded diagnostics without payload contents. Authentication precedes
all dispatch, including ignored refs, and the existing ingress body limit stays
in force. Commit arrays and unrelated raw data never enter the hint.

Consumers coalesce hints, match repository/target bindings and refetch
authoritative PR/check/review state before acting. Keep periodic polling:
provider push limits can suppress events, and this is neither ordered nor
lossless delivery. Ingress makes no provider reads, git calls, rebase, merge,
label or scheduling requests for these hints. Auto-merge remains restricted to
newly enqueued submitted approvals. No webhook registration or CI branch-filter
change is made by this feature.

### Repository file reads

`GET /api/v1/repos/{forge}/{owner}/{repo}/contents/{path}` preserves upstream
404 as gateway 404 with the fixed explanation "repository resource unavailable
at the requested path/ref". This does not distinguish an absent path, unknown
ref, missing repository, or privacy-masked access. No existence probes or
credential retries are performed. Explicit upstream 401/403 remain 401/403;
other upstream failures, transport failures and malformed file responses return
502. Successful UTF-8 content and omitted/explicit ref behavior are unchanged.
MCP `read_repository_file` reports gateway 404 as invalid-params (-32602) and
502 as internal-error (-32603); failures never become empty successful content.

### Request diagnostics

Request spans distinguish `route` (the matched route template, or `unmatched`)
from `path` (a safe resolved path). The existing `operation` field remains a
compatibility alias for the route template. Resolved paths are diagnostic text
only and must not be used as metrics labels. Request IDs, methods, failure
statuses and structured forge/owner/repo/target fields remain available, including
on authentication failures.

Only forge, owner and repository identifiers (ASCII letters, digits, `-`, `_`,
`.`) and numeric issue/pull/dependency IDs are resolved. Identifier components
are limited to 128 bytes; empty, dot-only (`.` or `..`), encoded, control-bearing
or otherwise unsafe values become `[redacted]`. Values are never percent-decoded.
File wildcards, labels and unreviewed parameters are also `[redacted]`.
Structured repository fields use the same safe components. The complete resolved
path is limited to 1024 bytes, with `[redacted]` as the fallback for unsafe path
shapes or excessive length; unmatched requests use `unmatched`. Route/operation
fields use the existing 128-character diagnostic bound. Query strings, full URLs,
headers, credentials and bodies are never included in these fields.

For GET contents, request middleware is the sole primary failure reporter:
expected typed upstream not-found produces one INFO event; other failures
produce one WARN event. Adapter and handler warnings are suppressed only for
this operation. The event includes `error_kind`, `gateway_status`, and numeric
`upstream_status` when a response was received (including 200 for invalid file
payloads). An absent upstream status means unknown, not an inferred 404.
`credential_source="unselected"` distinguishes early failures from a selected
credential or a known lack of credentials. Successful request logging is unchanged.

Dedicated `requested_path`, `requested_ref`, `ref_source`, `path_visibility`, and
`ref_visibility` fields supplement the existing wildcard/query redaction;
`target` remains a numeric issue/PR identifier or empty. Detailed file context
is considered only after successful gateway authentication and repository
authorization. Missing ref means `ref_source="default"`; explicit `HEAD` or
`main` means `explicit`. The actual default branch is never inferred. Before
extraction/authorization, the source is `unavailable` and visibility is
`unauthorized_or_unparsed`.

Disclosure is disabled by default, including for ordinary filenames. Configure
`[[server.file_read_diagnostics.repositories]]` with exact `forge`, `owner`,
`repo`, `paths`, and `refs` approvals (see `forge-mcp.example.toml`). Each field
is independently allowlisted; there are no wildcard or caller-controlled
approvals. Operators must approve only known non-sensitive values and protect
this configuration and log access. This is not automatic detection of arbitrary
secrets. Unapproved values stay `[redacted]` with `not_approved`; invalid values
use `invalid`, known credential matches use `credential`, and an omitted ref
uses `default`. Approved values use `approved`.

Startup rejects invalid or duplicate repository entries and excessive lists:
at most 64 repositories and 128 values per field per repository. Each path/ref
must be 1–256 UTF-8 bytes and use only ASCII letters, digits, `-`, `_`, `.`, `/`.
Absolute paths, empty or dot-traversal components, controls, Unicode and percent
escapes are ineligible. Values are compared against the extractor's canonical
once-decoded text, never recursively decoded or truncated. Known configured
gateway credentials and the effective upstream credential are blocked even if
accidentally approved. Invalid or unmatched fields are entirely redacted;
no unkeyed hashes, raw URIs, provider bodies, redirects or file contents are logged.
Older configuration files require no new options.

### Draft and mergeability contract

Change-request REST and MCP list/get responses, and create/update/close responses,
include `draft`: `true` means authoritative provider draft, `false` means
explicitly ready, and `null` means unavailable, absent or unsupported metadata.
Missing fields in older JSON remain accepted. No title/body inference or GitLab
`work_in_progress` fallback is used. Wrong-type metadata fails deserialization.
Sparse list results stay sparse; the gateway does not fetch each list item.
Consumers must re-read authoritative get before readiness decisions.

`mergeability` retains `mergeable`, `not_mergeable`, `conflicting`, and `unknown`.
`has_conflicts=null` means unknown, including generic blockers; consumers must
never translate `not_mergeable` back into a conflict. `conflicting` always has
positive evidence and `has_conflicts=true`. `mergeable` is evidence, not permission
to merge or advance ownership. Draft is independent and can coexist with conflict.

| Provider evidence | Normalized mergeability / has_conflicts |
| --- | --- |
| Forgejo `mergeable=true`, draft not true | `mergeable` / `false` |
| Forgejo `mergeable=true`, draft true (contradictory pinned contract) | `unknown` / `null` |
| Forgejo `mergeable=false`, any draft state | `not_mergeable` / `null` |
| Forgejo absent/null mergeable | `unknown` / `null` |
| GitHub false + `dirty` | `conflicting` / `true` |
| GitHub true, except contradictory `dirty` | `mergeable` / `false` |
| GitHub true + `dirty`, or absent/null mergeable | `unknown` / `null` |
| GitHub other false | `not_mergeable` / `null` |
| GitLab `conflict` or explicit true without contradiction | `conflicting` / `true` |
| GitLab `mergeable`, or legacy `can_be_merged` without detailed status | `mergeable` / `false` |
| GitLab conflict + explicit false, clean + explicit true, or pending + true | `unknown` / `null` |
| GitLab generic blockers, including `draft_status` and legacy `cannot_be_merged` | `not_mergeable` / `null` unless independent positive conflict evidence |
| GitLab checking/unchecked/recheck, error, unrecognized or missing status | `unknown` / `null` absent independent positive evidence; pending computation contradicts positive evidence |

GitLab detailed status takes precedence over legacy status. Conditional explicit
false during pending, unknown or blocked states is not clean-content evidence.
GitHub draft plus clean evidence is valid. Contradictions preserve draft metadata.

Forgejo 16.0.3's false boolean conflates WIP, pending/error checking and content
conflicts. This correction intentionally disables automatic Forgejo conflict
classification from that boolean, even for known ready PRs. Surface ambiguous
non-mergeability visibly. The CI-owned `forgejo_mergeability` test retains the
ready/WIP/ready regression from closed PR #236, diagnostic commit
`408437b7b5e4363166593b491bd7759a6f1e79b4`, and verifies a genuine conflicting
single-line replacement from a common ancestor, both ready and draft. Exact
ancestry/content establish the control's conflict; raw false does not establish
checker completion. No provider processes are started by local tests.

Follow-up boundaries (not implemented here):

- F1: opt-in bounded read-only conflict proof using documented exact source/target
  identities and supported Git merge-tree capabilities, outside normal conversion.
  It needs authorized fetches, resource/process limits, identity rechecks and
  permission-partitioned commit-pair caching. Errors remain uncertainty. No clone
  per list item or real merge/rebase probe. F1 is optional for this correction.
- F2: beyond the confirmed Forgejo cancellation endpoint above, provider-aware
  auto-merge status/cancellation with proven remote disarm,
  authorization/audit, exact heads and serialized ownership generations. Assess
  GitLab scheduling's currently ignored head argument in that separate scope.
- C1 (Cockpit): known drafts defer new owned review, conflict repair and scheduling;
  retain active workers and completion evidence, terminal/cancellation/integrity
  and needs-input reconciliation. ReviewOnly may review drafts without ownership.
  Unknown draft requires get reconciliation and a visible bounded hold/escalation.
  Same-head readiness must invalidate eligibility and claim each action exactly
  once across concurrent/replayed events. Worker exit with incomplete draft needs
  a visible operator state, not completion or endless automatic continuation.

Safe activation of C1's automatic merge lifecycle depends on F2: eligibility loss
must persist a revocation barrier and advance authority before new actions;
coordinate in-flight schedules and cancel late obsolete successes. Only confirmed
remote disarm clears that barrier, including across restarts or same-head readiness.
Unsupported/failed/unknown cancellation escalates visibly and blocks new authority.
Independent remote schedules and unobserved transitions remain provider race risks;
validate enforcement before activation. Reconcile a merge/close race truthfully.
Required downstream tests include active-worker preservation, ReviewOnly isolation,
all draft gates, duplicate dispatch, stale metadata, incomplete worker visibility,
late scheduling, cancellation failure/restart and terminal/provider races. Cockpit
#366 SQL repair and the broader completion protocol remain separate work.

Deploy this producer contract before consumer activation. JSON is additive, but
strict decoders need inventory and Rust constructors need the new field. Existing
Forgejo draft hints are unsupported, so polling is required; GitHub/GitLab refresh
hints only expedite authoritative reads. This correction alone does not remediate
already-armed schedules or the incomplete-worker incident.

New auto-merge schedules re-read the PR and validate the expected head, then reject
`draft=true` with `pull request is draft; auto-merge deferred` before repository
settings, success audit, provider scheduling or synthetic status writes. Explicit
REST/MCP callers receive validation failure; submitted-approval scheduling treats
this exact validation as expected deferral without `AutoMergeFailed`. Other
failures remain visible. Unknown draft retains existing gateway scheduling
behavior for compatibility and is not readiness; C1's owned policy is stricter.
This guard does not cancel already-armed remote schedules and does not eliminate
the race between reading draft state and scheduling. Those require F2/C1.
