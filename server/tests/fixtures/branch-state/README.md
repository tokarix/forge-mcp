# Branch and PR state fixture provenance

The deterministic fixtures in `../../branch_state_webhooks.rs` are small,
source-derived JSON subsets with synthetic repository identities and object
IDs. They are not captured live deliveries. Read/verified 2026-09-07. Mutation
loops exercise invalid fields, retries and combinations through real provider
authentication, HTTP ingress, EventBus and serialized envelopes. No provider
service, credentials or registration is needed locally.

## GitHub

- [Webhook reference](https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request)
  and [push reference](https://docs.github.com/en/webhooks/webhook-events-and-payloads#push).
- Exact `edited` schema verified in the official
  [API description](https://github.com/github/rest-api-description/blob/main/descriptions/api.github.com/api.github.com.json),
  `components.schemas.webhook-pull-request-edited.properties.changes.base`:
  `ref.from` is the prior branch; the schema also contains `sha.from`. Our
  SHA-only negative fixture intentionally omits the branch delta and emits no
  retarget hint.
- [Action names](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request):
  `ready_for_review` and `converted_to_draft`; subscribe to `pull_request`.
  Pushes use the `push` subscription. Explicit `deleted`/`forced` booleans are
  retained; missing booleans remain unknown.

## GitLab

- [MR changes and oldrev](https://docs.gitlab.com/user/project/integrations/webhook_events/#merge-request-action-specific-fields):
  typed target_branch/draft previous/current deltas; `oldrev` is code-change
  evidence on updates. Subscriptions are Merge request events and Push events.
- [Push shape and limits](https://docs.gitlab.com/user/project/integrations/webhook_events/#push-events).
- Deletion semantics checked against upstream
  [push data builder](https://github.com/gitlabhq/gitlabhq/blob/master/lib/gitlab/data_builder/push.rb)
  (`after: newrev`, `checkout_sha` removal case) and
  [Git constants](https://github.com/gitlabhq/gitlabhq/blob/master/lib/gitlab/git.rb)
  (`blank_ref?` accepts all-zero 40/64-digit IDs). No force flag is projected.
- [Delivery headers](https://docs.gitlab.com/user/project/integrations/webhooks/#delivery-headers):
  fixtures distinguish shared correlation UUIDs, stable modern IDs and the
  older webhook UUID. These are deterministic compatibility tests across header
  generations, not a claim of observed deliveries on a particular GitLab release.

## Forgejo 16.0.3

The dedicated provider lane pins `16.0.3-rootless`. The exact `v16.0.3` source
archive and files were accessible and inspected during implementation:

- [Notifier](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/webhook/notifier.go):
  `PullRequestChangeTargetBranch` emits `edited`, `changes.ref.from`, current
  `pull_request.base.ref`, subscription `HookEventPullRequest` (`pull_request`).
  `IssueChangeTitle` emits only `changes.title.from`.
- [Payload types](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/modules/structs/hook.go):
  `ChangesPayload` has title/body/ref fields, no draft delta; `PushPayload` has
  ref/before/after/repository, no forced/deleted field.
- [PR conversion](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/convert/pull.go)
  and [PR model](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/models/issues/pull.go):
  `draft` calls `IsWorkInProgress`, which derives it from configured title
  prefixes. There is no distinguishable explicit draft transition. Title edits,
  draft snapshots and GitHub draft action aliases are negative fixtures.
- [Push options](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/modules/repository/push.go)
  and [object IDs](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/modules/git/object_id.go):
  `IsDelRef` tests the new ID for zeros. `SyncPushCommits` forwards old/new IDs;
  deletion can therefore be reported from a full zero sentinel. Force-shaped
  fixtures preserve both IDs with unknown force status.
- [Headers](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/services/webhook/shared/payloader.go)
  and [subscription grouping](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.3/modules/webhook/type.go):
  `X-Forgejo-*` and `X-Gitea-*` aliases are emitted together. These tests exercise
  both header families with the same verified Forgejo payload contract. They do
  not claim that arbitrary Gitea versions or newer Forgejo releases share it.
  The existing specific `pull_request_label` Event-Type dispatch stays intact.
