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

## Auto-merge scheduling

Approval webhooks schedule auto-merge by default for compatibility. Operators
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
