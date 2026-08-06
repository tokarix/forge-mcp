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
- **Checks:** read

If webhooks are enabled, subscribe each App to **Issues**, **Issue comments**,
**Pull requests**, and **Pull request reviews**, and configure the same webhook
secret on the Apps and in forge-mcp. Webhook-driven auto-merge additionally
requires a forge-level token or `[forges.github_app]`; auto-merge must also be
enabled in the target repository.

For GitHub.com, `base_url = "https://github.com"` automatically selects
`https://api.github.com`. For GitHub Enterprise Server, forge-mcp derives
`<base_url>/api/v3`; set `api_url` explicitly for a nonstandard API endpoint.

To run the opt-in real-Forgejo dependency lifecycle test, use a disposable
Forgejo instance and token:

```text
FORGEJO_TEST_BASE_URL=https://forgejo.example \
FORGEJO_TEST_TOKEN=replace-me \
cargo test -p forge --test forgejo_issue_dependencies -- --ignored --nocapture
```

The test discovers the authenticated owner and Forgejo version, creates
temporary repositories and issues, exercises same- and cross-repository
dependency add/read/remove operations, and best-effort deletes its temporary
repositories. Never use production repositories or a long-lived production
token for this test.

Issues & PRs disabled. Development happens on an internal Forgejo instance.
