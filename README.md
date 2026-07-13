# forge-mcp

Multi-forge, policy-enforcing MCP server for AI coding agents.

Supported forges:
- **Forgejo / Gitea** — full support
- **GitLab** — read + write support. The GitLab adapter was autonomously implemented by cockpit-orchestrated agents overnight while I slept — which is kind of the whole point of this project.

GitHub support is planned.

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
- `forge/`: forge adapter trait and Forgejo implementation
- `git-exec/`: CLI-based git operations for the write path
- `orchestrator/`: read and write workflow composition
- `server/`: binary wiring and MCP entry point
- `transport/`: stdio MCP transport using `rmcp`

How to run:
- Set `FORGEJO_BASE_URL` to the Forgejo or Gitea base URL.
- Set `FORGEJO_TOKEN` for authenticated reads and all write operations.
- Optionally set `FORGE_MCP_AGENT_ID` and `FORGE_MCP_SESSION_ID`.
- Start the server with `cargo run -p server`.

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
