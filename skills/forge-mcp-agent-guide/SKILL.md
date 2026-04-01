---
name: forge-mcp-agent-guide
description: Use when interacting with a Forgejo or GitHub-shaped forge through the forge-mcp gateway — cloning repos, reading files, creating patches, or opening pull requests via MCP tools or the git proxy
---

# forge-mcp Agent Guide

## Overview

forge-mcp is a policy-enforcing gateway between AI agents and forge instances. All repository access goes through the gateway — never directly to the forge.

**Two interfaces:**
- **MCP tools** for reading files, committing patches, and opening pull requests
- **Git smart HTTP proxy** for `git clone` and `git fetch` (read-only)

## Network Security

The gateway listens on plain HTTP. In production, place it behind a TLS-terminating reverse proxy or restrict it to a trusted network. Never expose the HTTP port over untrusted networks — agent tokens would travel in cleartext.

## Authentication

All requests use your agent bearer token.

- **MCP tools:** Handled automatically by the MCP shim
- **Git proxy:** Use HTTP Basic auth — any username, token as password

## Git Proxy (clone/fetch)

The proxy is **read-only**. `git push` is blocked — use the `commit_patch` MCP tool instead.

**URL pattern:** `<scheme>://<gateway-host>:<port>/git/{forge}/{owner}/{repo}`

```bash
# Cache credentials in memory globally (default 15 min, avoids plaintext on disk)
git config --global credential.helper cache

# Clone through the gateway (use https:// if behind a TLS reverse proxy)
git clone http://gateway:8443/git/myforge/org/repo
```

## MCP Tools

Most tools require a `forge` parameter — the alias of the target forge instance.

### Discovery

| Tool | Purpose |
|------|---------|
| `forge_info` | Discover available forges, gateway URL, and git proxy URL |
| `poll_events` | Poll for buffered channel events (webhooks, notifications) |

### Reading

| Tool | Purpose |
|------|---------|
| `read_repository_file` | Read a single file (with optional git ref) |
| `list_change_requests` | List pull requests (filter by state) |
| `get_change_request` | Get details of a specific pull request |
| `get_change_request_diff` | Get the unified diff for a pull request |
| `get_change_request_comments` | Get all comments and reviews on a pull request |
| `list_issues` | List issues (filter by state) |
| `get_issue` | Get a single issue by index |
| `get_issue_comments` | Get all comments on an issue |

### Writing

| Tool | Purpose |
|------|---------|
| `commit_patch` | Apply a git-format patch to a branch and push |
| `open_change_request` | Open a pull request |
| `update_change_request` | Update a pull request's title and/or body |
| `close_change_request` | Close a pull request |
| `comment_on_change_request` | Post a comment on a pull request |
| `submit_change_request_review` | Submit a formal review (APPROVED, REQUEST_CHANGES, COMMENT) |
| `rebase_branch` | Squash (fixup) commits on a branch |
| `schedule_auto_merge` | Schedule a PR for auto-merge when checks pass |
| `create_issue` | Create a new issue |
| `assign_issue` | Assign an issue to a user |
| `close_issue` | Close an issue |
| `comment_on_issue` | Post a comment on an issue |

Before calling `create_issue`, check existing open issues with `list_issues`
and inspect the closest match with `get_issue` / `get_issue_comments` so you
do not file a duplicate.

### Write Workflow

1. Clone the repo via git proxy
2. Make changes locally
3. Generate a git-format patch with git itself, for example `git diff --no-ext-diff --binary`, `git diff --cached --no-ext-diff --binary`, or `git show`
4. Validate the patch locally with `git apply --check` (or `git apply --check --index`) and then submit via `commit_patch` with the diff, target branch name, and commit message
5. Open a pull request via `open_change_request`

**Patch format:**
- `commit_patch` only accepts git diff format starting with `diff --git`
- Do not hand-write traditional unified diffs; use git to generate the patch
- New files must use git headers such as `new file mode`, `--- /dev/null`, and `+++ b/<path>`
- If `git apply --check` fails locally, `commit_patch` will fail too

**Branch naming:** Your branch must start with the configured prefix (e.g. `agent/claude/`). The gateway enforces this.

**Protected paths:** Diffs touching protected paths (e.g. `.forgejo/`, `.github/`) are rejected.

## Addressing Review Feedback

When a reviewer requests changes on a PR:

1. Read the review with `get_change_request_comments`
2. Make fixes locally, generate patches with `git diff --no-ext-diff --binary`
3. Push fixes with `commit_patch` using `existing_branch: true`
4. Squash fixup commits into the right logical commits with `rebase_branch` — never leave fixup-style follow-up commits in the final series
5. Each commit in the result must be self-contained and independently buildable

**Never ask the user to run git commands manually.** The tools above cover the full workflow: committing, rebasing, and force-pushing are all handled server-side.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `git push` through the proxy | Use `commit_patch` MCP tool |
| Forgetting `forge` parameter | Most tools require it (`forge_info` and `poll_events` do not) |
| Wrong branch prefix | Check your agent's configured `branch_prefix` |
| Touching CI/workflow files | These are protected paths -- the gateway will reject |
| Using Bearer auth with git | Git sends Basic auth -- use password field for token |
| Hand-written or traditional unified diff patch | Generate the patch with `git diff --no-ext-diff --binary` or `git show`, then verify with `git apply --check` |
