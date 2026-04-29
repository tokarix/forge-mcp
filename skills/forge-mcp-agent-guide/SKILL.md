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

## Write Workflow

Always work in a **detached git worktree** — never edit files in the main checkout. This keeps the main working tree clean and prevents patches from picking up unrelated changes, especially when multiple agents share the same repository.

**CRITICAL WARNING:** You MUST generate patches from a proper git clone or worktree that shares the target repository's history. DO NOT run `git init` in a temporary directory to create a fake repository for patch generation — patches generated against an empty history will be rejected by the server because they will not apply cleanly. If you do not have a clone of the repository, you MUST run `git clone` using the git proxy URL first.

1. Clone the repo via git proxy (skip if already cloned)
2. Fetch the latest base branch: `git fetch origin master`
3. Create a worktree for the feature branch:
   ```bash
   git worktree add /tmp/<repo>-<feature> origin/master
   ```
4. Make changes in the worktree
5. Generate a git-format patch from the worktree with git itself, for example `git diff --no-ext-diff --binary`, `git diff --cached --no-ext-diff --binary`, or `git show`
6. Submit via `commit_patch` with the diff, target branch name, and commit message — the server validates the patch and applies it in a clean clone of the base branch. Do NOT run `git apply --check` locally; your worktree already contains the changes so it will always fail there.
7. Open a pull request via `open_change_request`
8. Remove the worktree when done (it will have dirty files after patch generation):
   ```bash
   git worktree remove --force /tmp/<repo>-<feature>
   ```

**Patch format:**
- `commit_patch` only accepts git diff format starting with `diff --git`
- Do not hand-write traditional unified diffs; use git to generate the patch
- New files must use git headers such as `new file mode`, `--- /dev/null`, and `+++ b/<path>`
- The server validates the patch in a clean clone — if it rejects the patch, check your diff against the base branch

**Branch naming:** Your branch must start with the configured prefix (e.g. `agent/claude/`). The gateway enforces this.

**Protected paths:** Diffs touching protected paths (e.g. `.forgejo/`, `.github/`) are rejected.

## Addressing Review Feedback

When a reviewer requests changes on a PR:

1. Read the review with `get_change_request_comments`
2. If the worktree from the original work no longer exists, create one from the PR branch:
   ```bash
   git fetch origin <pr-branch>
   git worktree add /tmp/<repo>-<feature> FETCH_HEAD
   ```
3. Make fixes in the worktree, generate patches with `git diff --no-ext-diff --binary`
4. Push fixes with `commit_patch` using `existing_branch: true`
5. Squash fixup commits into the right logical commits with `rebase_branch` — never leave fixup-style follow-up commits in the final series
6. Each commit in the result must be self-contained and independently buildable
7. Remove the worktree when done: `git worktree remove --force /tmp/<repo>-<feature>`

**Never ask the user to run git commands manually.** The tools above cover the full workflow: committing, rebasing, and force-pushing are all handled server-side.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `git push` through the proxy | Use `commit_patch` MCP tool |
| Forgetting `forge` parameter | Most tools require it (`forge_info` and `poll_events` do not) |
| Wrong branch prefix | Check your agent's configured `branch_prefix` |
| Touching CI/workflow files | These are protected paths -- the gateway will reject |
| Using Bearer auth with git | Git sends Basic auth -- use password field for token |
| Hand-written or traditional unified diff patch | Generate the patch with `git diff --no-ext-diff --binary` or `git show` |
| Editing files in the main checkout | Always use a detached `git worktree` — the main checkout accumulates drift and picks up unrelated changes |
