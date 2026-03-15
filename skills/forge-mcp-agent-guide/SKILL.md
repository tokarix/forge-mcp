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

All tools require a `forge` parameter — the alias of the target forge instance.

### Reading

| Tool | Purpose |
|------|---------|
| `read_repository_file` | Read a single file (with optional git ref) |
| `list_change_requests` | List pull requests (filter by state) |
| `get_change_request` | Get details of a specific pull request |

### Writing

| Tool | Purpose |
|------|---------|
| `commit_patch` | Apply a unified diff to a new branch and push |
| `open_change_request` | Open a pull request |

### Write Workflow

1. Clone the repo via git proxy
2. Make changes locally
3. Generate a unified diff (`git diff`)
4. Submit via `commit_patch` with the diff, target branch name, and commit message
5. Open a pull request via `open_change_request`

**Branch naming:** Your branch must start with the configured prefix (e.g. `agent/claude/`). The gateway enforces this.

**Protected paths:** Diffs touching protected paths (e.g. `.forgejo/`, `.github/`) are rejected.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `git push` through the proxy | Use `commit_patch` MCP tool |
| Forgetting `forge` parameter | Every MCP tool requires it |
| Wrong branch prefix | Check your agent's configured `branch_prefix` |
| Touching CI/workflow files | These are protected paths -- the gateway will reject |
| Using Bearer auth with git | Git sends Basic auth -- use password field for token |
