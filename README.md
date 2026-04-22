# forge-mcp

Multi-forge, policy-enforcing MCP server for AI coding agents.

Current status: Phase 2 — Forgejo read + write MCP server.

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
