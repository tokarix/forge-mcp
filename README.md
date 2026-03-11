# forge-mcp

Multi-forge, policy-enforcing MCP server for AI coding agents.

Current status:
- Phase 1
- Forgejo-first
- read-only stdio MCP server with `read_repository_file`
- wiring kept small enough to evolve safely

Workspace layout:
- `domain/`: canonical types and service traits
- `forge/`: forge adapter trait and Forgejo implementation
- `git-exec/`: reserved for the write path in Phase 2
- `audit/`: audit sink interfaces and in-memory implementation
- `orchestrator/`: read workflow composition
- `transport/`: stdio MCP transport using `rmcp`
- `server/`: binary wiring and MCP entry point

How to run:
- Set `FORGEJO_BASE_URL` to the Forgejo or Gitea base URL.
- Optionally set `FORGEJO_TOKEN` for authenticated reads.
- Optionally set `FORGE_MCP_AGENT_ID` and `FORGE_MCP_SESSION_ID`.
- Start the server with `cargo run -p server`.
