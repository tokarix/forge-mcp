# forge-mcp

Multi-forge, policy-enforcing MCP server for AI coding agents.

Current status:
- Phase 1 bootstrap
- Forgejo-first
- read-only flow for repository file reads
- wiring kept small enough to evolve safely

Workspace layout:
- `domain/`: canonical types and service traits
- `forge/`: forge adapter trait and Forgejo implementation
- `git-exec/`: reserved for the write path in Phase 2
- `audit/`: audit sink interfaces and in-memory implementation
- `orchestrator/`: read workflow composition
- `transport/`: MCP-facing transport seam and request handling
- `server/`: binary wiring and CLI entry point
