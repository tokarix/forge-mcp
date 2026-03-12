# Phase 3: HTTP Control Plane + MCP Shim

## Goal

Split the current monolithic stdio MCP server into two components: an HTTP control plane that holds credentials and enforces policy, and a lightweight MCP shim that agents spawn locally. This establishes the trust boundary where forge credentials never leave the control plane.

## Architecture

```
Agent → MCP shim (stdio) → HTTPS → Control plane (axum) → Orchestrator → Forge
```

### Control plane (`server` crate)

HTTP server built on axum. Responsibilities:

- Holds forge credentials (Forgejo token, future GitHub/GitLab tokens)
- Runs orchestrator, policy engine, audit, forge adapters, git-exec
- Exposes REST API at `/api/v1/`
- Authenticates callers via bearer tokens
- Maps each token to an agent identity and policy config
- Serves OpenAPI docs via utoipa + utoipa-scalar at `/api/v1/docs` (optional, can be disabled in config)
- Loads configuration from a TOML file at startup

### MCP shim (`transport` crate)

Lightweight stdio MCP server using rmcp. Responsibilities:

- Translates MCP tool calls into HTTP requests to the control plane
- Passes its bearer token in the `Authorization` header
- Holds no forge credentials, no policy logic, no business logic
- Configured via env var (`FORGE_MCP_GATEWAY_URL`) or CLI flag (`--gateway-url`)
- Token via env var (`FORGE_MCP_TOKEN`) or file path (`--token-file`); never accepted as a CLI value to avoid leaking credentials in process listings and shell history

## REST API Surface

```
GET  /api/v1/repos/{owner}/{repo}/contents/{path}?ref=<git_ref>
POST /api/v1/repos/{owner}/{repo}/patches
POST /api/v1/repos/{owner}/{repo}/pulls
GET  /api/v1/repos/{owner}/{repo}/pulls
GET  /api/v1/repos/{owner}/{repo}/pulls/{index}
```

### Endpoint mapping

| MCP tool                | HTTP method | Path                                      |
|-------------------------|-------------|-------------------------------------------|
| `read_repository_file`  | GET         | `/api/v1/repos/{owner}/{repo}/contents/{path}` |
| `commit_patch`          | POST        | `/api/v1/repos/{owner}/{repo}/patches`    |
| `open_change_request`   | POST        | `/api/v1/repos/{owner}/{repo}/pulls`      |
| `list_change_requests`  | GET         | `/api/v1/repos/{owner}/{repo}/pulls`      |
| `get_change_request`    | GET         | `/api/v1/repos/{owner}/{repo}/pulls/{index}` |

All endpoints require `Authorization: Bearer <token>`. The control plane resolves the token to an agent identity and policy config before calling the orchestrator.

### Request/response formats

**GET /contents/{path}**
- Query params: `ref` (optional git ref)
- Response: `{ "path": "...", "content": "...", "git_ref": "..." }`

**POST /patches**
- Body: `{ "base_branch": "main", "new_branch": "agent/fix", "patch": "diff...", "commit_message": "..." }`
- Response: `{ "branch": "agent/fix", "commit_sha": "abc123" }`

**POST /pulls**
- Body: `{ "base_branch": "main", "head_branch": "agent/fix", "title": "...", "body": "..." }`
- Response: `{ "index": 1, "url": "...", "title": "...", "state": "open", ... }`

**GET /pulls**
- Query params: `state` (optional: open, closed, merged)
- Response: `[{ "index": 1, ... }, ...]`

**GET /pulls/{index}**
- Response: `{ "index": 1, "url": "...", "title": "...", "state": "open", ... }`

### Error responses

```json
{ "error": "policy denied: branch 'main' does not start with required prefix 'agent/'" }
```

HTTP status codes:
- 400: validation errors, policy denials
- 401: missing or invalid bearer token
- 403: agent not authorized for the requested repository
- 502: upstream forge errors
- 500: internal errors (audit failure, git-exec failure)

## Authentication

Bearer tokens, each mapped to an agent identity and policy config. Loaded from the server config file at startup.

Token resolution flow:
1. Extract `Authorization: Bearer <token>` from request
2. Look up token in the agent registry
3. If not found → 401
4. Inject the resolved `AgentIdentity` and `PolicyConfig` into the request context
5. Verify `{owner}/{repo}` from the URL is in the agent's `allowed_repos` list → 403 if not
6. Pass to orchestrator with the agent's policy config

## Configuration

TOML config file, path specified via CLI argument or env var.

```toml
[server]
listen = "0.0.0.0:8443"

[forge.forgejo]
base_url = "https://forge.example"
token = "forgejo-api-token"

[[agents]]
token = "bearer-token-for-codex"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["org/repo", "org/other-repo"]
branch_prefix = "agent/codex/"
protected_paths = [".forgejo/", ".github/"]

[[agents]]
token = "bearer-token-for-claude"
agent_id = "claude"
session_id = "default"

[agents.policy]
allowed_repos = ["org/repo"]
branch_prefix = "agent/claude/"
protected_paths = [".forgejo/", ".github/"]
```

## Crate changes

### Modified

- **`server`** — becomes axum HTTP server. Replaces stdio wiring with HTTP routes. Loads TOML config, manages token-to-agent mapping, serves REST API + Scalar docs.
- **`transport`** — MCP shim. Instead of calling orchestrator directly, makes HTTP requests to the control plane. Becomes a separate binary.
- **`domain`** — add `Serialize` derives to response types for JSON serialization. Add request types for the HTTP API (or reuse existing domain types with serde).

### Unchanged

- **`audit`** — no changes
- **`forge`** — no changes
- **`git-exec`** — no changes
- **`orchestrator`** — no changes (already exposes the right service traits)

## Testing

- Config loading: parse TOML, validate, reject missing fields
- Token resolution: valid token returns agent identity, invalid returns 401
- HTTP handlers: each endpoint with success and error cases (using axum test utilities)
- MCP shim: tool calls translate to correct HTTP requests
- End-to-end: MCP shim → HTTP → control plane → fake forge adapter

## Dependencies

New crate dependencies:
- `server`: axum, tokio (with `net` feature), tower-http (cors/logging), utoipa, utoipa-scalar, serde, toml
- `transport`: reqwest (HTTP client to control plane), clap (CLI args)

## Phasing note

This is Phase 3 in the updated roadmap:
- Phase 1 (done): Read-only Forgejo MCP server
- Phase 2 (done): Write workflow with diff validation, policy, git-exec
- **Phase 3 (this): HTTP control plane + MCP shim split**
- Phase 4: GitHub/GitLab adapters, expanded policy
