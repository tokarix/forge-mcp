# Multi-Forge Support + Git Smart HTTP Proxy

## Goal

Evolve the gateway from a single-Forgejo control plane into a multi-forge, policy-enforcing gateway with a read-only git smart HTTP proxy — enabling transparent `git clone`/`fetch` through the gateway so that tools like `cargo` with git dependencies work seamlessly without direct access to upstream forges.

## Architecture

The gateway gains three capabilities:

1. **Multi-forge routing** — a `ForgeRegistry` maps short aliases to forge instances, each with its own adapter, credentials, and base URL.
2. **Glob-style repo authorization** — `allowed_repos` patterns use a `forge/owner/repo` triplet with wildcard support at any trailing level.
3. **Git smart HTTP proxy** — read-only (`git-upload-pack`) proxy endpoints that authenticate agents, enforce policy, and stream git protocol to/from upstream forges.

All writes continue through the existing `commit_patch` MCP tool, which provides diff validation, branch prefix enforcement, protected path checks, and audit logging. The git proxy does not support `git-receive-pack`.

## Config Format

```toml
[server]
listen = "0.0.0.0:8443"

[[forges]]
alias = "internal"
type = "forgejo"
base_url = "https://git.dev.adlevio.net"
token = "forgejo-api-token"

[[forges]]
alias = "client-a"
type = "forgejo"
base_url = "https://git.client-a.example"
token = "client-a-token"

[[agents]]
token = "bearer-token-for-codex"
agent_id = "codex"
session_id = "default"

[agents.policy]
allowed_repos = ["internal/stintel/*", "client-a/org/specific-repo"]
branch_prefix = "agent/codex/"
protected_paths = [".forgejo/", ".github/"]
```

### Changes from current config

- `[forge.forgejo]` becomes `[[forges]]` — an array of tables, each with an `alias` and `type` field.
- Multiple instances of the same forge type (e.g. two Forgejo instances) are supported naturally.
- `type` is a string enum: `"forgejo"` for now, `"github"` and `"gitlab"` reserved for future adapters.
- `token` is optional — omit for public/anonymous forge access.
- `allowed_repos` patterns gain a forge alias prefix: `"alias/owner/repo"`.
- This is a breaking change to the config format. No migration shim — the project is pre-1.0.

### Forge alias validation

Aliases must match `[a-z0-9][a-z0-9-]*` — lowercase alphanumeric with hyphens, no leading hyphen. This prevents ambiguity in URL paths and `allowed_repos` pattern parsing (slashes, dots, and uppercase are not allowed).

### Allowed repos pattern matching

- `"*"` — all repos on all forges
- `"alias/*"` — all repos on a specific forge
- `"alias/owner/*"` — all repos under an owner on a specific forge
- `"alias/owner/repo"` — exact match

Invalid forge aliases in patterns are caught at startup validation. Partial globs like `"alias/org/repo-*"` are not supported and treated as literals.

## Forge Registry

A `ForgeRegistry` struct maps aliases to forge instances. Built at startup from the `[[forges]]` config array.

```
ForgeRegistry {
    forges: HashMap<String, ForgeInstance>
}

ForgeInstance {
    alias: String,
    adapter: Arc<dyn ForgeAdapter>,
    base_url: String,
    token: Option<String>,
    read_service: Arc<dyn RepositoryReadService>,
    write_service: Arc<dyn RepositoryWriteService>,
}
```

Each `ForgeInstance` holds its own `ReadOrchestrator` and `WriteOrchestrator`, constructed at startup with the instance's adapter and a shared audit sink.

### Orchestrator refactoring

The current `WriteOrchestrator` takes a per-agent `PolicyConfig` and `forge_token` in its constructor. This is incompatible with the per-forge-instance model where orchestrators are shared across agents. Required changes:

- **Remove `policy_config` from `WriteOrchestrator`** — policy evaluation is already done in the handler layer (handlers.rs validates branch prefix, protected paths, and allowed repos before calling the orchestrator). The duplicate policy check inside `WriteOrchestrator` should be removed.
- **Move `forge_token` to `ForgeInstance`** — the orchestrator receives the token from its owning `ForgeInstance` rather than its constructor. Alternatively, `WriteOrchestrator` keeps the token but drops the policy field.

### `RepositoryRef` changes

`RepositoryRef` in `domain` gains an `alias: String` field alongside the existing `forge: ForgeKind` and `host: String`. The alias is set by the handler from the URL path parameter and flows through to audit records and policy evaluation.

### `AppState` restructuring

The current `AppState` holds a single `forgejo_base_url`, one `read_service`, and one `write_service`. This becomes:

```
AppState {
    agent_registry: AgentRegistry,
    forge_registry: ForgeRegistry,
}
```

Handlers look up the forge instance from the registry by alias, then use that instance's `read_service` or `write_service`.

### `is_repo_allowed` signature change

The current `is_repo_allowed(owner, repo)` becomes `is_repo_allowed(forge_alias, owner, repo)`. The matching algorithm:

1. If any pattern is `"*"`, allow.
2. Split the pattern on `/` into at most 3 parts: `[forge, owner, repo]`.
3. Match `forge_alias` against the first part (exact match).
4. If the pattern is `"alias/*"`, allow any owner/repo on that forge.
5. Match `owner` against the second part (exact match).
6. If the pattern is `"alias/owner/*"`, allow any repo under that owner.
7. Match `repo` against the third part (exact match).

## REST API Changes

All routes gain a `{forge}` path segment:

- `GET  /api/v1/repos/{forge}/{owner}/{repo}/contents/{*path}`
- `POST /api/v1/repos/{forge}/{owner}/{repo}/patches`
- `GET  /api/v1/repos/{forge}/{owner}/{repo}/pulls`
- `POST /api/v1/repos/{forge}/{owner}/{repo}/pulls`
- `GET  /api/v1/repos/{forge}/{owner}/{repo}/pulls/{index}`

Handlers resolve the forge alias from the registry. 404 if the alias is not found. The `allowed_repos` check uses the full `forge/owner/repo` pattern.

## MCP Shim Changes

All MCP tools gain a required `forge` parameter (the alias string):

- `read_repository_file(forge, owner, repo, path, ref?)`
- `commit_patch(forge, owner, repo, base_branch, new_branch, commit_message, patch)`
- `open_change_request(forge, owner, repo, title, body, head_branch, base_branch)`
- `list_change_requests(forge, owner, repo, state?)`
- `get_change_request(forge, owner, repo, index)`

The shim builds URLs using the forge parameter: `/api/v1/repos/{forge}/{owner}/{repo}/...`. No shim-side validation of forge aliases — the gateway handles resolution and policy.

## Git Smart HTTP Proxy

### Endpoints

- `GET  /git/{forge}/{owner}/{repo}.git/info/refs?service=git-upload-pack` — discovery
- `POST /git/{forge}/{owner}/{repo}.git/git-upload-pack` — fetch/clone

Requests targeting `git-receive-pack` return 403 with a message directing the agent to use the `commit_patch` MCP tool for writes.

The `.git` suffix in the proxy path is mandatory and stripped when constructing the upstream URL. Upstream forges typically accept URLs with or without `.git`; the proxy always forwards without the suffix and lets the forge handle the redirect if needed.

### Flow

1. Extract bearer token from request headers, resolve agent identity.
2. Look up forge alias in the registry — 404 if not found.
3. Check `allowed_repos` against `forge/owner/repo` — 403 if denied.
4. Rewrite the URL path to the upstream forge's base URL.
5. Add the upstream forge token to the proxied request (skip if the forge has no token configured).
6. Stream the upstream response back to the agent using axum's streaming body support and reqwest's streaming response. No buffering of pack data — bytes are proxied as they arrive. The POST endpoint (`git-upload-pack`) requires bidirectional streaming since the request body is also a stream in the git protocol.
7. Record audit entry (agent, action=`git_read`, repository). A single `git_read` action is used because clone and fetch are indistinguishable at the smart HTTP protocol level (both use `git-upload-pack`).

### Content types

The git smart HTTP protocol uses specific content types:

- Discovery: `application/x-git-upload-pack-advertisement`
- Upload pack: request `application/x-git-upload-pack-request`, response `application/x-git-upload-pack-result`

The proxy passes these through without interpretation.

### Agent-side setup

One-time git config per forge:

```bash
# Route git traffic through the gateway
git config --global url."http://gateway:8443/git/internal/".insteadOf "https://git.dev.adlevio.net/"

# Authenticate to the gateway
git config --global http.http://gateway:8443/.extraHeader "Authorization: Bearer <agent-token>"
```

After this, `cargo` with git dependencies pointing at `https://git.dev.adlevio.net/org/repo` works transparently — git rewrites the URL, the gateway authenticates, checks policy, and proxies to the upstream forge.

## Non-Goals

- **Git push through proxy** — `commit_patch` covers writes with full policy enforcement.
- **GitHub / GitLab adapters** — config supports the `type` field, but only `"forgejo"` is implemented in this phase.
- **Fork-and-PR workflow** — future feature.
- **Agent-side tooling** — skills or scripts for alias discovery are a separate concern.
- **Local repo caching / mirroring** — not needed; connections are fast enough.
