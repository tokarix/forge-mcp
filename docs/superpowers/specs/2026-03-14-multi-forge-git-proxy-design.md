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
- `allowed_repos` patterns gain a forge alias prefix: `"alias/owner/repo"`.

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

### Flow

1. Extract bearer token from request headers, resolve agent identity.
2. Look up forge alias in the registry — 404 if not found.
3. Check `allowed_repos` against `forge/owner/repo` — 403 if denied.
4. Rewrite the URL path to the upstream forge's base URL.
5. Add the upstream forge token to the proxied request.
6. Stream the upstream response back to the agent (no buffering of pack data).
7. Record audit entry (agent, action=`git_clone` or `git_fetch`, repository).

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
