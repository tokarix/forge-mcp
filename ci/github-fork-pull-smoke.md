# Trusted GitHub fork pull smoke

Run this job from protected CI configuration after independent review has
approved the exact implementation PR head. Source the runner script from a
trusted checkout and pass a fresh, clean checkout of the approved head via
`--checkout`. The protected job must verify the PR head against the reviewed
SHA before provisioning credentials. Ordinary pull-request workflows must
have no access to this lane or its secrets.

Use an isolated Linux runner with Git, Python 3.11+, and the workspace Rust
toolchain. Give this job an exclusive disposable GitHub fixture consisting of
an upstream repository and two forks under distinct owners. Keep the base
branch stable during the job and synchronize its commit into both forks.
Allow fixture branch creation and deletion. The fixture must have no hooks
or automation that open, change, or merge smoke PRs.

Provide these settings to the protected runner.

| Setting | Value |
| --- | --- |
| `GITHUB_FORK_SMOKE_HEAD` | Full SHA recorded by the independent review for the implementation PR |
| `GITHUB_FORK_SMOKE_UPSTREAM` | Upstream `owner/repo` |
| `GITHUB_FORK_SMOKE_FORK` | Granted fork `owner/repo`, preferably with a different short name |
| `GITHUB_FORK_SMOKE_UNGRANTED_FORK` | Second fork `owner/repo`, omitted from the agent's grants |
| `GITHUB_FORK_SMOKE_BASE` | Stable short base branch in the upstream |
| `GITHUB_FORK_SMOKE_GATEWAY_TOKEN` | Ephemeral credential with fixture repository and ref read access and permission to open an upstream PR |
| `GITHUB_FORK_SMOKE_FIXTURE_TOKEN` | Separate ephemeral credential with fixture content write access on the forks and PR read and close access on the upstream |

Scope both credentials to the fixture. Supply secrets via protected CI and
revoke them after the job. The script gives the gateway only its scoped token
and supplies the independent credential to the fixture and readback code.
It uses a private temporary directory and strips secret variables from child
process environments. Keep the runner isolated from other jobs.

```sh
python3 /trusted/forge-mcp/ci/github-fork-pull-smoke.py \
  --checkout /ci/implementation-head \
  --scratch /ci/runner-local > github-fork-pull-evidence.json
```

The runner builds the gateway and its MCP shim from the exact checked-out SHA.
It creates three unique branches with known commits directly ahead of the
base. It checks that no matching GitHub PRs exist across all states, calls
`open_change_request` once for the allowed branch, verifies the returned PR
against GitHub records, and verifies policy denials and zero matching PRs on
the other branches. Cleanup uses the fixture credential and verifies identities
before closing PRs and deleting run-owned refs.

Require the job to exit successfully and archive the JSON evidence. Validate
its implementation SHA against the reviewed head. The record includes the
fixture PR number and URL, the two repository IDs, exact head and base branch
names and commit SHAs, and both negative outcomes. Missing configuration,
failed or partial readback, cleanup failure, or an absent evidence artifact
fails the gate. Run this job again when the reviewed head changes.
