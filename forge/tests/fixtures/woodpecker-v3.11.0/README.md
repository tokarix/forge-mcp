# Woodpecker diagnostic fixtures

These are synthetic, sanitized responses matching the upstream **v3.11.0**
contract inspected on 2026-10-29. They are not production captures and do not
establish the deployed server version. Names, IDs, timestamps and output are
invented. `SENTINEL_*` strings are deliberate disclosure detectors, not secrets.
Unknown fields in `agent.json` exercise forward-compatible allowlist decoding.

Authoritative source links (all pinned to the same tag):

* [Repository model](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/model/repo.go)
  exposes `id`, `forge_id`, `forge_remote_id`, `owner`, `name`, `forge_url`,
  and `clone_url`. An internal forge ID alone does not identify the forge
  instance. Compare repository URL identity against the configured forge and
  authorized repository; owner/name equality alone is insufficient.
* [Repository API](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/api/repo.go)
  returns the session repository from `GET /api/repos/{repo_id}`.
* [Pipeline API](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/api/pipeline.go)
  resolves `GET /api/repos/{repo_id}/pipelines/{number}` with
  `GetPipelineNumber(session.Repo(c), num)`.
  [Pipeline model](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/model/pipeline.go)
  deliberately omits `RepoID` from JSON. Repository association therefore
  comes from the validated repository-scoped lookup, not a fictional
  `repo_id` field. Validate the returned pipeline number and child pipeline IDs.
  `id` and `number` have different meanings.
* [PR conversion](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/forge/gitea/helper.go)
  uses `hook.PullRequest.Head.Sha` as the pipeline commit. Do not equate a
  synthetic merge commit with this source SHA.
* [Workflow model](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/model/workflow.go)
  provides `agent_id`, `pipeline_id`, `id`, `pid`, `state`, `error`,
  `started`, `finished` and children. `ppid` on a child refers to workflow
  `pid`, not workflow database `id`.
* [Step model](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/model/step.go)
  provides `id`, `uuid`, `pipeline_id`, `pid`, `ppid`, `state`, `error`,
  `exit_code`, `started` and `finished`.
* [Pipeline error type](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/pipeline/errors/types/errors.go)
  defines pipeline `errors` as structured entries with `type`, `message`,
  `is_warning` and arbitrary `data`. Do not decode a pipeline `error` string
  or expose arbitrary `data`. Its Go slice can be null; `exit-255.json`
  exercises that representation, while missing errors are also accepted. Workflow and step errors are strings.
* [Agent API](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/api/agent.go)
  and [routes](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/router/api.go)
  provide single-agent `GET /api/agents/{agent_id}`, guarded by `MustAdmin`.
  Configured Woodpecker credentials can consequently read the pipeline but
  receive 403 on the agent lookup. Never fall back to another credential.
* [Agent model](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/model/agent.go)
  includes a registration `token` and arbitrary `custom_labels`. Only
  `id`, `platform`, `backend` and `version` are intended diagnostic output.
  This model has no historical termination, resource usage or host/container
  logs. Its current observations cannot establish why an earlier step failed.
* [Execution clock](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/pipeline/pipeline.go)
  initializes execution start with `time.Now().Unix()`;
  [server RPC](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/server/grpc/rpc.go)
  passes execution timestamps to pipeline updates. Preserve Unix seconds for
  pipeline/workflow/step timestamps. Missing values remain unknown; retain
  explicit zero values when supplied. Workflow and step timestamps have
  `omitempty` in the upstream serializer.
* [Log entry model](https://github.com/woodpecker-ci/woodpecker/blob/v3.11.0/pipeline/rpc/log_entry.go)
  uses Go `[]byte` for `data` (JSON base64), with `omitempty`. Null and
  missing data must remain accepted. Log `time` is separate from evidence
  timestamps and must not be interpreted as a step's Unix start time.

`exit-255.json` and `logs-passing.json` intentionally disagree in appearance:
the step remains failed with exit 255 despite passing tests and completed build
output. The fixture supplies no cause such as OOM, timeout or runner crash.
`workflow-only.json` retains a workflow error without failed children.
`logs-nullable.json` supplies no usable output; `logs-partial.json` combines
valid output with invalid base64 so an error must not erase the valid evidence.

A 404 on the agent lookup is resource-not-found, not proof that the agent API
is unsupported. The absence of historical termination evidence follows from
this pinned contract; it should be reported separately as `not_exposed`.
