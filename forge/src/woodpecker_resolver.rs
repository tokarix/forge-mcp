//! Repository-bound Woodpecker evidence resolution using the pinned v3.11 API.

use std::collections::HashSet;

use base64::Engine;
use domain::{
    CiDiagnostic, CiDiagnosticCode as Code, CiDiagnosticComponent as Component, CiFailureStep,
    CiLogExcerpt, CiProvider, CiResolution, CiTimestamps, RepositoryRef,
    WoodpeckerPipelineEvidence, WoodpeckerRunnerEvidence, WoodpeckerStepEvidence,
    WoodpeckerWorkflowEvidence,
};
use serde::Deserialize;
use serde_json::Value;

use crate::woodpecker::{Failure, Limits, Origin, Resource, Session, safe_text};

#[derive(Default, Deserialize)]
pub(super) struct Clock {
    pub(super) created: Option<i64>,
    pub(super) updated: Option<i64>,
    pub(super) started: Option<i64>,
    pub(super) finished: Option<i64>,
}
impl From<Clock> for CiTimestamps {
    fn from(c: Clock) -> Self {
        Self {
            created: c.created,
            updated: c.updated,
            started: c.started,
            finished: c.finished,
        }
    }
}
#[derive(Deserialize)]
pub(super) struct Repo {
    pub(super) id: u64,
    pub(super) owner: String,
    pub(super) name: String,
    pub(super) forge_url: String,
}
#[derive(Deserialize)]
pub(super) struct Pipeline {
    pub(super) id: i64,
    pub(super) number: u64,
    pub(super) commit: String,
    #[serde(rename = "ref")]
    pub(super) reference: Option<String>,
    pub(super) status: Option<String>,
    #[serde(default)]
    pub(super) errors: Option<Vec<ProviderError>>,
    #[serde(flatten)]
    pub(super) clock: Clock,
    pub(super) workflows: Option<Vec<Workflow>>,
}
#[derive(Deserialize)]
pub(super) struct ProviderError {
    pub(super) message: Option<String>,
}
#[derive(Deserialize)]
pub(super) struct Workflow {
    pub(super) id: i64,
    pub(super) pipeline_id: i64,
    pub(super) pid: i64,
    pub(super) name: Option<String>,
    pub(super) state: Option<String>,
    pub(super) error: Option<String>,
    pub(super) agent_id: Option<i64>,
    #[serde(flatten)]
    pub(super) clock: Clock,
    pub(super) children: Option<Vec<Step>>,
}
#[derive(Deserialize)]
pub(super) struct Step {
    pub(super) id: i64,
    pub(super) pipeline_id: i64,
    pub(super) ppid: i64,
    pub(super) uuid: Option<String>,
    pub(super) name: String,
    pub(super) state: String,
    pub(super) exit_code: Option<i64>,
    pub(super) error: Option<String>,
    #[serde(flatten)]
    pub(super) clock: Clock,
}
#[derive(Deserialize)]
struct Runner {
    id: i64,
    platform: Option<String>,
    backend: Option<String>,
    version: Option<String>,
}

/// Shared exact repository binding; owner/name alone never establish identity.
pub(super) fn validate_repository(
    identity: &Repo,
    repo_id: u64,
    repo: &RepositoryRef,
    forge_base: &str,
) -> Result<(), Failure> {
    let expected = format!(
        "{}/{}/{}",
        forge_base.trim_end_matches('/'),
        repo.owner,
        repo.name
    );
    if identity.id != repo_id
        || identity.owner != repo.owner
        || identity.name != repo.name
        || Origin::parse(&expected).is_err()
        || Origin::parse(&identity.forge_url).is_err()
        || reqwest::Url::parse(&identity.forge_url).ok() != reqwest::Url::parse(&expected).ok()
    {
        return Err(binding());
    }
    Ok(())
}

enum Selection<'a> {
    CurrentHead { expected_sha: &'a str },
    Historical,
}

/// One resolver per CI-details call; credentials and caches never cross requests.
pub(crate) struct Resolver {
    session: Session,
    origin: Origin,
    limits: Limits,
    secrets: Vec<String>,
    forge_base: String,
    pipelines: HashSet<(u64, u64)>,
    runners: HashSet<i64>,
    workflows: usize,
    steps: usize,
    emitted: usize,
    truncated: bool,
    source: Option<(String, Option<String>)>,
}
impl Resolver {
    pub(crate) fn new(
        config: &crate::ForgejoConfig,
        limits: Limits,
    ) -> Result<Option<Self>, Failure> {
        let Some(base) = &config.woodpecker_url else {
            return Ok(None);
        };
        let origin = Origin::parse(base)?;
        Ok(Some(Self {
            session: Session::new(origin.clone(), config.woodpecker_token.clone(), limits)?,
            origin,
            limits,
            secrets: [config.token.clone(), config.woodpecker_token.clone()]
                .into_iter()
                .flatten()
                .collect(),
            forge_base: config.base_url.clone(),
            pipelines: HashSet::new(),
            runners: HashSet::new(),
            workflows: 0,
            steps: 0,
            emitted: 0,
            truncated: false,
            source: None,
        }))
    }

    fn text(&mut self, raw: &str, cap: usize) -> String {
        let secrets: Vec<_> = self.secrets.iter().map(String::as_str).collect();
        let (text, truncated) = safe_text(raw, &secrets, cap);
        self.truncated |= truncated;
        text
    }
    fn optional(&mut self, raw: Option<String>) -> Option<String> {
        raw.map(|s| self.text(&s, self.limits.string_bytes))
    }

    pub(crate) async fn resolve(
        &mut self,
        repo: &RepositoryRef,
        sha: &str,
        target: &str,
    ) -> CiResolution {
        if !self.origin.matches_origin(target) {
            return CiResolution::Unsupported;
        }
        let (repo_id, number) = match self.origin.pipeline(target) {
            Ok(ids) => ids,
            Err(f) => {
                return CiResolution::Error {
                    message: format!("{:?}: {}", f.code, f.message),
                };
            }
        };
        match self
            .evidence(
                repo,
                Selection::CurrentHead { expected_sha: sha },
                repo_id,
                number,
            )
            .await
        {
            Ok(result) => self.bound_output(result),
            Err(f) => CiResolution::Error {
                message: format!("{:?}: {}", f.code, f.message),
            },
        }
    }

    pub(crate) async fn historical(
        &mut self,
        repo: &RepositoryRef,
        selector: domain::HistoricalCiSelector,
    ) -> domain::RepositoryCiDetails {
        if !selector.valid() {
            return selection_failure(selector, &binding());
        }
        match self
            .evidence(
                repo,
                Selection::Historical,
                selector.provider_repository_id,
                selector.pipeline_number,
            )
            .await
        {
            Err(f) => selection_failure(selector, &f),
            Ok(evidence) => {
                let Some((commit, reference)) = self.source.take() else {
                    return selection_failure(selector, &binding());
                };
                let mut response = domain::RepositoryCiDetails {
                    evidence_kind: domain::CiEvidenceKind::Historical,
                    selector: selector.clone(),
                    outcome: domain::HistoricalCiOutcome::Selected {
                        commit,
                        reference,
                        evidence: Box::new(evidence),
                    },
                };
                // Reserve the entire envelope's escaped JSON overhead before bounding evidence.
                let full_size = serde_json::to_vec(&response).map_or(usize::MAX, |v| v.len());
                if let domain::HistoricalCiOutcome::Selected { evidence, .. } =
                    &mut response.outcome
                {
                    let nested_size = serde_json::to_vec(&evidence).map_or(0, |v| v.len());
                    let overhead = full_size.saturating_sub(nested_size);
                    self.limits.output_bytes = self.limits.output_bytes.saturating_sub(overhead);
                    **evidence = self.bound_output((**evidence).clone());
                    if !matches!(**evidence, CiResolution::Resolved { .. }) {
                        return selection_failure(selector, &limit());
                    }
                }
                response
            }
        }
    }

    // Keep authorization, metadata capture and enrichment in visible order.
    #[allow(clippy::too_many_lines)]
    async fn evidence(
        &mut self,
        repo: &RepositoryRef,
        selection: Selection<'_>,
        repo_id: u64,
        number: u64,
    ) -> Result<CiResolution, Failure> {
        if !self.pipelines.contains(&(repo_id, number))
            && self.pipelines.len() >= self.limits.pipelines
        {
            return Err(limit());
        }
        self.pipelines.insert((repo_id, number));
        let identity: Repo = self.session.json(Resource::Repository(repo_id)).await?;
        validate_repository(&identity, repo_id, repo, &self.forge_base)?;
        let pipeline: Pipeline = self
            .session
            .json(Resource::Pipeline(repo_id, number))
            .await?;
        if pipeline.id <= 0 || pipeline.number != number {
            return Err(binding());
        }
        if let Selection::CurrentHead { expected_sha } = selection
            && (expected_sha.is_empty() || pipeline.commit != expected_sha)
        {
            return Err(binding());
        }
        let mut source_incomplete = false;
        if matches!(selection, Selection::Historical) {
            let commit = self.text(&pipeline.commit, self.limits.string_bytes);
            if commit.trim().is_empty() || commit != pipeline.commit {
                return Err(Failure {
                    code: Code::MalformedResponse,
                    status: None,
                    message: "Historical pipeline commit is missing or cannot be represented exactly",
                });
            }
            let reference = pipeline.reference.and_then(|raw| {
                let safe = self.text(&raw, self.limits.string_bytes);
                (safe == raw && !safe.trim().is_empty()).then_some(safe)
            });
            source_incomplete =
                reference.is_none() || pipeline.status.as_ref().is_none_or(|s| s.trim().is_empty());
            self.source = Some((commit, reference));
        }
        let id = pipeline.id;
        let mut evidence = WoodpeckerPipelineEvidence {
            repository_id: i64::try_from(repo_id).map_err(|_| binding())?,
            id,
            number: i64::try_from(number).map_err(|_| binding())?,
            status: self.optional(pipeline.status),
            errors: Vec::new(),
            timestamps: pipeline.clock.into(),
            workflows: Vec::new(),
            runners: Vec::new(),
            diagnostics: vec![diagnostic(
                Component::Termination,
                &Failure {
                    code: Code::NotExposed,
                    status: None,
                    message: "The Woodpecker v3.11 API does not expose historical termination, resource usage or host/container logs; current runner metadata cannot establish a failure cause",
                },
                id,
                None,
                None,
                None,
            )],
        };
        if source_incomplete {
            evidence.diagnostics.push(diagnostic(
                Component::Pipeline,
                &Failure {
                    code: Code::MalformedResponse,
                    status: None,
                    message: "Historical source ref or provider state is unknown",
                },
                id,
                None,
                None,
                None,
            ));
        }
        let errors = pipeline.errors.unwrap_or_default();
        if errors.len() > 64 {
            self.truncated = true;
        }
        for error in errors.into_iter().take(64) {
            if let Some(message) = error.message {
                evidence
                    .errors
                    .push(self.text(&message, self.limits.string_bytes));
            }
        }
        let mut failed_steps = Vec::new();
        let mut workflow_ids = HashSet::new();
        let mut workflow_positions = HashSet::new();
        let mut step_ids = HashSet::new();
        let mut local_runners = HashSet::new();
        for workflow in pipeline.workflows.unwrap_or_default() {
            if self.workflows >= self.limits.workflows {
                self.truncated = true;
                break;
            }
            self.workflows += 1;
            if workflow.id <= 0
                || workflow.pid <= 0
                || workflow.pipeline_id != id
                || !workflow_ids.insert(workflow.id)
                || !workflow_positions.insert(workflow.pid)
            {
                evidence.diagnostics.push(diagnostic(
                    Component::Workflow,
                    &binding(),
                    id,
                    None,
                    None,
                    None,
                ));
                continue;
            }
            let children = workflow.children.unwrap_or_default();
            if children.iter().any(|s| {
                s.id <= 0 || s.pipeline_id != id || s.ppid != workflow.pid || !step_ids.insert(s.id)
            }) {
                evidence.diagnostics.push(diagnostic(
                    Component::Workflow,
                    &binding(),
                    id,
                    Some(workflow.id),
                    None,
                    None,
                ));
                continue;
            }
            let wid = workflow.id;
            let runner_id = workflow.agent_id.filter(|n| *n > 0);
            evidence.workflows.push(WoodpeckerWorkflowEvidence {
                id: wid,
                name: self.optional(workflow.name),
                state: self.optional(workflow.state),
                error: self.optional(workflow.error),
                runner_id,
                timestamps: workflow.clock.into(),
            });
            if let Some(runner) = runner_id.filter(|r| local_runners.insert(*r)) {
                if !self.runners.contains(&runner) && self.runners.len() >= self.limits.runners {
                    self.truncated = true;
                } else {
                    self.runners.insert(runner);
                    match self
                        .session
                        .json::<Runner>(Resource::Runner(runner.cast_unsigned()))
                        .await
                    {
                        Ok(r) if r.id == runner => {
                            evidence.runners.push(WoodpeckerRunnerEvidence {
                                id: r.id,
                                platform: self.optional(r.platform),
                                backend: self.optional(r.backend),
                                version: self.optional(r.version),
                            });
                        }
                        result => {
                            let f = result.err().unwrap_or_else(binding);
                            evidence.diagnostics.push(diagnostic(
                                Component::Runner,
                                &f,
                                id,
                                Some(wid),
                                None,
                                Some(runner),
                            ));
                        }
                    }
                }
            }
            for step in children {
                if self.steps >= self.limits.steps {
                    self.truncated = true;
                    break;
                }
                self.steps += 1;
                if !matches!(step.state.as_str(), "failure" | "error") {
                    continue;
                }
                let mut step_evidence = WoodpeckerStepEvidence {
                    workflow_id: wid,
                    id: step.id,
                    uuid: self.optional(step.uuid),
                    exit_code: step.exit_code,
                    error: self.optional(step.error),
                    timestamps: step.clock.into(),
                    diagnostics: Vec::new(),
                };
                let logs = self
                    .logs(
                        repo_id,
                        number,
                        id,
                        wid,
                        step.id,
                        &mut step_evidence.diagnostics,
                    )
                    .await;
                failed_steps.push(CiFailureStep {
                    name: self.text(&step.name, self.limits.string_bytes),
                    state: self.text(&step.state, 64),
                    log_excerpt: logs,
                    woodpecker: Some(step_evidence),
                });
            }
        }
        if self.truncated {
            evidence.diagnostics.push(diagnostic(
                Component::Operation,
                &limit(),
                id,
                None,
                None,
                None,
            ));
            self.truncated = false;
        }
        let pipeline_url = self.origin_url(repo_id, number)?;
        Ok(CiResolution::Resolved {
            provider: CiProvider::Woodpecker,
            pipeline_url,
            failed_steps,
            woodpecker: Some(Box::new(evidence)),
        })
    }

    fn origin_url(&self, repo: u64, number: u64) -> Result<String, Failure> {
        self.origin.pipeline_url(repo, number)
    }

    async fn logs(
        &mut self,
        repo: u64,
        number: u64,
        pipeline: i64,
        workflow: i64,
        step: i64,
        diagnostics: &mut Vec<CiDiagnostic>,
    ) -> Option<CiLogExcerpt> {
        let logs = self
            .session
            .json::<Vec<Value>>(Resource::Logs(repo, number, step.cast_unsigned()))
            .await;
        let entries = match logs {
            Ok(entries) => entries,
            Err(f) => {
                diagnostics.push(diagnostic(
                    Component::StepLogs,
                    &f,
                    pipeline,
                    Some(workflow),
                    Some(step),
                    None,
                ));
                return None;
            }
        };
        let mut lines = Vec::new();
        let mut malformed = false;
        let mut limited = false;
        if entries.len() > self.limits.excerpt_entries {
            self.truncated = true;
            limited = true;
        }
        for entry in entries.iter().rev().take(self.limits.excerpt_entries) {
            let Some(object) = entry.as_object() else {
                malformed = true;
                continue;
            };
            let Some(value) = object.get("data").filter(|v| !v.is_null()) else {
                continue;
            };
            let Some(data) = value.as_str() else {
                malformed = true;
                continue;
            };
            match base64::prelude::BASE64_STANDARD.decode(data.trim()) {
                Ok(bytes) => {
                    let text =
                        self.text(&String::from_utf8_lossy(&bytes), self.limits.excerpt_bytes);
                    if !text.trim().is_empty() {
                        lines.push(text);
                    }
                }
                Err(_) => malformed = true,
            }
        }
        if limited {
            diagnostics.push(diagnostic(
                Component::StepLogs,
                &limit(),
                pipeline,
                Some(workflow),
                Some(step),
                None,
            ));
        }
        if malformed {
            diagnostics.push(diagnostic(Component::StepLogs, &Failure { code: Code::MalformedResponse,
            status: None, message: "Some Woodpecker log entries could not be decoded; valid excerpts are retained" }, pipeline, Some(workflow), Some(step), None));
        }
        if lines.is_empty() {
            diagnostics.push(diagnostic(
                Component::StepLogs,
                &Failure {
                    code: Code::EmptyLogs,
                    status: None,
                    message: "No usable Woodpecker log output",
                },
                pipeline,
                Some(workflow),
                Some(step),
                None,
            ));
            None
        } else {
            lines.reverse();
            Some(CiLogExcerpt { lines })
        }
    }

    fn bound_output(&mut self, mut result: CiResolution) -> CiResolution {
        let remaining = self.limits.output_bytes.saturating_sub(self.emitted);
        // Serialize to measure escaped JSON too. Remove optional evidence in a
        // deterministic order, retaining identity and an explicit incomplete marker.
        let mut marked = false;
        loop {
            let size = serde_json::to_vec(&result).map_or(usize::MAX, |v| v.len());
            if size <= remaining {
                self.emitted += size;
                return result;
            }
            let CiResolution::Resolved {
                failed_steps,
                woodpecker: Some(e),
                ..
            } = &mut result
            else {
                break;
            };
            if !marked {
                e.diagnostics.push(diagnostic(
                    Component::Operation,
                    &limit(),
                    e.id,
                    None,
                    None,
                    None,
                ));
                marked = true;
            }
            if let Some(step) = failed_steps
                .iter_mut()
                .rev()
                .find(|s| s.log_excerpt.is_some())
            {
                step.log_excerpt = None;
            } else if failed_steps.pop().is_some()
                || e.workflows.pop().is_some()
                || e.runners.pop().is_some()
                || e.errors.pop().is_some()
            {
            } else {
                break;
            }
        }
        CiResolution::Error {
            message: "limit_exceeded: Woodpecker output budget exhausted".to_owned(),
        }
    }
}
pub(crate) fn selection_failure(
    selector: domain::HistoricalCiSelector,
    failure: &Failure,
) -> domain::RepositoryCiDetails {
    let mut d = diagnostic(Component::Pipeline, failure, 0, None, None, None);
    d.pipeline_id = None;
    domain::RepositoryCiDetails {
        evidence_kind: domain::CiEvidenceKind::Historical,
        selector,
        outcome: domain::HistoricalCiOutcome::SelectionDiagnostic { diagnostic: d },
    }
}
fn binding() -> Failure {
    Failure {
        code: Code::BindingMismatch,
        status: None,
        message: "Woodpecker repository, pipeline, head or child identity could not be verified",
    }
}
fn limit() -> Failure {
    Failure {
        code: Code::LimitExceeded,
        status: None,
        message: "Woodpecker diagnostic evidence is incomplete because an operation limit was reached",
    }
}
fn diagnostic(
    component: Component,
    failure: &Failure,
    pipeline: i64,
    workflow: Option<i64>,
    step: Option<i64>,
    runner: Option<i64>,
) -> CiDiagnostic {
    CiDiagnostic {
        component,
        code: failure.code.clone(),
        message: failure.message.to_owned(),
        http_status: failure.status,
        pipeline_id: Some(pipeline),
        workflow_id: workflow,
        step_id: step,
        runner_id: runner,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn fixture(name: &str) -> Value {
        let raw = match name {
            "repo" => include_str!("../tests/fixtures/woodpecker-v3.11.0/repository.json"),
            "pipeline" => include_str!("../tests/fixtures/woodpecker-v3.11.0/exit-255.json"),
            "workflow" => include_str!("../tests/fixtures/woodpecker-v3.11.0/workflow-only.json"),
            "runner" => include_str!("../tests/fixtures/woodpecker-v3.11.0/agent.json"),
            "passing" => include_str!("../tests/fixtures/woodpecker-v3.11.0/logs-passing.json"),
            "partial" => include_str!("../tests/fixtures/woodpecker-v3.11.0/logs-partial.json"),
            "nullable" => include_str!("../tests/fixtures/woodpecker-v3.11.0/logs-nullable.json"),
            _ => unreachable!(),
        };
        serde_json::from_str(raw).expect("fixture")
    }
    fn repository() -> RepositoryRef {
        RepositoryRef {
            alias: "test".into(),
            forge: domain::ForgeKind::Forgejo,
            host: "forge.example.invalid".into(),
            owner: "fixture-owner".into(),
            name: "fixture-repo".into(),
        }
    }
    fn resolver(server: &MockServer, token: Option<&str>, limits: Limits) -> Resolver {
        Resolver::new(
            &crate::ForgejoConfig {
                base_url: "https://forge.example.invalid".into(),
                token: Some("FORGE_SECRET".into()),
                woodpecker_url: Some(server.uri()),
                woodpecker_token: token.map(str::to_owned),
            },
            limits,
        )
        .expect("resolver")
        .expect("configured")
    }
    async fn mount(server: &MockServer, route: &str, body: Value) {
        Mock::given(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
    async fn setup(server: &MockServer, pipeline: Value) {
        mount(server, "/api/repos/29", fixture("repo")).await;
        mount(server, "/api/repos/29/pipelines/42", pipeline).await;
    }
    async fn resolve(resolver: &mut Resolver, server: &MockServer) -> Value {
        serde_json::to_value(
            resolver
                .resolve(
                    &repository(),
                    SHA,
                    &format!("{}/repos/29/pipeline/42", server.uri()),
                )
                .await,
        )
        .expect("serialize")
    }

    fn selector() -> domain::HistoricalCiSelector {
        domain::HistoricalCiSelector {
            provider: "woodpecker".into(),
            provider_repository_id: 29,
            pipeline_number: 42,
        }
    }
    #[tokio::test]
    async fn historical_keeps_actual_identity_for_every_provider_state_without_current_reads() {
        for state in ["failure", "pending", "success"] {
            let server = MockServer::start().await;
            let mut p = fixture("pipeline");
            p["commit"] = "old-selected-commit".into();
            p["ref"] = "refs/heads/old".into();
            p["status"] = state.into();
            if state != "failure" {
                p["workflows"] = serde_json::json!([]);
            }
            setup(&server, p).await;
            mount(&server, "/api/repos/29/logs/42/7001", fixture("passing")).await;
            let response = resolver(&server, None, Limits::default())
                .historical(&repository(), selector())
                .await;
            let json = serde_json::to_value(response).expect("serialize");
            assert_eq!(json["evidence_kind"], "historical");
            assert_eq!(json["outcome"]["commit"], "old-selected-commit");
            assert_eq!(json["outcome"]["reference"], "refs/heads/old");
            assert_eq!(json["outcome"]["evidence"]["woodpecker"]["status"], state);
            assert_eq!(json["outcome"]["evidence"]["woodpecker"]["number"], 42);
            assert_ne!(json["outcome"]["evidence"]["woodpecker"]["id"], 42);
            assert!(json.get("head_sha").is_none());
            for request in server.received_requests().await.expect("requests") {
                assert!(
                    request.url.path() == "/api/repos/29"
                        || request.url.path().starts_with("/api/repos/29/")
                );
            }
        }
    }
    #[tokio::test]
    async fn adapter_historical_248_ignores_retry_249_and_changed_head() {
        use crate::ForgeAdapter;
        for latest in ["pending", "success"] {
            let ci = MockServer::start().await;
            let forge = MockServer::start().await;
            let mut repo = fixture("repo");
            repo["forge_url"] = format!("{}/fixture-owner/fixture-repo", forge.uri()).into();
            mount(&ci, "/api/repos/29", repo).await;
            let mut pipeline = fixture("pipeline");
            pipeline["number"] = 248.into();
            pipeline["commit"] = "historical-source".into();
            pipeline["ref"] = "refs/heads/historical".into();
            mount(&ci, "/api/repos/29/pipelines/248", pipeline).await;
            mount(&ci, "/api/repos/29/logs/248/7001", fixture("passing")).await;
            mount(
                &forge,
                "/api/v1/repos/fixture-owner/fixture-repo/pulls/1",
                serde_json::json!({"head":{"sha":"changed-head"}}),
            )
            .await;
            mount(&forge, "/api/v1/repos/fixture-owner/fixture-repo/commits/changed-head/status",
                serde_json::json!({"state":latest,"target_url":format!("{}/repos/29/pipeline/249",ci.uri())})).await;
            let adapter = crate::ForgejoAdapter::new(crate::ForgejoConfig {
                base_url: forge.uri(),
                token: Some("FORGE_SECRET".into()),
                woodpecker_url: Some(ci.uri()),
                woodpecker_token: None,
            })
            .expect("adapter");
            let mut selection = selector();
            selection.pipeline_number = 248;
            let response = adapter
                .get_repository_ci_details(
                    &repository(),
                    selection,
                    &domain::ForgeCredential {
                        token: Some("FORGE_SECRET".into()),
                    },
                )
                .await
                .expect("historical");
            let json = serde_json::to_value(response).expect("json");
            assert_eq!(json["outcome"]["commit"], "historical-source");
            assert_eq!(json["outcome"]["reference"], "refs/heads/historical");
            assert_eq!(json["outcome"]["evidence"]["woodpecker"]["number"], 248);
            assert!(json["outcome"]["evidence"]["failed_steps"][0]["log_excerpt"].is_object());
            assert!(
                forge
                    .received_requests()
                    .await
                    .expect("requests")
                    .is_empty()
            );
            assert!(
                ci.received_requests()
                    .await
                    .expect("requests")
                    .iter()
                    .all(|r| !r.url.path().contains("249")
                        && !r.headers.contains_key("authorization"))
            );
        }
    }
    #[tokio::test]
    async fn current_head_still_requires_nonempty_exact_sha() {
        let server = MockServer::start().await;
        setup(&server, fixture("pipeline")).await;
        for sha in ["", "different"] {
            let response = resolver(&server, None, Limits::default())
                .resolve(
                    &repository(),
                    sha,
                    &format!("{}/repos/29/pipeline/42", server.uri()),
                )
                .await;
            assert!(matches!(response, CiResolution::Error { .. }));
        }
        assert!(
            server
                .received_requests()
                .await
                .expect("requests")
                .iter()
                .all(|r| !r.url.path().contains("logs"))
        );
    }
    #[tokio::test]
    async fn historical_selection_failures_are_typed_and_suppress_enrichment() {
        for (status, code) in [
            (401, "authorization_denied"),
            (403, "authorization_denied"),
            (404, "resource_not_found"),
            (429, "unavailable"),
            (503, "unavailable"),
        ] {
            let server = MockServer::start().await;
            mount(&server, "/api/repos/29", fixture("repo")).await;
            Mock::given(path("/api/repos/29/pipelines/42"))
                .respond_with(ResponseTemplate::new(status).set_body_string("SENTINEL"))
                .mount(&server)
                .await;
            let response = resolver(&server, None, Limits::default())
                .historical(&repository(), selector())
                .await;
            let json = serde_json::to_value(response).expect("json");
            assert_eq!(json["outcome"]["type"], "selection_diagnostic");
            assert_eq!(json["outcome"]["diagnostic"]["code"], code);
            assert_eq!(json["outcome"]["diagnostic"]["http_status"], status);
            assert!(!json.to_string().contains("SENTINEL"));
            assert_eq!(server.received_requests().await.expect("requests").len(), 2);
        }
    }
    #[tokio::test]
    async fn historical_source_binding_and_complete_envelope_limits() {
        for mutation in 0..7 {
            let server = MockServer::start().await;
            let mut repo = fixture("repo");
            let mut p = fixture("pipeline");
            match mutation {
                0 => repo["forge_url"] = "https://other.invalid/fixture-owner/fixture-repo".into(),
                1 => p["number"] = 43.into(),
                2 => p["commit"] = "".into(),
                3 => p["commit"] = "終".repeat(5000).into(),
                4 => {
                    p["ref"] = serde_json::Value::Null;
                    p["status"] = serde_json::Value::Null;
                }
                5 => p["ref"] = "終".repeat(5000).into(),
                _ => p["workflows"][0]["name"] = "終".repeat(5000).into(),
            }
            mount(&server, "/api/repos/29", repo).await;
            mount(&server, "/api/repos/29/pipelines/42", p).await;
            mount(&server, "/api/repos/29/logs/42/7001", fixture("passing")).await;
            let limits = Limits {
                output_bytes: 2400,
                ..Limits::default()
            };
            let response = resolver(&server, None, limits)
                .historical(&repository(), selector())
                .await;
            let json = serde_json::to_value(response).expect("json");
            assert!(serde_json::to_vec(&json).expect("json").len() <= limits.output_bytes);
            if mutation < 4 {
                assert_eq!(json["outcome"]["type"], "selection_diagnostic");
                assert!(
                    server
                        .received_requests()
                        .await
                        .expect("requests")
                        .iter()
                        .all(|r| !r.url.path().contains("logs"))
                );
            } else {
                assert_eq!(json["outcome"]["type"], "selected");
                assert!(json.to_string().contains(if mutation == 6 {
                    "limit_exceeded"
                } else {
                    "malformed_response"
                }));
            }
        }
    }

    #[tokio::test]
    async fn exit_255_partial_evidence_secrets_and_request_local_reuse() {
        let server = MockServer::start().await;
        let mut pipeline = fixture("pipeline");
        pipeline["workflows"][0]["error"] = "FORGE_SECRET CI_SECRET".into();
        setup(&server, pipeline).await;
        mount(&server, "/api/repos/29/logs/42/7001", fixture("passing")).await;
        Mock::given(path("/api/agents/17"))
            .and(header("Authorization", "Bearer CI_SECRET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fixture("runner")))
            .expect(1)
            .mount(&server)
            .await;
        let mut r = resolver(&server, Some("CI_SECRET"), Limits::default());
        let first = resolve(&mut r, &server).await;
        assert_eq!(first["type"], "resolved");
        assert_eq!(first["failed_steps"][0]["state"], "failure");
        assert_eq!(first["failed_steps"][0]["woodpecker"]["exit_code"], 255);
        assert_eq!(first["failed_steps"][0]["woodpecker"]["id"], 7001);
        assert!(
            first["failed_steps"][0]["log_excerpt"]["lines"][0]
                .as_str()
                .expect("line")
                .contains("passed")
        );
        assert_eq!(first["woodpecker"]["workflows"][0]["runner_id"], 17);
        assert_eq!(first["woodpecker"]["diagnostics"][0]["code"], "not_exposed");
        assert_eq!(first["woodpecker"]["runners"][0]["version"], "3.11.0");
        let serialized = first.to_string();
        for secret in [
            "SENTINEL",
            "FORGE_SECRET",
            "CI_SECRET",
            "custom_labels",
            "authorization",
        ] {
            assert!(!serialized.contains(secret));
        }
        assert_eq!(resolve(&mut r, &server).await, first);
        assert_eq!(server.received_requests().await.expect("requests").len(), 4);
    }
    #[tokio::test]
    async fn logs_fail_independently_without_erasing_metadata() {
        for (body, code, has_logs) in [
            (fixture("nullable"), "empty_logs", false),
            (fixture("partial"), "malformed_response", true),
            (serde_json::json!([]), "empty_logs", false),
            (serde_json::json!([{"data":8}]), "malformed_response", false),
        ] {
            let server = MockServer::start().await;
            setup(&server, fixture("pipeline")).await;
            mount(&server, "/api/repos/29/logs/42/7001", body).await;
            let result = resolve(&mut resolver(&server, None, Limits::default()), &server).await;
            let step = &result["failed_steps"][0];
            assert_eq!(result["type"], "resolved");
            assert_eq!(step["log_excerpt"].is_object(), has_logs);
            assert!(
                step["woodpecker"]["diagnostics"]
                    .as_array()
                    .expect("diagnostics")
                    .iter()
                    .any(|d| d["code"] == code)
            );
            assert_eq!(
                result["woodpecker"]["diagnostics"][1]["code"],
                "credential_missing"
            );
            assert_eq!(server.received_requests().await.expect("requests").len(), 3);
        }
    }
    #[tokio::test]
    async fn log_http_errors_and_runner_denial_keep_identity() {
        for (status, code) in [
            (401, "authorization_denied"),
            (403, "authorization_denied"),
            (404, "resource_not_found"),
            (429, "unavailable"),
            (500, "unavailable"),
        ] {
            let server = MockServer::start().await;
            setup(&server, fixture("pipeline")).await;
            for route in ["/api/agents/17", "/api/repos/29/logs/42/7001"] {
                Mock::given(path(route))
                    .respond_with(ResponseTemplate::new(status).set_body_string("SENTINEL_SECRET"))
                    .mount(&server)
                    .await;
            }
            let result = resolve(
                &mut resolver(&server, Some("CI_SECRET"), Limits::default()),
                &server,
            )
            .await;
            assert_eq!(result["type"], "resolved");
            assert_eq!(result["woodpecker"]["diagnostics"][1]["code"], code);
            assert_eq!(
                result["failed_steps"][0]["woodpecker"]["diagnostics"][0]["http_status"],
                status
            );
            assert!(!result.to_string().contains("SENTINEL"));
        }
    }
    #[tokio::test]
    async fn binding_mismatches_suppress_all_enrichment() {
        for mutation in 0..8 {
            let server = MockServer::start().await;
            let mut repo = fixture("repo");
            let mut pipeline = fixture("pipeline");
            match mutation {
                0 => repo["id"] = 30.into(),
                1 => repo["forge_url"] = "https://wrong.example/fixture-owner/fixture-repo".into(),
                2 => repo["name"] = "other".into(),
                3 => pipeline["commit"] = "merge-sha".into(),
                4 => pipeline["number"] = 43.into(),
                5 => pipeline["workflows"][0]["pipeline_id"] = 999.into(),
                6 => pipeline["workflows"][0]["children"][0]["pipeline_id"] = 999.into(),
                _ => pipeline["workflows"][0]["children"][0]["ppid"] = 999.into(),
            }
            mount(&server, "/api/repos/29", repo).await;
            mount(&server, "/api/repos/29/pipelines/42", pipeline).await;
            let result = resolve(
                &mut resolver(&server, Some("CI_SECRET"), Limits::default()),
                &server,
            )
            .await;
            assert!(result.to_string().to_lowercase().contains("binding"));
            for request in server.received_requests().await.expect("requests") {
                assert!(!request.url.path().contains("agents"));
                assert!(!request.url.path().contains("logs"));
            }
        }
    }
    #[tokio::test]
    async fn workflow_only_zero_timestamps_and_runner_response_identity() {
        let server = MockServer::start().await;
        let mut pipeline = fixture("workflow");
        pipeline["number"] = 42.into();
        setup(&server, pipeline).await;
        let mut runner = fixture("runner");
        runner["id"] = 18.into();
        mount(&server, "/api/agents/17", runner).await;
        let result = resolve(
            &mut resolver(&server, Some("CI_SECRET"), Limits::default()),
            &server,
        )
        .await;
        assert_eq!(result["type"], "resolved");
        assert_eq!(result["failed_steps"], serde_json::json!([]));
        assert_eq!(result["woodpecker"]["timestamps"]["started"], 0);
        assert!(
            result["woodpecker"]["workflows"][0]["timestamps"]
                .as_object()
                .expect("timestamps")
                .is_empty()
        );
        assert_eq!(
            result["woodpecker"]["diagnostics"][1]["code"],
            "binding_mismatch"
        );
        assert_eq!(result["woodpecker"]["runners"], serde_json::json!([]));
        assert!(!result.to_string().contains("SENTINEL"));
    }
    #[tokio::test]
    async fn unicode_collection_output_and_request_limits_are_explicit() {
        for limits in [
            Limits {
                workflows: 0,
                ..Limits::default()
            },
            Limits {
                steps: 0,
                ..Limits::default()
            },
            Limits {
                runners: 0,
                ..Limits::default()
            },
            Limits {
                requests: 2,
                ..Limits::default()
            },
            Limits {
                output_bytes: 1800,
                ..Limits::default()
            },
            Limits {
                excerpt_bytes: 5,
                ..Limits::default()
            },
        ] {
            let server = MockServer::start().await;
            let mut pipeline = fixture("pipeline");
            pipeline["workflows"][0]["name"] = "終".repeat(5000).into();
            setup(&server, pipeline).await;
            mount(&server, "/api/repos/29/logs/42/7001", fixture("passing")).await;
            let result = resolve(&mut resolver(&server, None, limits), &server).await;
            assert!(result.to_string().contains("limit_exceeded"));
            assert!(serde_json::to_vec(&result).expect("json").len() <= limits.output_bytes);
        }
    }
    #[tokio::test]
    async fn adapter_shares_session_and_preserves_failure_states() {
        use crate::ForgeAdapter;
        let ci = MockServer::start().await;
        let forge = MockServer::start().await;
        let mut repo = fixture("repo");
        repo["forge_url"] = format!("{}/fixture-owner/fixture-repo", forge.uri()).into();
        mount(&ci, "/api/repos/29", repo).await;
        mount(&ci, "/api/repos/29/pipelines/42", fixture("pipeline")).await;
        mount(&ci, "/api/repos/29/logs/42/7001", fixture("passing")).await;
        let check = serde_json::json!({"context":"ci/woodpecker", "status":"failure",
            "target_url":format!("{}/repos/29/pipeline/42",ci.uri())});
        mount(&forge,&format!("/api/v1/repos/fixture-owner/fixture-repo/commits/{SHA}/status"),
            serde_json::json!({"state":"failure","sha":SHA,"total_count":2,"statuses":[check.clone(),check]})).await;
        let adapter = crate::ForgejoAdapter::new(crate::ForgejoConfig {
            base_url: forge.uri(),
            token: Some("FORGE_SECRET".into()),
            woodpecker_url: Some(ci.uri()),
            woodpecker_token: None,
        })
        .expect("adapter");
        let response = adapter
            .get_change_request_ci_details(
                &repository(),
                SHA,
                &domain::ForgeCredential {
                    token: Some("FORGE_SECRET".into()),
                },
            )
            .await
            .expect("details");
        assert_eq!(response.state, domain::CommitStatusState::Failure);
        assert_eq!(response.details.len(), 2);
        for check in response.details {
            assert_eq!(check.state, domain::CommitStatusState::Failure);
            assert!(matches!(check.resolution, CiResolution::Resolved { .. }));
        }
        assert_eq!(ci.received_requests().await.expect("requests").len(), 3);
        for request in ci.received_requests().await.expect("requests") {
            assert!(request.headers.get("authorization").is_none());
        }
    }
    #[tokio::test]
    async fn malformed_logs_and_mixed_siblings_retain_metadata_and_valid_output() {
        let server = MockServer::start().await;
        let mut pipeline = fixture("pipeline");
        let mut second = pipeline["workflows"][0]["children"][0].clone();
        second["id"] = 7002.into();
        pipeline["workflows"][0]["children"]
            .as_array_mut()
            .expect("children")
            .push(second);
        setup(&server, pipeline).await;
        mount(&server, "/api/repos/29/logs/42/7001", fixture("passing")).await;
        Mock::given(path("/api/repos/29/logs/42/7002"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{"))
            .mount(&server)
            .await;
        let result = resolve(&mut resolver(&server, None, Limits::default()), &server).await;
        assert_eq!(result["failed_steps"].as_array().expect("steps").len(), 2);
        assert!(result["failed_steps"][0]["log_excerpt"].is_object());
        assert_eq!(
            result["failed_steps"][1]["woodpecker"]["diagnostics"][0]["code"],
            "malformed_response"
        );
    }
    #[tokio::test]
    async fn multiple_workflows_runners_and_duplicate_ids_keep_associations() {
        let server = MockServer::start().await;
        let mut pipeline = fixture("pipeline");
        let mut second = pipeline["workflows"][0].clone();
        second["id"] = 6002.into();
        second["pid"] = 3.into();
        second["agent_id"] = 18.into();
        second["children"][0]["id"] = 7002.into();
        second["children"][0]["ppid"] = 3.into();
        let mut duplicate = second.clone();
        duplicate["id"] = 6003.into();
        duplicate["pid"] = 4.into();
        duplicate["agent_id"] = 19.into();
        duplicate["children"][0]["ppid"] = 4.into();
        pipeline["workflows"]
            .as_array_mut()
            .expect("workflows")
            .extend([second, duplicate]);
        setup(&server, pipeline).await;
        mount(&server, "/api/repos/29/logs/42/7001", fixture("nullable")).await;
        mount(&server, "/api/repos/29/logs/42/7002", fixture("passing")).await;
        mount(&server, "/api/agents/17", fixture("runner")).await;
        let mut runner = fixture("runner");
        runner["id"] = 18.into();
        mount(&server, "/api/agents/18", runner).await;
        let result = resolve(
            &mut resolver(&server, Some("CI_SECRET"), Limits::default()),
            &server,
        )
        .await;
        assert_eq!(
            result["woodpecker"]["workflows"]
                .as_array()
                .expect("workflows")
                .len(),
            2
        );
        assert_eq!(
            result["woodpecker"]["runners"]
                .as_array()
                .expect("runners")
                .len(),
            2
        );
        assert_eq!(result["failed_steps"][1]["woodpecker"]["workflow_id"], 6002);
        assert_eq!(result["woodpecker"]["workflows"][1]["runner_id"], 18);
        assert!(result.to_string().contains("binding_mismatch"));
        assert!(
            server
                .received_requests()
                .await
                .expect("requests")
                .iter()
                .all(|r| r.url.path() != "/api/agents/19")
        );
    }
    #[tokio::test]
    async fn absent_optional_fields_and_real_zero_values_remain_distinct() {
        let server = MockServer::start().await;
        let pipeline = serde_json::json!({"id":5001,"number":42,"commit":SHA,"workflows":[{
        "id":6001,"pipeline_id":5001,"pid":1,"children":[{
            "id":7001,"pipeline_id":5001,"ppid":1,"name":"verify","state":"error","exit_code":0,"started":0
        }]}]});
        setup(&server, pipeline).await;
        mount(&server, "/api/repos/29/logs/42/7001", fixture("nullable")).await;
        let result = resolve(&mut resolver(&server, None, Limits::default()), &server).await;
        let step = &result["failed_steps"][0]["woodpecker"];
        assert_eq!(step["exit_code"], 0);
        assert_eq!(step["timestamps"]["started"], 0);
        assert!(step.get("uuid").is_none());
        assert!(step["timestamps"].get("finished").is_none());
        assert!(result["woodpecker"].get("status").is_none());
        assert_eq!(server.received_requests().await.expect("requests").len(), 3);
    }
    #[tokio::test]
    async fn log_excerpt_keeps_last_twenty_entries_and_lossy_utf8() {
        let server = MockServer::start().await;
        setup(&server, fixture("pipeline")).await;
        let mut entries:Vec<Value>=(0..25).map(|i|serde_json::json!({"data":base64::prelude::BASE64_STANDARD.encode(format!("line {i}"))})).collect();
        entries.push(serde_json::json!({"data":"/w=="}));
        mount(&server, "/api/repos/29/logs/42/7001", entries.into()).await;
        let result = resolve(&mut resolver(&server, None, Limits::default()), &server).await;
        let lines = &result["failed_steps"][0]["log_excerpt"]["lines"];
        assert_eq!(lines.as_array().expect("lines").len(), 20);
        assert_eq!(lines[0], "line 6");
        assert_eq!(lines[19], "�");
        assert_eq!(
            result["failed_steps"][0]["woodpecker"]["diagnostics"][0]["code"],
            "limit_exceeded"
        );
    }
    #[tokio::test]
    async fn pipeline_and_deadline_limits_keep_validated_evidence() {
        let server = MockServer::start().await;
        setup(&server, fixture("pipeline")).await;
        Mock::given(path("/api/repos/29/logs/42/7001"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(1))
                    .set_body_json(fixture("passing")),
            )
            .mount(&server)
            .await;
        let mut r = resolver(
            &server,
            None,
            Limits {
                pipelines: 1,
                elapsed: std::time::Duration::from_millis(300),
                ..Limits::default()
            },
        );
        let result = resolve(&mut r, &server).await;
        assert_eq!(result["type"], "resolved");
        assert_eq!(result["failed_steps"][0]["woodpecker"]["id"], 7001);
        assert!(result["failed_steps"][0]["log_excerpt"].is_null());
        let second = r
            .resolve(
                &repository(),
                SHA,
                &format!("{}/repos/29/pipeline/43", server.uri()),
            )
            .await;
        assert!(matches!(second, CiResolution::Error { .. }));
        assert!(
            server
                .received_requests()
                .await
                .expect("requests")
                .iter()
                .all(|r| !r.url.path().ends_with("/43"))
        );
    }
}
