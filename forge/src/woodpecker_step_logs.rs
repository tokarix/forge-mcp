//! Focused selection for retained Woodpecker output, without CI enrichment.
//!
//! Selection validates the entire child membership graph before log access. The
//! caller must authorize the forge repository first and use a request-local
//! `Session::for_step_logs` so repository, pipeline and logs share one budget.

use std::collections::HashSet;

use domain::{CiDiagnosticCode, CiStepLogIdentity, CiStepLogSelector, RepositoryRef};

use crate::woodpecker::{Failure, Resource, Session, safe_text};
use crate::woodpecker_resolver::{Pipeline, Repo, validate_repository};

fn failure(code: CiDiagnosticCode, message: &'static str) -> Failure {
    Failure {
        code,
        status: None,
        message,
    }
}
fn binding() -> Failure {
    failure(
        CiDiagnosticCode::BindingMismatch,
        "Selected Woodpecker child identity is not unique or does not belong to the authorized repository pipeline",
    )
}
fn exact(raw: &str, secrets: &[&str], cap: usize) -> Result<String, Failure> {
    let (safe, clipped) = safe_text(raw, secrets, cap);
    if clipped || safe != raw || raw.trim().is_empty() {
        return Err(failure(
            CiDiagnosticCode::MalformedResponse,
            "Selected Woodpecker source or child identity cannot be represented exactly",
        ));
    }
    Ok(safe)
}

/// Validate explicit repository/run/workflow/step selection using two requests.
///
/// No runner, log, latest-head or forge credential lookup occurs here. Workflow
/// and step IDs are database IDs; the step parent is the workflow's provider pid.
/// All duplicate child IDs/positions are rejected before a caller can fetch logs.
/// Source commit and UUID are either represented exactly or selection fails.
///
/// # Errors
/// Returns safe transport, malformed metadata, deadline or binding failures.
pub async fn select_step(
    session: &mut Session,
    repository: &RepositoryRef,
    forge_base: &str,
    selector: CiStepLogSelector,
    secrets: &[&str],
) -> Result<CiStepLogIdentity, Failure> {
    if !selector.valid() || selector.provider != "woodpecker" {
        return Err(binding());
    }
    session.check_deadline()?;
    let repo: Repo = session
        .json(Resource::Repository(selector.provider_repository_id))
        .await?;
    validate_repository(
        &repo,
        selector.provider_repository_id,
        repository,
        forge_base,
    )?;
    let pipeline: Pipeline = session
        .json(Resource::Pipeline(
            selector.provider_repository_id,
            selector.pipeline_number,
        ))
        .await?;
    if pipeline.id <= 0 || pipeline.number != selector.pipeline_number {
        return Err(binding());
    }
    let commit = exact(&pipeline.commit, secrets, 1024)?;
    let reference = pipeline
        .reference
        .and_then(|raw| exact(&raw, secrets, 1024).ok());
    let mut ids = HashSet::new();
    let mut positions = HashSet::new();
    let mut steps = HashSet::new();
    let mut selected = None;
    for workflow in pipeline.workflows.unwrap_or_default() {
        session.check_deadline()?;
        if workflow.id <= 0
            || workflow.pid <= 0
            || workflow.pipeline_id != pipeline.id
            || !ids.insert(workflow.id)
            || !positions.insert(workflow.pid)
        {
            return Err(binding());
        }
        for step in workflow.children.unwrap_or_default() {
            session.check_deadline()?;
            if step.id <= 0
                || step.pipeline_id != pipeline.id
                || step.ppid != workflow.pid
                || !steps.insert(step.id)
            {
                return Err(binding());
            }
            if workflow.id.cast_unsigned() == selector.workflow_id
                && step.id.cast_unsigned() == selector.step_id
            {
                selected = Some((workflow.pid, step));
            }
        }
    }
    let (workflow_pid, step) = selected.ok_or_else(binding)?;
    let identity = CiStepLogIdentity {
        selector,
        pipeline_id: pipeline.id,
        commit,
        reference,
        workflow_pid,
        step_uuid: step
            .uuid
            .map(|raw| exact(&raw, secrets, 1024))
            .transpose()?,
        step_name: safe_text(&step.name, secrets, 1024).0,
        step_state: exact(&step.state, secrets, 64)?,
        timestamps: step.clock.into(),
    };
    session.check_deadline()?;
    Ok(identity)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use domain::ForgeKind;
    use serde_json::{Value, json};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};

    use super::*;
    use crate::woodpecker::{Origin, StepLogTransportLimits};

    fn selector() -> CiStepLogSelector {
        CiStepLogSelector {
            provider: "woodpecker".into(),
            provider_repository_id: 29,
            pipeline_number: 42,
            workflow_id: 6001,
            step_id: 7001,
        }
    }
    fn repository() -> RepositoryRef {
        RepositoryRef {
            alias: "fixture".into(),
            forge: ForgeKind::Forgejo,
            host: "forge.example".into(),
            owner: "fixture-owner".into(),
            name: "fixture-repo".into(),
        }
    }
    fn pipeline() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/woodpecker-v3.11.0/exit-255.json"
        ))
        .expect("fixture")
    }
    async fn mount(server: &MockServer, route: &str, body: Value) {
        Mock::given(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }
    async fn setup(server: &MockServer, pipeline: Value) {
        mount(server, "/api/repos/29", json!({"id":29,"owner":"fixture-owner","name":"fixture-repo", "forge_url":"https://forge.example/fixture-owner/fixture-repo"})).await;
        mount(server, "/api/repos/29/pipelines/42", pipeline).await;
    }
    fn session(server: &MockServer) -> Session {
        Session::for_step_logs(
            Origin::parse(&server.uri()).expect("origin"),
            None,
            StepLogTransportLimits::default(),
        )
        .expect("session")
    }
    async fn select(server: &MockServer) -> Result<CiStepLogIdentity, Failure> {
        select_step(
            &mut session(server),
            &repository(),
            "https://forge.example",
            selector(),
            &["FORGE_SECRET", "CI_SECRET"],
        )
        .await
    }

    #[tokio::test]
    async fn selection_is_independent_of_state_and_never_enriches() {
        for state in [
            "success",
            "failure",
            "error",
            "running",
            "cancelled",
            "skipped",
            "other",
        ] {
            let server = MockServer::start().await;
            let mut p = pipeline();
            p["workflows"][0]["children"][0]["state"] = state.into();
            p["ref"] = Value::Null;
            setup(&server, p.clone()).await;
            let identity = select(&server).await.expect("selection");
            assert_eq!(identity.selector, selector());
            assert_eq!(identity.pipeline_id, 5001);
            assert_eq!(identity.workflow_pid, 1);
            assert_eq!(identity.step_state, state);
            assert_eq!(identity.commit, p["commit"].as_str().expect("commit"));
            assert!(identity.reference.is_none());
            assert_eq!(server.received_requests().await.expect("requests").len(), 2);
        }
    }

    #[tokio::test]
    async fn rejects_mismatches_and_duplicate_graph_without_log_requests() {
        for mutation in 0..13 {
            let server = MockServer::start().await;
            let mut p = pipeline();
            match mutation {
                0 => p["id"] = 0.into(),
                1 => p["number"] = 5001.into(),
                2 => p["workflows"][0]["id"] = 1.into(),
                3 => p["workflows"][0]["pipeline_id"] = 999.into(),
                4 => p["workflows"][0]["pid"] = 0.into(),
                5 => p["workflows"][0]["children"][0]["id"] = 999.into(),
                6 => p["workflows"][0]["children"][0]["pipeline_id"] = 999.into(),
                7 => p["workflows"][0]["children"][0]["ppid"] = 6001.into(),
                8..=10 => {
                    let mut duplicate = p["workflows"][0].clone();
                    if mutation >= 9 {
                        duplicate["id"] = 6002.into();
                    }
                    if mutation == 10 {
                        duplicate["pid"] = 2.into();
                        duplicate["children"][0]["ppid"] = 2.into();
                    }
                    p["workflows"]
                        .as_array_mut()
                        .expect("workflows")
                        .push(duplicate);
                }
                11 => {
                    let child = p["workflows"][0]["children"][0].clone();
                    p["workflows"][0]["children"]
                        .as_array_mut()
                        .expect("children")
                        .push(child);
                }
                _ => p["workflows"] = Value::Null,
            }
            setup(&server, p).await;
            assert_eq!(
                select(&server).await.expect_err("binding").code,
                CiDiagnosticCode::BindingMismatch,
                "mutation {mutation}"
            );
            let requests = server.received_requests().await.expect("requests");
            assert_eq!(requests.len(), 2);
            assert!(
                requests
                    .iter()
                    .all(|r| !r.url.path().contains("logs") && !r.url.path().contains("agents"))
            );
        }
    }

    #[tokio::test]
    async fn rejects_repository_and_invalid_selector_before_downstream_requests() {
        for mutation in 0..6 {
            let server = MockServer::start().await;
            let mut r = json!({"id":29,"owner":"fixture-owner","name":"fixture-repo", "forge_url":"https://forge.example/fixture-owner/fixture-repo"});
            match mutation {
                0 => r["id"] = 30.into(),
                1 => r["owner"] = "other".into(),
                2 => r["name"] = "other".into(),
                3 => r["forge_url"] = "https://other.example/fixture-owner/fixture-repo".into(),
                4 => {
                    r["forge_url"] =
                        "https://user:pass@forge.example/fixture-owner/fixture-repo".into();
                }
                _ => {
                    r["forge_url"] =
                        "https://forge.example/prefix/fixture-owner/fixture-repo".into();
                }
            }
            mount(&server, "/api/repos/29", r).await;
            assert_eq!(
                select(&server).await.expect_err("binding").code,
                CiDiagnosticCode::BindingMismatch
            );
            assert_eq!(server.received_requests().await.expect("requests").len(), 1);
        }
        let server = MockServer::start().await;
        for id in [0, u64::MAX] {
            let mut s = selector();
            s.step_id = id;
            assert!(
                select_step(
                    &mut session(&server),
                    &repository(),
                    "https://forge.example",
                    s,
                    &[]
                )
                .await
                .is_err()
            );
        }
        assert!(
            server
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn identity_is_exact_or_explicitly_unknown_never_clipped() {
        for mutation in 0..5 {
            let server = MockServer::start().await;
            let mut p = pipeline();
            match mutation {
                0 => p["commit"] = "終".repeat(1024).into(),
                1 => p["commit"] = "FORGE_SECRET".into(),
                2 => p["workflows"][0]["children"][0]["uuid"] = "CI_SECRET".into(),
                3 => p["ref"] = "CI_SECRET".into(),
                _ => p["workflows"][0]["children"][0]["name"] = "CI_SECRET".into(),
            }
            setup(&server, p).await;
            let result = select(&server).await;
            if mutation < 3 {
                assert_eq!(
                    result.expect_err("identity").code,
                    CiDiagnosticCode::MalformedResponse
                );
            } else {
                let identity = result.expect("identity");
                if mutation == 3 {
                    assert!(identity.reference.is_none());
                }
                assert!(
                    !serde_json::to_string(&identity)
                        .expect("json")
                        .contains("CI_SECRET")
                );
            }
        }
    }
}
