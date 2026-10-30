//! Focused selection for retained Woodpecker output, without CI enrichment.
//!
//! Selection validates the entire child membership graph before log access. The
//! caller must authorize the forge repository first and use a request-local
//! `Session::for_step_logs` so repository, pipeline and logs share one budget.

use std::collections::HashSet;

use domain::{
    CiDiagnosticCode, CiStepLogDiagnostic, CiStepLogIdentity, CiStepLogOptions, CiStepLogSelector,
    CiStepLogStatus, RepositoryCiStepLogs, RepositoryRef,
};

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

/// Independent transport and decoder limits for one freshly fetched page.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReaderLimits {
    /// Shared identity/log I/O budget.
    pub transport: crate::woodpecker::StepLogTransportLimits,
    /// Full-snapshot parsing and canonicalization budget.
    pub decode: crate::woodpecker_log_decode::DecodeLimits,
}

fn failed(
    selector: CiStepLogSelector,
    identity: Option<CiStepLogIdentity>,
    status: CiStepLogStatus,
    code: &str,
    message: &str,
    http_status: Option<u16>,
) -> RepositoryCiStepLogs {
    let mut page = RepositoryCiStepLogs::unsupported(selector);
    page.provider_step_finished = identity.as_ref().and_then(|i| match i.step_state.as_str() {
        "success" | "failure" | "error" | "killed" | "skipped" | "cancelled" => Some(true),
        "pending" | "running" | "blocked" => Some(false),
        _ => None,
    });
    page.identity = identity;
    page.status = status;
    page.diagnostics = vec![
        CiStepLogDiagnostic {
            code: code.into(),
            message: message.into(),
            record_index: None,
            http_status,
        },
        CiStepLogDiagnostic {
            code: "not_exposed".into(),
            message: "Historical infrastructure diagnostics are not exposed".into(),
            record_index: None,
            http_status: None,
        },
    ];
    page
}

fn retrieval_failure(
    selector: CiStepLogSelector,
    identity: Option<CiStepLogIdentity>,
    failure: &Failure,
) -> RepositoryCiStepLogs {
    let (status, code) = match failure.code {
        CiDiagnosticCode::LimitExceeded => (CiStepLogStatus::RetrievalLimit, "retrieval_limit"),
        CiDiagnosticCode::BindingMismatch => (CiStepLogStatus::BindingMismatch, "binding_mismatch"),
        CiDiagnosticCode::MalformedResponse => {
            (CiStepLogStatus::MalformedResponse, "malformed_response")
        }
        CiDiagnosticCode::AuthorizationDenied => {
            (CiStepLogStatus::Unavailable, "authorization_denied")
        }
        CiDiagnosticCode::ResourceNotFound => (CiStepLogStatus::Unavailable, "resource_not_found"),
        CiDiagnosticCode::CredentialMissing => (CiStepLogStatus::Unavailable, "credential_missing"),
        _ => (CiStepLogStatus::Unavailable, "unavailable"),
    };
    failed(
        selector,
        identity,
        status,
        code,
        failure.message,
        failure.status,
    )
}

/// Retrieve one selected historical page with fresh identity and log evidence.
///
/// The caller must authorize `repository` before invoking this operation. Only
/// the configured CI credential is sent upstream. All known forge credentials
/// participate in redaction, including a request-specific gateway credential.
/// There is no cross-request cache, retry, runner lookup or state-based gate.
///
/// # Errors
/// Invalid selectors/options and budgets too small for a scalar or redaction
/// unit are input errors. Provider failures return a safe typed envelope.
#[allow(clippy::too_many_lines)]
pub async fn read(
    config: &crate::ForgejoConfig,
    repository: &RepositoryRef,
    selector: CiStepLogSelector,
    options: &CiStepLogOptions,
    credential: &domain::ForgeCredential,
    limits: ReaderLimits,
) -> Result<RepositoryCiStepLogs, crate::ForgeError> {
    if !selector.valid() {
        return Err(crate::ForgeError::InvalidPayload(
            "Step log selectors must be positive signed 64-bit integers".into(),
        ));
    }
    options
        .validate()
        .map_err(|message| crate::ForgeError::InvalidPayload(message.into()))?;
    if selector.provider != "woodpecker" {
        return Ok(RepositoryCiStepLogs::unsupported(selector));
    }
    let Some(base) = &config.woodpecker_url else {
        return Ok(RepositoryCiStepLogs::unsupported(selector));
    };
    let origin = match crate::woodpecker::Origin::parse(base) {
        Ok(origin) => origin,
        Err(failure) => return Ok(retrieval_failure(selector, None, &failure)),
    };
    let mut session = match Session::for_step_logs(
        origin.clone(),
        config.woodpecker_token.clone(),
        limits.transport,
    ) {
        Ok(session) => session,
        Err(failure) => return Ok(retrieval_failure(selector, None, &failure)),
    };
    let secrets: Vec<_> = [
        config.token.as_deref(),
        config.woodpecker_token.as_deref(),
        credential.token.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();
    let identity = match select_step(
        &mut session,
        repository,
        &config.base_url,
        selector.clone(),
        &secrets,
    )
    .await
    {
        Ok(identity) => identity,
        Err(failure) => return Ok(retrieval_failure(selector, None, &failure)),
    };
    let raw = match session
        .step_log_body(
            selector.provider_repository_id,
            selector.pipeline_number,
            selector.step_id,
        )
        .await
    {
        Ok(raw) => raw,
        Err(failure) => return Ok(retrieval_failure(selector, Some(identity), &failure)),
    };
    let records = match crate::woodpecker_log_decode::decode(
        &session,
        &raw,
        identity.step_uuid.as_deref(),
        &secrets,
        limits.decode,
    ) {
        Ok(records) => records,
        Err(failure) => return Ok(retrieval_failure(selector, Some(identity), &failure)),
    };
    let result = crate::woodpecker_log_snapshot::Snapshot::new(
        &session,
        repository,
        &origin,
        identity.clone(),
        &raw,
        records,
        &secrets,
    )
    .and_then(|snapshot| snapshot.page(&session, options));
    match result {
        Ok(page) => Ok(page),
        Err(error) => {
            if let Some(minimum) = error.minimum_page_bytes {
                return Err(crate::ForgeError::InvalidPayload(format!(
                    "page_bytes must be at least {minimum} for the next UTF-8 scalar or redaction unit"
                )));
            }
            let code = match error.status {
                CiStepLogStatus::InvalidCursor => "invalid_cursor",
                CiStepLogStatus::StaleCursor => "stale_cursor",
                CiStepLogStatus::BindingMismatch => "binding_mismatch",
                _ => "retrieval_limit",
            };
            Ok(failed(
                selector,
                Some(identity),
                error.status,
                code,
                error.message,
                None,
            ))
        }
    }
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
    fn config(server: &MockServer) -> crate::ForgejoConfig {
        crate::ForgejoConfig {
            base_url: "https://forge.example".into(),
            token: Some("FORGE_SECRET".into()),
            woodpecker_url: Some(server.uri()),
            woodpecker_token: Some("CI_SECRET".into()),
        }
    }
    async fn read_page(
        server: &MockServer,
        options: CiStepLogOptions,
        limits: ReaderLimits,
    ) -> RepositoryCiStepLogs {
        read(
            &config(server),
            &repository(),
            selector(),
            &options,
            &domain::ForgeCredential {
                token: Some("AGENT_SECRET".into()),
            },
            limits,
        )
        .await
        .expect("reader")
    }
    async fn logs(server: &MockServer, body: Value) {
        mount(server, "/api/repos/29/logs/42/7001", body).await;
    }
    fn output(text: &str) -> Value {
        use base64::Engine;
        json!({"data": base64::prelude::BASE64_STANDARD.encode(text)})
    }

    #[tokio::test]
    async fn reader_traverses_and_rewinds_with_fresh_authority_and_ci_only_credentials() {
        let server = MockServer::start().await;
        setup(&server, pipeline()).await;
        let blocks: Vec<_> = (0..6).map(|i| format!("panic {i}: 終🙂\n")).collect();
        logs(
            &server,
            Value::Array(blocks.iter().map(|s| output(s)).collect()),
        )
        .await;
        let mut options = CiStepLogOptions {
            start: Some(domain::CiLogStart::Tail),
            page_bytes: Some(20),
            cursor: None,
        };
        let tail = read_page(&server, options.clone(), ReaderLimits::default()).await;
        assert_eq!(tail.status, CiStepLogStatus::Available);
        assert!(tail.snapshot_complete);
        options.start = None;
        options.cursor = tail.beginning_cursor;
        let mut actual = String::new();
        let mut pages = 0;
        loop {
            let page = read_page(&server, options.clone(), ReaderLimits::default()).await;
            pages += 1;
            assert_eq!(page.status, CiStepLogStatus::Available);
            assert_eq!(page.identity.as_ref().expect("identity").pipeline_id, 5001);
            for fragment in page.fragments {
                actual.push_str(&fragment.text);
            }
            if page.snapshot_complete {
                assert!(page.next_cursor.is_none());
                break;
            }
            assert!(pages < 100);
            assert_ne!(options.cursor, page.next_cursor);
            options.cursor = page.next_cursor;
        }
        assert_eq!(actual, blocks.concat());
        assert!(pages > 2);
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), (pages + 1) * 3);
        for request in requests {
            assert_eq!(
                request.headers.get("authorization").expect("auth"),
                "Bearer CI_SECRET"
            );
            assert!(!request.url.path().contains("agents"));
        }
    }

    #[tokio::test]
    async fn reader_rejects_changed_log_and_preserves_identity_on_safe_failures() {
        let server = MockServer::start().await;
        setup(&server, pipeline()).await;
        logs(&server, json!([output("first second")])).await;
        let options = CiStepLogOptions {
            page_bytes: Some(5),
            ..CiStepLogOptions::default()
        };
        let first = read_page(&server, options.clone(), ReaderLimits::default()).await;
        let cursor = first.next_cursor.expect("continuation");
        for (status, body, expected) in [
            (
                200,
                serde_json::to_string(&json!([output("replacement")])).expect("json"),
                CiStepLogStatus::StaleCursor,
            ),
            (200, "{".into(), CiStepLogStatus::MalformedResponse),
            (
                404,
                "CI_SECRET AGENT_SECRET FORGE_SECRET".into(),
                CiStepLogStatus::Unavailable,
            ),
            (
                403,
                "CI_SECRET AGENT_SECRET FORGE_SECRET".into(),
                CiStepLogStatus::Unavailable,
            ),
            (429, "CI_SECRET".into(), CiStepLogStatus::Unavailable),
            (503, "CI_SECRET".into(), CiStepLogStatus::Unavailable),
        ] {
            server.reset().await;
            setup(&server, pipeline()).await;
            Mock::given(path("/api/repos/29/logs/42/7001"))
                .respond_with(ResponseTemplate::new(status).set_body_string(body))
                .mount(&server)
                .await;
            let page = read_page(
                &server,
                CiStepLogOptions {
                    cursor: Some(cursor.clone()),
                    ..options.clone()
                },
                ReaderLimits::default(),
            )
            .await;
            assert_eq!(page.status, expected);
            assert!(page.identity.is_some());
            assert!(page.fragments.is_empty());
            assert!(!page.snapshot_complete);
            assert!(page.next_cursor.is_none());
            let text = serde_json::to_string(&page).expect("page");
            for secret in ["CI_SECRET", "AGENT_SECRET", "FORGE_SECRET"] {
                assert!(!text.contains(secret));
            }
        }
    }

    #[tokio::test]
    async fn reader_has_no_state_gate_and_reports_hard_caps_without_false_eof() {
        let server = MockServer::start().await;
        for state in [
            "success",
            "failure",
            "error",
            "running",
            "cancelled",
            "other",
        ] {
            server.reset().await;
            let mut p = pipeline();
            p["workflows"][0]["children"][0]["state"] = state.into();
            setup(&server, p).await;
            logs(
                &server,
                json!([output("ordinary\n"), output("AGENT_"), output("SECRET")]),
            )
            .await;
            let page = read_page(
                &server,
                CiStepLogOptions::default(),
                ReaderLimits::default(),
            )
            .await;
            assert_eq!(page.status, CiStepLogStatus::Available);
            assert!(page.snapshot_complete);
            assert_eq!(
                page.fragments
                    .iter()
                    .map(|f| f.text.as_str())
                    .collect::<String>(),
                "ordinary\n[REDACTED]"
            );
            assert_eq!(
                page.provider_step_finished,
                match state {
                    "running" => Some(false),
                    "other" => None,
                    _ => Some(true),
                }
            );
            for limits in [
                ReaderLimits {
                    transport: StepLogTransportLimits {
                        requests: 2,
                        ..StepLogTransportLimits::default()
                    },
                    ..ReaderLimits::default()
                },
                ReaderLimits {
                    decode: crate::woodpecker_log_decode::DecodeLimits {
                        records: 1,
                        ..crate::woodpecker_log_decode::DecodeLimits::default()
                    },
                    ..ReaderLimits::default()
                },
            ] {
                let page = read_page(&server, CiStepLogOptions::default(), limits).await;
                assert_eq!(page.status, CiStepLogStatus::RetrievalLimit);
                assert!(page.identity.is_some());
                assert!(!page.snapshot_complete);
                assert!(page.next_cursor.is_none());
            }
        }
    }
}
