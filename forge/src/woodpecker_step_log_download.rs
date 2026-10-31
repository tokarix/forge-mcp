//! Uncached selected Woodpecker download reader with safe failure envelopes.
//!
//! Selection validates the entire child membership graph before log access. The
//! caller must authorize the forge repository first and use a request-local
//! `Session::for_step_logs` so repository, pipeline and logs share one budget.

use domain::{
    CiDiagnosticCode, CiStepLogDownloadDiagnostic, CiStepLogDownloadStatus, CiStepLogIdentity,
    CiStepLogOptions, CiStepLogSelector, RepositoryCiStepLogDownload, RepositoryRef,
};

use crate::woodpecker::{Failure, Session};
use crate::woodpecker_step_logs::select_step;

/// Independent transport and decoder limits for one freshly fetched page.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReaderLimits {
    /// Shared identity/log I/O budget.
    pub transport: crate::woodpecker::StepLogTransportLimits,
    /// Full-snapshot parsing and canonicalization budget.
    pub decode: crate::woodpecker_download_decode::DecodeLimits,
}

fn failed(
    selector: CiStepLogSelector,
    identity: Option<CiStepLogIdentity>,
    status: CiStepLogDownloadStatus,
    code: &str,
    message: &str,
    http_status: Option<u16>,
) -> RepositoryCiStepLogDownload {
    let mut page = RepositoryCiStepLogDownload::unsupported(selector);
    page.provider_step_finished = identity.as_ref().and_then(|i| match i.step_state.as_str() {
        "success" | "failure" | "error" | "killed" | "skipped" | "cancelled" => Some(true),
        "pending" | "running" | "blocked" => Some(false),
        _ => None,
    });
    page.identity = identity;
    page.status = status;
    page.diagnostics.push(CiStepLogDownloadDiagnostic {
        code: code.into(),
        message: message.into(),
        http_status,
    });
    page
}

fn retrieval_failure(
    selector: CiStepLogSelector,
    identity: Option<CiStepLogIdentity>,
    failure: &Failure,
) -> RepositoryCiStepLogDownload {
    let (status, code) = if matches!(failure.status, Some(405 | 501)) {
        (CiStepLogDownloadStatus::Unsupported, "unsupported")
    } else {
        match failure.code {
            CiDiagnosticCode::LimitExceeded => {
                (CiStepLogDownloadStatus::RetrievalLimit, "retrieval_limit")
            }
            CiDiagnosticCode::BindingMismatch => {
                (CiStepLogDownloadStatus::BindingMismatch, "binding_mismatch")
            }
            CiDiagnosticCode::MalformedResponse => (
                CiStepLogDownloadStatus::MalformedResponse,
                "malformed_response",
            ),
            CiDiagnosticCode::AuthorizationDenied => (
                CiStepLogDownloadStatus::AuthorizationDenied,
                "authorization_denied",
            ),
            CiDiagnosticCode::ResourceNotFound => (
                CiStepLogDownloadStatus::ResourceNotFound,
                "resource_not_found",
            ),
            CiDiagnosticCode::CredentialMissing => {
                (CiStepLogDownloadStatus::Unavailable, "credential_missing")
            }
            _ => (CiStepLogDownloadStatus::Unavailable, "unavailable"),
        }
    };
    failed(
        selector,
        identity,
        status,
        code,
        if failure.status == Some(404) {
            "Resource not found; download capability and retained output availability are uncertain"
        } else {
            failure.message
        },
        failure.status,
    )
}

/// Retrieve one independently selected historical plain-text download page.
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
) -> Result<RepositoryCiStepLogDownload, crate::ForgeError> {
    if !selector.valid() {
        return Err(crate::ForgeError::InvalidPayload(
            "Step log selectors must be positive signed 64-bit integers".into(),
        ));
    }
    options
        .validate()
        .map_err(|message| crate::ForgeError::InvalidPayload(message.into()))?;
    if selector.provider != "woodpecker" {
        return Ok(RepositoryCiStepLogDownload::unsupported(selector));
    }
    let Some(base) = &config.woodpecker_url else {
        return Ok(RepositoryCiStepLogDownload::unsupported(selector));
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
        .step_log_download_body(
            selector.provider_repository_id,
            selector.pipeline_number,
            selector.step_id,
        )
        .await
    {
        Ok(raw) => raw,
        Err(failure) => return Ok(retrieval_failure(selector, Some(identity), &failure)),
    };
    let records =
        match crate::woodpecker_download_decode::decode(&session, &raw, &secrets, limits.decode) {
            Ok(records) => records,
            Err(failure) => return Ok(retrieval_failure(selector, Some(identity), &failure)),
        };
    let result = crate::woodpecker_download_snapshot::Snapshot::new(
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
                CiStepLogDownloadStatus::InvalidCursor => "invalid_cursor",
                CiStepLogDownloadStatus::StaleCursor => "stale_cursor",
                CiStepLogDownloadStatus::BindingMismatch => "binding_mismatch",
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
    use super::*;
    use domain::ForgeKind;
    use serde_json::{Value, json};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};
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
    ) -> RepositoryCiStepLogDownload {
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

    const DOWNLOAD: &str = "/api/repos/29/logs/42/7001/download";
    #[tokio::test]
    async fn pages_reselect_refetch_and_redact_with_ci_only_auth() {
        let server = MockServer::start().await;
        setup(&server, pipeline()).await;
        let text = "before CI_SECRET FORGE_SECRET AGENT_SECRET\r\n終🙂";
        Mock::given(path(DOWNLOAD))
            .respond_with(ResponseTemplate::new(200).set_body_raw(text, "text/plain"))
            .mount(&server)
            .await;
        let mut options = CiStepLogOptions {
            page_bytes: Some(10),
            ..Default::default()
        };
        let mut actual = String::new();
        let mut pages = 0;
        loop {
            let page = read_page(&server, options.clone(), ReaderLimits::default()).await;
            pages += 1;
            assert_eq!(page.status, CiStepLogDownloadStatus::Available);
            assert_eq!(page.identity.as_ref().expect("identity").pipeline_id, 5001);
            for f in &page.fragments {
                actual.push_str(&f.text);
            }
            if page.snapshot_complete {
                break;
            }
            options.cursor = page.next_cursor;
        }
        assert_eq!(actual, "before [REDACTED] [REDACTED] [REDACTED]\r\n終🙂");
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), pages * 3);
        for request in requests {
            assert!(
                request.url.path() == DOWNLOAD
                    || request.url.path() == "/api/repos/29"
                    || request.url.path() == "/api/repos/29/pipelines/42"
            );
            assert_eq!(
                request.headers.get("authorization").expect("auth"),
                "Bearer CI_SECRET"
            );
        }
    }
    #[tokio::test]
    async fn failures_never_expose_partial_source_or_unvalidated_identity() {
        for (http, status) in [
            (401, CiStepLogDownloadStatus::AuthorizationDenied),
            (403, CiStepLogDownloadStatus::AuthorizationDenied),
            (404, CiStepLogDownloadStatus::ResourceNotFound),
            (405, CiStepLogDownloadStatus::Unsupported),
            (501, CiStepLogDownloadStatus::Unsupported),
            (429, CiStepLogDownloadStatus::Unavailable),
            (500, CiStepLogDownloadStatus::Unavailable),
        ] {
            let server = MockServer::start().await;
            setup(&server, pipeline()).await;
            Mock::given(path(DOWNLOAD))
                .respond_with(
                    ResponseTemplate::new(http)
                        .set_body_string("SENTINEL_SECRET")
                        .insert_header("x-secret", "SENTINEL_SECRET"),
                )
                .mount(&server)
                .await;
            let page = read_page(
                &server,
                CiStepLogOptions::default(),
                ReaderLimits::default(),
            )
            .await;
            assert_eq!(page.status, status);
            assert!(page.identity.is_some());
            assert!(
                page.fragments.is_empty()
                    && page.snapshot_id.is_none()
                    && page.next_cursor.is_none()
                    && page.beginning_cursor.is_none()
            );
            assert!(!page.snapshot_complete && page.truncated);
            assert!(
                !serde_json::to_string(&page)
                    .expect("json")
                    .contains("SENTINEL_SECRET")
            );
            assert!(
                page.diagnostics
                    .iter()
                    .any(|d| d.code == "output_completeness_unknown")
            );
        }
        for duplicate in [false, true] {
            let server = MockServer::start().await;
            let mut p = pipeline();
            if duplicate {
                let child = p["workflows"][0]["children"][0].clone();
                p["workflows"][0]["children"]
                    .as_array_mut()
                    .expect("children")
                    .push(child);
            } else {
                p["workflows"][0]["children"][0]["ppid"] = json!(999);
            }
            setup(&server, p).await;
            let page = read_page(
                &server,
                CiStepLogOptions::default(),
                ReaderLimits::default(),
            )
            .await;
            assert_eq!(page.status, CiStepLogDownloadStatus::BindingMismatch);
            assert!(page.identity.is_none());
            assert_eq!(server.received_requests().await.expect("requests").len(), 2);
        }
    }
}
