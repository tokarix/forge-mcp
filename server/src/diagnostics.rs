//! Bounded, task-local request diagnostics. Never record headers or bodies.
use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};
use tracing::Instrument;

const CONTENTS_ROUTE: &str = "/api/v1/repos/{forge}/{owner}/{repo}/contents/{*path}";
tokio::task_local! { static FILE_READ: bool; }

pub(crate) fn is_file_read() -> bool {
    FILE_READ.try_with(|value| *value).unwrap_or(false)
}

/// Keep contents diagnostics under server control, including dependency logs
/// forwarded by the log bridge (HTTP clients may otherwise log raw URLs).
/// Other operations retain their existing dependency logging policy.
#[must_use]
pub fn request_log_filter(metadata: &tracing::Metadata<'_>) -> bool {
    !is_file_read()
        || ["server", "forge", "orchestrator", "domain", "audit"]
            .iter()
            .any(|target| {
                metadata.target() == *target
                    || metadata
                        .target()
                        .strip_prefix(target)
                        .is_some_and(|rest| rest.starts_with("::"))
            })
}

/// Immutable, validated, server-owned diagnostic disclosure policy.
#[derive(Clone, Default)]
pub struct FileReadDiagnosticPolicy(crate::config::FileReadDiagnosticsConfig);

impl FileReadDiagnosticPolicy {
    /// # Errors
    /// Rejects invalid or excessive allowlists without echoing their values.
    pub fn new(config: crate::config::FileReadDiagnosticsConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self(config))
    }

    pub(crate) fn record(
        &self,
        path: &crate::api::ContentsPath,
        reference: Option<&str>,
        is_secret: impl Fn(&str) -> bool,
    ) {
        let entry = self.0.repositories.iter().find(|entry| {
            entry.forge == path.forge && entry.owner == path.owner && entry.repo == path.repo
        });
        let disclose = |value: &str, approved: Option<&Vec<String>>| {
            if !crate::config::safe_file_diagnostic_value(value) {
                (REDACTED.to_owned(), "invalid")
            } else if is_secret(value) {
                (REDACTED.to_owned(), "credential")
            } else if approved.is_some_and(|values| values.iter().any(|s| s == value)) {
                (value.to_owned(), "approved")
            } else {
                (REDACTED.to_owned(), "not_approved")
            }
        };
        let (requested_path, path_visibility) = disclose(&path.path, entry.map(|e| &e.paths));
        let (requested_ref, ref_visibility) = reference
            .map_or((REDACTED.to_owned(), "default"), |value| {
                disclose(value, entry.map(|e| &e.refs))
            });
        let span = tracing::Span::current();
        span.record("requested_path", requested_path.as_str());
        span.record("requested_ref", requested_ref.as_str());
        span.record("path_visibility", path_visibility);
        span.record("ref_visibility", ref_visibility);
        span.record(
            "ref_source",
            if reference.is_some() {
                "explicit"
            } else {
                "default"
            },
        );
    }
}

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

pub(crate) fn bounded(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect()
}

const REDACTED: &str = "[redacted]";

// Resolve only reviewed identifier parameters. In particular, file wildcards,
// labels and future parameters must not expose arbitrary caller-supplied text.
// Work with URI segments directly: Axum's Path extractor percent-decodes them.
fn safe_context(route: &str, raw_path: &str) -> (String, HashMap<String, String>) {
    if route == "unmatched" {
        return ("unmatched".into(), HashMap::new());
    }
    let mut raw = raw_path.split('/');
    let mut resolved = Vec::new();
    let mut fields = HashMap::new();
    for segment in route.split('/') {
        let Some(value) = raw.next() else {
            return (REDACTED.into(), HashMap::new());
        };
        if segment.starts_with("{*") {
            resolved.push(REDACTED);
            // A wildcard consumes all remaining segments, none of which are safe.
            break;
        }
        if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            let identifier = matches!(name, "forge" | "owner" | "repo");
            let number = matches!(name, "index" | "dependency");
            let safe = !value.is_empty()
                && value.len() <= 128
                && value != "."
                && value != ".."
                && value.bytes().all(|b| {
                    if number {
                        b.is_ascii_digit()
                    } else {
                        identifier && (b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    }
                });
            let value = if safe { value } else { REDACTED };
            resolved.push(value);
            if identifier || name == "index" {
                fields.insert(name.to_owned(), bounded(value));
            }
        } else if segment == value {
            resolved.push(segment);
        } else {
            return (REDACTED.into(), HashMap::new());
        }
    }
    let path = resolved.join("/");
    if path.len() > 1024 || (!route.contains("{*") && raw.next().is_some()) {
        return (REDACTED.into(), fields);
    }
    (path, fields)
}

pub(crate) fn record_agent(agent: &domain::AgentIdentity) {
    tracing::Span::current().record("agent_id", bounded(&agent.agent_id));
    tracing::Span::current().record("session_id", bounded(&agent.session_id));
}

pub(crate) async fn request_context(request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    // Locally generated IDs cannot contain caller-controlled log text.
    let request_id = format!(
        "{}-{}",
        std::process::id(),
        NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)
    );
    let operation = parts
        .extensions
        .get::<MatchedPath>()
        .map_or("unmatched", MatchedPath::as_str)
        .to_owned();
    let file_read = parts.method == axum::http::Method::GET && operation == CONTENTS_ROUTE;
    let (path, params) = safe_context(&operation, parts.uri.path());
    let route = bounded(&operation);
    // Compatibility alias: operation continues to mean the matched template.
    let operation = &route;
    let field = |name: &str| bounded(params.get(name).map_or("", String::as_str));
    let span = tracing::info_span!("request", %request_id, %operation, route = route.as_str(), path = path.as_str(),
        method = %parts.method, forge = field("forge"), owner = field("owner"), repo = field("repo"),
        target = field("index"), agent_id = tracing::field::Empty, session_id = tracing::field::Empty,
        credential_source = "unselected", upstream_username = tracing::field::Empty,
        requested_path = REDACTED, requested_ref = REDACTED, ref_source = "unavailable",
        path_visibility = "unauthorized_or_unparsed", ref_visibility = "unauthorized_or_unparsed");
    FILE_READ
        .scope(
            file_read,
            async move {
                let response = next.run(Request::from_parts(parts, body)).await;
                if response.status().is_client_error() || response.status().is_server_error() {
                    if file_read {
                        let metadata = response.extensions().get::<domain::FileReadError>();
                        let status = response.status().as_u16();
                        let error_kind = metadata.map_or_else(
                            || match status {
                                401 => "authentication",
                                403 => "authorization",
                                400 | 422 => "validation",
                                500 => "local_failure",
                                _ => "request_failure",
                            },
                            |error| error.kind.as_str(),
                        );
                        let upstream_status = metadata.and_then(|error| error.upstream_status);
                        if metadata
                            .is_some_and(|error| error.kind == domain::FileReadErrorKind::NotFound)
                        {
                            tracing::info!(
                                status,
                                gateway_status = status,
                                error_kind,
                                upstream_status,
                                "file read failed"
                            );
                        } else {
                            tracing::warn!(
                                status,
                                gateway_status = status,
                                error_kind,
                                upstream_status,
                                "file read failed"
                            );
                        }
                    } else {
                        tracing::warn!(status = response.status().as_u16(), "request failed");
                    }
                }
                response
            }
            .instrument(span),
        )
        .await
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        extract::Path,
        http::{Request as HttpRequest, StatusCode},
        routing::get,
    };
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber;

    #[derive(Clone, Default)]
    pub(crate) struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Capture {
        pub(crate) fn logs(&self) -> String {
            String::from_utf8(self.0.lock().expect("capture lock").clone()).expect("utf8")
        }
        pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + use<> {
            use tracing_subscriber::prelude::*;
            tracing_subscriber::registry().with(
                tracing_subscriber::fmt::layer()
                    .without_time()
                    .with_ansi(false)
                    .with_writer(self.clone())
                    .with_filter(tracing_subscriber::filter::dynamic_filter_fn(
                        |metadata, _| request_log_filter(metadata),
                    ))
                    .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
            )
        }
    }
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("capture lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    #[tokio::test]
    async fn dependency_log_filter_is_rechecked_for_each_operation() {
        fn dependency_event(value: &str) {
            tracing::debug!(target: "reqwest::connect", value, "dependency connection");
        }
        let capture = Capture::default();
        async {
            dependency_event("outside-before");
            FILE_READ
                .scope(true, async {
                    dependency_event("inside-secret");
                })
                .await;
            dependency_event("outside-after");
            FILE_READ
                .scope(true, async {
                    dependency_event("inside-again-secret");
                })
                .await;
        }
        .with_subscriber(capture.subscriber())
        .await;
        let logs = capture.logs();
        assert!(logs.contains("outside-before"), "{logs}");
        assert!(logs.contains("outside-after"), "{logs}");
        assert!(!logs.contains("secret"), "{logs}");
    }

    #[tokio::test]
    async fn concurrent_failures_keep_request_and_identity_context() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let app = Router::new()
            .route(
                "/repos/{forge}/{owner}/{repo}/{index}",
                get(|Path(p): Path<HashMap<String, String>>| async move {
                    if p["owner"] != "missing" {
                        record_agent(&domain::AgentIdentity {
                            agent_id: p["owner"].clone(),
                            session_id: "session".into(),
                        });
                    }
                    tokio::task::yield_now().await;
                    StatusCode::FORBIDDEN
                }),
            )
            .layer(axum::middleware::from_fn(request_context));
        async {
            let a = app.clone().oneshot(
                HttpRequest::builder()
                    .uri("/repos/f/alice/r/42")
                    .header("x-request-id", "secret-caller-text")
                    .body(Body::empty())
                    .expect("request"),
            );
            let b = app.oneshot(
                HttpRequest::builder()
                    .uri("/repos/f/missing/r/43")
                    .body(Body::empty())
                    .expect("request"),
            );
            let (a, b) = tokio::join!(a, b);
            assert_eq!(a.expect("response").status(), StatusCode::FORBIDDEN);
            assert_eq!(b.expect("response").status(), StatusCode::FORBIDDEN);
        }
        .with_subscriber(subscriber)
        .await;
        let bytes = capture.0.lock().expect("capture lock").clone();
        let logs = String::from_utf8(bytes).expect("utf8 logs");
        let lines: Vec<_> = logs.lines().collect();
        assert_eq!(lines.len(), 2, "{logs}");
        for line in lines {
            assert!(line.contains("request_id="));
            assert!(!line.contains("secret-caller-text"));
            if line.contains("target=\"42\"") {
                assert!(line.contains("agent_id=\"alice\""));
                assert!(!line.contains("missing"));
            } else {
                assert!(line.contains("target=\"43\""));
                assert!(!line.contains("alice"));
            }
        }
    }

    #[tokio::test]
    async fn resolved_paths_exclude_secrets_and_redact_unreviewed_segments() {
        let capture = Capture::default();
        let app = Router::new()
            .route(
                "/git/{forge}/{owner}/{repo}/info/refs",
                get(|| async { StatusCode::UNAUTHORIZED }),
            )
            .route(
                "/api/v1/repos/{forge}/{owner}/{repo}/issues/{index}",
                get(|| async { StatusCode::FORBIDDEN }),
            )
            .route("/contents/{*path}", get(|| async { StatusCode::FORBIDDEN }))
            .route("/labels/{label}", get(|| async { StatusCode::FORBIDDEN }))
            .layer(axum::middleware::from_fn(request_context));
        for (uri, expected) in [
            (
                "/git/adlevio/stintel/trade/info/refs?token=query-secret",
                "/git/adlevio/stintel/trade/info/refs",
            ),
            (
                "/api/v1/repos/adlevio/tokarix/forge-mcp/issues/230?secret=query-secret",
                "/api/v1/repos/adlevio/tokarix/forge-mcp/issues/230",
            ),
            ("/contents/private/secret-file", "/contents/[redacted]"),
            ("/labels/secret-label", "/labels/[redacted]"),
            ("/unknown/secret-unmatched?secret=query-secret", "unmatched"),
            (
                "/git/adlevio/stintel/secret%0Avalue/info/refs",
                "/git/adlevio/stintel/[redacted]/info/refs",
            ),
        ] {
            app.clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri(uri)
                        .header("authorization", "Bearer header-secret")
                        .body(Body::from("body-secret"))
                        .expect("request"),
                )
                .with_subscriber(capture.subscriber())
                .await
                .expect("response");
            let logs = capture.logs();
            let line = logs.lines().last().expect("failure log");
            assert!(line.contains(&format!("path=\"{expected}\"")), "{line}");
            assert!(line.contains("request_id="));
            assert!(line.contains("method=GET"));
        }
        let logs = capture.logs();
        assert!(logs.contains("route=\"/git/{forge}/{owner}/{repo}/info/refs\""));
        assert!(logs.contains("operation=/git/{forge}/{owner}/{repo}/info/refs"));
        assert!(logs.contains("target=\"230\""));
        for secret in [
            "query-secret",
            "header-secret",
            "body-secret",
            "secret-file",
            "secret-label",
            "secret-unmatched",
            "secret%0Avalue",
            "secretvalue",
        ] {
            assert!(!logs.contains(secret), "{logs}");
        }
    }

    #[test]
    fn resolved_context_bounds_and_redacts_unsafe_values_without_decoding() {
        let route = "/git/{forge}/{owner}/{repo}/info/refs";
        for value in [
            "a\nb".to_owned(),
            "a\rb".into(),
            "a\u{1b}b".into(),
            "a%2Fb".into(),
            "a%00b".into(),
            "a%252Fb".into(),
            "user:password@host".into(),
            "..".into(),
            "界".repeat(129),
            "a".repeat(129),
        ] {
            let (path, fields) =
                safe_context(route, &format!("/git/adlevio/stintel/{value}/info/refs"));
            assert_eq!(path, "/git/adlevio/stintel/[redacted]/info/refs");
            assert_eq!(fields["repo"], REDACTED);
        }
        let value = "a".repeat(128);
        let (path, fields) =
            safe_context(route, &format!("/git/adlevio/stintel/{value}/info/refs"));
        assert!(path.contains(&value));
        assert_eq!(fields["repo"], value);
        assert_eq!(safe_context("unmatched", "/secret").0, "unmatched");
        assert_eq!(safe_context("/static", "/different").0, REDACTED);
        assert_eq!(safe_context("/static", "/static/secret").0, REDACTED);
        assert_eq!(safe_context("/static/missing", "/static").0, REDACTED);
        let long = format!("/{}", "a".repeat(1024));
        assert_eq!(safe_context(&long, &long).0, REDACTED);
    }

    #[test]
    fn bounds_multibyte_context_and_removes_controls() {
        let value = bounded(&format!("\n{}\r", "界".repeat(300)));
        assert_eq!(value.chars().count(), 128);
        assert!(!value.contains('\n'));
    }
}
