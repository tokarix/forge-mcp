//! Bounded, task-local request diagnostics. Never record headers or bodies.
use axum::{
    extract::{FromRequestParts, MatchedPath, Path, Request},
    middleware::Next,
    response::Response,
};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};
use tracing::Instrument;

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

pub(crate) fn bounded(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect()
}

pub(crate) fn record_agent(agent: &domain::AgentIdentity) {
    tracing::Span::current().record("agent_id", bounded(&agent.agent_id));
    tracing::Span::current().record("session_id", bounded(&agent.session_id));
}

pub(crate) async fn request_context(request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
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
    let params = Path::<HashMap<String, String>>::from_request_parts(&mut parts, &())
        .await
        .map(|Path(p)| p)
        .unwrap_or_default();
    let field = |name: &str| bounded(params.get(name).map_or("", String::as_str));
    let span = tracing::info_span!("request", %request_id, %operation,
        method = %parts.method, forge = field("forge"), owner = field("owner"), repo = field("repo"),
        target = field("index"), agent_id = tracing::field::Empty, session_id = tracing::field::Empty,
        credential_source = tracing::field::Empty, upstream_username = tracing::field::Empty);
    async move {
        let response = next.run(Request::from_parts(parts, body)).await;
        if response.status().is_client_error() || response.status().is_server_error() {
            tracing::warn!(status = response.status().as_u16(), "request failed");
        }
        response
    }
    .instrument(span)
    .await
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
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
            tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(self.clone())
                .finish()
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

    #[test]
    fn bounds_multibyte_context_and_removes_controls() {
        let value = bounded(&format!("\n{}\r", "界".repeat(300)));
        assert_eq!(value.chars().count(), 128);
        assert!(!value.contains('\n'));
    }
}
