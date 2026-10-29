//! Request-local, bounded transport primitives for Woodpecker diagnostics.
//!
//! This module deliberately accepts only numeric API resources. Repository and
//! commit binding must be established by the resolver before logs or agents are
//! requested. Transport success alone never establishes that authorization.

use std::collections::HashMap;
use std::time::Duration;

use domain::CiDiagnosticCode;
use reqwest::{Client, Url, redirect::Policy};
use serde::de::DeserializeOwned;
use tokio::time::{Instant, timeout_at};

/// Limits shared by every Woodpecker check in one CI-details operation.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Wall-clock budget including response body reads.
    pub elapsed: Duration,
    /// Maximum number of upstream requests, including failed requests.
    pub requests: usize,
    /// Maximum bytes in one response before JSON decoding.
    pub body_bytes: usize,
    /// Maximum bytes fetched across all responses.
    pub fetched_bytes: usize,
    /// Maximum distinct pipelines retained by the resolver.
    pub pipelines: usize,
    /// Maximum workflows emitted across the operation.
    pub workflows: usize,
    /// Maximum steps emitted across the operation.
    pub steps: usize,
    /// Maximum distinct referenced runners.
    pub runners: usize,
    /// Maximum serialized diagnostic evidence bytes.
    pub output_bytes: usize,
    /// Maximum log entries retained for each step.
    pub excerpt_entries: usize,
    /// Maximum UTF-8 bytes in one excerpt.
    pub excerpt_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            elapsed: Duration::from_secs(30),
            requests: 64,
            body_bytes: 2 * 1024 * 1024,
            fetched_bytes: 8 * 1024 * 1024,
            pipelines: 16,
            workflows: 64,
            steps: 128,
            runners: 16,
            output_bytes: 256 * 1024,
            excerpt_entries: 20,
            excerpt_bytes: 8 * 1024,
        }
    }
}

/// Safe transport failure; never includes upstream bodies, URLs or headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// Stable component diagnostic code.
    pub code: CiDiagnosticCode,
    /// HTTP status if a response was received.
    pub status: Option<u16>,
    /// Static explanation suitable for public diagnostics.
    pub message: &'static str,
}

impl Failure {
    fn new(code: CiDiagnosticCode, message: &'static str) -> Self {
        Self {
            code,
            status: None,
            message,
        }
    }

    fn limit() -> Self {
        Self::new(
            CiDiagnosticCode::LimitExceeded,
            "Woodpecker operation limit reached",
        )
    }
}

/// Locally constructed API resource; no status-provided URL is requested.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Resource {
    /// Repository identity, which must be validated against the authorized forge.
    Repository(u64),
    /// Repository-scoped pipeline number, distinct from database pipeline ID.
    Pipeline(u64, u64),
    /// Step logs within a repository-scoped pipeline number.
    Logs(u64, u64, u64),
    /// Single agent referenced by a validated workflow; never a list lookup.
    Runner(u64),
}

impl Resource {
    fn path(self) -> String {
        match self {
            Self::Repository(repo) => format!("api/repos/{repo}"),
            Self::Pipeline(repo, number) => format!("api/repos/{repo}/pipelines/{number}"),
            Self::Logs(repo, number, step) => format!("api/repos/{repo}/logs/{number}/{step}"),
            Self::Runner(id) => format!("api/agents/{id}"),
        }
    }
}

/// Validated configured origin and optional deployment base prefix.
#[derive(Clone, Debug)]
pub struct Origin(Url);

impl Origin {
    /// Reject ambiguous URL forms before URL normalization can erase them.
    ///
    /// # Errors
    /// Returns a safe binding diagnostic for unsafe configuration.
    pub fn parse(configured: &str) -> Result<Self, Failure> {
        let mut base = safe_url(configured)?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        Ok(Self(base))
    }

    /// Parse an exact pipeline UI URL without trusting it as an API destination.
    ///
    /// # Errors
    /// Rejects other origins, prefixes, nonnumeric IDs and extra path segments.
    pub fn pipeline(&self, target: &str) -> Result<(u64, u64), Failure> {
        let url = safe_url(target)?;
        if url.origin() != self.0.origin() {
            return Err(binding_failure());
        }
        let relative = url
            .path()
            .strip_prefix(self.0.path())
            .ok_or_else(binding_failure)?;
        let parts: Vec<_> = relative.split('/').collect();
        match parts.as_slice() {
            ["repos", repo, "pipeline", number] => Ok((numeric(repo)?, numeric(number)?)),
            ["repos", repo, "pipeline", number, workflow] => {
                numeric(workflow)?;
                Ok((numeric(repo)?, numeric(number)?))
            }
            _ => Err(binding_failure()),
        }
    }
}

fn numeric(value: &str) -> Result<u64, Failure> {
    if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
        return Err(binding_failure());
    }
    value.parse().map_err(|_| binding_failure())
}

fn binding_failure() -> Failure {
    Failure::new(
        CiDiagnosticCode::BindingMismatch,
        "Unsafe or mismatched Woodpecker URL",
    )
}

fn safe_url(raw: &str) -> Result<Url, Failure> {
    if raw.len() > 8192
        || raw
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || raw.contains(['\\', '%', '?', '#', '@'])
        || raw.split('/').any(|s| s == "." || s == "..")
    {
        return Err(binding_failure());
    }
    let url = Url::parse(raw).map_err(|_| binding_failure())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path().contains("//")
    {
        return Err(binding_failure());
    }
    Ok(url)
}

/// Shared request budget and deduplication cache. Create once per details call.
///
/// This type intentionally does not implement `Debug`: it holds a credential.
pub struct Session {
    client: Client,
    origin: Origin,
    token: Option<String>,
    limits: Limits,
    deadline: Instant,
    requests: usize,
    fetched: usize,
    cache: HashMap<Resource, Result<Vec<u8>, Failure>>,
}

impl Session {
    /// Construct a redirect-disabled client with no ambient forge credentials.
    ///
    /// # Errors
    /// Returns a safe diagnostic when the HTTP client cannot be initialized.
    pub fn new(origin: Origin, token: Option<String>, limits: Limits) -> Result<Self, Failure> {
        crate::install_ring_provider();
        let client = Client::builder()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .timeout(limits.elapsed)
            .build()
            .map_err(|_| {
                Failure::new(
                    CiDiagnosticCode::Unavailable,
                    "Woodpecker client unavailable",
                )
            })?;
        Ok(Self {
            client,
            origin,
            token,
            limits,
            deadline: Instant::now() + limits.elapsed,
            requests: 0,
            fetched: 0,
            cache: HashMap::new(),
        })
    }

    /// Retrieve bounded JSON. Both successful and failed resources are reused.
    ///
    /// # Errors
    /// Reports credential, HTTP, transport, malformed-body and budget failures.
    /// A 404 is always resource-not-found, never capability detection.
    pub async fn json<T: DeserializeOwned>(&mut self, resource: Resource) -> Result<T, Failure> {
        if let Resource::Runner(_) = resource
            && self.token.as_deref().is_none_or(str::is_empty)
        {
            return Err(Failure::new(
                CiDiagnosticCode::CredentialMissing,
                "Woodpecker runner credential is missing",
            ));
        }
        if !self.cache.contains_key(&resource) {
            // A rejected request must not grow the cache beyond the request budget.
            if self.requests >= self.limits.requests || Instant::now() >= self.deadline {
                return Err(Failure::limit());
            }
            self.requests += 1;
            let result = match timeout_at(self.deadline, self.fetch(resource)).await {
                Ok(result) => result,
                Err(_) => Err(Failure::limit()),
            };
            self.cache.insert(resource, result);
        }
        let bytes = self.cache.get(&resource).ok_or_else(Failure::limit)?;
        match bytes {
            Ok(bytes) => serde_json::from_slice(bytes).map_err(|_| {
                Failure::new(
                    CiDiagnosticCode::MalformedResponse,
                    "Malformed Woodpecker JSON response",
                )
            }),
            Err(failure) => Err(failure.clone()),
        }
    }

    async fn fetch(&mut self, resource: Resource) -> Result<Vec<u8>, Failure> {
        let url = self
            .origin
            .0
            .join(&resource.path())
            .map_err(|_| binding_failure())?;
        let mut request = self.client.get(url);
        if let Some(token) = self.token.as_deref().filter(|token| !token.is_empty()) {
            request = request.bearer_auth(token);
        }
        let mut response = request.send().await.map_err(|_| {
            Failure::new(
                CiDiagnosticCode::Unavailable,
                "Woodpecker request unavailable",
            )
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(Failure {
                code: match status.as_u16() {
                    401 | 403 => CiDiagnosticCode::AuthorizationDenied,
                    404 => CiDiagnosticCode::ResourceNotFound,
                    _ => CiDiagnosticCode::Unavailable,
                },
                status: Some(status.as_u16()),
                message: "Woodpecker request did not succeed",
            });
        }
        let remaining = self.limits.fetched_bytes.saturating_sub(self.fetched);
        let cap = self.limits.body_bytes.min(remaining);
        if response
            .content_length()
            .is_some_and(|len| len > cap as u64)
        {
            return Err(Failure::limit());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            Failure::new(
                CiDiagnosticCode::Unavailable,
                "Woodpecker response body unavailable",
            )
        })? {
            self.fetched = self.fetched.saturating_add(chunk.len());
            if chunk.len() > cap.saturating_sub(bytes.len()) {
                return Err(Failure::limit());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

/// Redact configured credentials before truncation, preserving UTF-8 boundaries.
/// The boolean signals truncation so the caller can emit `limit_exceeded`.
#[must_use]
pub fn safe_text(raw: &str, secrets: &[&str], max_bytes: usize) -> (String, bool) {
    let mut secrets: Vec<_> = secrets.iter().copied().filter(|s| !s.is_empty()).collect();
    secrets.sort_unstable_by_key(|s| std::cmp::Reverse(s.len()));
    let mut result = String::new();
    let mut remaining = raw;
    while !remaining.is_empty() {
        let (piece, consumed) =
            if let Some(secret) = secrets.iter().find(|s| remaining.starts_with(**s)) {
                ("[REDACTED]", secret.len())
            } else {
                let length = remaining.chars().next().map_or(0, char::len_utf8);
                (&remaining[..length], length)
            };
        if piece.len() > max_bytes.saturating_sub(result.len()) {
            return (result, true);
        }
        result.push_str(piece);
        remaining = &remaining[consumed..];
    }
    (result, false)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use serde_json::Value;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn session(base: &str, token: Option<&str>, limits: Limits) -> Session {
        Session::new(
            Origin::parse(base).expect("origin"),
            token.map(str::to_owned),
            limits,
        )
        .expect("session")
    }

    #[test]
    fn urls_preserve_prefix_and_reject_ambiguous_or_foreign_paths() {
        let origin = Origin::parse("https://ci.example/woodpecker").expect("origin");
        assert_eq!(
            origin
                .pipeline("https://ci.example/woodpecker/repos/1/pipeline/42/2")
                .expect("workflow UI URL"),
            (1, 42)
        );
        assert_eq!(
            origin
                .pipeline("https://ci.example/woodpecker/repos/1/pipeline/42")
                .expect("pipeline"),
            (1, 42)
        );
        for target in [
            "https://evil.example/woodpecker/repos/1/pipeline/42",
            "http://ci.example/woodpecker/repos/1/pipeline/42",
            "https://ci.example:444/woodpecker/repos/1/pipeline/42",
            "https://user:secret@ci.example/woodpecker/repos/1/pipeline/42",
            "https://ci.example/woodpecker/repos/1/pipeline/42?token=secret",
            "https://ci.example/woodpecker/repos/1/pipeline/42#fragment",
            "https://ci.example/woodpecker/repos/1/pipeline/42/extra",
            "https://ci.example/woodpecker/repos//pipeline/42",
            "https://ci.example/woodpecker/repos/1/pipeline/",
            "https://ci.example/woodpecker/repos/1/pipeline/-1",
            "https://ci.example/woodpecker/repos/1/pipeline/18446744073709551616",
            "https://ci.example/woodpecker/repos/%31/pipeline/42",
            "https://ci.example/woodpecker/./repos/1/pipeline/42",
            "https://ci.example/woodpecker/a/../repos/1/pipeline/42",
            "https://ci.example/woodpecker/repos/1/pipeline/42/",
            "https://ci.example/woodpecker/repos/1\\pipeline/42",
            "https://ci.example/repos/1/pipeline/42",
        ] {
            assert_eq!(
                origin.pipeline(target).expect_err(target).code,
                CiDiagnosticCode::BindingMismatch
            );
        }
        for base in [
            "file:///etc/passwd",
            "https://ci.example/?secret",
            "https://ci.example/#fragment",
            "https://secret@ci.example",
            "https://ci.example//prefix",
            "https://ci.example/a/../b",
        ] {
            assert!(Origin::parse(base).is_err(), "{base}");
        }
    }

    #[test]
    fn redaction_precedes_utf8_safe_truncation() {
        assert_eq!(
            safe_text("é SECRETlong 終", &["SECRET", "SECRETlong", ""], 128),
            ("é [REDACTED] 終".to_owned(), false)
        );
        assert_eq!(
            safe_text("éSECRETlong", &["SECRETlong"], 5),
            ("é".to_owned(), true)
        );
        assert_eq!(safe_text("é終", &[], 4), ("é".to_owned(), true));
        assert_eq!(safe_text("", &[], 0), (String::new(), false));
        assert_eq!(safe_text("a", &[], 0), (String::new(), true));
    }

    #[tokio::test]
    async fn configured_token_prefix_and_request_local_deduplication() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ci/api/repos/1/pipelines/42"))
            .and(header("Authorization", "Bearer CI_SENTINEL"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 9})))
            .expect(1)
            .mount(&mock)
            .await;
        let resource = Resource::Pipeline(1, 42);
        let mut first = session(
            &format!("{}/ci", mock.uri()),
            Some("CI_SENTINEL"),
            Limits::default(),
        );
        for _ in 0..3 {
            assert_eq!(first.json::<Value>(resource).await.expect("json")["id"], 9);
        }
        assert_eq!(first.requests, 1);
        assert_eq!(first.fetched, 8);
        // A second session must not inherit permission-sensitive results.
        let mut second = session(&format!("{}/ci", mock.uri()), None, Limits::default());
        assert_eq!(
            second
                .json::<Value>(resource)
                .await
                .expect_err("missing header matcher")
                .code,
            CiDiagnosticCode::ResourceNotFound
        );
    }

    #[tokio::test]
    async fn runner_without_credential_never_makes_a_request() {
        let mock = MockServer::start().await;
        for token in [None, Some("")] {
            let mut client = session(&mock.uri(), token, Limits::default());
            assert_eq!(
                client
                    .json::<Value>(Resource::Runner(17))
                    .await
                    .expect_err("credential")
                    .code,
                CiDiagnosticCode::CredentialMissing
            );
        }
        assert!(mock.received_requests().await.expect("requests").is_empty());
    }

    #[tokio::test]
    async fn failures_are_typed_cached_and_never_include_provider_bodies() {
        let mock = MockServer::start().await;
        for (id, status, code) in [
            (1, 401, CiDiagnosticCode::AuthorizationDenied),
            (2, 403, CiDiagnosticCode::AuthorizationDenied),
            (3, 404, CiDiagnosticCode::ResourceNotFound),
            (4, 429, CiDiagnosticCode::Unavailable),
            (5, 500, CiDiagnosticCode::Unavailable),
        ] {
            Mock::given(path(format!("/api/agents/{id}")))
                .respond_with(
                    ResponseTemplate::new(status).set_body_string("SENTINEL_registration_token"),
                )
                .expect(1)
                .mount(&mock)
                .await;
            let mut client = session(&mock.uri(), Some("token"), Limits::default());
            for _ in 0..2 {
                let failure = client
                    .json::<Value>(Resource::Runner(id))
                    .await
                    .expect_err("failure");
                assert_eq!(failure.code, code);
                assert_eq!(failure.status, Some(status));
                assert!(!format!("{failure:?}").contains("SENTINEL"));
            }
        }
    }

    #[tokio::test]
    async fn redirects_never_reach_the_destination() {
        let source = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(path("/api/repos/1"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/api/agents/17", destination.uri())),
            )
            .expect(1)
            .mount(&source)
            .await;
        let mut client = session(&source.uri(), Some("secret"), Limits::default());
        let failure = client
            .json::<Value>(Resource::Repository(1))
            .await
            .expect_err("redirect");
        assert_eq!(failure.status, Some(302));
        assert!(
            destination
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn request_and_cumulative_body_limits_are_shared() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&mock)
            .await;
        let limits = Limits {
            requests: 2,
            fetched_bytes: 3,
            ..Limits::default()
        };
        let mut client = session(&mock.uri(), None, limits);
        client
            .json::<Value>(Resource::Repository(1))
            .await
            .expect("first");
        assert_eq!(
            client
                .json::<Value>(Resource::Repository(2))
                .await
                .expect_err("byte budget")
                .code,
            CiDiagnosticCode::LimitExceeded
        );
        assert_eq!(
            client
                .json::<Value>(Resource::Repository(3))
                .await
                .expect_err("request budget")
                .code,
            CiDiagnosticCode::LimitExceeded
        );
        // Validated cached evidence remains accessible after exhaustion.
        client
            .json::<Value>(Resource::Repository(1))
            .await
            .expect("cached");
        assert_eq!(mock.received_requests().await.expect("requests").len(), 2);
        assert_eq!(client.cache.len(), 2);
    }

    #[tokio::test]
    async fn malformed_and_oversized_json_are_distinct() {
        let mock = MockServer::start().await;
        Mock::given(path("/api/repos/1"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{"))
            .expect(1)
            .mount(&mock)
            .await;
        Mock::given(path("/api/repos/2"))
            .respond_with(ResponseTemplate::new(200).set_body_string("123456789"))
            .expect(1)
            .mount(&mock)
            .await;
        let mut client = session(
            &mock.uri(),
            None,
            Limits {
                body_bytes: 8,
                ..Limits::default()
            },
        );
        assert_eq!(
            client
                .json::<Value>(Resource::Repository(1))
                .await
                .expect_err("malformed")
                .code,
            CiDiagnosticCode::MalformedResponse
        );
        assert_eq!(
            client
                .json::<Value>(Resource::Repository(2))
                .await
                .expect_err("oversized")
                .code,
            CiDiagnosticCode::LimitExceeded
        );
    }

    #[tokio::test]
    async fn deadline_covers_slow_body_reads() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let provider = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buffer = [0; 4096];
            assert!(socket.read(&mut buffer).await.expect("request") > 0);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
                .await
                .expect("headers");
            tokio::time::sleep(Duration::from_millis(150)).await;
        });
        let mut client = session(
            &base,
            None,
            Limits {
                elapsed: Duration::from_millis(75),
                ..Limits::default()
            },
        );
        let failure = client
            .json::<Value>(Resource::Repository(1))
            .await
            .expect_err("deadline");
        // The outer deadline and reqwest's identical timeout may race.
        assert!(matches!(
            failure.code,
            CiDiagnosticCode::LimitExceeded | CiDiagnosticCode::Unavailable
        ));
        provider.await.expect("provider");
    }

    #[tokio::test]
    async fn chunked_response_without_length_is_bounded_before_decoding() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let provider = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buffer = [0; 4096];
            assert!(socket.read(&mut buffer).await.expect("request") > 0);
            socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n9\r\n123456789\r\n0\r\n\r\n").await.expect("response");
            socket.shutdown().await.expect("close");
        });
        let mut client = session(
            &base,
            None,
            Limits {
                body_bytes: 8,
                ..Limits::default()
            },
        );
        assert_eq!(
            client
                .json::<Value>(Resource::Repository(1))
                .await
                .expect_err("chunk limit")
                .code,
            CiDiagnosticCode::LimitExceeded
        );
        provider.await.expect("provider");
    }
}
