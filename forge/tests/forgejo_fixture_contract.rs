#![allow(clippy::unwrap_used)]

mod support;

use std::collections::HashMap;
use std::net::TcpListener;
use std::time::Duration;

use support::forgejo::{
    BASE_URL_ENV, PASSWORD_ENV, ReadinessOptions, USERNAME_ENV, bounded_preview, combine_results,
    parse_config, redact_known_secrets, wait_for_ready,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(values: &[(&str, &str)]) -> Result<support::forgejo::Config, String> {
    let values = values
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect::<HashMap<_, _>>();
    parse_config(|name| values.get(name).cloned())
}

fn complete(base_url: &str) -> Vec<(&str, &str)> {
    vec![
        (BASE_URL_ENV, base_url),
        (USERNAME_ENV, "fixture-user"),
        (PASSWORD_ENV, "fixture-password"),
    ]
}

fn fast_options() -> ReadinessOptions {
    ReadinessOptions {
        deadline: Duration::from_millis(80),
        backoff: Duration::from_millis(5),
        request_timeout: Duration::from_millis(20),
        preview_limit: 160,
    }
}

#[test]
fn configuration_is_all_or_nothing_and_normalizes_origins() {
    let parsed = config(&complete("http://example.test:3000")).unwrap();
    assert_eq!(parsed.base_url.as_str(), "http://example.test:3000/");
    assert_eq!(parsed.username, "fixture-user");

    assert!(
        config(&[])
            .unwrap_err()
            .contains("configuration is missing")
    );
    assert!(
        config(&[(BASE_URL_ENV, "http://example.test")])
            .unwrap_err()
            .contains("configuration is partial")
    );
    assert!(
        config(
            &complete("http://example.test")
                .into_iter()
                .map(|(key, value)| {
                    if key == USERNAME_ENV {
                        (key, "")
                    } else {
                        (key, value)
                    }
                })
                .collect::<Vec<_>>()
        )
        .unwrap_err()
        .contains("is empty")
    );
}

#[test]
fn configuration_rejects_non_origin_urls() {
    for invalid in [
        "ftp://example.test",
        "http://user@example.test",
        "http://example.test/path",
        "http://example.test?query=yes",
        "http://example.test#fragment",
        "not a URL",
    ] {
        assert!(config(&complete(invalid)).is_err(), "accepted {invalid}");
    }
    assert!(config(&complete("https://example.test/")).is_ok());
}

#[test]
fn previews_are_bounded_and_redact_every_known_secret() {
    let password = "sample-password";
    let basic = "Basic dXNlcjpwYXNz";
    let bearer = "sample-bearer-token";
    let input = format!("{password} {basic} {bearer} {}", "x".repeat(500));
    let preview = bounded_preview(&input, 48, &[password, basic, bearer]);
    assert!(preview.contains("[REDACTED]"));
    assert!(preview.contains("truncated"));
    assert!(!preview.contains(password));
    assert!(!preview.contains(basic));
    assert!(!preview.contains(bearer));

    let redacted = redact_known_secrets(&input, &[password, basic, bearer]);
    assert!(!redacted.contains(password));
    assert!(!redacted.contains(basic));
    assert!(!redacted.contains(bearer));
}

#[tokio::test]
async fn readiness_timeout_reports_bounded_phase_context() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(100))
                .set_body_json(serde_json::json!({"version": "16.0.3"})),
        )
        .mount(&server)
        .await;
    let fixture = config(&complete(&server.uri())).unwrap();
    let error = wait_for_ready(&fixture, fast_options()).await.unwrap_err();
    assert!(error.contains("phase=version"));
    assert!(error.contains("attempts="));
    assert!(error.contains("deadline_ms="));
    assert!(error.len() < 700);
    assert!(!error.contains("fixture-password"));
}

#[tokio::test]
async fn unreachable_readiness_reports_transport_context() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let fixture = config(&complete(&format!("http://{address}"))).unwrap();
    let error = wait_for_ready(&fixture, fast_options()).await.unwrap_err();
    assert!(error.contains("phase=version"));
    assert!(error.contains("last_status=transport-error"));
    assert!(error.contains("attempts="));
}

#[tokio::test]
async fn readiness_reports_non_success_and_invalid_json() {
    for response in [
        ResponseTemplate::new(503).set_body_string("starting"),
        ResponseTemplate::new(200).set_body_string("not-json"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/version"))
            .respond_with(response)
            .mount(&server)
            .await;
        let fixture = config(&complete(&server.uri())).unwrap();
        let error = wait_for_ready(&fixture, fast_options()).await.unwrap_err();
        assert!(error.contains("phase=version"));
        assert!(error.contains("last_status="));
        assert!(error.len() < 700);
    }
}

#[tokio::test]
async fn readiness_reports_bad_authentication_without_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": "16.0.3"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/user"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("denied fixture-password Basic dXNlcjpwYXNz"),
        )
        .mount(&server)
        .await;

    let fixture = config(&complete(&server.uri())).unwrap();
    let error = wait_for_ready(&fixture, fast_options()).await.unwrap_err();
    assert!(error.contains("phase=authentication"));
    assert!(error.contains("401"));
    assert!(!error.contains("fixture-password"));
    assert!(!error.contains("Basic dXNlcjpwYXNz"));
    assert!(error.len() < 700);
}

#[test]
fn result_combiner_preserves_primary_and_all_cleanup_errors() {
    assert_eq!(combine_results(Ok(()), vec![Ok(())]), Ok(()));
    assert_eq!(
        combine_results(Err("primary".into()), vec![Ok(())]),
        Err("primary".into())
    );
    assert_eq!(
        combine_results(Ok(()), vec![Err("cleanup".into())]),
        Err("cleanup failed: cleanup".into())
    );
    assert_eq!(
        combine_results(
            Err("primary".into()),
            vec![Err("cleanup one".into()), Err("cleanup two".into())]
        ),
        Err("primary; cleanup also failed: cleanup one; cleanup two".into())
    );
}
