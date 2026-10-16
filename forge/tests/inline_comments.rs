//! Inline REST reads preserve locations and fail atomically within pagination limits.
#![allow(clippy::expect_used)]

use domain::{ForgeCredential, ForgeKind, RepositoryRef};
use forge::github::{GitHubAdapter, GitHubConfig};
use forge::gitlab::{GitLabAdapter, GitLabConfig};
use forge::{ForgeAdapter, ForgeError, ForgejoAdapter, ForgejoConfig};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/github-inline-comments.json")).expect("fixture")
}

fn repository(host: &str) -> RepositoryRef {
    RepositoryRef {
        alias: "github".into(),
        forge: ForgeKind::GitHub,
        host: host.into(),
        owner: "org".into(),
        name: "repo".into(),
    }
}

fn adapter(base: &str) -> GitHubAdapter {
    GitHubAdapter::new(GitHubConfig {
        api_url: base.into(),
        token: Some("fallback-token".into()),
    })
    .expect("adapter")
}

fn credential() -> ForgeCredential {
    ForgeCredential {
        token: Some("agent-token".into()),
    }
}

#[tokio::test]
async fn github_enterprise_pages_preserve_roots_replies_and_unknown_locations() {
    let server = MockServer::start().await;
    let base = format!("{}/api/v3", server.uri());
    let endpoint = "/api/v3/repos/org/repo/pulls/7/comments";
    let payload = fixture();
    for (page, entries) in [
        (1, json!([payload[0], payload[1]])),
        (2, json!([payload[2], payload[3]])),
    ] {
        let mut response = ResponseTemplate::new(200).set_body_json(entries);
        if page == 1 {
            response = response.insert_header(
                "Link",
                format!("<{}{endpoint}?page=2>; rel=\"next\"", server.uri()),
            );
        }
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", page.to_string()))
            .and(query_param("per_page", "100"))
            .and(header("authorization", "Bearer agent-token"))
            .and(header("x-github-api-version", "2022-11-28"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
    }
    let result = adapter(&base)
        .get_change_request_inline_comments(&repository(&base), 7, &credential())
        .await
        .expect("complete read");
    assert_eq!(result.len(), 4);
    // Compare every supplied field, allowing only the deliberate user/login and
    // html_url/web URL normalization. All other serialized fields must be null.
    for (actual, supplied) in result.iter().zip(payload.as_array().expect("comments")) {
        let actual = serde_json::to_value(actual).expect("typed comment");
        for (key, value) in actual.as_object().expect("object") {
            let expected = match key.as_str() {
                "author" => &supplied["user"]["login"],
                "url" => &supplied["html_url"],
                _ => &supplied[key],
            };
            assert_eq!(value, expected, "field {key}");
        }
        for key in supplied.as_object().expect("supplied object").keys() {
            if key != "user" && key != "html_url" {
                assert_eq!(actual[key], supplied[key], "preserved field {key}");
            }
        }
    }
    assert_eq!(result[1].in_reply_to_id, Some(101));
    assert_eq!(result[1].line, None);
    assert_eq!(result[1].original_line, Some(12));
    assert_eq!(server.received_requests().await.expect("requests").len(), 2);
}

#[tokio::test]
async fn empty_and_malformed_reads_are_distinct() {
    for (payload, succeeds) in [
        (json!([]), true),
        (json!({}), false),
        (json!([{"id":1}]), false),
        (Value::Null, false),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/repo/pulls/7/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(payload))
            .expect(1)
            .mount(&server)
            .await;
        let result = adapter(&server.uri())
            .get_change_request_inline_comments(&repository(&server.uri()), 7, &credential())
            .await;
        if succeeds {
            assert!(result.expect("empty list").is_empty());
        } else {
            assert!(result.is_err());
        }
    }
}

#[tokio::test]
async fn later_page_errors_and_malformed_continuations_reject_partial_feedback() {
    for (status, payload, link) in [
        (503, json!([]), None),
        (200, json!({}), None),
        (200, json!([{"id":2}]), None),
        (200, json!([]), Some("<http://unused?page=2>; rel=\"next\"")),
        (
            200,
            json!([]),
            Some("<http://unused?page=invalid>; rel=\"next\""),
        ),
    ] {
        let server = MockServer::start().await;
        let endpoint = "/repos/org/repo/pulls/7/comments";
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(fixture())
                    .insert_header(
                        "Link",
                        format!("<{}{endpoint}?page=2>; rel=\"next\"", server.uri()),
                    ),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut response = ResponseTemplate::new(status).set_body_json(payload);
        if let Some(link) = link {
            response = response.insert_header("Link", link);
        }
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "2"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            adapter(&server.uri())
                .get_change_request_inline_comments(&repository(&server.uri()), 7, &credential())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn page_budget_exhaustion_rejects_partial_feedback() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/org/repo/pulls/7/comments"))
        .respond_with(|request: &wiremock::Request| {
            let page: u64 = request
                .url
                .query_pairs()
                .find(|(key, _)| key == "page")
                .expect("page")
                .1
                .parse()
                .expect("page number");
            ResponseTemplate::new(200)
                .set_body_json(json!([]))
                .insert_header(
                    "Link",
                    format!("<http://unused?page={}>; rel=\"next\"", page + 1),
                )
        })
        .expect(1000)
        .mount(&server)
        .await;
    let error = adapter(&server.uri())
        .get_change_request_inline_comments(&repository(&server.uri()), 7, &credential())
        .await
        .expect_err("page budget");
    assert!(error.to_string().contains("page budget"), "{error}");
}

#[tokio::test]
async fn unsupported_providers_fail_without_upstream_access() {
    let server = MockServer::start().await;
    let adapters: Vec<Box<dyn ForgeAdapter>> = vec![
        Box::new(
            ForgejoAdapter::new(ForgejoConfig {
                base_url: server.uri(),
                token: None,
                woodpecker_url: None,
                woodpecker_token: None,
            })
            .expect("forgejo"),
        ),
        Box::new(
            GitLabAdapter::new(GitLabConfig {
                base_url: server.uri(),
                token: None,
            })
            .expect("gitlab"),
        ),
    ];
    for adapter in adapters {
        assert!(matches!(
            adapter
                .get_change_request_inline_comments(&repository(&server.uri()), 7, &credential())
                .await,
            Err(ForgeError::Unsupported(_))
        ));
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty()
    );
}
