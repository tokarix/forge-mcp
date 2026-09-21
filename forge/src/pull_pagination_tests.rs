#![allow(clippy::expect_used)]

use super::*;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

fn limits() -> IssuePaginationLimits {
    IssuePaginationLimits {
        page_size: 2,
        max_pages: 3,
        max_raw_issues: 6,
        max_page_bytes: 4096,
        max_total_bytes: 12288,
        deadline: Duration::from_secs(2),
    }
}

fn pull(number: u64, branch: &str) -> Value {
    let mut value = crate::draft_contract_tests::fixture();
    value["number"] = json!(number);
    value["head"]["ref"] = json!(branch);
    value
}

async fn page(mock: &MockServer, number: u64, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/org/repo/pulls"))
        .and(query_param("page", number.to_string()))
        .and(query_param("limit", "2"))
        .and(query_param("state", "open"))
        .and(header("authorization", "Bearer scoped"))
        .respond_with(response)
        .expect(1)
        .mount(mock)
        .await;
}

fn link(mock: &MockServer, number: u64) -> String {
    format!(
        "<{}/api/v1/repos/org/repo/pulls?limit=2&page={number}&state=open>; rel=\"next\"",
        mock.uri()
    )
}

async fn list(
    mock: &MockServer,
    limits: IssuePaginationLimits,
) -> Result<Vec<ChangeRequest>, ForgeError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        base_url: mock.uri(),
        token: Some("default".into()),
        woodpecker_url: None,
        woodpecker_token: None,
    })
    .expect("adapter");
    let repo = RepositoryRef {
        alias: "test".into(),
        forge: domain::ForgeKind::Forgejo,
        host: mock.uri(),
        owner: "org".into(),
        name: "repo".into(),
    };
    adapter
        .list_pulls_with_limits(
            &repo,
            Some(&ChangeRequestState::Open),
            &ForgeCredential {
                token: Some("scoped".into()),
            },
            limits,
        )
        .await
}

#[tokio::test]
async fn exhaustive_discovery_and_first_occurrence_deduplication() {
    for first_match in [false, true] {
        let mock = MockServer::start().await;
        page(
            &mock,
            1,
            ResponseTemplate::new(200)
                .insert_header("Link", link(&mock, 2))
                .set_body_json(json!([pull(
                    1,
                    if first_match { "target" } else { "other" }
                )])),
        )
        .await;
        // A short first page must not suppress its continuation. Overlap must
        // keep the first occurrence, even if a later representation changes.
        page(
            &mock,
            2,
            ResponseTemplate::new(200)
                .set_body_json(json!([pull(1, "changed"), pull(2, "target")])),
        )
        .await;
        let result = list(&mock, limits()).await.expect("exhaustive list");
        assert_eq!(result.iter().map(|pr| pr.index).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(
            result
                .iter()
                .filter(|pr| pr.head_branch == "target")
                .count(),
            if first_match { 2 } else { 1 }
        );
    }
}

#[tokio::test]
async fn empty_and_exact_boundary_are_exhausted_without_next_link() {
    for body in [json!([]), json!([pull(1, "a"), pull(2, "b")])] {
        let mock = MockServer::start().await;
        page(&mock, 1, ResponseTemplate::new(200).set_body_json(&body)).await;
        assert_eq!(
            list(&mock, limits()).await.expect("list").len(),
            body.as_array().expect("array").len()
        );
    }
}

#[tokio::test]
async fn downstream_failure_never_returns_a_prefix() {
    for response in [
        ResponseTemplate::new(500),
        ResponseTemplate::new(200).set_body_string("{"),
        ResponseTemplate::new(302).insert_header("Location", "http://unsafe.invalid"),
    ] {
        let mock = MockServer::start().await;
        page(
            &mock,
            1,
            ResponseTemplate::new(200)
                .insert_header("Link", link(&mock, 2))
                .set_body_json(json!([pull(1, "target")])),
        )
        .await;
        page(&mock, 2, response).await;
        assert!(list(&mock, limits()).await.is_err());
    }
}

#[tokio::test]
async fn invalid_continuations_fail_closed() {
    let mock = MockServer::start().await;
    let valid = link(&mock, 2);
    let cases = [
        link(&mock, 1),
        link(&mock, 3),
        "broken".into(),
        valid.replace(&mock.uri(), "http://unsafe.invalid"),
        valid.replace("/org/repo/", "/other/repo/"),
        valid.replace("state=open", "state=closed"),
        valid.replace("page=2", "page=2&page=3"),
        valid.replace("page=2", "page=bad"),
        valid.replace("; rel=\"next\"", ""),
        format!("{valid},{valid}"),
        valid.replace("; rel=\"next\"", "; rel=\"mystery\""),
        valid.replace("rel=\"next\"", "rel=\"last\""),
        String::new(),
    ];
    for value in cases {
        mock.reset().await;
        page(
            &mock,
            1,
            ResponseTemplate::new(200)
                .insert_header("Link", value)
                .set_body_json(json!([pull(1, "target")])),
        )
        .await;
        assert!(list(&mock, limits()).await.is_err());
        mock.verify().await;
    }
}

#[tokio::test]
async fn page_item_byte_and_time_budgets_fail_closed() {
    for kind in ["pages", "items", "page bytes", "total bytes", "time"] {
        let mock = MockServer::start().await;
        let mut budget = limits();
        let body = json!([pull(1, "target"), pull(2, "other")]);
        let bytes = serde_json::to_vec(&body).expect("JSON").len();
        match kind {
            "pages" => {
                budget.max_pages = 1;
                budget.max_raw_issues = 2;
            }
            "items" => budget.max_raw_issues = 2,
            "page bytes" => budget.max_page_bytes = 10,
            "total bytes" => {
                budget.max_page_bytes = bytes;
                budget.max_total_bytes = bytes;
            }
            "time" => budget.deadline = Duration::from_millis(20),
            _ => unreachable!(),
        }
        let mut response = ResponseTemplate::new(200)
            .insert_header("Link", link(&mock, 2))
            .set_body_json(&body);
        if kind == "time" {
            response = response.set_delay(Duration::from_millis(100));
        }
        page(&mock, 1, response).await;
        if matches!(kind, "items" | "total bytes") {
            page(&mock, 2, ResponseTemplate::new(200).set_body_json(&body)).await;
        }
        assert!(list(&mock, budget).await.is_err(), "{kind}");
    }
}

#[tokio::test]
async fn repeated_continuation_on_later_page_and_empty_continuation_fail() {
    for empty in [false, true] {
        let mock = MockServer::start().await;
        page(
            &mock,
            1,
            ResponseTemplate::new(200)
                .insert_header("Link", link(&mock, 2))
                .set_body_json(json!([pull(1, "target")])),
        )
        .await;
        page(
            &mock,
            2,
            ResponseTemplate::new(200)
                .insert_header("Link", link(&mock, if empty { 3 } else { 2 }))
                .set_body_json(if empty {
                    json!([])
                } else {
                    json!([pull(2, "target")])
                }),
        )
        .await;
        assert!(list(&mock, limits()).await.is_err());
    }
}
