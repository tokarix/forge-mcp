#![allow(clippy::expect_used)]

use domain::{ChangeRequestCommentDetail, ForgeCredential, ForgeKind, RepositoryRef};
use forge::github::{GitHubAdapter, GitHubConfig};
use forge::gitlab::{GitLabAdapter, GitLabConfig};
use forge::{ForgeAdapter, ForgejoAdapter, ForgejoConfig};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Provider {
    adapter: Box<dyn ForgeAdapter>,
    repository: RepositoryRef,
    discussion: String,
    reviews: String,
    auth_header: &'static str,
    auth_value: &'static str,
}

fn provider(kind: ForgeKind, url: &str) -> Provider {
    let (adapter, discussion, reviews, auth_header, auth_value): (
        Box<dyn ForgeAdapter>,
        _,
        _,
        _,
        _,
    ) = match kind {
        ForgeKind::Forgejo => (
            Box::new(
                ForgejoAdapter::new(ForgejoConfig {
                    base_url: url.into(),
                    token: Some("fallback".into()),
                    woodpecker_url: None,
                    woodpecker_token: None,
                })
                .expect("forgejo adapter"),
            ),
            "/api/v1/repos/org/repo/issues/7/comments",
            "/api/v1/repos/org/repo/pulls/7/reviews",
            "authorization",
            "Bearer selected-token",
        ),
        ForgeKind::GitHub => (
            Box::new(
                GitHubAdapter::new(GitHubConfig {
                    api_url: url.into(),
                    token: Some("fallback".into()),
                })
                .expect("github adapter"),
            ),
            "/repos/org/repo/issues/7/comments",
            "/repos/org/repo/pulls/7/reviews",
            "authorization",
            "Bearer selected-token",
        ),
        ForgeKind::GitLab => (
            Box::new(
                GitLabAdapter::new(GitLabConfig {
                    base_url: url.into(),
                    token: Some("fallback".into()),
                })
                .expect("gitlab adapter"),
            ),
            "/api/v4/projects/org%2Frepo/merge_requests/7/notes",
            "/api/v4/projects/org%2Frepo/merge_requests/7/approvals",
            "private-token",
            "selected-token",
        ),
    };
    Provider {
        adapter,
        repository: RepositoryRef {
            alias: "test".into(),
            forge: kind,
            host: url.into(),
            owner: "org".into(),
            name: "repo".into(),
        },
        discussion: discussion.into(),
        reviews: reviews.into(),
        auth_header,
        auth_value,
    }
}

fn credential() -> ForgeCredential {
    ForgeCredential {
        token: Some("selected-token".into()),
    }
}

async fn read(
    p: &Provider,
    reviews: bool,
) -> Result<Vec<ChangeRequestCommentDetail>, forge::ForgeError> {
    if reviews {
        p.adapter
            .get_change_request_reviews(&p.repository, 7, &credential())
            .await
    } else {
        p.adapter
            .get_change_request_discussion_comments(&p.repository, 7, &credential())
            .await
    }
}

fn discussion_data() -> Value {
    json!([
        {"id": 3, "body": "REQUEST_CHANGES is discussion text", "created_at": "b",
         "user": {"login": "alice"}, "author": {"username": "alice"}, "system": false},
        {"id": 1, "body": "first", "created_at": "a",
         "user": {"login": "bob"}, "author": {"username": "bob"}, "system": false},
        {"id": 2, "body": "equal timestamp", "created_at": "a",
         "user": {"login": "carol"}, "author": {"username": "carol"}, "system": false}
    ])
}

fn review_data(kind: &ForgeKind) -> Value {
    if *kind == ForgeKind::GitLab {
        return json!({"approved_by": [{"user": {"username": "reviewer"}}]});
    }
    let (changes, comment) = if *kind == ForgeKind::GitHub {
        ("CHANGES_REQUESTED", "COMMENTED")
    } else {
        ("REQUEST_CHANGES", "COMMENT")
    };
    let dismissed_state = if *kind == ForgeKind::Forgejo {
        changes
    } else {
        "DISMISSED"
    };
    json!([
        {"id": 12, "body": "changes", "commit_id": "head", "state": changes,
         "submitted_at": "b", "user": {"login": "reviewer"}},
        {"id": 10, "body": null, "commit_id": "old", "state": comment,
         "submitted_at": "a", "user": {"login": "reviewer"}},
        {"id": 11, "body": "dismissed", "state": dismissed_state, "dismissed": true,
         "submitted_at": "a", "user": {"login": "reviewer"}},
        {"id": 13, "body": null, "state": "PENDING",
         "submitted_at": null, "user": {"login": "reviewer"}},
        {"id": 14, "body": "draft", "state": "PENDING", "user": {"login": "reviewer"}}
    ])
}

#[tokio::test]
async fn narrow_reads_isolate_resources_and_preserve_fields() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        for reviews in [false, true] {
            let server = MockServer::start().await;
            let mut payload = if reviews {
                review_data(&kind)
            } else {
                discussion_data()
            };
            if kind == ForgeKind::GitLab && !reviews {
                payload.as_array_mut().expect("notes").push(json!({
                    "id": 99, "body": "system", "system": true, "created_at": "a",
                    "author": {"username": "system"}
                }));
            }
            let p = provider(kind.clone(), &server.uri());
            let (selected, unused) = if reviews {
                (&p.reviews, &p.discussion)
            } else {
                (&p.discussion, &p.reviews)
            };
            Mock::given(method("GET"))
                .and(path(selected))
                .and(header(p.auth_header, p.auth_value))
                .respond_with(ResponseTemplate::new(200).set_body_json(payload))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(unused))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            let result = read(&p, reviews).await.expect("isolated read");
            if !reviews {
                assert_eq!(
                    result.iter().map(|entry| entry.id).collect::<Vec<_>>(),
                    [1, 2, 3]
                );
                assert_eq!(result[0].author, "bob");
                assert_eq!(result[2].body, "REQUEST_CHANGES is discussion text");
                assert!(result.iter().all(|entry| entry.kind == "comment"
                    && entry.commit_id.is_none()
                    && entry.review_state.is_none()));
            } else if kind == ForgeKind::GitLab {
                assert_eq!(
                    result,
                    vec![ChangeRequestCommentDetail {
                        author: "reviewer".into(),
                        body: String::new(),
                        commit_id: None,
                        created_at: String::new(),
                        id: 0,
                        kind: "review".into(),
                        review_state: Some("APPROVED".into()),
                    }]
                );
            } else {
                assert_eq!(
                    result.iter().map(|entry| entry.id).collect::<Vec<_>>(),
                    [10, 11, 12]
                );
                assert!(result.iter().all(|entry| entry.kind == "review"));
                assert_eq!(result[0].body, "");
                assert_eq!(result[0].author, "reviewer");
                assert_eq!(result[0].created_at, "a");
                assert_eq!(
                    result[0].review_state.as_deref(),
                    Some(if kind == ForgeKind::GitHub {
                        "COMMENTED"
                    } else {
                        "COMMENT"
                    })
                );
                assert_eq!(result[0].commit_id.as_deref(), Some("old"));
                assert_eq!(result[1].review_state.as_deref(), Some("DISMISSED"));
                assert_eq!(result[2].commit_id.as_deref(), Some("head"));
                assert_eq!(
                    result[2].review_state.as_deref(),
                    Some(if kind == ForgeKind::GitHub {
                        "CHANGES_REQUESTED"
                    } else {
                        "REQUEST_CHANGES"
                    })
                );
            }
        }
    }
}

#[tokio::test]
async fn narrow_empty_and_selected_errors() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        for reviews in [false, true] {
            for status in [200, 503] {
                let server = MockServer::start().await;
                let p = provider(kind.clone(), &server.uri());
                let (selected, unused) = if reviews {
                    (&p.reviews, &p.discussion)
                } else {
                    (&p.discussion, &p.reviews)
                };
                let empty = if reviews && kind == ForgeKind::GitLab {
                    json!({"approved_by": []})
                } else {
                    json!([])
                };
                Mock::given(method("GET"))
                    .and(path(selected))
                    .respond_with(ResponseTemplate::new(status).set_body_json(empty))
                    .expect(1)
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .and(path(unused))
                    .respond_with(ResponseTemplate::new(500))
                    .expect(0)
                    .mount(&server)
                    .await;
                let result = read(&p, reviews).await;
                if status == 200 {
                    assert!(result.expect("empty read").is_empty());
                } else {
                    assert!(result.is_err());
                }
            }
        }
    }
}

#[tokio::test]
async fn github_narrow_pagination_and_later_page_errors() {
    for reviews in [false, true] {
        for status in [200, 503] {
            let server = MockServer::start().await;
            let p = provider(ForgeKind::GitHub, &server.uri());
            let (selected, unused) = if reviews {
                (&p.reviews, &p.discussion)
            } else {
                (&p.discussion, &p.reviews)
            };
            Mock::given(method("GET"))
                .and(path(selected))
                .and(query_param("page", "1"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header(
                            "Link",
                            format!("<{}{selected}?page=2>; rel=\"next\"", server.uri()),
                        )
                        .set_body_json(json!([])),
                )
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(selected))
                .and(query_param("page", "2"))
                .and(header("authorization", "Bearer selected-token"))
                .respond_with(ResponseTemplate::new(status).set_body_json(if reviews {
                    review_data(&ForgeKind::GitHub)
                } else {
                    discussion_data()
                }))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(unused))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            let result = read(&p, reviews).await;
            if status == 200 {
                assert_eq!(result.expect("later page").len(), 3);
            } else {
                assert!(result.is_err());
            }
        }
    }
}

#[tokio::test]
async fn mixed_feed_retains_stable_ties_and_fails_without_partial_results() {
    for kind in [ForgeKind::Forgejo, ForgeKind::GitHub, ForgeKind::GitLab] {
        for status in [200, 503] {
            let server = MockServer::start().await;
            let p = provider(kind.clone(), &server.uri());
            Mock::given(method("GET"))
                .and(path(&p.discussion))
                .respond_with(ResponseTemplate::new(200).set_body_json(discussion_data()))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(&p.reviews))
                .respond_with(ResponseTemplate::new(status).set_body_json(review_data(&kind)))
                .expect(1)
                .mount(&server)
                .await;
            let result = p
                .adapter
                .get_change_request_comments(&p.repository, 7, &credential())
                .await;
            if status != 200 {
                assert!(result.is_err());
                continue;
            }
            let ids = result
                .expect("mixed feed")
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>();
            assert_eq!(
                ids,
                if kind == ForgeKind::GitLab {
                    vec![0, 1, 2, 3]
                } else {
                    vec![1, 2, 10, 11, 3, 12]
                }
            );
        }
    }
}
