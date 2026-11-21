//! Exercise repository admission and dispatch through the real GitHub adapter.
#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use audit::{AuditError, AuditRecord, AuditSink, InMemoryAuditSink};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use domain::{
    ForgeCredential, ForgeKind, OpenChangeRequestRequest, PullAuthorization, PullForgeBinding,
    RepositoryRef, RepositoryWriteService, ServiceError,
};
use forge::github::{GitHubAdapter, GitHubConfig};
use orchestrator::{ReadOrchestrator, WriteOrchestrator};
use serde_json::{Value, json};
use server::auth::AgentRegistry;
use server::auto_merge::AutoMergeService;
use server::config::{AgentConfig, AgentPolicyConfig};
use server::events::EventBus;
use server::handlers::AppState;
use server::registry::{ForgeInstance, ForgeRegistry};
use tower::ServiceExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ALIAS: &str = "github";
const TOKEN: &str = "forge-default-private-fork-reader";
const DESTINATION: &str = "upstream/project";
const FORK: &str = "fork/project";
const SELECTED_FORK: &str = "fork/renamed-fork";
const HEAD: &str = "agent/codex/Topic";
const BASE: &str = "release/v1";

type Writer = WriteOrchestrator<GitHubAdapter, TestAudit>;

#[derive(Default)]
struct TestAudit {
    sink: InMemoryAuditSink,
    fail: bool,
}

#[async_trait]
impl AuditSink for TestAudit {
    async fn record(&self, record: AuditRecord) -> Result<(), AuditError> {
        tokio::task::yield_now().await;
        if self.fail {
            return Err(AuditError::Unavailable);
        }
        self.sink.record(record).await
    }
}

struct Fixture {
    provider: MockServer,
    app: axum::Router,
    writer: Arc<Writer>,
    audit: Arc<TestAudit>,
    authorized: PullAuthorization,
}

impl Fixture {
    async fn new(grants: &[&str], prefix: Option<&str>, audit_fails: bool) -> Self {
        let provider = MockServer::start().await;
        let audit = Arc::new(TestAudit {
            fail: audit_fails,
            ..TestAudit::default()
        });
        let url = provider.uri();
        let adapter = Arc::new(
            GitHubAdapter::new(GitHubConfig {
                api_url: url.clone(),
                token: Some(TOKEN.into()),
            })
            .expect("GitHub adapter"),
        );
        let writer = Arc::new(
            WriteOrchestrator::new(adapter.clone(), audit.clone(), None).with_forge_binding(
                PullForgeBinding {
                    alias: ALIAS.into(),
                    host: url.clone(),
                    kind: ForgeKind::GitHub,
                },
            ),
        );
        let forges = Arc::new(ForgeRegistry::new(HashMap::from([(
            ALIAS.into(),
            ForgeInstance {
                adapter: adapter.clone(),
                alias: ALIAS.into(),
                base_url: url,
                client: server::http_client::client_builder()
                    .build()
                    .expect("client"),
                forge_kind: ForgeKind::GitHub,
                forge_type: "github".into(),
                git_auth_user: "x-access-token".into(),
                read_service: Arc::new(ReadOrchestrator::new(adapter.clone(), audit.clone())),
                token: None,
                webhook: None,
                webhook_adapter: adapter,
                write_service: writer.clone(),
            },
        )])));
        let agents = AgentRegistry::from_configs(&[AgentConfig {
            agent_id: "codex".into(),
            session_id: "test".into(),
            token: "test-token".into(),
            forge_identity: HashMap::new(),
            github_app: HashMap::new(),
            policy: AgentPolicyConfig {
                allowed_repos: grants.iter().map(|s| (*s).into()).collect(),
                branch_prefix: prefix.map(str::to_owned),
                protected_paths: Vec::new(),
            },
        }]);
        let agent = agents.resolve("test-token").expect("agent is registered");
        let authorized = PullAuthorization {
            agent: agent.identity.clone(),
            grants: agent.policy_config.allowed_repos.clone(),
            policy: agent.policy.clone(),
        };
        let events = EventBus::new();
        let app = server::build_router(
            AppState {
                agent_registry: agents,
                auto_merge_service: Arc::new(AutoMergeService::new(events.clone(), forges.clone())),
                audit_sink: audit.clone(),
                event_bus: events,
                forge_registry: forges,
            },
            false,
        );
        Self {
            provider,
            app,
            writer,
            audit,
            authorized,
        }
    }

    async fn http(&self, head: &str, selector: Option<&str>) -> (StatusCode, Value) {
        self.http_to(DESTINATION, head, selector).await
    }

    async fn http_to(
        &self,
        destination: &str,
        head: &str,
        selector: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut body = json!({
            "title": "Fixture title", "body": "Fixture\nbody", "head_branch": head, "base_branch": BASE
        });
        if let Some(selector) = selector {
            body["head_repo"] = json!(selector);
        }
        let response = self
            .app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/repos/{ALIAS}/{destination}/pulls"))
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("handler response");
        let status = response.status();
        let body = to_bytes(response.into_body(), 20_000).await.expect("body");
        (
            status,
            serde_json::from_slice(&body).expect("JSON response"),
        )
    }

    fn request(&self, head: &str, selector: Option<&str>) -> OpenChangeRequestRequest {
        OpenChangeRequestRequest {
            repository: RepositoryRef {
                alias: ALIAS.into(),
                forge: ForgeKind::GitHub,
                host: self.provider.uri(),
                owner: "upstream".into(),
                name: "project".into(),
            },
            head_branch: head.into(),
            head_repo: selector.map(str::to_owned),
            base_branch: BASE.into(),
            title: "Fixture title".into(),
            body: "Fixture\nbody".into(),
        }
    }

    async fn direct(&self, request: OpenChangeRequestRequest) -> Result<(), ServiceError> {
        self.writer
            .open_change_request(
                request,
                self.authorized.clone(),
                &ForgeCredential { token: None },
            )
            .await
            .map(|_| ())
    }

    async fn requests(&self) -> Vec<wiremock::Request> {
        self.provider
            .received_requests()
            .await
            .expect("provider requests")
    }
}

fn metadata(path: &str, id: &str, root: Option<&str>) -> Value {
    let (owner, name) = path.split_once('/').expect("repository path");
    json!({
        "owner": {"login": owner}, "name": name, "full_name": path,
        "node_id": id, "fork": root.is_some(), "private": true,
        "source": root.map(|node_id| json!({"node_id": node_id}))
    })
}

fn repository(path: &str, id: &str, branch: &str) -> Value {
    let (owner, name) = path.split_once('/').expect("repository path");
    json!({
        "__typename": "Repository",
        "id": id, "name": name, "nameWithOwner": path, "owner": {"login": owner},
        "ref": {"name": branch, "prefix": "refs/heads/", "repository": {"id": id}}
    })
}

fn pair(source: &str, destination: &str) -> Value {
    json!({"data": {
        "source": repository(source, "fork-id", HEAD),
        "destination": repository(destination, "root-id", BASE)
    }})
}

fn pull() -> Value {
    json!({
        "number": 19, "url": "https://github.example/pull/19", "title": "Fixture title",
        "body": "Fixture\nbody", "state": "OPEN", "isDraft": false,
        "headRefName": HEAD, "headRefOid": "fixture-head-oid", "baseRefName": BASE,
        "headRepository": {"id": "fork-id"}, "baseRepository": {"id": "root-id"}
    })
}

async fn serve_metadata(fixture: &Fixture, requested: &str, data: Value) {
    Mock::given(method("GET"))
        .and(path(format!("/repos/{requested}")))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(data))
        .mount(&fixture.provider)
        .await;
}

async fn serve_pair(fixture: &Fixture, requested_source: &str) {
    serve_metadata(fixture, DESTINATION, metadata(DESTINATION, "root-id", None)).await;
    serve_metadata(
        fixture,
        requested_source,
        metadata(requested_source, "fork-id", Some("root-id")),
    )
    .await;
}

fn query(operation: &'static str) -> impl Fn(&wiremock::Request) -> bool {
    move |request| {
        request.body_json::<Value>().ok().is_some_and(|body| {
            body["query"]
                .as_str()
                .is_some_and(|query| query.contains(operation))
        })
    }
}

async fn serve_refs(fixture: &Fixture, initial: Value, final_response: ResponseTemplate) {
    let audit = fixture.audit.clone();
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(query("query ForkPullRefs"))
        .respond_with(move |_: &wiremock::Request| {
            if audit.sink.records().expect("audit readable").is_empty() {
                ResponseTemplate::new(200).set_body_json(&initial)
            } else {
                final_response.clone()
            }
        })
        .mount(&fixture.provider)
        .await;
}

async fn serve_create(fixture: &Fixture, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(query("mutation CreateForkPull"))
        .respond_with(response)
        .mount(&fixture.provider)
        .await;
}

#[tokio::test]
async fn grants_block_all_provider_requests_even_with_a_forge_wide_credential() {
    for prefix in [Some("agent/codex/"), None] {
        for (grants, destination_denied) in [
            (&["github/upstream/project"][..], false),
            (&["github/fork/*", "other/upstream/project"][..], true),
            (&["github/upstream/project", "other/fork/*"][..], false),
            (&["other/*"][..], true),
        ] {
            let fixture = Fixture::new(grants, prefix, false).await;
            serve_pair(&fixture, FORK).await;
            serve_metadata(
                &fixture,
                SELECTED_FORK,
                metadata(SELECTED_FORK, "private", Some("root-id")),
            )
            .await;
            for (qualified_head, selector) in [
                (format!("fork:{HEAD}"), None),
                (format!("missing:{HEAD}"), None),
                (format!("fork:{HEAD}"), Some("renamed-fork")),
                (format!("fork:{HEAD}"), Some("nonexistent")),
            ] {
                let (status, body) = fixture.http(&qualified_head, selector).await;
                assert_eq!(
                    status,
                    if destination_denied {
                        StatusCode::FORBIDDEN
                    } else {
                        StatusCode::BAD_REQUEST
                    }
                );
                let denied_path = if destination_denied {
                    DESTINATION.into()
                } else {
                    let (owner, _) = qualified_head.split_once(':').expect("qualified head");
                    format!("{owner}/{}", selector.unwrap_or("project"))
                };
                assert!(
                    body["error"]
                        .as_str()
                        .expect("policy message")
                        .ends_with(&format!("is not authorized for repository '{denied_path}'")),
                    "{body}"
                );
                let error = fixture
                    .direct(fixture.request(&qualified_head, selector))
                    .await
                    .expect_err("service must deny the same grants");
                assert!(matches!(error, ServiceError::PolicyDenied { reasons }
                    if reasons.ends_with(&format!("is not authorized for repository '{denied_path}'"))));
            }
            if destination_denied {
                let head = format!("fork:{HEAD}");
                for selector in [None, Some("project")] {
                    let (status, body) = fixture.http_to("upstream/missing", &head, selector).await;
                    assert_eq!(status, StatusCode::FORBIDDEN);
                    let reason = "is not authorized for repository 'upstream/missing'";
                    assert!(
                        body["error"]
                            .as_str()
                            .expect("policy message")
                            .ends_with(reason)
                    );

                    let mut request = fixture.request(&head, selector);
                    request.repository.name = "missing".into();
                    let error = fixture
                        .direct(request)
                        .await
                        .expect_err("missing destination");
                    assert!(matches!(error, ServiceError::PolicyDenied { reasons }
                        if reasons.ends_with(reason)));
                }
            }
            assert!(fixture.requests().await.is_empty());
            assert!(fixture.audit.sink.records().expect("audit").is_empty());
        }
    }
}

#[tokio::test]
async fn rejects_invalid_heads_and_forge_bindings_before_provider_io() {
    let fixture = Fixture::new(&["github/*"], Some("agent/codex/"), false).await;
    for (head, selector, policy_denied) in [
        ("fork:other/topic", None, true),
        ("fork:agent/codex/:extra", None, false),
        (":agent/codex/topic", None, false),
        ("fork:", None, false),
        ("path/fork:agent/codex/topic", None, false),
        ("fork:refs/heads/agent/codex/topic", None, false),
        ("fork:agent/codex//topic", None, false),
        ("fork:agent/codex/topic.lock", None, false),
        ("fork:agent/codex/topic", Some("nested/path"), false),
        ("fork:agent/codex/topic", Some("%2e%2e"), false),
        (HEAD, Some("project"), false),
    ] {
        assert_eq!(
            fixture.http(head, selector).await.0,
            StatusCode::BAD_REQUEST
        );
        let error = fixture
            .direct(fixture.request(head, selector))
            .await
            .expect_err("invalid request denied");
        assert_eq!(
            matches!(error, ServiceError::PolicyDenied { .. }),
            policy_denied
        );
    }
    let qualified = format!("fork:{HEAD}");
    for invalid_base in ["refs/heads/main", "@{-1}", "feature/.topic", "feature/"] {
        let mut request = fixture.request(&qualified, None);
        request.base_branch = invalid_base.into();
        assert!(matches!(
            fixture.direct(request).await,
            Err(ServiceError::Validation(_))
        ));
    }
    let mut request = fixture.request(&qualified, None);
    request.repository.alias = "other".into();
    assert!(matches!(
        fixture.direct(request).await,
        Err(ServiceError::Validation(_))
    ));
    let mut request = fixture.request(&qualified, Some("project"));
    request.repository.forge = ForgeKind::Forgejo;
    assert!(matches!(
        fixture.direct(request).await,
        Err(ServiceError::Validation(_))
    ));
    assert!(fixture.requests().await.is_empty());
}

fn assert_ref_lookup(request: &wiremock::Request) {
    assert_eq!(request.url.path(), "/graphql");
    assert!(query("query ForkPullRefs")(request));
    assert_eq!(
        request.body_json::<Value>().expect("ref payload")["variables"],
        json!({
            "source": "fork-id", "destination": "root-id",
            "head": format!("refs/heads/{HEAD}"), "base": format!("refs/heads/{BASE}"),
        })
    );
}

#[tokio::test]
async fn authorized_forks_create_once_using_ids_and_final_owner() {
    for (source, selector, final_source, final_destination, grants) in [
        (
            FORK,
            None,
            FORK,
            DESTINATION,
            &["github/upstream/project", "github/fork/project"][..],
        ),
        (
            SELECTED_FORK,
            Some("renamed-fork"),
            SELECTED_FORK,
            DESTINATION,
            &["github/upstream/*", "github/fork/*"][..],
        ),
        (
            FORK,
            None,
            "new-fork/moved",
            "new-upstream/moved",
            &["github/*"][..],
        ),
    ] {
        let fixture = Fixture::new(grants, Some("agent/codex/"), false).await;
        serve_pair(&fixture, source).await;
        serve_refs(
            &fixture,
            pair(source, DESTINATION),
            ResponseTemplate::new(200).set_body_json(pair(final_source, final_destination)),
        )
        .await;
        serve_create(
            &fixture,
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {"createPullRequest": {"pullRequest": pull()}}
            })),
        )
        .await;
        let (status, body) = fixture.http(&format!("fork:{HEAD}"), selector).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["index"], 19);
        assert_eq!(body["state"], "Open");
        assert_eq!(body["head_branch"], HEAD);
        assert_eq!(body["base_branch"], BASE);
        assert_eq!(body["head_sha"], "fixture-head-oid");
        let requests = fixture.requests().await;
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[0].url.path(), format!("/repos/{DESTINATION}"));
        assert_eq!(requests[1].url.path(), format!("/repos/{source}"));
        assert_ref_lookup(&requests[2]);
        assert_ref_lookup(&requests[3]);
        assert!(query("mutation CreateForkPull")(&requests[4]));
        let (owner, _) = final_source.split_once('/').expect("final source path");
        assert_eq!(
            requests[4].body_json::<Value>().expect("mutation payload")["variables"]["input"],
            json!({
                "repositoryId": "root-id", "headRepositoryId": "fork-id",
                "baseRefName": BASE, "headRefName": format!("{owner}:{HEAD}"),
                "title": "Fixture title", "body": "Fixture\nbody",
            })
        );
        let records = fixture.audit.sink.records().expect("audit");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].target,
            format!(
                "{source} (fork-id) refs/heads/{HEAD} -> {DESTINATION} (root-id) refs/heads/{BASE}",
            )
        );
    }
}

#[tokio::test]
async fn bare_head_uses_only_the_original_rest_write() {
    let fixture = Fixture::new(&["*"], Some("agent/codex/"), false).await;
    Mock::given(method("POST"))
        .and(path("/repos/upstream/project/pulls"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(wiremock::matchers::body_json(json!({
            "head": HEAD, "base": BASE, "title": "Fixture title", "body": "Fixture\nbody",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "number": 17, "node_id": "rest-pull", "state": "open",
            "html_url": "https://github.example/pull/17", "title": "Fixture title", "body": "Fixture\nbody",
            "head": {"ref": HEAD, "sha": "head"}, "base": {"ref": BASE, "sha": "base"},
        })))
        .expect(1)
        .mount(&fixture.provider).await;
    let (status, body) = fixture.http(HEAD, None).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["index"], 17);
    assert_eq!(fixture.requests().await.len(), 1);
}

#[tokio::test]
async fn resolution_denies_ungranted_canonical_paths_and_wrong_fork_membership() {
    let fixture = Fixture::new(&["github/fork/*", "github/upstream/*"], None, false).await;
    serve_metadata(
        &fixture,
        DESTINATION,
        metadata("transferred/project", "root-id", None),
    )
    .await;
    let error = fixture
        .direct(fixture.request(&format!("fork:{HEAD}"), None))
        .await
        .expect_err("ungranted canonical destination");
    assert!(matches!(error, ServiceError::PolicyDenied { .. }));
    assert_eq!(fixture.requests().await.len(), 1);

    for (canonical, id, root, expected) in [
        (
            "transferred/project",
            "fork-id",
            Some("root-id"),
            "not authorized",
        ),
        (
            FORK,
            "fork-id",
            Some("different-root"),
            "different GitHub fork networks",
        ),
        (FORK, "root-id", None, "Use a bare head"),
        (FORK, "fork-id", Some(""), "incomplete or inconsistent"),
    ] {
        let fixture = Fixture::new(&["github/fork/*", "github/upstream/*"], None, false).await;
        serve_metadata(
            &fixture,
            DESTINATION,
            metadata(DESTINATION, "root-id", None),
        )
        .await;
        serve_metadata(&fixture, FORK, metadata(canonical, id, root)).await;
        let error = fixture
            .direct(fixture.request(&format!("fork:{HEAD}"), None))
            .await
            .expect_err("initial metadata rejected");
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(fixture.requests().await.len(), 2);
        assert!(fixture.audit.sink.records().expect("audit").is_empty());
    }
}

#[tokio::test]
async fn missing_ref_and_audit_failure_stop_before_final_read() {
    for audit_fails in [false, true] {
        let fixture = Fixture::new(&["github/*"], None, audit_fails).await;
        serve_pair(&fixture, FORK).await;
        let mut initial = pair(FORK, DESTINATION);
        if !audit_fails {
            initial["data"]["source"]["ref"] = Value::Null;
        }
        serve_refs(&fixture, initial, ResponseTemplate::new(500)).await;
        let error = fixture
            .direct(fixture.request(&format!("fork:{HEAD}"), None))
            .await
            .expect_err("request must stop before final read");
        assert_eq!(
            matches!(error, ServiceError::Audit(_)),
            audit_fails,
            "{error}"
        );
        let requests = fixture.requests().await;
        assert_eq!(requests.len(), 3);
        assert_ref_lookup(&requests[2]);
    }
}

#[tokio::test]
async fn final_read_denies_moves_replacement_wrong_refs_and_partial_data() {
    let mut replaced = pair(FORK, DESTINATION);
    replaced["data"]["source"] = repository(FORK, "replacement-id", HEAD);
    let mut wrong_ref = pair(FORK, DESTINATION);
    wrong_ref["data"]["destination"]["ref"]["prefix"] = json!("refs/tags/");
    for (status, readback, expected) in [
        (200, pair("moved/project", DESTINATION), "not authorized"),
        (200, pair(FORK, "moved/project"), "not authorized"),
        (200, replaced, "different repository"),
        (200, wrong_ref, "did not verify refs/heads"),
        (200, json!({"data": {"source": null}}), "ref lookup failed"),
        (
            200,
            json!({"data": pair(FORK, DESTINATION)["data"], "errors": [{"message":"truncated"}]}),
            "GraphQL errors",
        ),
        (
            500,
            json!({"message":"provider unavailable"}),
            "ref lookup failed",
        ),
    ] {
        let fixture = Fixture::new(
            &["github/upstream/project", "github/fork/project"],
            None,
            false,
        )
        .await;
        serve_pair(&fixture, FORK).await;
        // A second path lookup could return a different repository at the old path.
        // The complete request trace below requires both reads to use the pinned IDs.
        serve_refs(
            &fixture,
            pair(FORK, DESTINATION),
            ResponseTemplate::new(status).set_body_json(readback),
        )
        .await;
        let audit = fixture.audit.clone();
        Mock::given(method("GET"))
            .and(path("/repos/fork/project"))
            .and(move |_: &wiremock::Request| {
                !audit.sink.records().expect("audit readable").is_empty()
            })
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata(
                FORK,
                "replacement-id",
                Some("root-id"),
            )))
            .with_priority(1)
            .mount(&fixture.provider)
            .await;
        let error = fixture
            .direct(fixture.request(&format!("fork:{HEAD}"), None))
            .await
            .expect_err("final authorization must fail closed");
        assert!(error.to_string().contains(expected), "{error}");
        let requests = fixture.requests().await;
        assert_eq!(requests.len(), 4);
        assert_ref_lookup(&requests[2]);
        assert_ref_lookup(&requests[3]);
        assert_eq!(fixture.audit.sink.records().expect("audit").len(), 1);
    }
}

#[tokio::test]
async fn ambiguous_mutation_does_read_only_reconciliation_without_replay() {
    let mut inconsistent_pull = pull();
    inconsistent_pull["headRepository"]["id"] = json!("unexpected-id");
    for response in [
        ResponseTemplate::new(503),
        ResponseTemplate::new(200).set_body_json(json!({
            "data": {"createPullRequest": {"pullRequest": inconsistent_pull}}
        })),
    ] {
        let fixture = Fixture::new(&["github/*"], None, false).await;
        serve_pair(&fixture, FORK).await;
        serve_refs(
            &fixture,
            pair(FORK, DESTINATION),
            ResponseTemplate::new(200).set_body_json(pair(FORK, DESTINATION)),
        )
        .await;
        serve_create(&fixture, response).await;
        Mock::given(path("/graphql"))
            .and(query("query ReconcileForkPull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"destination": {"id": "root-id", "pullRequests": {
                    "pageInfo": {"hasNextPage": false}, "nodes": [pull()],
                }}}
            })))
            .expect(1)
            .mount(&fixture.provider)
            .await;
        let (status, body) = fixture.http(&format!("fork:{HEAD}"), None).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert!(
            body["error"]
                .as_str()
                .expect("error")
                .contains("Readback found #19.")
        );
        let requests = fixture.requests().await;
        assert_eq!(requests.len(), 6);
        assert!(query("mutation CreateForkPull")(&requests[4]));
        assert!(query("query ReconcileForkPull")(&requests[5]));
        assert_eq!(
            requests[5]
                .body_json::<Value>()
                .expect("readback variables")["variables"],
            json!({"destination": "root-id", "head": HEAD})
        );
    }
}
