//! Regression evidence from the CI-owned Forgejo 16.0.3 lifecycle.
#![allow(clippy::expect_used)]
use super::*;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

fn evidence() -> Value {
    let mut original: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/forgejo-source-identity-16.0.3.json"
    ))
    .expect("captured evidence");
    let prefix: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/forgejo-source-identity-prefix-16.0.3.json"
    ))
    .expect("prefix capture");
    for field in ["observations", "ground_truth"] {
        original[field].as_array_mut().expect("records").extend(
            prefix[field]
                .as_array()
                .expect("prefix records")
                .iter()
                .cloned(),
        );
    }
    original
}

fn wire(capture: &Value) -> Value {
    let mut value = crate::draft_contract_tests::fixture();
    for key in ["head", "base", "number", "merged", "state"] {
        value[key] = capture[key].clone();
    }
    value
}

#[test]
fn captured_list_and_detail_resolve_exact_ground_truth() {
    let evidence = evidence();
    for observation in evidence["observations"].as_array().expect("observations") {
        for key in ["list", "detail"] {
            let capture = &observation[key];
            let result: ForgejoPullRequest = serde_json::from_value(wire(capture)).expect("wire");
            let cr = result.into_change_request();
            assert_eq!(cr.head_branch, capture["head"]["ref"]);
            assert_eq!(cr.head_sha.as_deref(), capture["head"]["sha"].as_str());
            if capture["head"]["repo"].is_null() {
                assert_eq!(cr.source_branch_identity, None);
            } else {
                let identity = cr.source_branch_identity.expect("known identity");
                let truth = evidence["ground_truth"]
                    .as_array()
                    .expect("truth")
                    .iter()
                    .find(|row| {
                        row["index"] == capture["number"]
                            && row["source"]
                                == format!(
                                    "/api/v1/repos/{}",
                                    capture["head"]["repo"]["full_name"]
                                        .as_str()
                                        .expect("full name")
                                )
                    })
                    .expect("ground truth");
                assert_eq!(identity.branch, truth["branch"]);
                assert_eq!(identity.repository.id, capture["head"]["repo"]["id"]);
                assert_eq!(
                    identity.repository.owner,
                    capture["head"]["repo"]["owner"]["login"]
                );
                assert_eq!(identity.repository.name, capture["head"]["repo"]["name"]);
            }
        }
    }
}

#[test]
fn insufficient_or_conflicting_metadata_never_infers_identity() {
    let captured = &evidence()["observations"][0]["detail"];
    for (pointer, value) in [
        ("/head/label", Value::Null),
        ("/head/label", json!("")),
        ("/head/label", json!("owner:branch")),
        ("/head/repo", Value::Null),
        ("/head/repo_id", json!(-1)),
        ("/head/repo_id", json!(999)),
        ("/head/repo/owner/login", json!("")),
        ("/head/repo/full_name", json!("different/repository")),
        ("/head/ref", json!("contradiction")),
        ("/head/repo/name", json!("")),
    ] {
        let mut input = wire(captured);
        *input.pointer_mut(pointer).expect("pointer") = value;
        input["title"] = json!("evidence/closed/Case+λ");
        input["body"] = json!("Merged branch evidence/closed/Case+λ");
        let pr: ForgejoPullRequest = serde_json::from_value(input).expect("wire");
        assert_eq!(
            pr.into_change_request().source_branch_identity,
            None,
            "{pointer}"
        );
    }
    let mut input = wire(captured);
    input["head"].as_object_mut().expect("head").remove("label");
    let pr: ForgejoPullRequest = serde_json::from_value(input).expect("wire");
    assert_eq!(pr.into_change_request().source_branch_identity, None);
    for field in ["label", "repo", "repo_id"] {
        for absent in [false, true] {
            let mut input = wire(captured);
            if absent {
                input["head"].as_object_mut().expect("head").remove(field);
            } else {
                input["head"][field] = Value::Null;
            }
            let pr: ForgejoPullRequest = serde_json::from_value(input).expect("wire");
            assert_eq!(pr.into_change_request().source_branch_identity, None);
        }
    }
    for branch in [
        "Case/λ/+punctuation-_.@brace{}",
        "a/b/c",
        "Unicode/分支/nb\u{00a0}sp",
    ] {
        let mut input = wire(captured);
        input["head"]["label"] = json!(branch);
        input["head"]["ref"] = json!(branch);
        let pr: ForgejoPullRequest = serde_json::from_value(input).expect("wire");
        assert_eq!(
            pr.into_change_request()
                .source_branch_identity
                .expect("identity")
                .branch,
            branch
        );
    }
}

#[test]
fn collision_still_requires_original_label_and_repository_authority() {
    let evidence = evidence();
    for observation in evidence["observations"].as_array().expect("observations") {
        let captured = &observation["detail"];
        if captured["head"]["label"] != format!("refs/pull/{}/head", captured["number"]) {
            continue;
        }
        for pointer in ["/head/label", "/head/repo", "/head/repo_id"] {
            let mut input = wire(captured);
            *input.pointer_mut(pointer).expect("field") = Value::Null;
            let pr: ForgejoPullRequest = serde_json::from_value(input).expect("wire");
            assert_eq!(pr.into_change_request().source_branch_identity, None);
        }
    }
}

#[tokio::test]
async fn actual_adapter_exhausts_captured_pages_and_agrees_with_detail() {
    let mock = MockServer::start().await;
    let evidence = evidence();
    let adapter = ForgejoAdapter::new(ForgejoConfig {
        base_url: mock.uri(),
        token: None,
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
    let credential = ForgeCredential { token: None };
    let observations = evidence["observations"].as_array().expect("observations");
    let mut expected_rows = Vec::new();
    // Separate pages ensure terminal and unknown rows on later pages survive.
    for (offset, observation) in observations.iter().enumerate() {
        let page = offset + 1;
        let mut row = wire(&observation["list"]);
        // Preserve the actual open collision indices; other observations get
        // unique IDs so lifecycle repetitions do not trigger list deduplication.
        let collision = observation["phase"] == "prefix-open"
            && row["head"]["label"] == format!("refs/pull/{}/head", row["number"]);
        let index = if collision {
            row["number"].as_u64().expect("index")
        } else {
            u64::try_from(1000 + page).expect("index")
        };
        row["number"] = json!(index);
        // Only a captured replacement ref differs from the original label.
        // Genuine prefix names, including label/ref collisions, keep their bytes.
        if row["head"]["ref"] != row["head"]["label"]
            && row["head"]["ref"] == format!("refs/pull/{}/head", observation["list"]["number"])
        {
            row["head"]["ref"] = json!(format!("refs/pull/{index}/head"));
        }
        expected_rows.push(row.clone());
        let mut response = ResponseTemplate::new(200).set_body_json(json!([row.clone()]));
        if page < observations.len() {
            response = response.insert_header(
                "Link",
                format!(
                    "<{}/api/v1/repos/org/repo/pulls?state=all&page={}&limit=100>; rel=\"next\"",
                    mock.uri(),
                    page + 1
                ),
            );
        }
        Mock::given(method("GET"))
            .and(path("/api/v1/repos/org/repo/pulls"))
            .and(query_param("page", page.to_string()))
            .and(query_param("state", "all"))
            .respond_with(response)
            .expect(1)
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/repos/org/repo/pulls/{index}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(row))
            .mount(&mock)
            .await;
    }
    let rows = adapter
        .list_change_requests(&repo, Some(&domain::ChangeRequestFilter::All), &credential)
        .await
        .expect("list");
    assert_eq!(rows.len(), observations.len());
    for row in rows {
        let captured = expected_rows
            .iter()
            .find(|expected| expected["number"] == row.index)
            .expect("expected row");
        if captured["head"]["repo"].is_null() {
            assert_eq!(row.source_branch_identity, None);
        } else {
            let identity = row
                .source_branch_identity
                .as_ref()
                .expect("authoritative identity");
            assert_eq!(identity.branch, captured["head"]["label"]);
            assert_eq!(identity.repository.id, captured["head"]["repo"]["id"]);
        }
        let detail = adapter
            .get_change_request(&repo, row.index, &credential)
            .await
            .expect("detail");
        assert_eq!(row, detail);
    }
}
