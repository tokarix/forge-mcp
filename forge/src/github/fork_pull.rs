//! Resolve GitHub fork pulls and authorize their pinned targets before dispatch.

use std::time::Duration;

use domain::{
    ChangeRequest, ChangeRequestState, ForgeCredential, ForkPullHead, Mergeability,
    OpenChangeRequestRequest, PinnedPullRepositories, PinnedPullRepository, PullAuthorization,
    RepositoryRef, ServiceError, valid_github_path,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use super::{GitHubAdapter, GitHubGraphQlError};
use crate::ForgeError;

const PINNED_REFS: &str = r"
query ForkPullRefs($source: ID!, $destination: ID!, $head: String!, $base: String!) {
  source: node(id: $source) {
    ...RepositoryPath
    ... on Repository { ref(qualifiedName: $head) { name prefix repository { id } } }
  }
  destination: node(id: $destination) {
    ...RepositoryPath
    ... on Repository { ref(qualifiedName: $base) { name prefix repository { id } } }
  }
}
fragment RepositoryPath on Repository {
  __typename id name nameWithOwner owner { login }
}";

const PULL_FIELDS: &str = r"
fragment ForkPullFields on PullRequest {
  number url title body state isDraft headRefName headRefOid baseRefName
  headRepository { id }
  baseRepository { id }
}";

const CREATE: &str = r"
mutation CreateForkPull($input: CreatePullRequestInput!) {
  createPullRequest(input: $input) { pullRequest { ...ForkPullFields } }
}";

const RECONCILE: &str = r"
query ReconcileForkPull($destination: ID!, $head: String!) {
  destination: node(id: $destination) {
    ... on Repository {
      id
      pullRequests(first: 100, headRefName: $head) {
        pageInfo { hasNextPage }
        nodes { ...ForkPullFields }
      }
    }
  }
}";

pub(super) fn client() -> Result<reqwest::Client, ForgeError> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(30))
        .build()?)
}

#[derive(Deserialize)]
struct NodeId {
    id: String,
}

#[derive(Deserialize)]
struct RestNodeId {
    node_id: String,
}

#[derive(Deserialize)]
struct Owner {
    login: String,
}

#[derive(Deserialize)]
struct ForkMetadata {
    node_id: String,
    owner: Owner,
    name: String,
    full_name: String,
    fork: bool,
    source: Option<RestNodeId>,
}

#[derive(Deserialize)]
struct GraphQl<T> {
    data: Option<T>,
    errors: Option<Vec<GitHubGraphQlError>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BranchRef {
    name: String,
    prefix: String,
    repository: NodeId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryNode {
    #[serde(rename = "__typename")]
    kind: String,
    id: String,
    name: String,
    name_with_owner: String,
    owner: Owner,
    r#ref: BranchRef,
}

#[derive(Deserialize)]
struct RepositoryNodes {
    source: RepositoryNode,
    destination: RepositoryNode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullNode {
    number: u64,
    url: String,
    title: String,
    body: String,
    state: PullState,
    is_draft: bool,
    head_ref_name: String,
    head_ref_oid: String,
    base_ref_name: String,
    head_repository: NodeId,
    base_repository: NodeId,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PullState {
    Open,
    Closed,
    Merged,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MutationData {
    create_pull_request: MutationPull,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MutationPull {
    pull_request: PullNode,
}

#[derive(Deserialize)]
struct ReconciliationData {
    destination: PullRepository,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullRepository {
    id: String,
    pull_requests: PullConnection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PullConnection {
    nodes: Vec<PullNode>,
    page_info: PageInfo,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageInfo {
    has_next_page: bool,
}

fn canonical_repository(
    requested: &RepositoryRef,
    owner: String,
    name: String,
    full_name: &str,
) -> Result<RepositoryRef, ServiceError> {
    if !valid_github_path(&owner, &name) || full_name != format!("{owner}/{name}") {
        return Err(ServiceError::Upstream(format!(
            "GitHub returned an inconsistent canonical path for {}/{}",
            requested.owner, requested.name,
        )));
    }
    Ok(RepositoryRef {
        owner,
        name,
        ..requested.clone()
    })
}

impl RepositoryNode {
    fn verify(
        self,
        pinned: &PinnedPullRepository,
        branch: &str,
        authorized: &PullAuthorization,
    ) -> Result<PinnedPullRepository, ServiceError> {
        if self.kind != "Repository" || self.id != pinned.id {
            return Err(ServiceError::Upstream(format!(
                "GitHub returned a different repository for pinned ID {}",
                pinned.id,
            )));
        }
        let canonical = canonical_repository(
            &pinned.canonical,
            self.owner.login,
            self.name,
            &self.name_with_owner,
        )?;
        authorized.require_repository(&canonical)?;
        if self.r#ref.prefix != "refs/heads/"
            || self.r#ref.name != branch
            || self.r#ref.repository.id != self.id
        {
            return Err(ServiceError::Upstream(format!(
                "GitHub did not verify refs/heads/{branch} on pinned repository {}",
                pinned.id,
            )));
        }
        Ok(PinnedPullRepository {
            canonical,
            id: self.id,
        })
    }
}

impl PullNode {
    fn matches(&self, pinned: &PinnedPullRepositories, head: &str, base: &str) -> bool {
        self.number > 0
            && !self.url.is_empty()
            && !self.head_ref_oid.is_empty()
            && self.head_repository.id == pinned.source.id
            && self.base_repository.id == pinned.destination.id
            && self.head_ref_name == head
            && self.base_ref_name == base
    }

    fn into_change_request(self) -> ChangeRequest {
        let state = match self.state {
            PullState::Open => ChangeRequestState::Open,
            PullState::Closed => ChangeRequestState::Closed,
            PullState::Merged => ChangeRequestState::Merged,
        };
        ChangeRequest {
            draft: Some(self.is_draft),
            base_branch: self.base_ref_name,
            body: self.body,
            changed_files_count: None,
            commit_count: None,
            source_branch_identity: None,
            head_branch: self.head_ref_name,
            head_sha: Some(self.head_ref_oid),
            has_conflicts: None,
            index: self.number,
            labels: Vec::new(),
            merge_base_sha: None,
            requested_reviewers: None,
            mergeability: Mergeability::Unknown,
            state,
            title: self.title,
            url: self.url,
        }
    }
}

impl GitHubAdapter {
    async fn fork_metadata(
        &self,
        requested: &RepositoryRef,
        authorized: &PullAuthorization,
        credential: &ForgeCredential,
    ) -> Result<(PinnedPullRepository, String), ServiceError> {
        let path = Self::repo_path(requested);
        let url = format!("{}/repos/{path}", self.api_base());
        let read = async {
            let response =
                Self::authenticate(self.fork_pull_client.get(url), credential.token.as_deref())
                    .send()
                    .await?;
            Self::check_response(response)
                .await?
                .json::<ForkMetadata>()
                .await
                .map_err(ForgeError::from)
        };
        let metadata = read.await.map_err(|error| {
            ServiceError::Upstream(format!(
                "GitHub repository lookup for {path} failed: {error:#?}"
            ))
        })?;
        let canonical = canonical_repository(
            requested,
            metadata.owner.login,
            metadata.name,
            &metadata.full_name,
        )?;
        authorized.require_repository(&canonical)?;
        let root = match (metadata.fork, metadata.source) {
            (true, Some(source)) if source.node_id != metadata.node_id => Some(source.node_id),
            (false, None) => Some(metadata.node_id.clone()),
            _ => None,
        }
        .filter(|root| !root.is_empty() && !metadata.node_id.is_empty())
        .ok_or_else(|| {
            ServiceError::Upstream(format!(
                "GitHub fork metadata for {path} is incomplete or inconsistent"
            ))
        })?;
        Ok((
            PinnedPullRepository {
                canonical,
                id: metadata.node_id,
            },
            root,
        ))
    }

    async fn fork_graphql<T: DeserializeOwned>(
        &self,
        operation: &str,
        query: &str,
        variables: Value,
        credential: &ForgeCredential,
    ) -> Result<T, ServiceError> {
        let send = async {
            let response = Self::authenticate(
                self.fork_pull_client
                    .post(self.graphql_url())
                    .json(&json!({"query": query, "variables": variables})),
                credential.token.as_deref(),
            )
            .send()
            .await?;
            Self::check_response(response)
                .await?
                .json::<GraphQl<T>>()
                .await
                .map_err(ForgeError::from)
        };
        let result = send.await.map_err(|error| {
            ServiceError::Upstream(format!("GitHub {operation} failed: {error:#?}"))
        })?;
        if let Some(errors) = result.errors.filter(|errors| !errors.is_empty()) {
            let messages = errors
                .into_iter()
                .map(|error| error.message)
                .collect::<Vec<_>>();
            return Err(ServiceError::Upstream(format!(
                "GitHub {operation} returned GraphQL errors: {}",
                messages.join("; "),
            )));
        }
        result
            .data
            .ok_or_else(|| ServiceError::Upstream(format!("GitHub {operation} returned no data")))
    }

    async fn read_pinned_refs(
        &self,
        request: &OpenChangeRequestRequest,
        head: &ForkPullHead<'_>,
        pinned: &PinnedPullRepositories,
        authorized: &PullAuthorization,
        credential: &ForgeCredential,
    ) -> Result<PinnedPullRepositories, ServiceError> {
        let current: RepositoryNodes = self
            .fork_graphql(
                "fork pull ref lookup",
                PINNED_REFS,
                json!({
                    "source": pinned.source.id,
                    "destination": pinned.destination.id,
                    "head": format!("refs/heads/{}", head.branch),
                    "base": format!("refs/heads/{}", request.base_branch),
                }),
                credential,
            )
            .await?;
        Ok(PinnedPullRepositories {
            source: current
                .source
                .verify(&pinned.source, head.branch, authorized)?,
            destination: current.destination.verify(
                &pinned.destination,
                &request.base_branch,
                authorized,
            )?,
        })
    }

    pub(super) async fn resolve_fork_repositories(
        &self,
        request: &OpenChangeRequestRequest,
        head: &ForkPullHead<'_>,
        authorized: &PullAuthorization,
        credential: &ForgeCredential,
    ) -> Result<PinnedPullRepositories, ServiceError> {
        if credential.token.as_deref().is_none_or(str::is_empty) {
            return Err(ServiceError::Upstream(
                "GitHub fork pull creation requires an upstream credential".into(),
            ));
        }
        let (destination, destination_root) = self
            .fork_metadata(&request.repository, authorized, credential)
            .await?;
        let (source, source_root) = self
            .fork_metadata(&head.repository, authorized, credential)
            .await?;
        if source.id == destination.id {
            return Err(ServiceError::Validation("source and destination identify the same GitHub repository. Use a bare head branch".into()));
        }
        if source_root != destination_root {
            return Err(ServiceError::Validation(
                "source and destination are in different GitHub fork networks".into(),
            ));
        }
        let pinned = PinnedPullRepositories {
            source,
            destination,
        };
        self.read_pinned_refs(request, head, &pinned, authorized, credential)
            .await
    }

    pub(super) async fn dispatch_fork_pull(
        &self,
        request: &OpenChangeRequestRequest,
        head: &ForkPullHead<'_>,
        pinned: &PinnedPullRepositories,
        authorized: &PullAuthorization,
        credential: &ForgeCredential,
    ) -> Result<ChangeRequest, ServiceError> {
        let verified = self
            .read_pinned_refs(request, head, pinned, authorized, credential)
            .await?;
        authorized.require_branch(&verified.source.canonical, head.branch)?;
        let result = self.fork_graphql::<MutationData>(
            "fork pull creation",
            &format!("{CREATE}{PULL_FIELDS}"),
            json!({
                "input": {
                    "repositoryId": verified.destination.id,
                    "headRepositoryId": verified.source.id,
                    "headRefName": format!("{}:{}", verified.source.canonical.owner, head.branch),
                    "baseRefName": request.base_branch,
                    "title": request.title,
                    "body": request.body,
                }
            }),
            credential,
        ).await
            .map(|data| data.create_pull_request.pull_request)
            .and_then(|pull| {
                if pull.matches(&verified, head.branch, &request.base_branch) {
                    Ok(pull.into_change_request())
                } else {
                    Err(ServiceError::Upstream(format!(
                        "GitHub fork pull creation returned inconsistent identity or refs for PR #{}",
                        pull.number,
                    )))
                }
            });
        match result {
            Ok(pull) => Ok(pull),
            Err(error) => {
                let observed = self
                    .reconcile_fork_pull(&verified, head.branch, &request.base_branch, credential)
                    .await;
                Err(ServiceError::Upstream(format!(
                    "GitHub fork pull creation outcome unconfirmed ({error}). {observed}"
                )))
            }
        }
    }

    async fn reconcile_fork_pull(
        &self,
        pinned: &PinnedPullRepositories,
        head: &str,
        base: &str,
        credential: &ForgeCredential,
    ) -> String {
        let result = self
            .fork_graphql::<ReconciliationData>(
                "fork pull readback",
                &format!("{RECONCILE}{PULL_FIELDS}"),
                json!({"destination": pinned.destination.id, "head": head}),
                credential,
            )
            .await;
        match result {
            Ok(data) if data.destination.id == pinned.destination.id => {
                let pulls = data.destination.pull_requests;
                let numbers = pulls
                    .nodes
                    .into_iter()
                    .filter(|pull| pull.matches(pinned, head, base))
                    .map(|pull| format!("#{}", pull.number))
                    .collect::<Vec<_>>();
                if pulls.page_info.has_next_page {
                    format!(
                        "Readback was partial. Matching pulls observed: {}.",
                        numbers.join(", ")
                    )
                } else if numbers.is_empty() {
                    "Readback found no matching pulls.".into()
                } else {
                    format!(
                        "Readback found {}. Attribution to this request is unknown.",
                        numbers.join(", ")
                    )
                }
            }
            Ok(_) => "Readback returned a different repository identity.".into(),
            Err(error) => format!("Readback failed ({error})."),
        }
    }
}
