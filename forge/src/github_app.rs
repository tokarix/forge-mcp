//! Managed GitHub App installation credentials.

use domain::ForgeCredential;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{ForgeError, github::GitHubAdapter};

#[derive(Clone)]
pub struct GitHubAppConfig {
    pub app_id: u64,
    pub installation_id: u64,
    pub private_key_pem: String,
}

/// Refreshable credential for one GitHub App installation.
///
/// A credential is intentionally separate from [`GitHubAdapter`] so the
/// server can associate a different App installation with each forge-mcp
/// agent while sharing one GitHub API adapter.
#[derive(Clone)]
pub struct GitHubAppCredential {
    pub(crate) app_slug: Arc<str>,
    pub(crate) token: Arc<RwLock<String>>,
}

impl std::fmt::Debug for GitHubAppCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubAppCredential")
            .field("app_slug", &self.app_slug)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl GitHubAppCredential {
    /// Creates a managed installation credential and starts its refresh task.
    ///
    /// # Errors
    ///
    /// Returns an error when the private key is invalid, the JWT cannot be
    /// signed, or GitHub rejects the installation-token exchange.
    pub async fn new(api_url: &str, app: GitHubAppConfig) -> Result<Self, ForgeError> {
        crate::install_ring_provider();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Self::new_with_client(client, api_url.to_string(), app).await
    }

    pub(crate) async fn new_with_client(
        client: reqwest::Client,
        api_url: String,
        app: GitHubAppConfig,
    ) -> Result<Self, ForgeError> {
        let app_slug = resolve_app_slug(&client, &api_url, &app).await?;
        let token = exchange_installation_token(&client, &api_url, &app).await?;
        let managed_token = Arc::new(RwLock::new(token));
        spawn_installation_token_refresh(Arc::downgrade(&managed_token), client, api_url, app);
        Ok(Self {
            app_slug: app_slug.into(),
            token: managed_token,
        })
    }

    /// Returns the current installation token as a forge credential.
    #[must_use]
    pub fn credential(&self) -> ForgeCredential {
        ForgeCredential {
            token: self.token.read().ok().map(|token| token.clone()),
        }
    }

    /// Returns the GitHub bot login associated with this App.
    #[must_use]
    pub fn username(&self) -> String {
        format!("{}[bot]", self.app_slug)
    }

    pub(crate) fn matches_token(&self, token: &str) -> bool {
        self.token
            .read()
            .is_ok_and(|managed_token| managed_token.as_str() == token)
    }
}

impl std::fmt::Debug for GitHubAppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubAppConfig")
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct GitHubApp {
    slug: String,
}

#[derive(Debug, Deserialize)]
struct GitHubInstallationToken {
    token: String,
}

#[derive(Debug, Serialize)]
struct GitHubAppJwtClaims {
    exp: u64,
    iat: u64,
    iss: String,
}

fn app_jwt(app: &GitHubAppConfig) -> Result<String, ForgeError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ForgeError::Authentication(format!("system clock before epoch: {e}")))?
        .as_secs();
    let claims = GitHubAppJwtClaims {
        exp: now.saturating_add(9 * 60),
        iat: now.saturating_sub(60),
        iss: app.app_id.to_string(),
    };
    let key = EncodingKey::from_rsa_pem(app.private_key_pem.as_bytes())
        .map_err(|e| ForgeError::Authentication(format!("invalid GitHub App private key: {e}")))?;
    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|e| ForgeError::Authentication(format!("failed to sign GitHub App JWT: {e}")))
}

async fn exchange_installation_token(
    client: &reqwest::Client,
    api_url: &str,
    app: &GitHubAppConfig,
) -> Result<String, ForgeError> {
    let jwt = app_jwt(app)?;
    let url = format!(
        "{}/app/installations/{}/access_tokens",
        api_url.trim_end_matches('/'),
        app.installation_id
    );
    let response = GitHubAdapter::check_response(
        GitHubAdapter::authenticate(client.post(url), Some(&jwt))
            .send()
            .await?,
    )
    .await?;
    let token: GitHubInstallationToken = response.json().await?;
    if token.token.trim().is_empty() {
        return Err(ForgeError::Authentication(
            "GitHub returned an empty installation token".to_string(),
        ));
    }
    Ok(token.token)
}

async fn resolve_app_slug(
    client: &reqwest::Client,
    api_url: &str,
    app: &GitHubAppConfig,
) -> Result<String, ForgeError> {
    let jwt = app_jwt(app)?;
    let url = format!("{}/app", api_url.trim_end_matches('/'));
    let response = GitHubAdapter::check_response(
        GitHubAdapter::authenticate(client.get(url), Some(&jwt))
            .send()
            .await?,
    )
    .await?;
    let app: GitHubApp = response.json().await?;
    if app.slug.trim().is_empty() {
        return Err(ForgeError::Authentication(
            "GitHub returned an empty App slug".to_string(),
        ));
    }
    Ok(app.slug)
}

fn spawn_installation_token_refresh(
    token: Weak<RwLock<String>>,
    client: reqwest::Client,
    api_url: String,
    app: GitHubAppConfig,
) {
    tokio::spawn(async move {
        let mut delay = Duration::from_secs(50 * 60);
        loop {
            tokio::time::sleep(delay).await;
            let Some(token) = token.upgrade() else {
                return;
            };
            match exchange_installation_token(&client, &api_url, &app).await {
                Ok(value) => {
                    match token.write() {
                        Ok(mut current) => *current = value,
                        Err(error) => {
                            tracing::error!(%error, "GitHub App token lock poisoned");
                            return;
                        }
                    }
                    delay = Duration::from_secs(50 * 60);
                    tracing::debug!(
                        installation_id = app.installation_id,
                        "refreshed GitHub App installation token"
                    );
                }
                Err(error) => {
                    delay = Duration::from_secs(60);
                    tracing::warn!(
                        installation_id = app.installation_id,
                        %error,
                        "failed to refresh GitHub App installation token; retrying"
                    );
                }
            }
        }
    });
}
