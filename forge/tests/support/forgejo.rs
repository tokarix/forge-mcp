use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::{Client, Method, StatusCode, Url, redirect::Policy};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub const BASE_URL_ENV: &str = "FORGEJO_TEST_BASE_URL";
pub const USERNAME_ENV: &str = "FORGEJO_TEST_USERNAME";
pub const PASSWORD_ENV: &str = "FORGEJO_TEST_PASSWORD";
const DEFAULT_PREVIEW_LIMIT: usize = 1024;

#[derive(Clone, Debug)]
pub struct Config {
    pub base_url: Url,
    pub username: String,
    password: String,
}

impl Config {
    pub fn password(&self) -> &str {
        &self.password
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReadinessOptions {
    pub deadline: Duration,
    pub backoff: Duration,
    pub request_timeout: Duration,
    pub preview_limit: usize,
}

impl Default for ReadinessOptions {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(45),
            backoff: Duration::from_millis(250),
            request_timeout: Duration::from_secs(3),
            preview_limit: DEFAULT_PREVIEW_LIMIT,
        }
    }
}

#[derive(Debug, Deserialize)]
struct VersionResponse {
    version: String,
}

#[derive(Debug, Deserialize)]
struct UserResponse {
    login: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    sha1: String,
}

#[derive(Debug)]
pub struct ReadyService {
    pub client: Client,
    pub version: String,
}

#[derive(Debug)]
pub struct Context {
    pub client: Client,
    pub base_url: Url,
    pub username: String,
    pub version: String,
    token: String,
    token_name: String,
    password: String,
}

pub fn parse_config<F>(lookup: F) -> Result<Config, String>
where
    F: Fn(&str) -> Option<String>,
{
    let values = [
        (BASE_URL_ENV, lookup(BASE_URL_ENV)),
        (USERNAME_ENV, lookup(USERNAME_ENV)),
        (PASSWORD_ENV, lookup(PASSWORD_ENV)),
    ];
    let present = values.iter().filter(|(_, value)| value.is_some()).count();
    if present == 0 {
        return Err(format!(
            "provider test configuration is missing; set {BASE_URL_ENV}, {USERNAME_ENV}, and {PASSWORD_ENV}"
        ));
    }
    if present != values.len() {
        let missing = values
            .iter()
            .filter_map(|(name, value)| value.is_none().then_some(*name))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "provider test configuration is partial; missing {missing}; set all three variables"
        ));
    }

    for (name, value) in &values {
        if value.as_deref().is_some_and(str::is_empty) {
            return Err(format!(
                "provider test configuration variable {name} is empty"
            ));
        }
    }

    let [(_, Some(raw_url)), (_, Some(username)), (_, Some(password))] = values else {
        return Err("provider test configuration validation failed unexpectedly".to_string());
    };
    let mut base_url = Url::parse(&raw_url)
        .map_err(|error| format!("{BASE_URL_ENV} is not a valid URL: {error}"))?;
    if !matches!(base_url.scheme(), "http" | "https") {
        return Err(format!("{BASE_URL_ENV} must use http or https"));
    }
    if base_url.host_str().is_none() {
        return Err(format!("{BASE_URL_ENV} must include a host"));
    }
    if !base_url.username().is_empty() || base_url.password().is_some() {
        return Err(format!("{BASE_URL_ENV} must not include user information"));
    }
    if base_url.query().is_some() || base_url.fragment().is_some() {
        return Err(format!(
            "{BASE_URL_ENV} must not include a query or fragment"
        ));
    }
    if !matches!(base_url.path(), "" | "/") {
        return Err(format!("{BASE_URL_ENV} must be an origin without a path"));
    }
    base_url.set_path("/");

    Ok(Config {
        base_url,
        username,
        password,
    })
}

pub fn config_from_env() -> Result<Config, String> {
    parse_config(|name| std::env::var(name).ok())
}

fn build_client(timeout: Duration) -> Result<Client, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .build()
        .map_err(|error| format!("could not build Forgejo test client: {error}"))
}

fn api_url(base_url: &Url, path: &str) -> Result<Url, String> {
    base_url
        .join(path.trim_start_matches('/'))
        .map_err(|error| format!("could not join Forgejo API path {path}: {error}"))
}

pub fn redact_known_secrets(input: &str, secrets: &[&str]) -> String {
    let mut redacted = secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .fold(input.to_string(), |text, secret| {
            text.replace(secret, "[REDACTED]")
        });
    for scheme in ["Basic ", "Bearer "] {
        while let Some(start) = redacted.find(scheme) {
            let value_start = start + scheme.len();
            let end = redacted[value_start..]
                .find(char::is_whitespace)
                .map_or(redacted.len(), |offset| value_start + offset);
            redacted.replace_range(start..end, "[REDACTED AUTHORIZATION]");
        }
    }
    redacted
}

pub fn bounded_preview(input: &str, limit: usize, secrets: &[&str]) -> String {
    let redacted = redact_known_secrets(input, secrets);
    let count = redacted.chars().count();
    if count <= limit {
        return redacted;
    }
    let mut preview = redacted.chars().take(limit).collect::<String>();
    preview.push_str("…[truncated ");
    preview.push_str(&(count - limit).to_string());
    preview.push_str(" chars]");
    preview
}

async fn poll_json<T, F>(
    client: &Client,
    config: &Config,
    options: ReadinessOptions,
    started: Instant,
    phase: &str,
    path: &str,
    authenticate: F,
) -> Result<T, String>
where
    T: DeserializeOwned,
    F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
{
    let mut attempts = 0_u64;
    loop {
        attempts += 1;
        let url = api_url(&config.base_url, path)?;
        let result = authenticate(client.get(url)).send().await;
        let (last_status, last_preview) = match result {
            Ok(response) => {
                let status = response.status().to_string();
                match response.text().await {
                    Ok(body) => {
                        let mut preview =
                            bounded_preview(&body, options.preview_limit, &[config.password()]);
                        if status.starts_with('2') {
                            match serde_json::from_str(&body) {
                                Ok(value) => return Ok(value),
                                Err(error) => {
                                    preview = bounded_preview(
                                        &format!("invalid JSON: {error}; body={body}"),
                                        options.preview_limit,
                                        &[config.password()],
                                    );
                                }
                            }
                        }
                        (status, preview)
                    }
                    Err(error) => (
                        status,
                        bounded_preview(
                            &format!("response read error: {error}"),
                            options.preview_limit,
                            &[config.password()],
                        ),
                    ),
                }
            }
            Err(error) => (
                "transport-error".to_string(),
                bounded_preview(
                    &error.to_string(),
                    options.preview_limit,
                    &[config.password()],
                ),
            ),
        };

        let elapsed = started.elapsed();
        if elapsed >= options.deadline {
            return Err(format!(
                "Forgejo readiness phase={phase} attempts={attempts} elapsed_ms={} deadline_ms={} service_url={} last_status={last_status} last_response={last_preview}",
                elapsed.as_millis(),
                options.deadline.as_millis(),
                config.base_url,
            ));
        }
        tokio::time::sleep(options.backoff.max(Duration::from_millis(1))).await;
    }
}

pub async fn wait_for_ready(
    config: &Config,
    options: ReadinessOptions,
) -> Result<ReadyService, String> {
    let client = build_client(options.request_timeout.min(options.deadline))?;
    let started = Instant::now();
    let version: VersionResponse = poll_json(
        &client,
        config,
        options,
        started,
        "version",
        "/api/v1/version",
        |request| request,
    )
    .await?;
    let user: UserResponse = poll_json(
        &client,
        config,
        options,
        started,
        "authentication",
        "/api/v1/user",
        |request| request.basic_auth(&config.username, Some(config.password())),
    )
    .await?;
    if user.login != config.username {
        return Err(format!(
            "Forgejo readiness phase=authentication service_url={} returned unexpected user {}",
            config.base_url,
            bounded_preview(&user.login, options.preview_limit, &[config.password()]),
        ));
    }
    Ok(ReadyService {
        client,
        version: version.version,
    })
}

impl Context {
    pub async fn connect_from_env() -> Result<Self, String> {
        Self::connect(config_from_env()?, ReadinessOptions::default()).await
    }

    pub async fn connect(config: Config, options: ReadinessOptions) -> Result<Self, String> {
        let ready = wait_for_ready(&config, options).await?;
        let name = unique_name("forge-mcp-ci-token")?;
        let path = format!("/api/v1/users/{}/tokens", config.username);
        let url = api_url(&config.base_url, &path)?;
        let response = ready
            .client
            .post(url)
            .basic_auth(&config.username, Some(config.password()))
            .json(&json!({"name": name, "scopes": ["all"]}))
            .send()
            .await
            .map_err(|error| {
                format!(
                    "Forgejo phase=token-create service_url={} transport error: {}",
                    config.base_url,
                    bounded_preview(
                        &error.to_string(),
                        options.preview_limit,
                        &[config.password()]
                    ),
                )
            })?;
        let status = response.status();
        let body = response.text().await.map_err(|error| {
            format!(
                "Forgejo phase=token-create service_url={} response read error: {}",
                config.base_url,
                bounded_preview(
                    &error.to_string(),
                    options.preview_limit,
                    &[config.password()]
                ),
            )
        })?;
        if !status.is_success() {
            return Err(format!(
                "Forgejo phase=token-create service_url={} status={status} response={}",
                config.base_url,
                bounded_preview(&body, options.preview_limit, &[config.password()]),
            ));
        }
        let token: TokenResponse = serde_json::from_str(&body).map_err(|error| {
            format!(
                "Forgejo phase=token-create service_url={} invalid JSON: {error}; response={}",
                config.base_url,
                bounded_preview(&body, options.preview_limit, &[config.password()]),
            )
        })?;

        Ok(Self {
            client: ready.client,
            base_url: config.base_url,
            username: config.username,
            version: ready.version,
            token: token.sha1,
            token_name: name,
            password: config.password,
        })
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(StatusCode, String), String> {
        let url = api_url(&self.base_url, path)?;
        let request_body = body
            .as_ref()
            .map_or_else(|| "<none>".to_string(), Value::to_string);
        let mut request = self
            .client
            .request(method.clone(), url)
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.map_err(|error| {
            self.request_context(
                &method,
                path,
                &request_body,
                "transport-error",
                &error.to_string(),
            )
        })?;
        let status = response.status();
        let response_body = response.text().await.map_err(|error| {
            self.request_context(
                &method,
                path,
                &request_body,
                &status.to_string(),
                &format!("response read error: {error}"),
            )
        })?;
        Ok((status, response_body))
    }

    pub async fn request_success(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<String, String> {
        let request_body = body
            .as_ref()
            .map_or_else(|| "<none>".to_string(), Value::to_string);
        let (status, response_body) = self.request(method.clone(), path, body).await?;
        if !status.is_success() {
            return Err(self.request_context(
                &method,
                path,
                &request_body,
                &status.to_string(),
                &response_body,
            ));
        }
        Ok(response_body)
    }

    pub async fn request_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T, String> {
        let response_body = self.request_success(method.clone(), path, body).await?;
        serde_json::from_str(&response_body).map_err(|error| {
            self.request_context(
                &method,
                path,
                "<serialized request body omitted>",
                "success",
                &format!("invalid JSON: {error}; body={response_body}"),
            )
        })
    }

    fn request_context(
        &self,
        method: &Method,
        path: &str,
        request_body: &str,
        status: &str,
        response_body: &str,
    ) -> String {
        bounded_preview(
            &format!(
                "Forgejo version={}: {method} {path} request_body={request_body} status={status} response_body={response_body}",
                self.version,
            ),
            DEFAULT_PREVIEW_LIMIT,
            &[&self.password, &self.token],
        )
    }

    pub async fn delete_repository(&self, name: &str) -> Result<(), String> {
        self.request_success(
            Method::DELETE,
            &format!("/api/v1/repos/{}/{name}", self.username),
            None,
        )
        .await
        .map(|_| ())
    }

    pub async fn revoke_token(&self) -> Result<(), String> {
        let path = format!(
            "/api/v1/users/{}/tokens/{}",
            self.username,
            urlencoding::encode(&self.token_name)
        );
        let url = api_url(&self.base_url, &path)?;
        let response = self
            .client
            .delete(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|error| {
                format!(
                    "Forgejo phase=token-cleanup service_url={} transport error: {}",
                    self.base_url,
                    bounded_preview(
                        &error.to_string(),
                        DEFAULT_PREVIEW_LIMIT,
                        &[&self.password, &self.token]
                    ),
                )
            })?;
        let status = response.status();
        let body = response.text().await.map_err(|error| error.to_string())?;
        if !status.is_success() {
            return Err(format!(
                "Forgejo phase=token-cleanup service_url={} status={status} response={}",
                self.base_url,
                bounded_preview(&body, DEFAULT_PREVIEW_LIMIT, &[&self.password, &self.token]),
            ));
        }
        Ok(())
    }
}

pub fn unique_name(prefix: &str) -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("could not create unique fixture name: {error}"))?
        .as_nanos();
    Ok(format!("{prefix}-{}-{nanos}", std::process::id()))
}

pub fn combine_results(
    primary: Result<(), String>,
    cleanup: Vec<Result<(), String>>,
) -> Result<(), String> {
    let cleanup_errors = cleanup
        .into_iter()
        .filter_map(Result::err)
        .collect::<Vec<_>>();
    match (primary, cleanup_errors.is_empty()) {
        (Ok(()), true) => Ok(()),
        (Err(primary), true) => Err(primary),
        (Ok(()), false) => Err(format!("cleanup failed: {}", cleanup_errors.join("; "))),
        (Err(primary), false) => Err(format!(
            "{primary}; cleanup also failed: {}",
            cleanup_errors.join("; ")
        )),
    }
}
