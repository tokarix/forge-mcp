//! Binary entry point for the MCP shim.

use std::path::PathBuf;

use clap::Parser;
use transport::{GatewayConfig, ShimConfig, serve_stdio};

/// MCP shim for forge-mcp control plane.
#[derive(Parser)]
#[command(name = "forge-mcp-shim", version)]
struct Cli {
    /// Enable Claude Code channel notifications and the server-push event stream.
    #[arg(long, env = "FORGE_MCP_ENABLE_CHANNELS", default_value_t = false)]
    enable_channels: bool,

    /// Control plane gateway URL (e.g. `https://forge-mcp.example:8443`).
    /// Required when `--config` is not set.  Falls back to the
    /// `FORGE_MCP_GATEWAY_URL` env var (handled in `load_config`, not via
    /// Clap's `env`, so `--config` can coexist with a legacy env var).
    #[arg(long)]
    gateway_url: Option<String>,

    /// Send a single synthetic channel notification on startup for compatibility testing.
    #[arg(long, env = "FORGE_MCP_CHANNEL_STARTUP_SPIKE", default_value_t = false)]
    channel_startup_spike: bool,

    /// Path to a file containing the bearer token (single-gateway mode).
    /// The token is never accepted as a CLI value to avoid leaking it in
    /// process listings.
    #[arg(long)]
    token_file: Option<PathBuf>,

    /// Path to a JSON config file for multi-gateway mode. Mutually exclusive
    /// with `--gateway-url`.
    #[arg(long)]
    config: Option<PathBuf>,
}

/// JSON shape for the multi-gateway config file.
#[derive(serde::Deserialize)]
struct ConfigFile {
    gateways: Vec<ConfigGateway>,
}

/// JSON shape for a single gateway entry in the config file.
#[derive(serde::Deserialize)]
struct ConfigGateway {
    name: String,
    /// Inline token (discouraged — prefer `token_file` or `token_env`).
    token: Option<String>,
    /// Environment variable name containing the token.
    token_env: Option<String>,
    /// Path to a file containing the token.
    token_file: Option<PathBuf>,
    url: String,
}

fn read_single_gateway_token(cli: &Cli) -> Result<String, Box<dyn std::error::Error>> {
    // 1. --token-file flag
    if let Some(path) = &cli.token_file {
        return Ok(std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read token file {}: {e}", path.display()))?
            .trim()
            .to_string());
    }
    // 2. FORGE_MCP_TOKEN env var
    if let Ok(token) = std::env::var("FORGE_MCP_TOKEN") {
        return Ok(token);
    }
    Err("bearer token required: set FORGE_MCP_TOKEN env var or use --token-file".into())
}

fn resolve_gateway_token(gw: &ConfigGateway) -> Result<String, Box<dyn std::error::Error>> {
    let source_count = u8::from(gw.token.is_some())
        + u8::from(gw.token_env.is_some())
        + u8::from(gw.token_file.is_some());
    if source_count > 1 {
        return Err(format!(
            "gateway '{}': only one of token, token_env, or token_file may be set (found {})",
            gw.name, source_count,
        )
        .into());
    }
    match (&gw.token, &gw.token_env, &gw.token_file) {
        (Some(token), _, _) => Ok(token.trim().to_string()),
        (_, Some(env_var), _) => std::env::var(env_var).map_err(|e| {
            format!("gateway '{}': env var '{}' not set: {e}", gw.name, env_var).into()
        }),
        (_, _, Some(path)) => Ok(std::fs::read_to_string(path)
            .map_err(|e| {
                format!(
                    "gateway '{}': failed to read token file {}: {e}",
                    gw.name,
                    path.display()
                )
            })?
            .trim()
            .to_string()),
        _ => Err(format!(
            "gateway '{}': one of token, token_env, or token_file is required",
            gw.name
        )
        .into()),
    }
}

fn load_config(cli: &Cli) -> Result<ShimConfig, Box<dyn std::error::Error>> {
    let gateways = if let Some(config_path) = &cli.config {
        if cli.gateway_url.is_some() {
            return Err("--config and --gateway-url are mutually exclusive".into());
        }
        let config_text = std::fs::read_to_string(config_path)
            .map_err(|e| format!("failed to read config file {}: {e}", config_path.display()))?;
        let config_file: ConfigFile =
            serde_json::from_str(&config_text).map_err(|e| format!("invalid config JSON: {e}"))?;
        if config_file.gateways.is_empty() {
            return Err("config file must contain at least one gateway".into());
        }
        config_file
            .gateways
            .iter()
            .map(|gw| {
                Ok(GatewayConfig {
                    name: gw.name.clone(),
                    token: resolve_gateway_token(gw)?,
                    url: gw.url.clone(),
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?
    } else {
        let gateway_url = cli
            .gateway_url
            .clone()
            .or_else(|| std::env::var("FORGE_MCP_GATEWAY_URL").ok())
            .ok_or("--gateway-url or FORGE_MCP_GATEWAY_URL or --config is required")?;
        let token = read_single_gateway_token(cli)?;
        vec![GatewayConfig {
            name: "default".to_string(),
            token,
            url: gateway_url,
        }]
    };

    Ok(ShimConfig {
        channel_startup_spike: cli.channel_startup_spike,
        enable_channels: cli.enable_channels,
        gateways,
        server_name: "forge-mcp-shim".to_string(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = load_config(&cli)?;
    serve_stdio(config).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn resolve_gateway_token_rejects_multiple_sources() {
        let gw = ConfigGateway {
            name: "test".to_string(),
            token: Some("inline".to_string()),
            token_env: Some("MY_TOKEN".to_string()),
            token_file: None,
            url: "https://example.com".to_string(),
        };
        let err = resolve_gateway_token(&gw).expect_err("multiple token sources should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("only one of"),
            "error should mention exclusivity: {msg}"
        );
    }

    #[test]
    fn resolve_gateway_token_rejects_all_three_sources() {
        let gw = ConfigGateway {
            name: "test".to_string(),
            token: Some("inline".to_string()),
            token_env: Some("MY_TOKEN".to_string()),
            token_file: Some(PathBuf::from("/tmp/token")),
            url: "https://example.com".to_string(),
        };
        let err = resolve_gateway_token(&gw).expect_err("all three token sources should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("found 3"),
            "error should report count of 3: {msg}"
        );
    }

    #[test]
    fn resolve_gateway_token_accepts_single_inline_token() {
        let gw = ConfigGateway {
            name: "test".to_string(),
            token: Some("my-secret".to_string()),
            token_env: None,
            token_file: None,
            url: "https://example.com".to_string(),
        };
        assert_eq!(
            resolve_gateway_token(&gw).expect("resolve token"),
            "my-secret"
        );
    }

    #[test]
    fn resolve_gateway_token_rejects_no_sources() {
        let gw = ConfigGateway {
            name: "test".to_string(),
            token: None,
            token_env: None,
            token_file: None,
            url: "https://example.com".to_string(),
        };
        let err = resolve_gateway_token(&gw).expect_err("no token sources should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("one of token, token_env, or token_file is required"),
            "error should mention required fields: {msg}"
        );
    }
}
