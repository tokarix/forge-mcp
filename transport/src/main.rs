//! Binary entry point for the MCP shim.

use clap::Parser;
use transport::{ShimConfig, serve_stdio};

/// MCP shim for forge-mcp control plane.
#[derive(Parser)]
#[command(name = "forge-mcp-shim", version)]
struct Cli {
    /// Control plane gateway URL (e.g. `https://forge-mcp.example:8443`).
    #[arg(long, env = "FORGE_MCP_GATEWAY_URL")]
    gateway_url: String,

    /// Path to a file containing the bearer token. The token is never
    /// accepted as a CLI value to avoid leaking it in process listings.
    #[arg(long)]
    token_file: Option<std::path::PathBuf>,
}

fn read_token(cli: &Cli) -> Result<String, Box<dyn std::error::Error>> {
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

fn server_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let token = read_token(&cli)?;

    let config = ShimConfig {
        gateway_url: cli.gateway_url,
        server_name: "forge-mcp-shim".to_string(),
        server_version: server_version(),
        token,
    };

    serve_stdio(config).await?;
    Ok(())
}
