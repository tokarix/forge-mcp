//! Binary entry point for the Phase 1 forge-mcp server bootstrap.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use forge::{ForgejoAdapter, ForgejoConfig};
use orchestrator::ReadOrchestrator;
use transport::{ReadRepositoryFileInput, ToolHandlers};

#[derive(Debug, Parser)]
#[command(name = "forge-mcp")]
#[command(about = "Phase 1 bootstrap for a multi-forge policy-enforcing MCP server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ReadFile {
        #[arg(long)]
        host: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        git_ref: Option<String>,
        #[arg(long, default_value = "FORGEJO_TOKEN")]
        token_env: String,
        #[arg(long, default_value = "codex")]
        agent_id: String,
        #[arg(long, default_value = "local-session")]
        session_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::ReadFile {
            host,
            owner,
            repo,
            path,
            git_ref,
            token_env,
            agent_id,
            session_id,
        } => {
            let token = std::env::var(token_env).ok();
            let adapter = Arc::new(ForgejoAdapter::new(ForgejoConfig {
                base_url: host.clone(),
                token,
            }));
            let audit_sink = Arc::new(audit::InMemoryAuditSink::new());
            let read_service = Arc::new(ReadOrchestrator::new(adapter, audit_sink));
            let handlers = ToolHandlers::new(read_service);

            let content = handlers
                .read_repository_file(ReadRepositoryFileInput {
                    agent_id,
                    session_id,
                    host,
                    owner,
                    repo,
                    path,
                    git_ref,
                })
                .await?;

            println!("{content}");
        }
    }

    Ok(())
}
