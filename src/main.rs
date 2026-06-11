mod policy;
mod registry;
mod server;
mod tools;

use anyhow::Context;
use rmcp::ServiceExt;

use crate::policy::WorldConfig;
use crate::server::HarnessServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stdout is the MCP transport — all logging must go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config_path =
        std::env::var("HARNESS_CONFIG").unwrap_or_else(|_| "harness.yaml".to_string());
    let raw = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read harness config at {config_path}"))?;
    let config: WorldConfig =
        serde_yaml::from_str(&raw).with_context(|| format!("invalid config in {config_path}"))?;

    tracing::info!(
        world = %config.world.name,
        version = %config.version,
        tasks = ?config.tasks.keys().collect::<Vec<_>>(),
        "harness config loaded from {config_path}"
    );

    let server = HarnessServer::new(config)?;
    let service = server
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .context("failed to start MCP server on stdio")?;

    service.waiting().await?;
    Ok(())
}
