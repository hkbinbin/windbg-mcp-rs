use std::path::PathBuf;

use clap::Parser;
use rmcp::{
    ServiceExt,
    transport::{
        stdio,
        streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService},
    },
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use windbg_mcp_rs::WindbgMcpServer;

#[derive(Debug, Parser)]
#[command(
    name = "windbg-mcp-headless",
    about = "Thin WinDbg MCP server: open/close debugger daemons and point at the windbg_cli CLI"
)]
struct Cli {
    #[arg(
        long,
        help = "Listen on Streamable HTTP instead of stdio, for example 127.0.0.1:50051"
    )]
    listen: Option<String>,

    #[arg(
        long,
        help = "Path to the windbg_cli executable used to host debugger daemons. Defaults to WINDBG_CLI_PATH, then the server's own directory, then PATH."
    )]
    cli_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let cli = Cli::parse();
    let server = WindbgMcpServer::new(cli.cli_path.clone());

    if let Some(listen) = cli.listen.as_deref() {
        run_http(server, listen).await?;
    } else {
        let service = server.serve(stdio()).await?;
        service
            .waiting()
            .await
            .map(|_| ())
            .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })?;
    }

    Ok(())
}

async fn run_http(server: WindbgMcpServer, listen: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cancellation = CancellationToken::new();
    let listener = TcpListener::bind(listen).await?;
    let local_addr = listener.local_addr()?;

    let service: StreamableHttpService<WindbgMcpServer> = StreamableHttpService::new(
        move || Ok(server.clone()),
        Default::default(),
        StreamableHttpServerConfig {
            stateful_mode: true,
            sse_keep_alive: None,
            cancellation_token: cancellation.child_token(),
            ..Default::default()
        },
    );

    tracing::info!("thin WinDbg MCP listening at http://{}/mcp", local_addr);
    let router = axum::Router::new().nest_service("/mcp", service);
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { cancellation.cancelled_owned().await })
        .await?;
    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,windbg_mcp_rs=debug".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init();
}
