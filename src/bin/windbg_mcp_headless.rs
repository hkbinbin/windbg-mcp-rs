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
use windbg_mcp_rs::{HeadlessSessionManager, WindbgMcpServer};

#[derive(Debug, Parser)]
#[command(
    name = "windbg-mcp-headless",
    about = "Headless WinDbg MCP server with session-managed kernel attachments"
)]
struct Cli {
    #[arg(
        long,
        help = "Listen on Streamable HTTP instead of stdio, for example 127.0.0.1:50051"
    )]
    listen: Option<String>,

    #[arg(
        long,
        help = "Open an initial kernel session using the same options you would pass to -k, for example net:port=50000,key=..."
    )]
    connect_kernel: Option<String>,

    #[arg(long, help = "Optional session id for the initial connection")]
    session_id: Option<String>,

    #[arg(
        long,
        help = "Optional debugger command to run right after the initial attach, such as .symfix; .reload"
    )]
    startup_command: Option<String>,

    #[arg(
        long,
        help = "Timeout in seconds to wait for the initial attach to complete"
    )]
    attach_timeout_secs: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let cli = Cli::parse();
    let sessions = HeadlessSessionManager::new();

    if let Some(connection) = cli.connect_kernel.as_deref() {
        let session = sessions
            .open_kernel_session(
                connection,
                cli.session_id.as_deref(),
                cli.startup_command.as_deref(),
                cli.attach_timeout_secs,
            )
            .await?;
        tracing::info!(
            session_id = %session.session_id,
            connection = %session.connection_options,
            "initial headless WinDbg session opened"
        );
    }

    let server = WindbgMcpServer::headless(sessions);
    if let Some(listen) = cli.listen.as_deref() {
        run_http(server, listen).await?;
    } else {
        let service = server.serve(stdio()).await?;
        service.waiting().await?;
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

    tracing::info!("headless WinDbg MCP listening at http://{}/mcp", local_addr);
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
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}
