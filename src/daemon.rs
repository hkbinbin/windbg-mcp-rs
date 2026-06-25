//! Shared daemon plumbing for the `windbg_cli` persistent-session daemon.
//!
//! Both the CLI (`src/bin/windbg_cli.rs`, which *is* the daemon) and the thin
//! MCP server (`src/server.rs`, which *launches and talks to* daemons) need a
//! common definition of:
//!
//! - the on-disk daemon registry (`%TEMP%/windbg_cli_daemons/<name>.json`),
//! - the loopback TCP wire protocol (`Request` / `Response`),
//! - and a blocking `send_request` helper.
//!
//! Keeping these here lets the MCP `windbg_open_session` / `windbg_close_session`
//! tools drive a daemon that the CLI started, without duplicating the protocol.

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    path::PathBuf,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Default daemon name used when the caller does not specify one.
pub const DEFAULT_DAEMON_NAME: &str = "default";

// ---------------------------------------------------------------------------
// Daemon registry (one JSON file per daemon under %TEMP%).
// ---------------------------------------------------------------------------

/// A registered, running daemon. Persisted as JSON so other processes (the
/// observer `do` CLI and the MCP server) can discover the daemon's loopback
/// address and PID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonRegistry {
    pub name: String,
    pub pid: u32,
    pub address: String,
    pub target_summary: String,
    pub started_at_unix_ms: u64,
}

/// Directory that holds the per-daemon registry JSON files. Resolves under
/// `%TEMP%` (falling back to `%TMP%`, then the current directory).
pub fn registry_dir() -> PathBuf {
    let base = std::env::var_os("TEMP")
        .or_else(|| std::env::var_os("TMP"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("windbg_cli_daemons")
}

/// Path to the registry JSON file for `name`.
pub fn registry_path(name: &str) -> PathBuf {
    registry_dir().join(format!("{name}.json"))
}

/// Path to the daemon's stdout/stderr log file (written by the launcher).
pub fn log_path(name: &str) -> PathBuf {
    registry_dir().join(format!("{name}.log"))
}

/// Write (or overwrite) the registry entry for a daemon.
pub fn write_registry(entry: &DaemonRegistry) -> std::io::Result<()> {
    let dir = registry_dir();
    fs::create_dir_all(&dir)?;
    let path = registry_path(&entry.name);
    let bytes = serde_json::to_vec_pretty(entry).expect("serialize registry");
    fs::write(path, bytes)
}

/// Read the registry entry for `name`, if present and parseable.
pub fn read_registry(name: &str) -> std::io::Result<DaemonRegistry> {
    let bytes = fs::read(registry_path(name))?;
    let entry: DaemonRegistry = serde_json::from_slice(&bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    Ok(entry)
}

/// Best-effort removal of a daemon's registry file.
pub fn remove_registry(name: &str) {
    let _ = fs::remove_file(registry_path(name));
}

/// Enumerate all known daemons by scanning the registry directory.
pub fn list_registries() -> Vec<DaemonRegistry> {
    let dir = registry_dir();
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(&dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(reg) = serde_json::from_slice::<DaemonRegistry>(&bytes) {
                out.push(reg);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Wire protocol.
// ---------------------------------------------------------------------------

/// A single command sent to a running daemon over loopback TCP (one JSON line
/// per request).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Request {
    State,
    Info,
    Exec { command: String },
    Step { count: u32 },
    StepOver { count: u32 },
    StepOut,
    StepUntil { address: String, into: bool },
    Go,
    Interrupt,
    WaitBreak { timeout_secs: u64 },
    Bp { location: String, one_shot: bool },
    Ba { address: String, access: String, size: u32 },
    Bc { id: String },
    Bl,
    Reg { registers: Vec<String> },
    Mem { address: String, format: String, count: u32 },
    Dis { address: String, count: u32 },
    Bt { format: String, count: u32 },
    Snapshot,
    Dump {
        out_dir: String,
        minidump: bool,
        modules: bool,
        module_filter: Option<String>,
        resume_after: bool,
    },
    Shutdown,
}

/// The daemon's reply to a [`Request`].
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub state: Option<Value>,
}

impl Response {
    pub fn ok(text: impl Into<String>) -> Self {
        Self {
            ok: true,
            text: text.into(),
            state: None,
        }
    }

    pub fn ok_with_state(
        text: impl Into<String>,
        state: crate::executor::DebuggerExecutionState,
    ) -> Self {
        Self {
            ok: true,
            text: text.into(),
            state: serde_json::to_value(state).ok(),
        }
    }

    pub fn err(text: impl Into<String>) -> Self {
        Self {
            ok: false,
            text: text.into(),
            state: None,
        }
    }
}

/// Connect to a daemon at `address` (loopback `host:port`), send a single
/// request as one JSON line, and read back the JSON response line.
pub fn send_request(address: &str, request: &Request) -> Result<Response, String> {
    let mut stream = TcpStream::connect_timeout(
        &address
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?,
        Duration::from_secs(5),
    )
    .map_err(|e| format!("connect {address}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(180)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;
    let payload = serde_json::to_string(request).map_err(|e| e.to_string())?;
    writeln!(stream, "{payload}").map_err(|e| format!("write: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(line.trim()).map_err(|e| format!("decode: {e}"))
}
