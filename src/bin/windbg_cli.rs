//! `windbg-cli` — WinDbg debugger CLI built on top of the headless dbgeng
//! session manager that powers the MCP server.
//!
//! Two modes are supported:
//!
//! 1. **One-shot mode** (`run` / `attach` / `kernel` subcommands) — opens a
//!    debugger session, runs `-c` commands once the target is command-ready,
//!    prints output, then closes the session.
//!
//! 2. **Daemon mode** (`daemon start` + `do <command>` family) — keeps the
//!    debugger session alive in a background process and lets follow-up
//!    `do` commands inspect state, set breakpoints, single-step, run raw
//!    debugger commands, etc. The CLI plays *observer*; the daemon owns the
//!    dbgeng session.

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::sleep;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use windbg_mcp_rs::{
    DebuggerExecutionState, HeadlessSessionInfo, HeadlessSessionManager, UserModeAttach,
};

const DEFAULT_READY_TIMEOUT_SECS: u64 = 60;
const STATE_POLL_INTERVAL: Duration = Duration::from_millis(200);
const DEFAULT_DAEMON_NAME: &str = "default";

#[derive(Debug, Parser)]
#[command(
    name = "windbg-cli",
    about = "WinDbg debugger CLI — one-shot or persistent-daemon modes",
    version,
)]
struct Cli {
    /// Logical session id (auto-generated when omitted).
    #[arg(long, global = true)]
    session_id: Option<String>,

    /// Debugger command(s) to run after the initial break. Repeatable.
    /// Aliased as `-c`.
    #[arg(long = "command", short = 'c', global = true)]
    commands: Vec<String>,

    /// Read additional commands from a script file (one per line, `;` and
    /// `#` lines are ignored).
    #[arg(long, global = true)]
    script: Option<PathBuf>,

    /// Run an `.symfix; .reload` startup command before user commands.
    #[arg(long, global = true, default_value_t = false)]
    symfix: bool,

    /// Custom startup command run right after attach (e.g.
    /// ".sympath SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols").
    #[arg(long, global = true)]
    startup_command: Option<String>,

    /// Maximum seconds to wait for the initial attach.
    #[arg(long, global = true, default_value_t = 30)]
    attach_timeout_secs: u64,

    /// Maximum seconds to wait for the target to become command-ready before
    /// running each command.
    #[arg(long, global = true, default_value_t = DEFAULT_READY_TIMEOUT_SECS)]
    ready_timeout_secs: u64,

    /// Maximum seconds for `windbg_close_session` to finish.
    #[arg(long, global = true, default_value_t = 10)]
    shutdown_timeout_secs: u64,

    /// After commands run, resume the target instead of detaching/terminating
    /// immediately (kernel sessions only — leaves the VM running).
    #[arg(long, global = true, default_value_t = false)]
    resume_on_exit: bool,

    /// Terminate the user-mode debuggee on exit instead of detaching.
    #[arg(long, global = true, default_value_t = false)]
    terminate_on_exit: bool,

    /// Print verbose engine logs to stderr.
    #[arg(long, global = true, default_value_t = false)]
    verbose: bool,

    /// Maximum characters of output per command (0 = unlimited).
    #[arg(long, global = true, default_value_t = 0)]
    max_output_chars: usize,

    #[command(subcommand)]
    target: Target,
}

#[derive(Debug, Subcommand)]
enum Target {
    // --------------------------------------------------------------------
    // NOTE: The one-shot user-mode subcommands `run` and `attach` are
    // intentionally disabled.  For Windows user-mode debugging always use
    // the persistent daemon mode (`windbg_cli daemon start ...` +
    // `windbg_cli do ...`).  Keeping the one-shot path around encouraged
    // accidental usage where state was lost between invocations.
    //
    // /// One-shot: spawn a local user-mode binary as the debuggee.
    // Run {
    //     /// Executable path. Use absolute paths; relative paths resolve
    //     /// against the current directory.
    //     exe: PathBuf,
    //     /// Arguments forwarded to the debuggee. Anything after `--` lands
    //     /// here.
    //     #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    //     args: Vec<String>,
    //     /// Also debug child processes (default: only the spawned process).
    //     #[arg(long, default_value_t = false)]
    //     follow_children: bool,
    // },
    // /// One-shot: attach to a running user-mode process by PID.
    // Attach {
    //     /// Decimal process id.
    //     pid: u32,
    //     /// Use a non-invasive attach (read-only inspection).
    //     #[arg(long, default_value_t = false)]
    //     non_invasive: bool,
    // },
    /// One-shot: open a kernel debugging session using `-k`-style options.
    /// Kernel sessions remain one-shot because their lifecycle is dictated
    /// by the remote KDNET target.
    Kernel {
        /// Connection string passed to dbgeng `AttachKernelWide`.
        connection: String,
    },
    /// List the public MCP/CLI tool names that the headless server exposes.
    ListTools,

    /// Persistent daemon: start a long-running debugger session that other
    /// `do ...` commands can talk to.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Send a single command to the running daemon (observer-mode CLI).
    Do {
        /// Daemon name — must match the one used with `daemon start`.
        #[arg(long, default_value = DEFAULT_DAEMON_NAME)]
        name: String,
        #[command(subcommand)]
        action: DoAction,
    },
}

#[derive(Debug, Subcommand)]
enum DaemonAction {
    /// Spawn a debuggee and keep its dbgeng session alive in this terminal.
    /// Subsequent `windbg_cli do <cmd>` calls drive the same session.
    /// The daemon prints a one-line status JSON and then blocks until
    /// you press Ctrl+C, run `daemon stop`, or close the terminal.
    Start {
        /// Daemon name. Multiple daemons can run side-by-side as long as
        /// each has a unique name.
        #[arg(long, default_value = DEFAULT_DAEMON_NAME)]
        name: String,
        /// Bind address for the local control socket (loopback only).
        #[arg(long, default_value = "127.0.0.1:0")]
        bind: String,
        #[command(subcommand)]
        target: DaemonTarget,
    },
    /// Politely tell the daemon to close the debug session and exit.
    Stop {
        #[arg(long, default_value = DEFAULT_DAEMON_NAME)]
        name: String,
    },
    /// Print the registered daemon's address and PID, if any.
    Status {
        #[arg(long, default_value = DEFAULT_DAEMON_NAME)]
        name: String,
    },
    /// List all known daemons.
    List,
}

#[derive(Debug, Subcommand)]
enum DaemonTarget {
    /// Spawn a local user-mode binary as the debuggee.
    Run {
        exe: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
        #[arg(long, default_value_t = false)]
        follow_children: bool,
    },
    /// Attach to a running user-mode process by PID.
    Attach {
        pid: u32,
        #[arg(long, default_value_t = false)]
        non_invasive: bool,
    },
    /// Open a kernel debugging session using `-k`-style options.
    Kernel { connection: String },
}

#[derive(Debug, Subcommand)]
enum DoAction {
    /// Print the current execution state (break/go/no_debuggee).
    State,
    /// Resume execution. Returns immediately without waiting for the next
    /// break — use `wait-break` afterwards if you want to block.
    Go,
    /// Send an interrupt request (`break in`) and wait until the debugger
    /// stops.
    Interrupt,
    /// Wait until the debugger reports `break` (or hits the timeout).
    WaitBreak {
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
    },
    /// Single-step into one instruction (`t`).
    Step {
        #[arg(long, default_value_t = 1)]
        count: u32,
    },
    /// Step over one instruction/call (`p`).
    StepOver {
        #[arg(long, default_value_t = 1)]
        count: u32,
    },
    /// Run until the current function returns (`gu`).
    StepOut,
    /// Step until the given address (`pa <addr>` / `ta <addr>`).
    StepUntil {
        /// Target address (e.g. 0x4030f6 or `nt!NtClose`).
        address: String,
        /// Step *into* calls instead of stepping over them.
        #[arg(long, default_value_t = false)]
        into: bool,
    },
    /// Set a software breakpoint at `<location>`.
    Bp {
        location: String,
        /// One-shot (`bu` is replaced by `bp /1` here).
        #[arg(long, default_value_t = false)]
        one_shot: bool,
    },
    /// Set a hardware breakpoint with `ba`.
    Ba {
        /// Address.
        address: String,
        /// Access type: `e` (execute, default), `r`, `w`, or `io`.
        #[arg(long, default_value = "e")]
        access: String,
        /// Watch size in bytes (1/2/4/8).
        #[arg(long, default_value_t = 1)]
        size: u32,
    },
    /// Clear a breakpoint by id (or `*` for all).
    Bc {
        #[arg(default_value = "*")]
        id: String,
    },
    /// List breakpoints (`bl`).
    Bl,
    /// Show registers. With no args runs `r`; otherwise reads each register
    /// individually so the output is parser-friendly.
    Reg {
        /// Specific registers (e.g. `eip eax esp`). If omitted prints `r`.
        registers: Vec<String>,
    },
    /// Read memory. Format defaults to `qwords` on x64 / `dwords` on x86.
    Mem {
        address: String,
        #[arg(long, default_value = "bytes")]
        format: String,
        #[arg(long, default_value_t = 32)]
        count: u32,
    },
    /// Disassemble starting at `<address>`.
    Dis {
        address: String,
        #[arg(long, default_value_t = 16)]
        count: u32,
    },
    /// Stack backtrace (`kv` by default).
    Bt {
        #[arg(long, default_value = "kv")]
        format: String,
        #[arg(long, default_value_t = 32)]
        count: u32,
    },
    /// Snapshot at the current break: `.lastevent` + `r` + `u @eip L8` +
    /// `kv 16` + `bl`.
    Snapshot,
    /// Real-time dump: capture the full process memory (as a /ma minidump)
    /// and the raw bytes of every loaded module to `<out_dir>`. The daemon
    /// auto-interrupts the target if it is running; nothing is detached.
    Dump {
        /// Output directory. Created if missing. Existing files are
        /// overwritten.
        #[arg(long)]
        out_dir: PathBuf,
        /// Skip the full-memory minidump (`.dump /ma`).
        #[arg(long, default_value_t = false)]
        no_minidump: bool,
        /// Skip per-module raw byte dumps (`.writemem` per module).
        #[arg(long, default_value_t = false)]
        no_modules: bool,
        /// Only dump modules whose name (case-insensitive) contains this
        /// substring. Useful to skip system DLLs.
        #[arg(long)]
        module_filter: Option<String>,
        /// Resume the target after the dump finishes (default: leave it
        /// in `break` state).
        #[arg(long, default_value_t = false)]
        resume_after: bool,
    },
    /// Run any raw WinDbg command (subject to the same blocklist as
    /// `windbg_execute_command`).
    Exec {
        /// The command verbatim. Quote if it contains spaces, e.g.
        /// `do exec "u @eip L4"`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Print session info (transport, connection options, default state).
    Info,
}

// ---------------------------------------------------------------------------
// Daemon registry helpers (one JSON file per daemon under %TEMP%).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonRegistry {
    name: String,
    pid: u32,
    address: String,
    target_summary: String,
    started_at_unix_ms: u64,
}

fn registry_dir() -> PathBuf {
    let base = std::env::var_os("TEMP")
        .or_else(|| std::env::var_os("TMP"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("windbg_cli_daemons")
}

fn registry_path(name: &str) -> PathBuf {
    registry_dir().join(format!("{name}.json"))
}

fn write_registry(entry: &DaemonRegistry) -> std::io::Result<()> {
    let dir = registry_dir();
    fs::create_dir_all(&dir)?;
    let path = registry_path(&entry.name);
    let bytes = serde_json::to_vec_pretty(entry).expect("serialize registry");
    fs::write(path, bytes)
}

fn read_registry(name: &str) -> std::io::Result<DaemonRegistry> {
    let bytes = fs::read(registry_path(name))?;
    let entry: DaemonRegistry = serde_json::from_slice(&bytes)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    Ok(entry)
}

fn remove_registry(name: &str) {
    let _ = fs::remove_file(registry_path(name));
}

fn list_registries() -> Vec<DaemonRegistry> {
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
enum Request {
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

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    ok: bool,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    state: Option<Value>,
}

impl Response {
    fn ok(text: impl Into<String>) -> Self {
        Self { ok: true, text: text.into(), state: None }
    }
    fn ok_with_state(text: impl Into<String>, state: DebuggerExecutionState) -> Self {
        Self {
            ok: true,
            text: text.into(),
            state: serde_json::to_value(state).ok(),
        }
    }
    fn err(text: impl Into<String>) -> Self {
        Self { ok: false, text: text.into(), state: None }
    }
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.target {
        Target::ListTools => {
            print_tool_listing();
            ExitCode::SUCCESS
        }
        Target::Daemon { ref action } => match action {
            DaemonAction::Start { name, bind, target } => {
                run_daemon(&cli, name.clone(), bind.clone(), target).await
            }
            DaemonAction::Stop { name } => stop_daemon(name).await,
            DaemonAction::Status { name } => status_daemon(name),
            DaemonAction::List => list_daemons(),
        },
        Target::Do { ref name, ref action } => do_action(name, action),
        Target::Kernel { .. } => run_one_shot(cli).await,
    }
}

// ---------------------------------------------------------------------------
// One-shot mode.
// ---------------------------------------------------------------------------

async fn run_one_shot(cli: Cli) -> ExitCode {
    let commands = match assemble_commands(&cli) {
        Ok(commands) => commands,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };

    let manager = HeadlessSessionManager::new();
    let startup = effective_startup_command(&cli);

    let session = match open_session_from_target(&manager, &cli, startup.as_deref()).await {
        Ok(session) => session,
        Err(error) => {
            eprintln!("attach failed: {error}");
            return ExitCode::from(1);
        }
    };

    let session_id = session.session_id.clone();
    eprintln!(
        "session: {} ({}) state={}",
        session.session_id,
        session.transport,
        session.state.as_ref().map(|s| s.status_name.as_str()).unwrap_or("unknown")
    );

    let exit = match run_commands(&manager, &session_id, &cli, &commands).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("command run failed: {error}");
            ExitCode::from(1)
        }
    };

    close_session(&manager, &session_id, &cli).await;
    exit
}

// ---------------------------------------------------------------------------
// Daemon mode.
// ---------------------------------------------------------------------------

async fn run_daemon(cli: &Cli, name: String, bind: String, target: &DaemonTarget) -> ExitCode {
    if read_registry(&name).is_ok() {
        eprintln!("daemon `{name}` is already running (per registry). Stop it first with `windbg_cli daemon stop --name {name}` or use a different --name.");
        return ExitCode::from(2);
    }

    // Bind first so the port is known before we start the (potentially slow)
    // attach. clap doesn't accept the "0 port = pick one" form for SocketAddr
    // in some users, so we do it via std parser.
    let addr: SocketAddr = match bind.parse() {
        Ok(a) => a,
        Err(error) => {
            eprintln!("invalid --bind address `{bind}`: {error}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(error) => {
            eprintln!("failed to bind {addr}: {error}");
            return ExitCode::from(1);
        }
    };
    let local_addr = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));

    let manager = HeadlessSessionManager::new();
    let startup = effective_startup_command(cli);

    let session = match open_session_from_daemon_target(
        &manager,
        cli,
        target,
        startup.as_deref(),
    )
    .await
    {
        Ok(session) => session,
        Err(error) => {
            eprintln!("daemon attach failed: {error}");
            return ExitCode::from(1);
        }
    };
    let session_id = Arc::new(session.session_id.clone());
    let manager = Arc::new(manager);
    let target_summary = describe_daemon_target(target);

    let entry = DaemonRegistry {
        name: name.clone(),
        pid: std::process::id(),
        address: local_addr.to_string(),
        target_summary: target_summary.clone(),
        started_at_unix_ms: now_unix_ms(),
    };
    if let Err(err) = write_registry(&entry) {
        eprintln!("failed to write daemon registry entry: {err}");
        let _ = manager
            .close_session(&session_id, Some(cli.shutdown_timeout_secs), Some(false))
            .await;
        return ExitCode::from(1);
    }

    eprintln!(
        "daemon `{name}` listening on {} (pid={}, session={}, target={})",
        local_addr,
        std::process::id(),
        session_id,
        target_summary,
    );
    eprintln!("press Ctrl+C or run `windbg_cli daemon stop --name {name}` to terminate");
    println!(
        "{}",
        serde_json::to_string(&json!({
            "daemon": name,
            "address": local_addr.to_string(),
            "pid": std::process::id(),
            "session_id": session_id.as_str(),
            "target": target_summary,
        }))
        .unwrap()
    );

    listener
        .set_nonblocking(true)
        .expect("set listener non-blocking");

    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runtime_handle = tokio::runtime::Handle::current();

    // Accept loop. Block-wait for a connection up to 200 ms so we can also
    // poll the shutdown flag.
    'accept: loop {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _peer)) => {
                let manager = manager.clone();
                let session_id = session_id.clone();
                let shutdown = shutdown.clone();
                let handle = runtime_handle.clone();
                let cli_options = (cli.ready_timeout_secs, cli.max_output_chars);
                std::thread::spawn(move || {
                    handle_client(stream, manager, session_id, shutdown, cli_options, handle);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
                continue 'accept;
            }
            Err(error) => {
                eprintln!("accept error: {error}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    eprintln!("daemon `{name}`: shutting down");
    let _ = manager
        .close_session(
            &session_id,
            Some(cli.shutdown_timeout_secs),
            Some(cli.resume_on_exit),
        )
        .await;
    remove_registry(&name);
    ExitCode::SUCCESS
}

fn handle_client(
    stream: TcpStream,
    manager: Arc<HeadlessSessionManager>,
    session_id: Arc<String>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    cli_options: (u64, usize),
    rt: tokio::runtime::Handle,
) {
    let (ready_timeout_secs, max_output_chars) = cli_options;
    let peer = stream.peer_addr().ok();
    let reader = stream.try_clone().expect("clone tcp stream");
    let mut writer = stream;
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    while !shutdown.load(std::sync::atomic::Ordering::SeqCst) {
        line.clear();
        let n = match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let _ = n;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request: Request = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(error) => {
                let resp = Response::err(format!("invalid request json: {error}"));
                let _ = writeln!(writer, "{}", serde_json::to_string(&resp).unwrap());
                continue;
            }
        };

        let response = handle_request(
            &manager,
            &session_id,
            request,
            ready_timeout_secs,
            max_output_chars,
            &shutdown,
            &rt,
        );

        let line_out = serde_json::to_string(&response).unwrap();
        if writeln!(writer, "{line_out}").is_err() {
            break;
        }
    }
    let _ = peer;
}

fn handle_request(
    manager: &Arc<HeadlessSessionManager>,
    session_id: &str,
    request: Request,
    ready_timeout_secs: u64,
    max_output_chars: usize,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
    rt: &tokio::runtime::Handle,
) -> Response {
    match request {
        Request::Shutdown => {
            shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
            Response::ok("shutdown requested")
        }
        Request::State => match rt.block_on(manager.query_state(Some(session_id))) {
            Ok(state) => {
                let text = format!(
                    "{} (raw={}, ready={}, running={})",
                    state.status_name, state.raw_status, state.ready_for_commands, state.running
                );
                Response::ok_with_state(text, state)
            }
            Err(error) => Response::err(format!("state failed: {error}")),
        },
        Request::Info => match rt.block_on(manager.current_session()) {
            Ok(Some(info)) => {
                let text = format!(
                    "session_id={} transport={} connection={} startup_command={:?} state={:?}",
                    info.session_id,
                    info.transport,
                    info.connection_options,
                    info.startup_command,
                    info.state.as_ref().map(|s| &s.status_name)
                );
                Response::ok(text)
            }
            Ok(None) => Response::ok("no session"),
            Err(error) => Response::err(format!("info failed: {error}")),
        },
        Request::Exec { command } => {
            if let Err(error) =
                rt.block_on(wait_until_ready_inner(manager, session_id, ready_timeout_secs))
            {
                return Response::err(error);
            }
            match rt.block_on(manager.execute_command(Some(session_id), command)) {
                Ok(result) => Response::ok_with_state(
                    clamp(&result.output, max_output_chars),
                    result.state_after,
                ),
                Err(error) => Response::err(format!("exec failed: {error}")),
            }
        }
        Request::Step { count } => step_via_command(
            manager,
            session_id,
            "t",
            count,
            ready_timeout_secs,
            max_output_chars,
            rt,
        ),
        Request::StepOver { count } => step_via_command(
            manager,
            session_id,
            "p",
            count,
            ready_timeout_secs,
            max_output_chars,
            rt,
        ),
        Request::StepOut => step_via_command(
            manager,
            session_id,
            "gu",
            1,
            ready_timeout_secs,
            max_output_chars,
            rt,
        ),
        Request::StepUntil { address, into } => {
            let verb = if into { "ta" } else { "pa" };
            step_via_command(
                manager,
                session_id,
                &format!("{verb} {address}"),
                1,
                ready_timeout_secs,
                max_output_chars,
                rt,
            )
        }
        Request::Go => match rt.block_on(manager.resume(Some(session_id))) {
            Ok(state) => Response::ok_with_state("resumed", state),
            Err(error) => Response::err(format!("go failed: {error}")),
        },
        Request::Interrupt => match rt.block_on(manager.interrupt(Some(session_id))) {
            Ok(state) => {
                let text = format!("interrupted -> {}", state.status_name);
                Response::ok_with_state(text, state)
            }
            Err(error) => Response::err(format!("interrupt failed: {error}")),
        },
        Request::WaitBreak { timeout_secs } => {
            match rt.block_on(wait_until_break(manager, session_id, timeout_secs)) {
                Ok(state) => Response::ok_with_state(state.status_name.clone(), state),
                Err(error) => Response::err(error),
            }
        }
        Request::Bp { location, one_shot } => {
            let cmd = if one_shot {
                format!("bp /1 {location}")
            } else {
                format!("bp {location}")
            };
            execute_simple(manager, session_id, &cmd, ready_timeout_secs, max_output_chars, rt)
        }
        Request::Ba { address, access, size } => {
            let cmd = format!("ba {access} {size} {address}");
            execute_simple(manager, session_id, &cmd, ready_timeout_secs, max_output_chars, rt)
        }
        Request::Bc { id } => execute_simple(
            manager,
            session_id,
            &format!("bc {id}"),
            ready_timeout_secs,
            max_output_chars,
            rt,
        ),
        Request::Bl => execute_simple(
            manager,
            session_id,
            "bl",
            ready_timeout_secs,
            max_output_chars,
            rt,
        ),
        Request::Reg { registers } => {
            if registers.is_empty() {
                execute_simple(manager, session_id, "r", ready_timeout_secs, max_output_chars, rt)
            } else {
                let mut buf = String::new();
                for reg in &registers {
                    let cmd = format!("r @{reg}");
                    match rt.block_on(manager.execute_command(Some(session_id), cmd.clone())) {
                        Ok(result) => buf.push_str(&result.output),
                        Err(error) => buf.push_str(&format!("{cmd}: error {error}\n")),
                    }
                }
                Response::ok(clamp(&buf, max_output_chars))
            }
        }
        Request::Mem { address, format, count } => {
            let verb = match format.to_ascii_lowercase().as_str() {
                "b" | "byte" | "bytes" | "db" => "db",
                "w" | "word" | "words" | "dw" => "dw",
                "d" | "dword" | "dwords" | "dd" => "dd",
                "q" | "qword" | "qwords" | "dq" => "dq",
                "ascii" | "a" | "da" => "da",
                "unicode" | "u16" | "du" => "du",
                other => return Response::err(format!("unknown memory format `{other}`")),
            };
            let cmd = if matches!(verb, "da" | "du") {
                format!("{verb} {address}")
            } else {
                format!("{verb} {address} L{count:x}")
            };
            execute_simple(manager, session_id, &cmd, ready_timeout_secs, max_output_chars, rt)
        }
        Request::Dis { address, count } => execute_simple(
            manager,
            session_id,
            &format!("u {address} L{count:x}"),
            ready_timeout_secs,
            max_output_chars,
            rt,
        ),
        Request::Bt { format, count } => execute_simple(
            manager,
            session_id,
            &format!("{format} {count}"),
            ready_timeout_secs,
            max_output_chars,
            rt,
        ),
        Request::Snapshot => {
            let mut buf = String::new();
            for cmd in [".lastevent", "r", "u @eip L8", "kv 16", "bl"] {
                buf.push_str(&format!("=== {cmd} ===\n"));
                match rt.block_on(manager.execute_command(Some(session_id), cmd.to_string())) {
                    Ok(result) => buf.push_str(&result.output),
                    Err(error) => buf.push_str(&format!("error: {error}\n")),
                }
                if !buf.ends_with('\n') {
                    buf.push('\n');
                }
            }
            Response::ok(clamp(&buf, max_output_chars))
        }
        Request::Dump {
            out_dir,
            minidump,
            modules,
            module_filter,
            resume_after,
        } => handle_dump(
            manager,
            session_id,
            ready_timeout_secs,
            max_output_chars,
            rt,
            &out_dir,
            minidump,
            modules,
            module_filter.as_deref(),
            resume_after,
        ),
    }
}

// ---------------------------------------------------------------------------
// Real-time process / module dump.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ModuleEntry {
    /// Image base (e.g. 0x00400000).
    base: u64,
    /// Image end (exclusive). When unknown we skip the module.
    end: u64,
    /// Short module name (e.g. "Crackme" or "ntdll").
    name: String,
}

fn parse_lm_table(out: &str) -> Vec<ModuleEntry> {
    // `lm n` rows look like (32-bit example):
    //   00400000 0040b400   Crackme    Crackme.exe
    // and on x64 / WoW64 the addresses are split with a backtick:
    //   00000000`00400000 00000000`00486000   Crackme  Crackme.exe
    fn parse_addr(tok: &str) -> Option<u64> {
        let cleaned: String = tok
            .trim_start_matches("0x")
            .chars()
            .filter(|c| *c != '`')
            .collect();
        u64::from_str_radix(&cleaned, 16).ok()
    }
    let mut modules = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("start") || line.starts_with("Unloaded")
            || line.starts_with("=") || line.starts_with("Browse")
        {
            continue;
        }
        let mut parts = line.split_whitespace();
        let start = parts.next();
        let end = parts.next();
        let name = parts.next();
        let (Some(start), Some(end), Some(name)) = (start, end, name) else { continue };
        let Some(base) = parse_addr(start) else { continue };
        let Some(end_u) = parse_addr(end) else { continue };
        if base == 0 || end_u <= base {
            continue;
        }
        // Sanity: skip absurdly large ranges (>512 MiB) — those are usually
        // parser glitches, not real modules.
        if end_u - base > 0x2000_0000 {
            continue;
        }
        modules.push(ModuleEntry {
            base,
            end: end_u,
            name: name.trim_matches(&['(', ')', ',', ':'][..]).to_string(),
        });
    }
    modules
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.' => c,
            _ => '_',
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn handle_dump(
    manager: &Arc<HeadlessSessionManager>,
    session_id: &str,
    ready_timeout_secs: u64,
    max_output_chars: usize,
    rt: &tokio::runtime::Handle,
    out_dir: &str,
    minidump: bool,
    modules: bool,
    module_filter: Option<&str>,
    resume_after: bool,
) -> Response {
    let out_path = PathBuf::from(out_dir);
    if let Err(error) = fs::create_dir_all(&out_path) {
        return Response::err(format!("create_dir_all `{out_dir}`: {error}"));
    }

    // 1) Make sure we're broken in. If currently running, interrupt and wait
    //    for `break` so .dump / .writemem operate on a stable target.
    let was_running = match rt.block_on(manager.query_state(Some(session_id))) {
        Ok(state) => state.running,
        Err(error) => return Response::err(format!("query_state: {error}")),
    };
    if was_running {
        if let Err(error) = rt.block_on(manager.interrupt(Some(session_id))) {
            return Response::err(format!("interrupt: {error}"));
        }
    }
    if let Err(error) =
        rt.block_on(wait_until_ready_inner(manager, session_id, ready_timeout_secs))
    {
        return Response::err(format!("wait-ready: {error}"));
    }

    let mut log = String::new();
    let mut wrote_any = false;

    // 2) Full-process minidump via `.dump /ma` (writes a .dmp file you can
    //    open in WinDbg/dbgeng later). This is the canonical "snapshot the
    //    whole process" tool — it captures memory, threads, handles, modules.
    if minidump {
        let dmp_path = out_path.join("process.dmp");
        // Some dbgeng builds refuse to overwrite without /o, so always pass it.
        let cmd = format!(".dump /ma /o \"{}\"", dmp_path.display());
        log.push_str(&format!("=== {cmd} ===\n"));
        match rt.block_on(manager.execute_command(Some(session_id), cmd)) {
            Ok(result) => {
                log.push_str(&result.output);
                if !log.ends_with('\n') {
                    log.push('\n');
                }
                if dmp_path.exists() {
                    wrote_any = true;
                    log.push_str(&format!(
                        "  -> wrote {} ({} bytes)\n",
                        dmp_path.display(),
                        fs::metadata(&dmp_path).map(|m| m.len()).unwrap_or(0)
                    ));
                } else {
                    log.push_str("  warning: minidump file was not produced\n");
                }
            }
            Err(error) => log.push_str(&format!("  error: {error}\n")),
        }
    }

    // 3) Per-module raw byte dumps via `.writemem`. We list modules with
    //    `lm 1m` (one-line, image start+end+name), filter, then write
    //    `<base>-<end>` of each module to `<name>_<base>.bin`.
    let mut module_count = 0usize;
    if modules {
        log.push_str("=== lm n ===\n");
        let lm = match rt.block_on(manager.execute_command(Some(session_id), "lm n".to_string())) {
            Ok(r) => {
                log.push_str(&r.output);
                if !log.ends_with('\n') {
                    log.push('\n');
                }
                r.output
            }
            Err(error) => {
                log.push_str(&format!("  error: {error}\n"));
                return Response::err(log);
            }
        };
        let mut entries = parse_lm_table(&lm);
        if let Some(needle) = module_filter {
            let needle = needle.to_ascii_lowercase();
            entries.retain(|m| m.name.to_ascii_lowercase().contains(&needle));
        }
        log.push_str(&format!("=== dumping {} module(s) ===\n", entries.len()));
        let mod_dir = out_path.join("modules");
        if let Err(error) = fs::create_dir_all(&mod_dir) {
            return Response::err(format!("create_dir_all `{}`: {error}", mod_dir.display()));
        }
        for m in entries {
            let safe_name = sanitize_name(&m.name);
            let bin_path = mod_dir.join(format!("{}_{:016x}.bin", safe_name, m.base));
            // `.writemem` syntax: `.writemem <file> <start> <end>` — note that
            // the filename argument does NOT accept quoted strings (unlike
            // `.dump`). dbgeng treats everything from the first non-space
            // character up to the next whitespace as the filename, so we
            // must avoid spaces in the path. We make the directory absolute
            // and fall back to a short name in TEMP if it contains spaces.
            let bin_str = bin_path.to_string_lossy().to_string();
            let usable_path = if bin_str.contains(' ') {
                let temp_dir = std::env::var_os("TEMP")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));
                let tmp = temp_dir.join(format!(
                    "windbg_cli_dump_{}_{:016x}.bin",
                    safe_name, m.base
                ));
                Some(tmp)
            } else {
                None
            };
            let cmd_path = usable_path.as_ref().unwrap_or(&bin_path);
            let cmd = format!(
                ".writemem {} 0x{:x} 0x{:x}",
                cmd_path.display(),
                m.base,
                m.end - 1
            );
            log.push_str(&format!(
                "--- {} [0x{:x} .. 0x{:x}, {} bytes] ---\n",
                m.name,
                m.base,
                m.end,
                m.end - m.base
            ));
            match rt.block_on(manager.execute_command(Some(session_id), cmd)) {
                Ok(result) => {
                    if !result.output.trim().is_empty() {
                        log.push_str(&result.output);
                        if !log.ends_with('\n') {
                            log.push('\n');
                        }
                    }
                    // If we wrote to %TEMP% (because the user-requested path
                    // had spaces), move the file into the requested dir.
                    if let Some(tmp) = &usable_path {
                        if tmp.exists() {
                            if let Err(error) = fs::rename(tmp, &bin_path) {
                                // fall back to copy+delete (cross-volume)
                                if fs::copy(tmp, &bin_path).is_ok() {
                                    let _ = fs::remove_file(tmp);
                                } else {
                                    log.push_str(&format!(
                                        "  warning: could not move {} -> {}: {error}\n",
                                        tmp.display(),
                                        bin_path.display()
                                    ));
                                }
                            }
                        }
                    }
                    if bin_path.exists() {
                        module_count += 1;
                        wrote_any = true;
                        log.push_str(&format!(
                            "  -> {} ({} bytes)\n",
                            bin_path.display(),
                            fs::metadata(&bin_path).map(|m| m.len()).unwrap_or(0)
                        ));
                    } else {
                        log.push_str("  warning: module file was not produced\n");
                    }
                }
                Err(error) => log.push_str(&format!("  error: {error}\n")),
            }
        }
    }

    log.push_str(&format!(
        "\n=== dump complete: out_dir={}, modules_dumped={}, full_minidump={} ===\n",
        out_path.display(),
        module_count,
        minidump
    ));

    // 4) Optionally resume the target (default: stay broken so caller can
    //    keep poking). Even if we auto-interrupted at the start, we leave
    //    the decision to the caller — most "live dump" workflows want to
    //    take a peek and then continue.
    if resume_after {
        match rt.block_on(manager.resume(Some(session_id))) {
            Ok(state) => {
                log.push_str(&format!("=== resumed: {} ===\n", state.status_name));
                let _ = wrote_any;
                return Response::ok_with_state(clamp(&log, max_output_chars), state);
            }
            Err(error) => {
                log.push_str(&format!("warning: resume failed: {error}\n"));
            }
        }
    } else if was_running {
        log.push_str("note: target was running before dump; left in `break` state. Pass --resume-after to continue.\n");
    }

    let _ = wrote_any;
    Response::ok(clamp(&log, max_output_chars))
}


fn execute_simple(
    manager: &Arc<HeadlessSessionManager>,
    session_id: &str,
    command: &str,
    ready_timeout_secs: u64,
    max_output_chars: usize,
    rt: &tokio::runtime::Handle,
) -> Response {
    if let Err(error) = rt.block_on(wait_until_ready_inner(manager, session_id, ready_timeout_secs))
    {
        return Response::err(error);
    }
    match rt.block_on(manager.execute_command(Some(session_id), command.to_string())) {
        Ok(result) => Response::ok_with_state(clamp(&result.output, max_output_chars), result.state_after),
        Err(error) => Response::err(format!("`{command}` failed: {error}")),
    }
}

fn step_via_command(
    manager: &Arc<HeadlessSessionManager>,
    session_id: &str,
    base_command: &str,
    count: u32,
    ready_timeout_secs: u64,
    max_output_chars: usize,
    rt: &tokio::runtime::Handle,
) -> Response {
    let mut buf = String::new();
    let mut last_state: Option<DebuggerExecutionState> = None;
    for i in 0..count.max(1) {
        if let Err(error) =
            rt.block_on(wait_until_ready_inner(manager, session_id, ready_timeout_secs))
        {
            return Response::err(error);
        }
        match rt.block_on(manager.execute_command(Some(session_id), base_command.to_string())) {
            Ok(result) => {
                if count > 1 {
                    buf.push_str(&format!("--- {} (#{}) ---\n", base_command, i + 1));
                }
                buf.push_str(&result.output);
                if !buf.ends_with('\n') {
                    buf.push('\n');
                }
                last_state = Some(result.state_after);
            }
            Err(error) => {
                buf.push_str(&format!("error: {error}\n"));
                return Response::err(buf);
            }
        }
    }
    let text = clamp(&buf, max_output_chars);
    match last_state {
        Some(state) => Response::ok_with_state(text, state),
        None => Response::ok(text),
    }
}

async fn wait_until_break(
    manager: &Arc<HeadlessSessionManager>,
    session_id: &str,
    timeout_secs: u64,
) -> Result<DebuggerExecutionState, String> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    loop {
        let state = manager
            .query_state(Some(session_id))
            .await
            .map_err(|e| e.to_string())?;
        if state.status_name == "break" {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "wait_break timed out after {timeout_secs}s; last state {}",
                state.status_name
            ));
        }
        sleep(STATE_POLL_INTERVAL).await;
    }
}

async fn wait_until_ready_inner(
    manager: &Arc<HeadlessSessionManager>,
    session_id: &str,
    timeout_secs: u64,
) -> Result<DebuggerExecutionState, String> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut interrupted = false;
    loop {
        let state = manager
            .query_state(Some(session_id))
            .await
            .map_err(|e| e.to_string())?;
        if state.ready_for_commands {
            return Ok(state);
        }
        if state.running && !interrupted {
            let _ = manager.interrupt(Some(session_id)).await;
            interrupted = true;
            continue;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "ready timed out after {timeout_secs}s; last state {} ({})",
                state.status_name, state.raw_status
            ));
        }
        sleep(STATE_POLL_INTERVAL).await;
    }
}

fn clamp(text: &str, limit: usize) -> String {
    if limit == 0 || text.len() <= limit {
        text.to_string()
    } else {
        format!("{}\n... <truncated>", &text[..limit])
    }
}

// ---------------------------------------------------------------------------
// Daemon: stop/status/list.
// ---------------------------------------------------------------------------

async fn stop_daemon(name: &str) -> ExitCode {
    let entry = match read_registry(name) {
        Ok(e) => e,
        Err(error) => {
            eprintln!("no daemon `{name}`: {error}");
            return ExitCode::from(2);
        }
    };
    match send_request(&entry.address, &Request::Shutdown) {
        Ok(resp) => {
            println!("{}", resp.text);
            // Daemon will remove its own registry on shutdown; tolerate stragglers.
            std::thread::sleep(Duration::from_millis(500));
            if read_registry(name).is_ok() {
                remove_registry(name);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("stop failed: {error}");
            // Stale registry?
            remove_registry(name);
            ExitCode::from(1)
        }
    }
}

fn status_daemon(name: &str) -> ExitCode {
    match read_registry(name) {
        Ok(entry) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "name": entry.name,
                    "pid": entry.pid,
                    "address": entry.address,
                    "target": entry.target_summary,
                    "started_at_unix_ms": entry.started_at_unix_ms,
                }))
                .unwrap()
            );
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("no daemon `{name}`");
            ExitCode::from(1)
        }
    }
}

fn list_daemons() -> ExitCode {
    let entries = list_registries();
    if entries.is_empty() {
        println!("[]");
        return ExitCode::SUCCESS;
    }
    let pretty: Vec<Value> = entries
        .into_iter()
        .map(|e| {
            json!({
                "name": e.name,
                "pid": e.pid,
                "address": e.address,
                "target": e.target_summary,
                "started_at_unix_ms": e.started_at_unix_ms,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&pretty).unwrap());
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// `do <action>` client.
// ---------------------------------------------------------------------------

fn do_action(name: &str, action: &DoAction) -> ExitCode {
    let entry = match read_registry(name) {
        Ok(e) => e,
        Err(error) => {
            eprintln!("no daemon `{name}`: {error} (start one with `windbg_cli daemon start ...`)");
            return ExitCode::from(2);
        }
    };

    let request = match build_request(action) {
        Ok(r) => r,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };

    match send_request(&entry.address, &request) {
        Ok(resp) => {
            // Print state header + body.
            if let Some(state_val) = &resp.state {
                let status = state_val.get("status_name").and_then(Value::as_str).unwrap_or("?");
                let raw = state_val.get("raw_status").and_then(Value::as_u64).unwrap_or(0);
                let ready = state_val
                    .get("ready_for_commands")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let running = state_val
                    .get("running")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                eprintln!(
                    "[state {}/{}, ready={}, running={}]",
                    status, raw, ready, running
                );
            }
            let body = resp.text.trim_end();
            if !body.is_empty() {
                println!("{}", body);
            }
            if resp.ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
        }
        Err(error) => {
            eprintln!("daemon `{name}` request failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn build_request(action: &DoAction) -> Result<Request, String> {
    Ok(match action {
        DoAction::State => Request::State,
        DoAction::Info => Request::Info,
        DoAction::Go => Request::Go,
        DoAction::Interrupt => Request::Interrupt,
        DoAction::WaitBreak { timeout_secs } => Request::WaitBreak { timeout_secs: *timeout_secs },
        DoAction::Step { count } => Request::Step { count: *count },
        DoAction::StepOver { count } => Request::StepOver { count: *count },
        DoAction::StepOut => Request::StepOut,
        DoAction::StepUntil { address, into } => Request::StepUntil {
            address: address.clone(),
            into: *into,
        },
        DoAction::Bp { location, one_shot } => Request::Bp {
            location: location.clone(),
            one_shot: *one_shot,
        },
        DoAction::Ba { address, access, size } => Request::Ba {
            address: address.clone(),
            access: access.clone(),
            size: *size,
        },
        DoAction::Bc { id } => Request::Bc { id: id.clone() },
        DoAction::Bl => Request::Bl,
        DoAction::Reg { registers } => Request::Reg { registers: registers.clone() },
        DoAction::Mem { address, format, count } => Request::Mem {
            address: address.clone(),
            format: format.clone(),
            count: *count,
        },
        DoAction::Dis { address, count } => Request::Dis {
            address: address.clone(),
            count: *count,
        },
        DoAction::Bt { format, count } => Request::Bt {
            format: format.clone(),
            count: *count,
        },
        DoAction::Snapshot => Request::Snapshot,
        DoAction::Dump {
            out_dir,
            no_minidump,
            no_modules,
            module_filter,
            resume_after,
        } => {
            // Resolve to an absolute path so the daemon (which may have a
            // different cwd) writes to a predictable location.
            let resolved = if out_dir.is_absolute() {
                out_dir.clone()
            } else {
                std::env::current_dir()
                    .map(|d| d.join(out_dir))
                    .unwrap_or_else(|_| out_dir.clone())
            };
            Request::Dump {
                out_dir: resolved.to_string_lossy().into_owned(),
                minidump: !*no_minidump,
                modules: !*no_modules,
                module_filter: module_filter.clone(),
                resume_after: *resume_after,
            }
        }
        DoAction::Exec { command } => {
            let joined = command.join(" ");
            if joined.trim().is_empty() {
                return Err("missing command for `do exec`".into());
            }
            Request::Exec { command: joined }
        }
    })
}

fn send_request(address: &str, request: &Request) -> Result<Response, String> {
    let mut stream = TcpStream::connect_timeout(
        &address.parse().map_err(|e: std::net::AddrParseError| e.to_string())?,
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
    reader.read_line(&mut line).map_err(|e| format!("read: {e}"))?;
    serde_json::from_str(line.trim()).map_err(|e| format!("decode: {e}"))
}

// ---------------------------------------------------------------------------
// Shared session helpers.
// ---------------------------------------------------------------------------

fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn describe_daemon_target(target: &DaemonTarget) -> String {
    match target {
        DaemonTarget::Run { exe, args, follow_children } => format!(
            "run {} {} (follow_children={})",
            exe.display(),
            args.join(" "),
            follow_children
        ),
        DaemonTarget::Attach { pid, non_invasive } => {
            format!("attach pid={pid} non_invasive={non_invasive}")
        }
        DaemonTarget::Kernel { connection } => format!("kernel `{connection}`"),
    }
}

async fn open_session_from_target(
    manager: &HeadlessSessionManager,
    cli: &Cli,
    startup_command: Option<&str>,
) -> Result<HeadlessSessionInfo, String> {
    let attach_timeout = Some(cli.attach_timeout_secs);
    let session_id = cli.session_id.as_deref();
    let session = match &cli.target {
        // User-mode one-shot variants are disabled — see `enum Target` for
        // rationale.  Use `windbg_cli daemon start ...` instead.
        //
        // Target::Run { exe, args, follow_children } => {
        //     let exe = exe.canonicalize().unwrap_or_else(|_| exe.clone());
        //     let mut command_line = quote_argument(&exe.display().to_string());
        //     for arg in args {
        //         command_line.push(' ');
        //         command_line.push_str(&quote_argument(arg));
        //     }
        //     let attach = UserModeAttach::Launch {
        //         command_line,
        //         only_this_process: !*follow_children,
        //         detach_on_exit: !cli.terminate_on_exit,
        //     };
        //     manager
        //         .open_user_process_session(attach, session_id, startup_command, attach_timeout)
        //         .await
        // }
        // Target::Attach { pid, non_invasive } => {
        //     let attach = UserModeAttach::AttachPid {
        //         pid: *pid,
        //         non_invasive: *non_invasive,
        //         detach_on_exit: !cli.terminate_on_exit,
        //     };
        //     manager
        //         .open_user_process_session(attach, session_id, startup_command, attach_timeout)
        //         .await
        // }
        Target::Kernel { connection } => {
            manager
                .open_kernel_session(connection, session_id, startup_command, attach_timeout)
                .await
        }
        Target::ListTools | Target::Daemon { .. } | Target::Do { .. } => {
            return Err("unsupported target kind for one-shot helper".into())
        }
    };
    session.map_err(|e| e.to_string())
}

async fn open_session_from_daemon_target(
    manager: &HeadlessSessionManager,
    cli: &Cli,
    target: &DaemonTarget,
    startup_command: Option<&str>,
) -> Result<HeadlessSessionInfo, String> {
    let attach_timeout = Some(cli.attach_timeout_secs);
    let session_id = cli.session_id.as_deref();
    let session = match target {
        DaemonTarget::Run { exe, args, follow_children } => {
            let exe = exe.canonicalize().unwrap_or_else(|_| exe.clone());
            let mut command_line = quote_argument(&exe.display().to_string());
            for arg in args {
                command_line.push(' ');
                command_line.push_str(&quote_argument(arg));
            }
            let attach = UserModeAttach::Launch {
                command_line,
                only_this_process: !*follow_children,
                detach_on_exit: !cli.terminate_on_exit,
            };
            manager
                .open_user_process_session(attach, session_id, startup_command, attach_timeout)
                .await
        }
        DaemonTarget::Attach { pid, non_invasive } => {
            let attach = UserModeAttach::AttachPid {
                pid: *pid,
                non_invasive: *non_invasive,
                detach_on_exit: !cli.terminate_on_exit,
            };
            manager
                .open_user_process_session(attach, session_id, startup_command, attach_timeout)
                .await
        }
        DaemonTarget::Kernel { connection } => {
            manager
                .open_kernel_session(connection, session_id, startup_command, attach_timeout)
                .await
        }
    };
    session.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// One-shot helpers retained from the original CLI.
// ---------------------------------------------------------------------------

fn assemble_commands(cli: &Cli) -> Result<Vec<String>, String> {
    let mut commands: Vec<String> = cli
        .commands
        .iter()
        .map(|cmd| cmd.trim().to_string())
        .filter(|cmd| !cmd.is_empty())
        .collect();

    if let Some(script_path) = cli.script.as_ref() {
        let raw = fs::read_to_string(script_path)
            .map_err(|error| format!("failed to read script `{}`: {error}", script_path.display()))?;
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            commands.push(trimmed.to_string());
        }
    }

    Ok(commands)
}

fn effective_startup_command(cli: &Cli) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if cli.symfix {
        parts.push(".symfix".to_string());
        parts.push(".reload".to_string());
    }
    if let Some(extra) = cli.startup_command.as_deref().map(str::trim) {
        if !extra.is_empty() {
            parts.push(extra.to_string());
        }
    }
    if parts.is_empty() { None } else { Some(parts.join("; ")) }
}

async fn run_commands(
    manager: &HeadlessSessionManager,
    session_id: &str,
    cli: &Cli,
    commands: &[String],
) -> Result<(), String> {
    if commands.is_empty() {
        let state = wait_until_ready(manager, session_id, cli.ready_timeout_secs).await?;
        eprintln!("ready: {}", state.status_name);
        return Ok(());
    }

    for command in commands {
        let _ = wait_until_ready(manager, session_id, cli.ready_timeout_secs).await?;
        println!("=== {command} ===");
        let result = manager
            .execute_command(Some(session_id), command.clone())
            .await
            .map_err(|error| format!("`{command}` failed: {error}"))?;
        let output = result.output.trim_end();
        let truncated = if cli.max_output_chars > 0 && output.len() > cli.max_output_chars {
            format!("{}\n... <truncated>", &output[..cli.max_output_chars])
        } else {
            output.to_string()
        };
        if !truncated.is_empty() {
            println!("{truncated}");
        }
    }
    Ok(())
}

async fn wait_until_ready(
    manager: &HeadlessSessionManager,
    session_id: &str,
    timeout_secs: u64,
) -> Result<DebuggerExecutionState, String> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut interrupted = false;
    loop {
        let state = manager
            .query_state(Some(session_id))
            .await
            .map_err(|e| e.to_string())?;
        if state.ready_for_commands {
            return Ok(state);
        }
        if state.running && !interrupted {
            let _ = manager.interrupt(Some(session_id)).await;
            interrupted = true;
            continue;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "target did not become command-ready within {timeout_secs}s (last state: {} / {})",
                state.status_name, state.raw_status
            ));
        }
        sleep(STATE_POLL_INTERVAL).await;
    }
}

async fn close_session(manager: &HeadlessSessionManager, session_id: &str, cli: &Cli) {
    match manager
        .close_session(
            session_id,
            Some(cli.shutdown_timeout_secs),
            Some(cli.resume_on_exit),
        )
        .await
    {
        Ok(result) => {
            eprintln!(
                "closed: id={} resume_attempted={} shutdown_completed={} shutdown_error={}",
                result.closed_session_id,
                result.resume_attempted,
                result.shutdown_completed,
                result.shutdown_error.as_deref().unwrap_or("none"),
            );
        }
        Err(error) => eprintln!("close failed: {error}"),
    }
}

fn quote_argument(value: &str) -> String {
    if value.is_empty() {
        return "\"\"".to_string();
    }
    if value.chars().any(|c| c.is_whitespace() || c == '"' || c == '\\') {
        let escaped = value.replace('"', "\\\"");
        return format!("\"{escaped}\"");
    }
    value.to_string()
}

fn print_tool_listing() {
    let tools = [
        "windbg_open_session (kernel)",
        "windbg_open_user_process (user-mode launch / attach)",
        "windbg_close_session",
        "windbg_switch_session",
        "windbg_list_sessions",
        "windbg_current_session",
        "windbg_recover_session",
        "windbg_get_execution_state",
        "windbg_get_output",
        "windbg_interrupt_target",
        "windbg_resume_target",
        "windbg_execute_command",
        "windbg_set_breakpoint",
        "windbg_set_hardware_breakpoint",
        "windbg_trace_breakpoint",
        "windbg_continue_until_break",
        "windbg_step / windbg_step_over / windbg_go_up",
        "windbg_read_registers / windbg_read_memory / windbg_disassemble / windbg_backtrace",
        "windbg_list_modules / windbg_search_symbols / windbg_evaluate_expression",
        "windbg_set_driver_load_breakpoint / windbg_driver_summary / windbg_ioctl_snapshot",
    ];
    for name in tools {
        println!("{name}");
    }
}

fn init_tracing(verbose: bool) {
    let default_filter = if verbose { "info,windbg_mcp_rs=debug" } else { "warn" };
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_filter.into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init();
}

// (removed unused ctrlc shim — accept loop polls the shutdown flag every
// 200ms which is enough for the `daemon stop` and SIGINT cases.)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_argument_keeps_simple_tokens_unchanged() {
        assert_eq!(quote_argument("hello"), "hello");
    }

    #[test]
    fn quote_argument_quotes_paths_with_spaces() {
        assert_eq!(
            quote_argument(r"C:\Program Files\app.exe"),
            "\"C:\\Program Files\\app.exe\""
        );
    }
}
