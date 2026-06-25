//! Launches and manages `windbg_cli` daemons on behalf of the thin MCP server.
//!
//! The thin MCP server exposes only `open_session` / `close_session` /
//! `use_help`. The actual debugger session lives inside a `windbg_cli daemon`
//! process (because a dbgeng COM session cannot be shared across processes).
//! This module owns the lifecycle plumbing:
//!
//! - locating the `windbg_cli` executable,
//! - spawning `windbg_cli daemon start ...` **detached** (it blocks forever),
//! - polling the on-disk registry until the daemon is connectable (ready),
//! - idempotent reuse of an already-running daemon with the same name,
//! - stopping a daemon and cleaning up its registry / killing stale ones.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::daemon::{
    DaemonRegistry, Request, log_path, read_registry, registry_dir, remove_registry, send_request,
};

const POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Extra slack added on top of the attach timeout when waiting for readiness.
const READY_SLACK_SECS: u64 = 15;

/// The kind of target a session should attach to.
#[derive(Debug, Clone)]
pub enum TargetSpec {
    /// Spawn a local user-mode binary as the debuggee.
    Launch {
        command_line: String,
        follow_children: bool,
    },
    /// Attach to a running user-mode process by PID.
    Attach { pid: u32, non_invasive: bool },
    /// Open a kernel debugging session with a `-k`-style connection string.
    Kernel { connection: String },
}

impl TargetSpec {
    fn mode_label(&self) -> &'static str {
        match self {
            TargetSpec::Launch { .. } => "launch",
            TargetSpec::Attach { .. } => "attach",
            TargetSpec::Kernel { .. } => "kernel",
        }
    }

    /// The trailing `<target>` portion of `windbg_cli daemon start ...`.
    fn daemon_args(&self) -> Vec<String> {
        match self {
            TargetSpec::Launch {
                command_line,
                follow_children,
            } => {
                // The daemon target is `run <exe> [args...] [--follow-children]`.
                // We split the command line on whitespace; callers that need
                // exact quoting should pass a single-token path plus args.
                let mut args = vec!["run".to_string()];
                args.extend(split_command_line(command_line));
                if *follow_children {
                    args.push("--follow-children".to_string());
                }
                args
            }
            TargetSpec::Attach { pid, non_invasive } => {
                let mut args = vec!["attach".to_string(), pid.to_string()];
                if *non_invasive {
                    args.push("--non-invasive".to_string());
                }
                args
            }
            TargetSpec::Kernel { connection } => {
                vec!["kernel".to_string(), connection.clone()]
            }
        }
    }
}

/// Everything needed to open (or reuse) a daemon-backed session.
#[derive(Debug, Clone)]
pub struct OpenSpec {
    /// Explicit daemon name; when `None`, a unique `auto-<mode>-<rand>` name is
    /// generated.
    pub name: Option<String>,
    pub target: TargetSpec,
    pub startup_command: Option<String>,
    pub symfix: bool,
    pub attach_timeout_secs: Option<u64>,
    pub ready_timeout_secs: Option<u64>,
}

/// Locate the `windbg_cli` executable.
///
/// Resolution order:
/// 1. `override_path` (from the MCP `--cli-path` flag), if provided.
/// 2. `WINDBG_CLI_PATH` environment variable.
/// 3. Same directory as the current executable (`windbg_cli[.exe]`).
/// 4. Bare `windbg_cli` on `PATH`.
pub fn locate_cli(override_path: Option<&Path>) -> Result<PathBuf, String> {
    let exe_name = if cfg!(windows) {
        "windbg_cli.exe"
    } else {
        "windbg_cli"
    };

    if let Some(p) = override_path {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        return Err(format!("--cli-path `{}` does not exist", p.display()));
    }

    if let Some(env_path) = std::env::var_os("WINDBG_CLI_PATH") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!(
            "WINDBG_CLI_PATH `{}` does not exist",
            p.display()
        ));
    }

    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let candidate = dir.join(exe_name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // Fall back to PATH resolution by name. Command will resolve it at spawn.
    Ok(PathBuf::from(exe_name))
}

/// Open (or idempotently reuse) a daemon-backed session.
///
/// Returns the daemon's registry entry on success. If a daemon with the
/// requested name is already running and connectable, its existing entry is
/// returned without spawning a new one (idempotent reuse).
pub fn open_session(cli: &Path, spec: &OpenSpec) -> Result<DaemonRegistry, String> {
    let name = resolve_name(spec);

    // Idempotent reuse: if a live daemon with this name answers, return it.
    if let Ok(existing) = read_registry(&name) {
        if probe_alive(&existing.address) {
            return Ok(existing);
        }
        // Stale registry (file present, daemon dead). Clean up and re-create.
        remove_registry(&name);
    }

    let _ = std::fs::create_dir_all(registry_dir());

    // Build the daemon command line.
    let mut command = Command::new(cli);
    command.arg("daemon");
    command.arg("start");
    command.arg("--name");
    command.arg(&name);
    command.arg("--bind");
    command.arg("127.0.0.1:0");

    // Global flags that apply to the session, placed before the subcommand
    // target is appended (clap `global = true` accepts them anywhere, but we
    // keep them ahead of the target for clarity).
    if spec.symfix {
        command.arg("--symfix");
    }
    if let Some(startup) = spec.startup_command.as_deref() {
        if !startup.trim().is_empty() {
            command.arg("--startup-command");
            command.arg(startup);
        }
    }
    if let Some(secs) = spec.attach_timeout_secs {
        command.arg("--attach-timeout-secs");
        command.arg(secs.to_string());
    }

    // Trailing `<target>` (run/attach/kernel ...).
    for arg in spec.target.daemon_args() {
        command.arg(arg);
    }

    // Detach: no controlling terminal, redirect stdio to a log file so the
    // daemon does not block on a pipe and we can read errors back.
    let log = log_path(&name);
    let log_out = std::fs::File::create(&log)
        .map_err(|e| format!("create daemon log `{}`: {e}", log.display()))?;
    let log_err = log_out
        .try_clone()
        .map_err(|e| format!("clone daemon log handle: {e}"))?;
    command.stdin(Stdio::null());
    command.stdout(Stdio::from(log_out));
    command.stderr(Stdio::from(log_err));

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS (0x00000008) | CREATE_NEW_PROCESS_GROUP (0x00000200)
        command.creation_flags(0x0000_0008 | 0x0000_0200);
    }

    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to spawn `{}`: {e}", cli.display()))?;

    // Poll for readiness.
    let attach_secs = spec.attach_timeout_secs.unwrap_or(30);
    let ready_secs = spec
        .ready_timeout_secs
        .unwrap_or(attach_secs + READY_SLACK_SECS);
    let deadline = Instant::now() + Duration::from_secs(ready_secs.max(1));

    loop {
        // If the daemon process already exited, it failed to attach.
        if let Ok(Some(status)) = child.try_wait() {
            let tail = read_log_tail(&log, 40);
            remove_registry(&name);
            return Err(format!(
                "daemon `{name}` exited before becoming ready (status {status}).\n--- log tail ---\n{tail}"
            ));
        }

        if let Ok(entry) = read_registry(&name) {
            if entry.pid == child.id() && probe_alive(&entry.address) {
                return Ok(entry);
            }
        }

        if Instant::now() >= deadline {
            // Roll back: kill the child and clean up.
            let _ = child.kill();
            let _ = child.wait();
            remove_registry(&name);
            let tail = read_log_tail(&log, 40);
            return Err(format!(
                "daemon `{name}` did not become ready within {ready_secs}s.\n--- log tail ---\n{tail}"
            ));
        }

        sleep(POLL_INTERVAL);
    }
}

/// Stop a daemon by name. Sends `Shutdown`, then waits for the registry to
/// disappear. If the daemon is unreachable and `force` is set, kills the PID
/// (best effort) and removes the stale registry entry.
pub fn close_session(name: &str, force: bool) -> Result<String, String> {
    let entry = match read_registry(name) {
        Ok(e) => e,
        Err(_) => {
            return Ok(format!("daemon `{name}` not found (already stopped)"));
        }
    };

    match send_request(&entry.address, &Request::Shutdown) {
        Ok(_resp) => {
            // Wait briefly for the daemon to remove its own registry entry.
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if read_registry(name).is_err() {
                    return Ok(format!("daemon `{name}` stopped"));
                }
                sleep(POLL_INTERVAL);
            }
            // Daemon acked but registry lingered; clean up.
            remove_registry(name);
            Ok(format!("daemon `{name}` stopped (registry cleaned)"))
        }
        Err(err) => {
            if force {
                kill_pid(entry.pid);
                remove_registry(name);
                Ok(format!(
                    "daemon `{name}` was unreachable ({err}); force-killed pid {} and cleaned registry",
                    entry.pid
                ))
            } else {
                Err(format!(
                    "daemon `{name}` is unreachable ({err}); pass force=true to kill pid {} and clean the stale registry",
                    entry.pid
                ))
            }
        }
    }
}

/// Probe whether a daemon at `address` is alive by requesting its state.
fn probe_alive(address: &str) -> bool {
    matches!(send_request(address, &Request::State), Ok(resp) if resp.ok)
        || matches!(send_request(address, &Request::Info), Ok(_))
}

fn resolve_name(spec: &OpenSpec) -> String {
    match spec.name.as_deref() {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => format!(
            "auto-{}-{}",
            spec.target.mode_label(),
            short_token()
        ),
    }
}

/// A short pseudo-random token derived from the current time + pid. Good
/// enough to avoid collisions between auto-generated daemon names.
fn short_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mixed = nanos ^ (pid << 17);
    format!("{:08x}", (mixed as u64) & 0xffff_ffff)
}

fn split_command_line(command_line: &str) -> Vec<String> {
    command_line
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

fn read_log_tail(path: &Path, max_lines: usize) -> String {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(max_lines);
            lines[start..].join("\n")
        }
        Err(_) => "(no log available)".to_string(),
    }
}

#[cfg(windows)]
fn kill_pid(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/F", "/T", "/PID", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(windows))]
fn kill_pid(pid: u32) {
    let _ = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status();
}
