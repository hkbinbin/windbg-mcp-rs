//! Thin WinDbg MCP server.
//!
//! The MCP surface is intentionally tiny — only three tools:
//!
//! - `windbg_open_session`  : start (or idempotently reuse) a `windbg_cli`
//!   daemon that owns a live debugger session for a given target.
//! - `windbg_close_session` : stop a daemon.
//! - `windbg_use_help`      : return concise help that points at `windbg_cli`.
//!
//! All detailed debugging (breakpoints, memory, stepping, dumps, raw commands)
//! is performed by the agent running the `windbg_cli` executable directly from
//! a shell (`windbg_cli do --name <name> ...`). The debugger session lives
//! inside the daemon process — never inside this MCP server process — because a
//! dbgeng COM session cannot be shared across processes.
//!
//! The command catalog (extracted from `debugger.chm`) is still exposed as MCP
//! *resources* so an agent can look up command syntax.

use std::path::PathBuf;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, handler::server::common::schema_for_type,
    model::*, schemars::JsonSchema, service::RequestContext,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    catalog::{Catalog, CatalogResourceKind},
    daemon_launcher::{self, OpenSpec, TargetSpec},
    resources::{GUIDE_URI, render_compact_command, render_full_command, render_guide, render_help},
};

// ---------------------------------------------------------------------------
// Tool argument schemas.
// ---------------------------------------------------------------------------

/// Arguments for `windbg_open_session`.
///
/// Pick a `mode` and supply the matching fields:
/// - `launch` requires `command_line`
/// - `attach` requires `pid`
/// - `kernel` requires `connection`
#[derive(Debug, Deserialize, JsonSchema)]
struct OpenSessionArgs {
    /// Target kind: "launch" (spawn an exe), "attach" (attach to a PID), or
    /// "kernel" (KDNET-style connection string).
    mode: String,
    /// For `launch`: the executable path plus optional arguments, e.g.
    /// `C:\\path\\app.exe --flag`. The first whitespace token must be the exe.
    command_line: Option<String>,
    /// For `launch`: also debug child processes (default false).
    follow_children: Option<bool>,
    /// For `attach`: decimal process id to attach to.
    pid: Option<u32>,
    /// For `attach`: perform a non-invasive (read-only) attach.
    non_invasive: Option<bool>,
    /// For `kernel`: the `-k`-style connection string, e.g.
    /// `net:port=50000,key=...`.
    connection: Option<String>,
    /// Optional daemon name. When omitted, a unique `auto-<mode>-<rand>` name
    /// is generated. Reusing a live name returns the existing session.
    name: Option<String>,
    /// Optional debugger command run right after the initial break, e.g.
    /// `.symfix; .reload`.
    startup_command: Option<String>,
    /// Run `.symfix; .reload` automatically before user commands.
    symfix: Option<bool>,
    /// Maximum seconds to wait for the initial attach.
    attach_timeout_secs: Option<u64>,
    /// Maximum seconds to wait for the daemon to become connectable.
    ready_timeout_secs: Option<u64>,
}

/// Arguments for `windbg_close_session`.
#[derive(Debug, Deserialize, JsonSchema)]
struct CloseSessionArgs {
    /// Daemon name returned by `windbg_open_session`.
    name: String,
    /// When the daemon is registered but unreachable, force-kill its PID and
    /// clean up the stale registry entry.
    force: Option<bool>,
}

/// Arguments for `windbg_use_help`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
struct UseHelpArgs {
    /// Optional focus: "workflow", "open", "do", or "daemon". Omit for the
    /// full overview.
    topic: Option<String>,
}

// ---------------------------------------------------------------------------
// Server.
// ---------------------------------------------------------------------------

/// The thin MCP server. Holds only the path to the `windbg_cli` executable it
/// drives; it does not own any debugger session itself.
#[derive(Clone)]
pub struct WindbgMcpServer {
    cli_path: Option<PathBuf>,
}

impl Default for WindbgMcpServer {
    fn default() -> Self {
        Self::new(None)
    }
}

impl WindbgMcpServer {
    /// Create a server. `cli_path` overrides `windbg_cli` discovery; when
    /// `None`, the launcher falls back to `WINDBG_CLI_PATH`, the server's own
    /// directory, then `PATH`.
    pub fn new(cli_path: Option<PathBuf>) -> Self {
        Self { cli_path }
    }

    fn catalog(&self) -> &'static Catalog {
        Catalog::global()
    }

    fn parse_arguments<T>(&self, arguments: Option<JsonObject>) -> Result<T, McpError>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_value(Value::Object(arguments.unwrap_or_default()))
            .map_err(|error| McpError::invalid_params(error.to_string(), None))
    }

    // --- tool definitions -------------------------------------------------

    fn open_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_open_session",
            "Start (or idempotently reuse) a WinDbg debugger daemon for a target and return its daemon `name`. Use `mode`=\"launch\" (with `command_line`), \"attach\" (with `pid`), or \"kernel\" (with `connection`). After opening, run debugger actions from a shell: `windbg_cli do --name <name> <action>`. See `windbg_use_help`.",
            schema_for_type::<OpenSessionArgs>(),
        )
        .with_title("Open WinDbg session")
    }

    fn close_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_close_session",
            "Stop a WinDbg debugger daemon by `name`. Use `force`=true to kill an unreachable daemon and clean up its stale registry entry.",
            schema_for_type::<CloseSessionArgs>(),
        )
        .with_title("Close WinDbg session")
    }

    fn use_help_tool(&self) -> Tool {
        Tool::new(
            "windbg_use_help",
            "Return concise usage for this thin MCP server and the `windbg_cli` debugger CLI. Optional `topic`: \"workflow\", \"open\", \"do\", or \"daemon\". For exhaustive command flags, run `windbg_cli --help` and `windbg_cli do --help`.",
            schema_for_type::<UseHelpArgs>(),
        )
        .with_title("WinDbg usage help")
    }

    fn tools(&self) -> Vec<Tool> {
        vec![
            self.open_session_tool(),
            self.close_session_tool(),
            self.use_help_tool(),
        ]
    }

    // --- tool handlers ----------------------------------------------------

    fn open_session(&self, args: OpenSessionArgs) -> Result<Value, McpError> {
        let target = match args.mode.trim().to_ascii_lowercase().as_str() {
            "launch" => {
                let command_line = args.command_line.clone().filter(|s| !s.trim().is_empty());
                let command_line = command_line.ok_or_else(|| {
                    McpError::invalid_params(
                        "mode=launch requires `command_line`".to_string(),
                        None,
                    )
                })?;
                TargetSpec::Launch {
                    command_line,
                    follow_children: args.follow_children.unwrap_or(false),
                }
            }
            "attach" => {
                let pid = args.pid.ok_or_else(|| {
                    McpError::invalid_params("mode=attach requires `pid`".to_string(), None)
                })?;
                TargetSpec::Attach {
                    pid,
                    non_invasive: args.non_invasive.unwrap_or(false),
                }
            }
            "kernel" => {
                let connection = args.connection.clone().filter(|s| !s.trim().is_empty());
                let connection = connection.ok_or_else(|| {
                    McpError::invalid_params(
                        "mode=kernel requires `connection`".to_string(),
                        None,
                    )
                })?;
                TargetSpec::Kernel { connection }
            }
            other => {
                return Err(McpError::invalid_params(
                    format!("unknown mode `{other}` (expected launch/attach/kernel)"),
                    None,
                ));
            }
        };

        let cli = daemon_launcher::locate_cli(self.cli_path.as_deref())
            .map_err(|e| McpError::internal_error(e, None))?;

        let spec = OpenSpec {
            name: args.name.clone(),
            target,
            startup_command: args.startup_command.clone(),
            symfix: args.symfix.unwrap_or(false),
            attach_timeout_secs: args.attach_timeout_secs,
            ready_timeout_secs: args.ready_timeout_secs,
        };

        let entry = daemon_launcher::open_session(&cli, &spec)
            .map_err(|e| McpError::internal_error(e, None))?;

        Ok(json!({
            "name": entry.name,
            "address": entry.address,
            "pid": entry.pid,
            "target": entry.target_summary,
            "hint": format!(
                "Run debugger actions from a shell: windbg_cli do --name {} <action>. See windbg_use_help.",
                entry.name
            ),
        }))
    }

    fn close_session(&self, args: CloseSessionArgs) -> Result<Value, McpError> {
        let message = daemon_launcher::close_session(&args.name, args.force.unwrap_or(false))
            .map_err(|e| McpError::internal_error(e, None))?;
        Ok(json!({ "name": args.name, "message": message }))
    }

    fn use_help(&self, args: UseHelpArgs) -> Result<Value, McpError> {
        let text = render_help(self.catalog(), args.topic.as_deref());
        Ok(json!({ "help": text }))
    }
}

// ---------------------------------------------------------------------------
// ServerHandler.
// ---------------------------------------------------------------------------

impl ServerHandler for WindbgMcpServer {
    fn get_info(&self) -> ServerInfo {
        let instructions = "This MCP server exposes only three tools. Call `windbg_open_session` to start a debugger daemon for a target (launch/attach/kernel); it returns a daemon `name`. Then run all detailed debugger actions from a shell with `windbg_cli do --name <name> <action>` (bp, go, bt, mem, reg, step, dump, exec, ...). Call `windbg_close_session` when done. Call `windbg_use_help` for a usage overview, or run `windbg_cli --help`.";

        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_resources()
                .enable_tools()
                .build(),
        )
        .with_instructions(instructions)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: self.tools(),
            next_cursor: None,
            meta: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        match name {
            "windbg_open_session" => Some(self.open_session_tool()),
            "windbg_close_session" => Some(self.close_session_tool()),
            "windbg_use_help" => Some(self.use_help_tool()),
            _ => None,
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match request.name.as_ref() {
            "windbg_open_session" => {
                let args: OpenSessionArgs = self.parse_arguments(request.arguments)?;
                let payload = self.open_session(args)?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_close_session" => {
                let args: CloseSessionArgs = self.parse_arguments(request.arguments)?;
                let payload = self.close_session(args)?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_use_help" => {
                let args: UseHelpArgs = self.parse_arguments(request.arguments)?;
                let payload = self.use_help(args)?;
                Ok(CallToolResult::structured(payload))
            }
            other => Err(McpError::invalid_params(
                format!("unknown tool `{other}`"),
                None,
            )),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let guide = render_guide(self.catalog());

        Ok(ListResourcesResult {
            resources: vec![
                RawResource::new(GUIDE_URI, "windbg guide")
                    .with_title("WinDbg MCP guide")
                    .with_description(
                        "Overview of the thin MCP tools and the windbg_cli debugger CLI",
                    )
                    .with_mime_type("text/plain")
                    .with_size(guide.len() as u32)
                    .no_annotation(),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult {
            resource_templates: vec![
                RawResourceTemplate::new(
                    self.catalog().command_template_uri(),
                    "windbg compact command card",
                )
                .with_description("Compact syntax-first WinDbg command card by extracted catalog id")
                .with_mime_type("text/plain")
                .no_annotation(),
                RawResourceTemplate::new(
                    self.catalog().full_command_template_uri(),
                    "windbg full command page",
                )
                .with_description("Full extracted debugger command topic by extracted catalog id")
                .with_mime_type("text/plain")
                .no_annotation(),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        if request.uri == GUIDE_URI {
            return Ok(ReadResourceResult::new(vec![ResourceContents::text(
                render_guide(self.catalog()),
                request.uri,
            )]));
        }

        let (kind, entry) = self
            .catalog()
            .resolve_resource_uri(&request.uri)
            .ok_or_else(|| {
                McpError::resource_not_found(
                    "unknown_resource",
                    Some(json!({ "uri": request.uri })),
                )
            })?;
        let content = match kind {
            CatalogResourceKind::Compact => render_compact_command(entry),
            CatalogResourceKind::Full => render_full_command(entry),
        };

        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            content,
            request.uri,
        )]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_exposes_exactly_three_tools() {
        let server = WindbgMcpServer::new(None);
        let tools = server.tools();
        assert_eq!(tools.len(), 3);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(names.contains(&"windbg_open_session"));
        assert!(names.contains(&"windbg_close_session"));
        assert!(names.contains(&"windbg_use_help"));
    }

    #[test]
    fn get_tool_matches_list_tools() {
        let server = WindbgMcpServer::new(None);
        for tool in server.tools() {
            let fetched = server.get_tool(tool.name.as_ref());
            assert!(fetched.is_some(), "get_tool missing {}", tool.name);
            assert_eq!(fetched.unwrap().name, tool.name);
        }
        assert!(server.get_tool("windbg_execute_command").is_none());
    }

    #[test]
    fn open_session_rejects_missing_target_fields() {
        let server = WindbgMcpServer::new(None);
        let args = OpenSessionArgs {
            mode: "launch".to_string(),
            command_line: None,
            follow_children: None,
            pid: None,
            non_invasive: None,
            connection: None,
            name: None,
            startup_command: None,
            symfix: None,
            attach_timeout_secs: None,
            ready_timeout_secs: None,
        };
        assert!(server.open_session(args).is_err());
    }

    #[test]
    fn use_help_text_has_no_deleted_tool_names() {
        let server = WindbgMcpServer::new(None);
        let payload = server.use_help(UseHelpArgs::default()).expect("help");
        let text = payload["help"].as_str().unwrap_or_default();
        assert!(!text.contains("windbg_execute_command"));
        assert!(!text.contains("windbg_set_breakpoint"));
        assert!(text.contains("windbg_open_session"));
    }
}
