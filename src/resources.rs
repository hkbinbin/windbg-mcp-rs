use crate::catalog::{Catalog, CatalogEntry, ToolRouting};

pub const GUIDE_URI: &str = "windbg://guide/overview";

/// Render the overview guide for the thin MCP server.
///
/// The MCP surface is intentionally tiny — only `windbg_open_session`,
/// `windbg_close_session`, and `windbg_use_help`. All detailed debugging is
/// driven by the `windbg_cli` executable, which the agent runs directly from a
/// shell. This guide explains that split and points at `windbg_cli --help`.
pub fn render_guide(catalog: &Catalog) -> String {
    render_help(catalog, None)
}

/// Render help text, optionally focused on a single `topic`.
///
/// Supported topics: `workflow`, `open`, `do`, `daemon`. Any other value (or
/// `None`) yields the full overview.
pub fn render_help(catalog: &Catalog, topic: Option<&str>) -> String {
    let mut out = String::new();

    match topic {
        Some("open") => {
            out.push_str(&section_open());
        }
        Some("do") => {
            out.push_str(&section_do());
        }
        Some("daemon") => {
            out.push_str(&section_daemon());
        }
        Some("workflow") => {
            out.push_str(&section_workflow());
        }
        _ => {
            out.push_str("WinDbg MCP — thin server overview\n");
            out.push_str("=================================\n\n");
            out.push_str(
                "This MCP server exposes only three tools. Heavy debugging is done by\n\
                 running the `windbg_cli` executable directly from a shell, which keeps the\n\
                 MCP tool surface small while preserving full capability.\n\n",
            );
            out.push_str("MCP tools\n---------\n");
            out.push_str("- windbg_open_session  : start (or reuse) a debugger daemon for a target\n");
            out.push_str("- windbg_close_session : stop a debugger daemon\n");
            out.push_str("- windbg_use_help      : this help (optional `topic`)\n\n");
            out.push_str(&section_workflow());
            out.push('\n');
            out.push_str(&section_open());
            out.push('\n');
            out.push_str(&section_do());
            out.push('\n');
            out.push_str(&section_daemon());
            out.push('\n');
            out.push_str("Catalog search\n--------------\n");
            out.push_str(&format!(
                "- Command catalog is still available as resources: {}\n",
                catalog.command_template_uri()
            ));
            out.push_str(&format!("- Guide resource: {}\n", GUIDE_URI));
        }
    }

    out
}

fn section_workflow() -> String {
    let mut s = String::new();
    s.push_str("Workflow\n--------\n");
    s.push_str("1. Call `windbg_open_session` with a target (launch/attach/kernel). It returns\n");
    s.push_str("   a daemon `name` (and loopback address) that owns the live session.\n");
    s.push_str("2. Run debugger actions from a shell against that daemon:\n");
    s.push_str("     windbg_cli do --name <name> <action> [args]\n");
    s.push_str("   e.g. `windbg_cli do --name <name> bp nt!NtCreateFile`,\n");
    s.push_str("        `windbg_cli do --name <name> go`, `windbg_cli do --name <name> bt`.\n");
    s.push_str("3. Call `windbg_close_session` with the same `name` when finished.\n");
    s.push_str("For the full action list run: `windbg_cli do --help`.\n");
    s
}

fn section_open() -> String {
    let mut s = String::new();
    s.push_str("Opening a session (windbg_open_session)\n");
    s.push_str("---------------------------------------\n");
    s.push_str("mode = \"launch\" : spawn a user-mode exe   (command_line, follow_children?)\n");
    s.push_str("mode = \"attach\" : attach to a PID         (pid, non_invasive?)\n");
    s.push_str("mode = \"kernel\" : KDNET-style connection  (connection)\n");
    s.push_str("Optional: name, startup_command, symfix, attach_timeout_secs, ready_timeout_secs.\n");
    s.push_str("Omitting `name` generates a unique daemon name; reusing a live name is idempotent.\n");
    s
}

fn section_do() -> String {
    let mut s = String::new();
    s.push_str("Running debugger commands (shell, not MCP)\n");
    s.push_str("------------------------------------------\n");
    s.push_str("Use the CLI directly: `windbg_cli do --name <name> <action>`. Actions include:\n");
    s.push_str("  state | go | interrupt | wait-break | step | step-over | step-out | step-until\n");
    s.push_str("  bp | ba | bc | bl | reg | mem | dis | bt | snapshot | dump | exec | info\n");
    s.push_str("`exec` runs a raw WinDbg command, e.g. `windbg_cli do --name <name> exec \"u @rip L8\"`.\n");
    s.push_str("Run `windbg_cli do --help` for exact flags of each action.\n");
    s
}

fn section_daemon() -> String {
    let mut s = String::new();
    s.push_str("windbg_cli top-level commands\n");
    s.push_str("-----------------------------\n");
    s.push_str("- daemon start|stop|status|list : manage persistent debugger daemons\n");
    s.push_str("- do <action>                   : send one action to a running daemon\n");
    s.push_str("- kernel <connection>           : one-shot kernel session (no daemon)\n");
    s.push_str("- list-tools                    : print legacy tool name listing\n");
    s.push_str("Run `windbg_cli --help` for the complete CLI reference.\n");
    s
}

pub fn render_compact_command(entry: &CatalogEntry) -> String {
    let mut output = String::new();
    output.push_str(&format!("Title: {}\n", entry.title));
    output.push_str(&format!("Catalog Id: {}\n", entry.id));
    output.push_str(&format!("Tokens: {}\n", entry.tokens.join(", ")));
    output.push_str(&format!("Summary: {}\n", entry.summary));
    output.push_str(&format!(
        "Tool Route: {}\n",
        tool_route_label(entry.tool_routing())
    ));

    match entry.recommended_tool() {
        Some(tool) => output.push_str(&format!("Recommended Tool: {}\n", tool)),
        None => output.push_str("Recommended Tool: documentation only\n"),
    }

    output.push_str(&format!("Full Resource: {}\n", entry.full_resource_uri()));

    if let Some(syntax) = entry.syntax_block() {
        output.push_str("\nSyntax\n------\n");
        output.push_str(&syntax);
        output.push('\n');
    }

    output.push_str("\nNext Step\n---------\n");
    match entry.tool_routing() {
        ToolRouting::ExecuteCommand => output.push_str(
            "Build the final WinDbg command string from the syntax above and run it against a daemon: `windbg_cli do --name <name> exec \"<command>\"`. Check state first with `windbg_cli do --name <name> state`.\n",
        ),
        ToolRouting::InterruptTarget => output.push_str(
            "This topic maps to an engine-level break action. Use `windbg_cli do --name <name> interrupt` instead of a raw command.\n",
        ),
        ToolRouting::DocumentationOnly => output.push_str(
            "This topic is documentation-only because it describes a UI shortcut or non-text action.\n",
        ),
    }

    output
}

pub fn render_full_command(entry: &CatalogEntry) -> String {
    let mut output = render_compact_command(entry);
    output.push_str("\nDocumentation\n-------------\n");
    output.push_str(&entry.documentation);
    output
}

fn tool_route_label(route: ToolRouting) -> &'static str {
    match route {
        ToolRouting::ExecuteCommand => "execute_command",
        ToolRouting::InterruptTarget => "interrupt_target",
        ToolRouting::DocumentationOnly => "documentation_only",
    }
}
