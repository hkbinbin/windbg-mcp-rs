use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, handler::server::common::schema_for_type,
    model::*, schemars::JsonSchema, service::RequestContext,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    catalog::{Catalog, CatalogEntry, CatalogResourceKind, CatalogSection},
    executor::{CommandDispatcher, ExecutionError},
    resources::{GUIDE_URI, render_compact_command, render_full_command, render_guide},
    session_manager::HeadlessSessionManager,
};

#[cfg(test)]
use crate::executor::build_command;

#[derive(Debug, Deserialize, JsonSchema)]
struct ExecuteRawArgs {
    command: String,
    session_id: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct InterruptTargetArgs {
    session_id: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ResumeTargetArgs {
    session_id: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct GetExecutionStateArgs {
    session_id: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct GetOutputArgs {
    session_id: Option<String>,
    cursor: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchCatalogArgs {
    query: String,
    section: Option<CatalogSection>,
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct OpenSessionArgs {
    connection: String,
    session_id: Option<String>,
    startup_command: Option<String>,
    attach_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CloseSessionArgs {
    session_id: String,
    shutdown_timeout_secs: Option<u64>,
    resume_before_close: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SwitchSessionArgs {
    session_id: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ListSessionsArgs {}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct CurrentSessionArgs {}

#[derive(Clone)]
enum ServerBackend {
    AttachedSession { dispatcher: CommandDispatcher },
    Headless { sessions: HeadlessSessionManager },
}

#[derive(Clone)]
pub struct WindbgMcpServer {
    backend: ServerBackend,
}

impl WindbgMcpServer {
    pub fn new(dispatcher: CommandDispatcher) -> Self {
        Self {
            backend: ServerBackend::AttachedSession { dispatcher },
        }
    }

    pub fn headless(sessions: HeadlessSessionManager) -> Self {
        Self {
            backend: ServerBackend::Headless { sessions },
        }
    }

    fn is_headless(&self) -> bool {
        matches!(self.backend, ServerBackend::Headless { .. })
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

    fn generic_command_tool(&self) -> Tool {
        Tool::new(
            "windbg_execute_command",
            "Execute a WinDbg command string through dbgeng. Query state first and interrupt explicitly when needed. In headless mode, `session_id` routes the call to a specific attached session.",
            schema_for_type::<ExecuteRawArgs>(),
        )
        .with_title("Execute WinDbg command")
    }

    fn state_tool(&self) -> Tool {
        Tool::new(
            "windbg_get_execution_state",
            "Query the current debugger execution state before deciding whether to interrupt, resume, or execute a command. In headless mode, `session_id` routes the call to a specific session.",
            schema_for_type::<GetExecutionStateArgs>(),
        )
        .with_title("Get debugger execution state")
    }

    fn output_tool(&self) -> Tool {
        Tool::new(
            "windbg_get_output",
            "Read the buffered debugger command output history for the current session. Pass the last returned `next_cursor` to fetch only newer entries. In headless mode, `session_id` routes the call to a specific session.",
            schema_for_type::<GetOutputArgs>(),
        )
        .with_title("Get debugger output")
    }

    fn interrupt_tool(&self) -> Tool {
        Tool::new(
            "windbg_interrupt_target",
            "Request a debugger break into the currently running target and wait until debugger commands are accepted again. In headless mode, `session_id` routes the call to a specific session.",
            schema_for_type::<InterruptTargetArgs>(),
        )
        .with_title("Interrupt running target")
    }

    fn resume_tool(&self) -> Tool {
        Tool::new(
            "windbg_resume_target",
            "Resume the current target without issuing a text command. This is the safe headless equivalent of continuing execution after an initial break. In headless mode, `session_id` routes the call to a specific session.",
            schema_for_type::<ResumeTargetArgs>(),
        )
        .with_title("Resume target")
    }

    fn search_tool(&self) -> Tool {
        Tool::new(
            "windbg_search_catalog",
            "Search the static debugger command catalog extracted from debugger.chm and return the best low-context resources to read before execution.",
            schema_for_type::<SearchCatalogArgs>(),
        )
        .with_title("Search WinDbg catalog")
    }

    fn open_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_open_session",
            "Open a headless kernel-debug session using the same connection options you would pass to `-k`, for example `net:port=50000,key=...`. Full launcher strings like `windbgx -k net:...` are also accepted.",
            schema_for_type::<OpenSessionArgs>(),
        )
        .with_title("Open headless session")
    }

    fn close_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_close_session",
            "Close a headless debugger session and detach the owned dbgeng client from the target. By default this tries to resume a broken target before closing; set `resume_before_close` to false to skip that. `shutdown_timeout_secs` bounds teardown so a live KDNET detach cannot hang the MCP server indefinitely.",
            schema_for_type::<CloseSessionArgs>(),
        )
        .with_title("Close headless session")
    }

    fn switch_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_switch_session",
            "Set the default headless session used when `session_id` is omitted from tool calls.",
            schema_for_type::<SwitchSessionArgs>(),
        )
        .with_title("Switch default session")
    }

    fn list_sessions_tool(&self) -> Tool {
        Tool::new(
            "windbg_list_sessions",
            "List all headless debugger sessions managed by this MCP server.",
            schema_for_type::<ListSessionsArgs>(),
        )
        .with_title("List headless sessions")
    }

    fn current_session_tool(&self) -> Tool {
        Tool::new(
            "windbg_current_session",
            "Show the current default headless debugger session.",
            schema_for_type::<CurrentSessionArgs>(),
        )
        .with_title("Get current headless session")
    }

    fn syntax_preview(&self, entry: &CatalogEntry) -> Option<String> {
        let syntax = entry.syntax_block()?;
        let syntax = syntax.trim();
        if syntax.is_empty() {
            return None;
        }

        let preview = syntax
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or(syntax);
        let preview = preview.trim();
        if preview.len() <= 160 {
            Some(preview.to_string())
        } else {
            Some(format!("{}...", &preview[..157]))
        }
    }

    fn base_tools(&self) -> Vec<Tool> {
        vec![
            self.generic_command_tool(),
            self.state_tool(),
            self.output_tool(),
            self.search_tool(),
            self.interrupt_tool(),
            self.resume_tool(),
        ]
    }

    fn management_tools(&self) -> Vec<Tool> {
        if !self.is_headless() {
            return Vec::new();
        }

        vec![
            self.open_session_tool(),
            self.close_session_tool(),
            self.switch_session_tool(),
            self.list_sessions_tool(),
            self.current_session_tool(),
        ]
    }

    fn map_execution_error(error: ExecutionError) -> McpError {
        match error {
            ExecutionError::Session(_) | ExecutionError::InvalidVariant { .. } => {
                McpError::invalid_params(error.to_string(), None)
            }
            _ => McpError::internal_error(error.to_string(), None),
        }
    }

    async fn execute_command(
        &self,
        session_id: Option<&str>,
        command: String,
    ) -> Result<Value, McpError> {
        let execution = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .execute(command.clone())
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .execute_command(session_id, command.clone())
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(json!({
            "command": execution.command,
            "output": execution.output,
            "state_before": execution.state_before,
            "state_after": execution.state_after,
        }))
    }

    async fn query_state(&self, session_id: Option<&str>) -> Result<Value, McpError> {
        let state = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .query_state()
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .query_state(session_id)
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(json!({ "state": state }))
    }

    async fn get_output(
        &self,
        session_id: Option<&str>,
        cursor: Option<u64>,
    ) -> Result<Value, McpError> {
        let snapshot = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .get_output(cursor)
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .get_output(session_id, cursor)
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(json!({
            "entries": snapshot.entries,
            "history_start_cursor": snapshot.history_start_cursor,
            "next_cursor": snapshot.next_cursor,
        }))
    }

    async fn interrupt_target(&self, session_id: Option<&str>) -> Result<Value, McpError> {
        let state = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .interrupt()
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .interrupt(session_id)
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(json!({ "state": state }))
    }

    async fn resume_target(&self, session_id: Option<&str>) -> Result<Value, McpError> {
        let state = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .resume()
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { sessions } => sessions
                .resume(session_id)
                .await
                .map_err(Self::map_execution_error)?,
        };

        Ok(json!({ "state": state }))
    }

    #[cfg(test)]
    async fn run_entry_tool(
        &self,
        entry: &CatalogEntry,
        variant: Option<&str>,
        arguments: Option<&str>,
    ) -> Result<CallToolResult, McpError> {
        if !entry.supports_text_execution {
            let content = format!(
                "{} is documented as a keyboard action or non-text entry and cannot be executed as a raw debugger command string. Read {} for the official documentation.",
                entry.title,
                entry.resource_uri()
            );
            return Ok(CallToolResult::error(vec![Content::text(content)]));
        }

        let command = build_command(entry, variant, arguments)
            .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
        let execution = match &self.backend {
            ServerBackend::AttachedSession { dispatcher } => dispatcher
                .execute(command.clone())
                .await
                .map_err(Self::map_execution_error)?,
            ServerBackend::Headless { .. } => {
                return Err(McpError::internal_error(
                    "test-only helper is only implemented for attached-session mode",
                    None,
                ));
            }
        };

        Ok(CallToolResult::structured(json!({
            "entry_id": entry.id,
            "title": entry.title,
            "command": command,
            "output": execution.output,
            "state_before": execution.state_before,
            "state_after": execution.state_after,
        })))
    }
}

impl ServerHandler for WindbgMcpServer {
    fn get_info(&self) -> ServerInfo {
        let instructions = if self.is_headless() {
            "Open a session with `windbg_open_session` before using debugger actions. Then call `windbg_search_catalog`, read `windbg://command/{id}`, call `windbg_get_execution_state`, interrupt if needed, and only then call `windbg_execute_command`. Use `windbg_get_output` with the returned cursor to fetch buffered command output incrementally. Use `windbg_resume_target` to continue a live target without blocking on a raw `g` command. When multiple sessions are open, pass `session_id` or set a default with `windbg_switch_session`."
        } else {
            "This server is organized around low-context resources plus a small toolset. Start with `windbg_search_catalog`, read `windbg://command/{id}`, optionally escalate to `windbg://command-full/{id}`, then call `windbg_get_execution_state`. If the debugger is running or busy, call `windbg_interrupt_target` and verify state again before calling `windbg_execute_command`. Use `windbg_get_output` to read buffered command output again later, and `windbg_resume_target` to continue execution without issuing a raw `g` command."
        };

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
        let mut tools = self.management_tools();
        tools.extend(self.base_tools());

        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        match name {
            "windbg_execute_command" => Some(self.generic_command_tool()),
            "windbg_get_execution_state" => Some(self.state_tool()),
            "windbg_get_output" => Some(self.output_tool()),
            "windbg_search_catalog" => Some(self.search_tool()),
            "windbg_interrupt_target" => Some(self.interrupt_tool()),
            "windbg_resume_target" => Some(self.resume_tool()),
            "windbg_open_session" if self.is_headless() => Some(self.open_session_tool()),
            "windbg_close_session" if self.is_headless() => Some(self.close_session_tool()),
            "windbg_switch_session" if self.is_headless() => Some(self.switch_session_tool()),
            "windbg_list_sessions" if self.is_headless() => Some(self.list_sessions_tool()),
            "windbg_current_session" if self.is_headless() => Some(self.current_session_tool()),
            _ => None,
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        match request.name.as_ref() {
            "windbg_execute_command" => {
                let args: ExecuteRawArgs = self.parse_arguments(request.arguments)?;
                let payload = self
                    .execute_command(args.session_id.as_deref(), args.command)
                    .await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_get_execution_state" => {
                let args: GetExecutionStateArgs = self.parse_arguments(request.arguments)?;
                let payload = self.query_state(args.session_id.as_deref()).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_get_output" => {
                let args: GetOutputArgs = self.parse_arguments(request.arguments)?;
                let payload = self
                    .get_output(args.session_id.as_deref(), args.cursor)
                    .await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_search_catalog" => {
                let args: SearchCatalogArgs = self.parse_arguments(request.arguments)?;
                let limit = args.limit.unwrap_or(10).clamp(1, 100) as usize;
                let matches = self.catalog().search(&args.query, args.section, limit);
                let payload: Vec<Value> = matches
                    .into_iter()
                    .map(|entry| {
                        json!({
                            "id": entry.id,
                            "primary_token": entry.primary_token(),
                            "title": entry.title,
                            "tokens": entry.tokens,
                            "summary": entry.summary,
                            "supports_text_execution": entry.supports_text_execution,
                            "syntax_preview": self.syntax_preview(entry),
                            "resource": entry.resource_uri(),
                            "full_resource": entry.full_resource_uri(),
                            "routing": entry.tool_routing_name(),
                            "recommended_tool": entry.recommended_tool(),
                            "execution_state_tool": "windbg_get_execution_state",
                            "resume_tool": "windbg_resume_target"
                        })
                    })
                    .collect();
                Ok(CallToolResult::structured(json!({
                    "query": args.query,
                    "recommended_flow": [
                        "call windbg_search_catalog",
                        "read the compact resource for the best match",
                        "read the full resource only if needed",
                        "call windbg_get_execution_state",
                        "if needed, call windbg_interrupt_target and verify state again",
                        "call windbg_execute_command or another recommended tool"
                    ],
                    "matches": payload,
                })))
            }
            "windbg_interrupt_target" => {
                let args: InterruptTargetArgs = self.parse_arguments(request.arguments)?;
                let payload = self.interrupt_target(args.session_id.as_deref()).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_resume_target" => {
                let args: ResumeTargetArgs = self.parse_arguments(request.arguments)?;
                let payload = self.resume_target(args.session_id.as_deref()).await?;
                Ok(CallToolResult::structured(payload))
            }
            "windbg_open_session" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let args: OpenSessionArgs = self.parse_arguments(request.arguments)?;
                let session = sessions
                    .open_kernel_session(
                        &args.connection,
                        args.session_id.as_deref(),
                        args.startup_command.as_deref(),
                        args.attach_timeout_secs,
                    )
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!({
                    "session": session
                })))
            }
            "windbg_close_session" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let args: CloseSessionArgs = self.parse_arguments(request.arguments)?;
                let result = sessions
                    .close_session(
                        &args.session_id,
                        args.shutdown_timeout_secs,
                        args.resume_before_close,
                    )
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!(result)))
            }
            "windbg_switch_session" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let args: SwitchSessionArgs = self.parse_arguments(request.arguments)?;
                let session = sessions
                    .switch_session(&args.session_id)
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!({
                    "session": session
                })))
            }
            "windbg_list_sessions" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let _: ListSessionsArgs = self.parse_arguments(request.arguments)?;
                let payload = sessions
                    .list_sessions()
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!(payload)))
            }
            "windbg_current_session" => {
                let ServerBackend::Headless { sessions } = &self.backend else {
                    return Err(McpError::method_not_found::<CallToolRequestMethod>());
                };
                let _: CurrentSessionArgs = self.parse_arguments(request.arguments)?;
                let payload = sessions
                    .current_session()
                    .await
                    .map_err(Self::map_execution_error)?;
                Ok(CallToolResult::structured(json!({
                    "session": payload
                })))
            }
            _ => Err(McpError::method_not_found::<CallToolRequestMethod>()),
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
                        "Low-context workflow for mapping debugger requests to resources and tools",
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
                .with_description(
                    "Compact syntax-first WinDbg command card by extracted catalog id",
                )
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
    use std::collections::HashMap;

    use super::*;
    use crate::executor::ExecutionMode;

    #[tokio::test]
    async fn command_tool_uses_mock_dispatcher() {
        let mut responses = HashMap::new();
        responses.insert(
            "dt _PEB_LDR_DATA".to_string(),
            "ntdll!_PEB_LDR_DATA".to_string(),
        );
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock { responses })
            .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);
        let entry = server
            .catalog()
            .lookup("dt")
            .expect("dt entry should exist");

        let result = server
            .run_entry_tool(entry, None, Some("_PEB_LDR_DATA"))
            .await
            .expect("tool should succeed");

        let payload = result
            .structured_content
            .expect("structured payload expected");
        assert_eq!(payload["command"], "dt _PEB_LDR_DATA");
        assert_eq!(payload["output"], "ntdll!_PEB_LDR_DATA");
    }

    #[test]
    fn interrupt_tool_is_exposed() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);

        let tool = server
            .get_tool("windbg_interrupt_target")
            .expect("interrupt tool should be listed");
        assert_eq!(tool.name, "windbg_interrupt_target");
    }

    #[test]
    fn resume_tool_is_exposed() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);

        let tool = server
            .get_tool("windbg_resume_target")
            .expect("resume tool should be listed");
        assert_eq!(tool.name, "windbg_resume_target");
    }

    #[test]
    fn command_tool_is_exposed() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);

        let tool = server
            .get_tool("windbg_execute_command")
            .expect("command tool should be listed");
        assert_eq!(tool.name, "windbg_execute_command");
    }

    #[test]
    fn state_tool_is_exposed() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);

        let tool = server
            .get_tool("windbg_get_execution_state")
            .expect("state tool should be listed");
        assert_eq!(tool.name, "windbg_get_execution_state");
    }

    #[test]
    fn compact_resource_stays_small_and_points_to_full_doc() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);
        let entry = server
            .catalog()
            .lookup("bp")
            .expect("bp entry should exist");

        let resource = render_compact_command(entry);
        assert!(resource.contains("Syntax"));
        assert!(resource.contains("windbg://command-full/bp_bu_bm_set_breakpoint"));
        assert!(resource.contains("Next Step"));
    }

    #[test]
    fn syntax_preview_uses_inferred_syntax_when_structured_syntax_is_missing() {
        let dispatcher = CommandDispatcher::spawn(ExecutionMode::Mock {
            responses: HashMap::new(),
        })
        .expect("dispatcher should start");
        let server = WindbgMcpServer::new(dispatcher);
        let entry = server
            .catalog()
            .lookup("bp")
            .expect("bp entry should exist");

        let preview = server.syntax_preview(entry).expect("preview should exist");
        assert!(preview.contains("User-Mode"));
    }
}
