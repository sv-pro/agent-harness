use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParam, CallToolResult, Content, Implementation, ListToolsResult,
    PaginatedRequestParam, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
    ToolsCapability,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{Error as McpError, ServerHandler};

use crate::policy::WorldConfig;
use crate::session::WorldSession;

/// Thin MCP adapter: all policy, taint, and execution logic lives in
/// WorldSession; this type only translates between rmcp and the session.
#[derive(Clone)]
pub struct HarnessServer {
    session: Arc<WorldSession>,
}

impl HarnessServer {
    pub fn new(config: WorldConfig) -> anyhow::Result<Self> {
        Ok(Self {
            session: Arc::new(WorldSession::new(config)?),
        })
    }
}

impl ServerHandler for HarnessServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(true),
                }),
                ..Default::default()
            },
            server_info: Implementation {
                name: "agent-harness".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(format!(
                "Agent harness for world '{}'. We do not make agents safe; we make the \
                 world they live in safe. You MUST call set_task before any other tool — \
                 until then no other tool exists. After set_task, re-list tools: the \
                 listing is filtered to the active task. Available tasks: {}.",
                self.session.world_name(),
                self.session.task_names().join(", "),
            )),
        }
    }

    async fn list_tools(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        // Stage 1 — ABSENT semantics: the listing reflects the active task.
        let tools = self
            .session
            .visible_specs()
            .into_iter()
            .map(|spec| Tool {
                name: Cow::Borrowed(spec.name),
                description: Cow::Borrowed(spec.description),
                input_schema: Arc::new(
                    spec.schema
                        .as_object()
                        .expect("tool schemas are JSON objects")
                        .clone(),
                ),
            })
            .collect();
        Ok(ListToolsResult {
            next_cursor: None,
            tools,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = request.name.to_string();
        let args = request.arguments.unwrap_or_default();
        let is_set_task = tool_name == "set_task";

        // Session execution is blocking (fs/process I/O) and serialized
        // under the session lock.
        let session = Arc::clone(&self.session);
        let outcome = tokio::task::spawn_blocking(move || session.call(&tool_name, &args))
            .await
            .map_err(|e| McpError::internal_error(format!("tool task panicked: {e}"), None))?;

        // The visible tool set changes when the task changes.
        if is_set_task && !outcome.is_error {
            let _ = context.peer.notify_tool_list_changed().await;
        }

        Ok(if outcome.is_error {
            CallToolResult::error(vec![Content::text(outcome.text)])
        } else {
            CallToolResult::success(vec![Content::text(outcome.text)])
        })
    }
}
