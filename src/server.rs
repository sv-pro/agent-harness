use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use rmcp::model::{
    CallToolRequestParam, CallToolResult, Content, Implementation, ListToolsResult,
    PaginatedRequestParam, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{Error as McpError, ServerHandler};

use crate::policy::{PolicyEngine, WorldConfig};
use crate::registry::ToolRegistry;

#[derive(Default)]
struct SessionState {
    active_task: Option<String>,
    steps_taken: u32,
}

#[derive(Clone)]
pub struct HarnessServer {
    config: Arc<WorldConfig>,
    base_dir: PathBuf,
    policy: Arc<PolicyEngine>,
    registry: Arc<ToolRegistry>,
    state: Arc<Mutex<SessionState>>,
}

impl HarnessServer {
    pub fn new(config: WorldConfig) -> anyhow::Result<Self> {
        let base_dir = PathBuf::from(&config.world.working_dir)
            .canonicalize()
            .with_context(|| {
                format!("working_dir does not exist: {}", config.world.working_dir)
            })?;
        Ok(Self {
            config: Arc::new(config),
            policy: Arc::new(PolicyEngine::new(base_dir.clone())),
            base_dir,
            registry: Arc::new(ToolRegistry::new()),
            state: Arc::new(Mutex::new(SessionState::default())),
        })
    }

    fn set_task(&self, args: &serde_json::Map<String, serde_json::Value>) -> CallToolResult {
        let Some(task_name) = args.get("task").and_then(serde_json::Value::as_str) else {
            return error_result("set_task requires a 'task' argument".to_string());
        };
        let Some(task) = self.config.tasks.get(task_name) else {
            return error_result(format!(
                "unknown task '{task_name}'. Available tasks: {}",
                self.config
                    .tasks
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        };

        let mut state = self.state.lock().unwrap();
        state.active_task = Some(task_name.to_string());
        state.steps_taken = 0;

        tracing::info!(task = task_name, "active task set");
        CallToolResult::success(vec![Content::text(format!(
            "Active task: {task_name}\nDescription: {}\nAllowed tools: {}\n\
             allow_write: {} | paths_whitelist: [{}] | max_steps: {}",
            task.description,
            task.tools.join(", "),
            task.policy.allow_write,
            task.policy.paths_whitelist.join(", "),
            task.policy.max_steps,
        ))])
    }
}

fn error_result(message: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(message)])
}

impl ServerHandler for HarnessServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities {
                tools: Some(Default::default()),
                ..Default::default()
            },
            server_info: Implementation {
                name: "agent-harness".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(format!(
                "Agent harness for world '{}'. We do not make agents safe; we make the \
                 world they live in safe. You MUST call set_task before any other tool. \
                 Available tasks: {}.",
                self.config.world.name,
                self.config.tasks.keys().cloned().collect::<Vec<_>>().join(", "),
            )),
        }
    }

    async fn list_tools(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools = self
            .registry
            .specs()
            .iter()
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
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = request.name.to_string();
        let args = request.arguments.unwrap_or_default();

        // set_task is the meta-tool: it bypasses policy entirely.
        if tool_name == "set_task" {
            return Ok(self.set_task(&args));
        }

        // Policy gate — every rule is enforced here, before execution.
        {
            let mut state = self.state.lock().unwrap();

            // Rule 1: a task must be active.
            let Some(task_name) = state.active_task.clone() else {
                return Ok(error_result(
                    "policy violation: no active task. Call set_task first.".to_string(),
                ));
            };
            let task = self
                .config
                .tasks
                .get(&task_name)
                .expect("active task always exists in config");

            // Rules 2–6.
            match self
                .policy
                .check(&task_name, task, state.steps_taken, &tool_name, &args)
            {
                Ok(verdict) => {
                    if verdict.needs_approval {
                        // Rule 6: auto-approve in dev mode, but make it visible.
                        tracing::warn!(
                            tool = %tool_name,
                            task = %task_name,
                            "tool requires approval — auto-approved (dev mode)"
                        );
                    }
                }
                Err(reason) => {
                    tracing::warn!(tool = %tool_name, task = %task_name, %reason, "rejected");
                    return Ok(error_result(reason));
                }
            }

            state.steps_taken += 1;
            tracing::info!(
                tool = %tool_name,
                task = %task_name,
                step = state.steps_taken,
                max = task.policy.max_steps,
                "executing"
            );
        }

        // Execute outside the state lock; tool bodies are blocking I/O.
        let registry = Arc::clone(&self.registry);
        let base_dir = self.base_dir.clone();
        let result = tokio::task::spawn_blocking(move || {
            registry.execute(&tool_name, &base_dir, &args)
        })
        .await
        .map_err(|e| McpError::internal_error(format!("tool task panicked: {e}"), None))?;

        Ok(match result {
            Ok(output) => CallToolResult::success(vec![Content::text(output)]),
            Err(e) => error_result(format!("tool error: {e:#}")),
        })
    }
}
