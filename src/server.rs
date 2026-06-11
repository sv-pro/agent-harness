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

use crate::policy::{Escalation, PolicyEngine, SideEffectType, Verdict, WorldConfig};
use crate::registry::ToolRegistry;
use crate::session::SessionState;
use crate::taint::TaintLedger;

#[derive(Clone)]
pub struct HarnessServer {
    config: Arc<WorldConfig>,
    base_dir: PathBuf,
    policy: Arc<PolicyEngine>,
    registry: Arc<ToolRegistry>,
    ledger: Arc<TaintLedger>,
    state: Arc<Mutex<SessionState>>,
}

impl HarnessServer {
    pub fn new(config: WorldConfig) -> anyhow::Result<Self> {
        let base_dir = PathBuf::from(&config.world.working_dir)
            .canonicalize()
            .with_context(|| {
                format!("working_dir does not exist: {}", config.world.working_dir)
            })?;
        let ledger = TaintLedger::load(
            base_dir.join(".harness").join("taint_ledger.json"),
            base_dir.clone(),
        );
        Ok(Self {
            config: Arc::new(config),
            policy: Arc::new(PolicyEngine::new(base_dir.clone())),
            base_dir,
            registry: Arc::new(ToolRegistry::new()),
            ledger: Arc::new(ledger),
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
        // reset_task resets the step budget but deliberately preserves taint
        // (see session.rs for the laundering-hole rationale).
        state.reset_task(task_name.to_string());
        let tainted = state.tainted;
        drop(state);

        tracing::info!(task = task_name, tainted, "active task set");
        CallToolResult::success(vec![Content::text(format!(
            "Active task: {task_name}\nDescription: {}\nAllowed tools: {}\n\
             allow_write: {} | paths_whitelist: [{}] | max_steps: {} | escalation: {:?}\n\
             session tainted: {tainted}",
            task.description,
            task.tools.join(", "),
            task.policy.allow_write,
            task.policy.paths_whitelist.join(", "),
            task.policy.max_steps,
            task.policy.escalation,
        ))])
    }

    /// Update taint provenance after a tool has successfully executed.
    /// Persistent writes extend the ledger; reads that touch agent-written
    /// paths taint the session.
    fn record_effect(&self, side_effect: SideEffectType, path_arg: Option<&str>) {
        match side_effect {
            SideEffectType::PersistentWrite => {
                if let Some(p) = path_arg {
                    self.ledger.mark_written(&self.policy.resolve(p));
                }
            }
            SideEffectType::Read => {
                if let Some(p) = path_arg {
                    let abs = self.policy.resolve(p);
                    if self.ledger.taints_read(&abs) {
                        let mut state = self.state.lock().unwrap();
                        state.mark_tainted(p.to_string());
                        tracing::warn!(source = %p, "session tainted: read agent-written content");
                    }
                }
            }
            SideEffectType::Execute => {}
        }
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
        // ABSENT semantics (Stage 1): the listing is filtered by the active
        // task. Reading active_task does NOT consume a step, so re-listing is
        // free and stays consistent with the step counter.
        let active = self.state.lock().unwrap().active_task.clone();
        let task = active.as_deref().and_then(|t| self.config.tasks.get(t));
        let visible = self.registry.visible_names(task);

        let tools = self
            .registry
            .specs()
            .iter()
            .filter(|spec| visible.contains(&spec.name))
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

        let side_effect = self
            .registry
            .side_effect(&tool_name)
            .unwrap_or(SideEffectType::Read);
        let path_arg = args
            .get("path")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

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

            // Rules 2–6 + taint escalation, mapped onto the four-valued verdict.
            let verdict = self.policy.evaluate(
                &task_name,
                task,
                state.steps_taken,
                &tool_name,
                side_effect,
                &args,
                state.tainted,
            );

            match verdict {
                Verdict::Allow => {}
                Verdict::Absent { reason } => {
                    tracing::info!(tool = %tool_name, task = %task_name, "absent");
                    return Ok(error_result(format!("no such tool: {reason}")));
                }
                Verdict::Deny { reason } => {
                    tracing::warn!(tool = %tool_name, task = %task_name, %reason, "denied");
                    return Ok(error_result(reason));
                }
                Verdict::Ask { reason } => match task.policy.escalation {
                    Escalation::Reject => {
                        tracing::warn!(
                            tool = %tool_name, task = %task_name, %reason,
                            "ASK -> rejected by escalation policy"
                        );
                        return Ok(error_result(format!(
                            "policy violation: {reason} (escalation: reject)"
                        )));
                    }
                    Escalation::AutoApprove => {
                        tracing::warn!(
                            tool = %tool_name, task = %task_name, %reason,
                            "ASK -> auto-approved (dev mode)"
                        );
                    }
                    Escalation::Log => {
                        tracing::warn!(
                            tool = %tool_name, task = %task_name, %reason,
                            "ASK -> allowed and logged for review"
                        );
                    }
                },
            }

            // The call is proceeding: reserve a step from the budget.
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
        let exec_name = tool_name.clone();
        let exec_args = args.clone();
        let result = tokio::task::spawn_blocking(move || {
            registry.execute(&exec_name, &base_dir, &exec_args)
        })
        .await
        .map_err(|e| McpError::internal_error(format!("tool task panicked: {e}"), None))?;

        // Update taint provenance only on success.
        if result.is_ok() {
            self.record_effect(side_effect, path_arg.as_deref());
        }

        Ok(match result {
            Ok(output) => CallToolResult::success(vec![Content::text(output)]),
            Err(e) => error_result(format!("tool error: {e:#}")),
        })
    }
}
