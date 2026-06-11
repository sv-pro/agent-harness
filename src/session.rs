use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Context as _;
use serde_json::{Map, Value};

use crate::policy::{Escalation, PolicyEngine, Verdict, WorldConfig};
use crate::registry::{SideEffect, ToolRegistry, ToolSpec};
use crate::taint::TaintLedger;

/// The verdict kind that actually applied to a call, for transports and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    Allow,
    Ask,
    Deny,
    Absent,
}

/// Result of one tool call as seen through the policy gate.
#[derive(Debug)]
pub struct CallOutcome {
    pub kind: VerdictKind,
    /// Whether the tool body actually ran.
    pub executed: bool,
    /// Tool output if executed, otherwise the refusal/error reason.
    pub text: String,
    pub is_error: bool,
}

impl CallOutcome {
    fn refused(kind: VerdictKind, text: String) -> Self {
        Self {
            kind,
            executed: false,
            text,
            is_error: true,
        }
    }
}

struct SessionInner {
    active_task: Option<String>,
    steps_taken: u32,
    /// Set once this session has observed agent-written content. Never reset
    /// by set_task: a task switch must not launder provenance.
    tainted: bool,
    ledger: TaintLedger,
}

/// Transport-independent harness session: policy evaluation, taint tracking,
/// step accounting, and tool execution, all serialized under one lock so a
/// policy check can never interleave with another call's state mutation.
pub struct WorldSession {
    config: WorldConfig,
    base_dir: PathBuf,
    policy: PolicyEngine,
    registry: ToolRegistry,
    inner: Mutex<SessionInner>,
}

impl WorldSession {
    pub fn new(config: WorldConfig) -> anyhow::Result<Self> {
        let base_dir = PathBuf::from(&config.world.working_dir)
            .canonicalize()
            .with_context(|| {
                format!("working_dir does not exist: {}", config.world.working_dir)
            })?;
        let ledger = TaintLedger::load(base_dir.join(TaintLedger::DEFAULT_PATH));
        Ok(Self {
            policy: PolicyEngine::new(base_dir.clone()),
            registry: ToolRegistry::new(),
            inner: Mutex::new(SessionInner {
                active_task: None,
                steps_taken: 0,
                tainted: false,
                ledger,
            }),
            config,
            base_dir,
        })
    }

    pub fn world_name(&self) -> &str {
        &self.config.world.name
    }

    pub fn task_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.config.tasks.keys().cloned().collect();
        names.sort();
        names
    }

    /// Stage 1 — ABSENT semantics: only set_task is visible before a task is
    /// active; afterwards, exactly set_task plus the task's whitelist. Purely
    /// a read of session state — never touches the step counter.
    pub fn visible_specs(&self) -> Vec<&ToolSpec> {
        let active = {
            let inner = self.inner.lock().unwrap();
            inner.active_task.clone()
        };
        let allowed = active.and_then(|name| {
            self.config.tasks.get(&name).map(|t| t.tools.clone())
        });
        self.registry
            .specs()
            .iter()
            .filter(|spec| match (&allowed, spec.name) {
                (_, "set_task") => true,
                (Some(tools), name) => tools.iter().any(|t| t == name),
                (None, _) => false,
            })
            .collect()
    }

    /// Whether this session has observed agent-written content.
    pub fn is_tainted(&self) -> bool {
        self.inner.lock().unwrap().tainted
    }

    /// The policy chokepoint. Everything — rule evaluation, the symlink-aware
    /// path re-check, execution, taint bookkeeping, step accounting — happens
    /// under a single lock acquisition, so there is no window where another
    /// call can mutate ledger or counters between this call's check and its
    /// execution.
    pub fn call(&self, tool: &str, args: &Map<String, Value>) -> CallOutcome {
        if tool == "set_task" {
            return self.set_task(args);
        }

        let mut inner = self.inner.lock().unwrap();

        // Rule 1: before set_task, every other tool is ABSENT.
        let Some(task_name) = inner.active_task.clone() else {
            return CallOutcome::refused(
                VerdictKind::Absent,
                format!("unknown tool '{tool}': no active task, only set_task is available"),
            );
        };
        let task = self
            .config
            .tasks
            .get(&task_name)
            .expect("active task always exists in config");

        // A tool the registry has never heard of is ABSENT, same as a
        // whitelisted-away one — the caller cannot distinguish them.
        let Some(spec) = self.registry.specs().iter().find(|s| s.name == tool) else {
            return CallOutcome::refused(
                VerdictKind::Absent,
                format!("unknown tool '{tool}'"),
            );
        };

        // Rules 2–7 → ALLOW / ASK / DENY / ABSENT.
        let verdict = self.policy.evaluate(
            &task_name,
            task,
            inner.steps_taken,
            spec,
            args,
            inner.tainted,
            self.config.world.taint_tracking,
        );

        let kind = match verdict {
            Verdict::Allow => VerdictKind::Allow,
            Verdict::Absent => {
                return CallOutcome::refused(
                    VerdictKind::Absent,
                    format!("unknown tool '{tool}'"),
                );
            }
            Verdict::Deny { reason } => {
                tracing::warn!(tool, task = %task_name, %reason, "DENY");
                return CallOutcome::refused(
                    VerdictKind::Deny,
                    format!("policy violation: {reason}"),
                );
            }
            Verdict::Ask { reason } => match task.policy.escalation {
                Escalation::Reject => {
                    tracing::warn!(tool, task = %task_name, %reason, "ASK -> rejected");
                    return CallOutcome::refused(
                        VerdictKind::Ask,
                        format!("escalation required: {reason} (escalation: reject)"),
                    );
                }
                Escalation::AutoApprove => {
                    tracing::info!(tool, task = %task_name, %reason, "ASK -> auto-approved");
                    VerdictKind::Ask
                }
                Escalation::Log => {
                    tracing::warn!(
                        tool,
                        task = %task_name,
                        %reason,
                        "ASK -> approved with logging (dev mode)"
                    );
                    VerdictKind::Ask
                }
            },
        };

        // Symlink-aware re-check just before execution (closes the gap the
        // lexical rule-5 check leaves open). Still under the lock.
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or(".")
            .to_string();
        if matches!(spec.side_effect, SideEffect::PersistentWrite | SideEffect::Execute) {
            if let Err(reason) = self.policy.check_path_real(task, &path_arg) {
                tracing::warn!(tool, task = %task_name, %reason, "DENY (real path)");
                return CallOutcome::refused(
                    VerdictKind::Deny,
                    format!("policy violation: {reason}"),
                );
            }
        } else if spec.side_effect == SideEffect::Read && args.contains_key("path") {
            // Reads are not whitelist-confined (rule 5), but they must stay
            // inside the world: without this, read_file/search escape
            // working_dir via `..` or symlinks (self-review fix #3).
            if let Err(reason) = self.policy.check_world_containment(&path_arg) {
                tracing::warn!(tool, task = %task_name, %reason, "DENY (world escape)");
                return CallOutcome::refused(
                    VerdictKind::Deny,
                    format!("policy violation: {reason}"),
                );
            }
        }

        inner.steps_taken += 1;
        tracing::info!(
            tool,
            task = %task_name,
            step = inner.steps_taken,
            max = task.policy.max_steps,
            tainted = inner.tainted,
            "executing"
        );

        let result = self.registry.execute(tool, &self.base_dir, args);

        // Stage 2 — taint bookkeeping, still under the same lock.
        if self.config.world.taint_tracking && result.is_ok() {
            match spec.side_effect {
                SideEffect::PersistentWrite => {
                    // Record provenance durably: this path is now agent-written.
                    if let Ok(real) = self.policy.resolve_real(&path_arg) {
                        if let Err(e) = inner.ledger.record(real) {
                            tracing::error!(error = %e, "failed to persist taint ledger");
                        }
                    }
                }
                SideEffect::Read | SideEffect::Execute => {
                    if !inner.tainted && self.reads_tainted_source(&inner.ledger, spec, args) {
                        inner.tainted = true;
                        tracing::warn!(
                            tool,
                            task = %task_name,
                            "session tainted: output derived from agent-written content"
                        );
                    }
                }
                SideEffect::Meta => {}
            }
        }

        match result {
            Ok(output) => CallOutcome {
                kind,
                executed: true,
                text: output,
                is_error: false,
            },
            Err(e) => CallOutcome {
                kind,
                executed: true,
                text: format!("tool error: {e:#}"),
                is_error: true,
            },
        }
    }

    /// Did this read-like call touch any agent-written path? read_file taints
    /// on an exact ledger hit; search and shell read whole subtrees, so any
    /// ledger entry under their root taints conservatively.
    fn reads_tainted_source(
        &self,
        ledger: &TaintLedger,
        spec: &ToolSpec,
        args: &Map<String, Value>,
    ) -> bool {
        let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
        let Ok(real) = self.policy.resolve_real(path) else {
            return false;
        };
        match spec.name {
            "read_file" => ledger.contains(&real),
            "search" | "shell" => ledger.any_under(&real),
            _ => false,
        }
    }

    /// Meta-tool: bypasses policy, sets the active task, resets the step
    /// counter. Deliberately does NOT reset the taint flag — see the
    /// set_task_does_not_launder_taint test.
    fn set_task(&self, args: &Map<String, Value>) -> CallOutcome {
        let Some(task_name) = args.get("task").and_then(Value::as_str) else {
            return CallOutcome::refused(
                VerdictKind::Deny,
                "set_task requires a 'task' argument".to_string(),
            );
        };
        let Some(task) = self.config.tasks.get(task_name) else {
            return CallOutcome::refused(
                VerdictKind::Deny,
                format!(
                    "unknown task '{task_name}'. Available tasks: {}",
                    self.task_names().join(", ")
                ),
            );
        };

        let mut inner = self.inner.lock().unwrap();
        inner.active_task = Some(task_name.to_string());
        inner.steps_taken = 0;

        tracing::info!(task = task_name, tainted = inner.tainted, "active task set");
        CallOutcome {
            kind: VerdictKind::Allow,
            executed: true,
            text: format!(
                "Active task: {task_name}\nDescription: {}\nAllowed tools: {}\n\
                 allow_write: {} | paths_whitelist: [{}] | max_steps: {} | escalation: {:?}\n\
                 Note: the tool listing has changed — re-list tools to see what is available.",
                task.description,
                task.tools.join(", "),
                task.policy.allow_write,
                task.policy.paths_whitelist.join(", "),
                task.policy.max_steps,
                task.policy.escalation,
            ),
            is_error: false,
        }
    }
}
