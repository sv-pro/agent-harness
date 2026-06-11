use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct WorldConfig {
    pub version: String,
    pub world: World,
    pub tasks: HashMap<String, TaskConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct World {
    pub name: String,
    pub working_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TaskConfig {
    pub description: String,
    pub tools: Vec<String>,
    #[serde(default)]
    pub policy: Policy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub allow_write: bool,
    #[serde(default)]
    pub paths_whitelist: Vec<String>,
    #[serde(default)]
    pub require_approval: Vec<String>,
    #[serde(default = "default_max_steps")]
    pub max_steps: u32,
    /// What to do when a tool call resolves to the ASK verdict (rule 6 or a
    /// tainted dataflow into a persistent write). Defaults to auto-approve so
    /// existing dev-mode behavior is preserved.
    #[serde(default)]
    pub escalation: Escalation,
}

fn default_max_steps() -> u32 {
    20
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_write: false,
            paths_whitelist: Vec::new(),
            require_approval: Vec::new(),
            max_steps: default_max_steps(),
            escalation: Escalation::default(),
        }
    }
}

/// How an ASK verdict is resolved for a task.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Escalation {
    /// Let the call through, but log that approval was implicitly granted.
    /// Default so existing dev-mode behavior is preserved.
    #[default]
    AutoApprove,
    /// Turn ASK into a hard rejection.
    Reject,
    /// Let the call through and record it for out-of-band review.
    Log,
}

/// The kind of effect a tool can have on the world. Drives taint provenance:
/// only `PersistentWrite` sources can introduce taint, and only
/// `PersistentWrite` sinks can be escalated by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideEffectType {
    /// Observes state without changing it (search, read_file, git_*).
    Read,
    /// Runs a subprocess; effects are out of band (shell).
    Execute,
    /// Durably mutates the world in a way later reads can observe (write_file).
    PersistentWrite,
}

/// Four-valued result of a policy check, replacing the old boolean.
#[derive(Debug)]
pub enum Verdict {
    /// Proceed.
    Allow,
    /// The tool does not exist for this task — it was never even listed.
    Absent { reason: String },
    /// A hard rule rejected the call.
    Deny { reason: String },
    /// The call needs approval; how it resolves depends on `Escalation`.
    Ask { reason: String },
}

/// Enforces the world's rules before any tool executes.
pub struct PolicyEngine {
    /// Canonicalized world.working_dir — the root of the safe world.
    base_dir: PathBuf,
}

impl PolicyEngine {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Map rules 1–6 (rule 1 is checked by the caller) plus taint escalation
    /// onto the four-valued [`Verdict`].
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        task_name: &str,
        task: &TaskConfig,
        steps_taken: u32,
        tool: &str,
        side_effect: SideEffectType,
        args: &serde_json::Map<String, Value>,
        tainted: bool,
    ) -> Verdict {
        // Rule 3 (ABSENT): a tool outside the task's whitelist does not exist
        // in this world. It was filtered out of tools/list, and calling it
        // anyway is answered as "no such tool", not "denied".
        if !task.tools.iter().any(|t| t == tool) {
            return Verdict::Absent {
                reason: format!(
                    "tool '{tool}' does not exist for task '{task_name}'. \
                     Available: {}",
                    task.tools.join(", ")
                ),
            };
        }

        // Rule 2: step budget.
        if steps_taken >= task.policy.max_steps {
            return Verdict::Deny {
                reason: format!(
                    "policy violation: task '{task_name}' exhausted its step budget \
                     ({} of {} steps used). Call set_task to start over.",
                    steps_taken, task.policy.max_steps
                ),
            };
        }

        // Rule 4: persistent writes must be explicitly enabled.
        if side_effect == SideEffectType::PersistentWrite && !task.policy.allow_write {
            return Verdict::Deny {
                reason: format!(
                    "policy violation: task '{task_name}' is read-only (allow_write: false)"
                ),
            };
        }

        // Rule 5: write_file and shell are confined to whitelisted paths.
        if matches!(
            side_effect,
            SideEffectType::PersistentWrite | SideEffectType::Execute
        ) {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            if let Err(reason) = self.check_path(task_name, task, path) {
                return Verdict::Deny { reason };
            }
        }

        // Stage 2/3: a tainted value flowing into a persistent-write sink is
        // the ZombieAgent vector. Escalate to ASK regardless of approval list.
        if side_effect == SideEffectType::PersistentWrite && tainted {
            return Verdict::Ask {
                reason: format!(
                    "tainted dataflow: agent-written (untrusted) content is driving a \
                     persistent write via '{tool}'"
                ),
            };
        }

        // Rule 6: configured approval gate.
        if task.policy.require_approval.iter().any(|t| t == tool) {
            return Verdict::Ask {
                reason: format!("tool '{tool}' requires approval per task policy"),
            };
        }

        Verdict::Allow
    }

    fn check_path(&self, task_name: &str, task: &TaskConfig, path: &str) -> Result<(), String> {
        let target = self.resolve_real(path);
        if !target.starts_with(&self.base_dir) {
            return Err(format!(
                "policy violation: path '{path}' escapes the world's working_dir"
            ));
        }
        let allowed = task
            .policy
            .paths_whitelist
            .iter()
            .any(|entry| target.starts_with(self.resolve_real(entry)));
        if !allowed {
            return Err(format!(
                "policy violation: path '{path}' is outside the whitelist for task \
                 '{task_name}': [{}]",
                task.policy.paths_whitelist.join(", ")
            ));
        }
        Ok(())
    }

    /// Resolve a (possibly relative) path against base_dir and normalize it
    /// lexically, so `..` segments cannot escape the comparison below. This is
    /// the path as written; see [`resolve_real`] for the symlink-safe form.
    pub fn resolve(&self, path: &str) -> PathBuf {
        let joined = self.base_dir.join(path);
        let mut out = PathBuf::new();
        for component in joined.components() {
            match component {
                Component::ParentDir => {
                    out.pop();
                }
                Component::CurDir => {}
                other => out.push(other.as_os_str()),
            }
        }
        out
    }

    /// Symlink-safe resolution used for the security check. Lexical
    /// normalization alone is a TOCTOU hole: a symlink inside the whitelist
    /// (e.g. `src/evil -> /etc`) makes `src/evil/passwd` *look* contained while
    /// actually pointing outside. We canonicalize the longest existing prefix
    /// (which follows symlinks) and re-append the not-yet-existing tail.
    pub fn resolve_real(&self, path: &str) -> PathBuf {
        let lexical = self.resolve(path);
        let mut existing = lexical.clone();
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        while !existing.exists() {
            match existing.file_name() {
                Some(name) => {
                    tail.push(name.to_os_string());
                    if !existing.pop() {
                        break;
                    }
                }
                None => break,
            }
        }
        let mut real = existing.canonicalize().unwrap_or(existing);
        for seg in tail.iter().rev() {
            real.push(seg);
        }
        real
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}
