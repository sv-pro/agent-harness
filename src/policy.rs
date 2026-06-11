use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use crate::registry::{SideEffect, ToolSpec};

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
    /// Provenance tracking for persistent writes (Stage 2). On by default;
    /// disabling it demonstrates the unprotected blast radius (Stage 4).
    #[serde(default = "default_true")]
    pub taint_tracking: bool,
}

fn default_true() -> bool {
    true
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
    /// What to do when a call earns an ASK verdict.
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

/// Per-task escalation behavior for ASK verdicts (Stage 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Escalation {
    /// Execute silently (dev mode).
    AutoApprove,
    /// Refuse the call.
    Reject,
    /// Execute, but log a loud warning.
    #[default]
    Log,
}

/// Four-valued policy verdict (Stage 3).
///
/// ABSENT differs from DENY: an ABSENT tool is not listed by tools/list and
/// calling it behaves like calling a tool that does not exist, whereas DENY
/// acknowledges the tool but refuses this particular call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Ask { reason: String },
    Deny { reason: String },
    Absent,
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

    /// Rules 1–6 plus taint, mapped onto the four-valued verdict:
    ///
    /// 1. no active task          → ABSENT (only set_task exists yet)
    /// 2. step budget exhausted   → DENY
    /// 3. tool not in whitelist   → ABSENT (Stage 1: it is not listed either)
    /// 4. write w/o allow_write   → DENY
    /// 5. path outside whitelist  → DENY
    /// 6. tool in require_approval → ASK
    /// 7. tainted value flowing into a persistent_write tool → ASK (Stage 3)
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        task_name: &str,
        task: &TaskConfig,
        steps_taken: u32,
        spec: &ToolSpec,
        args: &serde_json::Map<String, Value>,
        session_tainted: bool,
        taint_tracking: bool,
    ) -> Verdict {
        // Rule 2: step budget.
        if steps_taken >= task.policy.max_steps {
            return Verdict::Deny {
                reason: format!(
                    "task '{task_name}' exhausted its step budget ({} of {} steps used). \
                     Call set_task to start over.",
                    steps_taken, task.policy.max_steps
                ),
            };
        }

        // Rule 3: tool whitelist → ABSENT, matching its absence from tools/list.
        if !task.tools.iter().any(|t| t == spec.name) {
            return Verdict::Absent;
        }

        // Rule 4: writes must be explicitly enabled.
        if spec.side_effect == SideEffect::PersistentWrite && !task.policy.allow_write {
            return Verdict::Deny {
                reason: format!("task '{task_name}' is read-only (allow_write: false)"),
            };
        }

        // Rule 5: write_file and shell are confined to whitelisted paths.
        if spec.side_effect == SideEffect::PersistentWrite || spec.side_effect == SideEffect::Execute
        {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            if let Err(reason) = self.check_path_lexical(task_name, task, path) {
                return Verdict::Deny { reason };
            }
        }

        // Rule 7 (Stage 2/3): tainted provenance flowing into a persistent write.
        if taint_tracking && session_tainted && spec.side_effect == SideEffect::PersistentWrite {
            return Verdict::Ask {
                reason: format!(
                    "tainted value flows into persistent_write tool '{}': this session has \
                     read agent-written content and is now attempting a persistent write",
                    spec.name
                ),
            };
        }

        // Rule 6: approval-gated tools.
        if task.policy.require_approval.iter().any(|t| t == spec.name) {
            return Verdict::Ask {
                reason: format!("tool '{}' is on the require_approval list", spec.name),
            };
        }

        Verdict::Allow
    }

    fn check_path_lexical(
        &self,
        task_name: &str,
        task: &TaskConfig,
        path: &str,
    ) -> Result<(), String> {
        let target = self.resolve(path);
        if !target.starts_with(&self.base_dir) {
            return Err(format!("path '{path}' escapes the world's working_dir"));
        }
        let allowed = task
            .policy
            .paths_whitelist
            .iter()
            .any(|entry| target.starts_with(self.resolve(entry)));
        if !allowed {
            return Err(format!(
                "path '{path}' is outside the whitelist for task '{task_name}': [{}]",
                task.policy.paths_whitelist.join(", ")
            ));
        }
        Ok(())
    }

    /// Symlink-aware re-check, run immediately before execution while the
    /// session lock is held. The lexical check above cannot see a symlink
    /// planted inside the whitelist that points outside it; this one
    /// canonicalizes the deepest existing ancestor first.
    pub fn check_path_real(&self, task: &TaskConfig, path: &str) -> Result<PathBuf, String> {
        let real = self
            .resolve_real(path)
            .map_err(|e| format!("cannot resolve path '{path}': {e}"))?;
        if !real.starts_with(&self.base_dir) {
            return Err(format!(
                "path '{path}' resolves outside the world's working_dir (symlink escape)"
            ));
        }
        let allowed = task.policy.paths_whitelist.iter().any(|entry| {
            let root = self.resolve_real(entry).unwrap_or_else(|_| self.resolve(entry));
            real.starts_with(root)
        });
        if allowed {
            Ok(real)
        } else {
            Err(format!(
                "path '{path}' resolves outside the whitelist (symlink escape): [{}]",
                task.policy.paths_whitelist.join(", ")
            ))
        }
    }

    /// World containment for read-shaped tools (self-review fix #3): rule 5
    /// only whitelists write_file/shell paths, which left read_file and
    /// search free to escape working_dir entirely via `..` or symlinks.
    /// Reads may roam the whole world, but never outside it.
    pub fn check_world_containment(&self, path: &str) -> Result<PathBuf, String> {
        let real = self
            .resolve_real(path)
            .map_err(|e| format!("cannot resolve path '{path}': {e}"))?;
        if real.starts_with(&self.base_dir) {
            Ok(real)
        } else {
            Err(format!(
                "path '{path}' resolves outside the world's working_dir"
            ))
        }
    }

    /// Resolve a (possibly relative) path against base_dir and normalize it
    /// lexically, so `..` segments cannot escape the comparison.
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

    /// Like `resolve`, but follows symlinks: canonicalize the deepest
    /// existing ancestor, then re-append the not-yet-existing remainder.
    pub fn resolve_real(&self, path: &str) -> std::io::Result<PathBuf> {
        let lexical = self.resolve(path);
        let mut existing = lexical.clone();
        let mut remainder: Vec<std::ffi::OsString> = Vec::new();
        while !existing.exists() {
            match existing.file_name() {
                Some(name) => {
                    remainder.push(name.to_owned());
                    existing.pop();
                }
                None => break,
            }
        }
        let mut real = existing.canonicalize()?;
        for part in remainder.iter().rev() {
            real.push(part);
        }
        Ok(real)
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}
