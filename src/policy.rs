use std::collections::HashMap;
use std::path::{Component, PathBuf};

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
        }
    }
}

/// Outcome of a policy check for a tool call that passed all hard rules.
pub struct Verdict {
    /// The tool is on the task's require_approval list (rule 6).
    pub needs_approval: bool,
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

    /// Rules 2–6. Rule 1 (no active task) is checked by the server before
    /// looking up the task config.
    pub fn check(
        &self,
        task_name: &str,
        task: &TaskConfig,
        steps_taken: u32,
        tool: &str,
        args: &serde_json::Map<String, Value>,
    ) -> Result<Verdict, String> {
        // Rule 2: step budget.
        if steps_taken >= task.policy.max_steps {
            return Err(format!(
                "policy violation: task '{task_name}' exhausted its step budget \
                 ({} of {} steps used). Call set_task to start over.",
                steps_taken, task.policy.max_steps
            ));
        }

        // Rule 3: tool whitelist.
        if !task.tools.iter().any(|t| t == tool) {
            return Err(format!(
                "policy violation: tool '{tool}' is not allowed for task '{task_name}'. \
                 Allowed tools: {}",
                task.tools.join(", ")
            ));
        }

        // Rule 4: writes must be explicitly enabled.
        if tool == "write_file" && !task.policy.allow_write {
            return Err(format!(
                "policy violation: task '{task_name}' is read-only (allow_write: false)"
            ));
        }

        // Rule 5: write_file and shell are confined to whitelisted paths.
        if tool == "write_file" || tool == "shell" {
            let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
            self.check_path(task_name, task, path)?;
        }

        // Rule 6: flag tools that require approval (auto-approved in dev mode).
        let needs_approval = task.policy.require_approval.iter().any(|t| t == tool);

        Ok(Verdict { needs_approval })
    }

    fn check_path(&self, task_name: &str, task: &TaskConfig, path: &str) -> Result<(), String> {
        let target = self.resolve(path);
        if !target.starts_with(&self.base_dir) {
            return Err(format!(
                "policy violation: path '{path}' escapes the world's working_dir"
            ));
        }
        let allowed = task
            .policy
            .paths_whitelist
            .iter()
            .any(|entry| target.starts_with(self.resolve(entry)));
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
    /// lexically, so `..` segments cannot escape the comparison below.
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
}
