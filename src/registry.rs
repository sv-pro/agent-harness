use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::tools;

pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: Value,
}

/// Maps tool names to their implementations. Every call has already been
/// cleared by the PolicyEngine before it reaches `execute`.
pub struct ToolRegistry {
    specs: Vec<ToolSpec>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        let specs = vec![
            ToolSpec {
                name: "set_task",
                description: "Meta-tool: select the active task from harness.yaml. \
                              Must be called before any other tool. Resets the step counter.",
                schema: json!({
                    "type": "object",
                    "properties": {
                        "task": { "type": "string", "description": "Task name from harness.yaml" }
                    },
                    "required": ["task"]
                }),
            },
            ToolSpec {
                name: "search",
                description: "Recursive grep-like search for a string in file contents.",
                schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Substring to search for" },
                        "path": { "type": "string", "description": "Directory or file relative to working_dir", "default": "." }
                    },
                    "required": ["query"]
                }),
            },
            ToolSpec {
                name: "read_file",
                description: "Read the contents of a file relative to working_dir.",
                schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File path relative to working_dir" }
                    },
                    "required": ["path"]
                }),
            },
            ToolSpec {
                name: "write_file",
                description: "Write content to a file relative to working_dir. \
                              Subject to allow_write and paths_whitelist policy.",
                schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File path relative to working_dir" },
                        "content": { "type": "string", "description": "Full file content to write" }
                    },
                    "required": ["path", "content"]
                }),
            },
            ToolSpec {
                name: "shell",
                description: "Run a shell command. cwd is working_dir/path and must be \
                              inside the task's paths_whitelist.",
                schema: json!({
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "Command to run via bash -c" },
                        "path": { "type": "string", "description": "Working directory relative to working_dir", "default": "." }
                    },
                    "required": ["command"]
                }),
            },
            ToolSpec {
                name: "git_log",
                description: "Show the last N commits (git log --oneline).",
                schema: json!({
                    "type": "object",
                    "properties": {
                        "n": { "type": "integer", "description": "Number of commits", "default": 10 }
                    }
                }),
            },
            ToolSpec {
                name: "git_diff",
                description: "Show the diff against a git ref.",
                schema: json!({
                    "type": "object",
                    "properties": {
                        "ref": { "type": "string", "description": "Git ref to diff against, e.g. HEAD or main" }
                    },
                    "required": ["ref"]
                }),
            },
        ];
        Self { specs }
    }

    pub fn specs(&self) -> &[ToolSpec] {
        &self.specs
    }

    pub fn execute(&self, name: &str, base_dir: &Path, args: &Map<String, Value>) -> Result<String> {
        let str_arg = |key: &str| -> Result<&str> {
            args.get(key)
                .and_then(Value::as_str)
                .with_context(|| format!("missing required string argument '{key}'"))
        };

        match name {
            "search" => {
                let query = str_arg("query")?;
                let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
                tools::search::run(base_dir, query, path)
            }
            "read_file" => {
                let path = str_arg("path")?;
                let full = base_dir.join(path);
                std::fs::read_to_string(&full)
                    .with_context(|| format!("failed to read {}", full.display()))
            }
            "write_file" => {
                let path = str_arg("path")?;
                let content = str_arg("content")?;
                let full = base_dir.join(path);
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&full, content)
                    .with_context(|| format!("failed to write {}", full.display()))?;
                Ok(format!("wrote {} bytes to {path}", content.len()))
            }
            "shell" => {
                let command = str_arg("command")?;
                let path = args.get("path").and_then(Value::as_str).unwrap_or(".");
                tools::shell::run(base_dir, command, path)
            }
            "git_log" => {
                let n = args.get("n").and_then(Value::as_u64).unwrap_or(10) as u32;
                tools::git::log(base_dir, n)
            }
            "git_diff" => {
                let gitref = str_arg("ref")?;
                tools::git::diff(base_dir, gitref)
            }
            other => anyhow::bail!("unknown tool: {other}"),
        }
    }
}
