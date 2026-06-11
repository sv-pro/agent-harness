# agent-harness

> **The Agent Hypervisor principle:** We do not make agents safe.
> We make the world they live in safe.

This project is an MCP server (stdio transport) that acts as an enforcement
layer between an AI agent and the filesystem/shell/git. All capability and
policy decisions live in `harness.yaml`, not in the agent's prompt.

## Rule zero: call `set_task` first

Every session starts with **no active task**, and every tool call is rejected
until you call `set_task` with one of the tasks below. `set_task` resets the
step counter; each subsequent tool call consumes one step from the task's
`max_steps` budget.

## Available tasks (from harness.yaml)

| Task | Tools | Write | Whitelist | Max steps |
|------|-------|-------|-----------|-----------|
| `triage` | search, read_file, git_log, git_diff | no | `.` | 15 |
| `refactor` | search, read_file, write_file, shell, git_log, git_diff | yes (approval on write_file) | `src/`, `tests/` | 30 |
| `review` | search, read_file, git_log, git_diff | no | `.` | 20 |

## What the policy engine enforces (before any tool runs)

1. A task must be active (`set_task`).
2. The task's `max_steps` budget must not be exhausted.
3. The tool must be on the task's `tools` whitelist.
4. `write_file` requires `allow_write: true`.
5. `write_file` and `shell` paths must be inside `paths_whitelist`.
6. Tools listed in `require_approval` are flagged (logged and auto-approved in dev mode).

## Building

```sh
cargo build --release
```

The binary is `./target/release/harness`; `.mcp.json` registers it with the
`HARNESS_CONFIG` env var pointing at `harness.yaml`.
