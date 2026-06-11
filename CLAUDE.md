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

Every call gets one of four verdicts: **ALLOW**, **ASK**, **DENY**, or
**ABSENT**. ABSENT tools do not appear in `tools/list` at all — before
`set_task`, only `set_task` itself exists; afterwards the listing is exactly
the active task's whitelist.

1. No active task → everything except `set_task` is ABSENT.
2. Exhausted `max_steps` budget → DENY.
3. Tool not on the task's `tools` whitelist → ABSENT.
4. `write_file` without `allow_write: true` → DENY.
5. `write_file`/`shell` paths outside `paths_whitelist` → DENY
   (checked lexically and again symlink-aware just before execution;
   reads may roam the world but never escape `working_dir`).
6. Tools in `require_approval` → ASK.
7. Tainted provenance flowing into a persistent write → ASK.

ASK is resolved by the task's `escalation` setting: `auto_approve`,
`reject`, or `log` (default — execute with a loud warning).

## Taint tracking (ZombieAgent defense)

Every `write_file` is recorded in a persistent ledger
(`.harness/taint.json`). When any session — including a later one — reads
agent-written content (`read_file` on a recorded path, or `search`/`shell`
over a subtree containing one), the session is tainted, and subsequent
persistent writes earn an ASK verdict. `set_task` resets the step counter
but never the taint flag.

## Building

```sh
cargo build --release
```

The binary is `./target/release/harness`; `.mcp.json` registers it with the
`HARNESS_CONFIG` env var pointing at `harness.yaml`.
