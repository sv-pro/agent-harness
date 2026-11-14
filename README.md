# agent-harness — model-evaluation fixture

> **What this is:** a reusable **model-evaluation fixture**, not a product and not
> the flagship implementation. `HARD_TASK.md` is one hard, four-stage governance
> prompt ("extend it in four interdependent stages; do not stop between stages");
> the branches (`hard-opus`, `hard-fable`, and their merge) are different models'
> attempts at it. The point was to **compare model implementations of the same
> governance task**, not to ship an enforcement layer.
>
> **The maintained implementation** of agentic execution governance lives in
> **[ai2rules](https://ai2rules.dev/kernel/)** (10-crate Rust harness). This
> repo is recorded there in [`DECISIONS.md`](https://ai2rules.dev/kernel/decisions/#d38--the-march-2026-runtime-cluster-is-superseded-record-the-lineage) (D38) as an eval fixture — distinct from
> the product lineage, and deliberately **kept, not archived**, for reuse.

The fixture itself is a portable, compiled MCP server (stdio transport) that acts
as an **enforcement layer** for AI dev agents.

> **The Agent Hypervisor principle:** We do not make agents safe.
> We make the world they live in safe.

Instead of trusting an agent's prompt to keep it in bounds, the harness sits
between the agent and the filesystem/shell/git and enforces policy on every
tool call — before execution, in compiled Rust code the agent cannot talk its
way around.

## How it works

```
┌─────────┐   MCP (stdio)   ┌──────────────────────────────┐
│  agent   │ ──────────────▶ │ harness                      │
│ (Claude, │                 │  call_tool                   │
│  etc.)   │ ◀────────────── │   └─ PolicyEngine ─▶ tools   │
└─────────┘    results /     │       (rules 1–6)            │
               rejections    └──────────────────────────────┘
                                        ▲
                                  harness.yaml
                          (world + tasks + policies)
```

The agent must first call the `set_task` meta-tool to pick a task defined in
`harness.yaml`. Every subsequent call passes through the policy gate:

1. **Active task required** — everything is rejected until `set_task`.
2. **Step budget** — each call consumes one of the task's `max_steps`.
3. **Tool whitelist** — only the task's `tools` list is callable.
4. **Write gating** — `write_file` requires `allow_write: true`.
5. **Path confinement** — `write_file`/`shell` paths must resolve inside
   `paths_whitelist` (lexically normalized; `..` cannot escape).
6. **Approval flagging** — tools in `require_approval` are logged with a
   warning and auto-approved in dev mode.

## Tools exposed

| Tool | Description |
|------|-------------|
| `set_task(task)` | Meta-tool: select the active task, reset the step counter |
| `search(query, path)` | Recursive grep-like file content search |
| `read_file(path)` | Read a file |
| `write_file(path, content)` | Write a file (policy-gated) |
| `shell(command, path)` | Run a command via `bash -c` in a whitelisted dir |
| `git_log(n)` | Last N commits |
| `git_diff(ref)` | Diff against a ref |

## Configuration

The binary reads the config path from the `HARNESS_CONFIG` env var
(default `harness.yaml`):

```yaml
version: "1"
world:
  name: agent-harness-dev
  working_dir: "."
tasks:
  refactor:
    description: Refactor code under src/ and tests/.
    tools: [search, read_file, write_file, shell, git_log, git_diff]
    policy:
      allow_write: true
      paths_whitelist: [src, tests]
      require_approval: [write_file]
      max_steps: 30
```

The bundled `harness.yaml` ships three example tasks: `triage` (read-only,
15 steps), `refactor` (gated writes to `src/` and `tests/`, 30 steps), and
`review` (read-only, 20 steps).

## Build & use

```sh
cargo build --release
```

`.mcp.json` registers `./target/release/harness` as an MCP server for Claude
Code with `HARNESS_CONFIG` pointing at `./harness.yaml`. See `CLAUDE.md` for
the agent-facing instructions.

## Layout

```
src/
├── main.rs        # stdio entrypoint, loads HARNESS_CONFIG
├── server.rs      # ServerHandler: the call_tool policy chokepoint
├── policy.rs      # WorldConfig + PolicyEngine (rules 1–6)
├── registry.rs    # tool specs (JSON schemas) + dispatch
└── tools/         # search, shell, git implementations
```
