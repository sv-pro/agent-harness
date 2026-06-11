# HARD_TASK Summary — hard-fable

Implementation of the four stages from `HARD_TASK.md`, completed by
Claude Fable 5. All stages verified with `cargo build --release && cargo test`
(zero warnings, 8/8 integration tests passing) plus a live JSON-RPC smoke
test over real MCP stdio.

## Architecture change

The policy/taint/execution core was extracted from the rmcp handler into a
transport-independent **`WorldSession`** (`src/session.rs`); `server.rs` is
now a thin MCP adapter. Every call — policy evaluation, symlink-aware path
re-check, execution, taint bookkeeping, step accounting — runs under a
single lock acquisition, so a policy check can never interleave with another
call's state mutation. This is also what makes cross-session adversarial
tests possible without spawning processes.

## Stage 1 — ABSENT semantics

- `tools/list` is filtered by session state: only `set_task` before a task
  is active; exactly `set_task` + the task's whitelist after.
- A `notifications/tools/list_changed` notification is emitted after a
  successful `set_task` (capability `tools.listChanged: true`).
- Listing is a pure read: it never touches the step counter.
- Calling an unlisted tool is indistinguishable from calling a nonexistent
  one (same "unknown tool" message), and consumes no steps.

## Stage 2 — Taint tracking

- `ToolSpec` gained `side_effect: Read | Execute | PersistentWrite | Meta`.
- Every successful `write_file` records the symlink-resolved path in a
  **persistent ledger** (`.harness/taint.json` under `working_dir`),
  written through immediately so provenance survives crashes, session ends,
  and process restarts.
- A session becomes **tainted** when it observes agent-written content:
  `read_file` on a recorded path, or `search`/`shell` over a subtree
  containing one (conservative subtree matching).
- Taint is a session-level flag, so it propagates through all chained calls.

## Stage 3 — ALLOW / DENY / ABSENT / ASK

`Verdict::{Allow, Ask, Deny, Absent}` replaces the boolean policy result.
Rules 1–6 map onto it:

| # | Rule | Verdict |
|---|------|---------|
| 1 | no active task | ABSENT (only `set_task` exists) |
| 2 | step budget exhausted | DENY |
| 3 | tool not in task whitelist | ABSENT (matches the filtered listing) |
| 4 | write without `allow_write` | DENY |
| 5 | `write_file`/`shell` path outside whitelist | DENY |
| 6 | tool in `require_approval` | ASK |
| 7 | tainted value → `persistent_write` tool | ASK |

ASK is resolved by per-task `escalation` in `harness.yaml`:
`auto_approve` (execute silently), `reject` (refuse), `log` (default —
execute with a loud warning).

## Stage 4 — ZombieAgent test + self-review

`tests/zombie_agent.rs` reproduces cross-session memory poisoning:

- **Protected:** session A writes a poisoned instruction file into
  `memory/`; session B reads it, becomes tainted, and its
  instruction-driven `write_file` into `src/` gets ASK → rejected.
  The payload never reaches disk.
- **Blast radius:** identical attack with `taint_tracking: false` —
  the poisoned write lands.

### Self-review: three holes found and fixed (each with a regression test)

1. **Taint laundering via `set_task`** — the task switch reset the taint
   flag along with the step counter, so a poisoned session could launder
   provenance by re-selecting a task before writing. Taint now survives
   `set_task`.
2. **Symlink escape (TOCTOU)** — the lexical rule-5 check cannot see a
   symlink planted inside the whitelist that points outside it. A
   symlink-resolving re-check now runs under the session lock immediately
   before execution, for both `write_file` paths and `shell` cwd.
3. **Unconfined reads** — rule 5 only covered `write_file`/`shell`, so
   `read_file`/`search` could escape `working_dir` entirely via `..` or
   symlinks (the lexical normalizer even resolved the traversal for the
   attacker). Reads are now world-contained: free inside `working_dir`,
   denied outside it.

## Verification

```
cargo build --release   # zero warnings
cargo test              # 8/8 integration tests pass
```

Live stdio smoke test confirmed: ABSENT listing before/after `set_task`,
the `list_changed` notification, and denial of a world-escaping read.

## Merge addendum (`hard-merged`)

This branch takes `hard-fable` as the base and ports the strengths of the
parallel `hard-opus` implementation:

1. **Relative-path taint ledger** — entries in `.harness/taint.json` are
   stored relative to `working_dir` (still canonicalized first, so symlink
   aliases keep matching), so provenance survives moving or cloning the
   checkout.
2. **`taint_sources` diagnostic trail** — the session records every
   read-shaped call that introduced taint (`tool: path`), exposes it via
   `WorldSession::taint_sources()`, and cites it in `escalation: reject`
   refusals so the operator can trace the poison.
3. **ABSENT wins over an exhausted budget** — the whitelist check (rule 3)
   now runs before the step-budget check (rule 2), so a budget-exhausted
   session cannot probe which tools would exist for a task.
4. **Clippy clean** — `Default` impl for `ToolRegistry`; zero warnings.

Verification on this branch: `cargo build --release` clean,
`cargo test` 10/10 (two new tests:
`ledger_is_relative_and_taint_sources_are_recorded`,
`absent_wins_over_exhausted_budget`).
