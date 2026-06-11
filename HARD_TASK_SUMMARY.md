# HARD_TASK Summary — From DENY to a Taint-Aware Agent Hypervisor

The harness previously implemented only **DENY** semantics: every tool was
listed and disallowed calls were rejected. This change extends it through four
interdependent stages so the *world* — not the agent — enforces provenance and
escalation. All stages were implemented together; `cargo build --release &&
cargo test` is green (4 integration tests, no clippy warnings).

## Structural change

The crate was split into a library (`src/lib.rs`, `name = "agent_harness"`)
plus the thin binary (`src/main.rs`), so the policy core can be exercised by
integration tests without standing up an MCP transport. New modules:
`src/taint.rs` (persistent ledger) and `src/session.rs` (per-session state).

## Stage 1 — ABSENT semantics

`tools/list` is now filtered by the active task (`ToolRegistry::visible_names`,
wired into `HarnessServer::list_tools`):

- **Before `set_task`:** only `set_task` is visible.
- **After `set_task`:** `set_task` + exactly the active task's whitelisted
  tools. Everything else is *absent from the listing*, not merely rejected.
- Listing reads `active_task` under the lock but **does not** touch the step
  counter, so re-listing is free and stays consistent with the budget.

Calling a non-listed tool resolves to the new `Verdict::Absent` ("no such
tool") rather than `Deny`, matching the listing.

## Stage 2 — Taint tracking for persistent writes

- Each `ToolSpec` carries a `side_effect: SideEffectType`
  (`Read | Execute | PersistentWrite`). `write_file` is the only
  `PersistentWrite`; `shell` is `Execute`; the rest are `Read`.
- `TaintLedger` (`src/taint.rs`) is a **persistent**, on-disk JSON record of
  every path written via a `PersistentWrite` tool
  (`.harness/taint_ledger.json`). It is the cross-session memory that survives
  process restarts.
- Provenance: after a successful `read_file`/`search` whose path intersects a
  ledgered path (`taints_read` handles exact, ancestor, and subtree matches),
  the session is marked `tainted`. Taint then propagates through the rest of
  the session.

## Stage 3 — ALLOW / DENY / ABSENT / ASK verdicts

The boolean result is replaced by `enum Verdict { Allow, Absent, Deny, Ask }`,
produced by `PolicyEngine::evaluate`. Rules 1–6 are preserved and mapped on:

| Condition | Verdict |
|-----------|---------|
| Rule 1 — no active task | rejected by server (pre-check) |
| Rule 3 — tool not on whitelist | `Absent` |
| Rule 2 — step budget exhausted | `Deny` |
| Rule 4 — persistent write without `allow_write` | `Deny` |
| Rule 5 — path escapes whitelist | `Deny` |
| **Taint → persistent write** | `Ask` |
| Rule 6 — tool on `require_approval` | `Ask` |
| otherwise | `Allow` |

`ASK` is resolved per task via a new `escalation` field in `harness.yaml`
(`auto_approve` | `log` | `reject`); the server applies it in `call_tool`.
`auto_approve` (the default) preserves prior dev-mode behavior; `reject` turns
ASK into a hard denial. A step is consumed only when a call actually proceeds.

## Stage 4 — Adversarial test + self-review

`tests/zombie_agent.rs` reproduces a **ZombieAgent cross-session memory
poisoning** attack and four guarantees:

1. `zombie_agent_cross_session_poisoning_is_contained` — Session A writes a
   poisoned instruction file; a **fresh** Session B (reloaded ledger, as a
   restarted process would see) reads it and attempts a persistent write.
   - **Without taint tracking** the write is `Allow` — poison lands.
   - **With taint tracking** the same write is `Ask` (and `Deny` under
     `escalation: reject`). Blast radius contained.
2. `absent_semantics_hide_non_whitelisted_tools` — Stage 1 visibility + the
   `Absent` verdict for a non-whitelisted call.

### Self-review: two real holes found and fixed

1. **Taint laundering across `set_task` (logic hole).** Resetting taint on task
   switch would let an agent that already read poison simply re-`set_task` to
   wipe the `tainted` flag and slip a previously-ASKed write through.
   `SessionState::reset_task` now resets **only** the step budget and active
   task and *deliberately preserves* taint provenance — you cannot un-read
   poison by switching tasks. Covered by `taint_survives_set_task_reset`.

2. **Symlink path escape / TOCTOU (path hole).** The old check normalized paths
   lexically only, so a symlink inside the whitelist (`src/evil -> /etc`) made
   `src/evil/passwd` *look* contained. `PolicyEngine::resolve_real`
   canonicalizes the longest existing prefix (following symlinks) before the
   whitelist comparison. Covered by `symlink_escape_is_denied` (Unix).

## Files touched

- `Cargo.toml` — `[lib]` target, dev-deps (`serde_yaml`, `serde_json`).
- `src/lib.rs`, `src/main.rs` — library split.
- `src/policy.rs` — `SideEffectType`, `Verdict`, `Escalation`, `evaluate`,
  symlink-safe `resolve_real`.
- `src/registry.rs` — per-tool `side_effect`, `side_effect()`,
  `visible_names()`.
- `src/server.rs` — ABSENT listing, verdict + escalation handling, taint
  recording, `record_effect`.
- `src/taint.rs`, `src/session.rs` — new modules.
- `harness.yaml` — `escalation` knob; `.gitignore` — ignore `.harness/`.
- `tests/zombie_agent.rs` — adversarial + regression tests.
