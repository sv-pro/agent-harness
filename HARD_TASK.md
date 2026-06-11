You are working in the agent-harness repo: a Rust MCP server (rmcp, stdio)
that enforces per-task policy from harness.yaml (the World Manifest).
Currently it only implements DENY semantics: tools/list exposes all tools,
and call_tool rejects disallowed ones. Extend it in four interdependent
stages. Do not stop between stages.

## Stage 1 — ABSENT semantics
Filter tools/list by the active task: tools not in the task's whitelist
must not appear in the listing at all (ABSENT), as opposed to being listed
but rejected (DENY). Before set_task, only set_task itself is visible.
The step counter and task state must stay consistent across re-listing.

## Stage 2 — Taint tracking for persistent writes
Add a side_effect_type field to tool specs (read | execute |
persistent_write). Implement provenance tracking: any value derived from
the output of a persistent_write-capable source (e.g. read_file on a path
previously written this session) is tainted. Propagate taint through
chained calls within a session.

## Stage 3 — ALLOW / DENY / ABSENT / ASK verdicts
Replace the boolean policy result with a four-valued verdict. ASK is
triggered when a tainted value flows into a persistent_write tool;
escalation behavior (auto-approve / reject / log) is configurable in
harness.yaml per task. Keep rules 1–6 intact and map them onto the new
verdict type.

## Stage 4 — Adversarial test + self-review
Write an integration test reproducing a ZombieAgent-style attack
(cross-session memory poisoning: session A writes a poisoned instruction
file, session B reads it and attempts a persistent write driven by it).
Show the blast radius difference: without taint tracking the write
succeeds; with it, the verdict is ASK/DENY.
Then review your own implementation and find and fix at least one real
race condition or logic hole (e.g. taint state across set_task resets,
step counting vs. tools/list, TOCTOU in path checks) before finishing.

Build and verify with: cargo build --release && cargo test