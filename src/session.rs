/// Mutable per-connection state. Distinct from the [`crate::taint::TaintLedger`],
/// which is shared and persistent: this is the live "where are we right now"
/// of one MCP session.
#[derive(Default, Debug)]
pub struct SessionState {
    pub active_task: Option<String>,
    pub steps_taken: u32,
    /// Whether any tainted (agent-written) content has been read into this
    /// session. Once set, it stays set for the life of the session.
    pub tainted: bool,
    /// Human-readable trail of what introduced taint, for diagnostics.
    pub taint_sources: Vec<String>,
}

impl SessionState {
    /// Switch the active task and reset the step budget.
    ///
    /// SECURITY (self-review fix): taint provenance is deliberately *not*
    /// cleared here. Resetting it would be a laundering hole — an agent that
    /// has already read poisoned content could simply re-`set_task` (even to
    /// the same task) to wipe the taint flag and then sail a previously-ASKed
    /// persistent write straight through. You cannot un-read poison by
    /// switching tasks, so the flag survives the reset; only the step counter
    /// and active task are reset.
    pub fn reset_task(&mut self, name: String) {
        self.active_task = Some(name);
        self.steps_taken = 0;
        // self.tainted and self.taint_sources intentionally preserved.
    }

    /// Mark this session tainted, recording the source path.
    pub fn mark_tainted(&mut self, source: impl Into<String>) {
        self.tainted = true;
        self.taint_sources.push(source.into());
    }
}
