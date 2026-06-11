use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Persistent provenance ledger of every path an agent has written via a
/// `persistent_write` tool. It is the cross-session memory that defeats
/// ZombieAgent-style poisoning: a file written by session A is remembered
/// here, so when session B (a fresh process) reads it back, the harness knows
/// the content has untrusted, agent-controlled provenance and taints it.
///
/// The ledger is the only taint state that survives process restarts; the
/// per-session "is this session tainted" flag lives in `SessionState`.
pub struct TaintLedger {
    /// On-disk JSON file backing the ledger.
    path: PathBuf,
    /// World root, used to store entries as portable relative paths.
    base: PathBuf,
    /// Relative paths written by some agent session.
    written: Mutex<BTreeSet<PathBuf>>,
}

impl TaintLedger {
    /// Load (or start) a ledger at `ledger_path`, storing paths relative to
    /// `base`. A missing or corrupt file yields an empty ledger.
    pub fn load(ledger_path: PathBuf, base: PathBuf) -> Self {
        let written = std::fs::read_to_string(&ledger_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .map(|v| v.into_iter().map(PathBuf::from).collect())
            .unwrap_or_default();
        Self {
            path: ledger_path,
            base,
            written: Mutex::new(written),
        }
    }

    fn relativize(&self, abs: &Path) -> PathBuf {
        abs.strip_prefix(&self.base)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| abs.to_path_buf())
    }

    /// Record that `abs_path` was written by an agent. Idempotent; persists
    /// immediately so a later process sees it.
    pub fn mark_written(&self, abs_path: &Path) {
        let rel = self.relativize(abs_path);
        let mut w = self.written.lock().unwrap();
        if w.insert(rel) {
            self.persist(&w);
        }
    }

    /// True if reading `abs_path` would surface agent-written content. Handles
    /// both an exact file read and a directory/recursive read (search) whose
    /// subtree contains a written file.
    pub fn taints_read(&self, abs_path: &Path) -> bool {
        let rel = self.relativize(abs_path);
        let w = self.written.lock().unwrap();
        w.iter()
            .any(|p| p == &rel || p.starts_with(&rel) || rel.starts_with(p))
    }

    /// Test/inspection helper: number of remembered paths.
    pub fn len(&self) -> usize {
        self.written.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn persist(&self, set: &BTreeSet<PathBuf>) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let list: Vec<String> = set
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&list) {
            let _ = std::fs::write(&self.path, json);
        }
    }
}
