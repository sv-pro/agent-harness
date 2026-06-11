use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Persistent record of every path the agent has written through the
/// harness. Survives across sessions (and processes) so that a file
/// poisoned in session A still counts as an agent-controlled source
/// when session B reads it — the ZombieAgent defense.
///
/// Entries are stored relative to the world's working_dir, so the ledger
/// stays valid if the checkout is moved or cloned elsewhere. Callers pass
/// canonicalized absolute paths (symlinks already resolved), which are
/// relativized against the canonicalized base on the way in and out.
pub struct TaintLedger {
    file: PathBuf,
    /// Canonicalized world root used to relativize entries.
    base: PathBuf,
    entries: HashSet<PathBuf>,
}

impl TaintLedger {
    /// Default ledger location relative to the world's working_dir.
    pub const DEFAULT_PATH: &'static str = ".harness/taint.json";

    pub fn load(file: PathBuf, base: PathBuf) -> Self {
        let entries = std::fs::read_to_string(&file)
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
            .map(|paths| paths.into_iter().map(PathBuf::from).collect())
            .unwrap_or_default();
        Self { file, base, entries }
    }

    fn relativize(&self, abs: &Path) -> PathBuf {
        abs.strip_prefix(&self.base)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| abs.to_path_buf())
    }

    /// Record an agent-written path and persist immediately, so a crash
    /// (or a hostile session ending early) cannot drop provenance.
    pub fn record(&mut self, path: PathBuf) -> Result<()> {
        let rel = self.relativize(&path);
        if self.entries.insert(rel) {
            self.persist()?;
        }
        Ok(())
    }

    /// Is this exact file an agent-written source?
    pub fn contains(&self, path: &Path) -> bool {
        self.entries.contains(&self.relativize(path))
    }

    /// Does any agent-written file live under `root`? Used for tools that
    /// read whole subtrees (search, shell cwd).
    pub fn any_under(&self, root: &Path) -> bool {
        let rel = self.relativize(root);
        self.entries.iter().any(|e| e.starts_with(&rel))
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let paths: Vec<String> = self
            .entries
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        std::fs::write(&self.file, serde_json::to_string_pretty(&paths)?)
            .with_context(|| format!("failed to persist taint ledger {}", self.file.display()))
    }
}
