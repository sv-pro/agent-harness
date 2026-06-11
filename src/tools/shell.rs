use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

/// Run a shell command in `working_dir`/`path`. The policy engine has
/// already verified that the path is inside the task's whitelist.
pub fn run(working_dir: &Path, command: &str, path: &str) -> Result<String> {
    let cwd = working_dir.join(path);
    if !cwd.is_dir() {
        anyhow::bail!("shell cwd does not exist: {}", cwd.display());
    }

    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .current_dir(&cwd)
        .output()
        .with_context(|| format!("failed to spawn: {command}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut out = String::new();
    if !stdout.is_empty() {
        out.push_str(&stdout);
    }
    if !stderr.is_empty() {
        out.push_str("\n--- stderr ---\n");
        out.push_str(&stderr);
    }
    if !output.status.success() {
        out.push_str(&format!(
            "\n--- exit status: {} ---",
            output.status.code().map_or("signal".into(), |c| c.to_string())
        ));
    }
    if out.is_empty() {
        out.push_str("(no output)");
    }
    Ok(out)
}
