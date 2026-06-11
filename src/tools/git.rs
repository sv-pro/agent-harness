use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

pub fn log(working_dir: &Path, n: u32) -> Result<String> {
    git(working_dir, &["log", &format!("-{n}"), "--oneline", "--decorate"])
}

pub fn diff(working_dir: &Path, gitref: &str) -> Result<String> {
    // `--` guards against refs that look like flags or paths.
    git(working_dir, &["diff", gitref, "--"])
}

fn git(working_dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(working_dir)
        .output()
        .with_context(|| format!("failed to run git {}", args.join(" ")))?;

    if !output.status.success() {
        anyhow::bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        Ok("(empty)".to_string())
    } else {
        Ok(stdout.into_owned())
    }
}
