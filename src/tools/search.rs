use std::path::Path;

use anyhow::Result;

const MAX_MATCHES: usize = 200;
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".cache"];

/// Recursive grep-like search for `query` in files under `root`/`path`.
pub fn run(root: &Path, query: &str, path: &str) -> Result<String> {
    let start = root.join(path);
    if !start.exists() {
        anyhow::bail!("search path does not exist: {}", start.display());
    }

    let mut matches = Vec::new();
    walk(&start, root, query, &mut matches)?;

    if matches.is_empty() {
        return Ok(format!("no matches for '{query}' under {path}"));
    }
    let mut out = matches.join("\n");
    if matches.len() >= MAX_MATCHES {
        out.push_str(&format!("\n... truncated at {MAX_MATCHES} matches"));
    }
    Ok(out)
}

fn walk(dir: &Path, root: &Path, query: &str, matches: &mut Vec<String>) -> Result<()> {
    if matches.len() >= MAX_MATCHES {
        return Ok(());
    }
    if dir.is_file() {
        scan_file(dir, root, query, matches);
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        if matches.len() >= MAX_MATCHES {
            break;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) || name.starts_with('.') {
                continue;
            }
            walk(&path, root, query, matches)?;
        } else if path.is_file() {
            scan_file(&path, root, query, matches);
        }
    }
    Ok(())
}

fn scan_file(file: &Path, root: &Path, query: &str, matches: &mut Vec<String>) {
    // Skip binary / non-UTF-8 files silently.
    let Ok(content) = std::fs::read_to_string(file) else {
        return;
    };
    let display = file.strip_prefix(root).unwrap_or(file).display().to_string();
    for (idx, line) in content.lines().enumerate() {
        if matches.len() >= MAX_MATCHES {
            return;
        }
        if line.contains(query) {
            matches.push(format!("{display}:{}: {}", idx + 1, line.trim_end()));
        }
    }
}
