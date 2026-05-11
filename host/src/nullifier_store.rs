//! Newline-delimited hex nullifier store. SPEC.md §6: linear scan for
//! non-inclusion, append on accept. v0 single-verifier, single-file.

use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub fn contains(path: &Path, nullifier_hex: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading nullifier store at {}", path.display()))?;
    Ok(contents.lines().any(|l| l.trim().eq_ignore_ascii_case(nullifier_hex)))
}

pub fn append(path: &Path, nullifier_hex: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating nullifier store parent dir {}", parent.display()))?;
        }
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening nullifier store at {}", path.display()))?;
    writeln!(f, "{}", nullifier_hex)?;
    Ok(())
}
