//! # `source_invariants`
//!
//! **Purpose**: Regression guards for source-level runtime contracts.
//! **Public API**: integration tests only
//! **Dependencies**: `std::fs`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 70 / 120

use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

const DIAGNOSTIC_OWNER_DIR: &str = "src/output";
const FORBIDDEN_DIAGNOSTIC_TOKENS: &[&str] = &["println!", "dbg!", "stderr()"];

#[test]
fn diagnostics_are_centralized_in_output_module() -> Result<(), Box<dyn Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let diagnostic_owner = manifest_dir.join(DIAGNOSTIC_OWNER_DIR);

    let mut rust_files = Vec::new();
    collect_rust_files(&src_dir, &mut rust_files)?;

    let mut violations = Vec::new();
    for path in rust_files {
        if path.starts_with(&diagnostic_owner) {
            continue;
        }

        let source = fs::read_to_string(&path)?;
        for (line_index, line) in source.lines().enumerate() {
            for token in FORBIDDEN_DIAGNOSTIC_TOKENS {
                if line.contains(token) {
                    let rel_path = relative_path(manifest_dir, &path).display();
                    let line_number = line_index + 1;
                    violations.push(format!("{rel_path}:{line_number} contains `{token}`"));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "diagnostics must be routed through `{DIAGNOSTIC_OWNER_DIR}`:\n{}",
        violations.join("\n")
    );
    Ok(())
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn relative_path<'a>(base: &'a Path, path: &'a Path) -> &'a Path {
    path.strip_prefix(base).unwrap_or(path)
}
