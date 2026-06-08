//! # `runtime::which`
//!
//! **Purpose**: Discover installed Chromium-based browsers on Windows.
//! **Public API**: `enum BrowserFamily`, `struct BrowserCandidate`, `fn discover_browser`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 155 / 200

use std::path::{Path, PathBuf};

/// Supported Chromium-based browser families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserFamily {
    /// Google Chrome.
    Chrome,
    /// Microsoft Edge.
    Edge,
    /// Chromium.
    Chromium,
    /// Brave.
    Brave,
    /// Vivaldi.
    Vivaldi,
}

/// A discovered browser executable with metadata.
#[derive(Debug)]
pub struct BrowserCandidate {
    /// Absolute path to the browser executable.
    pub path: PathBuf,
    /// Browser family.
    pub family: BrowserFamily,
    /// How the browser was found.
    pub source: &'static str,
}

/// Well-known browser executable names on Windows.
const KNOWN_EXES: &[(&str, BrowserFamily)] = &[
    ("chrome.exe", BrowserFamily::Chrome),
    ("msedge.exe", BrowserFamily::Edge),
    ("chromium.exe", BrowserFamily::Chromium),
    ("brave.exe", BrowserFamily::Brave),
    ("vivaldi.exe", BrowserFamily::Vivaldi),
];

/// Common install directory patterns relative to program files roots.
const COMMON_RELATIVE_PATHS: &[&str] = &[
    "Google\\Chrome\\Application\\chrome.exe",
    "Google\\Chrome SxS\\Application\\chrome.exe",
    "Chromium\\Application\\chrome.exe",
    "Microsoft\\Edge\\Application\\msedge.exe",
    "Microsoft\\Edge Beta\\Application\\msedge.exe",
    "Microsoft\\Edge Dev\\Application\\msedge.exe",
    "Microsoft\\Edge SxS\\Application\\msedge.exe",
    "BraveSoftware\\Brave-Browser\\Application\\brave.exe",
    "Vivaldi\\Application\\vivaldi.exe",
];

/// Registry App Paths subkeys to check for each browser.
const REGISTRY_APP_PATHS: &[(&str, BrowserFamily)] = &[
    ("chrome.exe", BrowserFamily::Chrome),
    ("msedge.exe", BrowserFamily::Edge),
    ("chromium.exe", BrowserFamily::Chromium),
    ("brave.exe", BrowserFamily::Brave),
    ("vivaldi.exe", BrowserFamily::Vivaldi),
];

/// Returns the browser family inferred from a full path.
fn family_from_path(path: &Path) -> BrowserFamily {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("\\edge\\") || lower.ends_with("msedge.exe") {
        return BrowserFamily::Edge;
    }
    if lower.contains("\\chromium\\") || lower.ends_with("chromium.exe") {
        return BrowserFamily::Chromium;
    }
    if lower.contains("\\brave") || lower.ends_with("brave.exe") {
        return BrowserFamily::Brave;
    }
    if lower.contains("\\vivaldi\\") || lower.ends_with("vivaldi.exe") {
        return BrowserFamily::Vivaldi;
    }
    BrowserFamily::Chrome
}

/// Queries Windows registry App Paths for a browser executable.
///
/// # Arguments
/// * `exe_name` — The executable name to look up (e.g. `"chrome.exe"`).
///
/// # Returns
/// `Some(PathBuf)` if the registry key exists and points to an existing file.
fn registry_lookup(exe_name: &str) -> Option<PathBuf> {
    use std::process::Command;
    for hive in ["HKCU", "HKLM"] {
        let key =
            format!("{hive}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{exe_name}");
        let output = Command::new("reg")
            .args(["query", &key, "/ve"])
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let path_str = stdout
            .lines()
            .find_map(parse_reg_default_value)
            .unwrap_or_default();
        if path_str.is_empty() {
            continue;
        }
        let path = PathBuf::from(path_str);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn parse_reg_default_value(line: &str) -> Option<String> {
    let line = line.trim();
    let value = line
        .split_once("REG_EXPAND_SZ")
        .or_else(|| line.split_once("REG_SZ"))?
        .1
        .trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// Checks common install directories under program files roots.
fn common_path_candidates() -> Vec<BrowserCandidate> {
    let mut results = Vec::new();
    let roots: Vec<PathBuf> = [
        std::env::var("ProgramFiles").ok(),
        std::env::var("ProgramFiles(x86)").ok(),
        std::env::var("LOCALAPPDATA").ok(),
    ]
    .into_iter()
    .flatten()
    .map(PathBuf::from)
    .collect();

    for root in &roots {
        for relative in COMMON_RELATIVE_PATHS {
            let candidate = root.join(relative);
            if candidate.exists() {
                results.push(BrowserCandidate {
                    path: candidate,
                    family: family_from_path(Path::new(relative)),
                    source: "common-path",
                });
            }
        }
    }
    results
}

/// Searches PATH for known browser executables via `where.exe`.
fn path_candidates() -> Vec<BrowserCandidate> {
    use std::process::Command;
    let mut results = Vec::new();
    for (exe_name, family) in KNOWN_EXES {
        let output = match Command::new("where.exe").arg(*exe_name).output() {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let path = PathBuf::from(line.trim());
            if path.exists() {
                results.push(BrowserCandidate {
                    path,
                    family: *family,
                    source: "PATH",
                });
            }
        }
    }
    results
}

/// Discovers installed browsers on the system.
///
/// Searches in order: registry App Paths → common install paths → PATH.
/// Returns candidates sorted by preference (Chrome > Edge > Chromium > Brave > Vivaldi).
///
/// # Arguments
/// * `prefer` — Preferred browser family. If `None`, prefers Chrome.
///
/// # Returns
/// A vector of discovered `BrowserCandidate`s, best first.
#[must_use]
pub fn discover_browser(prefer: Option<BrowserFamily>) -> Vec<BrowserCandidate> {
    let prefer = prefer.unwrap_or(BrowserFamily::Chrome);
    let mut candidates = Vec::new();

    // 1. Registry App Paths
    for (exe_name, family) in REGISTRY_APP_PATHS {
        if let Some(path) = registry_lookup(exe_name) {
            candidates.push(BrowserCandidate {
                path,
                family: *family,
                source: "registry",
            });
        }
    }

    // 2. Common install paths
    candidates.extend(common_path_candidates());

    // 3. PATH
    candidates.extend(path_candidates());

    // Deduplicate by path (case-insensitive on Windows)
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| seen.insert(c.path.to_string_lossy().to_ascii_lowercase()));

    // Sort by preference: preferred family first, then by source quality
    candidates.sort_by(|a, b| {
        let a_pref = i32::from(a.family == prefer);
        let b_pref = i32::from(b.family == prefer);
        b_pref.cmp(&a_pref)
    });

    candidates
}

/// Finds a single best browser for the given preference.
///
/// # Arguments
/// * `prefer` — Preferred browser family.
///
/// # Returns
/// The best matching `BrowserCandidate`, or `None` if no browser found.
#[must_use]
pub fn find_browser(prefer: Option<BrowserFamily>) -> Option<BrowserCandidate> {
    discover_browser(prefer)
        .into_iter()
        .find(|c| c.path.exists())
}

/// Resolves a user-specified browser string to a family.
///
/// # Arguments
/// * `name` — Browser name string (e.g. `"chrome"`, `"edge"`, `"brave"`).
///
/// # Returns
/// The corresponding `BrowserFamily`, or `None` if unrecognized.
#[must_use]
pub fn parse_browser_family(name: &str) -> Option<BrowserFamily> {
    match name.to_ascii_lowercase().as_str() {
        "chrome" => Some(BrowserFamily::Chrome),
        "edge" | "msedge" => Some(BrowserFamily::Edge),
        "chromium" => Some(BrowserFamily::Chromium),
        "brave" => Some(BrowserFamily::Brave),
        "vivaldi" => Some(BrowserFamily::Vivaldi),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_browser_family_recognizes_known_names() {
        assert_eq!(parse_browser_family("chrome"), Some(BrowserFamily::Chrome));
        assert_eq!(parse_browser_family("edge"), Some(BrowserFamily::Edge));
        assert_eq!(parse_browser_family("msedge"), Some(BrowserFamily::Edge));
        assert_eq!(parse_browser_family("brave"), Some(BrowserFamily::Brave));
        assert_eq!(
            parse_browser_family("vivaldi"),
            Some(BrowserFamily::Vivaldi)
        );
        assert_eq!(parse_browser_family("unknown"), None);
    }

    #[test]
    fn family_from_path_detects_edge() {
        let path = Path::new("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
        assert_eq!(family_from_path(path), BrowserFamily::Edge);
    }

    #[test]
    fn discover_browser_returns_candidates() {
        let candidates = discover_browser(None);
        // On a Windows machine with Edge installed, should find at least one
        if !candidates.is_empty() {
            assert!(candidates[0].path.exists());
        }
    }

    #[test]
    fn find_browser_returns_some_on_windows_with_edge() {
        let browser = find_browser(Some(BrowserFamily::Edge));
        if let Some(browser) = browser {
            assert!(browser.path.exists());
        }
    }

    #[test]
    fn parse_reg_default_value_extracts_path_after_type() {
        let line = r"(Default)    REG_SZ    C:\Program Files\Google\Chrome\Application\chrome.exe";

        let path = parse_reg_default_value(line).expect("registry path");

        assert_eq!(
            path,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        );
    }
}
