//! Scanner (trivy / grype) detection and shared image-reference helpers.
//!
//! The actual scanning/SBOM pipelines live in `security/sbom.rs` (SBOM with
//! three-tier fallback) and `k7s-commands/commands/scanner.rs` (status UI).
//! This module keeps what those callers share:
//!
//! - binary detection (`which_trivy` / `which_grype` / `check_scanners`);
//! - the common result types (`ScanResult` / `ScanSummary` / `Vulnerability`);
//! - registry-URL → `docker://` reference construction.
//!
//! A former `scan_image` entry point (and its trivy/grype JSON parsers) was
//! removed: every transport scans through `security::sbom` instead, so the
//! duplicate path here had no callers left.

use serde::Serialize;

// ---------------------------------------------------------------------------
// Event names
// ---------------------------------------------------------------------------

/// Tauri event name carrying one stdout/stderr line from a running scan.
pub const IMAGE_SCAN_LOG_EVENT: &str = "image-scan-log";
/// Tauri event name signalling the end of a scan (with success/failure).
pub const IMAGE_SCAN_DONE_EVENT: &str = "image-scan-done";

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Which scanning engine to use.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanEngine {
    Trivy,
    Grype,
}

/// Whether trivy / grype are available on this host.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanAvailability {
    pub trivy: bool,
    pub grype: bool,
    /// Resolved binary path for trivy, or None when not found.
    pub trivy_path: Option<String>,
    /// Resolved binary path for grype, or None when not found.
    pub grype_path: Option<String>,
}

/// The result of a completed image scan.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    /// The image reference that was scanned (e.g. `docker://harbor.local/library/nginx:1.25`).
    pub target: String,
    /// Which engine produced the result: `"trivy"` or `"grype"`.
    pub engine: String,
    /// Severity counts.
    pub summary: ScanSummary,
    /// Individual vulnerability entries.
    pub vulnerabilities: Vec<Vulnerability>,
    /// ISO 8601 timestamp of when the scan completed.
    pub scanned_at: String,
}

/// Severity counts rolled up from the vulnerability list.
#[derive(Clone, Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub total: u32,
}

/// A single vulnerability finding.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    /// CVE identifier (e.g. `CVE-2023-12345`).
    pub id: String,
    /// Normalised severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
    pub severity: String,
    /// Affected package name.
    pub pkg_name: String,
    /// Currently installed version.
    pub installed_version: String,
    /// Version that fixes the vulnerability, if available.
    pub fixed_version: Option<String>,
    /// Short human-readable title.
    pub title: String,
    /// Longer description.
    pub description: String,
    /// Upstream reference URLs.
    pub references: Vec<String>,
}

// ---------------------------------------------------------------------------
// Engine detection
// ---------------------------------------------------------------------------

/// Detect the trivy binary. Checks conventional install locations first (so a
/// Homebrew/macOS host doesn't pay a `which` spawn), then falls back to
/// `$PATH`. Returns None when trivy isn't installed.
pub fn which_trivy() -> Option<String> {
    for path in [
        "/usr/local/bin/trivy",
        "/opt/homebrew/bin/trivy",
        "/usr/bin/trivy",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    // Last resort: ask the shell. `which` is ubiquitous and cheap.
    if let Ok(out) = std::process::Command::new("which").arg("trivy").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// Detect the grype binary. Same strategy as `which_trivy`.
pub fn which_grype() -> Option<String> {
    for path in [
        "/usr/local/bin/grype",
        "/opt/homebrew/bin/grype",
        "/usr/bin/grype",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    // Last resort: ask the shell.
    if let Ok(out) = std::process::Command::new("which").arg("grype").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// Synchronous convenience alias — the underlying `check_scanners()` is already
/// non-async, but this name makes the intent clearer at call sites that expect
/// a `_sync` suffix (e.g. Tauri commands).
pub fn check_scanners_sync() -> ScanAvailability {
    check_scanners()
}

/// Probe availability of both trivy and grype. Cheap to call (just checks for
/// the binary on disk), so the frontend can call it on every invocation.
pub fn check_scanners() -> ScanAvailability {
    let trivy_path = which_trivy();
    let grype_path = which_grype();
    ScanAvailability {
        trivy: trivy_path.is_some(),
        grype: grype_path.is_some(),
        trivy_path,
        grype_path,
    }
}

// ---------------------------------------------------------------------------
// Image reference helpers
// ---------------------------------------------------------------------------

/// Strip the `https://` / `http://` scheme and any trailing slash from a
/// registry URL, leaving the bare `host[:port]` that a docker transport needs.
///
/// This mirrors `sync::registry_host()` — kept as a re-export so callers
/// of this module don't need to depend on `image_sync` directly.
pub use crate::kube::image::sync::registry_host;

/// Build a `docker://` image reference suitable for passing to trivy or grype.
///
/// Given a registry URL (with or without scheme), a repository path, and a tag,
/// constructs the canonical `docker://host/repo:tag` form.
pub fn build_image_ref(registry_url: &str, repo: &str, tag: &str) -> String {
    let host = registry_host(registry_url);
    let repo = repo.trim_start_matches('/');
    if tag.is_empty() {
        format!("docker://{host}/{repo}")
    } else {
        format!("docker://{host}/{repo}:{tag}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_image_ref_joins_host_repo_tag() {
        assert_eq!(
            build_image_ref("https://harbor.example.com", "library/nginx", "1.25"),
            "docker://harbor.example.com/library/nginx:1.25"
        );
    }

    #[test]
    fn build_image_ref_omits_colon_when_tag_empty() {
        assert_eq!(
            build_image_ref("https://reg.local", "app", ""),
            "docker://reg.local/app"
        );
    }

    #[test]
    fn build_image_ref_dedupes_leading_slash_in_repo() {
        assert_eq!(
            build_image_ref("http://reg.local:5000", "/library/nginx", "v1"),
            "docker://reg.local:5000/library/nginx:v1"
        );
    }

    #[test]
    fn build_image_ref_strips_scheme_and_trailing_slash() {
        assert_eq!(
            build_image_ref("https://reg.local/", "myapp", "latest"),
            "docker://reg.local/myapp:latest"
        );
        assert_eq!(
            build_image_ref("http://reg.local:5000/", "myapp", "v2"),
            "docker://reg.local:5000/myapp:v2"
        );
    }

    #[test]
    fn build_image_ref_no_scheme_passthrough() {
        assert_eq!(
            build_image_ref("reg.local:5000", "myapp", "v1"),
            "docker://reg.local:5000/myapp:v1"
        );
    }
}
