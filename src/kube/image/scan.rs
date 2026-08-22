//! Container image vulnerability scanning via the system `trivy` / `grype` CLIs.
//!
//! Air-gapped clusters still run images that may ship with known CVEs.  This
//! module shells out to whichever scanner is installed (preferring trivy,
//! falling back to grype) and normalises the JSON output into a common
//! `ScanResult` that the frontend can render without caring about the engine.
//!
//! Why a CLI shim rather than a library:
//!
//! - mirrors the established pattern from `image_sync.rs` (shelling out to
//!   skopeo) and `helm_ops.rs` — detect binary, spawn, pump stdout/stderr to
//!   the event sink, collect JSON result.
//! - trivy and grype both have excellent CLI output formats that are stable
//!   across versions; a Rust binding would be an extra dependency with limited
//!   upside.
//! - the host running the MCP server needs the scanner binary on its PATH;
//!   `which_trivy()` / `which_grype()` detect availability up front so the
//!   caller can surface a clear "install trivy or grype" message.

use crate::core::events::EventSink;
use crate::error::{AppError, AppResult};
use k7s_deps::tokio::io::{AsyncBufReadExt, BufReader};
use k7s_deps::tokio::process::Command;
use serde::Serialize;
use std::process::Stdio;

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
// Core scan function
// ---------------------------------------------------------------------------

/// Scan a container image for vulnerabilities using the specified engine.
///
/// `engine` must be `"trivy"` or `"grype"`. `image_ref` is the target image —
/// either a bare reference like `nginx:1.25` or a full `docker://host/repo:tag`
/// transport string. Progress lines are streamed to the UI via the event sink.
pub async fn scan_image(engine: &str, image_ref: &str, sink: EventSink) -> AppResult<ScanResult> {
    scan_image_with_prefs(engine, image_ref, sink, None, None, None).await
}

/// Like `scan_image`, but honours user-configured binary paths and timeout.
/// Any `None` field falls back to auto-detection / default.
pub async fn scan_image_with_prefs(
    engine: &str,
    image_ref: &str,
    sink: EventSink,
    custom_trivy_path: Option<&str>,
    custom_grype_path: Option<&str>,
    timeout: Option<&str>,
) -> AppResult<ScanResult> {
    let timeout = timeout.filter(|s| !s.trim().is_empty()).unwrap_or("5m");
    match engine {
        "trivy" => {
            let trivy = resolve_binary(custom_trivy_path, "trivy", which_trivy)?;
            scan_with_trivy(&trivy, image_ref, sink, timeout).await
        }
        "grype" => {
            let grype = resolve_binary(custom_grype_path, "grype", which_grype)?;
            scan_with_grype(&grype, image_ref, sink).await
        }
        other => Err(AppError::Other(format!(
            "unknown scan engine '{other}' — expected 'trivy' or 'grype'"
        ))),
    }
}

/// Resolve a binary path: custom > auto-detected.
fn resolve_binary(
    custom: Option<&str>,
    name: &str,
    auto_detect: fn() -> Option<String>,
) -> AppResult<String> {
    if let Some(p) = custom {
        let trimmed = p.trim();
        if !trimmed.is_empty() && std::path::Path::new(trimmed).is_file() {
            return Ok(trimmed.to_string());
        }
    }
    auto_detect().ok_or_else(|| {
        AppError::Other(format!(
            "{name} CLI not found on PATH — install {name} and retry"
        ))
    })
}

// ---------------------------------------------------------------------------
// Trivy implementation
// ---------------------------------------------------------------------------

async fn scan_with_trivy(
    trivy: &str,
    image_ref: &str,
    sink: EventSink,
    timeout: &str,
) -> AppResult<ScanResult> {
    let mut cmd = Command::new(trivy);
    cmd.args(["image", "--format", "json", "--quiet", "--timeout", timeout])
        .arg(image_ref)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(std::env::vars().filter(|(k, _)| k == "HOME" || k == "PATH"));

    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::Other(format!("spawn trivy: {e}")))?;

    // Collect stdout (the JSON result) while pumping stderr (progress) to the sink.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Other("no stdout from trivy".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::Other("no stderr from trivy".into()))?;

    // Pump stderr lines to the event sink.
    let sink_err = sink.clone();
    let err_task = k7s_deps::tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            sink_err.emit(
                IMAGE_SCAN_LOG_EVENT,
                &LogLine {
                    engine: "trivy",
                    stream: "stderr",
                    line,
                },
            );
        }
    });

    // Read all of stdout into a buffer — trivy --quiet prints the JSON report
    // to stdout and nothing else.
    let stdout_bytes = {
        use k7s_deps::tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut reader = BufReader::new(stdout);
        reader
            .read_to_end(&mut buf)
            .await
            .map_err(|e| AppError::Other(format!("read trivy stdout: {e}")))?;
        buf
    };

    let status = child
        .wait()
        .await
        .map_err(|e| AppError::Other(format!("wait trivy: {e}")))?;
    let _ = k7s_deps::tokio::join!(err_task);

    if !status.success() {
        let msg = format!("trivy exited with {status}");
        sink.emit(
            IMAGE_SCAN_LOG_EVENT,
            &LogLine {
                engine: "trivy",
                stream: "stderr",
                line: msg.clone(),
            },
        );
        return Err(AppError::Other(msg));
    }

    let report: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_slice(&stdout_bytes)
        .map_err(|e| AppError::Other(format!("parse trivy JSON: {e}")))?;

    let result = parse_trivy_report(image_ref, &report)?;
    sink.emit(IMAGE_SCAN_DONE_EVENT, &result);
    Ok(result)
}

/// Parse the trivy JSON report into our common `ScanResult`.
fn parse_trivy_report(
    image_ref: &str,
    report: &k7s_deps::serde_json::Value,
) -> AppResult<ScanResult> {
    let mut vulns = Vec::new();
    let results = report
        .get("Results")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for result_group in &results {
        let Some(vuln_list) = result_group
            .get("Vulnerabilities")
            .and_then(|v| v.as_array())
        else {
            continue;
        };
        for v in vuln_list {
            let id = v
                .get("VulnerabilityID")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let severity = v
                .get("Severity")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let pkg_name = v
                .get("PkgName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let installed_version = v
                .get("InstalledVersion")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let fixed_version = v
                .get("FixedVersion")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let title = v
                .get("Title")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let description = v
                .get("Description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut references = Vec::new();
            if let Some(url) = v.get("PrimaryURL").and_then(|v| v.as_str()) {
                if !url.is_empty() {
                    references.push(url.to_string());
                }
            }
            if let Some(refs) = v.get("References").and_then(|v| v.as_array()) {
                for r in refs {
                    if let Some(url) = r.as_str() {
                        references.push(url.to_string());
                    }
                }
            }

            vulns.push(Vulnerability {
                id,
                severity,
                pkg_name,
                installed_version,
                fixed_version,
                title,
                description,
                references,
            });
        }
    }

    let summary = build_summary(&vulns);
    Ok(ScanResult {
        target: image_ref.to_string(),
        engine: "trivy".to_string(),
        summary,
        vulnerabilities: vulns,
        scanned_at: k7s_deps::chrono::Utc::now().to_rfc3339(),
    })
}

// ---------------------------------------------------------------------------
// Grype implementation
// ---------------------------------------------------------------------------

async fn scan_with_grype(grype: &str, image_ref: &str, sink: EventSink) -> AppResult<ScanResult> {
    let mut cmd = Command::new(grype);
    cmd.args([image_ref, "-o", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(std::env::vars().filter(|(k, _)| k == "HOME" || k == "PATH"));

    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::Other(format!("spawn grype: {e}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Other("no stdout from grype".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::Other("no stderr from grype".into()))?;

    // Pump stderr lines to the event sink.
    let sink_err = sink.clone();
    let err_task = k7s_deps::tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            sink_err.emit(
                IMAGE_SCAN_LOG_EVENT,
                &LogLine {
                    engine: "grype",
                    stream: "stderr",
                    line,
                },
            );
        }
    });

    // Read all of stdout.
    let stdout_bytes = {
        use k7s_deps::tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut reader = BufReader::new(stdout);
        reader
            .read_to_end(&mut buf)
            .await
            .map_err(|e| AppError::Other(format!("read grype stdout: {e}")))?;
        buf
    };

    let status = child
        .wait()
        .await
        .map_err(|e| AppError::Other(format!("wait grype: {e}")))?;
    let _ = k7s_deps::tokio::join!(err_task);

    if !status.success() {
        let msg = format!("grype exited with {status}");
        sink.emit(
            IMAGE_SCAN_LOG_EVENT,
            &LogLine {
                engine: "grype",
                stream: "stderr",
                line: msg.clone(),
            },
        );
        return Err(AppError::Other(msg));
    }

    let report: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_slice(&stdout_bytes)
        .map_err(|e| AppError::Other(format!("parse grype JSON: {e}")))?;

    let result = parse_grype_report(image_ref, &report)?;
    sink.emit(IMAGE_SCAN_DONE_EVENT, &result);
    Ok(result)
}

/// Parse the grype JSON report into our common `ScanResult`.
fn parse_grype_report(
    image_ref: &str,
    report: &k7s_deps::serde_json::Value,
) -> AppResult<ScanResult> {
    let mut vulns = Vec::new();
    let matches = report
        .get("matches")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for m in &matches {
        let vulnerability = m.get("vulnerability");
        let artifact = m.get("artifact");

        let id = vulnerability
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let severity = vulnerability
            .and_then(|v| v.get("severity"))
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();
        let description = vulnerability
            .and_then(|v| v.get("description"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let pkg_name = artifact
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let installed_version = artifact
            .and_then(|v| v.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // grype puts fix info in vulnerability.fix.versions (an array).
        let fixed_version = vulnerability
            .and_then(|v| v.get("fix"))
            .and_then(|v| v.get("versions"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Collect reference URLs.
        let mut references = Vec::new();
        if let Some(urls) = vulnerability
            .and_then(|v| v.get("urls"))
            .and_then(|v| v.as_array())
        {
            for url in urls {
                if let Some(s) = url.as_str() {
                    references.push(s.to_string());
                }
            }
        }
        // grype also stores a Data.namespace that sometimes contains the advisory URL.
        if let Some(data) = m
            .get("matchDetails")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
        {
            if let Some(matched_on) = data.get("matchedOn").and_then(|v| v.as_object()) {
                if let Some(v) = matched_on.get("vulnerabilityID").and_then(|v| v.as_str()) {
                    if !v.is_empty() && v.starts_with("http") {
                        references.push(v.to_string());
                    }
                }
            }
        }

        vulns.push(Vulnerability {
            id,
            severity: severity.to_uppercase(),
            pkg_name,
            installed_version,
            fixed_version,
            title: String::new(), // grype doesn't provide a separate title field
            description,
            references,
        });
    }

    let summary = build_summary(&vulns);
    Ok(ScanResult {
        target: image_ref.to_string(),
        engine: "grype".to_string(),
        summary,
        vulnerabilities: vulns,
        scanned_at: k7s_deps::chrono::Utc::now().to_rfc3339(),
    })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Build a `ScanSummary` by counting severities across the vulnerability list.
fn build_summary(vulns: &[Vulnerability]) -> ScanSummary {
    let mut summary = ScanSummary::default();
    for v in vulns {
        match v.severity.to_uppercase().as_str() {
            "CRITICAL" => summary.critical += 1,
            "HIGH" => summary.high += 1,
            "MEDIUM" => summary.medium += 1,
            "LOW" => summary.low += 1,
            _ => {} // UNKNOWN / NEGLIGIBLE — not counted in severity buckets
        }
    }
    summary.total = summary.critical + summary.high + summary.medium + summary.low;
    summary
}

#[derive(Serialize, Clone)]
struct LogLine<'a> {
    engine: &'a str,
    stream: &'a str,
    line: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Scanner status types — used by web handlers and Tauri commands
// ---------------------------------------------------------------------------

/// Information about a single scanning engine.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerEngineInfo {
    /// Engine name: "trivy", "grype", or "native".
    pub name: String,
    /// Whether this engine is currently available (binary found or built-in).
    pub available: bool,
    /// Resolved binary path, or None for native (built-in).
    pub path: Option<String>,
    /// Whether the user can configure a custom path for this engine.
    pub configurable: bool,
    /// Source of the path: "configured" (user-set) or "auto-detected".
    pub path_source: String,
}

/// Overall scanner status returned to the frontend.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerStatus {
    /// All known engines, in fallback priority order.
    pub engines: Vec<ScannerEngineInfo>,
    /// The engine that would be used for the next scan: "trivy", "grype", or "native".
    pub active_engine: String,
    /// Configured timeout (e.g. "5m"), or the default.
    pub timeout: String,
}

/// Resolve the trivy path: user-configured > auto-detected.
pub fn resolve_trivy(prefs_trivy_path: Option<&str>) -> (Option<String>, String) {
    if let Some(custom) = prefs_trivy_path {
        let trimmed = custom.trim();
        if !trimmed.is_empty() && std::path::Path::new(trimmed).is_file() {
            return (Some(trimmed.to_string()), "configured".to_string());
        }
    }
    (which_trivy(), "auto-detected".to_string())
}

/// Resolve the grype path: user-configured > auto-detected.
pub fn resolve_grype(prefs_grype_path: Option<&str>) -> (Option<String>, String) {
    if let Some(custom) = prefs_grype_path {
        let trimmed = custom.trim();
        if !trimmed.is_empty() && std::path::Path::new(trimmed).is_file() {
            return (Some(trimmed.to_string()), "configured".to_string());
        }
    }
    (which_grype(), "auto-detected".to_string())
}

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

    #[test]
    fn build_summary_counts_severities() {
        let vulns = vec![
            Vulnerability {
                id: "CVE-1".into(),
                severity: "CRITICAL".into(),
                pkg_name: "a".into(),
                installed_version: "1".into(),
                fixed_version: None,
                title: "".into(),
                description: "".into(),
                references: vec![],
            },
            Vulnerability {
                id: "CVE-2".into(),
                severity: "HIGH".into(),
                pkg_name: "b".into(),
                installed_version: "1".into(),
                fixed_version: None,
                title: "".into(),
                description: "".into(),
                references: vec![],
            },
            Vulnerability {
                id: "CVE-3".into(),
                severity: "MEDIUM".into(),
                pkg_name: "c".into(),
                installed_version: "1".into(),
                fixed_version: None,
                title: "".into(),
                description: "".into(),
                references: vec![],
            },
            Vulnerability {
                id: "CVE-4".into(),
                severity: "LOW".into(),
                pkg_name: "d".into(),
                installed_version: "1".into(),
                fixed_version: None,
                title: "".into(),
                description: "".into(),
                references: vec![],
            },
            Vulnerability {
                id: "CVE-5".into(),
                severity: "CRITICAL".into(),
                pkg_name: "e".into(),
                installed_version: "1".into(),
                fixed_version: None,
                title: "".into(),
                description: "".into(),
                references: vec![],
            },
        ];
        let summary = build_summary(&vulns);
        assert_eq!(summary.critical, 2);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.total, 5);
    }

    #[test]
    fn build_summary_handles_case_insensitive_severity() {
        let vulns = vec![Vulnerability {
            id: "CVE-1".into(),
            severity: "critical".into(),
            pkg_name: "a".into(),
            installed_version: "1".into(),
            fixed_version: None,
            title: "".into(),
            description: "".into(),
            references: vec![],
        }];
        let summary = build_summary(&vulns);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.total, 1);
    }

    #[test]
    fn parse_trivy_report_extracts_vulns() {
        let json = k7s_deps::serde_json::json!({
            "Results": [
                {
                    "Target": "nginx:1.25 (debian 12.0)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-12345",
                            "PkgName": "libssl3",
                            "InstalledVersion": "3.0.9-1",
                            "FixedVersion": "3.0.10-1",
                            "Title": "OpenSSL buffer overflow",
                            "Description": "A buffer overflow in OpenSSL ...",
                            "Severity": "CRITICAL",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
                            "References": ["https://example.com/advisory"]
                        }
                    ]
                }
            ]
        });
        let result = parse_trivy_report("nginx:1.25", &json).unwrap();
        assert_eq!(result.engine, "trivy");
        assert_eq!(result.target, "nginx:1.25");
        assert_eq!(result.vulnerabilities.len(), 1);
        let v = &result.vulnerabilities[0];
        assert_eq!(v.id, "CVE-2023-12345");
        assert_eq!(v.severity, "CRITICAL");
        assert_eq!(v.pkg_name, "libssl3");
        assert_eq!(v.installed_version, "3.0.9-1");
        assert_eq!(v.fixed_version.as_deref(), Some("3.0.10-1"));
        assert_eq!(v.title, "OpenSSL buffer overflow");
        assert_eq!(result.summary.critical, 1);
        assert_eq!(result.summary.total, 1);
    }

    #[test]
    fn parse_grype_report_extracts_vulns() {
        let json = k7s_deps::serde_json::json!({
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2023-99999",
                        "severity": "High",
                        "description": "A test vulnerability",
                        "fix": {
                            "versions": ["1.2.3-4"],
                            "state": "fixed"
                        },
                        "urls": ["https://example.com/CVE-2023-99999"]
                    },
                    "artifact": {
                        "name": "openssl",
                        "version": "1.1.1k-1"
                    },
                    "matchDetails": []
                }
            ]
        });
        let result = parse_grype_report("nginx:1.25", &json).unwrap();
        assert_eq!(result.engine, "grype");
        assert_eq!(result.vulnerabilities.len(), 1);
        let v = &result.vulnerabilities[0];
        assert_eq!(v.id, "CVE-2023-99999");
        assert_eq!(v.severity, "HIGH");
        assert_eq!(v.pkg_name, "openssl");
        assert_eq!(v.installed_version, "1.1.1k-1");
        assert_eq!(v.fixed_version.as_deref(), Some("1.2.3-4"));
        assert_eq!(result.summary.high, 1);
        assert_eq!(result.summary.total, 1);
    }

    #[test]
    fn parse_trivy_report_handles_empty_results() {
        let json = k7s_deps::serde_json::json!({ "Results": [] });
        let result = parse_trivy_report("alpine:3.18", &json).unwrap();
        assert_eq!(result.vulnerabilities.len(), 0);
        assert_eq!(result.summary.total, 0);
    }

    #[test]
    fn parse_grype_report_handles_empty_matches() {
        let json = k7s_deps::serde_json::json!({ "matches": [] });
        let result = parse_grype_report("alpine:3.18", &json).unwrap();
        assert_eq!(result.vulnerabilities.len(), 0);
        assert_eq!(result.summary.total, 0);
    }
}
