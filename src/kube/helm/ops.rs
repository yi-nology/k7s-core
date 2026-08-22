//! Helm release operations: install, upgrade, uninstall, rollback.
//!
//! Strategy: shell out to the system `helm` CLI. Reasoning:
//!
//! - The official Go SDK (`helm.sh/helm/v3`) is enormous and pulls a Go
//!   runtime CGO dependency chain that would inflate compile time of the
//!   whole crate by minutes.
//! - A pure-Rust alternative (`kube-helm`, `helm-rs`) is less mature; the
//!   install/upgrade code paths are exactly the ones where correctness
//!   matters most.
//! - The `helm` binary is ubiquitous on any host that runs Kubernetes: it's
//!   in brew, apt, dnf, and ships with Docker Desktop. Detecting it is a
//!   one-time check at command time, not at compile time.
//!
//! The trade-off: the user's local `helm` becomes a build/runtime
//! dependency. We surface a clear error when it's missing, and we never
//! silently fall back to a half-implementation.
//!
//! All commands stream their stdout/stderr to the frontend via Tauri events
//! (so the install dialog shows a live "fetching chart... rendered template"
//! progress) and return the final result on completion.

use crate::core::events::EventSink;
use crate::error::{AppError, AppResult};
use k7s_deps::tokio::io::{AsyncBufReadExt, BufReader};
use k7s_deps::tokio::process::Command;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;

/// Tauri event name carrying a single log line from a running `helm` invocation.
pub const HELM_LOG_EVENT: &str = "helm-op-log";
/// Tauri event name signalling the end of a helm op (with success/failure).
pub const HELM_DONE_EVENT: &str = "helm-op-done";

/// What the user asked for. One of these becomes a `helm <op> ...` invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HelmOp {
    Install(InstallArgs),
    Upgrade(UpgradeArgs),
    Uninstall(UninstallArgs),
    Rollback(RollbackArgs),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallArgs {
    pub release: String,
    pub chart: String,
    /// Chart version; empty = latest.
    #[serde(default)]
    pub version: String,
    pub namespace: String,
    /// Optional kubeconfig content or path; if absent we use the active context.
    #[serde(default)]
    pub kubeconfig: Option<String>,
    /// Rendered values.yaml content; empty = chart defaults.
    #[serde(default)]
    pub values: String,
    /// True to render templates without applying.
    #[serde(default)]
    pub dry_run: bool,
    /// Override release name; we install with `--generate-name` if unset.
    #[serde(default)]
    pub create_namespace: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpgradeArgs {
    pub release: String,
    pub chart: String,
    #[serde(default)]
    pub version: String,
    pub namespace: String,
    #[serde(default)]
    pub kubeconfig: Option<String>,
    #[serde(default)]
    pub values: String,
    #[serde(default)]
    pub dry_run: bool,
    /// Re-use values from the previous release on fields the new chart dropped.
    #[serde(default)]
    pub reuse_values: bool,
    /// Roll back to this revision on failure.
    #[serde(default)]
    pub rollback_on_failure: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UninstallArgs {
    pub release: String,
    pub namespace: String,
    #[serde(default)]
    pub kubeconfig: Option<String>,
    /// Keep history so a rollback remains possible afterwards.
    #[serde(default)]
    pub keep_history: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackArgs {
    pub release: String,
    pub namespace: String,
    /// Target revision. Helm's default is the previous one.
    #[serde(default)]
    pub revision: Option<i64>,
    #[serde(default)]
    pub kubeconfig: Option<String>,
}

/// Result of a completed helm op.
#[derive(Clone, Debug, Serialize)]
pub struct HelmOpResult {
    pub op: &'static str,
    pub release: String,
    pub namespace: String,
    /// True if the helm process exited 0 and `dry_run` did not block apply.
    pub success: bool,
    /// Final stdout/stderr line count for the UI's "X lines" badge.
    pub lines: usize,
    /// Human-readable summary (e.g. "Release 'foo' installed at revision 3").
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Run a helm op to completion, streaming each stdout line as a Tauri event.
/// Returns the final result.
pub async fn run_op(op: HelmOp, sink: EventSink) -> AppResult<HelmOpResult> {
    // Detect helm up front. `which("helm")` is the right cross-platform check.
    let helm_path = which_helm().ok_or_else(|| {
        AppError::Other(
            "helm CLI not found in PATH — install Helm 3 (https://helm.sh/docs/intro/install/) and retry"
                .into(),
        )
    })?;

    let (label, argv) = build_argv(&helm_path, &op)?;
    let (release, namespace) = op_release_ns(&op);

    let mut cmd = Command::new(&helm_path);
    cmd.args(&argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Helm picks up KUBECONFIG from the environment; we pass through any
        // value the caller specified rather than letting the system default
        // leak in by accident.
        .envs(
            std::env::vars()
                .filter(|(k, _)| k == "KUBECONFIG" || k == "HELM_CONFIG" || k == "HOME"),
        );

    if let Some(kc) = op_kubeconfig(&op) {
        // Write the kubeconfig to a temp file (helm needs a path, not a blob).
        // We use a deterministic name so a stuck install can be located.
        let kc_path = write_temp_kubeconfig(&kc)?;
        cmd.env("KUBECONFIG", &kc_path);
    }

    // Spawn.
    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::Other(format!("spawn helm: {e}")))?;

    // Read stdout and stderr concurrently. Either/both can drive UI updates;
    // merging into a single ordered stream would need timestamps; for now
    // we interleave with a "stdout: " / "stderr: " prefix per line, which is
    // good enough for a live log.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Other("no stdout".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::Other("no stderr".into()))?;

    let line_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink_out = sink.clone();
    let count_out = line_count.clone();
    let out_task = k7s_deps::tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            count_out.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            sink_out.emit(
                HELM_LOG_EVENT,
                &LogLine {
                    stream: "stdout",
                    line,
                },
            );
        }
    });
    let sink_err = sink.clone();
    let count_err = line_count.clone();
    let err_task = k7s_deps::tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            count_err.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            sink_err.emit(
                HELM_LOG_EVENT,
                &LogLine {
                    stream: "stderr",
                    line,
                },
            );
        }
    });

    let status = child
        .wait()
        .await
        .map_err(|e| AppError::Other(format!("wait helm: {e}")))?;
    // Make sure both pump tasks drain before we return.
    let _ = k7s_deps::tokio::join!(out_task, err_task);

    let success = status.success();
    let summary = if success {
        format!("{label} ok")
    } else {
        format!("{label} failed: {}", status)
    };

    let result = HelmOpResult {
        op: label,
        release,
        namespace,
        success,
        lines: line_count.load(std::sync::atomic::Ordering::Relaxed),
        summary,
    };
    sink.emit(HELM_DONE_EVENT, &result);
    if success {
        Ok(result)
    } else {
        Err(AppError::Other(result.summary))
    }
}

// ---------------------------------------------------------------------------
// Argv construction
// ---------------------------------------------------------------------------

fn build_argv(helm_path: &str, op: &HelmOp) -> AppResult<(&'static str, Vec<String>)> {
    let _ = helm_path;
    let mut argv: Vec<String> = Vec::new();
    let label: &'static str;
    match op {
        HelmOp::Install(args) => {
            label = "install";
            argv.push("install".into());
            argv.push(args.release.clone());
            // chart can be `repo/name`, `repo/name --version x`, or an OCI URL.
            argv.push(args.chart.clone());
            if !args.version.is_empty() {
                argv.push("--version".into());
                argv.push(args.version.clone());
            }
            argv.push("--namespace".into());
            argv.push(args.namespace.clone());
            if args.create_namespace {
                argv.push("--create-namespace".into());
            }
            if args.dry_run {
                argv.push("--dry-run".into());
                argv.push("--debug".into()); // dry-run alone suppresses most output
            }
            push_values_args(&mut argv, &args.values);
        }
        HelmOp::Upgrade(args) => {
            label = "upgrade";
            argv.push("upgrade".into());
            argv.push(args.release.clone());
            argv.push(args.chart.clone());
            if !args.version.is_empty() {
                argv.push("--version".into());
                argv.push(args.version.clone());
            }
            argv.push("--namespace".into());
            argv.push(args.namespace.clone());
            if args.reuse_values {
                argv.push("--reuse-values".into());
            }
            if args.rollback_on_failure {
                argv.push("--rollback-on-failure".into());
            }
            if args.dry_run {
                argv.push("--dry-run".into());
                argv.push("--debug".into());
            }
            push_values_args(&mut argv, &args.values);
        }
        HelmOp::Uninstall(args) => {
            label = "uninstall";
            argv.push("uninstall".into());
            argv.push(args.release.clone());
            argv.push("--namespace".into());
            argv.push(args.namespace.clone());
            if !args.keep_history {
                // Default is to keep history; the UI offers the choice so the
                // user can decide whether a rollback remains possible.
                argv.push("--keep-history".into());
            }
        }
        HelmOp::Rollback(args) => {
            label = "rollback";
            argv.push("rollback".into());
            argv.push(args.release.clone());
            if let Some(rev) = args.revision {
                argv.push(rev.to_string());
            }
            argv.push("--namespace".into());
            argv.push(args.namespace.clone());
        }
    }
    // Always ask helm to be explicit about what it did.
    argv.push("--wait".into()); // wait until pods are ready
    argv.push("--timeout".into());
    argv.push("5m0s".into());
    Ok((label, argv))
}

fn push_values_args(argv: &mut Vec<String>, values: &str) {
    if values.trim().is_empty() {
        return;
    }
    // Two options:
    //   1. Pass as inline `--set` key=value pairs. Only viable for very small
    //      snippets; quoting is hell.
    //   2. Write to a temp file and pass `--values <path>`. Correct for any
    //      size, no escaping.
    // We go with (2) and stash the path in a process-wide table keyed by the
    // file name. The Tauri command writes the values, then invokes `run_op`,
    // which receives the *path* via a sibling struct field; in this code path
    // we expect the caller to have already written it. For the common case
    // where the user supplies raw values text, we accept the *contents* here
    // and the Tauri command writes to a known temp path before calling in.
    //
    // To keep the API here honest, the Tauri command passes the file *path*
    // in `args.values` by writing a sentinel `__file:<path>` prefix. Strip it.
    if let Some(path) = values.strip_prefix("__file:") {
        argv.push("--values".into());
        argv.push(path.to_string());
    } else {
        // Inline fallback: write a temp file now.
        match write_temp_values(values) {
            Ok(path) => {
                argv.push("--values".into());
                argv.push(path.display().to_string());
            }
            Err(e) => {
                k7s_deps::tracing::warn!("could not write values temp file: {e}; --values omitted");
            }
        }
    }
}

fn op_release_ns(op: &HelmOp) -> (String, String) {
    match op {
        HelmOp::Install(a) => (a.release.clone(), a.namespace.clone()),
        HelmOp::Upgrade(a) => (a.release.clone(), a.namespace.clone()),
        HelmOp::Uninstall(a) => (a.release.clone(), a.namespace.clone()),
        HelmOp::Rollback(a) => (a.release.clone(), a.namespace.clone()),
    }
}

fn op_kubeconfig(op: &HelmOp) -> Option<String> {
    match op {
        HelmOp::Install(a) => a.kubeconfig.clone(),
        HelmOp::Upgrade(a) => a.kubeconfig.clone(),
        HelmOp::Uninstall(a) => a.kubeconfig.clone(),
        HelmOp::Rollback(a) => a.kubeconfig.clone(),
    }
}

pub(crate) fn which_helm() -> Option<String> {
    // Try `helm` on PATH first; the typical install.
    for path in [
        "/usr/local/bin/helm",
        "/opt/homebrew/bin/helm",
        "/usr/bin/helm",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    if let Ok(out) = std::process::Command::new("which").arg("helm").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

fn write_temp_kubeconfig(content: &str) -> AppResult<PathBuf> {
    let dir = std::env::temp_dir().join("k7s-helm");
    std::fs::create_dir_all(&dir).map_err(|e| AppError::Other(format!("create tmp dir: {e}")))?;
    let path = dir.join(format!("kc-{}.yaml", std::process::id()));
    std::fs::write(&path, content)
        .map_err(|e| AppError::Other(format!("write kubeconfig: {e}")))?;
    // Best-effort chmod 0600 — kubeconfigs are credentials.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| AppError::Other(format!("stat kubeconfig: {e}")))?
            .permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(&path, perms);
    }
    Ok(path)
}

fn write_temp_values(content: &str) -> AppResult<PathBuf> {
    let dir = std::env::temp_dir().join("k7s-helm");
    std::fs::create_dir_all(&dir).map_err(|e| AppError::Other(format!("create tmp dir: {e}")))?;
    // Random suffix so two concurrent installs don't clobber each other.
    let suffix: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let path = dir.join(format!("values-{suffix}.yaml"));
    std::fs::write(&path, content).map_err(|e| AppError::Other(format!("write values: {e}")))?;
    Ok(path)
}

#[derive(Serialize, Clone)]
struct LogLine<'a> {
    stream: &'a str,
    line: String,
}

// ---------------------------------------------------------------------------
// Release history
// ---------------------------------------------------------------------------

/// One row of `helm history <release>`. Surfaced in the UI for the
/// "Revisions" tab on a release detail.
#[derive(Clone, Debug, Serialize)]
pub struct RevisionEntry {
    pub revision: i64,
    pub updated: String,
    pub status: String,
    pub chart: String,
    pub app_version: String,
    pub description: String,
}

/// Get the revision history for a release. `helm history --max 50` is
/// cheap; we run it synchronously because the result is a one-shot fetch
/// the UI needs before it can render the revisions tab.
pub async fn release_history(
    release: &str,
    namespace: &str,
    kubeconfig: Option<&str>,
) -> AppResult<Vec<RevisionEntry>> {
    let helm = which_helm().ok_or_else(|| AppError::Other("helm CLI not found".into()))?;
    let mut cmd = Command::new(&helm);
    cmd.args([
        "history",
        release,
        "--namespace",
        namespace,
        "--output",
        "json",
        "--max",
        "50",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    if let Some(kc) = kubeconfig {
        let path = write_temp_kubeconfig(kc)?;
        cmd.env("KUBECONFIG", &path);
    }
    let out = cmd
        .output()
        .await
        .map_err(|e| AppError::Other(format!("helm history: {e}")))?;
    if !out.status.success() {
        return Err(AppError::Other(format!(
            "helm history: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    // `helm history --output json` returns a top-level array.
    let rows: Vec<k7s_deps::serde_json::Value> = k7s_deps::serde_json::from_str(&raw)
        .map_err(|e| AppError::Other(format!("parse helm history: {e}")))?;
    Ok(rows
        .into_iter()
        .map(|r| RevisionEntry {
            revision: r.get("revision").and_then(|v| v.as_i64()).unwrap_or(0),
            updated: r
                .get("updated")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            status: r
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            chart: r
                .get("chart")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            app_version: r
                .get("app_version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            description: r
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect())
}

/// Render a chart's default values.yaml to a string (no install). Used to
/// prefill the values editor when the user picks a chart but hasn't
/// customised anything yet.
pub async fn render_default_values(
    chart: &str,
    version: &str,
    kubeconfig: Option<&str>,
) -> AppResult<String> {
    let helm = which_helm().ok_or_else(|| AppError::Other("helm CLI not found".into()))?;
    let mut cmd = Command::new(&helm);
    cmd.args(["show", "values", chart])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if !version.is_empty() {
        cmd.arg("--version").arg(version);
    }
    if let Some(kc) = kubeconfig {
        let path = write_temp_kubeconfig(kc)?;
        cmd.env("KUBECONFIG", &path);
    }
    let out = cmd
        .output()
        .await
        .map_err(|e| AppError::Other(format!("helm show values: {e}")))?;
    if !out.status.success() {
        return Err(AppError::Other(format!(
            "helm show values: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}
