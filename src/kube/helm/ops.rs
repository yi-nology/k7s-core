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
    /// `repo/name`, an OCI URL, or a local absolute path (`.tgz` or unpacked
    /// directory) — helm natively accepts all three, so no argv branch needed.
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
    /// Create the target namespace if it does not exist (`--create-namespace`).
    #[serde(default)]
    pub create_namespace: bool,
    /// Extra overrides; each key expands to one `--set k=v` pair.
    #[serde(default)]
    pub set: Option<k7s_deps::serde_json::Map<String, k7s_deps::serde_json::Value>>,
    /// True to roll back automatically on failure (`--atomic`).
    #[serde(default)]
    pub atomic: bool,
    /// Overrides the default 5m0s helm timeout.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
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
    /// Create the target namespace if it does not exist (`--create-namespace`).
    #[serde(default)]
    pub create_namespace: bool,
    /// Extra overrides; each key expands to one `--set k=v` pair.
    #[serde(default)]
    pub set: Option<k7s_deps::serde_json::Map<String, k7s_deps::serde_json::Value>>,
    /// True to roll back automatically on failure (`--atomic`).
    #[serde(default)]
    pub atomic: bool,
    /// Force resource updates through the replacement strategy (`--force`).
    #[serde(default)]
    pub force: bool,
    /// Overrides the default 5m0s helm timeout.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
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

    // Guards for every temp credential/values file this op creates. They live
    // here (not inside `build_argv`) so they drop only when `run_op` returns —
    // after helm has finished reading them.
    let mut temp_files: Vec<TempHelmFile> = Vec::new();
    let (label, argv) = build_argv(&helm_path, &op, &mut temp_files)?;
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
        // Write the kubeconfig to a 0600 temp file (helm needs a path, not a
        // blob). The guard deletes it when `run_op` returns so the credential
        // never outlives the operation.
        let kc_file = write_temp_kubeconfig(&kc)?;
        cmd.env("KUBECONFIG", kc_file.path());
        temp_files.push(kc_file);
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

fn build_argv(
    helm_path: &str,
    op: &HelmOp,
    temp_files: &mut Vec<TempHelmFile>,
) -> AppResult<(&'static str, Vec<String>)> {
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
            push_set_args(&mut argv, &args.set);
            if args.atomic {
                argv.push("--atomic".into());
            }
            push_values_args(&mut argv, &args.values, temp_files);
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
            push_set_args(&mut argv, &args.set);
            if args.atomic {
                argv.push("--atomic".into());
            }
            if args.force {
                argv.push("--force".into());
            }
            if args.create_namespace {
                argv.push("--create-namespace".into());
            }
            push_values_args(&mut argv, &args.values, temp_files);
        }
        HelmOp::Uninstall(args) => {
            label = "uninstall";
            argv.push("uninstall".into());
            argv.push(args.release.clone());
            argv.push("--namespace".into());
            argv.push(args.namespace.clone());
            if args.keep_history {
                // Helm deletes release history by default; --keep-history
                // opts out so a rollback stays possible after uninstall.
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
    argv.push(timeout_arg(install_or_upgrade_timeout_secs(op)));
    Ok((label, argv))
}

const DEFAULT_HELM_TIMEOUT: &str = "5m0s";

/// `--timeout 0s` makes helm wait *forever*, and a 0 arriving over the wire
/// means "unset" — clamp it to the default along with `None`.
fn timeout_arg(secs: Option<u64>) -> String {
    secs.filter(|s| *s > 0)
        .map(|s| format!("{s}s"))
        .unwrap_or_else(|| DEFAULT_HELM_TIMEOUT.to_string())
}

/// `Rollback`/`Uninstall` carry no timeout field and keep the default.
fn install_or_upgrade_timeout_secs(op: &HelmOp) -> Option<u64> {
    match op {
        HelmOp::Install(a) => a.timeout_secs,
        HelmOp::Upgrade(a) => a.timeout_secs,
        _ => None,
    }
}

/// `--set k=v` per top-level key. Objects/arrays serialise to JSON strings —
/// helm understands `--set a={"b":1}` well enough for scalars; complex nests
/// should go through `values` (the temp-file path) instead.
fn push_set_args(
    argv: &mut Vec<String>,
    set: &Option<k7s_deps::serde_json::Map<String, k7s_deps::serde_json::Value>>,
) {
    let Some(map) = set else { return };
    for (k, v) in map {
        let val = match v {
            k7s_deps::serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        argv.push("--set".into());
        argv.push(format!("{k}={val}"));
    }
}

fn push_values_args(argv: &mut Vec<String>, values: &str, temp_files: &mut Vec<TempHelmFile>) {
    if values.trim().is_empty() {
        return;
    }
    // Two options:
    //   1. Pass as inline `--set` key=value pairs. Only viable for very small
    //      snippets; quoting is hell.
    //   2. Write to a temp file and pass `--values <path>`. Correct for any
    //      size, no escaping.
    // We go with (2). The Tauri command may have already written the values
    // itself and passes the *path* via a `__file:<path>` sentinel; strip it —
    // that file is caller-managed, so no guard is taken for it.
    if let Some(path) = values.strip_prefix("__file:") {
        argv.push("--values".into());
        argv.push(path.to_string());
    } else {
        // Inline fallback: write a temp file now. Its guard moves into
        // `temp_files` so the file survives until the op finishes (helm reads
        // it after `run_op` spawns the process).
        match write_temp_values(values) {
            Ok(guard) => {
                argv.push("--values".into());
                argv.push(guard.path().display().to_string());
                temp_files.push(guard);
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

/// RAII guard over a temp file holding helm credentials or chart values.
///
/// The previous helpers returned plain paths and left deletion to the caller,
/// so any early return between write and cleanup leaked a kubeconfig in the
/// temp dir. Mirrors `image::sync::AuthFileGuard`: the file is created with
/// `create_new` and mode 0600 (atomic on unix — no chmod window where the
/// credential is world-readable), the uuid suffix keeps concurrent ops from
/// clobbering each other, and `Drop` removes it on every exit path.
struct TempHelmFile {
    path: PathBuf,
}

impl TempHelmFile {
    fn create(kind: &str, ext: &str, content: &str) -> AppResult<Self> {
        let dir = std::env::temp_dir().join("k7s-helm");
        std::fs::create_dir_all(&dir)
            .map_err(|e| AppError::Other(format!("create tmp dir: {e}")))?;
        let path = dir.join(format!("{kind}-{}.{ext}", k7s_deps::uuid::Uuid::new_v4()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // 0600 from the moment the inode exists: a kubeconfig is a
            // credential, and setting permissions after creation would leave
            // a window where other local users can read it.
            opts.mode(0o600);
        }
        use std::io::Write as _;
        let mut file = opts
            .open(&path)
            .map_err(|e| AppError::Other(format!("create {kind} temp file: {e}")))?;
        file.write_all(content.as_bytes())
            .map_err(|e| AppError::Other(format!("write {kind} temp file: {e}")))?;
        Ok(Self { path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempHelmFile {
    fn drop(&mut self) {
        // Best-effort: a missing file is fine (already reaped); anything else
        // is logged — Drop can't propagate errors.
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                k7s_deps::tracing::warn!(
                    "failed to remove helm temp file {}: {e}",
                    self.path.display()
                );
            }
        }
    }
}

fn write_temp_kubeconfig(content: &str) -> AppResult<TempHelmFile> {
    TempHelmFile::create("kc", "yaml", content)
}

fn write_temp_values(content: &str) -> AppResult<TempHelmFile> {
    TempHelmFile::create("values", "yaml", content)
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
    // Guard must outlive `cmd.output()` below — helm reads the kubeconfig
    // while the process runs; it drops (deleting the file) after the result.
    let kc_guard = kubeconfig.map(write_temp_kubeconfig).transpose()?;
    if let Some(g) = &kc_guard {
        cmd.env("KUBECONFIG", g.path());
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
    // Same lifetime rule as `release_history`: guard drops after `output()`.
    let kc_guard = kubeconfig.map(write_temp_kubeconfig).transpose()?;
    if let Some(g) = &kc_guard {
        cmd.env("KUBECONFIG", g.path());
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

// ---------------------------------------------------------------------------
// Offline template rendering (`helm template`)
// ---------------------------------------------------------------------------

/// Release-name placeholder handed to `helm template` (its first positional
/// argument is the release name). Nothing is installed, so any constant works,
/// but a fixed value keeps the rendered `Release.Name` output deterministic
/// for diffing.
const TEMPLATE_RELEASE_PLACEHOLDER: &str = "preview";

/// Build the argv for `helm template <release> <chart> [--version v] [--values p]`.
///
/// Pure so the flag logic is unit-testable without a helm binary. `version`
/// empty = omit `--version` (helm picks latest); `values_path` `None` =
/// render with chart defaults. Deliberately NO `--wait`/`--timeout`: those
/// are cluster-op flags and `helm template` is fully offline.
fn template_argv(chart_ref: &str, version: &str, values_path: Option<&str>) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "template".into(),
        TEMPLATE_RELEASE_PLACEHOLDER.into(),
        chart_ref.to_string(),
    ];
    if !version.is_empty() {
        argv.push("--version".into());
        argv.push(version.to_string());
    }
    if let Some(p) = values_path {
        argv.push("--values".into());
        argv.push(p.to_string());
    }
    argv
}

/// Render a chart's templates to a manifest string (offline `helm template`,
/// no cluster contact, nothing applied). `chart_ref` may be `repo/name`, an
/// OCI URL, or a local absolute path — helm natively accepts all three.
/// `version` empty = latest; `values` empty = chart defaults, otherwise the
/// content lands in a guarded 0600 temp file; `kubeconfig` `Some` = temp file
/// passed via `--kubeconfig` (helm needs a path, not a blob). Captures (not
/// streams) the output; a non-zero exit is an `AppError::Other` carrying
/// helm's stderr.
pub async fn render_chart_templates(
    chart_ref: &str,
    version: &str,
    values: &str,
    kubeconfig: Option<&str>,
) -> AppResult<String> {
    let helm = which_helm().ok_or_else(|| {
        AppError::Other(
            "helm CLI not found in PATH — install Helm 3 (https://helm.sh/docs/intro/install/) and retry"
                .into(),
        )
    })?;

    // Both guards must outlive `cmd.output()` below — helm reads the paths
    // while the process runs; they drop (deleting the files) after the result.
    let values_guard = if values.trim().is_empty() {
        None
    } else {
        Some(write_temp_values(values)?)
    };
    let kc_guard = kubeconfig.map(write_temp_kubeconfig).transpose()?;

    let mut cmd = Command::new(&helm);
    let values_path = values_guard
        .as_ref()
        .map(|g| g.path().display().to_string());
    cmd.args(template_argv(chart_ref, version, values_path.as_deref()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(g) = &kc_guard {
        cmd.arg("--kubeconfig").arg(g.path());
    }
    let out = cmd
        .output()
        .await
        .map_err(|e| AppError::Other(format!("helm template: {e}")))?;
    if !out.status.success() {
        return Err(AppError::Other(format!(
            "helm template: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::serde_json;

    fn install_args() -> InstallArgs {
        InstallArgs {
            release: "rel".into(),
            chart: "demo".into(),
            version: String::new(),
            namespace: "default".into(),
            kubeconfig: None,
            values: String::new(),
            dry_run: false,
            create_namespace: false,
            set: None,
            atomic: false,
            timeout_secs: None,
        }
    }

    /// `--keep-history` must appear only when the user asked to keep it:
    /// helm's own default is to delete release history, and the previous
    /// inverted condition silently did the opposite of the checkbox.
    #[test]
    fn uninstall_argv_keep_history_only_when_requested() {
        let keep = HelmOp::Uninstall(UninstallArgs {
            release: "rel".into(),
            namespace: "ns".into(),
            kubeconfig: None,
            keep_history: true,
        });
        let (_, argv) = build_argv("helm", &keep, &mut Vec::new()).unwrap();
        assert!(argv.contains(&"--keep-history".into()));

        let drop_history = HelmOp::Uninstall(UninstallArgs {
            release: "rel".into(),
            namespace: "ns".into(),
            kubeconfig: None,
            keep_history: false,
        });
        let (_, argv) = build_argv("helm", &drop_history, &mut Vec::new()).unwrap();
        assert!(!argv.contains(&"--keep-history".into()));
    }

    /// Inline values land in a guarded temp file whose path goes on the argv;
    /// the guard is handed to the caller so the file survives spawn.
    #[test]
    fn install_argv_uses_guarded_values_file() {
        let op = HelmOp::Install(InstallArgs {
            release: "rel".into(),
            chart: "ingress-nginx/ingress-nginx".into(),
            version: String::new(),
            namespace: "ns".into(),
            kubeconfig: None,
            values: "replicaCount: 2".into(),
            dry_run: false,
            create_namespace: false,
            set: None,
            atomic: false,
            timeout_secs: None,
        });
        let mut guards = Vec::new();
        let (_, argv) = build_argv("helm", &op, &mut guards).unwrap();
        assert!(argv.contains(&"--values".into()));
        assert_eq!(guards.len(), 1);
        assert!(guards[0].path().exists());
        // guards drop here, removing the file
    }

    /// The sentinel path passes straight through without creating a file.
    #[test]
    fn install_argv_file_sentinel_passthrough() {
        let op = HelmOp::Install(InstallArgs {
            release: "rel".into(),
            chart: "foo/bar".into(),
            version: String::new(),
            namespace: "ns".into(),
            kubeconfig: None,
            values: "__file:/tmp/pre-written.yaml".into(),
            dry_run: false,
            create_namespace: false,
            set: None,
            atomic: false,
            timeout_secs: None,
        });
        let mut guards = Vec::new();
        let (_, argv) = build_argv("helm", &op, &mut guards).unwrap();
        assert!(argv.contains(&"/tmp/pre-written.yaml".into()));
        assert!(guards.is_empty());
    }

    /// Credentials must not outlive their guard: the temp kubeconfig exists
    /// while the guard is alive and is removed the moment it drops.
    #[test]
    fn temp_kubeconfig_removed_on_drop() {
        let (path, guard) = {
            let guard = write_temp_kubeconfig("apiVersion: v1\n").unwrap();
            assert!(guard.path().exists());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(guard.path())
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "kubeconfig must be owner-only");
            }
            (guard.path().to_path_buf(), guard)
        };
        drop(guard);
        assert!(!path.exists());
    }

    /// Same contract for the values temp file.
    #[test]
    fn temp_values_removed_on_drop() {
        let path = {
            let guard = write_temp_values("foo: bar\n").unwrap();
            let p = guard.path().to_path_buf();
            assert!(p.exists());
            p
        };
        assert!(!path.exists(), "guard dropped at end of block above");
    }

    /// Concurrent ops must not share a temp file: uuid suffixes are distinct.
    #[test]
    fn temp_files_for_concurrent_ops_are_distinct() {
        let a = write_temp_kubeconfig("x").unwrap();
        let b = write_temp_kubeconfig("x").unwrap();
        assert_ne!(a.path(), b.path());
    }

    #[test]
    fn argv_honors_new_flags() {
        let mut a = install_args();
        a.set = Some(serde_json::Map::from_iter([(
            "replicaCount".to_string(),
            serde_json::json!(3),
        )]));
        a.atomic = true;
        a.timeout_secs = Some(600);
        let mut tmp = Vec::new();
        let (_label, argv) = build_argv("helm", &HelmOp::Install(a), &mut tmp).unwrap();
        assert!(argv.contains(&"--set".into()));
        assert!(argv.windows(2).any(|w| w == ["--set", "replicaCount=3"]));
        assert!(argv.contains(&"--atomic".into()));
        assert!(argv.windows(2).any(|w| w == ["--timeout", "600s"]));
    }

    #[test]
    fn argv_default_timeout_unchanged() {
        let (_label, argv) =
            build_argv("helm", &HelmOp::Install(install_args()), &mut Vec::new()).unwrap();
        assert!(argv.windows(2).any(|w| w == ["--timeout", "5m0s"]));
    }

    /// `Some(0)` is "unset", not "wait forever": `--timeout 0s` would make
    /// helm block indefinitely, so it clamps to the default like `None`.
    #[test]
    fn argv_timeout_zero_clamps_to_default() {
        let mut a = install_args();
        a.timeout_secs = Some(0);
        let (_label, argv) = build_argv("helm", &HelmOp::Install(a), &mut Vec::new()).unwrap();
        assert!(
            argv.windows(2).any(|w| w == ["--timeout", "5m0s"]),
            "argv: {argv:?}"
        );
        assert!(!argv.contains(&"0s".into()));
    }

    #[test]
    fn upgrade_argvs_add_force_and_create_ns() {
        let a = UpgradeArgs {
            release: "rel".into(),
            chart: "demo".into(),
            version: String::new(),
            namespace: "default".into(),
            kubeconfig: None,
            values: String::new(),
            dry_run: false,
            reuse_values: false,
            rollback_on_failure: false,
            force: true,
            create_namespace: true,
            atomic: false,
            timeout_secs: None,
            set: None,
        };
        let (_label, argv) = build_argv("helm", &HelmOp::Upgrade(a), &mut Vec::new()).unwrap();
        assert!(argv.contains(&"--force".into()));
        assert!(argv.contains(&"--create-namespace".into()));
    }

    /// `helm template` argv: version/values flags appear only when asked for.
    #[test]
    fn template_argv_flags() {
        let argv = template_argv("repo/app", "1.2.3", Some("/tmp/v.yaml"));
        assert_eq!(argv[0], "template");
        assert!(argv.contains(&"--version".into()) && argv.contains(&"1.2.3".into()));
        assert!(argv
            .windows(2)
            .any(|w| w == ["--values".to_string(), "/tmp/v.yaml".to_string()]));
        let bare = template_argv("/data/charts/demo-1.0.0", "", None);
        assert!(!bare.contains(&"--version".into()) && !bare.contains(&"--values".into()));
    }
}
