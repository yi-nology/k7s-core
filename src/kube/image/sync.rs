//! Image sync / import via the system `skopeo` CLI.
//!
//! Air-gapped clusters can't pull images from the public internet. This module
//! is the MCP-side answer to "how do I get an image into my internal registry?"
//! — it shells out to `skopeo copy`, which is the de-facto tool for copying
//! images between locations without a running Docker daemon.
//!
//! Why a CLI shim rather than a pure-Rust OCI push:
//!
//! - `helm_ops.rs` already established the project's pattern for shelling out
//!   (detect → spawn → pump stdout/stderr to the event sink → collect result),
//!   so this mirrors a reviewed, working design.
//! - skopeo speaks every transport that matters for an air-gapped workflow —
//!   `docker://` (registries), `docker-archive:` (local `docker save` tars),
//!   `oci:` (OCI layouts), `dir:` (unpacked), `containers-storage:` (runtime
//!   store). A hand-rolled push would only cover `docker://` and still need
//!   `sha2` + a TLS-enabled reqwest + chunked-upload bookkeeping.
//! - skopeo resolves cross-architecture images, signatures, and layer reuse
//!   (already-present layers are skipped) for free.
//!
//! The trade-off mirrors `helm_ops`: the host running the MCP server needs
//! `skopeo` on its PATH. `which_skopeo()` detects it up front and the caller
//! surfaces a clear "install skopeo" message when it's missing.

use crate::core::events::EventSink;
use crate::error::{AppError, AppResult};
use crate::kube::{image::export, image::repo};
use k7s_deps::tokio::io::{AsyncBufReadExt, BufReader};
use k7s_deps::tokio::process::Command;
use serde::Serialize;
use std::process::Stdio;

/// Tauri event name carrying one stdout/stderr line from a running skopeo call.
pub const IMAGE_SYNC_LOG_EVENT: &str = "image-sync-log";
/// Tauri event name signalling the end of an image sync (with success/failure).
pub const IMAGE_SYNC_DONE_EVENT: &str = "image-sync-done";

/// Wall-clock budget for one `skopeo copy`. Multi-GB images over slow links
/// legitimately take tens of minutes, but a registry that stalls mid-copy
/// must not pin the task (and its temp auth file) forever.
const COPY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// The result of a completed `skopeo copy`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageSyncResult {
    /// The original source transport string (e.g. `docker://nginx:1.25`).
    pub source: String,
    /// The final destination (`docker://harbor.internal/library/nginx:1.25`).
    pub destination: String,
    /// True if the skopeo process exited 0.
    pub success: bool,
    /// Number of stdout+stderr lines produced (a rough "how chatty was it" gauge).
    pub lines: usize,
    /// Human-readable summary, e.g. "copied nginx:1.25 → harbor/library/nginx:1.25".
    pub summary: String,
}

/// One row from `image_sync_status` — whether skopeo is usable on this host.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkopeoAvailability {
    pub available: bool,
    /// Resolved binary path, or None when not found.
    pub path: Option<String>,
    /// `skopeo --version` output, or an install hint when missing.
    pub version: Option<String>,
}

/// Detect the skopeo binary. Checks the conventional install locations first
/// (so a Homebrew/macOS host doesn't pay a `which` spawn), then falls back to
/// `$PATH`. Returns None when skopeo isn't installed.
pub fn which_skopeo() -> Option<String> {
    for path in [
        "/usr/local/bin/skopeo",
        "/opt/homebrew/bin/skopeo",
        "/usr/bin/skopeo",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    // Last resort: ask the shell. `which` is ubiquitous and cheap.
    if let Ok(out) = std::process::Command::new("which").arg("skopeo").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}

/// Probe skopeo availability + version. Cheap (`skopeo --version` exits
/// instantly), so the MCP `image_sync_status` tool can call it on every
/// invocation without slowing the conversation down.
pub async fn check_skopeo() -> SkopeoAvailability {
    let Some(path) = which_skopeo() else {
        return SkopeoAvailability {
            available: false,
            path: None,
            version: Some(
                "skopeo not found on PATH — install it (brew install skopeo / apt install skopeo) \
                 and retry"
                    .into(),
            ),
        };
    };
    // `--version` prints "skopeo version 1.x.y" and exits 0.
    let version = match Command::new(&path).arg("--version").output().await {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(e) => format!("could not run skopeo --version: {e}"),
    };
    SkopeoAvailability {
        available: true,
        path: Some(path),
        version: Some(version),
    }
}

/// Strip the `https://` / `http://` scheme and any trailing slash from a
/// registry URL, leaving the bare `host[:port]` that a docker transport needs.
///
/// `repo::ImageRegistry.url` is stored as `https://registry.example.com`
/// (the UI's convention — it's what the catalog API wants). skopeo's
/// `docker://` transport takes a bare host, so we canonicalise here.
pub fn registry_host(url: &str) -> String {
    let trimmed = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    trimmed.trim_end_matches('/').to_string()
}

/// A credential pair to write into a skopeo auth file. `creds` is the raw
/// `user:pass` string (as the MCP `image_copy` tool receives it); `(user, pass)`
/// is the split form used by the stored registry config.
pub(crate) enum AuthCreds<'a> {
    /// `user:pass` as a single string; split on the first `:`.
    Raw(&'a str),
    /// Separate username/password fields.
    Split { user: &'a str, pass: &'a str },
}

impl AuthCreds<'_> {
    /// Returns `(user, pass)` or `None` if the credentials are empty / have no
    /// username (anonymous access — no auth file entry needed).
    fn user_pass(&self) -> Option<(&str, &str)> {
        match self {
            AuthCreds::Raw(s) => {
                if s.is_empty() {
                    return None;
                }
                let (user, pass) = s.split_once(':')?;
                if user.is_empty() {
                    return None;
                }
                Some((user, pass))
            }
            AuthCreds::Split { user, pass } => {
                if user.is_empty() {
                    return None;
                }
                Some((user, pass))
            }
        }
    }
}

/// Write a Docker-format auth file for skopeo and return its path. The file is
/// created with `0600` permissions and holds the credentials for a single
/// registry host, base64-encoded exactly as Docker/skopeo's `--authfile`
/// expects (`{"auths":{"<host>":{"auth":"<base64 user:pass>"}}}`).
///
/// This is the secure alternative to `--src-creds`/`--dest-creds`: those place
/// `user:pass` on the process argv, where any local user can read it via `ps`
/// or `/proc/<pid>/cmdline`. An auth file keeps the secret on disk only for
/// the duration of the copy and is deleted by the caller afterwards.
///
/// Returns `Ok(None)` when the credentials are empty/anonymous (no auth file
/// is needed), so the caller can pass `None` straight through to `build_argv`.
pub(crate) fn write_skopeo_authfile(
    host: &str,
    creds: AuthCreds,
) -> AppResult<Option<std::path::PathBuf>> {
    use k7s_deps::base64::Engine;
    use std::io::Write;

    let Some((user, pass)) = creds.user_pass() else {
        return Ok(None);
    };

    let auth = k7s_deps::base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    let body = format!(r#"{{"auths":{{"{host}":{{"auth":"{auth}"}}}}}}"#);

    // A unique temp file per call so concurrent copies don't clobber each
    // other's auth file. Uniqueness = pid + nanosecond timestamp; the auth
    // files for src and dest within one copy get distinct suffixes from the
    // caller-provided `tag`.
    let path = unique_authfile_path("k7s-skopeo-auth")?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    // On Unix, restrict the file to owner-only (0600) since it holds creds.
    // On Windows, ACLs handle file permissions; no extra call needed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&path)
        .map_err(|e| AppError::Other(format!("create skopeo authfile: {e}")))?;
    file.write_all(body.as_bytes())
        .map_err(|e| AppError::Other(format!("write skopeo authfile: {e}")))?;

    Ok(Some(path))
}

/// Delete a temp auth file written by [`write_skopeo_authfile`]. Best-effort:
/// a failure to remove a 0600 file in the temp dir is logged but not fatal
/// (the credentials inside are short-lived and the OS reaps `/tmp` on reboot).
pub(crate) fn cleanup_authfile(path: Option<&std::path::PathBuf>) -> std::io::Result<()> {
    if let Some(p) = path {
        match std::fs::remove_file(p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => {
                k7s_deps::tracing::warn!("failed to remove skopeo authfile {}: {e}", p.display());
                Err(e)
            }
        }
    } else {
        Ok(())
    }
}

/// RAII guard over a skopeo auth file: deletes it on drop.
///
/// The auth file holds plaintext-equivalent registry credentials (`base64` is
/// reversible). Previously the cleanup call lived only at the end of each
/// function, so any `?` early-return between write and cleanup leaked the
/// file in `/tmp`. Wrapping the path in this guard means every exit path —
/// including `?` propagation — drops the guard and removes the file.
pub(crate) struct AuthFileGuard(pub(crate) Option<std::path::PathBuf>);

impl Drop for AuthFileGuard {
    fn drop(&mut self) {
        let _ = cleanup_authfile(self.0.as_ref());
    }
}

/// Build a unique temp file path without creating it. Mirrors the project's
/// existing temp-file convention (grafana.rs, audit.rs, client.rs): pid +
/// nanosecond timestamp gives uniqueness without a tempfile crate dependency.
fn unique_authfile_path(prefix: &str) -> AppResult<std::path::PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.json", std::process::id()));
    Ok(path)
}

/// Extract the registry host from a skopeo `docker://` transport reference, so
/// the auth file can be keyed to the right host. For non-`docker://` sources
/// (archives, oci layouts, dirs) there is no registry host to authenticate
/// against, so this returns `None`.
///
/// Docker reference normalisation applies before the host is taken: a first
/// path segment is only a registry when it contains a `.`/`:`, or is
/// `localhost` — otherwise it is a repository (namespace) on Docker Hub, whose
/// authfile key is `docker.io`. Returning the raw first segment here (e.g.
/// `nginx:1.25`) produced an authfile key no registry would ever match.
///
/// `docker://nginx:1.25`           → `docker.io` (Hub shorthand)
/// `docker://library/nginx:1.25`   → `docker.io` (namespace, not a host)
/// `docker://registry.local/foo:v1`→ `registry.local`
/// `docker://host:5000/lib/x:tag`  → `host:5000`
/// `docker-archive:/tmp/x.tar`     → `None`
pub(crate) fn docker_transport_host(reference: &str) -> Option<&str> {
    let rest = reference.strip_prefix("docker://")?;
    let host_end = rest.find('/').unwrap_or(rest.len());
    let first = &rest[..host_end];
    if first.is_empty() {
        return None;
    }
    // A bare `name:tag` has no path at all — the whole segment is the image
    // name (its `:` separates the tag), so it can never be a host.
    if host_end == rest.len() {
        return Some("docker.io");
    }
    let is_host =
        first.contains('.') || first.contains(':') || first.eq_ignore_ascii_case("localhost");
    if is_host {
        Some(first)
    } else {
        Some("docker.io")
    }
}

/// Build the destination docker-transport reference for a copy.
///
/// Joins the registry host, the repo path, and the tag into the canonical
/// `docker://host/repo:tag` form skopeo expects. We don't lowercase the host
/// here — registries are case-sensitive on the host part only in pathological
/// setups, and the repo path is case-sensitive by spec.
pub fn dest_reference(host: &str, repo: &str, tag: &str) -> String {
    // Avoid a double slash when the user passes a repo that already starts
    // with one (some UIs store `library/nginx`, others `/library/nginx`).
    let repo = repo.trim_start_matches('/');
    if tag.is_empty() {
        format!("docker://{host}/{repo}")
    } else {
        format!("docker://{host}/{repo}:{tag}")
    }
}

/// Copy an image from `source` into the configured destination registry.
///
/// `source` is any skopeo transport string:
///   - `docker://nginx:1.25`           — a public registry image
///   - `docker://registry-a/foo:v1`     — another private registry
///   - `docker-archive:/tmp/image.tar`  — a local `docker save` tarball
///   - `oci:/path/to/layout:tag`        — an OCI image layout
///   - `dir:/path/to/unpacked`          — an unpacked image directory
///
/// The destination is resolved from the user's configured registries
/// (`repo::list_registries`) by `dest_registry` name — this reuses the
/// stored URL + credentials so the caller never handles secrets directly.
///
/// Streams each stdout/stderr line to the event sink (so a UI can show live
/// "Copying blob sha256:…" progress) and returns the final result.
#[allow(clippy::too_many_arguments)]
pub async fn copy_image(
    source: &str,
    dest_registry: &str,
    dest_repo: &str,
    dest_tag: &str,
    src_creds: Option<&str>,
    insecure_src: bool,
    insecure_dest: bool,
    sink: EventSink,
) -> AppResult<ImageSyncResult> {
    let skopeo = which_skopeo().ok_or_else(|| {
        AppError::Other(
            "skopeo CLI not found in PATH — install skopeo \
             (brew install skopeo / apt install skopeo) and retry"
                .into(),
        )
    })?;

    // Resolve the destination registry from the stored configuration. We need
    // the full ImageRegistry (with the decrypted password) to build creds.
    let reg = repo::list_registries()
        .map_err(|e| AppError::Other(format!("load registries: {e}")))?
        .into_iter()
        .find(|r| r.name == dest_registry)
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "destination registry '{dest_registry}' is not configured — add it via the \
                 registries UI (or image_registry_upsert) first"
            ))
        })?;

    let host = registry_host(&reg.url);
    let dest_ref = dest_reference(&host, dest_repo, dest_tag);

    // Write credentials to temp auth files instead of placing them on the argv
    // (`--src-creds`/`--dest-creds` leak `user:pass` to `ps`/`/proc`). Each is
    // 0600 and deleted after the copy. Returns None for anonymous access.
    // Wrapped in `AuthFileGuard` so any `?` early-return below still drops
    // (deletes) the files — they hold plaintext-equivalent creds.
    let src_authfile = AuthFileGuard(match (docker_transport_host(source), src_creds) {
        (Some(src_host), Some(creds)) => write_skopeo_authfile(src_host, AuthCreds::Raw(creds))?,
        _ => None,
    });
    let dest_authfile = AuthFileGuard(write_skopeo_authfile(
        &host,
        AuthCreds::Split {
            user: reg.username.as_str(),
            pass: reg.password.as_str(),
        },
    )?);

    let argv = build_argv(
        &skopeo,
        source,
        &dest_ref,
        src_authfile.0.as_deref(),
        dest_authfile.0.as_deref(),
        insecure_src,
        insecure_dest,
    );

    let mut cmd = Command::new(&skopeo);
    cmd.args(&argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // skopeo reads its config from $HOME/.local/share/containers; pass
        // HOME through so auth files resolve the same way as a manual run.
        .envs(std::env::vars().filter(|(k, _)| k == "HOME" || k == "PATH"));

    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::Other(format!("spawn skopeo: {e}")))?;

    // Pump stdout and stderr concurrently into the sink, exactly like helm_ops.
    // skopeo writes layer-by-layer progress to stderr ("Copying blob … done")
    // and a final summary to stdout; interleaving them with a stream prefix
    // gives the UI enough context to render a live log.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Other("no stdout from skopeo".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::Other("no stderr from skopeo".into()))?;

    let line_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink_out = sink.clone();
    let count_out = line_count.clone();
    let out_task = k7s_deps::tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            count_out.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            sink_out.emit(
                IMAGE_SYNC_LOG_EVENT,
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
                IMAGE_SYNC_LOG_EVENT,
                &LogLine {
                    stream: "stderr",
                    line,
                },
            );
        }
    });

    let status = match k7s_deps::tokio::time::timeout(COPY_TIMEOUT, child.wait()).await {
        Ok(res) => res.map_err(|e| AppError::Other(format!("wait skopeo: {e}")))?,
        Err(_) => {
            // Timed out: kill skopeo so it stops pushing layers, then let the
            // pipe EOFs finish the pump tasks above before we bail out.
            let _ = child.kill().await;
            let _ = k7s_deps::tokio::join!(out_task, err_task);
            return Err(AppError::Other(format!(
                "skopeo copy timed out after {}s (source {source}) — \
                 retry, or raise COPY_TIMEOUT for exceptionally large images",
                COPY_TIMEOUT.as_secs()
            )));
        }
    };
    // Drain both pumps before we read the count / build the summary.
    let _ = k7s_deps::tokio::join!(out_task, err_task);

    let success = status.success();
    let lines = line_count.load(std::sync::atomic::Ordering::Relaxed);
    let summary = if success {
        format!("copied {source} → {dest_registry}/{dest_repo}:{dest_tag}")
    } else {
        format!("skopeo copy failed: {status}")
    };

    let result = ImageSyncResult {
        source: source.to_string(),
        destination: dest_ref,
        success,
        lines,
        summary,
    };
    // `src_authfile` / `dest_authfile` (AuthFileGuard) drop here, wiping the
    // temp auth files — they held plaintext-equivalent credentials (base64
    // is reversible). Drop runs on this happy path and on every `?` above.
    sink.emit(IMAGE_SYNC_DONE_EVENT, &result);
    if success {
        Ok(result)
    } else {
        Err(AppError::Other(result.summary))
    }
}

/// The result of exporting an image from a registry to a local .tar file.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportRegistryResult {
    /// Source image reference (e.g. "docker://harbor.local/nginx:1.25").
    pub source: String,
    /// Local file path the tar was saved to.
    pub saved_path: String,
    /// Whether skopeo exited 0.
    pub success: bool,
    /// Number of output lines.
    pub lines: usize,
    /// Human-readable summary.
    pub summary: String,
}

/// Construct the `skopeo copy` argv for exporting to a docker-archive.
///
/// Credentials are never placed on the argv: instead the caller writes a
/// Docker-format auth file (see [`write_skopeo_authfile`]) and passes its
/// path here as `src_authfile`. skopeo reads `--src-authfile`, keeping the
/// secret out of the process table (`ps`/`/proc/<pid>/cmdline`).
pub fn build_export_argv(
    skopeo: &str,
    source: &str,
    dest: &str,
    src_authfile: Option<&std::path::Path>,
    insecure_src: bool,
) -> Vec<String> {
    let _ = skopeo;
    let mut argv: Vec<String> = vec![
        "copy".into(),
        "--retry-times".into(),
        "3".into(),
        // Cluster nodes are linux regardless of the host OS (typically
        // darwin/arm64 for a laptop). The architecture is deliberately NOT
        // overridden: skopeo then copies per the source manifest(list), so an
        // arm64 cluster gets the arm64 variant instead of a hard-coded amd64.
        "--override-os".into(),
        "linux".into(),
    ];
    if let Some(path) = src_authfile {
        argv.push("--src-authfile".into());
        argv.push(path.to_string_lossy().into_owned());
    }
    if insecure_src {
        argv.push("--src-tls-verify=false".into());
    }
    argv.push(source.into());
    argv.push(dest.into());
    argv
}

/// Export an image from a configured registry to a local docker-archive tarball.
pub async fn export_from_registry(
    registry_name: &str,
    repo: &str,
    tag: &str,
    save_path: &str,
    insecure_src: bool,
    sink: EventSink,
) -> AppResult<ExportRegistryResult> {
    // Validate the save path before we touch skopeo: the destination is
    // `docker-archive:{save_path}`, i.e. skopeo writes the tar here, so a
    // hostile or malformed path could clobber arbitrary local files.
    export::validate_save_path(save_path)?;
    let skopeo = which_skopeo().ok_or_else(|| {
        AppError::Other(
            "skopeo CLI not found in PATH — install skopeo \
             (brew install skopeo / apt install skopeo) and retry"
                .into(),
        )
    })?;

    let reg = repo::list_registries()
        .map_err(|e| AppError::Other(format!("load registries: {e}")))?
        .into_iter()
        .find(|r| r.name == registry_name)
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "registry '{registry_name}' is not configured — add it via the registries UI first"
            ))
        })?;

    let host = registry_host(&reg.url);
    let source_ref = format!("docker://{host}/{}:{}", repo.trim_start_matches('/'), tag);
    let dest_ref = format!("docker-archive:{save_path}");

    // Write the source registry credentials to a temp auth file (0600) instead
    // of passing them as `--src-creds` on the argv, which leaks `user:pass` to
    // `ps`/`/proc`. Wrapped in `AuthFileGuard` so early returns still clean up.
    let src_authfile = AuthFileGuard(write_skopeo_authfile(
        &host,
        AuthCreds::Split {
            user: reg.username.as_str(),
            pass: reg.password.as_str(),
        },
    )?);

    let argv = build_export_argv(
        &skopeo,
        &source_ref,
        &dest_ref,
        src_authfile.0.as_deref(),
        insecure_src,
    );

    let mut cmd = Command::new(&skopeo);
    cmd.args(&argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(std::env::vars().filter(|(k, _)| k == "HOME" || k == "PATH"));

    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::Other(format!("spawn skopeo: {e}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Other("no stdout from skopeo".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::Other("no stderr from skopeo".into()))?;

    let line_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink_out = sink.clone();
    let count_out = line_count.clone();
    let out_task = k7s_deps::tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            count_out.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            sink_out.emit(
                IMAGE_SYNC_LOG_EVENT,
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
                IMAGE_SYNC_LOG_EVENT,
                &LogLine {
                    stream: "stderr",
                    line,
                },
            );
        }
    });

    let status = match k7s_deps::tokio::time::timeout(COPY_TIMEOUT, child.wait()).await {
        Ok(res) => res.map_err(|e| AppError::Other(format!("wait skopeo: {e}")))?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = k7s_deps::tokio::join!(out_task, err_task);
            return Err(AppError::Other(format!(
                "skopeo export timed out after {}s (source {source_ref})",
                COPY_TIMEOUT.as_secs()
            )));
        }
    };
    let _ = k7s_deps::tokio::join!(out_task, err_task);

    let success = status.success();
    let lines = line_count.load(std::sync::atomic::Ordering::Relaxed);
    let summary = if success {
        format!("exported {source_ref} → {save_path}")
    } else {
        format!("skopeo copy failed: {status}")
    };

    let result = ExportRegistryResult {
        source: source_ref,
        saved_path: save_path.to_string(),
        success,
        lines,
        summary,
    };
    // `src_authfile` (AuthFileGuard) drops here, wiping the temp auth file.
    sink.emit(IMAGE_SYNC_DONE_EVENT, &result);
    if success {
        Ok(result)
    } else {
        Err(AppError::Other(result.summary))
    }
}

/// Construct the `skopeo copy` argv. Kept separate from `copy_image` so a unit
/// test can assert the flag ordering without spinning up skopeo.
///
/// Credentials are never placed on the argv. Instead the caller writes a
/// Docker-format auth file (see [`write_skopeo_authfile`]) and passes its
/// path via `src_authfile` / `dest_authfile`; skopeo reads `--src-authfile`
/// / `--dest-authfile`. This keeps `user:pass` out of the process table
/// (`ps` / `/proc/<pid>/cmdline`), where any local user could read it.
#[allow(clippy::too_many_arguments)]
fn build_argv(
    skopeo: &str,
    source: &str,
    dest: &str,
    src_authfile: Option<&std::path::Path>,
    dest_authfile: Option<&std::path::Path>,
    insecure_src: bool,
    insecure_dest: bool,
) -> Vec<String> {
    let _ = skopeo; // the caller already resolved the path; argv is skopeo-agnostic
    let mut argv: Vec<String> = vec![
        "copy".into(),
        // Retry transient network failures (a flaky registry mid-copy shouldn't
        // abort a 2 GB image push). skopeo's default is 0 retries.
        "--retry-times".into(),
        "3".into(),
        // Always target linux — a K8s node never runs darwin — but leave the
        // architecture to skopeo: with no --override-arch it copies from the
        // source manifest list, so arm64 clusters receive the arm64 variant
        // (a hard-coded amd64 silently broke them).
        "--override-os".into(),
        "linux".into(),
    ];

    if let Some(path) = src_authfile {
        argv.push("--src-authfile".into());
        argv.push(path.to_string_lossy().into_owned());
    }
    if insecure_src {
        argv.push("--src-tls-verify=false".into());
    }
    if let Some(path) = dest_authfile {
        argv.push("--dest-authfile".into());
        argv.push(path.to_string_lossy().into_owned());
    }
    if insecure_dest {
        argv.push("--dest-tls-verify=false".into());
    }

    argv.push(source.into());
    argv.push(dest.into());
    argv
}

#[derive(Serialize, Clone)]
struct LogLine<'a> {
    stream: &'a str,
    line: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_host_strips_scheme_and_trailing_slash() {
        assert_eq!(
            registry_host("https://harbor.example.com"),
            "harbor.example.com"
        );
        assert_eq!(registry_host("http://reg.local:5000"), "reg.local:5000");
        assert_eq!(registry_host("https://reg.local/"), "reg.local");
        // No scheme: pass through (only trailing slash stripped).
        assert_eq!(registry_host("reg.local:5000/"), "reg.local:5000");
    }

    #[test]
    fn dest_reference_joins_host_repo_tag() {
        assert_eq!(
            dest_reference("harbor.local", "library/nginx", "1.25"),
            "docker://harbor.local/library/nginx:1.25"
        );
    }

    #[test]
    fn dest_reference_omits_colon_when_tag_empty() {
        // An empty tag copies by digest (skopeo resolves it from the source).
        assert_eq!(
            dest_reference("reg.local", "app", ""),
            "docker://reg.local/app"
        );
    }

    #[test]
    fn dest_reference_dedupes_leading_slash_in_repo() {
        // Some callers pass "/library/nginx"; avoid "docker://host//library/nginx".
        assert_eq!(
            dest_reference("reg.local", "/library/nginx", "v1"),
            "docker://reg.local/library/nginx:v1"
        );
    }

    #[test]
    fn build_argv_uses_authfile_not_creds() {
        // Credentials now go through a temp auth file, never on the argv.
        let authfile = std::path::Path::new("/tmp/k7s-test-src-auth.json");
        let dest_authfile = std::path::Path::new("/tmp/k7s-test-dest-auth.json");
        let argv = build_argv(
            "skopeo",
            "docker://nginx:1",
            "docker://h/app:1",
            Some(authfile),
            Some(dest_authfile),
            false,
            false,
        );
        assert!(argv.contains(&"--src-authfile".into()));
        assert!(argv.contains(&"/tmp/k7s-test-src-auth.json".into()));
        assert!(argv.contains(&"--dest-authfile".into()));
        assert!(argv.contains(&"/tmp/k7s-test-dest-auth.json".into()));
        // No raw credentials or *-creds flags must ever appear.
        assert!(!argv.iter().any(|a| a.starts_with("--src-creds")));
        assert!(!argv.iter().any(|a| a.starts_with("--dest-creds")));
    }

    #[test]
    fn build_argv_omits_authfile_flags_when_none() {
        let argv = build_argv(
            "skopeo",
            "docker://nginx:1",
            "docker://h/app:1",
            None,
            None,
            false,
            false,
        );
        assert!(!argv.iter().any(|a| a.starts_with("--src-authfile")));
        assert!(!argv.iter().any(|a| a.starts_with("--dest-authfile")));
        assert!(!argv.iter().any(|a| a.starts_with("--src-creds")));
        assert!(!argv.iter().any(|a| a.starts_with("--dest-creds")));
    }

    #[test]
    fn build_argv_respects_insecure_flags() {
        let argv = build_argv(
            "skopeo",
            "docker://nginx:1",
            "docker://h/app:1",
            None,
            None,
            true,
            true,
        );
        assert!(argv.contains(&"--src-tls-verify=false".into()));
        assert!(argv.contains(&"--dest-tls-verify=false".into()));
    }

    #[test]
    fn build_argv_forces_linux_os() {
        // Regression guard: linux must always be forced so a macOS host
        // doesn't copy a darwin image, while the architecture is left to the
        // source manifest (no --override-arch).
        let argv = build_argv(
            "skopeo",
            "docker://nginx:1",
            "docker://h/app:1",
            None,
            None,
            false,
            false,
        );
        assert!(argv.contains(&"--override-os".into()));
        assert!(argv.contains(&"linux".into()));
        assert!(!argv.iter().any(|a| a == "--override-arch"));
    }

    #[test]
    fn build_argv_puts_source_and_dest_last() {
        // skopeo parses positionally: flags first, then <source> <destination>.
        let argv = build_argv(
            "skopeo",
            "docker://nginx:1",
            "docker://h/app:1",
            None,
            None,
            false,
            false,
        );
        assert_eq!(argv[argv.len() - 2], "docker://nginx:1");
        assert_eq!(argv[argv.len() - 1], "docker://h/app:1");
    }

    #[test]
    fn export_argv_docker_archive_dest() {
        let authfile = std::path::Path::new("/tmp/k7s-test-export-auth.json");
        let argv = build_export_argv(
            "skopeo",
            "docker://harbor.local/library/nginx:1.25",
            "docker-archive:/tmp/nginx.tar",
            Some(authfile),
            false,
        );
        assert_eq!(
            argv[argv.len() - 2],
            "docker://harbor.local/library/nginx:1.25"
        );
        assert_eq!(argv[argv.len() - 1], "docker-archive:/tmp/nginx.tar");
        assert!(argv.contains(&"--src-authfile".into()));
        assert!(argv.contains(&"/tmp/k7s-test-export-auth.json".into()));
        // No raw credentials on the argv.
        assert!(!argv.iter().any(|a| a.starts_with("--src-creds")));
    }

    #[test]
    fn export_argv_no_authfile_when_none() {
        let argv = build_export_argv(
            "skopeo",
            "docker://reg.local/nginx:1",
            "docker-archive:/tmp/x.tar",
            None,
            false,
        );
        assert!(!argv.iter().any(|a| a.starts_with("--src-authfile")));
        assert!(!argv.iter().any(|a| a.starts_with("--src-creds")));
    }

    #[test]
    fn export_argv_insecure_flag() {
        let argv = build_export_argv(
            "skopeo",
            "docker://reg.local/nginx:1",
            "docker-archive:/tmp/x.tar",
            None,
            true,
        );
        assert!(argv.contains(&"--src-tls-verify=false".into()));
    }

    #[test]
    fn build_export_argv_forces_linux_os() {
        // Regression guard: linux must be forced, arch must not be (see
        // build_argv_forces_linux_os).
        let argv = build_export_argv(
            "skopeo",
            "docker://nginx:1",
            "docker-archive:/tmp/nginx.tar",
            None,
            false,
        );
        assert!(argv.contains(&"--override-os".into()));
        assert!(argv.contains(&"linux".into()));
        assert!(!argv.iter().any(|a| a == "--override-arch"));
    }

    #[test]
    fn docker_transport_host_extracts_registry() {
        // Hub shorthands normalise to docker.io — the key Docker/skopeo
        // authfiles actually use for the Hub.
        assert_eq!(
            docker_transport_host("docker://nginx:1.25"),
            Some("docker.io")
        );
        assert_eq!(
            docker_transport_host("docker://library/nginx:1.25"),
            Some("docker.io")
        );
        // A first segment without `.`/`:` (and not localhost) is a Hub
        // namespace, not a registry host.
        assert_eq!(
            docker_transport_host("docker://registry-a/foo:v1"),
            Some("docker.io")
        );
        // Real hosts (dotted, ported, or localhost) pass through.
        assert_eq!(
            docker_transport_host("docker://registry.local/foo:v1"),
            Some("registry.local")
        );
        assert_eq!(
            docker_transport_host("docker://host:5000/lib/x:tag"),
            Some("host:5000")
        );
        assert_eq!(
            docker_transport_host("docker://localhost/foo"),
            Some("localhost")
        );
        // Non-docker transports have no registry host to authenticate against.
        assert_eq!(docker_transport_host("docker-archive:/tmp/x.tar"), None);
        assert_eq!(docker_transport_host("oci:/layout:tag"), None);
        assert_eq!(docker_transport_host("dir:/path"), None);
    }

    #[test]
    fn authcreds_raw_splits_on_first_colon() {
        assert_eq!(
            AuthCreds::Raw("admin:s3cret").user_pass(),
            Some(("admin", "s3cret"))
        );
        // Password may itself contain colons.
        assert_eq!(
            AuthCreds::Raw("user:pass:with:colons").user_pass(),
            Some(("user", "pass:with:colons"))
        );
        // Empty / no-username creds are anonymous.
        assert_eq!(AuthCreds::Raw("").user_pass(), None);
        assert_eq!(AuthCreds::Raw(":onlypass").user_pass(), None);
        assert_eq!(AuthCreds::Raw("noseparator").user_pass(), None);
    }

    #[test]
    fn authcreds_split_handles_empty_user() {
        assert_eq!(
            AuthCreds::Split {
                user: "u",
                pass: "p"
            }
            .user_pass(),
            Some(("u", "p"))
        );
        assert_eq!(
            AuthCreds::Split {
                user: "",
                pass: "p"
            }
            .user_pass(),
            None
        );
    }

    #[test]
    fn write_skopeo_authfile_returns_none_for_anonymous() {
        // Empty/anonymous creds don't need an auth file at all.
        assert!(write_skopeo_authfile("reg.local", AuthCreds::Raw(""))
            .unwrap()
            .is_none());
        assert!(
            write_skopeo_authfile("reg.local", AuthCreds::Split { user: "", pass: "" })
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn write_skopeo_authfile_writes_valid_docker_format() {
        use k7s_deps::base64::Engine;
        let path = write_skopeo_authfile(
            "harbor.local",
            AuthCreds::Split {
                user: "admin",
                pass: "s3cret",
            },
        )
        .unwrap()
        .expect("auth file should be created for real creds");

        let body = std::fs::read_to_string(&path).unwrap();
        let _ = cleanup_authfile(Some(&path));

        // The auth value must be base64("admin:s3cret"), and the structure must
        // be a valid Docker auth file skopeo can consume via --authfile.
        let expected_auth =
            k7s_deps::base64::engine::general_purpose::STANDARD.encode("admin:s3cret");
        assert!(
            body.contains(r#""harbor.local""#),
            "body missing host: {body}"
        );
        assert!(
            body.contains(&expected_auth),
            "body missing base64 auth: {body}"
        );
        let parsed: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_str(&body).unwrap();
        assert_eq!(
            parsed["auths"]["harbor.local"]["auth"].as_str(),
            Some(expected_auth.as_str())
        );
    }
}
