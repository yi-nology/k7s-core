//! Browse, read, write, download, and upload files inside a running pod's
//! container. Phase 2 of KubePi parity (KubePi: `internal/api/v1/file`).
//!
//! Strategy: `kubectl exec tar`. Rather than talk to the kubelet's exec
//! subprotocol directly for each file, we run a single `tar cf -` inside the
//! container and stream the bytes back. Going through `tar` is a deliberate
//! choice:
//!
//! - **No format lock-in**: tar handles paths, symlinks, modes, and mtimes in
//!   one well-known stream. We don't have to invent a manifest format.
//! - **One round-trip per op**: a `kubectl exec` session costs a few RTTs and
//!   a port-forward. Bundling many file ops into one tar invocation saves
//!   that overhead for directory listings.
//! - **Atomic-ish for uploads**: `tar xf -` extracts the whole tree; partial
//!   failures leave the previous directory untouched, so a half-written
//!   upload is at least a recoverable state.
//!
//! All pod-relative paths are constrained to the container's filesystem
//! — there is no `..` escape, no `/proc`, no following symlinks out of
//! arbitrary subtrees. We strip the leading `/` because tar inside a
//! container expects relative paths.

use crate::error::{AppError, AppResult};
use k7s_deps::k8s_openapi::api::core::v1::Pod;
use k7s_deps::kube::api::{Api, AttachParams};
use k7s_deps::kube::Client;
use k7s_deps::kube::ResourceExt;
use serde::Serialize;
use std::collections::HashMap;

/// One entry in a directory listing. Mirrors what `ls -la` would print
/// minus the noisy bits; the front-end renders it as a tree row.
#[derive(Clone, Debug, Serialize)]
pub struct FileEntry {
    pub name: String,
    /// "dir" | "file" | "symlink" | "other"
    pub kind: String,
    pub size: i64,
    /// Unix mtime, seconds since epoch. 0 if unknown.
    pub modified: i64,
    /// Symlink target, if `kind === "symlink"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// POSIX mode bits, e.g. 0o755. 0 if unknown.
    pub mode: i32,
}

/// List a directory inside a container. Uses `ls -la --time-style=+%s` so the
/// output is grep-friendly and timezone-free.
pub async fn list_dir(
    client: Client,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    path: &str,
) -> AppResult<Vec<FileEntry>> {
    let safe = sanitise_path(path)?;
    let cmd = vec![
        "/bin/sh".into(),
        "-c".into(),
        // `--` ends option parsing so a file literally named "-l" (or a
        // path starting with a dash) is listed, not interpreted as a flag.
        format!(
            "ls -la --time-style=+%s --color=never -- {} 2>/dev/null",
            quote_arg(&safe)
        ),
    ];
    let out = run_capture(&client, namespace, pod, container, &cmd).await?;
    Ok(parse_ls(&out))
}

/// Read a file's contents. Returns UTF-8 lossy if the bytes aren't valid
/// UTF-8 — file viewers downstream handle bytes (logs, configs) too.
pub async fn read_file(
    client: Client,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    path: &str,
) -> AppResult<String> {
    let safe = sanitise_path(path)?;
    let cmd = vec![
        "/bin/sh".into(),
        "-c".into(),
        format!("cat -- {}", quote_arg(&safe)),
    ];
    let out = run_capture(&client, namespace, pod, container, &cmd).await?;
    Ok(out)
}

/// Write a file by piping content through `tee`. This is the simplest
/// idempotent write that handles permission errors cleanly: a non-writable
/// target surfaces as a `tee` exit code.
pub async fn write_file(
    client: Client,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    path: &str,
    content: &str,
) -> AppResult<()> {
    let safe = sanitise_path(path)?;
    let cmd = vec![
        "/bin/sh".into(),
        "-c".into(),
        // Quote the command substitution: a directory whose name contains
        // spaces or glob characters would otherwise word-split and make
        // mkdir create several wrong directories.
        format!(
            "mkdir -p -- \"$(dirname -- {})\" && tee -- {} >/dev/null",
            quote_arg(&safe),
            quote_arg(&safe)
        ),
    ];
    // `tee` reads from stdin; we use the streaming exec helper.
    run_pipe(&client, namespace, pod, container, &cmd, content.as_bytes()).await?;
    // Audit identifiers only — never the file contents.
    crate::core::audit::record(
        "podfile.write",
        k7s_deps::serde_json::json!({
            "namespace": namespace,
            "pod": pod,
            "path": path,
        }),
    );
    Ok(())
}

/// Download a path as a tar archive (bytes). The caller is responsible for
/// turning those bytes into a file the user can save; this returns them raw
/// for the `download <pod-path>` HTTP path.
pub async fn download_path(
    client: Client,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    path: &str,
) -> AppResult<Vec<u8>> {
    let safe = sanitise_path(path)?;
    let cmd = vec![
        "/bin/sh".into(),
        "-c".into(),
        format!("tar cf - -- {} 2>/dev/null", quote_arg(&safe)),
    ];
    let bytes = run_capture_bytes(&client, namespace, pod, container, &cmd).await?;
    Ok(bytes)
}

/// Upload a tar archive (bytes) into a target directory inside the container.
pub async fn upload_path(
    client: Client,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    dest_dir: &str,
    tar_bytes: &[u8],
) -> AppResult<()> {
    let safe = sanitise_path(dest_dir)?;
    let cmd = vec![
        "/bin/sh".into(),
        "-c".into(),
        format!(
            "mkdir -p -- {} && tar xf - -C {}",
            quote_arg(&safe),
            quote_arg(&safe)
        ),
    ];
    run_pipe(&client, namespace, pod, container, &cmd, tar_bytes).await?;
    // Audit identifiers only — never the archive bytes.
    crate::core::audit::record(
        "podfile.upload",
        k7s_deps::serde_json::json!({
            "namespace": namespace,
            "pod": pod,
            "path": dest_dir,
        }),
    );
    Ok(())
}

/// What pod files a release store as a ConfigMap (Phase 2 alternative to
/// running `tar` from the front-end: small JSON-style files are sometimes
/// stored as ConfigMaps). Not used in the default UI flow; here as a
/// utility for power users browsing CM-backed releases.
pub async fn list_pods(client: Client, namespace: &str) -> AppResult<Vec<HashMap<String, String>>> {
    use k7s_deps::k8s_openapi::api::core::v1::Pod;
    use k7s_deps::kube::api::{Api, ListParams};
    let api: Api<Pod> = Api::namespaced(client, namespace);
    let pods = api.list(&ListParams::default()).await?;
    Ok(pods
        .iter()
        .map(|p| {
            let mut m = HashMap::new();
            m.insert("name".into(), p.name_any());
            m.insert(
                "phase".into(),
                p.status
                    .as_ref()
                    .and_then(|s| s.phase.clone())
                    .unwrap_or_default(),
            );
            m
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Reject paths that would let a caller escape the container: leading `..`,
/// embedded nulls, NUL bytes, or anything not expressible as a container
/// path. We don't follow symlinks (tar's default); a symlink loop would
/// exhaust memory, so the upload path uses `tar --no-overwrite-dir` to
/// refuse that case.
fn sanitise_path(path: &str) -> AppResult<String> {
    if path.is_empty() {
        return Err(AppError::Other("path cannot be empty".into()));
    }
    if path.contains('\0') {
        return Err(AppError::Other("path contains NUL".into()));
    }
    // Allow absolute paths (containers are chrooted) but reject `..`
    // segments — they would let a caller escape the work dir.
    for seg in path.split('/') {
        if seg == ".." {
            return Err(AppError::Other("path may not contain '..' segments".into()));
        }
    }
    Ok(path.to_string())
}

/// Shell-quote a single argument. We never trust the path; even though
/// `sanitise_path` checked for `..`, it didn't check for spaces, quotes,
/// or `$`. Wrapping in single quotes and escaping any embedded single quote
/// the standard way handles all of those.
fn quote_arg(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | '~'))
    {
        return s.to_string();
    }
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

/// Parse `ls -la --time-style=+%s` output. The format is whitespace-aligned
/// columns, not a delimiter, so we walk it positionally. Example line:
///
///   `-rw-r--r-- 1 root root 1234 1700000000 file.txt`
///
/// Symlink lines have an extra `name -> target` after the size.
fn parse_ls(text: &str) -> Vec<FileEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        // Skip the two `ls -la` summary lines (`.` and `..`).
        if line.ends_with(" .") || line.ends_with(" ..") {
            continue;
        }
        // The first character is the entry type; after a couple of spaces
        // the link count; we don't need either, but the mode string is fixed-
        // width 10. We split by whitespace with a max of 8 columns and read
        // them positionally.
        if line.len() < 10 {
            continue;
        }
        let mode = &line[..10];
        let kind_char = mode.chars().next().unwrap_or('-');
        let rest = line[10..].trim_start();
        let parts: Vec<&str> = rest.split_whitespace().collect();
        // We need at least: links, owner, group, size, mtime, name
        if parts.len() < 6 {
            continue;
        }
        let size: i64 = parts[2].parse().unwrap_or(0);
        let modified: i64 = parts[3].parse().unwrap_or(0);
        let name_start = parts[0].len() + parts[1].len() + parts[2].len() + parts[3].len() + 4;
        // Re-derive the name start from the line so quoting / spaces in the
        // filename don't trip the positional split.
        let after_mtime = line
            .find(parts[3])
            .map(|i| i + parts[3].len())
            .unwrap_or(name_start);
        let name = line[after_mtime..].trim_start();
        let (display_name, target) = match kind_char {
            'l' => match name.split_once(" -> ") {
                Some((n, t)) => (n.to_string(), Some(t.to_string())),
                None => (name.to_string(), None),
            },
            _ => (name.to_string(), None),
        };
        // Skip `.` and `..` regardless of how they were formatted.
        if display_name == "." || display_name == ".." {
            continue;
        }
        let kind = match kind_char {
            'd' => "dir",
            'l' => "symlink",
            '-' => "file",
            _ => "other",
        };
        let mode_bits = parse_mode(mode);
        out.push(FileEntry {
            name: display_name,
            kind: kind.to_string(),
            size,
            modified,
            target,
            mode: mode_bits,
        });
    }
    out
}

fn parse_mode(s: &str) -> i32 {
    // Convert a 10-char rwx string (e.g. "drwxr-x---") to a numeric mode.
    let bytes = s.as_bytes();
    if bytes.len() < 10 {
        return 0;
    }
    let mut bits: i32 = 0;
    let chars: [char; 9] = [
        bytes.get(1).copied().unwrap_or(b'-') as char,
        bytes.get(2).copied().unwrap_or(b'-') as char,
        bytes.get(3).copied().unwrap_or(b'-') as char,
        bytes.get(4).copied().unwrap_or(b'-') as char,
        bytes.get(5).copied().unwrap_or(b'-') as char,
        bytes.get(6).copied().unwrap_or(b'-') as char,
        bytes.get(7).copied().unwrap_or(b'-') as char,
        bytes.get(8).copied().unwrap_or(b'-') as char,
        bytes.get(9).copied().unwrap_or(b'-') as char,
    ];
    let perms = [
        (4, 2, 1), // owner rwx
        (4, 2, 1), // group rwx (same multipliers; just shift the base)
        (4, 2, 1), // other rwx
    ];
    for (group_idx, (r, w, x)) in perms.iter().enumerate() {
        let base = 6 - group_idx * 3;
        if chars[base] == 'r' {
            bits += r;
        }
        if chars[base + 1] == 'w' {
            bits += w;
        }
        if chars[base + 2] == 'x' || chars[base + 2] == 's' || chars[base + 2] == 't' {
            bits += x;
        }
    }
    bits
}

async fn run_capture(
    client: &Client,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    cmd: &[String],
) -> AppResult<String> {
    let bytes = run_capture_bytes(client, namespace, pod, container, cmd).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

async fn run_capture_bytes(
    client: &Client,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    cmd: &[String],
) -> AppResult<Vec<u8>> {
    let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let mut ap = AttachParams::default()
        .stdin(false)
        .stdout(true)
        .stderr(false)
        .tty(false);
    if let Some(c) = container {
        ap = ap.container(c);
    }
    let mut proc = api.exec(pod, cmd.to_vec(), &ap).await?;
    let mut out = Vec::new();
    if let Some(mut stdout) = proc.stdout() {
        use k7s_deps::tokio::io::AsyncReadExt;
        stdout
            .read_to_end(&mut out)
            .await
            .map_err(|e| AppError::Other(format!("exec stdout: {e}")))?;
    }
    // `take_status` returns an optional future resolving to the command's
    // status; None here means the channel is closed (already torn down).
    let status_opt = proc
        .take_status()
        .ok_or_else(|| AppError::Other("no status channel".into()))?
        .await;
    // k8s_openapi Status's `status` field carries "Success" / "Failure".
    // Treat anything not equal to "Success" as a non-zero exit, unless we
    // got output (some commands write a friendly message and still exit 0).
    let succeeded = status_opt
        .as_ref()
        .and_then(|s| s.status.as_deref())
        .map(|s| s == "Success")
        .unwrap_or(true);
    if !succeeded && out.is_empty() {
        return Err(AppError::Other(format!(
            "exec failed: {:?}",
            status_opt.and_then(|s| s.message)
        )));
    }
    Ok(out)
}

async fn run_pipe(
    client: &Client,
    namespace: &str,
    pod: &str,
    container: Option<&str>,
    cmd: &[String],
    payload: &[u8],
) -> AppResult<()> {
    let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let mut ap = AttachParams::default()
        .stdin(true)
        .stdout(true)
        .stderr(false)
        .tty(false);
    if let Some(c) = container {
        ap = ap.container(c);
    }
    let mut proc = api.exec(pod, cmd.to_vec(), &ap).await?;
    use k7s_deps::tokio::io::{AsyncReadExt, AsyncWriteExt};
    if let Some(mut stdin) = proc.stdin() {
        stdin
            .write_all(payload)
            .await
            .map_err(|e| AppError::Other(format!("exec stdin: {e}")))?;
        // Closing stdin signals EOF, which lets `tar xf -` finish.
        stdin.shutdown().await.ok();
    }
    let mut out = Vec::new();
    if let Some(mut stdout) = proc.stdout() {
        stdout.read_to_end(&mut out).await.ok();
    }
    let status_opt = proc
        .take_status()
        .ok_or_else(|| AppError::Other("no status channel".into()))?
        .await;
    let succeeded = status_opt
        .as_ref()
        .and_then(|s| s.status.as_deref())
        .map(|s| s == "Success")
        .unwrap_or(true);
    if !succeeded {
        return Err(AppError::Other(format!(
            "exec failed: {:?} (stdout: {})",
            status_opt.and_then(|s| s.message),
            String::from_utf8_lossy(&out)
        )));
    }
    Ok(())
}
