//! Local audit trail for dangerous operations.
//!
//! k7s exposes cluster-control primitives (interactive shells, node shells,
//! exec, file writes into pods, apply/delete/drain, helm operations) over
//! three transports — the Tauri desktop shell, the web server, and MCP.
//! Until now none of them left a record of *who did what to which target*.
//! This module is the shared sink: one JSON line per dangerous action,
//! appended to `<data_dir>/audit.log` (mode 0600).
//!
//! The API is deliberately tiny and best-effort:
//!
//! - [`set_dir`] is called once at shell startup with the same `data_dir`
//!   the `CoreState` uses. Before that, [`record`] is a no-op.
//! - [`record`] never fails the calling operation: audit writes must not
//!   break the audited feature. Failures are logged via `tracing` only.
//!
//! What to record: the operation type (`action`), plus enough `detail` to
//! answer "who/what/where" — transport, namespace/pod/node, command or
//! path, outcome. Never record secrets (tokens, Secret contents).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

use k7s_deps::serde_json::Value;

/// File name (under the data dir) the audit trail is appended to.
const AUDIT_FILE: &str = "audit.log";

static AUDIT_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Point the audit trail at `dir`. Call once at shell startup, with the
/// same `data_dir` handed to [`crate::core::state::CoreState`]. Later calls
/// are ignored (first writer wins).
pub fn set_dir(dir: impl Into<PathBuf>) {
    let _ = AUDIT_DIR.set(dir.into());
}

/// Append one audit record. No-op (and quiet) when [`set_dir`] was never
/// called. Best-effort: write failures are logged, never propagated.
pub fn record(action: &str, detail: Value) {
    let Some(dir) = AUDIT_DIR.get() else {
        return;
    };
    record_to(dir, action, detail);
}

fn record_to(dir: &std::path::Path, action: &str, detail: Value) {
    let path = dir.join(AUDIT_FILE);
    let line = k7s_deps::serde_json::json!({
        "ts": k7s_deps::chrono::Utc::now().to_rfc3339(),
        "action": action,
        "detail": detail,
    });
    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            k7s_deps::tracing::warn!("audit: could not open {}: {e}", path.display());
            return;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = file.metadata() {
            let perms = meta.permissions();
            if perms.mode() & 0o077 != 0 {
                let mut p = perms.clone();
                p.set_mode(0o600);
                let _ = std::fs::set_permissions(&path, p);
            }
        }
    }
    // One write_all per record: rendering the Value through `writeln!`
    // issues many small writes (serde_json writes fragment by fragment),
    // and concurrent callers would interleave mid-record, tearing lines.
    // A single O_APPEND write keeps every record an intact line even when
    // parallel operations audit at the same time.
    let mut buf = line.to_string();
    buf.push('\n');
    if let Err(e) = file.write_all(buf.as_bytes()) {
        k7s_deps::tracing::warn!("audit: could not append to {}: {e}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_writes_json_line() {
        let dir = std::env::temp_dir().join(format!("k7s-audit-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        record_to(
            &dir,
            "shell.start",
            k7s_deps::serde_json::json!({"pod": "nginx-abc", "namespace": "default"}),
        );
        record_to(
            &dir,
            "shell.input",
            k7s_deps::serde_json::json!({"stream": "sh-nginx-abc-1"}),
        );

        let content = std::fs::read_to_string(dir.join(AUDIT_FILE)).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = k7s_deps::serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["action"], "shell.start");
        assert_eq!(first["detail"]["pod"], "nginx-abc");
        assert!(first["ts"].as_str().is_some());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(AUDIT_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_without_set_dir_is_noop() {
        // set_dir was never called with this process's AUDIT_DIR (tests share
        // the process; another test may have set it, so just assert no panic).
        record("noop", Value::Null);
    }
}
