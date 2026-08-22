//! Shared preferences schema and I/O.
//!
//! Both the Tauri shell and the web shell read/write the same `prefs.json` file.
//! This module is the single source of truth for the schema and the I/O helpers,
//! eliminating the hand-synced duplicate that previously lived in `commands.rs`
//! and `web::handlers::prefs_io`.

use crate::error::{AppError, AppResult};
use std::path::{Path, PathBuf};

/// Persisted UI preferences (B11): where the user left off. Written to
/// `<app_config_dir>/prefs.json`.
///
/// This struct is the schema of prefs.json — not just the part Rust uses.
/// Frontend-only fields are carried here so that a round-trip save doesn't
/// silently delete them (serde drops unknown fields by default).
#[derive(serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Prefs {
    pub context: Option<String>,
    pub nav: Option<String>,
    pub namespace: Option<String>,
    pub show_timestamps: Option<bool>,
    /// Kubeconfig files the user imported, re-imported on boot (B17).
    pub imported_files: Option<Vec<String>>,
    // ---- settings (B23) ----
    /// Seconds between metrics polls; None uses the built-in default.
    pub metrics_interval_secs: Option<u64>,
    /// Seconds between cluster-status polls; None uses the built-in default.
    pub status_interval_secs: Option<u64>,
    /// Shell command override for exec; None/empty uses the bash-or-sh probe.
    pub shell_command: Option<String>,
    /// Log ring-buffer size. Frontend-only; carried so it survives a save.
    pub log_buffer_cap: Option<u32>,
    /// Namespace selected on connect. Frontend-only; carried so it survives a save.
    pub default_namespace: Option<String>,
    /// Colour palette ("dark"/"light"/"system"). Frontend-only; carried so it
    /// survives a save (B52).
    pub theme: Option<String>,
    /// Container image for the node debug shell; None/empty uses the default (B53).
    pub node_shell_image: Option<String>,
    // ---- scanner (SBOM / image vulnerability scanning) ----
    /// Custom path to the trivy binary; None/empty uses auto-detection.
    pub scanner_trivy_path: Option<String>,
    /// Custom path to the grype binary; None/empty uses auto-detection.
    pub scanner_grype_path: Option<String>,
    /// Timeout for scanner invocations (e.g. "5m", "300s"); None uses the default (5m).
    pub scanner_timeout: Option<String>,
}

/// Path to the prefs file under a config directory.
fn prefs_path(data_dir: &Path) -> PathBuf {
    data_dir.join("prefs.json")
}

/// Read persisted prefs from `data_dir`, or defaults when absent/unreadable.
///
/// The backend reads the same prefs file the frontend writes rather than having
/// settings passed in per call: there's then exactly one copy of the truth, and
/// no way for a command to be invoked with settings that disagree with what the
/// user last saved.
pub fn read_prefs(data_dir: &Path) -> Prefs {
    let path = prefs_path(data_dir);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| k7s_deps::serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Default prefs when no file is reachable. Behaviour is the same as a
/// fresh-install prefs.json with no overrides.
pub fn read_prefs_default() -> Prefs {
    Prefs::default()
}

/// Save preferences (best-effort; creates the config dir if needed).
pub fn save_prefs(data_dir: &Path, prefs: &Prefs) -> AppResult<()> {
    let path = prefs_path(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| AppError::Other(e.to_string()))?;
    }
    let text = k7s_deps::serde_json::to_string_pretty(prefs)
        .map_err(|e| AppError::Other(e.to_string()))?;
    std::fs::write(&path, text).map_err(|e| AppError::Other(e.to_string()))?;
    Ok(())
}

/// Load persisted preferences as raw JSON, or None if absent/unreadable.
pub fn load_prefs_json(data_dir: &Path) -> Option<Prefs> {
    let text = std::fs::read_to_string(prefs_path(data_dir)).ok()?;
    k7s_deps::serde_json::from_str(&text).ok()
}

/// Poll intervals from prefs, clamped to the same bounds the settings panel
/// enforces — a hand-edited prefs.json shouldn't be able to hammer the API server.
pub fn poll_intervals(prefs: &Prefs) -> crate::kube::observability::metrics::PollIntervals {
    let clamp = |v: Option<u64>, default: std::time::Duration| {
        v.map(|s| std::time::Duration::from_secs(s.clamp(5, 300)))
            .unwrap_or(default)
    };
    crate::kube::observability::metrics::PollIntervals {
        metrics: clamp(
            prefs.metrics_interval_secs,
            crate::kube::observability::metrics::METRICS_INTERVAL,
        ),
        status: clamp(
            prefs.status_interval_secs,
            crate::kube::observability::metrics::STATUS_INTERVAL,
        ),
    }
}

/// Default poll intervals when prefs aren't readable. Same defaults the Tauri
/// shell uses before the user touches the settings panel.
pub fn poll_intervals_default() -> crate::kube::observability::metrics::PollIntervals {
    crate::kube::observability::metrics::PollIntervals {
        metrics: crate::kube::observability::metrics::METRICS_INTERVAL,
        status: crate::kube::observability::metrics::STATUS_INTERVAL,
    }
}
