//! Kubernetes integration: kubeconfig/contexts, the client manager, per-kind
//! watchers that stream row snapshots, log streaming, and metrics/status pollers.
//!
//! Everything the frontend sees flows through the DTOs in [`dto`] and the Tauri
//! events named in [`events`].

pub mod client;
pub mod config_snapshots;
pub mod dependency_graph;
pub mod discovery;
pub mod drain;
pub mod dto;
pub mod endpoints;
pub mod exec;
// helm + restart compile everywhere: properties/watchers/shell_common
// reference them unconditionally, and the iOS surface simply never exposes
// the commands that call them (the k7s-commands layer owns that gate).
pub mod helm;
pub mod image;
#[cfg(not(target_os = "ios"))]
#[cfg(not(any(target_os = "ios", target_os = "android")))]
#[cfg(not(any(target_os = "ios", target_os = "android")))]
#[cfg(not(any(target_os = "ios", target_os = "android")))]
#[cfg(not(any(target_os = "ios", target_os = "android")))]
#[cfg(not(any(target_os = "ios", target_os = "android")))]
#[cfg(not(any(target_os = "ios", target_os = "android")))]
#[cfg(not(target_os = "ios"))]
pub mod ingress_debug;
pub mod logs;
pub mod manager;
pub mod mappers;
pub mod nodeshell;
pub mod observability;
pub mod pod_diagnosis;
#[cfg(not(target_os = "ios"))]
pub mod pod_files;
pub mod portforward;
pub mod properties;
pub mod restart;
pub mod rollout;
pub mod security;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
#[cfg(not(target_os = "ios"))]
#[cfg(not(target_os = "ios"))]
pub mod templates;
pub mod watchers;

use serde::Serialize;

pub mod events;
mod kind;
pub use discovery::{custom_kind_counts, CustomKindCount};
pub use dto::Row;
pub use kind::*;
pub use manager::ClientManager;

// ---------------------------------------------------------------------------
// Per-user directories
// ---------------------------------------------------------------------------

/// The user's home directory: `$HOME` first, falling back to `$USERPROFILE`
/// (Windows shells routinely leave `HOME` unset, which used to make every
/// JSON side-car store fail with "no HOME" there).
pub(crate) fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
}

/// Resolve (and create) the per-user k7s config directory shared by the JSON
/// side-car stores (registries, alertmanagers, grafana, loki, metrics,
/// saved queries). Replaces six copy-pasted `config_path` helpers: same value
/// as before — `$HOME/Library/Application Support/k7s` on macOS,
/// `$HOME/.config/k7s` elsewhere — with `$USERPROFILE` substituting for a
/// missing `$HOME` so the unix path stays byte-identical for existing data.
pub(crate) fn user_config_dir() -> crate::error::AppResult<std::path::PathBuf> {
    use crate::error::AppError;
    let dir = match home_dir() {
        Some(h) => h.join(if cfg!(target_os = "macos") {
            "Library/Application Support/k7s"
        } else {
            ".config/k7s"
        }),
        None => return Err(AppError::Other("no HOME or USERPROFILE".into())),
    };
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Other(format!("mkdir {}: {e}", dir.display())))?;
    Ok(dir)
}

/// Payload for [`events::RESOURCE_UPDATE`].
///
/// `kind` is the frontend kind id as a string rather than a [`ResourceKind`]:
/// custom (CRD-backed) kinds aren't in that enum, and their ids are "group/plural"
/// (B15). Built-in kinds pass `ResourceKind::id()`, so the wire format is
/// unchanged either way.
#[derive(Serialize, Clone)]
pub struct ResourceUpdate {
    pub kind: String,
    pub rows: Vec<Row>,
}

/// Payload for [`events::WATCH_KIND_STATUS`].
///
/// Emitted when a per-kind watch encounters a 403 Forbidden or recovers from one.
#[derive(Serialize, Clone)]
pub struct KindStatus {
    pub kind: String,
    pub status: String,
}
