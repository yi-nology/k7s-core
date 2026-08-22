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
#[cfg(not(target_os = "ios"))]
pub mod helm;
pub mod image;
pub mod observability;
pub mod security;
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
pub mod pod_diagnosis;
#[cfg(not(target_os = "ios"))]
pub mod pod_files;
pub mod portforward;
pub mod properties;
#[cfg(not(target_os = "ios"))]
pub mod restart;
pub mod rollout;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
#[cfg(not(target_os = "ios"))]
#[cfg(not(target_os = "ios"))]
pub mod templates;
pub mod watchers;

use serde::Serialize;

mod kind;
pub mod events;
pub use discovery::{custom_kind_counts, CustomKindCount};
pub use kind::*;
pub use dto::Row;
pub use manager::ClientManager;




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
