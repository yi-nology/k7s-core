//! k7s core — the transport-agnostic layer shared by every shell.
//!
//! This module is the single source of truth for *what k7s does*. It holds:
//!
//! - All Kubernetes plumbing under [`crate::kube`] (re-exported).
//! - The [`EventSink`] trait, the single seam between business logic and whatever
//!   happens to be carrying events to the user (Tauri's `app.emit`, an SSE
//!   stream, a future gRPC server, etc.).
//! - The [`CoreState`] struct that every command handler closes over.
//!
//! Each shell (Tauri, the standalone web server, anything else we add later)
//! builds its own `EventSink` and constructs a `CoreState` from it. From there
//! the same `cmd_*` functions in [`crate::core::commands`] are invoked whether
//! the call originated as a `#[tauri::command]` or an axum route — see
//! `commands.rs` (Tauri) and `web/handlers.rs` (HTTP) for the two adapters.
//!
//! What the core must *not* know: the Tauri runtime, axum, anything in
//! `tauri::AppHandle`, or any specific I/O strategy. Those are shell
//! concerns.

pub mod audit;
pub mod events;
pub mod prefs;
pub mod shell_common;
pub mod state;

pub mod commands;

#[cfg(feature = "tauri")]
pub use events::{tauri_sink, TauriEventSink};
pub use events::{EventSink, McpEventSink, WebEventSink};
pub use state::CoreState;

// Re-export the kube module so the public API stays "kube::client" etc. —
// command handlers and web routes import it from here, the Tauri adapter still
// re-exports it from `crate::kube` for backwards compatibility.
pub use crate::kube;
