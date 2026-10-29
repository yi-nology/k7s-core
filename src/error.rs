//! Application error type.
//!
//! Every Tauri command returns `Result<T, AppError>`. `AppError` serializes to a
//! plain string so the frontend receives a human-readable message (e.g. a
//! kubeconfig parse failure or a Kubernetes API 403) rather than an opaque code.

use serde::{Serialize, Serializer};

/// The single error type surfaced to the frontend across the command boundary.
#[derive(Debug, k7s_deps::thiserror::Error)]
pub enum AppError {
    /// No kubeconfig could be found or parsed.
    #[error("kubeconfig error: {0}")]
    Kubeconfig(String),

    /// Building a client or talking to the API server failed.
    #[error("kubernetes error: {0}")]
    Kube(String),

    /// A requested context/resource was not present.
    #[error("not found: {0}")]
    NotFound(String),

    /// The server is reachable but no cluster is currently connected. The
    /// front-end can switch on this variant to drive a "connect to a cluster"
    /// banner instead of treating it as a generic failure — `NotFound` is
    /// overloaded and a missing object looks the same as "you're not even
    /// talking to a cluster yet". Splitting it out makes that case
    /// cheap to detect without string-matching the message.
    #[error("not connected to a cluster")]
    Disconnected,

    /// The caller acted on a connection that is no longer the active one
    /// (another web session switched the shared manager's cluster).
    #[error("{0}")]
    Conflict(String),

    /// YAML (de)serialization failed while reading or applying a manifest.
    #[error("yaml error: {0}")]
    Yaml(String),

    /// Catch-all for anything that doesn't fit the above.
    #[error("{0}")]
    Other(String),
}

// Serialize the error as its `Display` string. Tauri sends this to the webview,
// where the UI shows it verbatim (e.g. inline under the YAML editor).
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// Convenience conversions so `?` works against the crates we use most.
impl From<k7s_deps::kube::Error> for AppError {
    fn from(e: k7s_deps::kube::Error) -> Self {
        AppError::Kube(e.to_string())
    }
}

impl From<k7s_deps::kube::config::KubeconfigError> for AppError {
    fn from(e: k7s_deps::kube::config::KubeconfigError) -> Self {
        AppError::Kubeconfig(e.to_string())
    }
}

impl From<k7s_deps::yaml_serde::Error> for AppError {
    fn from(e: k7s_deps::yaml_serde::Error) -> Self {
        AppError::Yaml(e.to_string())
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        AppError::Other(s)
    }
}

impl From<k7s_deps::tokio::task::JoinError> for AppError {
    fn from(e: k7s_deps::tokio::task::JoinError) -> Self {
        AppError::Other(e.to_string())
    }
}

impl From<k7s_deps::anyhow::Error> for AppError {
    fn from(e: k7s_deps::anyhow::Error) -> Self {
        AppError::Other(e.to_string())
    }
}

/// Shorthand for command return types.
pub type AppResult<T> = Result<T, AppError>;
