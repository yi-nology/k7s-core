//! Error types for the AI module.
//!
//! Kept separate from the top-level [`crate::AppError`] because AI errors have a
//! richer taxonomy the agent loop wants to distinguish (a tool being denied by
//! the permission gate is recoverable and worth telling the LLM; an LLM HTTP
//! failure is not). The single `From<AiError> for AppError` impl lets commands
//! return them with `?` without the caller caring about the variants.

use crate::error::{AppError, AppResult};
use std::fmt;

/// Everything that can go wrong inside the AI module.
#[derive(Debug)]
pub enum AiError {
    /// AI is toggled off in settings — the command should never have been called.
    Disabled,
    /// The configured `base_url` / `api_key` / `model` is missing or bad.
    NotConfigured(&'static str),
    /// A network or HTTP failure talking to the LLM provider.
    Llm(String),
    /// The LLM returned a response we couldn't parse (malformed JSON, no choices, …).
    LlmParse(String),
    /// A tool was invoked but the LLM-supplied arguments didn't match its schema.
    ToolArgs(String),
    /// A tool ran and the underlying kube call failed. The string is the kube error.
    Tool(String),
    /// A write tool was blocked by the permission gate. Recoverable: the agent loop
    /// feeds this back to the LLM so it can pick a read-only alternative or stop.
    PermissionDenied(String),
    /// The user declined a write-operation approval, or cancelled the run.
    Cancelled,
    /// The agent loop hit its turn cap without the LLM producing a final answer.
    TurnLimit,
    /// Generic catch-all.
    Other(String),
}

impl fmt::Display for AiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AiError::Disabled => write!(f, "AI assistant is disabled"),
            AiError::NotConfigured(w) => write!(f, "AI not configured: {w}"),
            AiError::Llm(m) => write!(f, "LLM request failed: {m}"),
            AiError::LlmParse(m) => write!(f, "LLM response parse failed: {m}"),
            AiError::ToolArgs(m) => write!(f, "invalid tool arguments: {m}"),
            AiError::Tool(m) => write!(f, "tool error: {m}"),
            AiError::PermissionDenied(m) => write!(f, "permission denied: {m}"),
            AiError::Cancelled => write!(f, "cancelled"),
            AiError::TurnLimit => write!(f, "agent turn limit reached"),
            AiError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for AiError {}

impl From<AiError> for AppError {
    fn from(e: AiError) -> Self {
        // AppError has no AI-specific variants worth mapping onto, and the
        // AI taxonomy already carries user-appropriate messages in its
        // Display — so every variant funnels through Other unchanged. (The
        // old two-arm match mapped both arms to exactly this.)
        AppError::Other(e.to_string())
    }
}

impl From<AiError> for AppResult<()> {
    fn from(e: AiError) -> Self {
        Err(e.into())
    }
}

impl From<k7s_deps::serde_json::Error> for AiError {
    fn from(e: k7s_deps::serde_json::Error) -> Self {
        AiError::ToolArgs(format!("json: {e}"))
    }
}

/// Convenience alias used throughout the module.
pub type AiResult<T> = Result<T, AiError>;
