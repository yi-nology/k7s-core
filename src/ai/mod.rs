//! AI assistant module — a built-in, runtime-toggleable Kubernetes AI agent.
//!
//! Inspired by openocta's "natural language → automatic execution" experience,
//! specialized for k8s ops. Unlike k7s's existing MCP server (which exposes
//! tools for *external* AI clients to drive), this module embeds the LLM
//! *inside* k7s itself, so the user gets a chat panel right in the app.
//!
//! # Architecture (one-paragraph tour)
//!
//! [`config`] loads the user's `AiConfig` (provider/permission/sandbox/toggle)
//! from `ai-config.json`; the `api_key` is stored separately, obfuscated, in
//! [`secret`]. [`llm::OpenAiClient`] is the OpenAI-compatible streaming client
//! (covers DeepSeek/Kimi/Zhipu/OpenAI/Ollama). [`tools`] is an *independent*
//! tool set — a `Tool` trait + `ToolRegistry`, ~12 tools in read/write/diag
//! groups — designed for LLM function-calling (Plan C). Under the hood every
//! tool reuses [`crate::core::shell_common`]'s free functions plus raw `kube`
//! calls (it deliberately avoids the feature-gated `crate::mcp::kube_api`, so
//! the AI module ships in the plain desktop build), so there's no second
//! cluster-access layer (Plan A reuse). [`permission`] is the hard gate write
//! tools pass through. [`agent::AgentLoop`] is the ReAct cycle: LLM → tool
//! calls → permission gate → execute → loop, streaming events to the caller
//! via the transport-agnostic [`agent::EventSink`] trait.
//!
//! # Runtime toggle
//!
//! The whole module is compiled into every build (no Cargo feature gate), but
//! [`AiConfig::enabled`] defaults to `false`. When disabled, the Tauri
//! `ai_chat` command refuses and the UI hides the panel. Flipping the toggle in
//! settings is enough — no recompile, no separate binary.

pub mod agent;
pub mod browser;
pub mod config;
pub mod context;
pub mod context_compress;
pub mod cron;
pub mod embedded_models;
pub mod error;
pub mod evolution;
pub mod hooks;
pub mod knowledge_sync;
pub mod llm;
pub mod memory;
pub mod permission;
pub mod plugins;
pub mod prompt_builder;
pub mod sandbox;
pub mod secret;
pub mod session;
pub mod skills;
pub mod timeouts;
pub mod tools;

pub use agent::{AgentEvent, AgentLoop, ChatRequest, EventSink};
pub use config::{AiConfig, AiConfigView, LlmProviderConfig, PermissionMode};
pub use error::{AiError, AiResult};
pub use llm::{FunctionDef, LlmClient, Message, OpenAiClient};
pub use memory::{MemoryEntry, MemorySource, MemoryStore};
pub use skills::{Skill, SkillExample, SkillRegistry};
pub use tools::{ToolContext, ToolRegistry};

/// Resolve the platform-specific default config directory.
///
/// Uses the same platform rule as `metrics_config.rs`: macOS →
/// `~/Library/Application Support/k7s`, else `~/.config/k7s`. The Tauri shell
/// overrides this with `app_config_dir()` via callers that pass `data_dir`.
pub fn default_config_dir() -> error::AiResult<std::path::PathBuf> {
    let dir = match std::env::var_os("HOME") {
        Some(h) => std::path::PathBuf::from(h).join(if cfg!(target_os = "macos") {
            "Library/Application Support/k7s"
        } else {
            ".config/k7s"
        }),
        None => return Err(error::AiError::Other("no HOME".into())),
    };
    std::fs::create_dir_all(&dir)
        .map_err(|e| error::AiError::Other(format!("mkdir {}: {e}", dir.display())))?;
    Ok(dir)
}

/// Atomically write a JSON-serialisable value to `path`.
///
/// Writes to a `.json.tmp` sibling first, then renames — so a crash mid-write
/// never leaves a half-written file on disk.
pub fn atomic_write_json<T: serde::Serialize + ?Sized>(
    path: &std::path::Path,
    value: &T,
) -> std::io::Result<()> {
    let text = k7s_deps::serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &text)?;
    std::fs::rename(&tmp, path)
}

/// Read a JSON file and deserialize it, returning `T::default()` when it's
/// missing or empty.
///
/// Corrupt JSON is treated differently from "never persisted": the broken
/// bytes are renamed to `<path>.corrupt` (so the next save doesn't silently
/// destroy them and the user can recover) and an error is logged, then
/// defaults are returned — one bad file must not take the whole module down.
pub fn atomic_read_json<T: serde::de::DeserializeOwned + Default>(path: &std::path::Path) -> T {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return T::default(),
        Err(e) => {
            // Unreadable for another reason (permissions, …): warn and fall
            // back like before rather than crash every caller.
            k7s_deps::tracing::warn!(
                path = %path.display(),
                error = %e,
                "cannot read JSON file; using defaults"
            );
            return T::default();
        }
    };
    if text.trim().is_empty() {
        return T::default();
    }
    match k7s_deps::serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            let mut backup = path.as_os_str().to_os_string();
            backup.push(".corrupt");
            if let Err(rename_err) = std::fs::rename(path, &backup) {
                k7s_deps::tracing::warn!(
                    path = %path.display(),
                    error = %rename_err,
                    "could not back up corrupt JSON file"
                );
            }
            k7s_deps::tracing::error!(
                path = %path.display(),
                error = %e,
                "corrupt JSON file; backed up and reset to defaults"
            );
            T::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "k7s-ai-test-mod-{tag}-{}",
            k7s_deps::uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("state.json")
    }

    /// Missing file → defaults, quietly (nothing was ever persisted).
    #[test]
    fn missing_file_returns_default() {
        let path = temp_file("missing");
        let v: k7s_deps::serde_json::Value = atomic_read_json(&path);
        assert!(v.is_null());
    }

    /// Corrupt JSON → defaults, and the broken bytes are kept as `.corrupt`
    /// instead of being overwritten by the next save.
    #[test]
    fn corrupt_file_backed_up_and_reset() {
        let path = temp_file("corrupt");
        std::fs::write(&path, "{ not valid json !!!").unwrap();
        let v: k7s_deps::serde_json::Value = atomic_read_json(&path);
        assert!(v.is_null());
        let backup = path.with_file_name("state.json.corrupt");
        assert!(backup.exists(), "corrupt bytes must be preserved");
        assert_eq!(
            std::fs::read_to_string(&backup).unwrap(),
            "{ not valid json !!!"
        );
        assert!(!path.exists(), "original path is freed for a fresh write");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Valid and empty files keep their existing behavior.
    #[test]
    fn valid_and_empty_files() {
        let path = temp_file("valid");
        std::fs::write(&path, r#"{"ok":true}"#).unwrap();
        let v: k7s_deps::serde_json::Value = atomic_read_json(&path);
        assert_eq!(v["ok"], true);

        std::fs::write(&path, "   \n").unwrap();
        let v: k7s_deps::serde_json::Value = atomic_read_json(&path);
        assert!(v.is_null());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
