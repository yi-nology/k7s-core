//! AI assistant configuration — load / save / defaults.
//!
//! Mirrors the storage pattern of [`crate::kube::observability::metrics_config`]: a single JSON
//! file (`ai-config.json`) under the app config dir, written atomically via a
//! `.tmp` rename. The `api_key` is never stored in plaintext here — it goes
//! through [`crate::ai::secret`] which encrypts it at rest. This file holds only
//! the non-secret envelope; the key is merged back in at load time.

use crate::ai::error::{AiError, AiResult};
use crate::ai::secret;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How aggressive the AI is allowed to be on the cluster.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionMode {
    /// No write tools are even offered to the LLM.
    ReadOnly,
    /// Write tools are offered but every invocation pauses for user approval.
    #[default]
    ReadConfirmWrite,
    /// Write tools run without confirmation. Use with care.
    FullAuto,
}

/// Non-secret LLM provider config. The secret `api_key` lives in [`secret`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmProviderConfig {
    /// OpenAI-compatible base URL, e.g. `https://api.deepseek.com/v1`.
    /// No trailing slash. Defaults empty — must be set before first use.
    #[serde(default)]
    pub base_url: String,
    /// Model id, e.g. `deepseek-chat`, `gpt-4o-mini`, `kimi-k2`. Empty by default.
    #[serde(default)]
    pub model: String,
    /// Sampling temperature. `None` = provider default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

/// The whole persisted AI config. Serialized to `ai-config.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiConfig {
    /// Master switch. When `false`, the AI panel is hidden and `ai_chat` refuses.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: LlmProviderConfig,
    #[serde(default)]
    pub permission: PermissionMode,
    /// Hard cap on agent loop turns. Prevents a runaway LLM from burning tokens.
    #[serde(default = "default_max_turns")]
    pub max_turns: u32,
    /// Sandbox security settings (denied namespaces, policy rules, rate
    /// limits). Persisted here so the config file is the single place a user
    /// edits; `SandboxConfig::default()` is fail-secure.
    #[serde(default)]
    pub sandbox: crate::ai::sandbox::SandboxConfig,
}

fn default_max_turns() -> u32 {
    10
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: LlmProviderConfig::default(),
            permission: PermissionMode::default(),
            max_turns: default_max_turns(),
            sandbox: crate::ai::sandbox::SandboxConfig::default(),
        }
    }
}

/// What the frontend sees: identical to [`AiConfig`] but with the api_key field
/// present (masked — `Some("".to_string())` indicates a key is set). This keeps
/// the wire shape simple and avoids leaking the key bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiConfigView {
    #[serde(flatten)]
    pub config: AiConfig,
    /// True when an api_key is stored (the key bytes themselves are never sent
    /// to the UI). The frontend uses this only to show the "key set" indicator.
    #[serde(default)]
    pub has_api_key: bool,
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Config file inside a specific data dir (used by the Tauri shell, which has a
/// real `app_config_dir`).
pub fn config_path_in(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("ai-config.json")
}

fn config_path() -> AiResult<PathBuf> {
    Ok(crate::ai::default_config_dir()?.join("ai-config.json"))
}

/// Load config + merge in the api_key indicator (key bytes stay in `secret`).
///
/// `data_dir` is `Some` when called from a shell that owns one (Tauri / web);
/// `None` falls back to the platform default dir.
///
/// This is a synchronous function (uses `std::fs`); callers should run it on a
/// thread that's allowed to block, which Tauri command futures are.
pub fn load(data_dir: Option<&std::path::Path>) -> AiResult<AiConfigView> {
    let path = match data_dir {
        Some(d) => config_path_in(d),
        None => config_path()?,
    };
    let config = if !path.exists() {
        AiConfig::default()
    } else {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| AiError::Other(format!("read {}: {e}", path.display())))?;
        if text.trim().is_empty() {
            AiConfig::default()
        } else {
            k7s_deps::serde_json::from_str(&text)
                .map_err(|e| AiError::Other(format!("parse {}: {e}", path.display())))?
        }
    };
    let has_api_key = secret::load(data_dir)?
        .map(|k| !k.is_empty())
        .unwrap_or(false);
    Ok(AiConfigView {
        config,
        has_api_key,
    })
}

/// Persist config. The api_key is **not** written here — the UI sends it
/// separately via [`save_api_key`].
pub fn save(data_dir: Option<&std::path::Path>, config: &AiConfig) -> AiResult<()> {
    let dir = match data_dir {
        Some(d) => d.to_path_buf(),
        None => crate::ai::default_config_dir()?,
    };
    std::fs::create_dir_all(&dir)
        .map_err(|e| AiError::Other(format!("mkdir {}: {e}", dir.display())))?;
    let path = dir.join("ai-config.json");
    crate::ai::atomic_write_json(&path, config)
        .map_err(|e| AiError::Other(format!("write config: {e}")))?;
    Ok(())
}

/// Store (or clear, when empty) the api_key, encrypted at rest.
pub fn save_api_key(data_dir: Option<&std::path::Path>, key: &str) -> AiResult<()> {
    secret::save(data_dir, key)
}

/// Validate that config is usable for a chat. Returns the resolved
/// `(base_url, model, api_key)` triple the LLM client needs.
pub fn resolve(
    config: &AiConfig,
    data_dir: Option<&std::path::Path>,
) -> AiResult<(String, String, String)> {
    if !config.enabled {
        return Err(AiError::Disabled);
    }
    let base = config.provider.base_url.trim();
    if base.is_empty() {
        return Err(AiError::NotConfigured("base_url is empty"));
    }
    let model = config.provider.model.trim();
    if model.is_empty() {
        return Err(AiError::NotConfigured("model is empty"));
    }
    let api_key = secret::load(data_dir)?
        .filter(|k| !k.is_empty())
        .ok_or(AiError::NotConfigured("api_key is empty"))?;
    Ok((base.to_string(), model.to_string(), api_key))
}
