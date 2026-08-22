//! Grafana integration (Phase 1 Tier-2 of KubePi parity).
//!
//! Storage: a JSON file under the user config dir, same shape as the
//! image-registry and metrics-config modules. The user can configure
//! several Grafana instances; the UI shows the active one's URL and
//! embeds a chosen dashboard in an iframe.
//!
//! What we don't do: we don't *generate* dashboards. The user picks
//! one from a list of well-known IDs (the "preset" list), and our UI
//! just builds the iframe URL `…/d/<uid>?from=…&to=…&var-datasource=…`.
//! KubePi takes the same shortcut — generating bespoke dashboards
//! would mean a JSON editor, which is its own project.

use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrafanaConfig {
    pub name: String,
    /// `https://grafana.example.com` — no trailing slash.
    pub url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default, skip_serializing)]
    pub password: String,
    /// API token. In Grafana 9+ the recommended way to authenticate is a
    /// service-account token; we accept it as `api_token` in the upsert
    /// form and store it in the side-channel the same way we do passwords.
    #[serde(default, skip_serializing)]
    pub api_token: String,
    /// What datasource the embedded dashboards should default to.
    #[serde(default)]
    pub default_datasource: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_refreshed: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct GrafanaFile {
    grafanas: Vec<GrafanaMeta>,
    /// Side-channel: API tokens, keyed by grafana name.
    #[serde(default)]
    api_tokens: HashMap<String, String>,
    /// Side-channel: passwords (for the Basic auth fallback), keyed by name.
    #[serde(default)]
    passwords: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GrafanaMeta {
    name: String,
    url: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    default_datasource: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    last_refreshed: Option<String>,
}

fn config_path() -> AppResult<PathBuf> {
    let dir = match std::env::var_os("HOME") {
        Some(h) => std::path::PathBuf::from(h).join(if cfg!(target_os = "macos") {
            "Library/Application Support/k7s"
        } else {
            ".config/k7s"
        }),
        None => return Err(AppError::Other("no HOME".into())),
    };
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Other(format!("mkdir {}: {e}", dir.display())))?;
    Ok(dir.join("grafana.json"))
}

fn load_file() -> AppResult<GrafanaFile> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(GrafanaFile::default());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| AppError::Other(format!("read {}: {e}", path.display())))?;
    if text.trim().is_empty() {
        return Ok(GrafanaFile::default());
    }
    k7s_deps::serde_json::from_str(&text).map_err(|e| AppError::Other(format!("parse: {e}")))
}

fn save_file(f: &GrafanaFile) -> AppResult<()> {
    let path = config_path()?;
    let text = k7s_deps::serde_json::to_string_pretty(f)
        .map_err(|e| AppError::Other(format!("serialise: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| AppError::Other(format!("write tmp: {e}")))?;
    std::fs::rename(&tmp, &path).map_err(|e| AppError::Other(format!("rename: {e}")))?;
    Ok(())
}

pub fn list() -> AppResult<Vec<GrafanaConfig>> {
    let f = load_file()?;
    Ok(f.grafanas
        .into_iter()
        .map(|g| {
            let password = f.passwords.get(&g.name).cloned().unwrap_or_default();
            let api_token = f.api_tokens.get(&g.name).cloned().unwrap_or_default();
            GrafanaConfig {
                name: g.name,
                url: g.url,
                username: g.username,
                password,
                api_token,
                default_datasource: g.default_datasource,
                description: g.description,
                last_error: g.last_error,
                last_refreshed: g.last_refreshed,
            }
        })
        .collect())
}

pub fn upsert(
    name: &str,
    url: &str,
    username: &str,
    password: &str,
    api_token: &str,
    default_datasource: &str,
    description: &str,
) -> AppResult<GrafanaConfig> {
    let name = name.trim();
    let url = url.trim().trim_end_matches('/');
    if name.is_empty() {
        return Err(AppError::Other("name cannot be empty".into()));
    }
    if url.is_empty() {
        return Err(AppError::Other("url cannot be empty".into()));
    }
    let mut f = load_file()?;
    if let Some(idx) = f.grafanas.iter().position(|g| g.name == name) {
        f.grafanas[idx] = GrafanaMeta {
            name: name.to_string(),
            url: url.to_string(),
            username: username.to_string(),
            default_datasource: default_datasource.to_string(),
            description: description.to_string(),
            last_error: None,
            last_refreshed: None,
        };
    } else {
        f.grafanas.push(GrafanaMeta {
            name: name.to_string(),
            url: url.to_string(),
            username: username.to_string(),
            default_datasource: default_datasource.to_string(),
            description: description.to_string(),
            last_error: None,
            last_refreshed: None,
        });
    }
    if api_token.is_empty() {
        f.api_tokens.remove(name);
    } else {
        f.api_tokens.insert(name.to_string(), api_token.to_string());
    }
    if password.is_empty() {
        f.passwords.remove(name);
    } else {
        f.passwords.insert(name.to_string(), password.to_string());
    }
    save_file(&f)?;
    Ok(GrafanaConfig {
        name: name.to_string(),
        url: url.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        api_token: api_token.to_string(),
        default_datasource: default_datasource.to_string(),
        description: description.to_string(),
        last_error: None,
        last_refreshed: None,
    })
}

pub fn remove(name: &str) -> AppResult<()> {
    let mut f = load_file()?;
    let before = f.grafanas.len();
    f.grafanas.retain(|g| g.name != name);
    f.api_tokens.remove(name);
    f.passwords.remove(name);
    if f.grafanas.len() != before {
        save_file(&f)?;
    }
    Ok(())
}

pub async fn test_connect(name: &str) -> AppResult<()> {
    let cfg = find(name)?;
    let client = k7s_deps::reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("k7s/grafana")
        .build()
        .map_err(|e| AppError::Other(format!("build client: {e}")))?;
    // Grafana's health endpoint: /api/health returns 200 even unauthenticated.
    let url = format!("{}/api/health", cfg.url);
    let mut req = client.get(&url);
    if !cfg.api_token.is_empty() {
        req = req.bearer_auth(&cfg.api_token);
    } else if !cfg.username.is_empty() {
        req = req.basic_auth(&cfg.username, Some(&cfg.password));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    let status = resp.status();
    if status.is_success() || status.as_u16() == 401 {
        Ok(())
    } else {
        Err(AppError::Other(format!("{url}: HTTP {status}")))
    }
}

/// The list of preset dashboards we know about. Picking from a list is a
/// deliberate shortcut: a JSON-designer for custom dashboards would be a
/// project of its own, and the common case is "show me node CPU".
pub fn preset_dashboards() -> Vec<DashboardPreset> {
    vec![
        DashboardPreset {
            id: "k7s-nodes".to_string(),
            title: "Cluster / Nodes".to_string(),
            uid: "rYdddlPWk".to_string(), // node-exporter full
            description: "CPU, memory, disk, network per node".to_string(),
        },
        DashboardPreset {
            id: "k7s-pods".to_string(),
            title: "Cluster / Pods".to_string(),
            uid: "6417bae1f9f1a85f2c7e0c12f6e9a3a3".to_string(),
            description: "Per-pod CPU and memory".to_string(),
        },
        DashboardPreset {
            id: "k7s-namespaces".to_string(),
            title: "Cluster / Namespaces".to_string(),
            uid: "85a5620789f06f0f2b8f79ce4b9c7f06".to_string(),
            description: "Per-namespace resource usage".to_string(),
        },
        DashboardPreset {
            id: "k7s-kubelet".to_string(),
            title: "Cluster / Kubelet".to_string(),
            uid: "f57d8e8c-1f3c-4b3e-a5e3-1e2b3c4d5e6f".to_string(),
            description: "Kubelet stats, running pods, errors".to_string(),
        },
    ]
}

#[derive(Clone, Debug, Serialize)]
pub struct DashboardPreset {
    pub id: String,
    pub title: String,
    pub uid: String,
    pub description: String,
}

/// Build the URL the iframe should `src` to. We don't try to honour
/// every Grafana URL knob — `from`/`to` get a sensible default, the
/// rest is whatever Grafana's default state is.
pub fn dashboard_url(name: &str, uid: &str, from_ms: i64, to_ms: i64) -> AppResult<String> {
    let cfg = find(name)?;
    let ds = if cfg.default_datasource.is_empty() {
        "Prometheus".to_string()
    } else {
        cfg.default_datasource.clone()
    };
    let from_secs = from_ms / 1000;
    let to_secs = to_ms / 1000;
    Ok(format!(
        "{}/d/{}?from={}&to={}&var-datasource={}&kiosk",
        cfg.url,
        uid,
        from_secs,
        to_secs,
        urlencode(&ds)
    ))
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn find(name: &str) -> AppResult<GrafanaConfig> {
    list()?
        .into_iter()
        .find(|c| c.name == name)
        .ok_or_else(|| AppError::NotFound(format!("grafana '{name}' not found")))
}

// ---------------------------------------------------------------------------
// Dashboard search via Grafana API
// ---------------------------------------------------------------------------

/// A dashboard returned by Grafana's `/api/search`.
#[derive(Clone, Debug, Serialize)]
pub struct DashboardSearchResult {
    pub uid: String,
    pub title: String,
    pub uri: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub tags: Vec<String>,
    pub url: String,
}

/// Search dashboards on a Grafana instance via `/api/search`.
pub async fn search_dashboards(name: &str, query: &str) -> AppResult<Vec<DashboardSearchResult>> {
    let cfg = find(name)?;
    let client = k7s_deps::reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| AppError::Other(format!("build client: {e}")))?;

    let encoded_q = query.replace(' ', "%20");
    let url = format!("{}/api/search?query={}&type=dash-db", cfg.url, encoded_q);
    let mut req = client.get(&url);
    if !cfg.api_token.is_empty() {
        req = req.bearer_auth(&cfg.api_token);
    } else if !cfg.username.is_empty() {
        req = req.basic_auth(&cfg.username, Some(&cfg.password));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(AppError::Other(format!("{url}: HTTP {status}")));
    }

    let raw: Vec<k7s_deps::serde_json::Value> = resp
        .json()
        .await
        .map_err(|e| AppError::Other(format!("decode: {e}")))?;

    Ok(raw
        .iter()
        .map(|v| DashboardSearchResult {
            uid: v
                .get("uid")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            title: v
                .get("title")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            uri: v
                .get("uri")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            kind: v
                .get("type")
                .and_then(|s| s.as_str())
                .unwrap_or("dash-db")
                .to_string(),
            tags: v
                .get("tags")
                .and_then(|t| t.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            url: v
                .get("url")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_safe_chars() {
        assert_eq!(urlencode("Prometheus"), "Prometheus");
        assert_eq!(urlencode("My/DS 1"), "My%2FDS%201");
    }

    #[test]
    fn presets_have_unique_ids() {
        let p = preset_dashboards();
        let mut ids: Vec<_> = p.iter().map(|d| d.id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), p.len());
    }
}
