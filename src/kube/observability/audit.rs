//! K8s Audit Log integration via Loki (Phase 3 — KubePi parity).
//!
//! Queries a Loki instance for kube-apiserver audit events using LogQL.
//! The expected Loki label set is `{job="kube-apiserver-audit"}` (or a
//! user-configured label selector). Each log line is a JSON-encoded
//! Kubernetes AuditEvent; we extract the key fields for display.
//!
//! Loki instance config is stored alongside the Prometheus config
//! (reuses the same CRUD pattern as `metrics_config`).

use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Loki instance registry (reuses the metrics_config pattern)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LokiConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_refreshed: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct LokiFile {
    instances: Vec<LokiConfig>,
    #[serde(default)]
    passwords: HashMap<String, String>,
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
    Ok(dir.join("loki.json"))
}

fn load_file() -> AppResult<LokiFile> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(LokiFile::default());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| AppError::Other(format!("read {}: {e}", path.display())))?;
    if text.trim().is_empty() {
        return Ok(LokiFile::default());
    }
    k7s_deps::serde_json::from_str(&text).map_err(|e| AppError::Other(format!("parse: {e}")))
}

fn save_file(f: &LokiFile) -> AppResult<()> {
    let path = config_path()?;
    let text =
        k7s_deps::serde_json::to_string_pretty(f).map_err(|e| AppError::Other(format!("serialise: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| AppError::Other(format!("write tmp: {e}")))?;
    std::fs::rename(&tmp, &path).map_err(|e| AppError::Other(format!("rename: {e}")))?;
    Ok(())
}

pub fn list() -> AppResult<Vec<LokiConfig>> {
    let f = load_file()?;
    Ok(f.instances
        .into_iter()
        .map(|mut m| {
            m.password = f.passwords.get(&m.name).cloned().unwrap_or_default();
            m
        })
        .collect())
}

pub fn upsert(
    name: &str,
    url: &str,
    username: &str,
    password: &str,
    description: &str,
) -> AppResult<LokiConfig> {
    let name = name.trim();
    let url = url.trim().trim_end_matches('/');
    if name.is_empty() {
        return Err(AppError::Other("name cannot be empty".into()));
    }
    if url.is_empty() {
        return Err(AppError::Other("url cannot be empty".into()));
    }
    let mut f = load_file()?;
    if let Some(idx) = f.instances.iter().position(|m| m.name == name) {
        f.instances[idx] = LokiConfig {
            name: name.to_string(),
            url: url.to_string(),
            username: username.to_string(),
            password: String::new(),
            description: description.to_string(),
            last_error: None,
            last_refreshed: None,
        };
    } else {
        f.instances.push(LokiConfig {
            name: name.to_string(),
            url: url.to_string(),
            username: username.to_string(),
            password: String::new(),
            description: description.to_string(),
            last_error: None,
            last_refreshed: None,
        });
    }
    if password.is_empty() {
        f.passwords.remove(name);
    } else {
        f.passwords.insert(name.to_string(), password.to_string());
    }
    save_file(&f)?;
    Ok(LokiConfig {
        name: name.to_string(),
        url: url.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        description: description.to_string(),
        last_error: None,
        last_refreshed: None,
    })
}

pub fn remove(name: &str) -> AppResult<()> {
    let mut f = load_file()?;
    let before = f.instances.len();
    f.instances.retain(|m| m.name != name);
    f.passwords.remove(name);
    if f.instances.len() != before {
        save_file(&f)?;
    }
    Ok(())
}

pub async fn test_connect(name: &str) -> AppResult<()> {
    let cfg = find(name)?;
    let client = k7s_deps::reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Other(format!("build client: {e}")))?;
    let url = format!("{}/ready", cfg.url);
    let mut req = client.get(&url);
    if !cfg.username.is_empty() {
        req = req.basic_auth(&cfg.username, Some(&cfg.password));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(AppError::Other(format!("{}: HTTP {}", url, resp.status())))
    }
}

fn find(name: &str) -> AppResult<LokiConfig> {
    list()?
        .into_iter()
        .find(|c| c.name == name)
        .ok_or_else(|| AppError::NotFound(format!("loki instance '{name}' not found")))
}

// ---------------------------------------------------------------------------
// Audit event query
// ---------------------------------------------------------------------------

/// A parsed Kubernetes audit event, as returned to the frontend.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub timestamp: String,
    pub verb: String,
    pub resource: String,
    pub subresource: String,
    pub namespace: String,
    pub name: String,
    pub user: String,
    pub source_ip: String,
    pub status_code: i64,
    pub stage: String,
    pub audit_id: String,
    /// Raw JSON for drill-down.
    pub raw: String,
}

/// Query parameters for fetching audit events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Loki instance name.
    pub instance: String,
    /// Filter by namespace (optional).
    #[serde(default)]
    pub namespace: String,
    /// Filter by resource kind (optional, e.g. "pods", "deployments").
    #[serde(default)]
    pub resource: String,
    /// Filter by user (optional).
    #[serde(default)]
    pub user: String,
    /// How far back to look, in seconds. Default 3600 (1h).
    #[serde(default = "default_since")]
    pub since_seconds: i64,
    /// Max events to return. Default 200.
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_since() -> i64 {
    3600
}
fn default_limit() -> usize {
    200
}

/// Fetch audit events from Loki.
pub async fn query_audit_events(query: &AuditQuery) -> AppResult<Vec<AuditEvent>> {
    let cfg = find(&query.instance)?;
    let client = k7s_deps::reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| AppError::Other(format!("build client: {e}")))?;

    // Build LogQL query
    let mut selectors = vec!["job=\"kube-apiserver-audit\"".to_string()];
    if !query.namespace.is_empty() {
        selectors.push(format!("namespace=\"{}\"", query.namespace));
    }

    let logql = format!("{{{}}}", selectors.join(", "));

    // Loki /loki/api/v1/query_range
    let end = k7s_deps::chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let start = end - query.since_seconds * 1_000_000_000;

    // Simple percent encoding for the LogQL query (only braces and quotes need encoding)
    let encoded_query = logql
        .replace('{', "%7B")
        .replace('}', "%7D")
        .replace('"', "%22")
        .replace(' ', "%20");

    let url = format!(
        "{}/loki/api/v1/query_range?query={}&limit={}&start={}&end={}&direction=backward",
        cfg.url, encoded_query, query.limit, start, end,
    );
    let mut req = client.get(&url);
    if !cfg.username.is_empty() {
        req = req.basic_auth(&cfg.username, Some(&cfg.password));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Other(format!("{url}: HTTP {status}: {text}")));
    }

    let body: k7s_deps::serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Other(format!("decode: {e}")))?;

    let results = body
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();

    let mut events: Vec<AuditEvent> = Vec::new();

    for stream in &results {
        let values = stream
            .get("values")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        for entry in &values {
            // Each entry is [timestamp_ns, log_line]
            let log_line = entry.get(1).and_then(|v| v.as_str()).unwrap_or("");
            if let Some(event) = parse_audit_line(log_line) {
                // Apply client-side filters
                if !query.resource.is_empty()
                    && !event
                        .resource
                        .to_lowercase()
                        .contains(&query.resource.to_lowercase())
                {
                    continue;
                }
                if !query.user.is_empty()
                    && !event
                        .user
                        .to_lowercase()
                        .contains(&query.user.to_lowercase())
                {
                    continue;
                }
                events.push(event);
            }
        }
    }

    Ok(events)
}

fn parse_audit_line(line: &str) -> Option<AuditEvent> {
    let v: k7s_deps::serde_json::Value = k7s_deps::serde_json::from_str(line).ok()?;
    let ts = v
        .get("requestReceivedTimestamp")
        .or_else(|| v.get("stageTimestamp"))
        .or_else(|| v.get("auditID").and(None))
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    let verb = v
        .get("verb")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let resource = v
        .get("objectRef")
        .and_then(|o| o.get("resource"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let subresource = v
        .get("objectRef")
        .and_then(|o| o.get("subresource"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let namespace = v
        .get("objectRef")
        .and_then(|o| o.get("namespace"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let name = v
        .get("objectRef")
        .and_then(|o| o.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let user = v
        .get("user")
        .and_then(|u| u.get("username"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let source_ip = v
        .get("sourceIPs")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let status_code = v
        .get("responseStatus")
        .and_then(|s| s.get("code"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let stage = v
        .get("stage")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let audit_id = v
        .get("auditID")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(AuditEvent {
        timestamp: ts,
        verb,
        resource,
        subresource,
        namespace,
        name,
        user,
        source_ip,
        status_code,
        stage,
        audit_id,
        raw: line.to_string(),
    })
}
