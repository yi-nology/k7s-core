//! Prometheus / metrics-server configuration (Phase 1 Tier-2 of KubePi parity).
//!
//! Two roles here:
//!
//!   1. **Multi-instance Prometheus registry.** `promql.rs` already auto-discovers
//!      a `prometheus-operated` Service in the cluster; this module adds the
//!      user-managed list, so a Metrics Explorer can choose between the in-cluster
//!      Prometheus, an external one (corp Prometheus, Grafana Cloud, …), or
//!      several. Storage is a JSON file under the user config dir, mirroring
//!      how [`crate::kube::helm::market`] keeps chart repos.
//!
//!   2. **PromQL query.** A single entry point that wraps a Prometheus HTTP API
//!      request — `query` for an instant value, `query_range` for a window —
//!      and maps the response into typed `Series` rows the front-end can hand
//!      straight to Plotly. We keep the parsing tight (timestamps as i64 ms,
//!      values as f64) because every millisecond on the response path matters
//!      when a user is typing into the Explorer.
//!
//! Auth: the same bearer-challenge dance as [`crate::kube::image::repo`], but
//! inlined here to keep the modules independent. We don't refactor it into
//! a shared helper yet because the two callers do different things after
//! the auth dance and a premature abstraction would just hide the difference.

use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub name: String,
    /// `https://prom.example.com` — no trailing slash, no `/api/v1`.
    pub url: String,
    #[serde(default)]
    pub username: String,
    #[serde(default, skip_serializing)]
    pub password: String,
    #[serde(default)]
    pub description: String,
    /// Last refresh outcome; UI shows a red dot on a broken instance.
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_refreshed: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct MetricsFile {
    metrics: Vec<MetricsMeta>,
    /// Same split-file trick as the image-registry module: passwords in a
    /// side-channel so `list` can return redacted DTOs.
    #[serde(default)]
    passwords: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MetricsMeta {
    name: String,
    url: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    last_refreshed: Option<String>,
}

fn config_path() -> AppResult<PathBuf> {
    Ok(crate::kube::user_config_dir()?.join("metrics-config.json"))
}

fn load_file() -> AppResult<MetricsFile> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(MetricsFile::default());
    }
    let text = std::fs::read_to_string(&path)
        .map_err(|e| AppError::Other(format!("read {}: {e}", path.display())))?;
    if text.trim().is_empty() {
        return Ok(MetricsFile::default());
    }
    k7s_deps::serde_json::from_str(&text).map_err(|e| AppError::Other(format!("parse: {e}")))
}

fn save_file(f: &MetricsFile) -> AppResult<()> {
    let path = config_path()?;
    let text = k7s_deps::serde_json::to_string_pretty(f)
        .map_err(|e| AppError::Other(format!("serialise: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| AppError::Other(format!("write tmp: {e}")))?;
    std::fs::rename(&tmp, &path).map_err(|e| AppError::Other(format!("rename: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

pub fn list() -> AppResult<Vec<MetricsConfig>> {
    let f = load_file()?;
    Ok(f.metrics
        .into_iter()
        .map(|m| {
            let password = f.passwords.get(&m.name).cloned().unwrap_or_default();
            MetricsConfig {
                name: m.name,
                url: m.url,
                username: m.username,
                password,
                description: m.description,
                last_error: m.last_error,
                last_refreshed: m.last_refreshed,
            }
        })
        .collect())
}

pub fn upsert(
    name: &str,
    url: &str,
    username: &str,
    password: &str,
    description: &str,
) -> AppResult<MetricsConfig> {
    let name = name.trim();
    let url = url.trim().trim_end_matches('/');
    if name.is_empty() {
        return Err(AppError::Other("name cannot be empty".into()));
    }
    if url.is_empty() {
        return Err(AppError::Other("url cannot be empty".into()));
    }
    let mut f = load_file()?;
    if let Some(idx) = f.metrics.iter().position(|m| m.name == name) {
        f.metrics[idx] = MetricsMeta {
            name: name.to_string(),
            url: url.to_string(),
            username: username.to_string(),
            description: description.to_string(),
            last_error: None,
            last_refreshed: None,
        };
    } else {
        f.metrics.push(MetricsMeta {
            name: name.to_string(),
            url: url.to_string(),
            username: username.to_string(),
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
    Ok(MetricsConfig {
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
    let before = f.metrics.len();
    f.metrics.retain(|m| m.name != name);
    f.passwords.remove(name);
    if f.metrics.len() != before {
        save_file(&f)?;
    }
    Ok(())
}

pub async fn test_connect(name: &str) -> AppResult<()> {
    let cfg = find(name)?;
    let client = build_client(&cfg)?;
    let url = format!("{}/api/v1/status/runtimeinfo", cfg.url);
    let resp = client
        .get(&url)
        .basic_auth(&cfg.username, Some(&cfg.password))
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

// ---------------------------------------------------------------------------
// PromQL
// ---------------------------------------------------------------------------

/// One (timestamp, value) sample. Mirrors what Plotly's basic-dist-min wants
/// for `scatter` traces.
#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    pub ts: i64,
    pub value: f64,
}

/// One series returned by a PromQL query. `metric` carries the label set
/// (e.g. `{instance="…", job="…"}`) so the front-end can show a legend.
#[derive(Clone, Debug, Serialize)]
pub struct Series {
    pub metric: HashMap<String, String>,
    pub samples: Vec<Sample>,
}

/// A complete query result, ready for the front-end to render.
#[derive(Clone, Debug, Serialize)]
pub struct QueryResult {
    /// "matrix" | "vector" | "scalar" | "string" — what Prometheus returned.
    pub result_type: String,
    pub series: Vec<Series>,
}

pub async fn query(name: &str, promql: &str) -> AppResult<QueryResult> {
    let cfg = find(name)?;
    let client = build_client(&cfg)?;
    let url = format!("{}/api/v1/query?query={}", cfg.url, urlencode(promql));
    let resp = client
        .get(&url)
        .basic_auth(&cfg.username, Some(&cfg.password))
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Other(format!("{url}: HTTP {status}: {text}")));
    }
    let body: PromResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Other(format!("decode: {e}")))?;
    Ok(translate(body))
}

pub async fn query_range(
    name: &str,
    promql: &str,
    start_ms: i64,
    end_ms: i64,
    step_seconds: i64,
) -> AppResult<QueryResult> {
    let cfg = find(name)?;
    let client = build_client(&cfg)?;
    let url = format!(
        "{}/api/v1/query_range?query={}&start={}&end={}&step={}",
        cfg.url,
        urlencode(promql),
        start_ms / 1000,
        end_ms / 1000,
        step_seconds
    );
    let resp = client
        .get(&url)
        .basic_auth(&cfg.username, Some(&cfg.password))
        .send()
        .await
        .map_err(|e| AppError::Other(format!("GET {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Other(format!("{url}: HTTP {status}: {text}")));
    }
    let body: PromResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Other(format!("decode: {e}")))?;
    Ok(translate(body))
}

// ---------------------------------------------------------------------------
// Wire types — exactly what Prometheus returns
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
struct PromResponse {
    data: PromData,
    #[serde(default = "default_status")]
    status: String,
}

fn default_status() -> String {
    "success".to_string()
}

#[derive(Deserialize)]
struct PromData {
    #[serde(default, rename = "resultType")]
    result_type: String,
    result: k7s_deps::serde_json::Value,
}

fn translate(body: PromResponse) -> QueryResult {
    let arr = match body.data.result.as_array() {
        Some(a) => a,
        None => {
            return QueryResult {
                result_type: body.data.result_type,
                series: vec![],
            }
        }
    };
    let mut series = Vec::with_capacity(arr.len());
    for item in arr {
        let metric = item
            .get("metric")
            .and_then(|m| m.as_object())
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();
        let samples = match item.get("values").and_then(|v| v.as_array()) {
            Some(vs) => vs
                .iter()
                .filter_map(|pair| {
                    let p = pair.as_array()?;
                    let ts = p.first()?.as_f64()? as i64;
                    let val = p.get(1)?.as_str()?.parse::<f64>().ok()?;
                    Some(Sample {
                        ts: ts * 1000,
                        value: val,
                    })
                })
                .collect(),
            None => match item.get("value").and_then(|v| v.as_array()) {
                Some(pair) => {
                    let ts = pair.first().and_then(|v| v.as_f64()).unwrap_or(0.0) as i64;
                    let val = pair
                        .get(1)
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<f64>().ok())
                        .unwrap_or(0.0);
                    vec![Sample {
                        ts: ts * 1000,
                        value: val,
                    }]
                }
                None => vec![],
            },
        };
        series.push(Series { metric, samples });
    }
    QueryResult {
        result_type: body.data.result_type,
        series,
    }
}

pub(crate) fn find(name: &str) -> AppResult<MetricsConfig> {
    list()?
        .into_iter()
        .find(|c| c.name == name)
        .ok_or_else(|| AppError::NotFound(format!("metrics config '{name}' not found")))
}

fn build_client(_cfg: &MetricsConfig) -> AppResult<k7s_deps::reqwest::Client> {
    k7s_deps::reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("k7s/metrics-explorer")
        .build()
        .map_err(|e| AppError::Other(format!("build client: {e}")))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_passes_safe_chars() {
        assert_eq!(
            urlencode("rate(node_cpu[5m])"),
            "rate%28node_cpu%5B5m%5D%29"
        );
    }

    #[test]
    fn urlencode_keeps_alnum_and_dash() {
        assert_eq!(urlencode("kube_pod-info"), "kube_pod-info");
    }

    fn sample_matrix() -> k7s_deps::serde_json::Value {
        k7s_deps::serde_json::json!({
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {"__name__": "up", "job": "apiserver"},
                        "values": [
                            [1700000000.0, "1"],
                            [1700000060.0, "0"],
                            [1700000120.0, "1"]
                        ]
                    }
                ]
            }
        })
    }

    #[test]
    fn translate_matrix_parses_timestamps_and_values() {
        let body: PromResponse = k7s_deps::serde_json::from_value(sample_matrix()).unwrap();
        let r = translate(body);
        assert_eq!(r.result_type, "matrix");
        assert_eq!(r.series.len(), 1);
        let s = &r.series[0];
        assert_eq!(s.metric.get("job").map(String::as_str), Some("apiserver"));
        assert_eq!(s.samples.len(), 3);
        // Timestamps are converted from seconds to milliseconds.
        assert_eq!(s.samples[0].ts, 1_700_000_000_000);
        assert_eq!(s.samples[1].value, 0.0);
        assert_eq!(s.samples[2].value, 1.0);
    }

    #[test]
    fn translate_vector_uses_single_sample_per_series() {
        let body: PromResponse = k7s_deps::serde_json::from_value(k7s_deps::serde_json::json!({
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"foo": "bar"},
                        "value": [1.7e9, "42"]
                    }
                ]
            }
        }))
        .unwrap();
        let r = translate(body);
        assert_eq!(r.series.len(), 1);
        let s = &r.series[0];
        assert_eq!(s.samples.len(), 1);
        // 1.7e9 seconds → 1.7e12 ms.
        assert_eq!(s.samples[0].ts, 1_700_000_000_000);
        assert_eq!(s.samples[0].value, 42.0);
    }

    #[test]
    fn translate_handles_empty_result() {
        let body: PromResponse = k7s_deps::serde_json::from_value(k7s_deps::serde_json::json!({
            "data": {"resultType": "matrix", "result": []}
        }))
        .unwrap();
        let r = translate(body);
        assert!(r.series.is_empty());
        assert_eq!(r.result_type, "matrix");
    }
}
