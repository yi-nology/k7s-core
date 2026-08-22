//! Metrics and cluster-status pollers.
//!
//! Two tasks run per connection:
//!   - metrics poller (~15s): pod + node usage from `metrics.k8s.io`, emitting
//!     `pod-metrics` / `node-metrics`. If the metrics API is absent it stops
//!     emitting (UI shows "—") but keeps probing occasionally.
//!   - status poller (~10s): server version, API latency (timed `/version`), nodes
//!     ready, and cluster CPU/MEM %, emitting `cluster-status`.
//!
//! The two share the latest cluster CPU/MEM % via a small mutex so the status
//! event can include them without re-fetching.

use crate::core::events::EventSink;
use crate::kube::events;
use k7s_deps::k8s_openapi::api::core::v1::Node;
use k7s_deps::kube::api::{Api, ListParams};
use k7s_deps::kube::Client;
use k7s_deps::tokio::sync::Mutex;
use k7s_deps::tokio::time::{interval, Duration, Instant};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Default poll intervals. Both are user-configurable (B23); these are the
/// values used when nothing has been saved.
pub const METRICS_INTERVAL: Duration = Duration::from_secs(15);
pub const STATUS_INTERVAL: Duration = Duration::from_secs(10);

/// How often the pollers run. Read from prefs on connect (B23), so a change
/// takes effect the next time a connection is established.
#[derive(Clone, Copy)]
pub struct PollIntervals {
    pub metrics: Duration,
    pub status: Duration,
}

impl Default for PollIntervals {
    fn default() -> Self {
        PollIntervals {
            metrics: METRICS_INTERVAL,
            status: STATUS_INTERVAL,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire payloads
// ---------------------------------------------------------------------------

/// Per-pod usage keyed by "ns/name".
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PodUsage {
    cpu_millis: i64,
    mem_bytes: i64,
    /// Epoch milliseconds when this sample was taken.
    ts: i64,
}

/// One point in a pod's CPU/memory history, returned by Prometheus backfill.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PodSample {
    /// Epoch milliseconds — the x axis.
    pub ts: i64,
    /// CPU usage in millicores.
    pub cpu_millis: i64,
    /// Working-set memory in bytes.
    pub mem_bytes: i64,
}

/// Per-node usage percentages keyed by node name.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NodeUsage {
    cpu_percent: f64,
    mem_percent: f64,
    /// Absolute CPU usage (millicores) and memory (bytes), plus the node's
    /// allocatable capacity. metrics.k8s.io gives both the usage and the Node
    /// object gives the ceiling, so we surface them for the node Metrics tab to
    /// plot "how much room is left" without needing node-exporter.
    cpu_millis: i64,
    mem_bytes: i64,
    mem_total_bytes: i64,
}

/// Cluster-wide status for the status bar / switcher.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ClusterStatusPayload {
    connected: bool,
    version: String,
    api_latency_ms: u64,
    nodes_ready: i32,
    nodes_total: i32,
    /// null (None) when metrics are unavailable.
    cpu_percent: Option<f64>,
    mem_percent: Option<f64>,
}

// ---------------------------------------------------------------------------
// Raw metrics.k8s.io response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct MetricsList<T> {
    pub items: Vec<T>,
}
#[derive(Deserialize)]
pub struct MetaName {
    pub name: String,
    #[serde(default)]
    pub namespace: String,
}
#[derive(Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub cpu: String,
    #[serde(default)]
    pub memory: String,
}
#[derive(Deserialize)]
pub struct PodMetric {
    pub metadata: MetaName,
    pub containers: Vec<ContainerUsage>,
}
#[derive(Deserialize)]
pub struct ContainerUsage {
    pub usage: Usage,
}
#[derive(Deserialize)]
pub struct NodeMetric {
    pub metadata: MetaName,
    pub usage: Usage,
}

/// Shared latest cluster CPU/MEM % (produced by the metrics task, read by status).
type SharedClusterPct = Arc<Mutex<Option<(f64, f64)>>>;

/// Spawn the metrics + status pollers, returning their join handles for the
/// manager to register (and abort on disconnect).
pub fn spawn_pollers(
    sink: EventSink,
    client: Client,
    intervals: PollIntervals,
) -> (
    k7s_deps::tokio::task::JoinHandle<()>,
    k7s_deps::tokio::task::JoinHandle<()>,
) {
    let shared: SharedClusterPct = Arc::new(Mutex::new(None));

    let metrics_task = k7s_deps::tokio::spawn(metrics_loop(
        sink.clone(),
        client.clone(),
        shared.clone(),
        intervals.metrics,
    ));
    let status_task = k7s_deps::tokio::spawn(status_loop(sink, client, shared, intervals.status));
    (metrics_task, status_task)
}

/// Poll pod/node metrics on an interval; emit events; track availability.
async fn metrics_loop(sink: EventSink, client: Client, shared: SharedClusterPct, every: Duration) {
    let mut tick = interval(every);
    // When the metrics API is missing we back off probing to ~60s.
    let mut miss_streak = 0u32;

    loop {
        tick.tick().await;

        // Skip most attempts while the API is known-absent (probe every ~4th tick).
        if miss_streak > 0 && miss_streak % 4 != 0 {
            miss_streak += 1;
            continue;
        }

        let pods = fetch_pod_metrics(&client).await;
        let nodes = fetch_node_metrics(&client).await;

        match (pods, nodes) {
            (Ok(pod_map), Ok((node_map, cluster_pct))) => {
                miss_streak = 0;
                sink.emit(events::POD_METRICS, &&pod_map);
                sink.emit(events::NODE_METRICS, &&node_map);
                *shared.lock().await = Some(cluster_pct);
            }
            _ => {
                // metrics-server absent or erroring: stop feeding stale values.
                if miss_streak == 0 {
                    k7s_deps::tracing::warn!("metrics.k8s.io unavailable; CPU/MEM will show as —");
                }
                miss_streak += 1;
                *shared.lock().await = None;
            }
        }
    }
}

/// Fetch pod metrics and reduce to a "ns/name" → usage map (summing containers).
async fn fetch_pod_metrics(
    client: &Client,
) -> Result<HashMap<String, PodUsage>, k7s_deps::kube::Error> {
    let req = k7s_deps::http::Request::get("/apis/metrics.k8s.io/v1beta1/pods")
        .body(Vec::new())
        .map_err(|e| k7s_deps::kube::Error::Service(Box::new(e)))?;
    let list: MetricsList<PodMetric> = client.request(req).await?;

    let now_ms = k7s_deps::chrono::Utc::now().timestamp_millis();
    let mut map = HashMap::new();
    for pm in list.items {
        let cpu: i64 = pm
            .containers
            .iter()
            .map(|c| parse_cpu_millis(&c.usage.cpu))
            .sum();
        let mem: i64 = pm
            .containers
            .iter()
            .map(|c| parse_mem_bytes(&c.usage.memory))
            .sum();
        let key = format!("{}/{}", pm.metadata.namespace, pm.metadata.name);
        map.insert(
            key,
            PodUsage {
                cpu_millis: cpu,
                mem_bytes: mem,
                ts: now_ms,
            },
        );
    }
    Ok(map)
}

/// Fetch node metrics + allocatable and compute per-node and cluster-wide %.
async fn fetch_node_metrics(
    client: &Client,
) -> Result<(HashMap<String, NodeUsage>, (f64, f64)), k7s_deps::kube::Error> {
    // Usage from metrics.k8s.io.
    let req = k7s_deps::http::Request::get("/apis/metrics.k8s.io/v1beta1/nodes")
        .body(Vec::new())
        .map_err(|e| k7s_deps::kube::Error::Service(Box::new(e)))?;
    let list: MetricsList<NodeMetric> = client.request(req).await?;

    // Allocatable capacity from the Node objects.
    let nodes: Api<Node> = Api::all(client.clone());
    let node_objs = nodes.list(&ListParams::default()).await?;

    let mut alloc: HashMap<String, (i64, i64)> = HashMap::new();
    for n in node_objs.items {
        let name = n.metadata.name.clone().unwrap_or_default();
        if let Some(status) = &n.status {
            if let Some(a) = &status.allocatable {
                let cpu = a.get("cpu").map(|q| parse_cpu_millis(&q.0)).unwrap_or(0);
                let mem = a.get("memory").map(|q| parse_mem_bytes(&q.0)).unwrap_or(0);
                alloc.insert(name, (cpu, mem));
            }
        }
    }

    let mut map = HashMap::new();
    let (mut used_cpu, mut used_mem, mut cap_cpu, mut cap_mem) = (0i64, 0i64, 0i64, 0i64);
    for nm in list.items {
        let name = nm.metadata.name;
        let cpu = parse_cpu_millis(&nm.usage.cpu);
        let mem = parse_mem_bytes(&nm.usage.memory);
        let (acpu, amem) = alloc.get(&name).copied().unwrap_or((0, 0));
        map.insert(
            name,
            NodeUsage {
                cpu_percent: pct(cpu, acpu),
                mem_percent: pct(mem, amem),
                cpu_millis: cpu,
                mem_bytes: mem,
                mem_total_bytes: amem,
            },
        );
        used_cpu += cpu;
        used_mem += mem;
        cap_cpu += acpu;
        cap_mem += amem;
    }

    Ok((map, (pct(used_cpu, cap_cpu), pct(used_mem, cap_mem))))
}

/// Poll cluster status on an interval: version, latency, nodes ready, cpu/mem %.
async fn status_loop(sink: EventSink, client: Client, shared: SharedClusterPct, every: Duration) {
    let mut tick = interval(every);
    loop {
        tick.tick().await;

        // Timed version probe doubles as the reachability + latency check.
        let start = Instant::now();
        let version_res = client.apiserver_version().await;
        let latency = start.elapsed().as_millis() as u64;

        let (connected, version) = match version_res {
            Ok(info) => (true, info.git_version),
            Err(e) => {
                k7s_deps::tracing::warn!("cluster status probe failed: {e}");
                (false, String::new())
            }
        };

        // Node readiness (best-effort; 0/0 if the list fails).
        let (ready, total) = if connected {
            count_ready_nodes(&client).await
        } else {
            (0, 0)
        };

        let (cpu, mem) = match *shared.lock().await {
            Some((c, m)) => (Some(round1(c)), Some(round1(m))),
            None => (None, None),
        };

        let payload = ClusterStatusPayload {
            connected,
            version,
            api_latency_ms: latency,
            nodes_ready: ready,
            nodes_total: total,
            cpu_percent: cpu,
            mem_percent: mem,
        };
        sink.emit(events::CLUSTER_STATUS, &payload);
    }
}

/// Count Ready nodes / total nodes.
async fn count_ready_nodes(client: &Client) -> (i32, i32) {
    let nodes: Api<Node> = Api::all(client.clone());
    match nodes.list(&ListParams::default()).await {
        Ok(list) => {
            let total = list.items.len() as i32;
            let ready = list
                .items
                .iter()
                .filter(|n| {
                    n.status
                        .as_ref()
                        .and_then(|s| s.conditions.as_ref())
                        .map(|cs| cs.iter().any(|c| c.type_ == "Ready" && c.status == "True"))
                        .unwrap_or(false)
                })
                .count() as i32;
            (ready, total)
        }
        Err(_) => (0, 0),
    }
}

// ---------------------------------------------------------------------------
// Quantity parsing
// ---------------------------------------------------------------------------

/// Parse a Kubernetes CPU quantity to milli-cores.
/// Handles nano ("123456n"), micro ("500u"), milli ("212m"), and cores ("2", "1.5").
pub fn parse_cpu_millis(s: &str) -> i64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    if let Some(v) = s.strip_suffix('n') {
        return (v.parse::<f64>().unwrap_or(0.0) / 1_000_000.0).round() as i64;
    }
    if let Some(v) = s.strip_suffix('u') {
        return (v.parse::<f64>().unwrap_or(0.0) / 1_000.0).round() as i64;
    }
    if let Some(v) = s.strip_suffix('m') {
        return v.parse::<f64>().unwrap_or(0.0).round() as i64;
    }
    // Bare number is in cores.
    (s.parse::<f64>().unwrap_or(0.0) * 1000.0).round() as i64
}

/// Parse a Kubernetes memory quantity to bytes.
/// Handles binary (Ki/Mi/Gi/Ti/Pi), decimal (k/M/G/T/P), and bare bytes.
pub fn parse_mem_bytes(s: &str) -> i64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    // Binary suffixes first (they end in 'i').
    const BINARY: [(&str, f64); 5] = [
        ("Ki", 1024.0),
        ("Mi", 1024.0 * 1024.0),
        ("Gi", 1024.0 * 1024.0 * 1024.0),
        ("Ti", 1024.0 * 1024.0 * 1024.0 * 1024.0),
        ("Pi", 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0),
    ];
    for (suf, mult) in BINARY {
        if let Some(v) = s.strip_suffix(suf) {
            return (v.parse::<f64>().unwrap_or(0.0) * mult).round() as i64;
        }
    }
    const DECIMAL: [(&str, f64); 5] =
        [("k", 1e3), ("M", 1e6), ("G", 1e9), ("T", 1e12), ("P", 1e15)];
    for (suf, mult) in DECIMAL {
        if let Some(v) = s.strip_suffix(suf) {
            return (v.parse::<f64>().unwrap_or(0.0) * mult).round() as i64;
        }
    }
    s.parse::<f64>().unwrap_or(0.0).round() as i64
}

/// Percentage used/capacity, guarding divide-by-zero.
fn pct(used: i64, cap: i64) -> f64 {
    if cap <= 0 {
        0.0
    } else {
        (used as f64 / cap as f64) * 100.0
    }
}

/// Round to one decimal place.
fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_quantity_parsing() {
        assert_eq!(parse_cpu_millis("212m"), 212);
        assert_eq!(parse_cpu_millis("2"), 2000);
        assert_eq!(parse_cpu_millis("1.5"), 1500);
        assert_eq!(parse_cpu_millis("500000000n"), 500); // 0.5 cores
        assert_eq!(parse_cpu_millis("500000u"), 500);
        assert_eq!(parse_cpu_millis(""), 0);
    }

    #[test]
    fn mem_quantity_parsing() {
        assert_eq!(parse_mem_bytes("486Mi"), 486 * 1024 * 1024);
        assert_eq!(parse_mem_bytes("2Gi"), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_mem_bytes("1000k"), 1_000_000);
        assert_eq!(parse_mem_bytes("1048576"), 1_048_576);
        assert_eq!(parse_mem_bytes(""), 0);
    }

    #[test]
    fn percentage_guards_zero_capacity() {
        assert_eq!(pct(5, 0), 0.0);
        assert_eq!(pct(50, 100), 50.0);
    }
}
