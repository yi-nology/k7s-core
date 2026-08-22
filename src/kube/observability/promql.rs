//! Prometheus-backed history for the node charts (B38).
//!
//! B27's scraper produces live samples but starts from nothing: open a node's
//! Metrics tab and the plots begin empty, filling one point at a time. If the
//! cluster already runs a Prometheus scraping the same node-exporters, that
//! history is sitting there — this backfills the charts from it so they open
//! populated, and the live scraper carries on as the freshest point.
//!
//! Everything here degrades to nothing rather than failing: no Prometheus, an
//! unreachable one, or a cluster whose scrape targets have drifted all return an
//! empty history and leave B27's behaviour exactly as it was. That is not
//! hypothetical — murphy-yi's Prometheus held zero `node_*` series until its scrape
//! config was fixed, because the targets named a node IP that had changed.
//!
//! Reached through the API server's service proxy, the same transport the
//! metrics pollers use, so it needs no port-forward and no route to the pod.

use super::exporter::NodeSample;
use super::metrics::PodSample;
use crate::error::AppResult;
use k7s_deps::k8s_openapi::api::core::v1::Service;
use k7s_deps::kube::api::{Api, ListParams};
use k7s_deps::kube::{Client, ResourceExt};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Interfaces excluded from the network totals: virtual devices carry the same
/// bytes as the physical ones they sit on, so counting both double-counts.
/// Mirrors the filter `exporter::Sampler` applies to a live scrape.
const VIRTUAL_IFACES: &str = "lo|veth.*|docker.*|br-.*|cni.*|flannel.*|cali.*|tunl.*|kube-ipvs.*";

/// A Prometheus we can query, addressed through the API server's service proxy.
#[derive(Clone, Debug, PartialEq)]
pub struct PromService {
    pub namespace: String,
    pub name: String,
    pub port: i32,
}

impl PromService {
    /// Path to one of Prometheus's HTTP API endpoints via the service proxy.
    fn path(&self, endpoint: &str, query: &str) -> String {
        format!(
            "/api/v1/namespaces/{}/services/{}:{}/proxy/api/v1/{}?{}",
            self.namespace, self.name, self.port, endpoint, query
        )
    }
}

/// How well a Service looks like Prometheus, or None if it doesn't at all.
///
/// Deliberately conventional rather than clever: an exact name match beats a
/// prefix, which beats a label match, and a 9090 port beats any other. Picking
/// the wrong Service would mean querying something that isn't Prometheus and
/// quietly getting no history, so the ordering is what makes this predictable on
/// a cluster with several candidates.
fn score(svc: &Service) -> Option<(i32, PromService)> {
    let name = svc.name_any();
    let labels = svc.labels();
    let by_label = ["app", "app.kubernetes.io/name"]
        .iter()
        .any(|k| labels.get(*k).is_some_and(|v| v == "prometheus"));

    let name_score = if name == "prometheus" {
        3
    } else if name.starts_with("prometheus") {
        2
    } else if by_label {
        1
    } else {
        return None;
    };

    // Prefer the well-known port; fall back to a conventionally-named one.
    let ports = svc.spec.as_ref()?.ports.as_ref()?;
    let port = ports
        .iter()
        .find(|p| p.port == 9090)
        .or_else(|| {
            ports
                .iter()
                .find(|p| matches!(p.name.as_deref(), Some("web" | "http" | "http-web")))
        })
        .or_else(|| ports.first())?;
    let port_score = if port.port == 9090 { 1 } else { 0 };

    Some((
        name_score * 2 + port_score,
        PromService {
            namespace: svc.namespace().unwrap_or_default(),
            name,
            port: port.port,
        },
    ))
}

/// Find the cluster's Prometheus, or None when there isn't one we recognise.
pub async fn discover(client: &Client) -> Option<PromService> {
    let svcs: Api<Service> = Api::all(client.clone());
    let list = svcs.list(&ListParams::default()).await.ok()?;
    let mut found: Vec<(i32, PromService)> = list.items.iter().filter_map(score).collect();
    // Highest score wins; namespace/name breaks ties so the choice is stable
    // rather than dependent on list order.
    found.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.namespace.cmp(&b.1.namespace))
            .then_with(|| a.1.name.cmp(&b.1.name))
    });
    found.into_iter().next().map(|(_, s)| s)
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RangeResponse {
    data: RangeData,
}

#[derive(Deserialize)]
struct RangeData {
    #[serde(default)]
    result: Vec<RangeSeries>,
}

#[derive(Deserialize)]
struct RangeSeries {
    /// `[unix_seconds, "value"]` — Prometheus sends the value as a string.
    #[serde(default)]
    values: Vec<(f64, String)>,
}

/// Run a `query_range` and return the first series as (epoch millis, value).
///
/// A query matching nothing is an empty series, not an error: a cluster may run
/// node-exporter without the load metrics, and one missing panel shouldn't cost
/// the rest of the history.
async fn range(
    client: &Client,
    svc: &PromService,
    query: &str,
    start: i64,
    end: i64,
    step: i64,
) -> AppResult<Vec<(i64, f64)>> {
    let q = format!(
        "query={}&start={start}&end={end}&step={step}",
        urlencode(query)
    );
    let req = k7s_deps::http::Request::get(svc.path("query_range", &q))
        .body(Vec::new())
        .map_err(|e| crate::error::AppError::Other(e.to_string()))?;
    let resp: RangeResponse = client.request(req).await?;
    Ok(resp
        .data
        .result
        .into_iter()
        .next()
        .map(|s| {
            s.values
                .into_iter()
                .filter_map(|(ts, v)| v.parse::<f64>().ok().map(|v| ((ts * 1000.0) as i64, v)))
                .collect()
        })
        .unwrap_or_default())
}

/// Percent-encode a PromQL expression for a query string. The expressions here
/// are full of `{}"[]+` and spaces, all of which must survive intact.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Node history
// ---------------------------------------------------------------------------

/// The PromQL behind each series of a node's charts.
///
/// These must mean the same thing as the live scrape they backfill, or the plot
/// would step at the join. The rate window is deliberately wider than the scrape
/// interval so a single missed scrape doesn't punch a hole in the line.
fn node_queries(node: &str) -> [(&'static str, String); 8] {
    let n = format!("node=\"{node}\"");
    [
        (
            "cpu",
            format!("100 - (avg(rate(node_cpu_seconds_total{{mode=\"idle\",{n}}}[2m])) * 100)"),
        ),
        (
            "mem_used",
            format!("node_memory_MemTotal_bytes{{{n}}} - node_memory_MemAvailable_bytes{{{n}}}"),
        ),
        ("mem_total", format!("node_memory_MemTotal_bytes{{{n}}}")),
        (
            "rx",
            format!(
                "sum(rate(node_network_receive_bytes_total{{{n},device!~\"{VIRTUAL_IFACES}\"}}[2m]))"
            ),
        ),
        (
            "tx",
            format!(
                "sum(rate(node_network_transmit_bytes_total{{{n},device!~\"{VIRTUAL_IFACES}\"}}[2m]))"
            ),
        ),
        ("load1", format!("node_load1{{{n}}}")),
        ("load5", format!("node_load5{{{n}}}")),
        ("load15", format!("node_load15{{{n}}}")),
    ]
}

/// Assemble per-timestamp samples from the individual series.
///
/// Series are keyed by timestamp rather than zipped by index: Prometheus aligns
/// a `query_range` to the step, but a series with a gap returns fewer points, and
/// zipping would then shift every later value onto the wrong time.
fn assemble(series: Vec<(&'static str, Vec<(i64, f64)>)>) -> Vec<NodeSample> {
    let mut by_ts: BTreeMap<i64, NodeSample> = BTreeMap::new();
    for (name, points) in series {
        for (ts, v) in points {
            let s = by_ts.entry(ts).or_insert_with(|| NodeSample {
                ts,
                ..Default::default()
            });
            match name {
                "cpu" => s.cpu_percent = v,
                "mem_used" => s.mem_used_bytes = v,
                "mem_total" => s.mem_total_bytes = v,
                "rx" => s.net_rx_bps = v,
                "tx" => s.net_tx_bps = v,
                "load1" => s.load1 = v,
                "load5" => s.load5 = v,
                "load15" => s.load15 = v,
                _ => {}
            }
        }
    }
    by_ts.into_values().collect()
}

/// Backfill a node's charts from Prometheus: the last `window_secs`, sampled
/// every `step_secs`.
///
/// Filesystems are deliberately absent — the UI renders those as a *current* bar
/// chart, not a series, so the live scrape is the only sensible source and
/// backfilling them would show stale usage as if it were now.
pub async fn node_history(
    client: &Client,
    svc: &PromService,
    node: &str,
    now_secs: i64,
    window_secs: i64,
    step_secs: i64,
) -> AppResult<Vec<NodeSample>> {
    let start = now_secs - window_secs;
    let mut series = Vec::new();
    for (name, q) in node_queries(node) {
        // One failing query shouldn't lose the whole backfill.
        let points = range(client, svc, &q, start, now_secs, step_secs)
            .await
            .unwrap_or_default();
        series.push((name, points));
    }
    Ok(assemble(series))
}

// ---------------------------------------------------------------------------
// Pod history
// ---------------------------------------------------------------------------

/// The PromQL behind each series of a pod's charts.
///
/// CPU is a rate over 5m (wider than the scrape interval so a missed scrape
/// doesn't punch a hole) converted to millicores. Memory is the working-set
/// bytes, summed across containers.
fn pod_queries(namespace: &str, pod: &str) -> [(&'static str, String); 2] {
    let sel = format!("pod=\"{pod}\",namespace=\"{namespace}\"");
    [
        (
            "cpu_millis",
            format!("sum(rate(container_cpu_usage_seconds_total{{{sel}}}[5m])) * 1000"),
        ),
        (
            "mem_bytes",
            format!("sum(container_memory_working_set_bytes{{{sel}}})"),
        ),
    ]
}

/// Backfill a pod's CPU/memory charts from Prometheus: the last `duration_secs`,
/// sampled every 30s.
///
/// Returns an empty vec when the cluster has no Prometheus or the pod has no
/// container metrics — the live metrics poller carries on as before.
pub async fn pod_history(
    client: &Client,
    namespace: &str,
    pod: &str,
    duration_secs: i64,
) -> AppResult<Vec<PodSample>> {
    let Some(svc) = discover(client).await else {
        return Ok(Vec::new());
    };
    let now = k7s_deps::chrono::Utc::now().timestamp();
    let start = now - duration_secs;
    let step = 30i64;

    let mut series = Vec::new();
    for (name, q) in pod_queries(namespace, pod) {
        let points = range(client, &svc, &q, start, now, step)
            .await
            .unwrap_or_default();
        series.push((name, points));
    }

    // Assemble per-timestamp samples, keyed by timestamp like node_history.
    let mut by_ts: BTreeMap<i64, PodSample> = BTreeMap::new();
    for (name, points) in series {
        for (ts, v) in points {
            let s = by_ts.entry(ts).or_insert_with(|| PodSample {
                ts,
                cpu_millis: 0,
                mem_bytes: 0,
            });
            match name {
                "cpu_millis" => s.cpu_millis = v.round() as i64,
                "mem_bytes" => s.mem_bytes = v.round() as i64,
                _ => {}
            }
        }
    }
    Ok(by_ts.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k7s_deps::serde_json::json;

    fn svc(v: k7s_deps::serde_json::Value) -> Service {
        k7s_deps::serde_json::from_value(v).unwrap()
    }

    /// The obvious Service wins, and its 9090 port is what gets addressed.
    #[test]
    fn scores_a_conventional_prometheus() {
        let s = svc(json!({
            "metadata": { "name": "prometheus", "namespace": "panoptes" },
            "spec": { "ports": [{ "port": 9090 }, { "port": 9002 }] },
        }));
        let (_, p) = score(&s).expect("recognised");
        assert_eq!(
            p,
            PromService {
                namespace: "panoptes".into(),
                name: "prometheus".into(),
                port: 9090
            }
        );
    }

    /// A Service is not Prometheus just because it exists.
    #[test]
    fn ignores_unrelated_services() {
        let s = svc(json!({
            "metadata": { "name": "grafana", "namespace": "panoptes" },
            "spec": { "ports": [{ "port": 3000 }] },
        }));
        assert!(score(&s).is_none());
    }

    /// Labelled but oddly named still counts — operator-installed Prometheus is
    /// usually `kube-prometheus-stack-prometheus` or similar.
    #[test]
    fn recognises_by_label() {
        let s = svc(json!({
            "metadata": { "name": "kps-server", "namespace": "monitoring",
                          "labels": { "app.kubernetes.io/name": "prometheus" } },
            "spec": { "ports": [{ "port": 9090 }] },
        }));
        assert!(score(&s).is_some());
    }

    /// An exact name beats a prefix, which beats a label — so a cluster running
    /// several candidates picks the same one every time.
    #[test]
    fn exact_name_outranks_prefix_and_label() {
        let exact = score(&svc(json!({
            "metadata": { "name": "prometheus", "namespace": "a" },
            "spec": { "ports": [{ "port": 9090 }] } })))
        .unwrap()
        .0;
        let prefix = score(&svc(json!({
            "metadata": { "name": "prometheus-operated", "namespace": "a" },
            "spec": { "ports": [{ "port": 9090 }] } })))
        .unwrap()
        .0;
        let labelled = score(&svc(json!({
            "metadata": { "name": "mon", "namespace": "a",
                          "labels": { "app": "prometheus" } },
            "spec": { "ports": [{ "port": 9090 }] } })))
        .unwrap()
        .0;
        assert!(exact > prefix && prefix > labelled);
    }

    /// The proxy path is the shape the API server expects, including the
    /// `name:port` form that selects the service port.
    #[test]
    fn builds_the_service_proxy_path() {
        let p = PromService {
            namespace: "panoptes".into(),
            name: "prometheus".into(),
            port: 9090,
        };
        assert_eq!(
            p.path("query_range", "query=up&start=1&end=2&step=30"),
            "/api/v1/namespaces/panoptes/services/prometheus:9090/proxy/api/v1/query_range?query=up&start=1&end=2&step=30"
        );
    }

    /// PromQL is mostly punctuation; every byte of it has to survive the query
    /// string intact.
    #[test]
    fn encodes_promql_punctuation() {
        assert_eq!(
            urlencode("node_load1{node=\"murphy-yi\"}"),
            "node_load1%7Bnode%3D%22murphy-yi%22%7D"
        );
        assert_eq!(
            urlencode("rate(x[2m]) * 100"),
            "rate%28x%5B2m%5D%29%20%2A%20100"
        );
    }

    /// Series are joined on timestamp, not zipped by position — a gap in one
    /// series must not shift every later value of the others onto the wrong time.
    #[test]
    fn assembles_on_timestamp_not_position() {
        let out = assemble(vec![
            ("cpu", vec![(1_000, 10.0), (2_000, 20.0), (3_000, 30.0)]),
            // load1 is missing the middle point.
            ("load1", vec![(1_000, 0.1), (3_000, 0.3)]),
        ]);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].ts, 1_000);
        assert_eq!(out[1].ts, 2_000);
        assert_eq!(
            (out[1].cpu_percent, out[1].load1),
            (20.0, 0.0),
            "gap leaves a default, not a shift"
        );
        assert_eq!((out[2].cpu_percent, out[2].load15), (30.0, 0.0));
        assert_eq!(
            out[2].load1, 0.3,
            "the later load value stays on its own timestamp"
        );
    }

    /// Backfilled points carry no filesystems: the UI shows those as current
    /// usage, and a historical value would read as if it were now.
    #[test]
    fn backfill_carries_no_filesystems() {
        let out = assemble(vec![("cpu", vec![(1_000, 5.0)])]);
        assert!(out[0].filesystems.is_empty());
    }

    /// The node label is what makes this work after B38's scrape fix — the
    /// queries key on node name, which survives the IP churn that broke murphy-yi.
    #[test]
    fn queries_key_on_node_name() {
        let qs = node_queries("murphy-yi");
        assert!(qs.iter().all(|(_, q)| q.contains("node=\"murphy-yi\"")));
        assert!(qs.iter().any(|(k, _)| *k == "cpu"));
        // Virtual interfaces are excluded, or the network totals double-count.
        let rx = &qs.iter().find(|(k, _)| *k == "rx").unwrap().1;
        assert!(
            rx.contains("device!~"),
            "rx must exclude virtual interfaces"
        );
        assert!(rx.contains("veth"));
    }
}
