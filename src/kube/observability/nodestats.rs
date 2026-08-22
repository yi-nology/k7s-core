//! Live node statistics from node-exporter (B27): find the exporter for a node,
//! scrape it on a tick, and emit plottable samples.
//!
//! Runs only while a node's Metrics tab is open. That's deliberate: each poll
//! transfers a few hundred KB (murphy-yi's exporter serves ~411KB), so this is not
//! something to leave running for every node in the background.
//!
//! Reaching the exporter goes through the same port-forward machinery as B6. Two
//! more obvious routes don't work on a real cluster:
//!   - Prometheus already has this data *if* it's scraping the exporters — but a
//!     cluster whose scrape targets have drifted has none at all (murphy-yi's point at
//!     a node IP that no longer exists), and that isn't something the app can fix.
//!   - The API server's pod proxy (`/api/v1/.../pods/x:9100/proxy/metrics`) is the
//!     tidiest route on paper, and times out on murphy-yi even for a Ready node.
//!
//! Port-forwarding goes via the kubelet instead, and works.

use super::exporter::{self, NodeSample, Sampler};
use crate::core::events::EventSink;
use crate::error::{AppError, AppResult};
use crate::kube::events;
use k7s_deps::k8s_openapi::api::core::v1::Pod;
use k7s_deps::kube::api::{Api, ListParams};
use k7s_deps::kube::{Client, ResourceExt};
use k7s_deps::tokio::sync::{mpsc, oneshot};
use k7s_deps::tokio::time::{interval, Duration, MissedTickBehavior};
use serde::Serialize;

/// The port node-exporter listens on. Its well-known default; the DaemonSet on
/// murphy-yi declares it explicitly too.
const EXPORTER_PORT: u16 = 9100;

/// Payload for [`events::NODE_STATS`].
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NodeStats {
    pub node: String,
    pub sample: NodeSample,
}

/// Payload for [`events::NODE_STATS_ERROR`] — why a node has no plots.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatsError {
    pub node: String,
    pub message: String,
}

/// Find the node-exporter pod running on `node`.
///
/// Matched by container port rather than by name or label: every distribution
/// names and labels its exporter differently ("node-exporter",
/// "prometheus-node-exporter", "kube-prometheus-stack-prometheus-node-exporter"),
/// but they all serve 9100, and only one pod per node does.
pub async fn find_exporter(client: Client, node: &str) -> AppResult<(String, String)> {
    let pods: Api<Pod> = Api::all(client);
    let lp = ListParams::default().fields(&format!("spec.nodeName={node},status.phase=Running"));
    let list = pods
        .list(&lp)
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;

    for p in list.items {
        let serves_9100 = p
            .spec
            .iter()
            .flat_map(|s| s.containers.iter())
            .flat_map(|c| c.ports.iter().flatten())
            .any(|port| port.container_port == i32::from(EXPORTER_PORT));
        // The name check keeps us from grabbing some unrelated pod that happens to
        // use 9100; the port check is what makes the name check tolerant.
        if serves_9100 && p.name_any().contains("node-exporter") {
            return Ok((p.namespace().unwrap_or_default(), p.name_any()));
        }
    }
    Err(AppError::NotFound(format!(
        "no node-exporter pod found on {node} — install one, or its port isn't 9100"
    )))
}

/// Scrape `node`'s exporter every `every`, emitting samples until aborted.
pub async fn run_node_stats(client: Client, sink: EventSink, node: String, every: Duration) {
    let (namespace, pod) = match find_exporter(client.clone(), &node).await {
        Ok(v) => v,
        Err(e) => return fail(&sink, &node, e.to_string()),
    };

    // One forward for the life of the tab, rather than one per scrape: setting a
    // forward up costs a round trip through the API server, which would dominate a
    // 5s poll.
    let (ready_tx, ready_rx) = oneshot::channel();
    let (err_tx, mut err_rx) = mpsc::channel::<String>(8);
    let pf = k7s_deps::tokio::spawn(crate::kube::portforward::run_port_forward(
        client,
        namespace,
        pod.clone(),
        EXPORTER_PORT,
        0, // let the OS pick a free port
        ready_tx,
        err_tx,
    ));

    let local_port = match ready_rx.await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            pf.abort();
            return fail(&sink, &node, format!("could not forward to {pod}: {e}"));
        }
        Err(_) => {
            pf.abort();
            return fail(
                &sink,
                &node,
                "port-forward ended before it was ready".into(),
            );
        }
    };

    let http = k7s_deps::reqwest::Client::new();
    let url = format!("http://127.0.0.1:{local_port}/metrics");
    let mut sampler = Sampler::default();
    let mut tick = interval(every);
    // A slow scrape must not cause a burst of catch-up polls.
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Report a scrape failure once, not on every tick.
    let mut reported = false;

    loop {
        tick.tick().await;

        // A dead forward is unrecoverable here (the pod went away); say so rather
        // than tick silently forever.
        if let Ok(e) = err_rx.try_recv() {
            fail(&sink, &node, format!("port-forward to {pod} failed: {e}"));
            break;
        }

        match scrape(&http, &url).await {
            Ok(text) => {
                reported = false;
                let raw = exporter::parse(&text, now_ms());
                // The first scrape only establishes a baseline for the counters.
                if let Some(sample) = sampler.push(raw) {
                    sink.emit(
                        events::NODE_STATS,
                        &NodeStats {
                            node: node.clone(),
                            sample,
                        },
                    );
                }
            }
            Err(e) => {
                if !reported {
                    reported = true;
                    fail(&sink, &node, format!("scrape failed: {e}"));
                }
            }
        }
    }

    pf.abort();
}

/// GET the exporter's /metrics.
async fn scrape(http: &k7s_deps::reqwest::Client, url: &str) -> Result<String, String> {
    let resp = http
        // Bounded: a hung exporter must not wedge the poll loop forever.
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.text().await.map_err(|e| e.to_string())
}

/// Tell the UI why this node has no plots (best-effort).
fn fail(sink: &EventSink, node: &str, message: String) {
    k7s_deps::tracing::warn!("node stats for {node}: {message}");
    sink.emit(
        events::NODE_STATS_ERROR,
        &NodeStatsError {
            node: node.to_string(),
            message,
        },
    );
}

/// Epoch milliseconds.
fn now_ms() -> i64 {
    k7s_deps::chrono::Utc::now().timestamp_millis()
}
