//! Event names pushed to the frontend over the EventSink.
    /// Full row snapshot for a kind: `{ kind, rows }`. Debounced per kind.
    pub const RESOURCE_UPDATE: &str = "resource-update";
    /// CRD-backed kinds discovered on connect (B15): `[{ id, group, kind, … }]`.
    pub const CUSTOM_KINDS: &str = "custom-kinds";
    /// Pod usage keyed by "ns/name": `{ [key]: { cpuMillis, memBytes } }`.
    pub const POD_METRICS: &str = "pod-metrics";
    /// Node usage percentages keyed by node name: `{ [name]: { cpuPercent, memPercent } }`.
    pub const NODE_METRICS: &str = "node-metrics";
    /// Cluster-wide status for the status bar / switcher.
    pub const CLUSTER_STATUS: &str = "cluster-status";
    /// Count of live watcher + log-stream tasks (sidebar footer).
    pub const WATCH_STATUS: &str = "watch-status";
    /// Per-kind RBAC status: emitted when a watch hits 403 Forbidden or recovers.
    pub const WATCH_KIND_STATUS: &str = "watch-kind-status";
    /// The active port-forwards, pushed whenever one is added, removed, or fails
    /// (B16) — so the strip reflects failures without the UI polling for them.
    pub const FORWARDS_UPDATE: &str = "forwards-update";
    /// One node-exporter sample for a node (B27): `{ node, sample }`. Only while
    /// that node's Metrics tab is open.
    pub const NODE_STATS: &str = "node-stats";
    /// Why a node has no plots (B27): `{ node, message }`.
    pub const NODE_STATS_ERROR: &str = "node-stats-error";
    /// Progress of a node drain (B20): `{ node, evicted, total, failures, done }`.
    /// One event carrying the node, rather than a per-node channel, so progress
    /// lands in the store and survives navigating away mid-drain.
    pub const DRAIN_PROGRESS: &str = "drain-progress";
    /// Log lines for a stream: emitted as `log-line:{streamId}`.
    pub const LOG_LINE_PREFIX: &str = "log-line:";
    /// Stream end/error: emitted as `log-closed:{streamId}`.
    pub const LOG_CLOSED_PREFIX: &str = "log-closed:";
