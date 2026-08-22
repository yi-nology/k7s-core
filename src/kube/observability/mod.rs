//! Observability domain: Prometheus metrics ([`metrics`], [`metrics_config`],
//! [`promql`]), AlertManager ([`alerting`]), Grafana ([`grafana`]), Loki/K8s
//! audit ([`audit`]), node stats ([`nodestats`]), saved queries, and the
//! Prometheus-format exporter ([`exporter`]).

pub mod alerting;

pub mod audit;

pub mod exporter;

#[cfg(not(target_os = "ios"))]
pub mod grafana;

pub mod metrics;

pub mod metrics_config;

pub mod nodestats;

pub mod promql;

pub mod saved_queries;
