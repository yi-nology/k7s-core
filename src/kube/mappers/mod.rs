//! Per-kind mapping from typed Kubernetes objects to [`Row`] DTOs.
//!
//! Each `map_*` function produces cells in the exact column order declared for its
//! kind in src/lib/kinds.ts (the shared column contract). Coloring (tone) follows
//! the prototype's rules: healthy -> Good (green, with a status dot), degraded ->
//! Warn (amber), failed -> Bad (red); names Primary, namespace/age Muted, data
//! Secondary. CPU/MEM for pods and CPU/MEMORY for nodes are "—" placeholders that
//! the frontend overlays from the separate metrics feed.

mod cluster;
mod config;
mod dynamic;
mod network;
mod pod;
mod rbac;
mod storage;
#[cfg(test)]
mod test_utils;
mod workload;

// Re-export all public map_* functions so existing call sites (e.g. watchers.rs)
// continue to work as `mappers::map_pod(...)`.
pub use cluster::*;
pub use config::*;
pub use dynamic::*;
pub use network::*;
pub use pod::*;
pub use rbac::*;
pub use storage::*;
pub use workload::*;

use super::dto::{Cell, Row, Tone};
use k7s_deps::kube::ResourceExt;

// ---------------------------------------------------------------------------
// Shared helpers (visible to submodules via `super::*`)
// ---------------------------------------------------------------------------

/// Stable uid: the k8s uid, or "namespace/name" when uid is absent.
pub(super) fn uid_of<K: ResourceExt>(obj: &K) -> String {
    obj.uid()
        .unwrap_or_else(|| format!("{}/{}", obj.namespace().unwrap_or_default(), obj.name_any()))
}

/// RFC3339 creation timestamp string, or "" if unset.
pub(super) fn creation_rfc3339<K: ResourceExt>(obj: &K) -> String {
    obj.creation_timestamp()
        .map(|t| t.0.to_string())
        .unwrap_or_default()
}

/// Age cell built from the object's creation timestamp (frontend formats it).
pub(super) fn age_cell<K: ResourceExt>(obj: &K) -> Cell {
    let ts = creation_rfc3339(obj);
    Cell::age(if ts.is_empty() { None } else { Some(ts) })
}

/// The leading NAME cell (primary tone).
pub(super) fn name_cell<K: ResourceExt>(obj: &K) -> Cell {
    Cell::new(obj.name_any(), Tone::Primary)
}

/// The NAMESPACE cell (muted tone).
pub(super) fn ns_cell<K: ResourceExt>(obj: &K) -> Cell {
    Cell::new(obj.namespace().unwrap_or_default(), Tone::Muted)
}

/// Convert a JSON value to a display string: strings pass through, numbers
/// stringify, anything else becomes "—".
pub(super) fn json_value_to_string(v: Option<&k7s_deps::serde_json::Value>) -> String {
    match v {
        Some(val) => {
            if let Some(s) = val.as_str() {
                s.to_string()
            } else if let Some(n) = val.as_i64() {
                n.to_string()
            } else if let Some(n) = val.as_u64() {
                n.to_string()
            } else if let Some(n) = val.as_f64() {
                format!("{n}")
            } else {
                "—".to_string()
            }
        }
        None => "—".to_string(),
    }
}

/// The prototype's status-word -> tone mapping.
pub fn status_tone(status: &str) -> Tone {
    match status {
        "Running" | "Ready" | "Active" | "Completed" | "Succeeded" | "Bound" => Tone::Good,
        "Pending" | "ContainerCreating" | "Terminating" => Tone::Warn,
        _ => Tone::Bad,
    }
}

/// Humanize a duration in seconds like kubectl ages/durations ("42s", "3m12s",
/// "2h14m", "4d2h", "31d"). Mirrors the TS `formatAge` so both sides agree.
pub fn humanize_duration(mut secs: i64) -> String {
    if secs < 0 {
        secs = 0;
    }
    const MIN: i64 = 60;
    const HOUR: i64 = 3600;
    const DAY: i64 = 86400;
    if secs < MIN {
        return format!("{secs}s");
    }
    if secs < HOUR {
        let m = secs / MIN;
        let s = secs % MIN;
        return if m < 10 && s > 0 {
            format!("{m}m{s}s")
        } else {
            format!("{m}m")
        };
    }
    if secs < DAY {
        let h = secs / HOUR;
        let m = (secs % HOUR) / MIN;
        return if m > 0 {
            format!("{h}h{m}m")
        } else {
            format!("{h}h")
        };
    }
    let d = secs / DAY;
    if d < 8 {
        let h = (secs % DAY) / HOUR;
        return if h > 0 {
            format!("{d}d{h}h")
        } else {
            format!("{d}d")
        };
    }
    format!("{d}d")
}

/// Seconds between an RFC3339-ish k8s `Time` and now (clamped at 0).
pub(super) fn secs_since(
    t: &k7s_deps::k8s_openapi::apimachinery::pkg::apis::meta::v1::Time,
) -> i64 {
    let now = k7s_deps::k8s_openapi::jiff::Timestamp::now();
    now.duration_since(t.0).as_secs().max(0)
}

/// Build a namespaced Row from prebuilt cells (shared by the simple kinds).
pub(super) fn simple_row<K: ResourceExt>(obj: &K, cells: Vec<Cell>) -> Row {
    Row {
        uid: uid_of(obj),
        name: obj.name_any(),
        namespace: obj.namespace(),
        cells,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn humanize_duration_always_has_unit_suffix(secs in 0i64..1_000_000) {
            let result = humanize_duration(secs);
            assert!(
                result.ends_with('s') || result.ends_with('m')
                    || result.ends_with('h') || result.ends_with('d'),
                "unexpected suffix in: {result}"
            );
        }

        #[test]
        fn humanize_duration_negative_clamped(secs in i64::MIN..0i64) {
            let result = humanize_duration(secs);
            assert_eq!(result, "0s");
        }

        #[test]
        fn humanize_duration_monotonic(a in 0i64..500_000, b in 0i64..500_000) {
            prop_assume!(a <= b);
            let sa = parse_duration_secs(&humanize_duration(a));
            let sb = parse_duration_secs(&humanize_duration(b));
            assert!(sa <= sb, "not monotonic: humanize({a}) parsed {sa}, humanize({b}) parsed {sb}");
        }

        #[test]
        fn status_tone_good_statuses(s in "(Running|Succeeded|Active|Completed|Bound|Ready)") {
            assert_eq!(status_tone(&s), Tone::Good);
        }

        #[test]
        fn status_tone_warn_statuses(s in "(Pending|ContainerCreating|Terminating)") {
            assert_eq!(status_tone(&s), Tone::Warn);
        }

        #[test]
        fn status_tone_unknown_is_bad(s in "[A-Z][a-zA-Z]{3,20}") {
            // Skip the test if the generated string happens to be a known status.
            if !matches!(
                s.as_str(),
                "Running" | "Succeeded" | "Active" | "Completed" | "Bound" | "Ready"
                    | "Pending" | "ContainerCreating" | "Terminating"
            ) {
                assert_eq!(status_tone(&s), Tone::Bad);
            }
        }
    }

    /// Parse a humanized duration string back into total seconds.
    fn parse_duration_secs(s: &str) -> i64 {
        let mut total = 0i64;
        let mut num = String::new();
        for c in s.chars() {
            if c.is_ascii_digit() {
                num.push(c);
            } else {
                let n: i64 = num.parse().unwrap_or(0);
                total += match c {
                    's' => n,
                    'm' => n * 60,
                    'h' => n * 3600,
                    'd' => n * 86400,
                    _ => 0,
                };
                num.clear();
            }
        }
        total
    }
}
