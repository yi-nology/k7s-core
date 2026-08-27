//! Pod log streaming.
//!
//! Each stream runs as an abortable task that follows a container's logs, parses
//! every line into `{ ts, level, msg }`, batches them (~80ms) to avoid IPC spam,
//! and emits `log-line:{streamId}`. On end/error it emits `log-closed:{streamId}`.
//! The parser (splitting the RFC3339 prefix and detecting a level) is unit-tested.

use super::events;
use crate::core::events::EventSink;
use crate::error::{AppError, AppResult};
use k7s_deps::chrono::{DateTime, Utc};
use k7s_deps::futures::{AsyncBufReadExt, StreamExt};
use k7s_deps::k8s_openapi::api::core::v1::Pod;
use k7s_deps::kube::api::{Api, LogParams};
use k7s_deps::kube::Client;
use k7s_deps::tokio::time::{interval, Duration};
use serde::Serialize;

/// Flush cadence for batched log lines.
const FLUSH: Duration = Duration::from_millis(80);

/// A parsed log line sent to the frontend.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct LogLine {
    /// "HH:MM:SS.mmm", or "" when no timestamp prefix was present.
    pub ts: String,
    /// Normalized level: "DEBUG" | "INFO" | "WARN" | "ERROR" | "".
    pub level: &'static str,
    pub msg: String,
    /// Source container name. Empty for a single-container stream; set when
    /// streaming all containers of a pod (B7) so the UI can tag each line.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub container: String,
}

/// Batch payload for a `log-line:{id}` event.
#[derive(Serialize, Clone)]
struct LogBatch {
    lines: Vec<LogLine>,
}

/// Options mirrored from the frontend `LogOptions`.
#[derive(Default, Clone)]
pub struct LogStreamOptions {
    /// Seed with this many historical lines on first open.
    pub tail: Option<i64>,
    /// Resume from this time (used on un-pause), RFC3339.
    pub since_time: Option<String>,
    /// Only lines from the last N seconds (B29). Mutually exclusive with
    /// `since_time` at the API — see [`log_params`] for which wins.
    pub since_seconds: Option<i64>,
    /// Read the *previous* container instead of the current one (B29): what a
    /// crash-looper printed on its way down, which the running container can't
    /// tell you.
    pub previous: bool,
}

/// Run a follow-log stream until the task is aborted or the stream ends.
///
/// Emits `log-line:{stream_id}` batches and a final `log-closed:{stream_id}`.
pub async fn run_log_stream(
    client: Client,
    sink: EventSink,
    stream_id: String,
    namespace: String,
    pod: String,
    container: String,
    opts: LogStreamOptions,
) {
    let closed_event = format!("{}{}", events::LOG_CLOSED_PREFIX, stream_id);
    // Empty container = stream every container of the pod, interleaved (B7).
    let result = if container.is_empty() {
        stream_all(client, &sink, &stream_id, &namespace, &pod, opts).await
    } else {
        stream_one(
            client, &sink, &stream_id, &namespace, &pod, &container, opts,
        )
        .await
    };
    match result {
        Ok(reason) => {
            sink.emit(&closed_event, &reason);
        }
        Err(e) => {
            // Surface the API error as the close reason so the UI can show it.
            sink.emit(&closed_event, &e.to_string());
        }
    }
}

/// Build the LogParams shared by single- and multi-container streams.
///
/// Two rules here are the API's, not ours:
///
/// - **`previous` can't be followed.** The previous container is dead; it will
///   never emit another line, so `follow` would hang the task until it's aborted
///   rather than ending the stream. A previous read is a snapshot.
/// - **`since_time` and `since_seconds` are mutually exclusive** — sending both
///   is a 400. The resume anchor wins: it's the more precise of the two, and it's
///   always inside the window the user picked anyway, so honouring it can't show
///   them lines older than they asked for.
pub fn log_params(container: &str, opts: &LogStreamOptions) -> LogParams {
    let mut lp = LogParams {
        follow: !opts.previous,
        timestamps: true,
        container: Some(container.to_string()),
        previous: opts.previous,
        ..Default::default()
    };
    lp.tail_lines = opts.tail;

    match (&opts.since_time, opts.since_seconds) {
        (Some(ts), _) => {
            // Parse the resume time; ignore a malformed value rather than failing.
            if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
                let dt_utc = dt.with_timezone(&Utc);
                lp.since_time = k7s_deps::k8s_openapi::jiff::Timestamp::new(
                    dt_utc.timestamp(),
                    dt_utc.timestamp_subsec_nanos() as i32,
                )
                .ok();
            }
        }
        (None, Some(secs)) => lp.since_seconds = Some(secs),
        (None, None) => {}
    }
    lp
}

/// Stream a single container's logs, tagging each line with the container name.
async fn stream_one(
    client: Client,
    sink: &EventSink,
    stream_id: &str,
    namespace: &str,
    pod: &str,
    container: &str,
    opts: LogStreamOptions,
) -> AppResult<String> {
    let api: Api<Pod> = Api::namespaced(client, namespace);
    let reader = api
        .log_stream(pod, &log_params(container, &opts))
        .await
        .map_err(|e| AppError::Kube(e.to_string()))?;
    let mut lines = reader.lines();

    let line_event = format!("{}{}", events::LOG_LINE_PREFIX, stream_id);
    let mut batch: Vec<LogLine> = Vec::new();
    let mut flush = interval(FLUSH);

    loop {
        k7s_deps::tokio::select! {
            next = lines.next() => match next {
                Some(Ok(raw)) => {
                    let mut line = parse_log_line(&raw);
                    line.container = container.to_string();
                    batch.push(line);
                }
                None => {
                    flush_batch(sink, &line_event, &mut batch);
                    return Ok("stream ended".to_string());
                }
                Some(Err(e)) => {
                    flush_batch(sink, &line_event, &mut batch);
                    return Err(AppError::Kube(e.to_string()));
                }
            },
            _ = flush.tick() => flush_batch(sink, &line_event, &mut batch),
        }
    }
}

/// Stream every container of the pod, interleaved. One reader task per container
/// feeds a shared channel; the batcher drains it. Reader tasks live in a JoinSet
/// so aborting this stream (dropping the JoinSet) aborts them too.
async fn stream_all(
    client: Client,
    sink: &EventSink,
    stream_id: &str,
    namespace: &str,
    pod: &str,
    opts: LogStreamOptions,
) -> AppResult<String> {
    // Discover the pod's containers.
    let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let pod_obj = api.get(pod).await?;
    let containers: Vec<String> = pod_obj
        .spec
        .map(|s| s.containers.into_iter().map(|c| c.name).collect())
        .unwrap_or_default();
    if containers.is_empty() {
        return Ok("no containers".to_string());
    }

    let (tx, mut rx) = k7s_deps::tokio::sync::mpsc::channel::<LogLine>(256);
    let mut readers = k7s_deps::tokio::task::JoinSet::new();
    for container in containers {
        let api = api.clone();
        let lp = log_params(&container, &opts);
        let tx = tx.clone();
        let pod_name = pod.to_string();
        readers.spawn(async move {
            match api.log_stream(&pod_name, &lp).await {
                Ok(reader) => {
                    let mut lines = reader.lines();
                    while let Some(Ok(raw)) = lines.next().await {
                        let mut line = parse_log_line(&raw);
                        line.container = container.clone();
                        if tx.send(line).await.is_err() {
                            break; // batcher gone
                        }
                    }
                }
                // A failed container must not vanish silently from an
                // all-containers stream — the other containers keep flowing,
                // so the failure looks like "no logs". Surface it as an
                // ERROR line through the same batch channel/sink.
                Err(e) => {
                    let _ = tx
                        .send(LogLine {
                            ts: String::new(),
                            level: "ERROR",
                            msg: format!("log stream for container '{container}' failed: {e}"),
                            container: container.clone(),
                        })
                        .await;
                }
            }
        });
    }
    drop(tx); // so rx closes once all readers finish

    let line_event = format!("{}{}", events::LOG_LINE_PREFIX, stream_id);
    let mut batch: Vec<LogLine> = Vec::new();
    let mut flush = interval(FLUSH);
    loop {
        k7s_deps::tokio::select! {
            got = rx.recv() => match got {
                Some(line) => batch.push(line),
                None => {
                    flush_batch(sink, &line_event, &mut batch);
                    return Ok("stream ended".to_string());
                }
            },
            _ = flush.tick() => flush_batch(sink, &line_event, &mut batch),
        }
    }
}

/// Emit and clear the batch if non-empty.
fn flush_batch(sink: &EventSink, line_event: &str, batch: &mut Vec<LogLine>) {
    if !batch.is_empty() {
        sink.emit(
            line_event,
            &LogBatch {
                lines: std::mem::take(batch),
            },
        );
    }
}

/// Fetch logs for export: resolves containers, fetches each, interleaves
/// headers. Returns the assembled text and total line count. The caller decides
/// where to write the output (file for Tauri, return-count for web).
pub async fn fetch_export_logs(
    client: Client,
    namespace: &str,
    pod: &str,
    containers: Vec<String>,
    since_seconds: Option<i64>,
    previous: bool,
) -> AppResult<(String, usize)> {
    let api: Api<Pod> = Api::namespaced(client, namespace);

    let opts = LogStreamOptions {
        tail: None,
        since_time: None,
        since_seconds,
        previous,
    };

    // An empty container means "all of them" (B7), so the export mirrors what the
    // view interleaves — one block per container, labelled, rather than a soup of
    // lines whose origin the file can't show.
    let containers = if containers.is_empty() {
        let p = api
            .get(pod)
            .await
            .map_err(|e| AppError::Kube(e.to_string()))?;
        p.spec
            .map(|s| s.containers.into_iter().map(|c| c.name).collect::<Vec<_>>())
            .unwrap_or_default()
    } else {
        containers
    };

    let mut out = String::new();
    for name in &containers {
        let mut lp = log_params(name, &opts);
        // log_params follows unless reading `previous`; an export must always end.
        lp.follow = false;
        let text = api
            .logs(pod, &lp)
            .await
            .map_err(|e| AppError::Kube(e.to_string()))?;
        if containers.len() > 1 {
            out.push_str(&format!("===== container: {name} =====\n"));
        }
        out.push_str(&text);
        if !text.ends_with('\n') {
            out.push('\n');
        }
    }

    let lines = out.lines().count();
    Ok((out, lines))
}

/// Parse one raw log line (with a leading RFC3339 timestamp from `timestamps:true`)
/// into `{ ts, level, msg }`. Never drops content: an unparseable timestamp leaves
/// the whole line as the message with an empty ts.
pub fn parse_log_line(raw: &str) -> LogLine {
    // kube prefixes "<rfc3339> <message>"; split on the first space.
    let (ts, msg) = match raw.split_once(' ') {
        Some((maybe_ts, rest)) => match DateTime::parse_from_rfc3339(maybe_ts) {
            Ok(dt) => (
                dt.with_timezone(&Utc).format("%H:%M:%S%.3f").to_string(),
                rest,
            ),
            // No parseable timestamp: keep the whole line as the message.
            Err(_) => (String::new(), raw),
        },
        None => (String::new(), raw),
    };
    LogLine {
        ts,
        level: detect_level(msg),
        msg: msg.to_string(),
        container: String::new(),
    }
}

/// Detect a log level from the message: a JSON `"level"` field first, then a
/// word-boundary token scan of the head of the line. Returns "" if none found.
fn detect_level(msg: &str) -> &'static str {
    // Only inspect the head — levels appear near the start of a line.
    let head_len = msg.len().min(200);
    let head = &msg[..head_len];

    if let Some(l) = json_level(head) {
        return l;
    }

    let upper = head.to_ascii_uppercase();
    // Order matters: error-family first, then warn, info, debug/trace.
    const TOKENS: [(&str, &str); 8] = [
        ("PANIC", "ERROR"),
        ("FATAL", "ERROR"),
        ("ERROR", "ERROR"),
        ("ERR", "ERROR"),
        ("WARNING", "WARN"),
        ("WARN", "WARN"),
        ("INFO", "INFO"),
        ("DEBUG", "DEBUG"),
    ];
    for (needle, level) in TOKENS {
        if contains_word(&upper, needle) {
            return level;
        }
    }
    // TRACE maps to DEBUG (checked last so it can't shadow the others).
    if contains_word(&upper, "TRACE") {
        return "DEBUG";
    }
    ""
}

/// Extract a level from a JSON `"level":"…"` field if present.
fn json_level(head: &str) -> Option<&'static str> {
    let idx = head.find("\"level\"")?;
    // Find the value string after the colon.
    let after = &head[idx + 7..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(normalize_level(&rest[..end]))
}

/// Map an arbitrary level word to one of our four buckets (or "").
fn normalize_level(word: &str) -> &'static str {
    match word.to_ascii_uppercase().as_str() {
        "ERROR" | "ERR" | "FATAL" | "PANIC" | "CRITICAL" => "ERROR",
        "WARN" | "WARNING" => "WARN",
        "INFO" | "INFORMATION" | "NOTICE" => "INFO",
        "DEBUG" | "TRACE" | "VERBOSE" => "DEBUG",
        _ => "",
    }
}

/// True if `needle` appears in `haystack` bounded by non-alphanumeric characters
/// (so "ERROR" doesn't match inside "TERROR" and "ERR" doesn't match "ERROR").
fn contains_word(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let nlen = needle.len();
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        let i = start + pos;
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let after_idx = i + nlen;
        let after_ok = after_idx >= bytes.len() || !bytes[after_idx].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = i + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_prefix_into_hms_millis() {
        let line = parse_log_line("2026-07-15T13:04:05.678901234Z hello world");
        assert_eq!(line.ts, "13:04:05.678");
        assert_eq!(line.msg, "hello world");
    }

    #[test]
    fn line_without_timestamp_keeps_full_message() {
        let line = parse_log_line("no timestamp here");
        assert_eq!(line.ts, "");
        assert_eq!(line.msg, "no timestamp here");
        assert_eq!(line.level, "");
    }

    #[test]
    fn detects_klog_style_levels() {
        assert_eq!(
            parse_log_line("2026-07-15T13:04:05Z INFO started ok").level,
            "INFO"
        );
        assert_eq!(
            parse_log_line("2026-07-15T13:04:05Z ERROR boom").level,
            "ERROR"
        );
        assert_eq!(
            parse_log_line("2026-07-15T13:04:05Z WARN careful").level,
            "WARN"
        );
        assert_eq!(
            parse_log_line("2026-07-15T13:04:05Z DEBUG noisy").level,
            "DEBUG"
        );
    }

    #[test]
    fn detects_json_level_field() {
        let l = parse_log_line(r#"2026-07-15T13:04:05Z {"level":"error","msg":"nope"}"#);
        assert_eq!(l.level, "ERROR");
        let w = parse_log_line(r#"2026-07-15T13:04:05Z {"ts":1,"level": "warning"}"#);
        assert_eq!(w.level, "WARN");
    }

    #[test]
    fn word_boundary_avoids_false_positives() {
        // "TERROR" should not be read as ERROR; "information" not as INFO-token
        // via boundaries (it still normalizes via json only). Here plain text:
        assert_eq!(detect_level("the TERROR of substrings"), "");
        assert_eq!(detect_level("reticulating splines"), "");
    }

    #[test]
    fn fatal_and_panic_map_to_error() {
        assert_eq!(detect_level("FATAL could not bind"), "ERROR");
        assert_eq!(detect_level("PANIC nil deref"), "ERROR");
        assert_eq!(detect_level("TRACE entering fn"), "DEBUG");
    }

    // ---- LogParams construction (B29) ----

    /// The default read follows the running container, seeded by tail.
    #[test]
    fn default_params_follow_the_current_container() {
        let lp = log_params(
            "app",
            &LogStreamOptions {
                tail: Some(200),
                ..Default::default()
            },
        );
        assert!(lp.follow);
        assert!(!lp.previous);
        assert_eq!(lp.tail_lines, Some(200));
        assert_eq!(lp.container.as_deref(), Some("app"));
        assert!(lp.timestamps, "the parser needs the RFC3339 prefix");
    }

    /// A previous read must not follow: that container is dead and will never emit
    /// another line, so following it would hang the task instead of ending it.
    #[test]
    fn previous_never_follows() {
        let lp = log_params(
            "app",
            &LogStreamOptions {
                previous: true,
                ..Default::default()
            },
        );
        assert!(lp.previous);
        assert!(
            !lp.follow,
            "a terminated container is a snapshot, not a stream"
        );
    }

    /// The API rejects since_time and since_seconds together, so only one is set.
    #[test]
    fn since_time_and_since_seconds_are_never_both_sent() {
        let lp = log_params(
            "app",
            &LogStreamOptions {
                since_time: Some("2026-07-17T12:00:00Z".into()),
                since_seconds: Some(300),
                ..Default::default()
            },
        );
        assert!(lp.since_time.is_some());
        assert_eq!(lp.since_seconds, None, "sending both is a 400");
    }

    /// The resume anchor wins, because it's more precise — and it's always inside
    /// the window the user picked, so this can't show them older lines than asked.
    #[test]
    fn the_resume_anchor_wins_over_the_window() {
        let lp = log_params(
            "app",
            &LogStreamOptions {
                since_time: Some("2026-07-17T12:00:00Z".into()),
                ..Default::default()
            },
        );
        assert!(lp.since_time.is_some());
    }

    /// A window with no anchor is the plain "last 5 minutes" case.
    #[test]
    fn a_window_alone_sets_since_seconds() {
        let lp = log_params(
            "app",
            &LogStreamOptions {
                since_seconds: Some(300),
                ..Default::default()
            },
        );
        assert_eq!(lp.since_seconds, Some(300));
        assert!(lp.since_time.is_none());
    }

    /// A malformed resume anchor is ignored rather than failing the stream — the
    /// worst case is re-showing a few lines, which beats no logs at all.
    #[test]
    fn a_malformed_anchor_is_ignored() {
        let lp = log_params(
            "app",
            &LogStreamOptions {
                since_time: Some("nonsense".into()),
                ..Default::default()
            },
        );
        assert!(lp.since_time.is_none());
        assert!(lp.follow);
    }
}
