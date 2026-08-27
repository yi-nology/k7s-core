//! Scheduled AI tasks — periodic health checks, alert analysis, etc.
//!
//! Inspired by openocta's cron module (`src/pkg/cron/`). Users define
//! recurring tasks with a cron expression and a prompt; when a task comes
//! due, it is run through the AI agent loop and the results are stored.
//!
//! Tasks are persisted as JSON under `<data_dir>/ai-cron.json`.
//!
//! # Who drives the clock
//!
//! The scheduling loop is driven by the host shell (it polls
//! [`CronScheduler::due_tasks`] on its own timer and runs what's due);
//! core itself only provides **due determination** — a minimal 5-field cron
//! matcher ([`CronExpr`], supporting `* , - /` and numbers at minute
//! granularity) plus persistence of each task's `last_run`. There is no
//! background timer inside this module.

use k7s_deps::tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// A scheduled AI task.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronTask {
    pub id: String,
    /// Human-readable name (e.g. "Hourly health check").
    pub name: String,
    /// Cron expression (5-field: min hour day month weekday).
    pub cron_expr: String,
    /// The prompt to send to the AI agent.
    pub prompt: String,
    /// Whether this task is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// The skill to activate for this task (optional).
    #[serde(default)]
    pub skill_id: Option<String>,
    /// Last run timestamp (ISO 8601).
    #[serde(default)]
    pub last_run: Option<String>,
    /// Last run result (the AI's response).
    #[serde(default)]
    pub last_result: Option<String>,
    /// Last run status.
    #[serde(default)]
    pub last_status: CronRunStatus,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CronRunStatus {
    #[default]
    Never,
    Success,
    Failed,
}

/// Result of a cron task run.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CronRunResult {
    pub task_id: String,
    pub timestamp: String,
    pub success: bool,
    pub response: String,
    pub duration_ms: u64,
}

/// The persisted cron file.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct CronFile {
    tasks: Vec<CronTask>,
    /// History of recent runs (newest first, capped at 100).
    #[serde(default)]
    history: Vec<CronRunResult>,
}

/// In-memory scheduler state.
pub struct CronScheduler {
    data_dir: PathBuf,
    state: Arc<Mutex<CronFile>>,
}

/// Process-wide registry of per-data_dir cron states.
///
/// Same lost-update hazard as [`crate::ai::session::SessionManager`]: several
/// `CronScheduler` instances over one data_dir each holding a private copy
/// would overwrite each other's full-file saves. Sharing the memory per
/// data_dir (first instance loads, the rest reuse) serializes mutations.
static CRON_STATES: std::sync::OnceLock<std::sync::Mutex<HashMap<PathBuf, Arc<Mutex<CronFile>>>>> =
    std::sync::OnceLock::new();

fn shared_cron_state(data_dir: &std::path::Path) -> Arc<Mutex<CronFile>> {
    let registry = CRON_STATES.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut map = registry.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(data_dir.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(load_file(data_dir))))
        .clone()
}

impl CronScheduler {
    pub fn new(data_dir: PathBuf) -> Self {
        let state = shared_cron_state(&data_dir);
        Self { data_dir, state }
    }

    /// List all tasks.
    pub async fn list(&self) -> Vec<CronTask> {
        self.state.lock().await.tasks.clone()
    }

    /// Add a new task.
    pub async fn add(&self, task: CronTask) {
        let mut state = self.state.lock().await;
        state.tasks.push(task);
        save_file(&self.data_dir, &state);
    }

    /// Update an existing task (matched by id).
    pub async fn update(&self, task: &CronTask) -> bool {
        let mut state = self.state.lock().await;
        if let Some(existing) = state.tasks.iter_mut().find(|t| t.id == task.id) {
            *existing = task.clone();
            save_file(&self.data_dir, &state);
            true
        } else {
            false
        }
    }

    /// Delete a task by id.
    pub async fn delete(&self, id: &str) -> bool {
        let mut state = self.state.lock().await;
        let before = state.tasks.len();
        state.tasks.retain(|t| t.id != id);
        if state.tasks.len() < before {
            save_file(&self.data_dir, &state);
            true
        } else {
            false
        }
    }

    /// Toggle a task's enabled state.
    pub async fn toggle(&self, id: &str) -> bool {
        let mut state = self.state.lock().await;
        if let Some(task) = state.tasks.iter_mut().find(|t| t.id == id) {
            task.enabled = !task.enabled;
            save_file(&self.data_dir, &state);
            true
        } else {
            false
        }
    }

    /// Record a run result.
    /// Stamp `last_run` WITHOUT recording an outcome — used by the
    /// background runner before executing, so the next tick can't re-fire
    /// a run that's still in flight.
    pub async fn mark_started(&self, task_id: &str) {
        let mut state = self.state.lock().await;
        if let Some(task) = state.tasks.iter_mut().find(|t| t.id == task_id) {
            task.last_run = Some(k7s_deps::chrono::Utc::now().to_rfc3339());
        }
        save_file(&self.data_dir, &state);
    }

    pub async fn record_run(&self, result: CronRunResult) {
        let mut state = self.state.lock().await;
        // Update the task's last_run.
        if let Some(task) = state.tasks.iter_mut().find(|t| t.id == result.task_id) {
            task.last_run = Some(result.timestamp.clone());
            task.last_result = Some(result.response.clone());
            task.last_status = if result.success {
                CronRunStatus::Success
            } else {
                CronRunStatus::Failed
            };
        }
        // Add to history (newest first, cap at 100).
        state.history.insert(0, result);
        state.history.truncate(100);
        save_file(&self.data_dir, &state);
    }

    /// Get run history for a task (or all tasks).
    pub async fn history(&self, task_id: Option<&str>) -> Vec<CronRunResult> {
        let state = self.state.lock().await;
        state
            .history
            .iter()
            .filter(|r| task_id.map_or(true, |id| r.task_id == id))
            .cloned()
            .collect()
    }

    /// Get the tasks due to run now, per each task's cron expression and its
    /// persisted `last_run`. A task is due when the next occurrence after its
    /// last run (or after the epoch, if never run) is at or before now.
    /// Tasks with an unparseable expression are skipped with a warning rather
    /// than firing on a bogus schedule.
    pub async fn due_tasks(&self) -> Vec<CronTask> {
        let state = self.state.lock().await;
        let now = k7s_deps::chrono::Utc::now();
        state
            .tasks
            .iter()
            .filter(|t| t.enabled)
            .filter(|t| {
                let expr = match CronExpr::parse(&t.cron_expr) {
                    Ok(e) => e,
                    Err(e) => {
                        k7s_deps::tracing::warn!(
                            task = %t.id,
                            expr = %t.cron_expr,
                            error = %e,
                            "invalid cron expression; skipping task"
                        );
                        return false;
                    }
                };
                // Anchor at the last recorded run; an unparseable stamp is
                // treated as "never ran" so a corrupt timestamp can't
                // silently disable a task forever.
                let anchor = t
                    .last_run
                    .as_deref()
                    .and_then(|s| k7s_deps::chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&k7s_deps::chrono::Utc))
                    .unwrap_or(k7s_deps::chrono::DateTime::UNIX_EPOCH);
                match expr.next_after(anchor) {
                    Some(next) => next <= now,
                    None => false, // never matches within the scan horizon
                }
            })
            .cloned()
            .collect()
    }
}

fn load_file(data_dir: &std::path::Path) -> CronFile {
    crate::ai::atomic_read_json(&data_dir.join("ai-cron.json"))
}

fn save_file(data_dir: &std::path::Path, state: &CronFile) {
    let path = data_dir.join("ai-cron.json");
    let _ = crate::ai::atomic_write_json(&path, state);
}

// ---------------------------------------------------------------------------
// Minimal 5-field cron matcher
// ---------------------------------------------------------------------------

/// A parsed 5-field cron expression: `minute hour day-of-month month
/// day-of-week`. Supports `*`, numbers, lists (`a,b`), ranges (`a-b`), and
/// steps (`*/n`, `a-b/n`, `a/n`), at minute granularity. Deliberately not a
/// full Vixie-cron: no names, no macros (`@daily`), no per-user semantics —
/// enough for "hourly health check" style AI tasks without pulling in a
/// cron crate.
#[derive(Clone, Debug)]
pub struct CronExpr {
    minutes: Vec<u32>,
    hours: Vec<u32>,
    doms: Vec<u32>,
    months: Vec<u32>,
    dows: Vec<u32>,
    /// Whether day-of-month was written as something other than `*` — needed
    /// for the standard "DOM or DOW when both are restricted" rule below.
    dom_restricted: bool,
    /// Whether day-of-week was written as something other than `*`.
    dow_restricted: bool,
}

/// Field bounds: (min, max) per position.
const FIELD_BOUNDS: [(u32, u32); 5] = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)];

impl CronExpr {
    /// Parse a 5-field expression. Errors carry the offending field.
    pub fn parse(expr: &str) -> Result<Self, String> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(format!(
                "expected 5 fields (min hour dom month dow), got {}",
                fields.len()
            ));
        }
        let names = ["minute", "hour", "day-of-month", "month", "day-of-week"];
        let mut sets: Vec<Vec<u32>> = Vec::with_capacity(5);
        let mut restricted = [false; 5];
        for (i, field) in fields.iter().enumerate() {
            let (lo, hi) = FIELD_BOUNDS[i];
            sets.push(parse_field(field, lo, hi).map_err(|e| format!("{} field: {e}", names[i]))?);
            restricted[i] = field.trim() != "*";
        }
        Ok(Self {
            minutes: sets.remove(0),
            hours: sets.remove(0),
            doms: sets.remove(0),
            months: sets.remove(0),
            dows: sets.remove(0),
            dom_restricted: restricted[2],
            dow_restricted: restricted[4],
        })
    }

    /// Does `t` (at minute granularity) match this expression? Day-of-month
    /// and day-of-week follow standard cron: when BOTH are restricted, either
    /// matching is enough; when only one is restricted, it must match.
    fn matches(&self, t: &k7s_deps::chrono::DateTime<k7s_deps::chrono::Utc>) -> bool {
        use k7s_deps::chrono::{Datelike, Timelike};
        if !self.minutes.contains(&t.minute()) || !self.hours.contains(&t.hour()) {
            return false;
        }
        if !self.months.contains(&t.month()) {
            return false;
        }
        // chrono: Sunday = 0 matches cron's weekday numbering.
        let dom_ok = self.doms.contains(&t.day());
        let dow_ok = self.dows.contains(&t.weekday().num_days_from_sunday());
        match (self.dom_restricted, self.dow_restricted) {
            (true, true) => dom_ok || dow_ok,
            (true, false) => dom_ok,
            (false, true) => dow_ok,
            (false, false) => true,
        }
    }

    /// The first matching minute strictly after `t`. Forward scan capped at
    /// 366 days (~527k minutes) so a never-matching expression (e.g.
    /// `0 0 31 2 *`) terminates and returns `None` instead of looping forever.
    pub fn next_after(
        &self,
        t: k7s_deps::chrono::DateTime<k7s_deps::chrono::Utc>,
    ) -> Option<k7s_deps::chrono::DateTime<k7s_deps::chrono::Utc>> {
        use k7s_deps::chrono::{Duration, Timelike};
        // Start at the next whole minute (truncate seconds/nanos, then +1min).
        // Truncation can only fail for impossible wall-times, which UTC has
        // none of — falling back to `t` keeps this panic-free regardless.
        let truncated = t
            .with_second(0)
            .and_then(|dt| dt.with_nanosecond(0))
            .unwrap_or(t);
        let mut candidate = truncated + Duration::minutes(1);
        let limit = t + Duration::days(366);
        while candidate <= limit {
            if self.matches(&candidate) {
                return Some(candidate);
            }
            candidate += Duration::minutes(1);
        }
        None
    }
}

/// Parse one cron field into the explicit set of values it matches.
fn parse_field(field: &str, lo: u32, hi: u32) -> Result<Vec<u32>, String> {
    let mut out = Vec::new();
    for part in field.split(',') {
        // Split `base/step`, remembering whether a step was given.
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => (
                r,
                s.parse::<u32>()
                    .map_err(|_| format!("bad step in '{part}'"))?,
            ),
            None => (part, 1),
        };
        if step == 0 {
            return Err(format!("step 0 in '{part}'"));
        }
        let (start, end) = if range == "*" {
            (lo, hi)
        } else if let Some((a, b)) = range.split_once('-') {
            let a: u32 = a
                .trim()
                .parse()
                .map_err(|_| format!("bad range in '{part}'"))?;
            let b: u32 = b
                .trim()
                .parse()
                .map_err(|_| format!("bad range in '{part}'"))?;
            (a, b)
        } else {
            // Single number; with a step (`a/n`) Vixie semantics run a..max.
            let a: u32 = range
                .trim()
                .parse()
                .map_err(|_| format!("bad value in '{part}'"))?;
            (a, if part.contains('/') { hi } else { a })
        };
        if start < lo || end > hi || start > end {
            return Err(format!("value out of range {lo}..={hi} in '{part}'"));
        }
        let mut v = start;
        while v <= end {
            out.push(v);
            v += step;
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Background scheduling loop
// ---------------------------------------------------------------------------

/// Headless [`agent::EventSink`] for scheduled runs: no UI, no approvals —
/// every pending write is DENIED (nobody is awake at 03:00 to click
/// approve, and auto-approving cluster mutations would be indefensible), so
/// write tools fail closed while read-only analysis runs unattended.
struct CronSink {
    outcome: k7s_deps::tokio::sync::Mutex<Option<Result<String, String>>>,
}

impl crate::ai::agent::EventSink for CronSink {
    fn emit(&self, ev: crate::ai::agent::AgentEvent) {
        match ev {
            crate::ai::agent::AgentEvent::Done { final_message, .. } => {
                if let Ok(mut slot) = self.outcome.try_lock() {
                    *slot = Some(Ok(final_message.unwrap_or_default()));
                }
            }
            crate::ai::agent::AgentEvent::Error { message } => {
                if let Ok(mut slot) = self.outcome.try_lock() {
                    *slot = Some(Err(message));
                }
            }
            _ => {}
        }
    }
    fn await_approval(&self, _call_id: &str) -> k7s_deps::tokio::sync::oneshot::Receiver<bool> {
        let (tx, rx) = k7s_deps::tokio::sync::oneshot::channel();
        let _ = tx.send(false); // deny — headless run, no human in the loop
        rx
    }
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// What a due task should do. Implemented by the desktop/web shells by
/// constructing an [`crate::ai::agent::AgentLoop`] from the saved AI config;
/// kept as a closure so k7s-core stays independent of config resolution.
pub type CronExecutor = std::sync::Arc<
    dyn Fn(
            CronTask,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

/// Spawn the background cron loop: every 60s, collect due tasks and run
/// them through `executor`, recording each outcome in the run history.
/// `last_run` is stamped BEFORE execution so a slow run isn't re-fired by
/// the next tick. Returns the JoinHandle (call `.abort()` to stop).
pub fn spawn_runner(
    data_dir: std::path::PathBuf,
    executor: CronExecutor,
) -> k7s_deps::tokio::task::JoinHandle<()> {
    k7s_deps::tokio::spawn(async move {
        let mut ticker = k7s_deps::tokio::time::interval(std::time::Duration::from_secs(60));
        // First tick fires immediately; that's fine — due_tasks anchors on
        // last_run, so nothing re-fires just because the process restarted.
        loop {
            ticker.tick().await;
            let scheduler = CronScheduler::new(data_dir.clone());
            for task in scheduler.due_tasks().await {
                k7s_deps::tracing::info!(task = %task.id, name = %task.name, "cron: firing task");
                // Stamp last_run now (without a result) so the next tick
                // doesn't double-fire a run that's still in flight.
                scheduler.mark_started(&task.id).await;
                let started = std::time::Instant::now();
                let result = executor(task.clone()).await;
                let success = result.is_ok();
                scheduler
                    .record_run(CronRunResult {
                        task_id: task.id.clone(),
                        timestamp: k7s_deps::chrono::Utc::now().to_rfc3339(),
                        success,
                        response: result.unwrap_or_else(|e| format!("error: {e}")),
                        duration_ms: started.elapsed().as_millis() as u64,
                    })
                    .await;
            }
        }
    })
}

/// Convenience executor built from the pieces every shell already has: an
/// LLM factory and the resolved permission mode. Runs the task's prompt
/// headlessly via [`CronSink`]. A fresh `ToolRegistry` + `AgentLoop` is
/// built per invocation (cheap; `ToolRegistry` is not `Clone`).
#[allow(clippy::too_many_arguments)]
pub fn headless_executor(
    llm_factory: std::sync::Arc<dyn Fn() -> Box<dyn crate::ai::llm::LlmClient> + Send + Sync>,
    mode: crate::ai::config::PermissionMode,
    max_turns: u32,
    manager: std::sync::Arc<crate::kube::manager::ClientManager>,
    data_dir: std::path::PathBuf,
) -> CronExecutor {
    std::sync::Arc::new(move |task: CronTask| {
        let llm_factory = llm_factory.clone();
        let manager = manager.clone();
        let data_dir = data_dir.clone();
        Box::pin(async move {
            let agent = crate::ai::agent::AgentLoop::new(
                crate::ai::tools::ToolRegistry::new(),
                llm_factory,
            );
            let sink = std::sync::Arc::new(CronSink {
                outcome: k7s_deps::tokio::sync::Mutex::new(None),
            });
            let req = crate::ai::agent::ChatRequest {
                message: task.prompt.clone(),
                history: Vec::new(),
                context: None,
                skill_id: task.skill_id.clone(),
                kube_context: None,
            };
            agent
                .run(req, mode, max_turns, manager, sink.clone(), data_dir, None)
                .await;
            let outcome = match sink.outcome.lock().await.take() {
                Some(Ok(text)) => Ok(text),
                Some(Err(e)) => Err(e),
                None => Err("agent run produced no terminal event".to_string()),
            };
            outcome
        })
    })
}

/// Boot helper for the shells: load the saved AI config, build the headless
/// executor, and spawn the background runner. If AI is disabled or no LLM
/// can be resolved (no key, no local Ollama), log once and skip — scheduled
/// tasks need a model to talk to.
///
/// `force_read_only` mirrors the web chat handler's safety downgrade: the
/// web shell never lets a saved FullAuto config drive unattended writes.
/// (Headless runs deny approvals regardless — see [`CronSink`].)
pub async fn spawn_configured_runner(
    data_dir: std::path::PathBuf,
    manager: std::sync::Arc<crate::kube::manager::ClientManager>,
    force_read_only: bool,
) {
    let view = match crate::ai::config::load(Some(&data_dir)) {
        Ok(v) => v,
        Err(e) => {
            k7s_deps::tracing::warn!("cron: could not load AI config: {e}");
            return;
        }
    };
    let cfg = view.config;
    if !cfg.enabled {
        k7s_deps::tracing::info!("cron: AI assistant disabled — scheduler not started");
        return;
    }
    let (base, model, key) = match crate::ai::config::resolve(&cfg, Some(&data_dir)) {
        Ok(t) => t,
        Err(_) => match crate::ai::embedded_models::discover_ollama(None).await {
            Some(models) if !models.is_empty() => (
                "http://localhost:11434/v1".to_string(),
                models[0].name.clone(),
                "ollama".to_string(),
            ),
            _ => {
                k7s_deps::tracing::info!(
                    "cron: no LLM configured (set an API key in Settings) — scheduler not started"
                );
                return;
            }
        },
    };
    let mode = if force_read_only {
        crate::ai::config::PermissionMode::ReadOnly
    } else {
        cfg.permission
    };
    let temperature = cfg.provider.temperature;
    let llm_factory: std::sync::Arc<dyn Fn() -> Box<dyn crate::ai::llm::LlmClient> + Send + Sync> =
        std::sync::Arc::new(move || {
            Box::new(crate::ai::llm::OpenAiClient::new(
                base.clone(),
                model.clone(),
                key.clone(),
                temperature,
            ))
        });
    let runner_dir = data_dir.clone();
    let executor = headless_executor(llm_factory, mode, cfg.max_turns, manager, data_dir);
    let _handle = spawn_runner(runner_dir, executor);
    k7s_deps::tracing::info!("cron: scheduler started (60s tick)");
}

/// Built-in scheduled task presets.
pub fn builtin_presets() -> Vec<CronTask> {
    vec![
        CronTask {
            id: "hourly-health".into(),
            name: "每小时集群健康检查".into(),
            cron_expr: "0 * * * *".into(),
            prompt: "Run a full cluster health check: check node status, pod status, resource pressure, and any recent warning events. Report problems concisely.".into(),
            enabled: false,
            skill_id: None,
            last_run: None,
            last_result: None,
            last_status: CronRunStatus::Never,
        },
        CronTask {
            id: "daily-audit".into(),
            name: "每日集群审计".into(),
            cron_expr: "0 9 * * *".into(),
            prompt: "Daily cluster audit: list all namespaces, check for pods in CrashLoopBackOff or ImagePullBackOff, check node resource usage, review recent events for warnings. Provide a summary report.".into(),
            enabled: false,
            skill_id: None,
            last_run: None,
            last_result: None,
            last_status: CronRunStatus::Never,
        },
        CronTask {
            id: "resource-pressure".into(),
            name: "资源压力监控".into(),
            cron_expr: "*/30 * * * *".into(),
            prompt: "Check resource pressure: which nodes are approaching CPU/memory capacity? Which namespaces are the biggest consumers? Any pods without resource limits?".into(),
            enabled: false,
            skill_id: Some("resource-pressure".into()),
            last_run: None,
            last_result: None,
            last_status: CronRunStatus::Never,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(s: &str) -> k7s_deps::chrono::DateTime<k7s_deps::chrono::Utc> {
        // 2026-08-27 is a Thursday.
        k7s_deps::chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
            .unwrap()
            .and_utc()
    }

    /// `0 9 * * *` fires at 09:00 and only at 09:00 — the daily-audit preset.
    #[test]
    fn daily_at_nine() {
        let e = CronExpr::parse("0 9 * * *").unwrap();
        assert_eq!(
            e.next_after(dt("2026-08-27 08:59:00")).unwrap(),
            dt("2026-08-27 09:00:00")
        );
        // A task that ran exactly at 09:00 isn't due again until tomorrow.
        assert_eq!(
            e.next_after(dt("2026-08-27 09:00:00")).unwrap(),
            dt("2026-08-28 09:00:00")
        );
        // Later the same day: still tomorrow.
        assert_eq!(
            e.next_after(dt("2026-08-27 23:30:00")).unwrap(),
            dt("2026-08-28 09:00:00")
        );
    }

    /// Steps (`*/30`), lists (`9,17`) and ranges (`9-17`).
    #[test]
    fn steps_lists_ranges() {
        let e = CronExpr::parse("*/30 * * * *").unwrap();
        assert_eq!(
            e.next_after(dt("2026-08-27 10:00:00")).unwrap(),
            dt("2026-08-27 10:30:00")
        );
        assert_eq!(
            e.next_after(dt("2026-08-27 10:31:00")).unwrap(),
            dt("2026-08-27 11:00:00")
        );

        let e = CronExpr::parse("0 9,17 * * *").unwrap();
        assert_eq!(
            e.next_after(dt("2026-08-27 10:00:00")).unwrap(),
            dt("2026-08-27 17:00:00")
        );
        assert_eq!(
            e.next_after(dt("2026-08-27 17:00:00")).unwrap(),
            dt("2026-08-28 09:00:00")
        );

        let e = CronExpr::parse("0 9-11 * * *").unwrap();
        assert_eq!(
            e.next_after(dt("2026-08-27 09:30:00")).unwrap(),
            dt("2026-08-27 10:00:00")
        );
        assert_eq!(
            e.next_after(dt("2026-08-27 11:30:00")).unwrap(),
            dt("2026-08-28 09:00:00")
        );
    }

    /// Day-of-week: `0 9 * * 1` = Mondays at 09:00 (2026-08-27 is Thursday).
    #[test]
    fn weekday_matching() {
        let e = CronExpr::parse("0 9 * * 1").unwrap();
        // After Thursday 2026-08-27 10:00 → Monday 2026-08-31 09:00.
        assert_eq!(
            e.next_after(dt("2026-08-27 10:00:00")).unwrap(),
            dt("2026-08-31 09:00:00")
        );
        // Sunday field value 0 works: `* * * * 0` next hits Sunday 2026-08-30.
        let e = CronExpr::parse("0 9 * * 0").unwrap();
        assert_eq!(
            e.next_after(dt("2026-08-27 10:00:00")).unwrap(),
            dt("2026-08-30 09:00:00")
        );
    }

    /// Month rollover: `0 9 1 1 *` only matches Jan 1st — from mid-August the
    /// next hit is next year.
    #[test]
    fn month_and_dom_rollover() {
        let e = CronExpr::parse("0 9 1 1 *").unwrap();
        assert_eq!(
            e.next_after(dt("2026-08-27 10:00:00")).unwrap(),
            dt("2027-01-01 09:00:00")
        );
    }

    /// Feb 30 never exists → the 366-day scan horizon gives up with None
    /// instead of looping forever.
    #[test]
    fn impossible_expression_returns_none() {
        let e = CronExpr::parse("0 0 30 2 *").unwrap();
        assert!(e.next_after(dt("2026-08-27 10:00:00")).is_none());
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(CronExpr::parse("not a cron").is_err());
        assert!(CronExpr::parse("0 9 * *").is_err()); // 4 fields
        assert!(CronExpr::parse("60 * * * *").is_err()); // minute out of range
        assert!(CronExpr::parse("* 24 * * *").is_err()); // hour out of range
        assert!(CronExpr::parse("*/0 * * * *").is_err()); // zero step
        assert!(CronExpr::parse("5-1 * * * *").is_err()); // inverted range
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "k7s-ai-test-cron-{tag}-{}",
            k7s_deps::uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// End-to-end through the store: a `0 9 * * *` task that "just ran" at
    /// 09:00 today is not due; one whose last_run was before today 09:00 is.
    #[k7s_deps::tokio::test]
    async fn due_tasks_follow_cron_and_last_run() {
        let dir = temp_dir("due");
        let sched = CronScheduler::new(dir.clone());
        let now = k7s_deps::chrono::Utc::now();

        let mut ran_recently = builtin_presets()[1].clone(); // "0 9 * * *"
        ran_recently.enabled = true;
        ran_recently.last_run = Some(now.to_rfc3339()); // ran "now"

        let mut ran_yesterday = ran_recently.clone();
        ran_yesterday.id = "daily-audit-2".into();
        // Backdate 25h: the next 9:00 after that is <= now → due.
        ran_yesterday.last_run = Some((now - k7s_deps::chrono::Duration::hours(25)).to_rfc3339());

        let never_ran = {
            let mut t = builtin_presets()[0].clone(); // "0 * * * *"
            t.enabled = true;
            t.last_run = None;
            t
        };

        sched.add(ran_recently).await;
        sched.add(ran_yesterday).await;
        sched.add(never_ran).await;

        let due = sched.due_tasks().await;
        let ids: Vec<&str> = due.iter().map(|t| t.id.as_str()).collect();
        assert!(
            !ids.contains(&"daily-audit"),
            "just-ran task must not be due"
        );
        assert!(ids.contains(&"daily-audit-2"), "backdated task must be due");
        assert!(ids.contains(&"hourly-health"), "never-run task must be due");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two schedulers over the same data_dir share state: a task added via
    /// one is visible (and due) via the other — the lost-update guard.
    #[k7s_deps::tokio::test]
    async fn schedulers_share_state_per_data_dir() {
        let dir = temp_dir("shared");
        let a = CronScheduler::new(dir.clone());
        let b = CronScheduler::new(dir.clone());

        let mut task = builtin_presets()[0].clone();
        task.enabled = true;
        task.last_run = None;
        a.add(task).await;

        assert_eq!(b.list().await.len(), 1);
        assert_eq!(b.due_tasks().await.len(), 1);
        // Delete via b is visible via a.
        assert!(b.delete("hourly-health").await);
        assert!(a.list().await.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
