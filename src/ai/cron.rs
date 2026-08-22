//! Scheduled AI tasks — periodic health checks, alert analysis, etc.
//!
//! Inspired by openocta's cron module (`src/pkg/cron/`). Users define
//! recurring tasks with a cron expression and a prompt; the scheduler runs
//! them through the AI agent loop at the specified interval and stores the
//! results.
//!
//! Tasks are persisted as JSON under `<data_dir>/ai-cron.json`. The scheduler
//! runs as a background tokio task managed by [`CronScheduler`].

use k7s_deps::tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
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
    data_dir: std::path::PathBuf,
    state: Arc<Mutex<CronFile>>,
}

impl CronScheduler {
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        let state = load_file(&data_dir);
        Self {
            data_dir,
            state: Arc::new(Mutex::new(state)),
        }
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

    /// Get the next tasks due to run (based on current time vs cron expression).
    /// This is a simplified check — a production scheduler would use a proper
    /// cron parser. For now, we check if enough time has elapsed since last_run.
    pub async fn due_tasks(&self) -> Vec<CronTask> {
        let state = self.state.lock().await;
        let now = k7s_deps::chrono::Utc::now();
        state
            .tasks
            .iter()
            .filter(|t| t.enabled)
            .filter(|t| {
                // Simple interval check: if last_run is older than the cron interval.
                match &t.last_run {
                    None => true, // never run
                    Some(last) => {
                        k7s_deps::chrono::DateTime::parse_from_rfc3339(last)
                            .map(|dt| {
                                let elapsed = now - dt.with_timezone(&k7s_deps::chrono::Utc);
                                // Default: run if more than 1 hour has elapsed.
                                elapsed > k7s_deps::chrono::Duration::hours(1)
                            })
                            .unwrap_or(true)
                    }
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
