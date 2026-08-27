//! Explicit session management — inspired by openocta's `session` package.
//!
//! A "session" is a named, persistent conversation with its own history,
//! active skill, and metadata. Sessions survive app restarts (persisted as
//! JSON). The user can switch between sessions, rename them, and export them.
//!
//! The session manager also handles the auto-reply queue: when multiple
//! messages arrive (e.g., from IM channels), they're queued and processed
//! serially to prevent race conditions.

use k7s_deps::tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

/// A persistent conversation session.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    /// The conversation history for this session.
    pub history: Vec<SessionMessage>,
    /// Active skill for this session.
    #[serde(default)]
    pub active_skill_id: Option<String>,
    /// Kubeconfig context this session is bound to.
    #[serde(default)]
    pub kube_context: Option<String>,
    /// Tags for organization.
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMessage {
    pub role: String,
    pub content: String,
    pub timestamp: String,
}

/// Process-wide registry of per-data_dir session states.
///
/// `SessionManager::new` is cheap and called all over the codebase (every
/// chat turn constructs one). If each instance kept its own copy of the
/// sessions, two live instances would load → mutate → full-save separately
/// and the last save would silently wipe the other's writes. Sharing the
/// in-memory state per data_dir (first instance loads from disk, everyone
/// else reuses it) makes every mutation + save globally serialized.
static SESSION_STATES: std::sync::OnceLock<
    std::sync::Mutex<HashMap<PathBuf, Arc<Mutex<Vec<Session>>>>>,
> = std::sync::OnceLock::new();

fn shared_sessions(data_dir: &PathBuf) -> Arc<Mutex<Vec<Session>>> {
    let registry = SESSION_STATES.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    // Short critical section on the std Mutex — just the map lookup/insert;
    // the async lock on the sessions themselves is taken per operation.
    let mut map = registry.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(data_dir.clone())
        .or_insert_with(|| Arc::new(Mutex::new(load_sessions(data_dir))))
        .clone()
}

/// The session manager — owns all sessions and the auto-reply queue.
pub struct SessionManager {
    data_dir: PathBuf,
    sessions: Arc<Mutex<Vec<Session>>>,
    reply_queue: Arc<Mutex<VecDeque<QueuedMessage>>>,
}

#[derive(Clone, Debug)]
pub struct QueuedMessage {
    pub session_id: String,
    pub message: String,
    pub source: String,
    pub enqueued_at: k7s_deps::chrono::DateTime<k7s_deps::chrono::Utc>,
}

impl SessionManager {
    pub fn new(data_dir: PathBuf) -> Self {
        // Shares the process-wide state for this data_dir (loaded from disk
        // only by the first instance — see `SESSION_STATES`).
        let sessions = shared_sessions(&data_dir);
        Self {
            data_dir,
            sessions,
            reply_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub async fn list(&self) -> Vec<Session> {
        self.sessions.lock().await.clone()
    }

    pub async fn get(&self, id: &str) -> Option<Session> {
        self.sessions
            .lock()
            .await
            .iter()
            .find(|s| s.id == id)
            .cloned()
    }

    pub async fn create(&self, name: &str, kube_context: Option<String>) -> Session {
        let session = Session {
            id: k7s_deps::uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            created_at: k7s_deps::chrono::Utc::now().to_rfc3339(),
            updated_at: k7s_deps::chrono::Utc::now().to_rfc3339(),
            history: Vec::new(),
            active_skill_id: None,
            kube_context,
            tags: Vec::new(),
        };
        let mut sessions = self.sessions.lock().await;
        sessions.push(session.clone());
        save_sessions(&self.data_dir, &sessions);
        session
    }

    pub async fn add_message(&self, session_id: &str, role: &str, content: &str) {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.iter_mut().find(|s| s.id == session_id) {
            session.history.push(SessionMessage {
                role: role.to_string(),
                content: content.to_string(),
                timestamp: k7s_deps::chrono::Utc::now().to_rfc3339(),
            });
            session.updated_at = k7s_deps::chrono::Utc::now().to_rfc3339();
            save_sessions(&self.data_dir, &sessions);
        }
    }

    pub async fn delete(&self, id: &str) -> bool {
        let mut sessions = self.sessions.lock().await;
        let before = sessions.len();
        sessions.retain(|s| s.id != id);
        if sessions.len() < before {
            save_sessions(&self.data_dir, &sessions);
            true
        } else {
            false
        }
    }

    // -- Auto-reply queue --

    pub async fn enqueue(&self, session_id: &str, message: &str, source: &str) {
        let mut queue = self.reply_queue.lock().await;
        queue.push_back(QueuedMessage {
            session_id: session_id.to_string(),
            message: message.to_string(),
            source: source.to_string(),
            enqueued_at: k7s_deps::chrono::Utc::now(),
        });
    }

    pub async fn dequeue(&self) -> Option<QueuedMessage> {
        self.reply_queue.lock().await.pop_front()
    }

    pub async fn queue_size(&self) -> usize {
        self.reply_queue.lock().await.len()
    }
}

fn load_sessions(data_dir: &std::path::Path) -> Vec<Session> {
    crate::ai::atomic_read_json(&data_dir.join("ai-sessions.json"))
}

fn save_sessions(data_dir: &std::path::Path, sessions: &[Session]) {
    let path = data_dir.join("ai-sessions.json");
    let _ = crate::ai::atomic_write_json(&path, sessions);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        // Unique per tag AND per run: the shared registry is process-global,
        // so a rerun must not observe state left by a previous test process
        // against the same (now deleted) directory.
        let dir = std::env::temp_dir().join(format!(
            "k7s-ai-test-session-{tag}-{}",
            k7s_deps::uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Two managers over the same data_dir are one logical store: messages
    /// written through either instance must all survive. Before the shared
    /// registry, each instance kept its own copy and the last full-file save
    /// silently wiped the other's writes.
    #[k7s_deps::tokio::test]
    async fn concurrent_managers_do_not_lose_updates() {
        let dir = temp_dir("concurrent");
        let mgr_a = SessionManager::new(dir.clone());
        let mgr_b = SessionManager::new(dir.clone());

        let session = mgr_a.create("shared", None).await;
        let sid = session.id;

        // Alternate writers through the two instances — the exact interleaving
        // that used to lose writes.
        for i in 0..20 {
            let (m, role) = if i % 2 == 0 {
                (&mgr_a, "user")
            } else {
                (&mgr_b, "assistant")
            };
            m.add_message(&sid, role, &format!("message {i}")).await;
        }

        // Both instances (and a fresh third one reading from disk) see all 20.
        for mgr in [&mgr_a, &mgr_b] {
            let got = mgr.get(&sid).await.expect("session visible via both");
            assert_eq!(got.history.len(), 20, "no message may be lost");
        }
        let mgr_c = SessionManager::new(dir.clone());
        let got = mgr_c.get(&sid).await.expect("persisted session readable");
        assert_eq!(got.history.len(), 20);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A session created through one instance is immediately visible through
    /// another (shared memory, not load-once-per-instance snapshots).
    #[k7s_deps::tokio::test]
    async fn create_visible_across_instances() {
        let dir = temp_dir("visible");
        let mgr_a = SessionManager::new(dir.clone());
        let mgr_b = SessionManager::new(dir.clone());

        let s = mgr_a.create("made-by-a", None).await;
        assert!(mgr_b.get(&s.id).await.is_some());
        assert!(mgr_b.delete(&s.id).await);
        assert!(mgr_a.get(&s.id).await.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
