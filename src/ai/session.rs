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
use std::collections::VecDeque;
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
        let sessions = load_sessions(&data_dir);
        Self {
            data_dir,
            sessions: Arc::new(Mutex::new(sessions)),
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
