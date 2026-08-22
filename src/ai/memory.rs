//! Four-tier memory system, inspired by openocta's "四级记忆 + 自主进化".
//!
//! Tiers (from most ephemeral to most permanent):
//!
//! 1. **Session memory** — the current conversation (lives in `agent.rs`'s
//!    `messages` Vec, never persisted).
//! 2. **Short-term memory** — recent conversation summaries, auto-extracted by
//!    the agent after each run. Decays after a configurable TTL (default 7 days).
//! 3. **Long-term memory** — important facts promoted from short-term (either
//!    manually by the user, or auto-promoted when referenced ≥ N times).
//!    Persists indefinitely.
//! 4. **Knowledge Vault** — structured cluster knowledge: runbooks, past
//!    diagnoses, user preferences, cluster documentation. Indexed for
//!    retrieval by keyword/tag.
//!
//! All tiers are scoped to a kubeconfig context and stored under
//! `<data_dir>/ai-memory/<context>/`. The agent loop injects relevant memories
//! from tiers 2–4 into the system prompt each run.
//!
//! Auto-promotion: when a short-term memory is referenced (matched in a search
//! or included in the context block) ≥ 3 times, it's promoted to long-term.
//! Decay: short-term memories older than `ttl_days` are pruned on load.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Memory tier — determines storage, retrieval priority, and lifetime.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Recent conversation summaries. Decays after TTL.
    ShortTerm,
    /// Important facts. Persists indefinitely.
    LongTerm,
    /// Structured knowledge (runbooks, preferences, cluster docs).
    KnowledgeVault,
}

/// A single memory entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryEntry {
    pub id: String,
    pub tier: Tier,
    pub created_at: String,
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub source: MemorySource,
    /// How many times this memory has been referenced (used for auto-promotion).
    #[serde(default)]
    pub reference_count: u32,
    /// Auto-promotion threshold. When `reference_count >= promote_at` and tier
    /// is ShortTerm, it's moved to LongTerm.
    #[serde(default = "default_promote_at")]
    pub promote_at: u32,
}

fn default_promote_at() -> u32 {
    3
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MemorySource {
    User,
    Ai,
}

/// The persisted memory file for one kubeconfig context.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct MemoryFile {
    context: String,
    entries: Vec<MemoryEntry>,
    /// User preferences extracted from conversations.
    #[serde(default)]
    preferences: Vec<UserPreference>,
}

/// A learned user preference (e.g. "user prefers kubectl over helm for simple
/// deploys", "user's production namespace is 'prod'", "user likes concise
/// answers with bullet points").
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPreference {
    pub key: String,
    pub value: String,
    pub learned_at: String,
    #[serde(default)]
    pub confidence: f32, // 0.0–1.0, increases with repeated observation
}

/// Public API: load/save/query memories for the current context.
pub struct MemoryStore {
    dir: PathBuf,
    #[allow(dead_code)]
    context: String,
    data: MemoryFile,
    #[allow(dead_code)]
    ttl_days: u64,
}

impl MemoryStore {
    /// Open (or create) the memory store for a given kubeconfig context.
    pub fn open(data_dir: &std::path::Path, context: &str) -> Self {
        let dir = data_dir.join("ai-memory").join(safe_name(context));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("memory.json");
        let mut data: MemoryFile = crate::ai::atomic_read_json(&path);
        data.context = context.to_string();
        // Prune expired short-term memories.
        let ttl_days = 7;
        let cutoff =
            k7s_deps::chrono::Utc::now() - k7s_deps::chrono::Duration::days(ttl_days as i64);
        data.entries.retain(|e| {
            e.tier != Tier::ShortTerm
                || k7s_deps::chrono::DateTime::parse_from_rfc3339(&e.created_at)
                    .map(|dt| dt.with_timezone(&k7s_deps::chrono::Utc) > cutoff)
                    .unwrap_or(true)
        });
        Self {
            dir,
            context: context.to_string(),
            data,
            ttl_days,
        }
    }

    /// Add a memory to a specific tier.
    pub fn add(&mut self, tier: Tier, content: &str, tags: Vec<String>, source: MemorySource) {
        self.data.entries.push(MemoryEntry {
            id: k7s_deps::uuid::Uuid::new_v4().to_string(),
            tier,
            created_at: k7s_deps::chrono::Utc::now().to_rfc3339(),
            content: content.to_string(),
            tags,
            source,
            reference_count: 0,
            promote_at: 3,
        });
        self.save();
    }

    /// List all memories, optionally filtered by tier.
    pub fn list(&self, tier: Option<Tier>) -> Vec<&MemoryEntry> {
        self.data
            .entries
            .iter()
            .rev()
            .filter(|e| tier.map_or(true, |t| e.tier == t))
            .collect()
    }

    /// Search memories by keyword (case-insensitive on content + tags).
    /// Increments `reference_count` on matches (for auto-promotion).
    pub fn search(&mut self, query: &str) -> Vec<MemoryEntry> {
        let q = query.to_lowercase();
        let mut results = Vec::new();
        for entry in &mut self.data.entries {
            if entry.content.to_lowercase().contains(&q)
                || entry.tags.iter().any(|t| t.to_lowercase().contains(&q))
            {
                entry.reference_count += 1;
                // Auto-promote short-term → long-term if threshold reached.
                if entry.tier == Tier::ShortTerm && entry.reference_count >= entry.promote_at {
                    entry.tier = Tier::LongTerm;
                }
                results.push(entry.clone());
            }
        }
        self.save();
        results
    }

    /// Delete a memory by id.
    pub fn delete(&mut self, id: &str) -> bool {
        let before = self.data.entries.len();
        self.data.entries.retain(|m| m.id != id);
        if self.data.entries.len() < before {
            self.save();
            true
        } else {
            false
        }
    }

    /// Clear all memories in a tier (or all tiers).
    pub fn clear(&mut self, tier: Option<Tier>) {
        match tier {
            Some(t) => self.data.entries.retain(|e| e.tier != t),
            None => self.data.entries.clear(),
        }
        self.save();
    }

    // -- Knowledge Vault specific --

    /// Add a runbook entry to the Knowledge Vault.
    pub fn add_runbook(&mut self, title: &str, content: &str, tags: Vec<String>) {
        self.add(
            Tier::KnowledgeVault,
            &format!("[Runbook: {title}] {content}"),
            tags,
            MemorySource::User,
        );
    }

    /// Search the Knowledge Vault specifically.
    pub fn search_vault(&mut self, query: &str) -> Vec<MemoryEntry> {
        let q = query.to_lowercase();
        let mut results = Vec::new();
        for entry in &mut self.data.entries {
            if entry.tier == Tier::KnowledgeVault
                && (entry.content.to_lowercase().contains(&q)
                    || entry.tags.iter().any(|t| t.to_lowercase().contains(&q)))
            {
                entry.reference_count += 1;
                results.push(entry.clone());
            }
        }
        self.save();
        results
    }

    // -- User Preferences --

    /// Learn or reinforce a user preference.
    pub fn learn_preference(&mut self, key: &str, value: &str) {
        if let Some(pref) = self.data.preferences.iter_mut().find(|p| p.key == key) {
            if pref.value == value {
                pref.confidence = (pref.confidence + 0.1).min(1.0);
            } else {
                pref.value = value.to_string();
                pref.confidence = 0.5; // conflicting observation
            }
        } else {
            self.data.preferences.push(UserPreference {
                key: key.to_string(),
                value: value.to_string(),
                learned_at: k7s_deps::chrono::Utc::now().to_rfc3339(),
                confidence: 0.6,
            });
        }
        self.save();
    }

    /// Get all learned preferences.
    pub fn preferences(&self) -> &[UserPreference] {
        &self.data.preferences
    }

    // -- Context injection --

    /// Build the memory context block for the system prompt.
    /// Includes: short-term summaries, long-term facts, knowledge vault hits,
    /// and user preferences. Ordered by relevance (tier priority).
    pub fn to_context_block(&self, max_entries: usize) -> String {
        let mut lines: Vec<String> = Vec::new();

        // User preferences first (highest signal).
        if !self.data.preferences.is_empty() {
            lines.push("[User Preferences]".to_string());
            for pref in &self.data.preferences {
                if pref.confidence > 0.3 {
                    lines.push(format!(
                        "- {}: {} (confidence: {:.0}%)",
                        pref.key,
                        pref.value,
                        pref.confidence * 100.0
                    ));
                }
            }
        }

        // Knowledge vault entries.
        let vault: Vec<_> = self
            .data
            .entries
            .iter()
            .filter(|e| e.tier == Tier::KnowledgeVault)
            .rev()
            .take(max_entries / 3)
            .collect();
        if !vault.is_empty() {
            lines.push("[Knowledge Vault]".to_string());
            for entry in vault {
                lines.push(format!("- {}", entry.content));
            }
        }

        // Long-term memories.
        let long_term: Vec<_> = self
            .data
            .entries
            .iter()
            .filter(|e| e.tier == Tier::LongTerm)
            .rev()
            .take(max_entries / 3)
            .collect();
        if !long_term.is_empty() {
            lines.push("[Long-term Memory]".to_string());
            for entry in long_term {
                let date = &entry.created_at[..10];
                lines.push(format!("- {date}: {}", entry.content));
            }
        }

        // Short-term memories.
        let short_term: Vec<_> = self
            .data
            .entries
            .iter()
            .filter(|e| e.tier == Tier::ShortTerm)
            .rev()
            .take(max_entries / 3)
            .collect();
        if !short_term.is_empty() {
            lines.push("[Recent Memory]".to_string());
            for entry in short_term {
                let date = &entry.created_at[..10];
                lines.push(format!("- {date}: {}", entry.content));
            }
        }

        if lines.is_empty() {
            String::new()
        } else {
            lines.join("\n")
        }
    }

    /// Auto-extract a summary from a conversation and store as short-term memory.
    /// Called by the agent loop after each run.
    pub fn auto_summarize(
        &mut self,
        user_message: &str,
        assistant_response: &str,
        tool_calls: &[String],
    ) {
        // Only summarize non-trivial conversations (those with tool calls or
        // substantial assistant responses).
        if tool_calls.is_empty() && assistant_response.len() < 100 {
            return;
        }
        let summary = if !tool_calls.is_empty() {
            format!(
                "User asked: \"{}\" → AI used tools [{}] and responded: \"{}\"",
                truncate(user_message, 80),
                tool_calls.join(", "),
                truncate(assistant_response, 120)
            )
        } else {
            format!(
                "User asked: \"{}\" → AI responded: \"{}\"",
                truncate(user_message, 80),
                truncate(assistant_response, 120)
            )
        };
        self.add(Tier::ShortTerm, &summary, vec![], MemorySource::Ai);
    }

    fn save(&self) {
        let path = self.dir.join("memory.json");
        let _ = crate::ai::atomic_write_json(&path, &self.data);
    }
}

fn safe_name(context: &str) -> String {
    context.replace(['/', ':'], "_")
}

fn truncate(s: &str, max_chars: usize) -> String {
    let truncated: String = s.chars().take(max_chars).collect();
    if s.chars().count() > max_chars {
        format!("{truncated}…")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(context: &str) -> MemoryStore {
        let dir = std::env::temp_dir().join(format!("k7s-ai-test-memory-{context}"));
        let _ = std::fs::remove_dir_all(&dir);
        MemoryStore::open(&dir, context)
    }

    #[test]
    fn four_tier_round_trip() {
        let mut store = temp_store("test-4tier");

        // Add to each tier.
        store.add(
            Tier::ShortTerm,
            "recent crash in payment pod",
            vec!["crash".into()],
            MemorySource::Ai,
        );
        store.add(
            Tier::LongTerm,
            "production frontend uses image v2.3.1",
            vec!["frontend".into()],
            MemorySource::User,
        );
        store.add(
            Tier::KnowledgeVault,
            "[Runbook: OOM] Increase memory limit to 256Mi",
            vec!["oom".into()],
            MemorySource::User,
        );

        assert_eq!(store.list(Some(Tier::ShortTerm)).len(), 1);
        assert_eq!(store.list(Some(Tier::LongTerm)).len(), 1);
        assert_eq!(store.list(Some(Tier::KnowledgeVault)).len(), 1);
        assert_eq!(store.list(None).len(), 3);

        // Search crosses all tiers.
        let results = store.search("OOM");
        assert!(results.len() >= 1);
    }

    #[test]
    fn auto_promotion_on_reference() {
        let mut store = temp_store("test-promote");
        store.add(
            Tier::ShortTerm,
            "frequently referenced fact",
            vec![],
            MemorySource::Ai,
        );

        // Search 3 times to trigger auto-promotion.
        for _ in 0..3 {
            store.search("frequently referenced");
        }

        let entry = store.list(None)[0];
        assert_eq!(
            entry.tier,
            Tier::LongTerm,
            "should be promoted to long-term"
        );
    }

    #[test]
    fn user_preferences() {
        let mut store = temp_store("test-prefs");
        store.learn_preference("answer_style", "concise bullet points");
        store.learn_preference("answer_style", "concise bullet points"); // reinforce
        store.learn_preference("production_namespace", "prod");

        let prefs = store.preferences();
        assert_eq!(prefs.len(), 2);
        let style = prefs.iter().find(|p| p.key == "answer_style").unwrap();
        assert!(
            style.confidence > 0.6,
            "reinforced preference should have high confidence"
        );
    }

    #[test]
    fn context_block_includes_all_tiers() {
        let mut store = temp_store("test-ctx");
        store.add(Tier::ShortTerm, "recent event", vec![], MemorySource::Ai);
        store.add(Tier::LongTerm, "important fact", vec![], MemorySource::User);
        store.add_runbook("OOM Fix", "increase memory limit", vec!["oom".into()]);
        store.learn_preference("style", "concise");

        let block = store.to_context_block(20);
        assert!(block.contains("[User Preferences]"));
        assert!(block.contains("[Knowledge Vault]"));
        assert!(block.contains("[Long-term Memory]"));
        assert!(block.contains("[Recent Memory]"));
    }

    #[test]
    fn auto_summarize_ignores_trivial() {
        let mut store = temp_store("test-summarize");
        // Trivial conversation (no tool calls, short response).
        store.auto_summarize("hi", "hello", &[]);
        assert_eq!(
            store.list(None).len(),
            0,
            "trivial conversations should not be stored"
        );

        // Non-trivial (has tool calls).
        store.auto_summarize("list pods", "here are the pods", &["list_resources".into()]);
        assert_eq!(store.list(None).len(), 1);
    }

    #[test]
    fn knowledge_vault_runbook() {
        let mut store = temp_store("test-vault");
        store.add_runbook(
            "CrashLoopBackOff",
            "1. Check events\n2. Check previous logs\n3. Fix resource limits",
            vec!["crashloop".into()],
        );

        let results = store.search_vault("CrashLoop");
        assert_eq!(results.len(), 1);
        assert!(results[0].content.contains("Runbook"));
    }
}
