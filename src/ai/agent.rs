//! The agent loop — the ReAct cycle that ties LLM ↔ tools ↔ user together.
//!
//! Each call to [`AgentLoop::run`] is one user message. The loop:
//!
//! 1. Builds the message list (system prompt + history + selected-resource
//!    context + the new user message).
//! 2. Asks the LLM for a streaming completion.
//! 3. As text deltas arrive, forwards them to the caller via [`EventSink::text`].
//! 4. When the LLM emits `tool_calls`, dispatches each through the
//!    [`ToolRegistry`]. Write tools route through the [`PermissionGate`]; a
//!    `NeedsApproval` decision pauses and calls [`EventSink::request_approval`],
//!    then awaits the user's response.
//! 5. Tool results become `tool` messages appended to history.
//! 6. Repeat from step 2 until the LLM returns text with no tool calls, the
//!    turn cap is hit, or the run is cancelled.
//!
//! The loop is transport-agnostic: it talks to the outside world only through
//! the [`EventSink`] trait object. The Tauri command and the HTTP handler each
//! provide an implementation.

use crate::ai::config::PermissionMode;
use crate::ai::context::{self, SelectedContext};
use crate::ai::error::{AiError, AiResult};
use crate::ai::llm::{LlmClient, Message, OutgoingToolCall, StreamEvent};
use crate::ai::permission::{self, Decision};
use crate::ai::tools::{ToolContext, ToolRegistry};
use crate::kube::manager::ClientManager;
use k7s_deps::futures::StreamExt;
use k7s_deps::tokio::sync::oneshot;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The conversation turn the UI sends to start a chat.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatRequest {
    /// The user's new message.
    pub message: String,
    /// The full prior conversation (so the loop is stateless across calls).
    /// Empty for a fresh chat.
    #[serde(default)]
    pub history: Vec<Message>,
    /// Optional: the resource the user currently has focused in the UI.
    #[serde(default)]
    pub context: Option<SelectedContext>,
    /// Optional: run with a specific skill active (injects skill prompt +
    /// filters tools to whitelist). `None` = normal mode.
    #[serde(default)]
    pub skill_id: Option<String>,
    /// Optional: kubeconfig context name (used to scope memory).
    /// If not provided, memory is not loaded.
    #[serde(default)]
    pub kube_context: Option<String>,
}

/// What the loop tells the outside world as it runs. Transport-agnostic — the
/// Tauri command emits these as Tauri events; the web handler writes them as
/// SSE frames.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AgentEvent {
    /// Incremental assistant text (content field from the LLM).
    #[serde(rename_all = "camelCase")]
    TextDelta { text: String },
    /// Incremental reasoning text (reasoning_content from reasoning models
    /// like MiMo, DeepSeek R1). Displayed as a collapsible thinking block.
    #[serde(rename_all = "camelCase")]
    ReasoningDelta { text: String },
    /// Context that was injected into the system prompt before the run.
    /// Lets the user see exactly what the AI "knows".
    #[serde(rename_all = "camelCase")]
    ContextInjected {
        /// "memory" | "skill" | "evolution" | "sandbox" | "preferences"
        block_type: String,
        /// Short summary of what was injected.
        summary: String,
    },
    /// The assistant wants to call a tool; shown in the UI as a card.
    #[serde(rename_all = "camelCase")]
    ToolCall {
        call_id: String,
        name: String,
        arguments: k7s_deps::serde_json::Value,
        is_write: bool,
    },
    /// A write tool is awaiting user approval.
    #[serde(rename_all = "camelCase")]
    PendingApproval {
        call_id: String,
        name: String,
        arguments: k7s_deps::serde_json::Value,
        summary: String,
    },
    /// A tool finished; include its result (success or error) for the card.
    #[serde(rename_all = "camelCase")]
    ToolResult {
        call_id: String,
        ok: bool,
        result: k7s_deps::serde_json::Value,
    },
    /// The run completed. `final_message` is the assistant's last text (if any).
    #[serde(rename_all = "camelCase")]
    Done {
        final_message: Option<String>,
        /// Updated history including this turn — the UI stores this back and
        /// sends it as `history` next turn.
        history: Vec<Message>,
    },
    /// The run failed terminally (LLM down, etc.).
    #[serde(rename_all = "camelCase")]
    Error { message: String },
}

/// How the loop talks back to the caller.
///
/// `emit` pushes an [`AgentEvent`]. `await_approval` blocks until the user
/// responds to a `pending_approval` and returns whether they accepted. It MUST
/// register the approval channel before returning, so that an approval that
/// arrives immediately after the `pending_approval` event can't race past the
/// registration (which would drop the response and hang the loop).
pub trait EventSink: Send + Sync {
    fn emit(&self, ev: AgentEvent);
    /// Block until the user decides on a pending write tool. Returns `true` if
    /// approved. The implementation is responsible for registering the
    /// resolution channel synchronously (before the returned future resolves),
    /// not via a spawned task.
    fn await_approval(&self, call_id: &str) -> oneshot::Receiver<bool>;
    /// Was the run cancelled? Polled between steps.
    fn is_cancelled(&self) -> bool;
}

/// Owns the registry + a way to build an LLM client. One per app, cheap to clone.
pub struct AgentLoop {
    registry: Arc<ToolRegistry>,
    llm_factory: Arc<dyn Fn() -> Box<dyn LlmClient> + Send + Sync>,
}

impl AgentLoop {
    pub fn new(
        registry: ToolRegistry,
        llm_factory: Arc<dyn Fn() -> Box<dyn LlmClient> + Send + Sync>,
    ) -> Self {
        Self {
            registry: Arc::new(registry),
            llm_factory,
        }
    }

    /// Run one user message to completion.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        req: ChatRequest,
        mode: PermissionMode,
        max_turns: u32,
        manager: Arc<ClientManager>,
        sink: Arc<dyn EventSink>,
        data_dir: std::path::PathBuf,
        session_id: Option<String>,
    ) {
        // Best-effort run; all errors become a terminal Error event.
        match self
            .run_inner(
                req,
                mode,
                max_turns,
                manager,
                sink.clone(),
                data_dir,
                session_id,
            )
            .await
        {
            Ok(()) => {}
            Err(e) => sink.emit(AgentEvent::Error {
                message: e.to_string(),
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_inner(
        &self,
        req: ChatRequest,
        mode: PermissionMode,
        max_turns: u32,
        manager: Arc<ClientManager>,
        sink: Arc<dyn EventSink>,
        data_dir: std::path::PathBuf,
        session_id: Option<String>,
    ) -> AiResult<()> {
        let data_dir_ref = Some(data_dir.as_path());

        let tool_ctx = ToolContext {
            manager: manager.clone(),
            data_dir: data_dir.clone(),
        };

        // ----------------------------------------------------------------
        // Load cluster info.
        // ----------------------------------------------------------------
        let info = manager.connection_info().await;
        let cluster_ver = info.as_ref().map(|i| i.version.clone());
        let context_name = info.as_ref().map(|i| i.context.clone());

        // ----------------------------------------------------------------
        // Load skill (if any).
        // ----------------------------------------------------------------
        let active_skill: Option<crate::ai::skills::Skill> =
            req.skill_id.as_deref().and_then(|id| {
                crate::ai::skills::SkillRegistry::load(data_dir_ref)
                    .get(id)
                    .cloned()
            });

        // ----------------------------------------------------------------
        // Load memory (four-tier).
        // ----------------------------------------------------------------
        let memory_block =
            if let (Some(ctx_name), Some(dir)) = (req.kube_context.as_deref(), data_dir_ref) {
                let store = crate::ai::memory::MemoryStore::open(dir, ctx_name);
                let block = store.to_context_block(20);
                if block.is_empty() {
                    None
                } else {
                    Some(block)
                }
            } else {
                None
            };

        // ----------------------------------------------------------------
        // Load evolution strategies.
        // ----------------------------------------------------------------
        let evolution_block = if let Some(dir) = data_dir_ref {
            let store = crate::ai::evolution::EvolutionStore::open(dir);
            let block = store.to_context_block(&req.message);
            if block.is_empty() {
                None
            } else {
                Some(block)
            }
        } else {
            None
        };

        // ----------------------------------------------------------------
        // Load sandbox config.
        // ----------------------------------------------------------------
        let sandbox_config = crate::ai::sandbox::SandboxConfig::default();

        // ----------------------------------------------------------------
        // Load user preferences from memory.
        // ----------------------------------------------------------------
        let preferences: Vec<(String, String, f32)> =
            if let (Some(ctx_name), Some(dir)) = (req.kube_context.as_deref(), data_dir_ref) {
                let store = crate::ai::memory::MemoryStore::open(dir, ctx_name);
                store
                    .preferences()
                    .iter()
                    .map(|p| (p.key.clone(), p.value.clone(), p.confidence))
                    .collect()
            } else {
                Vec::new()
            };

        // ----------------------------------------------------------------
        // Build dynamic system prompt via PromptBuilder.
        // ----------------------------------------------------------------
        let mut builder = crate::ai::prompt_builder::PromptBuilder::new()
            .base(cluster_ver.as_deref(), context_name.as_deref())
            .sandbox(&sandbox_config.denied_namespaces, max_turns);

        if let Some(skill) = &active_skill {
            builder = builder.skill(&skill.name, &skill.system_prompt_suffix);
        }
        if let Some(ref block) = memory_block {
            builder = builder.memory(block);
        }
        if let Some(ref block) = evolution_block {
            builder = builder.evolution(block);
        }
        if !preferences.is_empty() {
            builder = builder.preferences(&preferences);
        }
        let sys = builder.build();

        // ----------------------------------------------------------------
        // Assemble message list.
        // ----------------------------------------------------------------
        let mut messages: Vec<Message> = Vec::with_capacity(req.history.len() + 3);
        messages.push(Message::System { content: sys });
        messages.extend(req.history.iter().cloned());

        // Inject selected-resource context (transient).
        if let Some(sel) = &req.context {
            if sel.kind.is_some() && sel.name.is_some() {
                if let Some(desc) = context::selected_resource_context(&manager, sel).await {
                    let note = format!(
                        "The user has this resource selected in the UI:\n```json\n{}\n```",
                        k7s_deps::serde_json::to_string_pretty(&desc).unwrap_or_default()
                    );
                    messages.push(Message::System { content: note });
                }
            }
        }
        messages.push(Message::User {
            content: req.message.clone(),
        });

        // ----------------------------------------------------------------
        // Compress context if over budget.
        // ----------------------------------------------------------------
        messages = crate::ai::context_compress::compress_messages(
            &messages,
            crate::ai::context_compress::DEFAULT_CONTEXT_BUDGET,
        );
        // Recalculate returnable_start: after system + any summary, before
        // the recent turns that were kept verbatim.
        let returnable_start = messages
            .iter()
            .position(|m| !matches!(m, Message::System { .. }))
            .unwrap_or(0);

        // ----------------------------------------------------------------
        // Prepare tools (filtered by skill whitelist).
        // ----------------------------------------------------------------
        let mut tool_defs = self.registry.function_defs(mode);
        if let Some(skill) = &active_skill {
            if !skill.tool_whitelist.is_empty() {
                tool_defs.retain(|d| skill.tool_whitelist.contains(&d.name));
            }
        }
        let llm = (self.llm_factory)();

        // Emit context injection events so the user can see what the AI "knows".
        if let Some(skill) = &active_skill {
            sink.emit(AgentEvent::ContextInjected {
                block_type: "skill".into(),
                summary: format!("{}: {}", skill.name, skill.description),
            });
        }
        if memory_block.is_some() {
            sink.emit(AgentEvent::ContextInjected {
                block_type: "memory".into(),
                summary: "Cluster memory loaded (recent + long-term + vault)".into(),
            });
        }
        if evolution_block.is_some() {
            sink.emit(AgentEvent::ContextInjected {
                block_type: "evolution".into(),
                summary: "Learned strategies from past runs".into(),
            });
        }
        if !sandbox_config.denied_namespaces.is_empty() {
            sink.emit(AgentEvent::ContextInjected {
                block_type: "sandbox".into(),
                summary: format!(
                    "Security: denied namespaces [{}]",
                    sandbox_config.denied_namespaces.join(", ")
                ),
            });
        }
        if !preferences.is_empty() {
            sink.emit(AgentEvent::ContextInjected {
                block_type: "preferences".into(),
                summary: format!("{} user preferences loaded", preferences.len()),
            });
        }

        // ----------------------------------------------------------------
        // Initialize run-scoped components.
        // ----------------------------------------------------------------
        let deadline = crate::ai::timeouts::RunDeadline::new(300); // 5 min default
        let timeout_config = crate::ai::timeouts::TimeoutConfig::default();
        let mut plugins = crate::ai::plugins::PluginRegistry::new();
        plugins.register(Box::new(crate::ai::plugins::AuditLogger));
        plugins.register(Box::new(crate::ai::plugins::RateLimiter::new(30)));

        // Fire RunStart.
        plugins.fire(&crate::ai::plugins::PluginEvent::RunStart {
            run_id: "run",
            user_message: &req.message,
        });

        // Track tool calls for evolution recording.
        let mut tools_called: Vec<String> = Vec::new();
        let run_start = std::time::Instant::now();
        let mut turns = 0u32;

        // ----------------------------------------------------------------
        // Main ReAct loop.
        // ----------------------------------------------------------------
        loop {
            turns += 1;

            // Check turn limit.
            if turns > max_turns {
                sink.emit(AgentEvent::Done {
                    final_message: Some(format!(
                        "Reached the {max_turns}-turn limit without finishing."
                    )),
                    history: messages[returnable_start..].to_vec(),
                });
                // Record outcome for evolution.
                self.record_outcome(
                    &data_dir,
                    &req.message,
                    &tools_called,
                    false,
                    "turn limit",
                    run_start,
                    turns,
                )
                .await;
                return Ok(());
            }

            // Check cancellation.
            if sink.is_cancelled() {
                sink.emit(AgentEvent::Done {
                    final_message: Some("(cancelled)".to_string()),
                    history: messages[returnable_start..].to_vec(),
                });
                self.record_outcome(
                    &data_dir,
                    &req.message,
                    &tools_called,
                    false,
                    "cancelled",
                    run_start,
                    turns,
                )
                .await;
                return Ok(());
            }

            // Check run deadline.
            if deadline.is_expired() {
                sink.emit(AgentEvent::Done {
                    final_message: Some("Run deadline exceeded (5 minutes).".to_string()),
                    history: messages[returnable_start..].to_vec(),
                });
                self.record_outcome(
                    &data_dir,
                    &req.message,
                    &tools_called,
                    false,
                    "deadline",
                    run_start,
                    turns,
                )
                .await;
                return Ok(());
            }

            // Fire BeforeLlm.
            plugins.fire(&crate::ai::plugins::PluginEvent::BeforeLlm {
                run_id: "run",
                messages: &messages,
            });

            // Drive one LLM turn.
            k7s_deps::tracing::info!(turns, "starting LLM turn");
            let mut stream = llm.chat_stream(&messages, &tool_defs);
            let mut assistant_text = String::new();
            let mut tool_calls: Vec<OutgoingToolCall> = Vec::new();
            while let Some(item) = stream.next().await {
                match item? {
                    StreamEvent::TextDelta(t) => {
                        assistant_text.push_str(&t);
                        sink.emit(AgentEvent::TextDelta { text: t });
                    }
                    StreamEvent::ReasoningDelta(t) => {
                        // Reasoning is accumulated into assistant_text too (so
                        // it becomes the final answer when content is empty),
                        // but emitted as a separate event for the UI to render
                        // as a collapsible thinking block.
                        assistant_text.push_str(&t);
                        sink.emit(AgentEvent::ReasoningDelta { text: t });
                    }
                    StreamEvent::Done {
                        tool_calls: tc,
                        finish_reason,
                    } => {
                        tool_calls = tc;
                        if finish_reason == "length" {
                            sink.emit(AgentEvent::TextDelta {
                                text: "…[output truncated]".into(),
                            });
                        }
                        break;
                    }
                }
            }
            k7s_deps::tracing::info!(
                turns,
                text_len = assistant_text.len(),
                tool_calls = tool_calls.len(),
                "LLM turn complete"
            );

            // Fire AfterLlm.
            plugins.fire(&crate::ai::plugins::PluginEvent::AfterLlm {
                run_id: "run",
                response: &assistant_text,
            });

            // If no tool calls, the turn is done.
            if tool_calls.is_empty() {
                // If the LLM didn't produce text but we have tool results,
                // construct a fallback summary so the user always sees something.
                let effective_text = if assistant_text.is_empty() {
                    let summary = summarize_tool_results(&messages);
                    k7s_deps::tracing::info!(
                        summary_len = summary.len(),
                        "fallback summary generated"
                    );
                    summary
                } else {
                    assistant_text.clone()
                };
                let final_text = if effective_text.is_empty() {
                    None
                } else {
                    Some(effective_text.clone())
                };
                let response_text = effective_text;
                messages.push(Message::Assistant {
                    content: some_content(&assistant_text),
                    tool_calls: None,
                });
                k7s_deps::tracing::info!(
                    final_text_len = final_text.as_ref().map_or(0, |s| s.len()),
                    "emitting Done event"
                );
                sink.emit(AgentEvent::Done {
                    final_message: final_text,
                    history: messages[returnable_start..].to_vec(),
                });
                // Save assistant response to session.
                save_session_response(&data_dir, &session_id, &response_text);
                // Record successful outcome.
                self.record_outcome(
                    &data_dir,
                    &req.message,
                    &tools_called,
                    true,
                    &response_text,
                    run_start,
                    turns,
                )
                .await;
                // Auto-summarize into short-term memory.
                if let (Some(ctx_name), Some(dir)) = (req.kube_context.as_deref(), data_dir_ref) {
                    let mut store = crate::ai::memory::MemoryStore::open(dir, ctx_name);
                    store.auto_summarize(&req.message, &response_text, &tools_called);
                }
                // Fire RunEnd.
                plugins.fire(&crate::ai::plugins::PluginEvent::RunEnd {
                    run_id: "run",
                    final_message: Some(&response_text),
                });
                return Ok(());
            }

            // Record assistant turn in history.
            messages.push(Message::Assistant {
                content: some_content(&assistant_text),
                tool_calls: Some(tool_calls.clone()),
            });

            // Dispatch each tool call.
            for call in &tool_calls {
                if sink.is_cancelled() {
                    return Err(AiError::Cancelled);
                }
                if deadline.is_expired() {
                    break;
                }

                let args: k7s_deps::serde_json::Value =
                    k7s_deps::serde_json::from_str(&call.arguments)
                        .unwrap_or(k7s_deps::serde_json::Value::Null);
                let is_write = self.registry.is_write(&call.name);
                tools_called.push(call.name.clone());

                sink.emit(AgentEvent::ToolCall {
                    call_id: call.id.clone(),
                    name: call.name.clone(),
                    arguments: args.clone(),
                    is_write,
                });

                // --- Plugin: BeforeTool ---
                let plugin_decision = plugins.fire(&crate::ai::plugins::PluginEvent::BeforeTool {
                    run_id: "run",
                    tool_name: &call.name,
                    args: &args,
                });
                if let crate::ai::plugins::PluginDecision::Block { reason } = &plugin_decision {
                    sink.emit(AgentEvent::ToolResult {
                        call_id: call.id.clone(),
                        ok: false,
                        result: k7s_deps::serde_json::json!({ "error": format!("blocked by plugin: {reason}") }),
                    });
                    messages.push(Message::Tool {
                        tool_call_id: call.id.clone(),
                        content:
                            k7s_deps::serde_json::json!({ "error": format!("blocked by plugin: {reason}") })
                                .to_string(),
                    });
                    continue;
                }

                // --- Sandbox evaluation ---
                let sandbox_decision =
                    crate::ai::sandbox::evaluate(&sandbox_config, &call.name, &args);
                let pre_denied: Option<AiError> = match sandbox_decision {
                    crate::ai::sandbox::SandboxDecision::Deny { reason } => {
                        Some(AiError::PermissionDenied(format!(
                            "sandbox denied '{}': {reason}",
                            call.name
                        )))
                    }
                    crate::ai::sandbox::SandboxDecision::Ask { reason } => {
                        // Same as permission gate NeedsApproval.
                        let summary = summarize_call(&call.name, &args);
                        sink.emit(AgentEvent::PendingApproval {
                            call_id: call.id.clone(),
                            name: call.name.clone(),
                            arguments: args.clone(),
                            summary: format!("{summary} (sandbox: {reason})"),
                        });
                        let approved = matches!(sink.await_approval(&call.id).await, Ok(true));
                        if approved {
                            None
                        } else {
                            Some(AiError::PermissionDenied(format!(
                                "user declined '{}' (sandbox)",
                                call.name
                            )))
                        }
                    }
                    crate::ai::sandbox::SandboxDecision::Allow => None,
                };

                // --- Permission gate (if sandbox allowed) ---
                let pre_denied = if pre_denied.is_some() {
                    pre_denied
                } else {
                    match permission::decide(mode, is_write) {
                        Decision::Allow => None,
                        Decision::Deny => Some(AiError::PermissionDenied(format!(
                            "write tool '{}' refused by permission mode {:?}",
                            call.name, mode
                        ))),
                        Decision::NeedsApproval => {
                            let summary = summarize_call(&call.name, &args);
                            sink.emit(AgentEvent::PendingApproval {
                                call_id: call.id.clone(),
                                name: call.name.clone(),
                                arguments: args.clone(),
                                summary,
                            });
                            let approved = matches!(sink.await_approval(&call.id).await, Ok(true));
                            if approved {
                                None
                            } else {
                                Some(AiError::PermissionDenied(format!(
                                    "user declined '{}'",
                                    call.name
                                )))
                            }
                        }
                    }
                };

                // --- Execute with timeout ---
                let result_val: k7s_deps::serde_json::Value = match pre_denied {
                    Some(e) => {
                        let msg = e.to_string();
                        sink.emit(AgentEvent::ToolResult {
                            call_id: call.id.clone(),
                            ok: false,
                            result: k7s_deps::serde_json::json!({ "error": msg }),
                        });
                        k7s_deps::serde_json::json!({ "error": msg })
                    }
                    _ => {
                        let dispatch_result = crate::ai::timeouts::with_timeout(
                            std::time::Duration::from_secs(timeout_config.tool_timeout_secs),
                            self.registry.dispatch(&call.name, &tool_ctx, args.clone()),
                        )
                        .await;

                        let result: AiResult<k7s_deps::serde_json::Value> = match dispatch_result {
                            Ok(v) => Ok(v),
                            Err(crate::ai::timeouts::TimeoutError::TimedOut) => {
                                Err(AiError::Tool(format!(
                                    "tool '{}' timed out after {}s",
                                    call.name, timeout_config.tool_timeout_secs
                                )))
                            }
                            Err(crate::ai::timeouts::TimeoutError::Inner(e)) => Err(e),
                        };

                        // Fire AfterTool.
                        plugins.fire(&crate::ai::plugins::PluginEvent::AfterTool {
                            run_id: "run",
                            tool_name: &call.name,
                            result: &result
                                .as_ref()
                                .map(|_| k7s_deps::serde_json::Value::Null)
                                .map_err(|e| e.to_string()),
                        });

                        match result {
                            Ok(v) => {
                                sink.emit(AgentEvent::ToolResult {
                                    call_id: call.id.clone(),
                                    ok: true,
                                    result: v.clone(),
                                });
                                v
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                sink.emit(AgentEvent::ToolResult {
                                    call_id: call.id.clone(),
                                    ok: false,
                                    result: k7s_deps::serde_json::json!({ "error": msg }),
                                });
                                k7s_deps::serde_json::json!({ "error": msg })
                            }
                        }
                    }
                };

                let trimmed = trim_result(result_val);
                messages.push(Message::Tool {
                    tool_call_id: call.id.clone(),
                    content: k7s_deps::serde_json::to_string(&trimmed)
                        .unwrap_or_else(|_| "{}".into()),
                });
            }
        }
    }

    /// Record a run outcome in the evolution store for self-improvement.
    #[allow(clippy::too_many_arguments)]
    async fn record_outcome(
        &self,
        data_dir: &std::path::Path,
        user_message: &str,
        tools_called: &[String],
        success: bool,
        response: &str,
        start: std::time::Instant,
        turn_count: u32,
    ) {
        let mut store = crate::ai::evolution::EvolutionStore::open(data_dir);
        store.record_run(crate::ai::evolution::RunOutcome {
            run_id: k7s_deps::uuid::Uuid::new_v4().to_string(),
            user_message: user_message.to_string(),
            tools_called: tools_called.to_vec(),
            success,
            final_response: response.chars().take(500).collect(),
            error: if success {
                None
            } else {
                Some(response.to_string())
            },
            duration_ms: start.elapsed().as_millis() as u64,
            turn_count,
        });
        // Periodically scan and update strategies.
        store.scan_and_update();
    }
}

/// Normalize assistant text for storage in message history.
/// Always returns `Some(text)` — even empty strings — because some LLM
/// providers (MiMo, DeepSeek) require `content` to be present (non-null)
/// on assistant messages, even when `tool_calls` is also present.
fn some_content(text: &str) -> Option<String> {
    Some(text.to_string())
}

/// Save assistant response to session (non-blocking, best-effort).
fn save_session_response(data_dir: &std::path::Path, session_id: &Option<String>, response: &str) {
    if let Some(sid) = session_id {
        if !response.is_empty() {
            let mgr = crate::ai::session::SessionManager::new(data_dir.to_path_buf());
            let sid = sid.clone();
            let resp = response.to_string();
            k7s_deps::tokio::spawn(async move {
                mgr.add_message(&sid, "assistant", &resp).await;
            });
        }
    }
}

/// When the LLM doesn't produce a final text response (common with reasoning
/// models that put everything in tool calls), construct a fallback summary from
/// the tool results in the message history.
fn summarize_tool_results(messages: &[Message]) -> String {
    let mut summaries = Vec::new();
    let mut tool_count = 0;
    for msg in messages {
        if let Message::Tool { content, .. } = msg {
            tool_count += 1;
            k7s_deps::tracing::debug!(
                content_len = content.len(),
                "processing tool result for summary"
            );
            if let Ok(val) = k7s_deps::serde_json::from_str::<k7s_deps::serde_json::Value>(content)
            {
                if let Some(arr) = val.as_array() {
                    // Array of resources — show count + first few names.
                    let count = arr.len();
                    let names: Vec<&str> = arr
                        .iter()
                        .take(5)
                        .filter_map(|item| {
                            item.get("name")
                                .and_then(|n| n.as_str())
                                .or_else(|| item.get("node").and_then(|n| n.as_str()))
                        })
                        .collect();
                    if !names.is_empty() {
                        summaries.push(format!(
                            "Found {} resources: {}{}",
                            count,
                            names.join(", "),
                            if count > 5 { ", ..." } else { "" }
                        ));
                    } else {
                        // Array with no name field — show count.
                        summaries.push(format!("Result: {count} items."));
                    }
                } else if let Some(problems) = val.get("problems").and_then(|p| p.as_array()) {
                    if problems.is_empty() {
                        summaries.push("No problems found — cluster is healthy.".to_string());
                    } else {
                        summaries.push(format!("Found {} problems.", problems.len()));
                    }
                } else if let Some(b) = val.get("scaled").and_then(|v| v.as_bool()) {
                    if b {
                        summaries.push("Resource scaled successfully.".into());
                    }
                } else if let Some(b) = val.get("applied").and_then(|v| v.as_bool()) {
                    if b {
                        summaries.push("Manifest applied successfully.".into());
                    }
                } else if let Some(b) = val.get("deleted").and_then(|v| v.as_bool()) {
                    if b {
                        summaries.push("Resource deleted.".into());
                    }
                } else if let Some(b) = val.get("restarted").and_then(|v| v.as_bool()) {
                    if b {
                        summaries.push("Workload restarted.".into());
                    }
                } else {
                    // Generic: show a compact representation of the result.
                    let compact = k7s_deps::serde_json::to_string(&val).unwrap_or_default();
                    if compact.len() <= 500 {
                        summaries.push(compact);
                    } else {
                        summaries.push(format!("{}…", &compact[..500]));
                    }
                }
            } else {
                // Non-JSON tool result — show as-is (truncated).
                let preview = content.chars().take(300).collect::<String>();
                summaries.push(preview);
            }
        }
    }
    if summaries.is_empty() {
        // No tool results at all — the model just didn't respond.
        k7s_deps::tracing::warn!(tool_count, "no summaries generated from tool results");
        "AI did not produce a response. Please try again.".to_string()
    } else {
        k7s_deps::tracing::info!(
            tool_count,
            summary_count = summaries.len(),
            "tool result summaries generated"
        );
        summaries.join("\n\n")
    }
}

/// Build a one-line human summary for a pending approval, e.g.
/// "scale deployments/payment to 5 replicas".
fn summarize_call(name: &str, args: &k7s_deps::serde_json::Value) -> String {
    let g = |k: &str| args.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let gi = |k: &str| args.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    match name {
        "scale_workload" => format!(
            "scale {} {}/{} to {} replicas",
            g("kind"),
            g("namespace"),
            g("name"),
            gi("replicas")
        ),
        "restart_workload" => format!(
            "rollout-restart {} {}/{}",
            g("kind"),
            g("namespace"),
            g("name")
        ),
        "delete_resource" => format!("delete {} {}/{}", g("kind"), g("namespace"), g("name")),
        "apply_manifest" => "apply a YAML manifest".to_string(),
        _ => format!("run tool '{name}'"),
    }
}

/// Keep tool results small enough not to dominate the next turn's prompt.
/// Truncates long string fields and limits array length.
fn trim_result(v: k7s_deps::serde_json::Value) -> k7s_deps::serde_json::Value {
    match v {
        k7s_deps::serde_json::Value::String(s) => {
            if s.chars().count() > 4000 {
                let head: String = s.chars().take(4000).collect();
                k7s_deps::serde_json::Value::String(format!("{head}\n…[truncated]"))
            } else {
                k7s_deps::serde_json::Value::String(s)
            }
        }
        k7s_deps::serde_json::Value::Array(a) => {
            let truncated = a.len() > 50;
            let mut iter: Box<dyn Iterator<Item = k7s_deps::serde_json::Value>> =
                Box::new(a.into_iter().take(50).map(trim_result));
            let mut out: Vec<k7s_deps::serde_json::Value> = (&mut iter).collect();
            if truncated {
                out.push(k7s_deps::serde_json::json!({ "note": "results truncated to 50 rows" }));
            }
            k7s_deps::serde_json::Value::Array(out)
        }
        k7s_deps::serde_json::Value::Object(o) => {
            let map = o.into_iter().map(|(k, vv)| (k, trim_result(vv))).collect();
            k7s_deps::serde_json::Value::Object(map)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::llm::{ChatStream, FunctionDef, StreamEvent};
    use k7s_deps::tokio::sync::oneshot;
    use std::sync::Mutex;

    /// A mock LlmClient that returns a pre-scripted sequence of turn responses.
    /// Each call to `chat_stream` advances to the next script entry.
    struct MockLlm {
        /// One Vec per turn: the stream items to emit.
        script: Mutex<Vec<Vec<StreamEvent>>>,
    }

    impl MockLlm {
        fn new(turns: Vec<Vec<StreamEvent>>) -> Self {
            Self {
                script: Mutex::new(turns),
            }
        }
    }

    impl LlmClient for MockLlm {
        fn chat_stream(&self, _messages: &[Message], _tools: &[FunctionDef]) -> ChatStream {
            let mut script = self.script.lock().unwrap();
            let turn = if script.is_empty() {
                vec![StreamEvent::Done {
                    tool_calls: vec![],
                    finish_reason: "stop".into(),
                }]
            } else {
                script.remove(0)
            };
            // Build a stream that yields each item then ends.
            Box::pin(k7s_deps::futures::stream::iter(
                turn.into_iter().map(Ok::<_, AiError>),
            ))
        }
    }

    /// A mock EventSink that records emitted events and auto-approves every
    /// pending write (so the gate doesn't block the test).
    #[allow(dead_code)] // event-capture helper for agent tests
    struct MockSink {
        events: Mutex<Vec<AgentEvent>>,
        cancelled: Mutex<bool>,
    }

    #[allow(dead_code)]
    impl MockSink {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                cancelled: Mutex::new(false),
            }
        }
        fn events(&self) -> Vec<AgentEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    impl EventSink for MockSink {
        fn emit(&self, ev: AgentEvent) {
            self.events.lock().unwrap().push(ev);
        }
        fn await_approval(&self, _call_id: &str) -> oneshot::Receiver<bool> {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(true); // auto-approve in tests
            rx
        }
        fn is_cancelled(&self) -> bool {
            *self.cancelled.lock().unwrap()
        }
    }

    fn make_agent(script: Vec<Vec<StreamEvent>>) -> AgentLoop {
        let llm = Arc::new(MockLlm::new(script));
        let factory: Arc<dyn Fn() -> Box<dyn LlmClient> + Send + Sync> =
            Arc::new(move || Box::new(MockLlm::new(vec![])));
        // The factory isn't used by run() if we pass our own agent; but
        // AgentLoop::new needs one. Build the agent with a factory that
        // reconstructs a fresh mock per call — for the test we instead build
        // the agent and rely on factory producing a defaulting mock.
        let _ = llm;
        AgentLoop::new(crate::ai::ToolRegistry::new(), factory)
    }

    /// trim_result truncates long strings and caps arrays at 50 + a note.
    #[test]
    fn trim_truncates_long_string() {
        let long = "x".repeat(5000);
        let v = trim_result(k7s_deps::serde_json::Value::String(long));
        let s = v.as_str().unwrap();
        assert!(s.contains("[truncated]"));
        assert!(s.chars().count() < 4100);
    }

    #[test]
    fn trim_caps_array_at_50() {
        let arr: Vec<k7s_deps::serde_json::Value> =
            (0..100).map(k7s_deps::serde_json::Value::from).collect();
        let v = trim_result(k7s_deps::serde_json::Value::Array(arr));
        let a = v.as_array().unwrap();
        assert_eq!(a.len(), 51); // 50 + the note
        assert!(a.last().unwrap().get("note").is_some());
    }

    #[test]
    fn trim_passes_through_small_values() {
        assert_eq!(
            trim_result(k7s_deps::serde_json::json!(42)),
            k7s_deps::serde_json::json!(42)
        );
        assert_eq!(
            trim_result(k7s_deps::serde_json::json!("short")),
            k7s_deps::serde_json::json!("short")
        );
    }

    /// summarize_call produces human-readable one-liners for the approval card.
    #[test]
    fn summarize_scale_call() {
        let s = summarize_call(
            "scale_workload",
            &k7s_deps::serde_json::json!({"kind":"deployments","namespace":"prod","name":"api","replicas":5}),
        );
        assert!(s.contains("deployments"));
        assert!(s.contains("prod/api"));
        assert!(s.contains("5"));
    }

    // (The agent-loop integration test with a live mock LLM requires a connected
    // ClientManager, which we can't build cheaply in a unit test. The loop's
    // pure helpers above are covered; the full loop is exercised by the dev
    // cluster smoke test in dev/web.mjs + a real LLM provider.)
    #[test]
    fn agent_loop_helpers_smoke() {
        // Ensure the factory + registry wire together without panicking.
        let _ = make_agent(vec![]);
    }
}
