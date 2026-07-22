//! Session persistence, compaction, usage tracking, and prompt assembly
//! extracted from the `runtime` crate.

pub mod compact;
pub mod hooks;
pub mod prompt;
pub mod session;
pub mod session_control;
pub mod usage;

pub use compact::{
    compact_session, estimate_session_tokens, format_compact_summary,
    get_compact_continuation_message, should_compact, CompactionConfig, CompactionResult,
};
pub use hooks::{
    HookAbortSignal, HookEvent, HookProgressEvent, HookProgressReporter, HookRunResult, HookRunner,
};
pub use prompt::{
    load_system_prompt, load_system_prompt_with_effort, prepend_bullets, ContextFile,
    ProjectContext, PromptBuildError, SystemPromptBuilder, FRONTIER_MODEL_NAME,
    SYSTEM_PROMPT_DYNAMIC_BOUNDARY,
};
pub use session::{
    ContentBlock, ConversationMessage, MessageRole, Session, SessionCompaction, SessionError,
    SessionFork, SessionPromptEntry,
};
pub use session_control::{SessionStore, SessionControlError};
pub use usage::{
    format_usd, pricing_for_model, ModelPricing, TokenUsage, UsageCostEstimate, UsageTracker,
};
