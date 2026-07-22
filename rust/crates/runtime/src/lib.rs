//! Core runtime primitives for the `kraken` CLI and supporting crates.
//!
//! This crate owns session persistence, permission evaluation, prompt assembly,
//! MCP plumbing, tool-facing file operations, and the core conversation loop
//! that drives interactive and one-shot turns.

mod bash;
pub mod audit_integration;
pub mod bash_validation;

// Infrastructure modules re-exported from kraken-infra
pub use kraken_infra::bootstrap;
pub use kraken_infra::circuit_breaker;
pub use kraken_infra::concurrency;
pub use kraken_infra::file_ops;
pub use kraken_infra::fingerprint;
pub use kraken_infra::forensic;
pub use kraken_infra::health_probe;
pub use kraken_infra::path_traversal;
pub use kraken_infra::rate_limiter;
pub use kraken_infra::sandbox;
pub use kraken_infra::sanitizer;
pub use kraken_infra::size_budget;
pub use kraken_infra::summary_compression;
// Git modules re-exported from kraken-git
pub use kraken_git::branch_lock;
pub use kraken_git::git_context;
pub use kraken_git::stale_base;
pub use kraken_git::stale_branch;
// Event modules re-exported from kraken-events
pub use kraken_events::lane_events;
pub use kraken_events::task_packet;
pub use kraken_events::task_registry;
pub use kraken_events::team_cron_registry;
pub use kraken_events::{
    compute_event_fingerprint, dedupe_superseded_commit_events, dedupe_terminal_events,
    is_terminal_event, BlockedSubphase, EventProvenance, LaneCommitProvenance, LaneEvent,
    LaneEventBlocker, LaneEventBuilder, LaneEventMetadata, LaneEventName, LaneEventStatus,
    LaneFailureClass, LaneOwnership, SessionIdentity, ShipMergeMethod, ShipProvenance,
    WatcherAction,
};
pub use kraken_events::{validate_packet, TaskPacket, TaskPacketValidationError, ValidatedPacket};
pub use kraken_events::{Task, TaskMessage, TaskRegistry, TaskStatus};
pub use kraken_events::{CronEntry, CronRegistry, Team, TeamRegistry, TeamStatus};

// Config modules re-exported from kraken-config
pub use kraken_config::config;
pub use kraken_config::config_validate;
pub use kraken_config::config::{
    ConfigEntry, ConfigError, ConfigLoader, ConfigSource, McpConfigCollection,
    McpManagedProxyServerConfig, McpOAuthConfig, McpRemoteServerConfig, McpSdkServerConfig,
    McpServerConfig, McpStdioServerConfig, McpTransport, McpWebSocketServerConfig, OAuthConfig,
    ProviderFallbackConfig, ResolvedPermissionMode, RuntimeConfig, RuntimeFeatureConfig,
    RuntimeHookConfig, RuntimePermissionRuleConfig, RuntimePluginConfig, ScopedMcpServerConfig,
    KRAKEN_SETTINGS_SCHEMA_NAME,
};
pub use kraken_config::config_validate::{
    check_unsupported_format, format_diagnostics, validate_config_file, ConfigDiagnostic,
    DiagnosticKind, ValidationResult,
};

// Policy modules re-exported from kraken-policy
pub use kraken_policy::green_contract;
pub use kraken_policy::permission_enforcer;
pub use kraken_policy::permissions;
pub use kraken_policy::permissions::{
    PermissionContext, PermissionMode, PermissionOutcome, PermissionOverride, PermissionPolicy,
    PermissionPromptDecision, PermissionPrompter, PermissionRequest,
};
pub use kraken_policy::policy_engine::{
    evaluate, DiffScope, GreenLevel, LaneBlocker, LaneContext, PolicyAction, PolicyCondition,
    PolicyEngine, PolicyRule, ReconcileReason, ReviewStatus,
};
#[cfg(test)]
pub use kraken_policy::trust_resolver::{TrustConfig, TrustDecision, TrustEvent, TrustPolicy, TrustResolver};

// MCP modules re-exported from kraken-mcp
pub use kraken_mcp::mcp;
pub use kraken_mcp::mcp_client;
pub use kraken_mcp::mcp_lifecycle_hardened;
pub use kraken_mcp::mcp_server;
pub use kraken_mcp::mcp_stdio;
pub use kraken_mcp::mcp_tool_bridge;
pub use kraken_mcp::mcp::{
    mcp_server_signature, mcp_tool_name, mcp_tool_prefix, normalize_name_for_mcp,
    scoped_mcp_config_hash, unwrap_ccr_proxy_url,
};
pub use kraken_mcp::mcp_client::{
    McpClientAuth, McpClientBootstrap, McpClientTransport, McpManagedProxyTransport,
    McpRemoteTransport, McpSdkTransport, McpStdioTransport,
};
pub use kraken_mcp::mcp_lifecycle_hardened::{
    McpDegradedReport, McpErrorSurface, McpFailedServer, McpLifecyclePhase, McpLifecycleState,
    McpLifecycleValidator, McpPhaseResult,
};
pub use kraken_mcp::mcp_server::{McpServer, McpServerSpec, ToolCallHandler, MCP_SERVER_PROTOCOL_VERSION};
pub use kraken_mcp::mcp_stdio::{
    spawn_mcp_stdio_process, JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse,
    ManagedMcpTool, McpDiscoveryFailure, McpInitializeClientInfo, McpInitializeParams,
    McpInitializeResult, McpInitializeServerInfo, McpListResourcesParams, McpListResourcesResult,
    McpListToolsParams, McpListToolsResult, McpReadResourceParams, McpReadResourceResult,
    McpResource, McpResourceContents, McpServerManager, McpServerManagerError, McpStdioProcess,
    McpTool, McpToolCallContent, McpToolCallParams, McpToolCallResult, McpToolDiscoveryReport,
    UnsupportedMcpServer,
};
pub use kraken_mcp::oauth::{
    clear_oauth_credentials, code_challenge_s256, credentials_path, generate_pkce_pair,
    generate_state, load_oauth_credentials, loopback_redirect_uri, parse_oauth_callback_query,
    parse_oauth_callback_request_target, save_oauth_credentials, OAuthAuthorizationRequest,
    OAuthCallbackParams, OAuthRefreshRequest, OAuthTokenExchangeRequest, OAuthTokenSet,
    PkceChallengeMethod, PkceCodePair,
};

// Session modules re-exported from kraken-session
pub use kraken_session::compact::{
    compact_session, estimate_session_tokens, format_compact_summary,
    get_compact_continuation_message, should_compact, CompactionConfig, CompactionResult,
};
pub use kraken_session::hooks::{
    HookAbortSignal, HookEvent, HookProgressEvent, HookProgressReporter, HookRunResult, HookRunner,
};
pub use kraken_session::prompt::{
    load_system_prompt, load_system_prompt_with_effort, prepend_bullets, ContextFile, ProjectContext,
    PromptBuildError,
    SystemPromptBuilder, FRONTIER_MODEL_NAME, SYSTEM_PROMPT_DYNAMIC_BOUNDARY,
};
pub use kraken_session::session::{
    ContentBlock, ConversationMessage, MessageRole, Session, SessionCompaction, SessionError,
    SessionFork, SessionPromptEntry,
};
pub use kraken_session::session_control::{SessionStore, SessionControlError};
pub use kraken_session::session_control;
pub use kraken_session::usage::{
    format_usd, pricing_for_model, ModelPricing, TokenUsage, UsageCostEstimate, UsageTracker,
};

// Conversation modules re-exported from kraken-conversation
pub use kraken_conversation::conversation::{
    auto_compaction_threshold_from_env, ApiClient, ApiRequest, AssistantEvent, AutoCompactionEvent,
    ConversationRuntime, PromptCacheEvent, RuntimeError, StaticToolExecutor, ToolError,
    ToolExecutor, TurnSummary,
};

// Modules still in runtime
pub mod heuristic_engine;
pub mod provider_chain;
pub mod lsp_client;
pub mod plugin_lifecycle;
pub mod recovery_recipes;
pub mod remote;
pub mod adaptive_engine;
pub mod self_healing;
pub mod meta_agent;
pub mod siem_export;
mod sse;
pub mod worker_boot;

pub use bash::{execute_bash, BashCommandInput, BashCommandOutput};
pub use file_ops::{
    edit_file, glob_search, grep_search, read_file, write_file, EditFileOutput, GlobSearchOutput,
    GrepSearchInput, GrepSearchOutput, ReadFileOutput, StructuredPatchHunk, TextFilePayload,
    WriteFileOutput,
};
pub use git_context::{GitCommitEntry, GitContext};
pub use plugin_lifecycle::{
    DegradedMode, DiscoveryResult, PluginHealthcheck, PluginLifecycle, PluginLifecycleEvent,
    PluginState, ResourceInfo, ServerHealth, ServerStatus, ToolInfo,
};
pub use recovery_recipes::{
    attempt_recovery, recipe_for, EscalationPolicy, FailureScenario, RecoveryContext,
    RecoveryEvent, RecoveryRecipe, RecoveryResult, RecoveryStep,
};
pub use remote::{
    inherited_upstream_proxy_env, no_proxy_list, read_token, upstream_proxy_ws_url,
    RemoteSessionContext, UpstreamProxyBootstrap, UpstreamProxyState, DEFAULT_REMOTE_BASE_URL,
    DEFAULT_SESSION_TOKEN_PATH, DEFAULT_SYSTEM_CA_BUNDLE, NO_PROXY_HOSTS, UPSTREAM_PROXY_ENV_KEYS,
};
pub use sandbox::{
    build_linux_sandbox_command, detect_container_environment, detect_container_environment_from,
    resolve_sandbox_status, resolve_sandbox_status_for_request, ContainerEnvironment,
    FilesystemIsolationMode, LinuxSandboxCommand, SandboxConfig, SandboxDetectionInputs,
    SandboxRequest, SandboxStatus,
};
pub use sse::{IncrementalSseParser, SseEvent};
pub use worker_boot::{
    Worker, WorkerEvent, WorkerEventKind, WorkerEventPayload, WorkerFailure, WorkerFailureKind,
    WorkerPromptTarget, WorkerReadySnapshot, WorkerRegistry, WorkerStatus, WorkerTrustResolution,
};

#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
