//! Policy engine, trust resolution, and permission enforcement extracted from the `runtime` crate.

pub mod green_contract;
pub mod permission_enforcer;
pub mod permissions;
pub mod policy_engine;
pub mod trust_resolver;

pub use green_contract::GreenLevel as ContractGreenLevel;
pub use permissions::{
    PermissionContext, PermissionMode, PermissionOutcome, PermissionOverride, PermissionPolicy,
    PermissionPromptDecision, PermissionPrompter, PermissionRequest,
};
pub use permission_enforcer::{EnforcementResult, PermissionEnforcer};
pub use policy_engine::{
    evaluate, DiffScope, GreenLevel, LaneBlocker, LaneContext, PolicyAction, PolicyCondition,
    PolicyEngine, PolicyRule, ReconcileReason, ReviewStatus,
};
#[cfg(test)]
pub use trust_resolver::{TrustConfig, TrustDecision, TrustEvent, TrustPolicy, TrustResolver};
