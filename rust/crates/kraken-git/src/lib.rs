//! Git context and source control utilities extracted from the `runtime` crate.

pub mod branch_lock;
pub mod git_context;
pub mod stale_base;
pub mod stale_branch;

pub use branch_lock::{detect_branch_lock_collisions, BranchLockCollision, BranchLockIntent};
pub use git_context::{GitCommitEntry, GitContext};
pub use stale_base::{
    check_base_commit, format_stale_base_warning, read_kraken_base_file, resolve_expected_base,
    BaseCommitSource, BaseCommitState,
};
pub use stale_branch::{
    apply_policy, check_freshness, BranchFreshness, StaleBranchAction, StaleBranchEvent,
    StaleBranchPolicy,
};
