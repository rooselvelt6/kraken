#![allow(clippy::needless_pass_by_value)]

use proptest::prelude::*;
use runtime::{PermissionMode, PermissionOutcome, PermissionPolicy};

fn mode_strategy() -> impl Strategy<Value = PermissionMode> {
    prop_oneof![
        Just(PermissionMode::ReadOnly),
        Just(PermissionMode::WorkspaceWrite),
        Just(PermissionMode::DangerFullAccess),
        Just(PermissionMode::Allow),
    ]
}

proptest! {
    #[test]
    fn decision_is_deterministic(
        mode in mode_strategy(),
        tool_name in "([a-zA-Z_][a-zA-Z0-9_]{0,20})",
        input in ".*",
    ) {
        let policy = PermissionPolicy::new(mode);
        let r1 = policy.authorize(&tool_name, &input, None);
        let r2 = policy.authorize(&tool_name, &input, None);
        prop_assert_eq!(r1, r2);
    }

    #[test]
    fn default_required_mode_is_danger_full_access(
        tool_name in "([a-zA-Z_][a-zA-Z0-9_]{0,20})",
    ) {
        let policy = PermissionPolicy::new(PermissionMode::ReadOnly);
        prop_assert_eq!(
            policy.required_mode_for(&tool_name),
            PermissionMode::DangerFullAccess
        );
    }

    #[test]
    fn active_mode_matches_constructor(mode in mode_strategy()) {
        let policy = PermissionPolicy::new(mode);
        prop_assert_eq!(policy.active_mode(), mode);
    }

    #[test]
    fn higher_mode_never_more_restrictive(
        tool_name in "([a-zA-Z_][a-zA-Z0-9_]{0,20})",
        input in ".*",
    ) {
        let low_modes = [PermissionMode::ReadOnly, PermissionMode::WorkspaceWrite, PermissionMode::DangerFullAccess];
        let high_modes = [PermissionMode::WorkspaceWrite, PermissionMode::DangerFullAccess, PermissionMode::Allow];

        for (&low, &high) in low_modes.iter().zip(high_modes.iter()) {
            let low_policy = PermissionPolicy::new(low);
            let high_policy = PermissionPolicy::new(high);
            let low_result = low_policy.authorize(&tool_name, &input, None);
            let high_result = high_policy.authorize(&tool_name, &input, None);
            if low_result == PermissionOutcome::Allow {
                prop_assert_eq!(
                    high_result,
                    PermissionOutcome::Allow,
                    "higher mode {:?} denied what lower mode {:?} allowed for tool={} input={}",
                    high, low, tool_name, input
                );
            }
        }
    }

    #[test]
    fn tool_requirement_is_honored(
        tool_name in "([a-zA-Z_][a-zA-Z0-9_]{0,20})",
        required in mode_strategy(),
        mode in mode_strategy(),
    ) {
        let policy = PermissionPolicy::new(mode)
            .with_tool_requirement(&tool_name, required);
        prop_assert_eq!(policy.required_mode_for(&tool_name), required);
    }

    #[test]
    fn enforcer_check_matches_policy(
        mode in mode_strategy(),
        tool_name in "([a-zA-Z_][a-zA-Z0-9_]{0,20})",
        input in ".*",
    ) {
        let policy = PermissionPolicy::new(mode);
        let enforcer = runtime::permission_enforcer::PermissionEnforcer::new(policy);
        let result = enforcer.check(&tool_name, &input);
        let outcome = PermissionPolicy::new(mode).authorize(&tool_name, &input, None);
        match outcome {
            PermissionOutcome::Allow => {
                prop_assert_eq!(result, runtime::permission_enforcer::EnforcementResult::Allowed);
            }
            PermissionOutcome::Deny { .. } => {
                assert!(matches!(result, runtime::permission_enforcer::EnforcementResult::Denied { .. }));
            }
        }
    }
}
