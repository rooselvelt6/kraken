#![allow(clippy::needless_pass_by_value)]

use proptest::prelude::*;

proptest! {
    #[test]
    fn resolve_model_alias_is_idempotent(model in "[a-zA-Z0-9._/-]{1,50}") {
        let first = api::resolve_model_alias(&model);
        let second = api::resolve_model_alias(&first);
        prop_assert_eq!(first, second, "alias resolution should be idempotent");
    }

    #[test]
    fn resolve_model_alias_never_empty(model in "[a-zA-Z0-9._/-]{1,50}") {
        let result = api::resolve_model_alias(&model);
        prop_assert!(!result.is_empty(), "resolved alias should never be empty");
    }

    #[test]
    fn max_tokens_for_model_always_positive(model in "[a-zA-Z0-9._-]{1,50}") {
        let tokens = api::max_tokens_for_model(&model);
        prop_assert!(tokens > 0, "max_tokens should always be positive, got {tokens}");
    }

    #[test]
    fn max_tokens_with_override_respects_override(
        model in "[a-zA-Z0-9._-]{1,50}",
        override_val in 1u32..1_000_000u32,
    ) {
        let result = api::max_tokens_for_model_with_override(&model, Some(override_val));
        prop_assert_eq!(result, override_val);
    }

    #[test]
    fn max_tokens_without_override_matches_default(model in "[a-zA-Z0-9._-]{1,50}") {
        let default_val = api::max_tokens_for_model(&model);
        let result = api::max_tokens_for_model_with_override(&model, None);
        prop_assert_eq!(result, default_val);
    }

    #[test]
    fn is_reasoning_model_returns_bool(model in "[a-zA-Z0-9._-]{1,50}") {
        let _ = api::is_reasoning_model(&model);
    }

    #[test]
    fn model_rejects_is_error_returns_bool(model in "[a-zA-Z0-9._-]{1,50}") {
        let _ = api::model_rejects_is_error_field(&model);
    }

    #[test]
    fn flatten_tool_result_preserves_text(texts in prop::collection::vec("[a-zA-Z0-9 ]{0,100}", 0..20)) {
        let blocks: Vec<api::ToolResultContentBlock> = texts
            .iter()
            .map(|t| api::ToolResultContentBlock::Text { text: t.clone() })
            .collect();
        let result = api::flatten_tool_result_content(&blocks);
        for text in &texts {
            if !text.is_empty() {
                prop_assert!(result.contains(text.as_str()), "flattened result should contain '{text}'");
            }
        }
    }

    #[test]
    fn user_text_preserves_content(text in ".*{0,500}") {
        let msg = api::InputMessage::user_text(&text);
        prop_assert_eq!(msg.role, "user");
        prop_assert_eq!(msg.content.len(), 1);
    }

    #[test]
    fn usage_total_tokens_sums_all(
        input in 0u32..1_000_000u32,
        output in 0u32..1_000_000u32,
        cache_create in 0u32..1_000_000u32,
        cache_read in 0u32..1_000_000u32,
    ) {
        let usage = api::Usage {
            input_tokens: input,
            output_tokens: output,
            cache_creation_input_tokens: cache_create,
            cache_read_input_tokens: cache_read,
        };
        let total = usage.total_tokens();
        prop_assert_eq!(total, input + output + cache_create + cache_read);
    }
}

#[test]
fn flatten_tool_result_empty_when_no_blocks() {
    let blocks: Vec<api::ToolResultContentBlock> = vec![];
    let result = api::flatten_tool_result_content(&blocks);
    assert!(result.is_empty());
}
