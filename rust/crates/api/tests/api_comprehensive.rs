use api::{
    flatten_tool_result_content, is_reasoning_model, max_tokens_for_model,
    max_tokens_for_model_with_override, model_rejects_is_error_field, resolve_model_alias,
    build_chat_completion_request, OpenAiCompatConfig,
    ContentBlockDelta, ContentBlockDeltaEvent, ContentBlockStartEvent, ContentBlockStopEvent,
    InputContentBlock, InputMessage, MessageDelta, MessageDeltaEvent, MessageRequest,
    MessageStartEvent, MessageStopEvent, OutputContentBlock, StreamEvent, ToolChoice,
    ToolDefinition, ToolResultContentBlock, Usage,
};
use serde_json::json;

#[test]
fn resolve_opus_alias() {
    assert_eq!(resolve_model_alias("opus"), "claude-opus-4-6");
}

#[test]
fn resolve_sonnet_alias() {
    assert_eq!(resolve_model_alias("sonnet"), "claude-sonnet-4-6");
}

#[test]
fn resolve_haiku_alias() {
    assert_eq!(resolve_model_alias("haiku"), "claude-haiku-4-5-20251213");
}

#[test]
fn resolve_grok_alias() {
    assert_eq!(resolve_model_alias("grok"), "grok-3");
}

#[test]
fn resolve_grok_3_alias() {
    assert_eq!(resolve_model_alias("grok-3"), "grok-3");
}

#[test]
fn resolve_grok_mini_alias() {
    assert_eq!(resolve_model_alias("grok-mini"), "grok-3-mini");
}

#[test]
fn resolve_grok_2_alias() {
    assert_eq!(resolve_model_alias("grok-2"), "grok-2");
}

#[test]
fn resolve_deepseek_alias() {
    assert_eq!(resolve_model_alias("deepseek"), "deepseek-chat");
}

#[test]
fn resolve_deepseek_v3_alias() {
    assert_eq!(resolve_model_alias("deepseek-v3"), "deepseek-chat");
}

#[test]
fn resolve_deepseek_chat_alias() {
    assert_eq!(resolve_model_alias("deepseek-chat"), "deepseek-chat");
}

#[test]
fn resolve_deepseek_reasoner_alias() {
    assert_eq!(resolve_model_alias("deepseek-reasoner"), "deepseek-reasoner");
}

#[test]
fn resolve_r1_alias() {
    assert_eq!(resolve_model_alias("r1"), "deepseek-reasoner");
}

#[test]
fn resolve_deepseek_r1_alias() {
    assert_eq!(resolve_model_alias("deepseek-r1"), "deepseek-reasoner");
}

#[test]
fn resolve_deepseek_coder_alias() {
    assert_eq!(resolve_model_alias("deepseek-coder"), "deepseek-coder");
}

#[test]
fn resolve_kimi_alias() {
    assert_eq!(resolve_model_alias("kimi"), "kimi-k2.5");
}

#[test]
fn resolve_big_pickle_alias() {
    assert_eq!(resolve_model_alias("big-pickle"), "big-pickle");
}

#[test]
fn resolve_opencode_big_pickle_alias() {
    assert_eq!(resolve_model_alias("opencode/big-pickle"), "big-pickle");
}

#[test]
fn resolve_unknown_model_passthrough() {
    assert_eq!(resolve_model_alias("some-unknown-model"), "some-unknown-model");
}

#[test]
fn resolve_case_insensitive() {
    assert_eq!(resolve_model_alias("OPUS"), "claude-opus-4-6");
    assert_eq!(resolve_model_alias("Sonnet"), "claude-sonnet-4-6");
}

#[test]
fn resolve_trimmed_whitespace() {
    assert_eq!(resolve_model_alias("  grok  "), "grok-3");
}

#[test]
fn max_tokens_opus() {
    assert_eq!(max_tokens_for_model("opus"), 32_000);
}

#[test]
fn max_tokens_sonnet() {
    assert_eq!(max_tokens_for_model("sonnet"), 64_000);
}

#[test]
fn max_tokens_haiku() {
    assert_eq!(max_tokens_for_model("haiku"), 64_000);
}

#[test]
fn max_tokens_grok_3() {
    assert_eq!(max_tokens_for_model("grok-3"), 64_000);
}

#[test]
fn max_tokens_grok_3_mini() {
    assert_eq!(max_tokens_for_model("grok-3-mini"), 64_000);
}

#[test]
fn max_tokens_deepseek_chat() {
    assert_eq!(max_tokens_for_model("deepseek-chat"), 64_000);
}

#[test]
fn max_tokens_deepseek_coder() {
    assert_eq!(max_tokens_for_model("deepseek-coder"), 32_000);
}

#[test]
fn max_tokens_kimi() {
    assert_eq!(max_tokens_for_model("kimi"), 16_384);
}

#[test]
fn max_tokens_big_pickle() {
    assert_eq!(max_tokens_for_model("big-pickle"), 128_000);
}

#[test]
fn max_tokens_unknown_model() {
    assert_eq!(max_tokens_for_model("unknown-model"), 64_000);
}

#[test]
fn max_tokens_with_override_some() {
    assert_eq!(max_tokens_for_model_with_override("opus", Some(9999)), 9999);
}

#[test]
fn max_tokens_with_override_none() {
    assert_eq!(max_tokens_for_model_with_override("opus", None), 32_000);
}

#[test]
fn max_tokens_with_override_sonnet() {
    assert_eq!(max_tokens_for_model_with_override("sonnet", Some(1024)), 1024);
}

#[test]
fn max_tokens_with_override_zero() {
    assert_eq!(max_tokens_for_model_with_override("opus", Some(0)), 0);
}

#[test]
fn is_reasoning_model_o1() {
    assert!(is_reasoning_model("o1"));
}

#[test]
fn is_reasoning_model_o1_mini() {
    assert!(is_reasoning_model("o1-mini"));
}

#[test]
fn is_reasoning_model_o3_mini() {
    assert!(is_reasoning_model("o3-mini"));
}

#[test]
fn is_reasoning_model_o4_mini() {
    assert!(is_reasoning_model("o4-mini"));
}

#[test]
fn is_reasoning_model_grok_3_mini() {
    assert!(is_reasoning_model("grok-3-mini"));
}

#[test]
fn is_reasoning_model_qwen_qwq() {
    assert!(is_reasoning_model("qwen-qwq-32b"));
}

#[test]
fn is_reasoning_model_qwq() {
    assert!(is_reasoning_model("qwq-plus"));
}

#[test]
fn is_reasoning_model_thinking() {
    assert!(is_reasoning_model("qwen3-30b-a3b-thinking"));
}

#[test]
fn is_not_reasoning_model_gpt_4o() {
    assert!(!is_reasoning_model("gpt-4o"));
}

#[test]
fn is_not_reasoning_model_grok_3() {
    assert!(!is_reasoning_model("grok-3"));
}

#[test]
fn is_not_reasoning_model_sonnet() {
    assert!(!is_reasoning_model("claude-sonnet-4-6"));
}

#[test]
fn is_not_reasoning_model_deepseek() {
    assert!(!is_reasoning_model("deepseek-chat"));
}

#[test]
fn is_reasoning_model_with_prefix() {
    assert!(is_reasoning_model("qwen/qwen-qwq-32b"));
    assert!(!is_reasoning_model("qwen/qwen-plus"));
}

#[test]
fn model_rejects_is_error_kimi() {
    assert!(model_rejects_is_error_field("kimi-k2.5"));
    assert!(model_rejects_is_error_field("kimi-k1.5"));
}

#[test]
fn model_rejects_is_error_kimi_with_prefix() {
    assert!(model_rejects_is_error_field("dashscope/kimi-k2.5"));
}

#[test]
fn model_rejects_is_error_gpt_4o() {
    assert!(!model_rejects_is_error_field("gpt-4o"));
}

#[test]
fn model_rejects_is_error_claude() {
    assert!(!model_rejects_is_error_field("claude-sonnet-4-6"));
}

#[test]
fn model_rejects_is_error_grok() {
    assert!(!model_rejects_is_error_field("grok-3"));
}

#[test]
fn flatten_tool_result_single_text() {
    let content = vec![ToolResultContentBlock::Text {
        text: "hello".to_string(),
    }];
    assert_eq!(flatten_tool_result_content(&content), "hello");
}

#[test]
fn flatten_tool_result_multiple_text() {
    let content = vec![
        ToolResultContentBlock::Text {
            text: "a".to_string(),
        },
        ToolResultContentBlock::Text {
            text: "b".to_string(),
        },
    ];
    assert_eq!(flatten_tool_result_content(&content), "a\nb");
}

#[test]
fn flatten_tool_result_json() {
    let content = vec![ToolResultContentBlock::Json {
        value: json!({"key": "val"}),
    }];
    let result = flatten_tool_result_content(&content);
    assert!(result.contains("key"));
    assert!(result.contains("val"));
}

#[test]
fn flatten_tool_result_mixed() {
    let content = vec![
        ToolResultContentBlock::Text {
            text: "text".to_string(),
        },
        ToolResultContentBlock::Json {
            value: json!({"n": 1}),
        },
    ];
    let result = flatten_tool_result_content(&content);
    assert!(result.contains("text"));
    assert!(result.contains('n'));
}

#[test]
fn flatten_tool_result_empty() {
    let content: Vec<ToolResultContentBlock> = vec![];
    assert_eq!(flatten_tool_result_content(&content), "");
}

#[test]
fn input_message_user_text() {
    let msg = InputMessage::user_text("Hello");
    assert_eq!(msg.role, "user");
    assert_eq!(msg.content.len(), 1);
    match &msg.content[0] {
        InputContentBlock::Text { text } => assert_eq!(text, "Hello"),
        _ => panic!("expected Text block"),
    }
}

#[test]
fn input_message_user_tool_result() {
    let msg = InputMessage::user_tool_result("tool_1", "result", true);
    assert_eq!(msg.role, "user");
    assert_eq!(msg.content.len(), 1);
    match &msg.content[0] {
        InputContentBlock::ToolResult {
            tool_use_id,
            is_error,
            ..
        } => {
            assert_eq!(tool_use_id, "tool_1");
            assert!(*is_error);
        }
        _ => panic!("expected ToolResult block"),
    }
}

#[test]
fn input_message_user_tool_result_not_error() {
    let msg = InputMessage::user_tool_result("t1", "ok", false);
    match &msg.content[0] {
        InputContentBlock::ToolResult { is_error, .. } => assert!(!is_error),
        _ => panic!("expected ToolResult"),
    }
}

#[test]
fn message_request_default() {
    let req = MessageRequest::default();
    assert_eq!(req.model, "");
    assert_eq!(req.max_tokens, 0);
    assert!(req.messages.is_empty());
    assert!(req.system.is_none());
    assert!(req.tools.is_none());
    assert!(!req.stream);
}

#[test]
fn message_request_with_streaming() {
    let req = MessageRequest::default().with_streaming();
    assert!(req.stream);
}

#[test]
fn message_request_serde_roundtrip() {
    let req = MessageRequest {
        model: "gpt-4o".to_string(),
        max_tokens: 1024,
        messages: vec![InputMessage::user_text("hi")],
        system: Some("be helpful".to_string()),
        stream: true,
        temperature: Some(0.7),
        ..Default::default()
    };
    let json = serde_json::to_string(&req).unwrap();
    let deserialized: MessageRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, deserialized);
}

#[test]
fn message_request_skip_stream_false() {
    let req = MessageRequest {
        stream: false,
        ..Default::default()
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(!json.contains("stream"));
}

#[test]
fn message_request_skip_none_fields() {
    let req = MessageRequest::default();
    let json = serde_json::to_string(&req).unwrap();
    assert!(!json.contains("system"));
    assert!(!json.contains("tools"));
    assert!(!json.contains("temperature"));
}

#[test]
fn message_request_with_tools_serde() {
    let req = MessageRequest {
        model: "gpt-4o".to_string(),
        max_tokens: 100,
        messages: vec![],
        tools: Some(vec![ToolDefinition {
            name: "weather".to_string(),
            description: Some("Get weather".to_string()),
            input_schema: json!({"type": "object"}),
        }]),
        ..Default::default()
    };
    let json = serde_json::to_string(&req).unwrap();
    let deserialized: MessageRequest = serde_json::from_str(&json).unwrap();
    assert!(deserialized.tools.is_some());
    assert_eq!(deserialized.tools.unwrap().len(), 1);
}

#[test]
fn input_message_serde_roundtrip() {
    let msg = InputMessage::user_text("test");
    let json = serde_json::to_string(&msg).unwrap();
    let deserialized: InputMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(msg, deserialized);
}

#[test]
fn input_content_block_text_serde() {
    let block = InputContentBlock::Text {
        text: "hello".to_string(),
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: InputContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn input_content_block_tool_use_serde() {
    let block = InputContentBlock::ToolUse {
        id: "call_1".to_string(),
        name: "tool_name".to_string(),
        input: json!({"arg": "val"}),
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: InputContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn input_content_block_tool_result_serde() {
    let block = InputContentBlock::ToolResult {
        tool_use_id: "t1".to_string(),
        content: vec![ToolResultContentBlock::Text {
            text: "ok".to_string(),
        }],
        is_error: false,
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: InputContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn usage_default() {
    let usage = Usage::default();
    assert_eq!(usage.input_tokens, 0);
    assert_eq!(usage.output_tokens, 0);
    assert_eq!(usage.cache_creation_input_tokens, 0);
    assert_eq!(usage.cache_read_input_tokens, 0);
}

#[test]
fn usage_total_tokens() {
    let usage = Usage {
        input_tokens: 100,
        output_tokens: 50,
        cache_creation_input_tokens: 10,
        cache_read_input_tokens: 20,
    };
    assert_eq!(usage.total_tokens(), 180);
}

#[test]
fn usage_serde_roundtrip() {
    let usage = Usage {
        input_tokens: 100,
        output_tokens: 200,
        cache_creation_input_tokens: 30,
        cache_read_input_tokens: 40,
    };
    let json = serde_json::to_string(&usage).unwrap();
    let deserialized: Usage = serde_json::from_str(&json).unwrap();
    assert_eq!(usage, deserialized);
}

#[test]
fn usage_serde_default_fields() {
    let json = "{}";
    let usage: Usage = serde_json::from_str(json).unwrap();
    assert_eq!(usage, Usage::default());
}

#[test]
fn usage_cost_estimate() {
    let usage = Usage {
        input_tokens: 1000,
        output_tokens: 500,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    };
    let cost = usage.estimated_cost_usd("gpt-4o");
    assert!(cost.total_cost_usd() >= 0.0);
}

#[test]
fn tool_choice_auto_serde() {
    let tc = ToolChoice::Auto;
    let json = serde_json::to_string(&tc).unwrap();
    let deserialized: ToolChoice = serde_json::from_str(&json).unwrap();
    assert_eq!(tc, deserialized);
}

#[test]
fn tool_choice_any_serde() {
    let tc = ToolChoice::Any;
    let json = serde_json::to_string(&tc).unwrap();
    let deserialized: ToolChoice = serde_json::from_str(&json).unwrap();
    assert_eq!(tc, deserialized);
}

#[test]
fn tool_choice_tool_serde() {
    let tc = ToolChoice::Tool {
        name: "weather".to_string(),
    };
    let json = serde_json::to_string(&tc).unwrap();
    let deserialized: ToolChoice = serde_json::from_str(&json).unwrap();
    assert_eq!(tc, deserialized);
}

#[test]
fn tool_choice_not_equal_variants() {
    assert_ne!(ToolChoice::Auto, ToolChoice::Any);
    assert_ne!(
        ToolChoice::Auto,
        ToolChoice::Tool {
            name: "x".to_string()
        }
    );
}

#[test]
fn tool_definition_serde() {
    let td = ToolDefinition {
        name: "calc".to_string(),
        description: Some("Calculator".to_string()),
        input_schema: json!({"type": "object"}),
    };
    let json = serde_json::to_string(&td).unwrap();
    let deserialized: ToolDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(td, deserialized);
}

#[test]
fn tool_definition_no_description() {
    let td = ToolDefinition {
        name: "t".to_string(),
        description: None,
        input_schema: json!({}),
    };
    let json = serde_json::to_string(&td).unwrap();
    assert!(!json.contains("description"));
}

#[test]
fn tool_result_content_block_text_serde() {
    let block = ToolResultContentBlock::Text {
        text: "result".to_string(),
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: ToolResultContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn tool_result_content_block_json_serde() {
    let block = ToolResultContentBlock::Json {
        value: json!({"ok": true}),
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: ToolResultContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn output_content_block_text_serde() {
    let block = OutputContentBlock::Text {
        text: "hello".to_string(),
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: OutputContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn output_content_block_tool_use_serde() {
    let block = OutputContentBlock::ToolUse {
        id: "call_1".to_string(),
        name: "tool".to_string(),
        input: json!({}),
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: OutputContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn output_content_block_thinking_serde() {
    let block = OutputContentBlock::Thinking {
        thinking: "reasoning".to_string(),
        signature: Some("sig".to_string()),
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: OutputContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn output_content_block_thinking_no_sig() {
    let block = OutputContentBlock::Thinking {
        thinking: "thought".to_string(),
        signature: None,
    };
    let json = serde_json::to_string(&block).unwrap();
    assert!(!json.contains("signature"));
}

#[test]
fn output_content_block_redacted_thinking_serde() {
    let block = OutputContentBlock::RedactedThinking {
        data: json!({"encrypted": "data"}),
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: OutputContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn content_block_delta_text_serde() {
    let delta = ContentBlockDelta::TextDelta {
        text: "hello".to_string(),
    };
    let json = serde_json::to_string(&delta).unwrap();
    let deserialized: ContentBlockDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(delta, deserialized);
}

#[test]
fn content_block_delta_input_json_serde() {
    let delta = ContentBlockDelta::InputJsonDelta {
        partial_json: "{\"key".to_string(),
    };
    let json = serde_json::to_string(&delta).unwrap();
    let deserialized: ContentBlockDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(delta, deserialized);
}

#[test]
fn content_block_delta_thinking_serde() {
    let delta = ContentBlockDelta::ThinkingDelta {
        thinking: "thought".to_string(),
    };
    let json = serde_json::to_string(&delta).unwrap();
    let deserialized: ContentBlockDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(delta, deserialized);
}

#[test]
fn content_block_delta_signature_serde() {
    let delta = ContentBlockDelta::SignatureDelta {
        signature: "sig123".to_string(),
    };
    let json = serde_json::to_string(&delta).unwrap();
    let deserialized: ContentBlockDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(delta, deserialized);
}

#[test]
fn content_block_start_event_serde() {
    let event = ContentBlockStartEvent {
        index: 0,
        content_block: OutputContentBlock::Text {
            text: String::new(),
        },
    };
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: ContentBlockStartEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn content_block_stop_event_serde() {
    let event = ContentBlockStopEvent { index: 1 };
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: ContentBlockStopEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn content_block_delta_event_serde() {
    let event = ContentBlockDeltaEvent {
        index: 0,
        delta: ContentBlockDelta::TextDelta {
            text: "chunk".to_string(),
        },
    };
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: ContentBlockDeltaEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn message_start_event_serde() {
    let event = MessageStartEvent {
        message: api::MessageResponse {
            id: "msg_1".to_string(),
            kind: "message".to_string(),
            role: "assistant".to_string(),
            content: vec![],
            model: "gpt-4o".to_string(),
            stop_reason: None,
            stop_sequence: None,
            usage: Usage::default(),
            request_id: None,
        },
    };
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: MessageStartEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event.message.id, deserialized.message.id);
}

#[test]
fn message_delta_event_serde() {
    let event = MessageDeltaEvent {
        delta: MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
        },
        usage: Usage::default(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: MessageDeltaEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(
        event.delta.stop_reason,
        deserialized.delta.stop_reason
    );
}

#[test]
fn message_stop_event_serde() {
    let event = MessageStopEvent {};
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: MessageStopEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn stream_event_message_start_serde() {
    let event = StreamEvent::MessageStart(MessageStartEvent {
        message: api::MessageResponse {
            id: "m".to_string(),
            kind: "message".to_string(),
            role: "assistant".to_string(),
            content: vec![],
            model: "gpt-4o".to_string(),
            stop_reason: None,
            stop_sequence: None,
            usage: Usage::default(),
            request_id: None,
        },
    });
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: StreamEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, StreamEvent::MessageStart(_)));
}

#[test]
fn stream_event_message_stop_serde() {
    let event = StreamEvent::MessageStop(MessageStopEvent {});
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: StreamEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, StreamEvent::MessageStop(_)));
}

#[test]
fn stream_event_content_block_start_serde() {
    let event = StreamEvent::ContentBlockStart(ContentBlockStartEvent {
        index: 0,
        content_block: OutputContentBlock::Text {
            text: String::new(),
        },
    });
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: StreamEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, StreamEvent::ContentBlockStart(_)));
}

#[test]
fn stream_event_content_block_stop_serde() {
    let event = StreamEvent::ContentBlockStop(ContentBlockStopEvent { index: 0 });
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: StreamEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, StreamEvent::ContentBlockStop(_)));
}

#[test]
fn stream_event_content_block_delta_serde() {
    let event = StreamEvent::ContentBlockDelta(ContentBlockDeltaEvent {
        index: 0,
        delta: ContentBlockDelta::TextDelta {
            text: "hi".to_string(),
        },
    });
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: StreamEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(
        deserialized,
        StreamEvent::ContentBlockDelta(_)
    ));
}

#[test]
fn stream_event_message_delta_serde() {
    let event = StreamEvent::MessageDelta(MessageDeltaEvent {
        delta: MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
        },
        usage: Usage::default(),
    });
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: StreamEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized, StreamEvent::MessageDelta(_)));
}

#[test]
fn message_response_total_tokens() {
    let resp = api::MessageResponse {
        id: "m1".to_string(),
        kind: "message".to_string(),
        role: "assistant".to_string(),
        content: vec![],
        model: "gpt-4o".to_string(),
        stop_reason: None,
        stop_sequence: None,
        usage: Usage {
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 10,
            cache_read_input_tokens: 20,
        },
        request_id: None,
    };
    assert_eq!(resp.total_tokens(), 180);
}

#[test]
fn message_response_serde_roundtrip() {
    let resp = api::MessageResponse {
        id: "msg_123".to_string(),
        kind: "message".to_string(),
        role: "assistant".to_string(),
        content: vec![OutputContentBlock::Text {
            text: "hello".to_string(),
        }],
        model: "gpt-4o".to_string(),
        stop_reason: Some("end_turn".to_string()),
        stop_sequence: None,
        usage: Usage {
            input_tokens: 10,
            output_tokens: 20,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        },
        request_id: Some("req_abc".to_string()),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deserialized: api::MessageResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, deserialized);
}

#[test]
fn message_response_default_fields() {
    let json = r#"{"id":"m","type":"message","role":"assistant","content":[],"model":"gpt-4o"}"#;
    let resp: api::MessageResponse = serde_json::from_str(json).unwrap();
    assert!(resp.stop_reason.is_none());
    assert!(resp.stop_sequence.is_none());
    assert_eq!(resp.usage, Usage::default());
    assert!(resp.request_id.is_none());
}

#[test]
fn input_image_source_serde() {
    let src = api::ImageSource {
        source_type: "base64".to_string(),
        media_type: "image/png".to_string(),
        data: "iVBOR...".to_string(),
    };
    let json = serde_json::to_string(&src).unwrap();
    assert!(json.contains("type"));
    let deserialized: api::ImageSource = serde_json::from_str(&json).unwrap();
    assert_eq!(src, deserialized);
}

#[test]
fn input_content_block_image_serde() {
    let block = InputContentBlock::Image {
        source: api::ImageSource {
            source_type: "base64".to_string(),
            media_type: "image/png".to_string(),
            data: "abc123".to_string(),
        },
    };
    let json = serde_json::to_string(&block).unwrap();
    let deserialized: InputContentBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, deserialized);
}

#[test]
fn openai_compat_config_xai() {
    let config = OpenAiCompatConfig::xai();
    assert_eq!(config.provider_name, "xAI");
    assert_eq!(config.api_key_env, "XAI_API_KEY");
}

#[test]
fn openai_compat_config_openai() {
    let config = OpenAiCompatConfig::openai();
    assert_eq!(config.provider_name, "OpenAI");
    assert_eq!(config.api_key_env, "OPENAI_API_KEY");
}

#[test]
fn openai_compat_config_dashscope() {
    let config = OpenAiCompatConfig::dashscope();
    assert_eq!(config.provider_name, "DashScope");
    assert_eq!(config.api_key_env, "DASHSCOPE_API_KEY");
}

#[test]
fn openai_compat_config_deepseek() {
    let config = OpenAiCompatConfig::deepseek();
    assert_eq!(config.provider_name, "DeepSeek");
    assert_eq!(config.api_key_env, "DEEPSEEK_API_KEY");
}

#[test]
fn openai_compat_config_opencode() {
    let config = OpenAiCompatConfig::opencode();
    assert_eq!(config.provider_name, "OpenCode");
    assert_eq!(config.api_key_env, "OPENCODE_API_KEY");
}

#[test]
fn message_delta_serde_roundtrip() {
    let delta = MessageDelta {
        stop_reason: Some("tool_use".to_string()),
        stop_sequence: None,
    };
    let json = serde_json::to_string(&delta).unwrap();
    let deserialized: MessageDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(delta, deserialized);
}

#[test]
fn message_delta_no_stop_reason() {
    let delta = MessageDelta {
        stop_reason: None,
        stop_sequence: None,
    };
    let json = serde_json::to_string(&delta).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(val["stop_reason"], serde_json::Value::Null);
}

#[test]
fn message_request_with_all_tuning_params() {
    let req = MessageRequest {
        model: "gpt-4o".to_string(),
        max_tokens: 512,
        messages: vec![],
        temperature: Some(0.5),
        top_p: Some(0.9),
        frequency_penalty: Some(0.1),
        presence_penalty: Some(0.2),
        stop: Some(vec!["STOP".to_string()]),
        reasoning_effort: None,
        ..Default::default()
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("temperature"));
    assert!(json.contains("top_p"));
    assert!(json.contains("frequency_penalty"));
    assert!(json.contains("presence_penalty"));
    assert!(json.contains("stop"));
}

#[test]
fn build_request_adds_system_message() {
    let req = MessageRequest {
        model: "gpt-4o".to_string(),
        max_tokens: 100,
        messages: vec![InputMessage::user_text("hi")],
        system: Some("system prompt".to_string()),
        ..Default::default()
    };
    let payload = build_chat_completion_request(&req, OpenAiCompatConfig::openai());
    assert_eq!(payload["messages"][0]["role"], "system");
    assert_eq!(payload["messages"][0]["content"], "system prompt");
}

#[test]
fn build_request_empty_system_omitted() {
    let req = MessageRequest {
        model: "gpt-4o".to_string(),
        max_tokens: 100,
        messages: vec![InputMessage::user_text("hi")],
        system: Some(String::new()),
        ..Default::default()
    };
    let payload = build_chat_completion_request(&req, OpenAiCompatConfig::openai());
    for msg in payload["messages"].as_array().unwrap() {
        assert_ne!(msg["role"], "system");
    }
}

#[test]
fn build_request_tool_choice_auto() {
    let req = MessageRequest {
        model: "gpt-4o".to_string(),
        max_tokens: 100,
        messages: vec![],
        tool_choice: Some(ToolChoice::Auto),
        ..Default::default()
    };
    let payload = build_chat_completion_request(&req, OpenAiCompatConfig::openai());
    assert_eq!(payload["tool_choice"], "auto");
}

#[test]
fn build_request_tool_choice_any() {
    let req = MessageRequest {
        model: "gpt-4o".to_string(),
        max_tokens: 100,
        messages: vec![],
        tool_choice: Some(ToolChoice::Any),
        ..Default::default()
    };
    let payload = build_chat_completion_request(&req, OpenAiCompatConfig::openai());
    assert_eq!(payload["tool_choice"], "required");
}

#[test]
fn build_request_tool_choice_specific() {
    let req = MessageRequest {
        model: "gpt-4o".to_string(),
        max_tokens: 100,
        messages: vec![],
        tool_choice: Some(ToolChoice::Tool {
            name: "weather".to_string(),
        }),
        ..Default::default()
    };
    let payload = build_chat_completion_request(&req, OpenAiCompatConfig::openai());
    assert_eq!(payload["tool_choice"]["type"], "function");
    assert_eq!(payload["tool_choice"]["function"]["name"], "weather");
}

#[test]
fn build_request_strip_routing_prefix() {
    let req = MessageRequest {
        model: "openai/gpt-4o".to_string(),
        max_tokens: 100,
        messages: vec![],
        ..Default::default()
    };
    let payload = build_chat_completion_request(&req, OpenAiCompatConfig::openai());
    assert_eq!(payload["model"], "gpt-4o");
}

#[test]
fn build_request_strips_qwen_prefix() {
    let req = MessageRequest {
        model: "qwen/qwen-plus".to_string(),
        max_tokens: 100,
        messages: vec![],
        ..Default::default()
    };
    let payload = build_chat_completion_request(&req, OpenAiCompatConfig::dashscope());
    assert_eq!(payload["model"], "qwen-plus");
}

#[test]
fn message_request_clone() {
    let req = MessageRequest {
        model: "gpt-4o".to_string(),
        max_tokens: 100,
        messages: vec![InputMessage::user_text("hi")],
        ..Default::default()
    };
    let cloned = req.clone();
    assert_eq!(req, cloned);
}

#[test]
fn input_message_clone() {
    let msg = InputMessage::user_text("test");
    let cloned = msg.clone();
    assert_eq!(msg, cloned);
}

#[test]
fn usage_token_usage() {
    let usage = Usage {
        input_tokens: 10,
        output_tokens: 20,
        cache_creation_input_tokens: 5,
        cache_read_input_tokens: 3,
    };
    let tu = usage.token_usage();
    assert_eq!(tu.input_tokens, 10);
    assert_eq!(tu.output_tokens, 20);
}

#[test]
fn flatten_single_json_block() {
    let content = vec![ToolResultContentBlock::Json {
        value: json!([1, 2, 3]),
    }];
    let result = flatten_tool_result_content(&content);
    assert!(result.contains('1'));
}

#[test]
fn message_request_max_tokens_zero() {
    let req = MessageRequest {
        max_tokens: 0,
        ..Default::default()
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"max_tokens\":0"));
}

#[test]
fn stream_event_all_variants_roundtrip() {
    let events = vec![
        StreamEvent::MessageStart(MessageStartEvent {
            message: api::MessageResponse {
                id: "m".to_string(),
                kind: "message".to_string(),
                role: "assistant".to_string(),
                content: vec![],
                model: "gpt-4o".to_string(),
                stop_reason: None,
                stop_sequence: None,
                usage: Usage::default(),
                request_id: None,
            },
        }),
        StreamEvent::MessageDelta(MessageDeltaEvent {
            delta: MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
            },
            usage: Usage::default(),
        }),
        StreamEvent::ContentBlockStart(ContentBlockStartEvent {
            index: 0,
            content_block: OutputContentBlock::Text {
                text: String::new(),
            },
        }),
        StreamEvent::ContentBlockDelta(ContentBlockDeltaEvent {
            index: 0,
            delta: ContentBlockDelta::TextDelta {
                text: "hi".to_string(),
            },
        }),
        StreamEvent::ContentBlockStop(ContentBlockStopEvent { index: 0 }),
        StreamEvent::MessageStop(MessageStopEvent {}),
    ];
    for event in events {
        let json = serde_json::to_string(&event).unwrap();
        let _: StreamEvent = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn input_content_block_all_variants_serde() {
    let blocks = vec![
        InputContentBlock::Text {
            text: "t".to_string(),
        },
        InputContentBlock::ToolUse {
            id: "id".to_string(),
            name: "n".to_string(),
            input: json!({}),
        },
        InputContentBlock::ToolResult {
            tool_use_id: "t1".to_string(),
            content: vec![ToolResultContentBlock::Text {
                text: "r".to_string(),
            }],
            is_error: false,
        },
        InputContentBlock::Image {
            source: api::ImageSource {
                source_type: "base64".to_string(),
                media_type: "image/png".to_string(),
                data: "d".to_string(),
            },
        },
    ];
    for block in blocks {
        let json = serde_json::to_string(&block).unwrap();
        let _: InputContentBlock = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn content_block_delta_all_variants_serde() {
    let deltas = vec![
        ContentBlockDelta::TextDelta {
            text: "t".to_string(),
        },
        ContentBlockDelta::InputJsonDelta {
            partial_json: "p".to_string(),
        },
        ContentBlockDelta::ThinkingDelta {
            thinking: "t".to_string(),
        },
        ContentBlockDelta::SignatureDelta {
            signature: "s".to_string(),
        },
    ];
    for delta in deltas {
        let json = serde_json::to_string(&delta).unwrap();
        let _: ContentBlockDelta = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn max_tokens_deepseek_reasoner() {
    assert_eq!(max_tokens_for_model("deepseek-reasoner"), 64_000);
}

#[test]
fn max_tokens_kimi_k25() {
    assert_eq!(max_tokens_for_model("kimi-k2.5"), 16_384);
}

#[test]
fn is_reasoning_model_case_insensitive() {
    assert!(is_reasoning_model("O1"));
    assert!(is_reasoning_model("O3-MINI"));
    assert!(!is_reasoning_model("GPT-4O"));
}

#[test]
fn flatten_tool_result_three_blocks() {
    let content = vec![
        ToolResultContentBlock::Text {
            text: "a".to_string(),
        },
        ToolResultContentBlock::Text {
            text: "b".to_string(),
        },
        ToolResultContentBlock::Text {
            text: "c".to_string(),
        },
    ];
    assert_eq!(flatten_tool_result_content(&content), "a\nb\nc");
}
