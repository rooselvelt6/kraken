use api::{
    build_chat_completion_request, ContentBlockDelta, ContentBlockDeltaEvent,
    ContentBlockStartEvent, ContentBlockStopEvent, flatten_tool_result_content, ImageSource,
    InputContentBlock, InputMessage, is_reasoning_model,
    max_tokens_for_model, max_tokens_for_model_with_override,
    MessageDelta, MessageDeltaEvent, MessageRequest, MessageResponse, MessageStartEvent,
    MessageStopEvent, model_rejects_is_error_field, OutputContentBlock, parse_frame, ProxyConfig,
    ProviderKind, resolve_model_alias, SseParser, StreamEvent, ToolChoice, ToolDefinition,
    ToolResultContentBlock, translate_message, Usage,
};
use serde_json::{json, Value};

// ─── helpers ────────────────────────────────────────────────────────────────

fn sample_message_request() -> MessageRequest {
    MessageRequest {
        model: "claude-sonnet-4-6".to_string(),
        max_tokens: 1024,
        messages: vec![InputMessage::user_text("hello")],
        system: Some("sys".to_string()),
        tools: None,
        tool_choice: None,
        stream: false,
        ..Default::default()
    }
}

fn sample_message_response() -> MessageResponse {
    MessageResponse {
        id: "msg_1".to_string(),
        kind: "message".to_string(),
        role: "assistant".to_string(),
        content: vec![OutputContentBlock::Text {
            text: "hi".to_string(),
        }],
        model: "claude-sonnet-4-6".to_string(),
        stop_reason: Some("end_turn".to_string()),
        stop_sequence: None,
        usage: Usage {
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 10,
            cache_read_input_tokens: 20,
        },
        request_id: None,
    }
}

// ─── Usage ──────────────────────────────────────────────────────────────────

#[test]
fn usage_total_tokens_basic() {
    let u = Usage {
        input_tokens: 10,
        output_tokens: 20,
        cache_creation_input_tokens: 5,
        cache_read_input_tokens: 15,
    };
    assert_eq!(u.total_tokens(), 50);
}

#[test]
fn usage_total_tokens_zero() {
    assert_eq!(Usage::default().total_tokens(), 0);
}

#[test]
fn usage_token_usage_field_mapping() {
    let u = Usage {
        input_tokens: 1,
        output_tokens: 2,
        cache_creation_input_tokens: 3,
        cache_read_input_tokens: 4,
    };
    let tu = u.token_usage();
    assert_eq!(tu.input_tokens, 1);
    assert_eq!(tu.output_tokens, 2);
    assert_eq!(tu.cache_creation_input_tokens, 3);
    assert_eq!(tu.cache_read_input_tokens, 4);
}

#[test]
fn usage_serde_roundtrip() {
    let u = Usage {
        input_tokens: 10,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
        output_tokens: 20,
    };
    let json = serde_json::to_string(&u).unwrap();
    let back: Usage = serde_json::from_str(&json).unwrap();
    assert_eq!(u, back);
}

#[test]
fn usage_default_is_all_zero() {
    let u = Usage::default();
    assert_eq!(u.input_tokens, 0);
    assert_eq!(u.output_tokens, 0);
    assert_eq!(u.cache_creation_input_tokens, 0);
    assert_eq!(u.cache_read_input_tokens, 0);
}

#[test]
fn usage_deserialize_missing_fields_defaults() {
    let u: Usage = serde_json::from_str("{}").unwrap();
    assert_eq!(u, Usage::default());
}

// ─── MessageRequest ─────────────────────────────────────────────────────────

#[test]
fn message_request_default() {
    let r = MessageRequest::default();
    assert_eq!(r.model, "");
    assert_eq!(r.max_tokens, 0);
    assert!(r.messages.is_empty());
    assert!(!r.stream);
}

#[test]
fn message_request_with_streaming() {
    let r = MessageRequest::default().with_streaming();
    assert!(r.stream);
}

#[test]
fn message_request_serde_omits_none_fields() {
    let r = MessageRequest {
        model: "m".to_string(),
        max_tokens: 10,
        messages: vec![],
        system: None,
        tools: None,
        tool_choice: None,
        stream: false,
        temperature: None,
        top_p: None,
        frequency_penalty: None,
        presence_penalty: None,
        stop: None,
        reasoning_effort: None,
    };
    let json = serde_json::to_value(&r).unwrap();
    assert!(json.get("system").is_none());
    assert!(json.get("tools").is_none());
    assert!(json.get("tool_choice").is_none());
    assert!(json.get("temperature").is_none());
    assert!(json.get("top_p").is_none());
    assert!(json.get("stop").is_none());
    assert!(json.get("reasoning_effort").is_none());
}

#[test]
fn message_request_stream_false_omitted() {
    let r = MessageRequest {
        stream: false,
        ..sample_message_request()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert!(json.get("stream").is_none());
}

#[test]
fn message_request_with_temperature() {
    let r = MessageRequest {
        temperature: Some(0.5),
        ..sample_message_request()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["temperature"], json!(0.5));
}

#[test]
fn message_request_with_top_p() {
    let r = MessageRequest {
        top_p: Some(0.9),
        ..sample_message_request()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["top_p"], json!(0.9));
}

#[test]
fn message_request_with_frequency_penalty() {
    let r = MessageRequest {
        frequency_penalty: Some(0.1),
        ..sample_message_request()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["frequency_penalty"], json!(0.1));
}

#[test]
fn message_request_with_presence_penalty() {
    let r = MessageRequest {
        presence_penalty: Some(0.2),
        ..sample_message_request()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["presence_penalty"], json!(0.2));
}

#[test]
fn message_request_with_stop() {
    let r = MessageRequest {
        stop: Some(vec!["STOP".to_string()]),
        ..sample_message_request()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["stop"], json!(["STOP"]));
}

#[test]
fn message_request_with_reasoning_effort() {
    let r = MessageRequest {
        reasoning_effort: Some("high".to_string()),
        ..sample_message_request()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["reasoning_effort"], json!("high"));
}

#[test]
fn message_request_serde_roundtrip() {
    let r = sample_message_request();
    let json = serde_json::to_string(&r).unwrap();
    let back: MessageRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ─── InputMessage ───────────────────────────────────────────────────────────

#[test]
fn input_message_user_text() {
    let m = InputMessage::user_text("hi");
    assert_eq!(m.role, "user");
    assert_eq!(m.content.len(), 1);
    match &m.content[0] {
        InputContentBlock::Text { text } => assert_eq!(text, "hi"),
        _ => panic!("expected Text block"),
    }
}

#[test]
fn input_message_user_tool_result() {
    let m = InputMessage::user_tool_result("id1", "err", true);
    assert_eq!(m.role, "user");
    match &m.content[0] {
        InputContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => {
            assert_eq!(tool_use_id, "id1");
            assert!(*is_error);
            assert_eq!(content.len(), 1);
            match &content[0] {
                ToolResultContentBlock::Text { text } => assert_eq!(text, "err"),
                _ => panic!("expected Text inside ToolResult"),
            }
        }
        _ => panic!("expected ToolResult block"),
    }
}

#[test]
fn input_message_user_tool_result_not_error() {
    let m = InputMessage::user_tool_result("id2", "ok", false);
    match &m.content[0] {
        InputContentBlock::ToolResult { is_error, .. } => assert!(!is_error),
        _ => panic!("expected ToolResult"),
    }
}

#[test]
fn input_message_serde_roundtrip() {
    let m = InputMessage::user_text("test");
    let json = serde_json::to_string(&m).unwrap();
    let back: InputMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ─── InputContentBlock ──────────────────────────────────────────────────────

#[test]
fn input_content_block_text_serde() {
    let block = InputContentBlock::Text {
        text: "hello".to_string(),
    };
    let json = serde_json::to_value(&block).unwrap();
    assert_eq!(json["type"], "text");
    assert_eq!(json["text"], "hello");
    let back: InputContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(block, back);
}

#[test]
fn input_content_block_tool_use_serde() {
    let block = InputContentBlock::ToolUse {
        id: "tu_1".to_string(),
        name: "weather".to_string(),
        input: json!({"city": "NYC"}),
    };
    let json = serde_json::to_value(&block).unwrap();
    assert_eq!(json["type"], "tool_use");
    assert_eq!(json["id"], "tu_1");
    let back: InputContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(block, back);
}

#[test]
fn input_content_block_tool_result_serde() {
    let block = InputContentBlock::ToolResult {
        tool_use_id: "tu_1".to_string(),
        content: vec![ToolResultContentBlock::Text {
            text: "result".to_string(),
        }],
        is_error: false,
    };
    let json = serde_json::to_value(&block).unwrap();
    assert_eq!(json["type"], "tool_result");
    assert_eq!(json["tool_use_id"], "tu_1");
    let back: InputContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(block, back);
}

#[test]
fn input_content_block_image_serde() {
    let block = InputContentBlock::Image {
        source: ImageSource {
            source_type: "base64".to_string(),
            media_type: "image/png".to_string(),
            data: "abc123".to_string(),
        },
    };
    let json = serde_json::to_value(&block).unwrap();
    assert_eq!(json["type"], "image");
    assert_eq!(json["source"]["type"], "base64");
    let back: InputContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(block, back);
}

#[test]
fn input_content_block_tool_result_is_error_omitted_when_false() {
    let block = InputContentBlock::ToolResult {
        tool_use_id: "id".to_string(),
        content: vec![],
        is_error: false,
    };
    let json = serde_json::to_value(&block).unwrap();
    assert!(json.get("is_error").is_none());
}

#[test]
fn input_content_block_tool_result_is_error_present_when_true() {
    let block = InputContentBlock::ToolResult {
        tool_use_id: "id".to_string(),
        content: vec![],
        is_error: true,
    };
    let json = serde_json::to_value(&block).unwrap();
    assert_eq!(json["is_error"], true);
}

// ─── ToolResultContentBlock ─────────────────────────────────────────────────

#[test]
fn tool_result_content_text_serde() {
    let b = ToolResultContentBlock::Text {
        text: "t".to_string(),
    };
    let json = serde_json::to_value(&b).unwrap();
    assert_eq!(json["type"], "text");
    let back: ToolResultContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn tool_result_content_json_serde() {
    let b = ToolResultContentBlock::Json {
        value: json!({"k": "v"}),
    };
    let json = serde_json::to_value(&b).unwrap();
    assert_eq!(json["type"], "json");
    let back: ToolResultContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(b, back);
}

// ─── ToolDefinition ─────────────────────────────────────────────────────────

#[test]
fn tool_definition_serde() {
    let td = ToolDefinition {
        name: "calc".to_string(),
        description: Some("does math".to_string()),
        input_schema: json!({"type": "object"}),
    };
    let json = serde_json::to_value(&td).unwrap();
    assert_eq!(json["name"], "calc");
    assert_eq!(json["description"], "does math");
    let back: ToolDefinition = serde_json::from_value(json).unwrap();
    assert_eq!(td, back);
}

#[test]
fn tool_definition_description_omitted_when_none() {
    let td = ToolDefinition {
        name: "x".to_string(),
        description: None,
        input_schema: json!({}),
    };
    let json = serde_json::to_value(&td).unwrap();
    assert!(json.get("description").is_none());
}

// ─── ToolChoice ─────────────────────────────────────────────────────────────

#[test]
fn tool_choice_auto_serde() {
    let tc = ToolChoice::Auto;
    let json = serde_json::to_value(&tc).unwrap();
    assert_eq!(json["type"], "auto");
    let back: ToolChoice = serde_json::from_value(json).unwrap();
    assert_eq!(tc, back);
}

#[test]
fn tool_choice_any_serde() {
    let tc = ToolChoice::Any;
    let json = serde_json::to_value(&tc).unwrap();
    assert_eq!(json["type"], "any");
    let back: ToolChoice = serde_json::from_value(json).unwrap();
    assert_eq!(tc, back);
}

#[test]
fn tool_choice_tool_serde() {
    let tc = ToolChoice::Tool {
        name: "my_tool".to_string(),
    };
    let json = serde_json::to_value(&tc).unwrap();
    assert_eq!(json["type"], "tool");
    assert_eq!(json["name"], "my_tool");
    let back: ToolChoice = serde_json::from_value(json).unwrap();
    assert_eq!(tc, back);
}

// ─── OutputContentBlock ─────────────────────────────────────────────────────

#[test]
fn output_content_block_text_serde() {
    let b = OutputContentBlock::Text {
        text: "hello".to_string(),
    };
    let json = serde_json::to_value(&b).unwrap();
    assert_eq!(json["type"], "text");
    let back: OutputContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn output_content_block_tool_use_serde() {
    let b = OutputContentBlock::ToolUse {
        id: "tu_1".to_string(),
        name: "get_weather".to_string(),
        input: json!({"city": "NYC"}),
    };
    let json = serde_json::to_value(&b).unwrap();
    assert_eq!(json["type"], "tool_use");
    let back: OutputContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn output_content_block_thinking_serde() {
    let b = OutputContentBlock::Thinking {
        thinking: "step 1".to_string(),
        signature: Some("sig".to_string()),
    };
    let json = serde_json::to_value(&b).unwrap();
    assert_eq!(json["type"], "thinking");
    assert_eq!(json["thinking"], "step 1");
    assert_eq!(json["signature"], "sig");
    let back: OutputContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn output_content_block_thinking_signature_omitted_when_none() {
    let b = OutputContentBlock::Thinking {
        thinking: "t".to_string(),
        signature: None,
    };
    let json = serde_json::to_value(&b).unwrap();
    assert!(json.get("signature").is_none());
}

#[test]
fn output_content_block_redacted_thinking_serde() {
    let b = OutputContentBlock::RedactedThinking {
        data: json!({"encrypted": true}),
    };
    let json = serde_json::to_value(&b).unwrap();
    assert_eq!(json["type"], "redacted_thinking");
    let back: OutputContentBlock = serde_json::from_value(json).unwrap();
    assert_eq!(b, back);
}

// ─── MessageResponse ────────────────────────────────────────────────────────

#[test]
fn message_response_total_tokens() {
    let r = sample_message_response();
    assert_eq!(r.total_tokens(), 180);
}

#[test]
fn message_response_serde_roundtrip() {
    let r = sample_message_response();
    let json = serde_json::to_string(&r).unwrap();
    let back: MessageResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn message_response_stop_reason_optional() {
    let r = MessageResponse {
        stop_reason: None,
        ..sample_message_response()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["stop_reason"], Value::Null);
}

#[test]
fn message_response_request_id_optional() {
    let r = MessageResponse {
        request_id: None,
        ..sample_message_response()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["request_id"], Value::Null);
}

#[test]
fn message_response_with_request_id() {
    let r = MessageResponse {
        request_id: Some("req_123".to_string()),
        ..sample_message_response()
    };
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["request_id"], "req_123");
}

#[test]
fn message_response_multiple_content_blocks() {
    let r = MessageResponse {
        content: vec![
            OutputContentBlock::Thinking {
                thinking: "step".to_string(),
                signature: None,
            },
            OutputContentBlock::Text {
                text: "answer".to_string(),
            },
        ],
        ..sample_message_response()
    };
    assert_eq!(r.content.len(), 2);
}

#[test]
fn message_response_empty_content() {
    let r = MessageResponse {
        content: vec![],
        ..sample_message_response()
    };
    assert!(r.content.is_empty());
}

// ─── StreamEvent ────────────────────────────────────────────────────────────

#[test]
fn stream_event_message_start_serde() {
    let e = StreamEvent::MessageStart(MessageStartEvent {
        message: sample_message_response(),
    });
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["type"], "message_start");
    let back: StreamEvent = serde_json::from_value(json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn stream_event_message_delta_serde() {
    let e = StreamEvent::MessageDelta(MessageDeltaEvent {
        delta: MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
        },
        usage: Usage::default(),
    });
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["type"], "message_delta");
    let back: StreamEvent = serde_json::from_value(json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn stream_event_content_block_start_serde() {
    let e = StreamEvent::ContentBlockStart(ContentBlockStartEvent {
        index: 0,
        content_block: OutputContentBlock::Text {
            text: "".to_string(),
        },
    });
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["type"], "content_block_start");
    let back: StreamEvent = serde_json::from_value(json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn stream_event_content_block_delta_serde() {
    let e = StreamEvent::ContentBlockDelta(ContentBlockDeltaEvent {
        index: 0,
        delta: ContentBlockDelta::TextDelta {
            text: "Hi".to_string(),
        },
    });
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["type"], "content_block_delta");
    let back: StreamEvent = serde_json::from_value(json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn stream_event_content_block_stop_serde() {
    let e = StreamEvent::ContentBlockStop(ContentBlockStopEvent { index: 0 });
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["type"], "content_block_stop");
    let back: StreamEvent = serde_json::from_value(json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn stream_event_message_stop_serde() {
    let e = StreamEvent::MessageStop(MessageStopEvent {});
    let json = serde_json::to_value(&e).unwrap();
    assert_eq!(json["type"], "message_stop");
    let back: StreamEvent = serde_json::from_value(json).unwrap();
    assert_eq!(e, back);
}

// ─── ContentBlockDelta ──────────────────────────────────────────────────────

#[test]
fn content_block_delta_text_delta_serde() {
    let d = ContentBlockDelta::TextDelta {
        text: "Hi".to_string(),
    };
    let json = serde_json::to_value(&d).unwrap();
    assert_eq!(json["type"], "text_delta");
    let back: ContentBlockDelta = serde_json::from_value(json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn content_block_delta_input_json_delta_serde() {
    let d = ContentBlockDelta::InputJsonDelta {
        partial_json: r#"{"city":"NYC"}"#.to_string(),
    };
    let json = serde_json::to_value(&d).unwrap();
    assert_eq!(json["type"], "input_json_delta");
    let back: ContentBlockDelta = serde_json::from_value(json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn content_block_delta_thinking_delta_serde() {
    let d = ContentBlockDelta::ThinkingDelta {
        thinking: "reasoning".to_string(),
    };
    let json = serde_json::to_value(&d).unwrap();
    assert_eq!(json["type"], "thinking_delta");
    let back: ContentBlockDelta = serde_json::from_value(json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn content_block_delta_signature_delta_serde() {
    let d = ContentBlockDelta::SignatureDelta {
        signature: "sig123".to_string(),
    };
    let json = serde_json::to_value(&d).unwrap();
    assert_eq!(json["type"], "signature_delta");
    let back: ContentBlockDelta = serde_json::from_value(json).unwrap();
    assert_eq!(d, back);
}

// ─── ContentBlockStartEvent / ContentBlockStopEvent ─────────────────────────

#[test]
fn content_block_start_event_index() {
    let e = ContentBlockStartEvent {
        index: 5,
        content_block: OutputContentBlock::Text {
            text: "".to_string(),
        },
    };
    assert_eq!(e.index, 5);
}

#[test]
fn content_block_stop_event_index() {
    let e = ContentBlockStopEvent { index: 3 };
    assert_eq!(e.index, 3);
}

// ─── MessageDelta / MessageDeltaEvent ───────────────────────────────────────

#[test]
fn message_delta_stop_reason_and_sequence() {
    let d = MessageDelta {
        stop_reason: Some("tool_use".to_string()),
        stop_sequence: Some("seq".to_string()),
    };
    assert_eq!(d.stop_reason.as_deref(), Some("tool_use"));
    assert_eq!(d.stop_sequence.as_deref(), Some("seq"));
}

#[test]
fn message_delta_serde_roundtrip() {
    let d = MessageDelta {
        stop_reason: None,
        stop_sequence: None,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: MessageDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn message_delta_event_default_usage() {
    let e = MessageDeltaEvent {
        delta: MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
        },
        usage: Usage::default(),
    };
    assert_eq!(e.usage.total_tokens(), 0);
}

#[test]
fn message_delta_event_serde_roundtrip() {
    let e = MessageDeltaEvent {
        delta: MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
        },
        usage: Usage {
            input_tokens: 10,
            output_tokens: 20,
            ..Usage::default()
        },
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: MessageDeltaEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ─── MessageStartEvent / MessageStopEvent ───────────────────────────────────

#[test]
fn message_start_event_serde_roundtrip() {
    let e = MessageStartEvent {
        message: sample_message_response(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: MessageStartEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn message_stop_event_empty_struct() {
    let e = MessageStopEvent {};
    let json = serde_json::to_value(&e).unwrap();
    let back: MessageStopEvent = serde_json::from_value(json).unwrap();
    assert_eq!(e, back);
}

// ─── ImageSource ────────────────────────────────────────────────────────────

#[test]
fn image_source_serde_roundtrip() {
    let s = ImageSource {
        source_type: "base64".to_string(),
        media_type: "image/png".to_string(),
        data: "iVBORw0KGgo".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: ImageSource = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ─── SseParser ──────────────────────────────────────────────────────────────

#[test]
fn sse_parser_new_is_empty() {
    let mut p = SseParser::new();
    assert!(p.push(b"").unwrap().is_empty());
    assert!(p.finish().unwrap().is_empty());
}

#[test]
fn sse_parser_text_delta() {
    let mut p = SseParser::new();
    let frame = concat!(
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n"
    );
    let events = p.push(frame.as_bytes()).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        StreamEvent::ContentBlockDelta(d) => {
            assert_eq!(
                d.delta,
                ContentBlockDelta::TextDelta {
                    text: "Hello".to_string()
                }
            );
        }
        _ => panic!("expected ContentBlockDelta"),
    }
}

#[test]
fn sse_parser_message_stop() {
    let mut p = SseParser::new();
    let frame = concat!(
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n"
    );
    let events = p.push(frame.as_bytes()).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], StreamEvent::MessageStop(_)));
}

#[test]
fn sse_parser_done_yields_nothing() {
    let mut p = SseParser::new();
    let frame = "data: [DONE]\n\n";
    let events = p.push(frame.as_bytes()).unwrap();
    assert!(events.is_empty());
}

#[test]
fn sse_parser_ping_ignored() {
    let mut p = SseParser::new();
    let frame = "event: ping\n\n";
    let events = p.push(frame.as_bytes()).unwrap();
    assert!(events.is_empty());
}

#[test]
fn sse_parser_comment_ignored() {
    let mut p = SseParser::new();
    let frame = ": keepalive\n\n";
    let events = p.push(frame.as_bytes()).unwrap();
    assert!(events.is_empty());
}

#[test]
fn sse_parser_chunked_delivery() {
    let mut p = SseParser::new();
    let a = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"He";
    let b = b"llo\"}}\n\n";
    assert!(p.push(a).unwrap().is_empty());
    let events = p.push(b).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn sse_parser_with_context() {
    let mut p = SseParser::new().with_context("Anthropic", "claude-sonnet-4-6");
    let frame = concat!(
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n"
    );
    let events = p.push(frame.as_bytes()).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn sse_parser_finish_with_trailing_data() {
    let mut p = SseParser::new();
    let frame = concat!(
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}"
    );
    let events = p.push(frame.as_bytes()).unwrap();
    assert!(events.is_empty());
    let finish = p.finish().unwrap();
    assert_eq!(finish.len(), 1);
}

#[test]
fn parse_frame_empty_string() {
    let result = parse_frame("").unwrap();
    assert!(result.is_none());
}

#[test]
fn parse_frame_invalid_json() {
    let frame = "data: not json\n\n";
    let result = parse_frame(frame);
    assert!(result.is_err());
}

#[test]
fn parse_frame_multiple_data_lines_joined() {
    let frame = concat!(
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\n",
        "data: \"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n"
    );
    let event = parse_frame(frame).unwrap();
    assert!(event.is_some());
}

// ─── ProviderKind ───────────────────────────────────────────────────────────

#[test]
fn provider_kind_anthropic_variant() {
    let k = ProviderKind::Anthropic;
    assert_eq!(format!("{k:?}"), "Anthropic");
}

#[test]
fn provider_kind_xai_variant() {
    let k = ProviderKind::Xai;
    assert_eq!(format!("{k:?}"), "Xai");
}

#[test]
fn provider_kind_openai_variant() {
    let k = ProviderKind::OpenAi;
    assert_eq!(format!("{k:?}"), "OpenAi");
}

#[test]
fn provider_kind_deepseek_variant() {
    let k = ProviderKind::DeepSeek;
    assert_eq!(format!("{k:?}"), "DeepSeek");
}

#[test]
fn provider_kind_equality() {
    assert_eq!(ProviderKind::Anthropic, ProviderKind::Anthropic);
    assert_ne!(ProviderKind::Anthropic, ProviderKind::Xai);
}

#[test]
fn provider_kind_clone() {
    let k = ProviderKind::OpenAi;
    let k2 = k;
    assert_eq!(k, k2);
}

#[test]
fn provider_kind_copy() {
    let k = ProviderKind::DeepSeek;
    let k2 = k;
    assert_eq!(k, k2);
}

// ─── resolve_model_alias ────────────────────────────────────────────────────

#[test]
fn resolve_model_alias_opus() {
    assert_eq!(resolve_model_alias("opus"), "claude-opus-4-6");
}

#[test]
fn resolve_model_alias_sonnet() {
    assert_eq!(resolve_model_alias("sonnet"), "claude-sonnet-4-6");
}

#[test]
fn resolve_model_alias_haiku() {
    assert_eq!(resolve_model_alias("haiku"), "claude-haiku-4-5-20251213");
}

#[test]
fn resolve_model_alias_grok() {
    assert_eq!(resolve_model_alias("grok"), "grok-3");
}

#[test]
fn resolve_model_alias_grok_3() {
    assert_eq!(resolve_model_alias("grok-3"), "grok-3");
}

#[test]
fn resolve_model_alias_grok_mini() {
    assert_eq!(resolve_model_alias("grok-mini"), "grok-3-mini");
}

#[test]
fn resolve_model_alias_grok_3_mini() {
    assert_eq!(resolve_model_alias("grok-3-mini"), "grok-3-mini");
}

#[test]
fn resolve_model_alias_grok_2() {
    assert_eq!(resolve_model_alias("grok-2"), "grok-2");
}

#[test]
fn resolve_model_alias_deepseek() {
    assert_eq!(resolve_model_alias("deepseek"), "deepseek-chat");
}

#[test]
fn resolve_model_alias_deepseek_v3() {
    assert_eq!(resolve_model_alias("deepseek-v3"), "deepseek-chat");
}

#[test]
fn resolve_model_alias_deepseek_chat() {
    assert_eq!(resolve_model_alias("deepseek-chat"), "deepseek-chat");
}

#[test]
fn resolve_model_alias_deepseek_reasoner() {
    assert_eq!(resolve_model_alias("deepseek-reasoner"), "deepseek-reasoner");
}

#[test]
fn resolve_model_alias_r1() {
    assert_eq!(resolve_model_alias("r1"), "deepseek-reasoner");
}

#[test]
fn resolve_model_alias_deepseek_r1() {
    assert_eq!(resolve_model_alias("deepseek-r1"), "deepseek-reasoner");
}

#[test]
fn resolve_model_alias_deepseek_coder() {
    assert_eq!(resolve_model_alias("deepseek-coder"), "deepseek-coder");
}

#[test]
fn resolve_model_alias_kimi() {
    assert_eq!(resolve_model_alias("kimi"), "kimi-k2.5");
}

#[test]
fn resolve_model_alias_big_pickle() {
    assert_eq!(resolve_model_alias("big-pickle"), "big-pickle");
}

#[test]
fn resolve_model_alias_opencode_big_pickle() {
    assert_eq!(resolve_model_alias("opencode/big-pickle"), "big-pickle");
}

#[test]
fn resolve_model_alias_unknown_passthrough() {
    assert_eq!(resolve_model_alias("my-custom-model"), "my-custom-model");
}

#[test]
fn resolve_model_alias_case_insensitive() {
    assert_eq!(resolve_model_alias("OPUS"), "claude-opus-4-6");
}

#[test]
fn resolve_model_alias_whitespace_trimmed() {
    assert_eq!(resolve_model_alias("  sonnet  "), "claude-sonnet-4-6");
}

// ─── max_tokens_for_model ───────────────────────────────────────────────────

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
fn max_tokens_grok3() {
    assert_eq!(max_tokens_for_model("grok-3"), 64_000);
}

#[test]
fn max_tokens_grok_mini() {
    assert_eq!(max_tokens_for_model("grok-mini"), 64_000);
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

// ─── max_tokens_for_model_with_override ─────────────────────────────────────

#[test]
fn max_tokens_override_none_falls_back() {
    assert_eq!(max_tokens_for_model_with_override("opus", None), 32_000);
}

#[test]
fn max_tokens_override_some() {
    assert_eq!(max_tokens_for_model_with_override("opus", Some(9999)), 9999);
}

// ─── is_reasoning_model ─────────────────────────────────────────────────────

#[test]
fn is_reasoning_o1() {
    assert!(is_reasoning_model("o1"));
}

#[test]
fn is_reasoning_o1_mini() {
    assert!(is_reasoning_model("o1-mini"));
}

#[test]
fn is_reasoning_o3() {
    assert!(is_reasoning_model("o3"));
}

#[test]
fn is_reasoning_o3_mini() {
    assert!(is_reasoning_model("o3-mini"));
}

#[test]
fn is_reasoning_o4_mini() {
    assert!(is_reasoning_model("o4-mini"));
}

#[test]
fn is_reasoning_grok3_mini() {
    assert!(is_reasoning_model("grok-3-mini"));
}

#[test]
fn is_reasoning_qwen_qwq() {
    assert!(is_reasoning_model("qwen-qwq"));
}

#[test]
fn is_reasoning_thinking_model() {
    assert!(is_reasoning_model("some-thinking-model"));
}

#[test]
fn is_not_reasoning_gpt4o() {
    assert!(!is_reasoning_model("gpt-4o"));
}

#[test]
fn is_not_reasoning_grok3() {
    assert!(!is_reasoning_model("grok-3"));
}

#[test]
fn is_not_reasoning_sonnet() {
    assert!(!is_reasoning_model("claude-sonnet-4-6"));
}

#[test]
fn is_reasoning_with_prefix() {
    assert!(is_reasoning_model("openai/o3-mini"));
}

// ─── model_rejects_is_error_field ───────────────────────────────────────────

#[test]
fn rejects_is_error_kimi() {
    assert!(model_rejects_is_error_field("kimi-k2.5"));
}

#[test]
fn rejects_is_error_kimi_prefix() {
    assert!(model_rejects_is_error_field("kimi/kimi-k2.5"));
}

#[test]
fn rejects_is_error_kimi_k1_5() {
    assert!(model_rejects_is_error_field("kimi-k1.5"));
}

#[test]
fn not_rejects_is_error_gpt4o() {
    assert!(!model_rejects_is_error_field("gpt-4o"));
}

#[test]
fn not_rejects_is_error_sonnet() {
    assert!(!model_rejects_is_error_field("claude-sonnet-4-6"));
}

// ─── flatten_tool_result_content ────────────────────────────────────────────

#[test]
fn flatten_single_text() {
    let content = vec![ToolResultContentBlock::Text {
        text: "hello".to_string(),
    }];
    assert_eq!(flatten_tool_result_content(&content), "hello");
}

#[test]
fn flatten_multiple_texts() {
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
fn flatten_json_block() {
    let content = vec![ToolResultContentBlock::Json {
        value: json!({"key": "value"}),
    }];
    let result = flatten_tool_result_content(&content);
    assert!(result.contains("key"));
    assert!(result.contains("value"));
}

#[test]
fn flatten_mixed_text_and_json() {
    let content = vec![
        ToolResultContentBlock::Text {
            text: "text".to_string(),
        },
        ToolResultContentBlock::Json {
            value: json!({"k": 1}),
        },
    ];
    let result = flatten_tool_result_content(&content);
    assert!(result.contains("text"));
    assert!(result.contains("k"));
}

#[test]
fn flatten_empty_content() {
    let content: Vec<ToolResultContentBlock> = vec![];
    assert_eq!(flatten_tool_result_content(&content), "");
}

// ─── translate_message ──────────────────────────────────────────────────────

#[test]
fn translate_user_text_message() {
    let msg = InputMessage::user_text("Hello");
    let result = translate_message(&msg, "gpt-4o");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0]["role"], "user");
    assert_eq!(result[0]["content"], "Hello");
}

#[test]
fn translate_assistant_text_message() {
    let msg = InputMessage {
        role: "assistant".to_string(),
        content: vec![InputContentBlock::Text {
            text: "Hi there".to_string(),
        }],
    };
    let result = translate_message(&msg, "gpt-4o");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0]["role"], "assistant");
    assert_eq!(result[0]["content"], "Hi there");
}

#[test]
fn translate_assistant_tool_use_message() {
    let msg = InputMessage {
        role: "assistant".to_string(),
        content: vec![InputContentBlock::ToolUse {
            id: "tu_1".to_string(),
            name: "weather".to_string(),
            input: json!({"city": "NYC"}),
        }],
    };
    let result = translate_message(&msg, "gpt-4o");
    assert_eq!(result.len(), 1);
    assert!(result[0]["tool_calls"].is_array());
}

#[test]
fn translate_assistant_empty_content_returns_empty() {
    let msg = InputMessage {
        role: "assistant".to_string(),
        content: vec![],
    };
    let result = translate_message(&msg, "gpt-4o");
    assert!(result.is_empty());
}

#[test]
fn translate_user_tool_result_message() {
    let msg = InputMessage::user_tool_result("tu_1", "result text", false);
    let result = translate_message(&msg, "gpt-4o");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0]["role"], "tool");
    assert_eq!(result[0]["tool_call_id"], "tu_1");
}

#[test]
fn translate_tool_result_with_is_error() {
    let msg = InputMessage::user_tool_result("tu_1", "err", true);
    let result = translate_message(&msg, "gpt-4o");
    assert_eq!(result[0]["is_error"], true);
}

#[test]
fn translate_tool_result_for_kimi_omits_is_error() {
    let msg = InputMessage::user_tool_result("tu_1", "err", true);
    let result = translate_message(&msg, "kimi-k2.5");
    assert!(result[0].get("is_error").is_none());
}

// ─── build_chat_completion_request ──────────────────────────────────────────

#[test]
fn build_request_basic() {
    let config = api::OpenAiCompatConfig::openai();
    let req = sample_message_request();
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["model"], "claude-sonnet-4-6");
    assert_eq!(payload["max_tokens"], 1024);
    assert!(payload["messages"].is_array());
}

#[test]
fn build_request_with_system() {
    let config = api::OpenAiCompatConfig::openai();
    let req = sample_message_request();
    let payload = build_chat_completion_request(&req, config);
    let messages = payload["messages"].as_array().unwrap();
    assert!(messages.iter().any(|m| m["role"] == "system"));
}

#[test]
fn build_request_without_system() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        system: None,
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    let messages = payload["messages"].as_array().unwrap();
    assert!(!messages.iter().any(|m| m["role"] == "system"));
}

#[test]
fn build_request_stream_includes_stream_options_for_openai() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        stream: true,
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["stream"], true);
    assert_eq!(payload["stream_options"]["include_usage"], true);
}

#[test]
fn build_request_stream_no_stream_options_for_non_openai() {
    let config = api::OpenAiCompatConfig::xai();
    let req = MessageRequest {
        stream: true,
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["stream"], true);
    assert!(payload.get("stream_options").is_none());
}

#[test]
fn build_request_strips_routing_prefix() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        model: "openai/gpt-4o".to_string(),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["model"], "gpt-4o");
}

#[test]
fn build_request_with_tools() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        tools: Some(vec![ToolDefinition {
            name: "calc".to_string(),
            description: Some("math".to_string()),
            input_schema: json!({"type": "object", "properties": {"x": {"type": "number"}}}),
        }]),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert!(payload["tools"].is_array());
    let tools = payload["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["type"], "function");
}

#[test]
fn build_request_with_tool_choice_auto() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        tool_choice: Some(ToolChoice::Auto),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["tool_choice"], "auto");
}

#[test]
fn build_request_with_tool_choice_any() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        tool_choice: Some(ToolChoice::Any),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["tool_choice"], "required");
}

#[test]
fn build_request_with_tool_choice_specific() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        tool_choice: Some(ToolChoice::Tool {
            name: "weather".to_string(),
        }),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["tool_choice"]["type"], "function");
    assert_eq!(payload["tool_choice"]["function"]["name"], "weather");
}

#[test]
fn build_request_temperature_for_non_reasoning() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        temperature: Some(0.7),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["temperature"], json!(0.7));
}

#[test]
fn build_request_temperature_stripped_for_reasoning() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        model: "o3-mini".to_string(),
        temperature: Some(0.7),
        max_tokens: 1024,
        messages: vec![InputMessage::user_text("hi")],
        ..Default::default()
    };
    let payload = build_chat_completion_request(&req, config);
    assert!(payload.get("temperature").is_none());
}

#[test]
fn build_request_top_p_for_non_reasoning() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        top_p: Some(0.9),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["top_p"], json!(0.9));
}

#[test]
fn build_request_frequency_penalty() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        frequency_penalty: Some(0.1),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["frequency_penalty"], json!(0.1));
}

#[test]
fn build_request_presence_penalty() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        presence_penalty: Some(0.2),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["presence_penalty"], json!(0.2));
}

#[test]
fn build_request_stop() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        stop: Some(vec!["STOP".to_string()]),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["stop"], json!(["STOP"]));
}

#[test]
fn build_request_reasoning_effort() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        reasoning_effort: Some("high".to_string()),
        ..sample_message_request()
    };
    let payload = build_chat_completion_request(&req, config);
    assert_eq!(payload["reasoning_effort"], "high");
}

#[test]
fn build_request_gpt5_uses_max_completion_tokens() {
    let config = api::OpenAiCompatConfig::openai();
    let req = MessageRequest {
        model: "gpt-5".to_string(),
        max_tokens: 4096,
        messages: vec![InputMessage::user_text("hi")],
        ..Default::default()
    };
    let payload = build_chat_completion_request(&req, config);
    assert!(payload.get("max_tokens").is_none());
    assert_eq!(payload["max_completion_tokens"], json!(4096));
}

// ─── ProxyConfig ────────────────────────────────────────────────────────────

#[test]
fn proxy_config_default_is_empty() {
    let c = ProxyConfig::default();
    assert!(c.is_empty());
    assert!(c.http_proxy.is_none());
    assert!(c.https_proxy.is_none());
    assert!(c.no_proxy.is_none());
    assert!(c.proxy_url.is_none());
}

#[test]
fn proxy_config_from_proxy_url() {
    let c = ProxyConfig::from_proxy_url("http://proxy:3128");
    assert!(!c.is_empty());
    assert_eq!(c.proxy_url.as_deref(), Some("http://proxy:3128"));
    assert!(c.http_proxy.is_none());
    assert!(c.https_proxy.is_none());
}

#[test]
fn proxy_config_from_proxy_url_is_not_empty() {
    let c = ProxyConfig::from_proxy_url("http://proxy:3128");
    assert!(!c.is_empty());
}

#[test]
fn proxy_config_with_only_no_proxy_is_empty() {
    let c = ProxyConfig {
        no_proxy: Some("localhost".to_string()),
        ..ProxyConfig::default()
    };
    assert!(c.is_empty());
}

#[test]
fn proxy_config_equality() {
    let a = ProxyConfig::default();
    let b = ProxyConfig::default();
    assert_eq!(a, b);
}

#[test]
fn proxy_config_clone() {
    let a = ProxyConfig::from_proxy_url("http://proxy:3128");
    let b = a.clone();
    assert_eq!(a, b);
}

// ─── OpenAiCompatConfig ────────────────────────────────────────────────────

#[test]
fn openai_compat_config_xai() {
    let c = api::OpenAiCompatConfig::xai();
    assert_eq!(c.provider_name, "xAI");
    assert_eq!(c.api_key_env, "XAI_API_KEY");
}

#[test]
fn openai_compat_config_openai() {
    let c = api::OpenAiCompatConfig::openai();
    assert_eq!(c.provider_name, "OpenAI");
    assert_eq!(c.api_key_env, "OPENAI_API_KEY");
}

#[test]
fn openai_compat_config_dashscope() {
    let c = api::OpenAiCompatConfig::dashscope();
    assert_eq!(c.provider_name, "DashScope");
    assert_eq!(c.api_key_env, "DASHSCOPE_API_KEY");
}

#[test]
fn openai_compat_config_deepseek() {
    let c = api::OpenAiCompatConfig::deepseek();
    assert_eq!(c.provider_name, "DeepSeek");
    assert_eq!(c.api_key_env, "DEEPSEEK_API_KEY");
}

#[test]
fn openai_compat_config_opencode() {
    let c = api::OpenAiCompatConfig::opencode();
    assert_eq!(c.provider_name, "OpenCode");
    assert_eq!(c.api_key_env, "OPENCODE_API_KEY");
}

#[test]
fn openai_compat_config_max_request_body_bytes_dashscope() {
    let c = api::OpenAiCompatConfig::dashscope();
    assert_eq!(c.max_request_body_bytes, 6_291_456);
}

#[test]
fn openai_compat_config_max_request_body_bytes_openai() {
    let c = api::OpenAiCompatConfig::openai();
    assert_eq!(c.max_request_body_bytes, 104_857_600);
}

// ─── PromptCacheConfig ──────────────────────────────────────────────────────

#[test]
fn prompt_cache_config_new() {
    let c = api::PromptCacheConfig::new("sess1");
    assert_eq!(c.session_id, "sess1");
}

#[test]
fn prompt_cache_config_default() {
    let c = api::PromptCacheConfig::default();
    assert_eq!(c.session_id, "default");
}

#[test]
fn prompt_cache_config_has_ttls() {
    let c = api::PromptCacheConfig::new("s");
    assert!(c.completion_ttl.as_secs() > 0);
    assert!(c.prompt_ttl.as_secs() > 0);
}

// ─── PromptCachePaths ───────────────────────────────────────────────────────

#[test]
fn prompt_cache_paths_for_session() {
    let p = api::PromptCachePaths::for_session("my-sess");
    assert!(p.session_dir.ends_with("my-sess"));
    assert!(p.completion_dir.ends_with("completions"));
    assert!(p.session_state_path.ends_with("session-state.json"));
    assert!(p.stats_path.ends_with("stats.json"));
}

#[test]
fn prompt_cache_paths_completion_entry_path() {
    let p = api::PromptCachePaths::for_session("s");
    let entry = p.completion_entry_path("abc123");
    assert!(entry.to_str().unwrap().contains("abc123.json"));
}

#[test]
fn prompt_cache_paths_sanitizes_special_chars() {
    let p = api::PromptCachePaths::for_session("a/b:c");
    let dir_name = p.session_dir.file_name().unwrap().to_str().unwrap();
    assert!(!dir_name.contains('/'));
    assert!(!dir_name.contains(':'));
}

#[test]
fn prompt_cache_paths_serde_roundtrip() {
    let p = api::PromptCachePaths::for_session("s");
    let json = serde_json::to_string(&p).unwrap();
    let back: api::PromptCachePaths = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ─── PromptCacheStats ───────────────────────────────────────────────────────

#[test]
fn prompt_cache_stats_default() {
    let s = api::PromptCacheStats::default();
    assert_eq!(s.tracked_requests, 0);
    assert_eq!(s.completion_cache_hits, 0);
    assert_eq!(s.completion_cache_misses, 0);
    assert_eq!(s.completion_cache_writes, 0);
    assert_eq!(s.unexpected_cache_breaks, 0);
}

#[test]
fn prompt_cache_stats_serde_roundtrip() {
    let s = api::PromptCacheStats {
        tracked_requests: 5,
        completion_cache_hits: 3,
        ..api::PromptCacheStats::default()
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: api::PromptCacheStats = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ─── CacheBreakEvent ────────────────────────────────────────────────────────

#[test]
fn cache_break_event_serde_roundtrip() {
    let e = api::CacheBreakEvent {
        unexpected: true,
        reason: "token drop".to_string(),
        previous_cache_read_input_tokens: 1000,
        current_cache_read_input_tokens: 100,
        token_drop: 900,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: api::CacheBreakEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn cache_break_event_fields() {
    let e = api::CacheBreakEvent {
        unexpected: false,
        reason: "model changed".to_string(),
        previous_cache_read_input_tokens: 500,
        current_cache_read_input_tokens: 50,
        token_drop: 450,
    };
    assert!(!e.unexpected);
    assert_eq!(e.token_drop, 450);
}

// ─── PromptCacheRecord ──────────────────────────────────────────────────────

#[test]
fn prompt_cache_record_no_break() {
    let r = api::PromptCacheRecord {
        cache_break: None,
        stats: api::PromptCacheStats::default(),
    };
    assert!(r.cache_break.is_none());
}

#[test]
fn prompt_cache_record_with_break() {
    let r = api::PromptCacheRecord {
        cache_break: Some(api::CacheBreakEvent {
            unexpected: true,
            reason: "reason".to_string(),
            previous_cache_read_input_tokens: 100,
            current_cache_read_input_tokens: 0,
            token_drop: 100,
        }),
        stats: api::PromptCacheStats::default(),
    };
    assert!(r.cache_break.is_some());
    assert!(r.cache_break.unwrap().unexpected);
}

// ─── ApiError ───────────────────────────────────────────────────────────────

#[test]
fn api_error_missing_credentials_display() {
    let e = api::ApiError::missing_credentials("OpenAI", &["OPENAI_API_KEY"]);
    let msg = e.to_string();
    assert!(msg.contains("missing OpenAI credentials"));
    assert!(msg.contains("OPENAI_API_KEY"));
}

#[test]
fn api_error_missing_credentials_with_hint() {
    let e = api::ApiError::missing_credentials_with_hint(
        "Anthropic",
        &["ANTHROPIC_API_KEY"],
        "Try setting OPENAI_API_KEY",
    );
    let msg = e.to_string();
    assert!(msg.contains("missing Anthropic credentials"));
    assert!(msg.contains("Try setting OPENAI_API_KEY"));
}

#[test]
fn api_error_auth_display() {
    let e = api::ApiError::Auth("bad token".to_string());
    assert_eq!(e.to_string(), "auth error: bad token");
}

#[test]
fn api_error_invalid_sse_frame_display() {
    let e = api::ApiError::InvalidSseFrame("bad data");
    assert_eq!(e.to_string(), "invalid sse frame: bad data");
}

#[test]
fn api_error_backoff_overflow_display() {
    let e = api::ApiError::BackoffOverflow {
        attempt: 10,
        base_delay: std::time::Duration::from_secs(1),
    };
    let msg = e.to_string();
    assert!(msg.contains("retry backoff overflowed"));
    assert!(msg.contains("10"));
}

#[test]
fn api_error_request_body_size_exceeded_display() {
    let e = api::ApiError::RequestBodySizeExceeded {
        estimated_bytes: 10_000_000,
        max_bytes: 6_000_000,
        provider: "DashScope",
    };
    let msg = e.to_string();
    assert!(msg.contains("10000000"));
    assert!(msg.contains("6000000"));
    assert!(msg.contains("DashScope"));
}

#[test]
fn api_error_context_window_display() {
    let e = api::ApiError::ContextWindowExceeded {
        model: "claude-sonnet-4-6".to_string(),
        estimated_input_tokens: 150_000,
        requested_output_tokens: 64_000,
        estimated_total_tokens: 214_000,
        context_window_tokens: 200_000,
    };
    let msg = e.to_string();
    assert!(msg.contains("context_window_blocked"));
    assert!(msg.contains("claude-sonnet-4-6"));
}

#[test]
fn api_error_expired_oauth_display() {
    let e = api::ApiError::ExpiredOAuthToken;
    assert!(e.to_string().contains("expired"));
}

#[test]
fn api_error_retries_exhausted_display() {
    let e = api::ApiError::RetriesExhausted {
        attempts: 3,
        last_error: Box::new(api::ApiError::Auth("fail".to_string())),
    };
    let msg = e.to_string();
    assert!(msg.contains("3 attempts"));
    assert!(msg.contains("auth error: fail"));
}

#[test]
fn api_error_is_retryable_api_retryable() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(503).unwrap(),
        error_type: None,
        message: None,
        request_id: None,
        body: String::new(),
        retryable: true,
        suggested_action: None,
    };
    assert!(e.is_retryable());
}

#[test]
fn api_error_is_retryable_api_not_retryable() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(400).unwrap(),
        error_type: None,
        message: None,
        request_id: None,
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    assert!(!e.is_retryable());
}

#[test]
fn api_error_is_retryable_auth() {
    let e = api::ApiError::Auth("bad".to_string());
    assert!(!e.is_retryable());
}

#[test]
fn api_error_request_id_from_api() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(500).unwrap(),
        error_type: None,
        message: None,
        request_id: Some("req_abc".to_string()),
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    assert_eq!(e.request_id(), Some("req_abc"));
}

#[test]
fn api_error_request_id_none_for_non_api() {
    let e = api::ApiError::Auth("bad".to_string());
    assert_eq!(e.request_id(), None);
}

#[test]
fn api_error_safe_failure_class_auth() {
    let e = api::ApiError::missing_credentials("OpenAI", &["OPENAI_API_KEY"]);
    assert_eq!(e.safe_failure_class(), "provider_auth");
}

#[test]
fn api_error_safe_failure_class_context_window() {
    let e = api::ApiError::ContextWindowExceeded {
        model: "m".to_string(),
        estimated_input_tokens: 0,
        requested_output_tokens: 0,
        estimated_total_tokens: 0,
        context_window_tokens: 0,
    };
    assert_eq!(e.safe_failure_class(), "context_window");
}

#[test]
fn api_error_safe_failure_class_api_429() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(429).unwrap(),
        error_type: None,
        message: None,
        request_id: None,
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    assert_eq!(e.safe_failure_class(), "provider_rate_limit");
}

#[test]
fn api_error_safe_failure_class_api_401() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(401).unwrap(),
        error_type: None,
        message: None,
        request_id: None,
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    assert_eq!(e.safe_failure_class(), "provider_auth");
}

#[test]
fn api_error_safe_failure_class_api_403() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(403).unwrap(),
        error_type: None,
        message: None,
        request_id: None,
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    assert_eq!(e.safe_failure_class(), "provider_auth");
}

#[test]
fn api_error_is_context_window_status_400_with_marker() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(400).unwrap(),
        error_type: None,
        message: Some("maximum context length exceeded".to_string()),
        request_id: None,
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    assert!(e.is_context_window_failure());
}

#[test]
fn api_error_is_context_window_status_413_with_marker() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(413).unwrap(),
        error_type: None,
        message: Some("prompt is too long".to_string()),
        request_id: None,
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    assert!(e.is_context_window_failure());
}

#[test]
fn api_error_is_not_context_window_500() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(500).unwrap(),
        error_type: None,
        message: Some("maximum context length".to_string()),
        request_id: None,
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    assert!(!e.is_context_window_failure());
}

#[test]
fn api_error_is_generic_fatal_wrapper() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(500).unwrap(),
        error_type: None,
        message: Some("Something went wrong while processing your request".to_string()),
        request_id: None,
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    assert!(e.is_generic_fatal_wrapper());
    assert_eq!(e.safe_failure_class(), "provider_internal");
}

#[test]
fn api_error_retries_exhausted_preserves_nested_class() {
    let inner = api::ApiError::ContextWindowExceeded {
        model: "m".to_string(),
        estimated_input_tokens: 0,
        requested_output_tokens: 0,
        estimated_total_tokens: 0,
        context_window_tokens: 0,
    };
    let e = api::ApiError::RetriesExhausted {
        attempts: 2,
        last_error: Box::new(inner),
    };
    assert_eq!(e.safe_failure_class(), "context_window");
}

#[test]
fn api_error_retries_exhausted_preserves_nested_request_id() {
    let inner = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(502).unwrap(),
        error_type: None,
        message: None,
        request_id: Some("req_inner".to_string()),
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    let e = api::ApiError::RetriesExhausted {
        attempts: 3,
        last_error: Box::new(inner),
    };
    assert_eq!(e.request_id(), Some("req_inner"));
}

#[test]
fn api_error_json_deserialize() {
    let source =
        serde_json::from_str::<serde_json::Value>("{invalid").expect_err("bad json");
    let e = api::ApiError::json_deserialize("OpenAI", "gpt-4o", "the raw body", source);
    let msg = e.to_string();
    assert!(msg.contains("OpenAI"));
    assert!(msg.contains("gpt-4o"));
    assert!(msg.contains("first 200 chars of body: the raw body"));
}

#[test]
fn api_error_json_deserialize_truncates_long_body() {
    let long_body = "x".repeat(300);
    let source =
        serde_json::from_str::<serde_json::Value>("{bad").expect_err("bad json");
    let e = api::ApiError::json_deserialize("Provider", "model", &long_body, source);
    let msg = e.to_string();
    assert!(msg.contains("…"));
}

#[test]
fn api_error_api_display_with_error_type_and_message() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(400).unwrap(),
        error_type: Some("invalid_request".to_string()),
        message: Some("bad input".to_string()),
        request_id: Some("req_1".to_string()),
        body: String::new(),
        retryable: false,
        suggested_action: None,
    };
    let msg = e.to_string();
    assert!(msg.contains("400"));
    assert!(msg.contains("invalid_request"));
    assert!(msg.contains("bad input"));
    assert!(msg.contains("req_1"));
}

#[test]
fn api_error_api_display_without_error_type_and_message() {
    let e = api::ApiError::Api {
        status: reqwest::StatusCode::from_u16(500).unwrap(),
        error_type: None,
        message: None,
        request_id: None,
        body: "raw body".to_string(),
        retryable: false,
        suggested_action: None,
    };
    let msg = e.to_string();
    assert!(msg.contains("500"));
    assert!(msg.contains("raw body"));
}

#[test]
fn api_error_is_std_error() {
    let e = api::ApiError::Auth("test".to_string());
    let err: &dyn std::error::Error = &e;
    assert!(err.source().is_none());
}

#[test]
fn api_error_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
    let api_err: api::ApiError = io_err.into();
    assert!(matches!(api_err, api::ApiError::Io(_)));
}

#[test]
fn api_error_from_var_error() {
    let var_err = std::env::VarError::NotPresent;
    let api_err: api::ApiError = var_err.into();
    assert!(matches!(api_err, api::ApiError::InvalidApiKeyEnv(_)));
}

#[test]
fn api_error_from_serde_json_error() {
    let json_err = serde_json::from_str::<serde_json::Value>("{bad").unwrap_err();
    let api_err: api::ApiError = json_err.into();
    assert!(matches!(api_err, api::ApiError::Json { .. }));
}

// ─── PromptCache ────────────────────────────────────────────────────────────

#[test]
fn prompt_cache_new() {
    let cache = api::PromptCache::new("test-sess");
    let paths = cache.paths();
    assert!(paths.session_dir.to_str().unwrap().contains("test-sess"));
}

#[test]
fn prompt_cache_initial_stats() {
    let cache = api::PromptCache::new("stats-sess");
    let stats = cache.stats();
    assert_eq!(stats.tracked_requests, 0);
}

#[test]
fn prompt_cache_lookup_miss() {
    let cache = api::PromptCache::new("miss-sess");
    let req = sample_message_request();
    assert!(cache.lookup_completion(&req).is_none());
}

// ─── OpenAiCompatConfig credential env vars ─────────────────────────────────

#[test]
fn openai_compat_credential_env_vars_xai() {
    let vars = api::OpenAiCompatConfig::xai().credential_env_vars();
    assert!(vars.contains(&"XAI_API_KEY"));
}

#[test]
fn openai_compat_credential_env_vars_openai() {
    let vars = api::OpenAiCompatConfig::openai().credential_env_vars();
    assert!(vars.contains(&"OPENAI_API_KEY"));
}

#[test]
fn openai_compat_credential_env_vars_dashscope() {
    let vars = api::OpenAiCompatConfig::dashscope().credential_env_vars();
    assert!(vars.contains(&"DASHSCOPE_API_KEY"));
}

#[test]
fn openai_compat_credential_env_vars_deepseek() {
    let vars = api::OpenAiCompatConfig::deepseek().credential_env_vars();
    assert!(vars.contains(&"DEEPSEEK_API_KEY"));
}

#[test]
fn openai_compat_credential_env_vars_opencode() {
    let vars = api::OpenAiCompatConfig::opencode().credential_env_vars();
    assert!(vars.contains(&"OPENCODE_API_KEY"));
}
