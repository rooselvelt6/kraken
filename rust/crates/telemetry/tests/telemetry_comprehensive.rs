use std::sync::Arc;

use telemetry::*;
use serde_json::{json, Map, Value};

fn sink() -> Arc<MemoryTelemetrySink> {
    Arc::new(MemoryTelemetrySink::default())
}

#[test]
fn client_identity_new() {
    let id = ClientIdentity::new("my-app", "2.0.0");
    assert_eq!(id.app_name, "my-app");
    assert_eq!(id.app_version, "2.0.0");
}

#[test]
fn client_identity_default_runtime() {
    let id = ClientIdentity::new("app", "1.0");
    assert_eq!(id.runtime, DEFAULT_RUNTIME);
}

#[test]
fn client_identity_with_runtime() {
    let id = ClientIdentity::new("app", "1.0").with_runtime("node");
    assert_eq!(id.runtime, "node");
}

#[test]
fn client_identity_user_agent() {
    let id = ClientIdentity::new("foo", "42");
    assert_eq!(id.user_agent(), "foo/42");
}

#[test]
fn client_identity_default() {
    let id = ClientIdentity::default();
    assert_eq!(id.app_name, DEFAULT_APP_NAME);
    assert_eq!(id.runtime, DEFAULT_RUNTIME);
}

#[test]
fn client_identity_eq() {
    let a = ClientIdentity::new("app", "1.0");
    let b = ClientIdentity::new("app", "1.0");
    assert_eq!(a, b);
}

#[test]
fn client_identity_ne() {
    let a = ClientIdentity::new("app1", "1.0");
    let b = ClientIdentity::new("app2", "1.0");
    assert_ne!(a, b);
}

#[test]
fn client_identity_clone() {
    let id = ClientIdentity::new("app", "1.0").with_runtime("go");
    let c = id.clone();
    assert_eq!(c.app_name, "app");
    assert_eq!(c.runtime, "go");
}

#[test]
fn client_identity_serde_roundtrip() {
    let id = ClientIdentity::new("test", "1.0");
    let json = serde_json::to_string(&id).unwrap();
    let back: ClientIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, id);
}

#[test]
fn client_identity_debug() {
    let id = ClientIdentity::new("app", "1.0");
    let d = format!("{id:?}");
    assert!(d.contains("app"));
}

#[test]
fn anthropic_request_profile_new() {
    let id = ClientIdentity::new("test", "1.0");
    let p = AnthropicRequestProfile::new(id);
    assert_eq!(p.anthropic_version, DEFAULT_ANTHROPIC_VERSION);
    assert_eq!(p.betas.len(), 2);
    assert!(p.extra_body.is_empty());
}

#[test]
fn anthropic_request_profile_with_beta() {
    let id = ClientIdentity::new("test", "1.0");
    let p = AnthropicRequestProfile::new(id).with_beta("custom-beta");
    assert_eq!(p.betas.len(), 3);
    assert!(p.betas.contains(&"custom-beta".to_string()));
}

#[test]
fn anthropic_request_profile_beta_dedup() {
    let id = ClientIdentity::new("test", "1.0");
    let p = AnthropicRequestProfile::new(id).with_beta(DEFAULT_AGENTIC_BETA.to_string());
    assert_eq!(p.betas.len(), 2);
}

#[test]
fn anthropic_request_profile_with_extra_body() {
    let id = ClientIdentity::new("test", "1.0");
    let p = AnthropicRequestProfile::new(id)
        .with_extra_body("key", Value::Bool(true));
    assert_eq!(p.extra_body["key"], Value::Bool(true));
}

#[test]
fn anthropic_request_profile_header_pairs() {
    let id = ClientIdentity::new("test", "1.0");
    let p = AnthropicRequestProfile::new(id);
    let pairs = p.header_pairs();
    assert_eq!(pairs.len(), 3);
    assert!(pairs.iter().any(|(k, _)| k == "anthropic-version"));
    assert!(pairs.iter().any(|(k, _)| k == "user-agent"));
    assert!(pairs.iter().any(|(k, _)| k == "anthropic-beta"));
}

#[test]
fn anthropic_request_profile_header_pairs_no_betas() {
    let id = ClientIdentity::new("test", "1.0");
    let mut p = AnthropicRequestProfile::new(id);
    p.betas.clear();
    let pairs = p.header_pairs();
    assert_eq!(pairs.len(), 2);
    assert!(!pairs.iter().any(|(k, _)| k == "anthropic-beta"));
}

#[test]
fn anthropic_request_profile_default() {
    let p = AnthropicRequestProfile::default();
    assert_eq!(p.anthropic_version, DEFAULT_ANTHROPIC_VERSION);
    assert_eq!(p.client_identity.app_name, DEFAULT_APP_NAME);
}

#[test]
fn anthropic_request_profile_render_json_body() {
    let id = ClientIdentity::new("test", "1.0");
    let p = AnthropicRequestProfile::new(id);
    let body = p.render_json_body(&json!({"model": "claude-sonnet"})).unwrap();
    assert_eq!(body["model"], "claude-sonnet");
    assert!(body["betas"].is_array());
}

#[test]
fn anthropic_request_profile_render_json_body_with_extra() {
    let id = ClientIdentity::new("test", "1.0");
    let p = AnthropicRequestProfile::new(id)
        .with_extra_body("metadata", json!({"source": "test"}));
    let body = p.render_json_body(&json!({"model": "test"})).unwrap();
    assert_eq!(body["metadata"]["source"], "test");
}

#[test]
fn anthropic_request_profile_render_non_object_error() {
    let id = ClientIdentity::new("test", "1.0");
    let p = AnthropicRequestProfile::new(id);
    let result = p.render_json_body(&vec![1, 2, 3]);
    assert!(result.is_err());
}

#[test]
fn anthropic_request_profile_serde_roundtrip() {
    let id = ClientIdentity::new("test", "1.0");
    let p = AnthropicRequestProfile::new(id);
    let json = serde_json::to_string(&p).unwrap();
    let back: AnthropicRequestProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(back.anthropic_version, p.anthropic_version);
}

#[test]
fn analytics_event_new() {
    let e = AnalyticsEvent::new("ns", "act");
    assert_eq!(e.namespace, "ns");
    assert_eq!(e.action, "act");
    assert!(e.properties.is_empty());
}

#[test]
fn analytics_event_with_property() {
    let e = AnalyticsEvent::new("ns", "act")
        .with_property("k", Value::Number(42.into()));
    assert_eq!(e.properties["k"], Value::Number(42.into()));
}

#[test]
fn analytics_event_multiple_properties() {
    let e = AnalyticsEvent::new("ns", "act")
        .with_property("a", Value::Bool(true))
        .with_property("b", Value::String("x".into()));
    assert_eq!(e.properties.len(), 2);
}

#[test]
fn analytics_event_clone() {
    let e = AnalyticsEvent::new("ns", "act")
        .with_property("k", Value::Bool(true));
    let c = e.clone();
    assert_eq!(c.namespace, "ns");
    assert_eq!(c.properties.len(), 1);
}

#[test]
fn analytics_event_eq() {
    let a = AnalyticsEvent::new("ns", "act");
    let b = AnalyticsEvent::new("ns", "act");
    assert_eq!(a, b);
}

#[test]
fn analytics_event_ne() {
    let a = AnalyticsEvent::new("ns1", "act");
    let b = AnalyticsEvent::new("ns2", "act");
    assert_ne!(a, b);
}

#[test]
fn analytics_event_serde_roundtrip() {
    let e = AnalyticsEvent::new("ns", "act")
        .with_property("k", Value::Bool(true));
    let json = serde_json::to_string(&e).unwrap();
    let back: AnalyticsEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.namespace, "ns");
}

#[test]
fn analytics_event_debug() {
    let e = AnalyticsEvent::new("ns", "act");
    let d = format!("{e:?}");
    assert!(d.contains("AnalyticsEvent"));
}

#[test]
fn memory_sink_empty() {
    let s = MemoryTelemetrySink::default();
    assert!(s.events().is_empty());
}

#[test]
fn memory_sink_record_one() {
    let s = MemoryTelemetrySink::default();
    s.record(TelemetryEvent::Analytics(AnalyticsEvent::new("a", "b")));
    assert_eq!(s.events().len(), 1);
}

#[test]
fn memory_sink_record_multiple() {
    let s = MemoryTelemetrySink::default();
    for i in 0..10 {
        s.record(TelemetryEvent::Analytics(AnalyticsEvent::new("ns", format!("act{i}"))));
    }
    assert_eq!(s.events().len(), 10);
}

#[test]
fn memory_sink_events_clone() {
    let s = MemoryTelemetrySink::default();
    s.record(TelemetryEvent::Analytics(AnalyticsEvent::new("a", "b")));
    let events = s.events();
    assert_eq!(events.len(), 1);
}

#[test]
fn memory_sink_is_default() {
    let _s = MemoryTelemetrySink::default();
}

#[test]
fn session_tracer_new() {
    let s = sink();
    let t = SessionTracer::new("sess-1", s);
    assert_eq!(t.session_id(), "sess-1");
}

#[test]
fn session_tracer_record() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    let mut attrs = Map::new();
    attrs.insert("foo".into(), Value::Bool(true));
    t.record("custom_event", attrs);
    let events = s.events();
    assert_eq!(events.len(), 1);
    match &events[0] {
        TelemetryEvent::SessionTrace(r) => {
            assert_eq!(r.name, "custom_event");
            assert_eq!(r.session_id, "s");
            assert_eq!(r.attributes["foo"], Value::Bool(true));
        }
        _ => panic!("expected SessionTrace"),
    }
}

#[test]
fn session_tracer_record_sequence() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record("a", Map::new());
    t.record("b", Map::new());
    t.record("c", Map::new());
    let events = s.events();
    let seqs: Vec<u64> = events.iter().filter_map(|e| match e {
        TelemetryEvent::SessionTrace(r) => Some(r.sequence),
        _ => None,
    }).collect();
    assert_eq!(seqs, vec![0, 1, 2]);
}

#[test]
fn session_tracer_record_http_started() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_http_request_started(1, "POST", "/v1/messages", Map::new());
    let events = s.events();
    assert_eq!(events.len(), 2);
    match &events[0] {
        TelemetryEvent::HttpRequestStarted { session_id, attempt, method, path, .. } => {
            assert_eq!(session_id, "s");
            assert_eq!(*attempt, 1);
            assert_eq!(method, "POST");
            assert_eq!(path, "/v1/messages");
        }
        _ => panic!("expected HttpRequestStarted"),
    }
}

#[test]
fn session_tracer_record_http_succeeded() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_http_request_succeeded(1, "GET", "/test", 200, Some("req-123".into()), Map::new());
    let events = s.events();
    assert_eq!(events.len(), 2);
    match &events[0] {
        TelemetryEvent::HttpRequestSucceeded { status, request_id, .. } => {
            assert_eq!(*status, 200);
            assert_eq!(request_id.as_deref(), Some("req-123"));
        }
        _ => panic!("expected HttpRequestSucceeded"),
    }
}

#[test]
fn session_tracer_record_http_succeeded_no_request_id() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_http_request_succeeded(1, "GET", "/test", 200, None, Map::new());
    let events = s.events();
    match &events[0] {
        TelemetryEvent::HttpRequestSucceeded { request_id, .. } => {
            assert!(request_id.is_none());
        }
        _ => panic!("expected HttpRequestSucceeded"),
    }
}

#[test]
fn session_tracer_record_http_failed() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_http_request_failed(2, "POST", "/v1/messages", "timeout", true, Map::new());
    let events = s.events();
    assert_eq!(events.len(), 2);
    match &events[0] {
        TelemetryEvent::HttpRequestFailed { retryable, error, .. } => {
            assert!(*retryable);
            assert_eq!(error, "timeout");
        }
        _ => panic!("expected HttpRequestFailed"),
    }
}

#[test]
fn session_tracer_record_http_failed_not_retryable() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_http_request_failed(1, "POST", "/test", "error", false, Map::new());
    let events = s.events();
    match &events[0] {
        TelemetryEvent::HttpRequestFailed { retryable, .. } => {
            assert!(!retryable);
        }
        _ => panic!("expected HttpRequestFailed"),
    }
}

#[test]
fn session_tracer_record_analytics() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_analytics(
        AnalyticsEvent::new("cli", "prompt_sent")
            .with_property("model", Value::String("claude-opus".into())),
    );
    let events = s.events();
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], TelemetryEvent::Analytics(_)));
}

#[test]
fn session_tracer_analytics_copies_to_trace() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_analytics(
        AnalyticsEvent::new("ns", "act")
            .with_property("key", Value::String("val".into())),
    );
    let events = s.events();
    match &events[1] {
        TelemetryEvent::SessionTrace(r) => {
            assert_eq!(r.attributes["namespace"], Value::String("ns".into()));
            assert_eq!(r.attributes["action"], Value::String("act".into()));
            assert_eq!(r.attributes["key"], Value::String("val".into()));
        }
        _ => panic!("expected SessionTrace"),
    }
}

#[test]
fn session_tracer_started_trace_has_method_path_attempt() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_http_request_started(3, "PUT", "/api/v2", Map::new());
    let events = s.events();
    match &events[1] {
        TelemetryEvent::SessionTrace(r) => {
            assert_eq!(r.attributes["method"], Value::String("PUT".into()));
            assert_eq!(r.attributes["path"], Value::String("/api/v2".into()));
            assert_eq!(r.attributes["attempt"], Value::from(3));
        }
        _ => panic!("expected SessionTrace"),
    }
}

#[test]
fn session_tracer_succeeded_trace_has_status() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_http_request_succeeded(1, "GET", "/test", 404, None, Map::new());
    let events = s.events();
    match &events[1] {
        TelemetryEvent::SessionTrace(r) => {
            assert_eq!(r.attributes["status"], Value::Number(404.into()));
        }
        _ => panic!("expected SessionTrace"),
    }
}

#[test]
fn session_tracer_failed_trace_has_error() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    t.record_http_request_failed(1, "POST", "/test", "connection refused", false, Map::new());
    let events = s.events();
    match &events[1] {
        TelemetryEvent::SessionTrace(r) => {
            assert_eq!(r.attributes["error"], Value::String("connection refused".into()));
            assert_eq!(r.attributes["retryable"], Value::Bool(false));
        }
        _ => panic!("expected SessionTrace"),
    }
}

#[test]
fn session_tracer_clone() {
    let s = sink();
    let t = SessionTracer::new("s", s);
    let _c = t.clone();
}

#[test]
fn session_tracer_debug() {
    let s = sink();
    let t = SessionTracer::new("s", s);
    let d = format!("{t:?}");
    assert!(d.contains("SessionTracer"));
}

#[test]
fn telemetry_event_http_started_serde() {
    let e = TelemetryEvent::HttpRequestStarted {
        session_id: "s".into(),
        attempt: 1,
        method: "GET".into(),
        path: "/".into(),
        attributes: Map::new(),
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"type\":\"http_request_started\""));
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, TelemetryEvent::HttpRequestStarted { .. }));
}

#[test]
fn telemetry_event_http_succeeded_serde() {
    let e = TelemetryEvent::HttpRequestSucceeded {
        session_id: "s".into(),
        attempt: 1,
        method: "GET".into(),
        path: "/".into(),
        status: 200,
        request_id: Some("r1".into()),
        attributes: Map::new(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    match back {
        TelemetryEvent::HttpRequestSucceeded { status, request_id, .. } => {
            assert_eq!(status, 200);
            assert_eq!(request_id.as_deref(), Some("r1"));
        }
        _ => panic!("expected HttpRequestSucceeded"),
    }
}

#[test]
fn telemetry_event_http_failed_serde() {
    let e = TelemetryEvent::HttpRequestFailed {
        session_id: "s".into(),
        attempt: 1,
        method: "POST".into(),
        path: "/".into(),
        error: "err".into(),
        retryable: true,
        attributes: Map::new(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    match back {
        TelemetryEvent::HttpRequestFailed { retryable, error, .. } => {
            assert!(retryable);
            assert_eq!(error, "err");
        }
        _ => panic!("expected HttpRequestFailed"),
    }
}

#[test]
fn telemetry_event_analytics_serde() {
    let e = TelemetryEvent::Analytics(AnalyticsEvent::new("n", "a"));
    let json = serde_json::to_string(&e).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, TelemetryEvent::Analytics(_)));
}

#[test]
fn telemetry_event_session_trace_serde() {
    let e = TelemetryEvent::SessionTrace(SessionTraceRecord {
        session_id: "s".into(),
        sequence: 5,
        name: "test".into(),
        timestamp_ms: 12345,
        attributes: Map::new(),
    });
    let json = serde_json::to_string(&e).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    match back {
        TelemetryEvent::SessionTrace(r) => {
            assert_eq!(r.sequence, 5);
            assert_eq!(r.name, "test");
        }
        _ => panic!("expected SessionTrace"),
    }
}

#[test]
fn telemetry_event_all_variants_serde_roundtrip() {
    let events = vec![
        TelemetryEvent::HttpRequestStarted {
            session_id: "s".into(),
            attempt: 1,
            method: "GET".into(),
            path: "/".into(),
            attributes: Map::new(),
        },
        TelemetryEvent::HttpRequestSucceeded {
            session_id: "s".into(),
            attempt: 1,
            method: "GET".into(),
            path: "/".into(),
            status: 200,
            request_id: None,
            attributes: Map::new(),
        },
        TelemetryEvent::HttpRequestFailed {
            session_id: "s".into(),
            attempt: 1,
            method: "GET".into(),
            path: "/".into(),
            error: "err".into(),
            retryable: false,
            attributes: Map::new(),
        },
        TelemetryEvent::Analytics(AnalyticsEvent::new("n", "a")),
        TelemetryEvent::SessionTrace(SessionTraceRecord {
            session_id: "s".into(),
            sequence: 0,
            name: "t".into(),
            timestamp_ms: 1000,
            attributes: Map::new(),
        }),
    ];
    for event in &events {
        let json = serde_json::to_string(event).unwrap();
        let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }
}

#[test]
fn session_trace_record_struct() {
    let r = SessionTraceRecord {
        session_id: "s".into(),
        sequence: 42,
        name: "test".into(),
        timestamp_ms: 999,
        attributes: Map::new(),
    };
    assert_eq!(r.sequence, 42);
    assert_eq!(r.timestamp_ms, 999);
}

#[test]
fn session_trace_record_clone() {
    let r = SessionTraceRecord {
        session_id: "s".into(),
        sequence: 1,
        name: "t".into(),
        timestamp_ms: 100,
        attributes: Map::new(),
    };
    let c = r.clone();
    assert_eq!(c.sequence, 1);
}

#[test]
fn session_trace_record_serde_roundtrip() {
    let r = SessionTraceRecord {
        session_id: "s".into(),
        sequence: 7,
        name: "ev".into(),
        timestamp_ms: 5000,
        attributes: {
            let mut m = Map::new();
            m.insert("key".into(), Value::String("val".into()));
            m
        },
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: SessionTraceRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sequence, 7);
    assert_eq!(back.attributes["key"], Value::String("val".into()));
}

#[test]
fn jsonl_sink_new() {
    let dir = std::env::temp_dir().join(format!("telemetry-jsonl-test-{}", current_ts()));
    let file = dir.join("test.log");
    let _sink = JsonlTelemetrySink::new(&file).unwrap();
    assert_eq!(_sink.path(), file.as_path());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn jsonl_sink_record() {
    let dir = std::env::temp_dir().join(format!("telemetry-jsonl-test-{}", current_ts()));
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("test.log");
    let sink = JsonlTelemetrySink::new(&file).unwrap();
    sink.record(TelemetryEvent::Analytics(AnalyticsEvent::new("cli", "turn_done")));
    let contents = std::fs::read_to_string(&file).unwrap();
    assert!(contents.contains("\"type\":\"analytics\""));
    assert!(contents.contains("\"action\":\"turn_done\""));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn jsonl_sink_debug() {
    let dir = std::env::temp_dir().join(format!("telemetry-jsonl-debug-{}", current_ts()));
    let file = dir.join("debug.log");
    let sink = JsonlTelemetrySink::new(&file).unwrap();
    let d = format!("{sink:?}");
    assert!(d.contains("JsonlTelemetrySink"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn constants_values() {
    assert_eq!(DEFAULT_ANTHROPIC_VERSION, "2023-06-01");
    assert_eq!(DEFAULT_APP_NAME, "claude-code");
    assert_eq!(DEFAULT_RUNTIME, "rust");
    assert_eq!(DEFAULT_AGENTIC_BETA, "claude-code-20250219");
    assert_eq!(DEFAULT_PROMPT_CACHING_SCOPE_BETA, "prompt-caching-scope-2026-01-05");
}

#[test]
fn client_identity_with_runtime_chained() {
    let id = ClientIdentity::new("a", "b").with_runtime("x").with_runtime("y");
    assert_eq!(id.runtime, "y");
}

#[test]
fn anthropic_profile_multiple_betas() {
    let id = ClientIdentity::new("t", "1");
    let p = AnthropicRequestProfile::new(id)
        .with_beta("beta1")
        .with_beta("beta2")
        .with_beta("beta3");
    assert_eq!(p.betas.len(), 5);
}

#[test]
fn anthropic_profile_render_preserves_original_fields() {
    let id = ClientIdentity::new("t", "1");
    let p = AnthropicRequestProfile::new(id);
    let body = p.render_json_body(&json!({"model": "claude-opus", "max_tokens": 100})).unwrap();
    assert_eq!(body["model"], "claude-opus");
    assert_eq!(body["max_tokens"], 100);
}

#[test]
fn analytics_event_property_override() {
    let e = AnalyticsEvent::new("ns", "act")
        .with_property("k", Value::Number(1.into()))
        .with_property("k", Value::Number(2.into()));
    assert_eq!(e.properties["k"], Value::Number(2.into()));
}

#[test]
fn memory_sink_thread_safe() {
    use std::thread;
    let s = Arc::new(MemoryTelemetrySink::default());
    let mut handles = vec![];
    for i in 0..5 {
        let s2 = Arc::clone(&s);
        handles.push(thread::spawn(move || {
            s2.record(TelemetryEvent::Analytics(AnalyticsEvent::new("ns", format!("a{i}"))));
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(s.events().len(), 5);
}

#[test]
fn session_tracer_http_started_with_attributes() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    let mut attrs = Map::new();
    attrs.insert("custom".into(), Value::String("val".into()));
    t.record_http_request_started(1, "POST", "/api", attrs);
    let events = s.events();
    match &events[0] {
        TelemetryEvent::HttpRequestStarted { attributes, .. } => {
            assert_eq!(attributes["custom"], Value::String("val".into()));
        }
        _ => panic!("expected HttpRequestStarted"),
    }
}

#[test]
fn session_tracer_http_succeeded_with_attributes() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    let mut attrs = Map::new();
    attrs.insert("extra".into(), Value::Bool(true));
    t.record_http_request_succeeded(1, "GET", "/test", 200, None, attrs);
    let events = s.events();
    match &events[0] {
        TelemetryEvent::HttpRequestSucceeded { attributes, .. } => {
            assert_eq!(attributes["extra"], Value::Bool(true));
        }
        _ => panic!("expected HttpRequestSucceeded"),
    }
}

#[test]
fn session_tracer_http_failed_with_attributes() {
    let s = sink();
    let t = SessionTracer::new("s", s.clone());
    let mut attrs = Map::new();
    attrs.insert("detail".into(), Value::Number(42.into()));
    t.record_http_request_failed(1, "POST", "/test", "err", false, attrs);
    let events = s.events();
    match &events[0] {
        TelemetryEvent::HttpRequestFailed { attributes, .. } => {
            assert_eq!(attributes["detail"], Value::Number(42.into()));
        }
        _ => panic!("expected HttpRequestFailed"),
    }
}

#[test]
fn telemetry_event_debug() {
    let e = TelemetryEvent::Analytics(AnalyticsEvent::new("n", "a"));
    let d = format!("{e:?}");
    assert!(d.contains("Analytics"));
}

#[test]
fn session_trace_record_debug() {
    let r = SessionTraceRecord {
        session_id: "s".into(),
        sequence: 0,
        name: "t".into(),
        timestamp_ms: 0,
        attributes: Map::new(),
    };
    let d = format!("{r:?}");
    assert!(d.contains("SessionTraceRecord"));
}

#[test]
fn telemetry_event_with_attributes_serde() {
    let mut attrs = Map::new();
    attrs.insert("key".into(), Value::String("value".into()));
    let e = TelemetryEvent::HttpRequestStarted {
        session_id: "s".into(),
        attempt: 1,
        method: "GET".into(),
        path: "/".into(),
        attributes: attrs,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    match back {
        TelemetryEvent::HttpRequestStarted { attributes, .. } => {
            assert_eq!(attributes["key"], Value::String("value".into()));
        }
        _ => panic!("expected HttpRequestStarted"),
    }
}

fn current_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
