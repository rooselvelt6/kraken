/// Distributed tracing for request correlation
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub operation: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub tags: HashMap<String, String>,
    pub status: SpanStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpanStatus {
    Started,
    Ok,
    Error,
}

impl TraceContext {
    pub fn new(operation: &str) -> Self {
        Self {
            trace_id: Uuid::new_v4().to_string(),
            span_id: Uuid::new_v4().to_string()[..8].to_string(),
            parent_span_id: None,
            operation: operation.to_string(),
            start_time: Utc::now(),
            end_time: None,
            tags: HashMap::new(),
            status: SpanStatus::Started,
        }
    }

    pub fn with_parent(mut self, parent: &TraceContext) -> Self {
        self.parent_span_id = Some(parent.span_id.clone());
        self
    }

    pub fn with_tag(mut self, key: &str, value: &str) -> Self {
        self.tags.insert(key.to_string(), value.to_string());
        self
    }

    pub fn finish(&mut self) {
        self.end_time = Some(Utc::now());
    }

    pub fn finish_ok(&mut self) {
        self.status = SpanStatus::Ok;
        self.finish();
    }

    pub fn finish_error(&mut self) {
        self.status = SpanStatus::Error;
        self.finish();
    }

    pub fn duration_ms(&self) -> Option<i64> {
        self.end_time
            .map(|end| (end - self.start_time).num_milliseconds())
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

pub struct SpanTracer {
    current: Option<TraceContext>,
    spans: Vec<TraceContext>,
}

impl SpanTracer {
    pub fn new() -> Self {
        Self {
            current: None,
            spans: Vec::new(),
        }
    }

    pub fn start_span(&mut self, operation: &str) -> &mut TraceContext {
        let mut span = TraceContext::new(operation);
        if let Some(ref parent) = self.current {
            span = span.with_parent(parent);
        }
        self.current = Some(span);
        self.current.as_mut().unwrap()
    }

    pub fn end_span(&mut self) {
        if let Some(mut span) = self.current.take() {
            span.finish();
            self.spans.push(span);
        }
    }

    pub fn end_span_ok(&mut self) {
        if let Some(mut span) = self.current.take() {
            span.finish_ok();
            self.spans.push(span);
        }
    }

    pub fn end_span_error(&mut self) {
        if let Some(mut span) = self.current.take() {
            span.finish_error();
            self.spans.push(span);
        }
    }

    pub fn get_current(&self) -> Option<&TraceContext> {
        self.current.as_ref()
    }

    pub fn get_spans(&self) -> &Vec<TraceContext> {
        &self.spans
    }

    pub fn clear(&mut self) {
        self.spans.clear();
        self.current = None;
    }
}

impl Default for SpanTracer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceCollector {
    traces: Vec<TraceContext>,
}

impl TraceCollector {
    pub fn new() -> Self {
        Self { traces: Vec::new() }
    }

    pub fn add_span(&mut self, span: TraceContext) {
        self.traces.push(span);
    }

    pub fn finish_trace(&mut self, trace_id: &str) -> Vec<TraceContext> {
        let spans: Vec<TraceContext> = self
            .traces
            .drain(..)
            .filter(|s| s.trace_id == trace_id)
            .collect();
        spans
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.traces).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_creation() {
        let trace = TraceContext::new("api_request");

        assert!(!trace.trace_id.is_empty());
        assert!(!trace.span_id.is_empty());
        assert_eq!(trace.operation, "api_request");
    }

    #[test]
    fn test_span_tracer() {
        let mut tracer = SpanTracer::new();

        tracer.start_span("test_operation");
        assert!(tracer.get_current().is_some());

        tracer.end_span_ok();
        assert!(tracer.get_current().is_none());
        assert_eq!(tracer.spans.len(), 1);
    }

    #[test]
    fn test_trace_with_tags() {
        let trace = TraceContext::new("request")
            .with_tag("provider", "deepseek")
            .with_tag("model", "deepseek-chat");

        assert_eq!(trace.tags.get("provider"), Some(&"deepseek".to_string()));
    }

    #[test]
    fn test_trace_context_defaults() {
        let trace = TraceContext::new("op");
        assert!(trace.parent_span_id.is_none());
        assert!(trace.end_time.is_none());
        assert!(trace.tags.is_empty());
        assert!(matches!(trace.status, SpanStatus::Started));
    }

    #[test]
    fn test_trace_context_with_parent() {
        let parent = TraceContext::new("parent_op");
        let child = TraceContext::new("child_op").with_parent(&parent);

        assert_eq!(child.parent_span_id, Some(parent.span_id));
        assert_ne!(child.trace_id, parent.trace_id);
    }

    #[test]
    fn test_trace_context_with_multiple_tags() {
        let trace = TraceContext::new("op")
            .with_tag("k1", "v1")
            .with_tag("k2", "v2")
            .with_tag("k3", "v3");

        assert_eq!(trace.tags.len(), 3);
        assert_eq!(trace.tags.get("k1"), Some(&"v1".to_string()));
        assert_eq!(trace.tags.get("k3"), Some(&"v3".to_string()));
    }

    #[test]
    fn test_trace_context_tag_overwrite() {
        let trace = TraceContext::new("op")
            .with_tag("k", "v1")
            .with_tag("k", "v2");
        assert_eq!(trace.tags.get("k"), Some(&"v2".to_string()));
    }

    #[test]
    fn test_trace_context_finish() {
        let mut trace = TraceContext::new("op");
        assert!(trace.end_time.is_none());

        trace.finish();
        assert!(trace.end_time.is_some());
        assert!(matches!(trace.status, SpanStatus::Started));
    }

    #[test]
    fn test_trace_context_finish_ok() {
        let mut trace = TraceContext::new("op");
        trace.finish_ok();
        assert!(trace.end_time.is_some());
        assert!(matches!(trace.status, SpanStatus::Ok));
    }

    #[test]
    fn test_trace_context_finish_error() {
        let mut trace = TraceContext::new("op");
        trace.finish_error();
        assert!(trace.end_time.is_some());
        assert!(matches!(trace.status, SpanStatus::Error));
    }

    #[test]
    fn test_trace_context_duration_ms_none_when_unfinished() {
        let trace = TraceContext::new("op");
        assert!(trace.duration_ms().is_none());
    }

    #[test]
    fn test_trace_context_duration_ms_some_when_finished() {
        let mut trace = TraceContext::new("op");
        trace.finish();
        let dur = trace.duration_ms();
        assert!(dur.is_some());
        assert!(dur.unwrap() >= 0);
    }

    #[test]
    fn test_trace_context_to_json() {
        let trace = TraceContext::new("op");
        let json = trace.to_json();
        assert!(!json.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["operation"], "op");
    }

    #[test]
    fn test_trace_context_serialization_roundtrip() {
        let trace = TraceContext::new("api_call")
            .with_tag("key", "val")
            .with_parent(&TraceContext::new("parent"));

        let json = serde_json::to_string(&trace).unwrap();
        let deserialized: TraceContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.operation, "api_call");
        assert_eq!(deserialized.tags.get("key"), Some(&"val".to_string()));
        assert!(deserialized.parent_span_id.is_some());
    }

    #[test]
    fn test_span_status_serialization() {
        for status in [SpanStatus::Started, SpanStatus::Ok, SpanStatus::Error] {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: SpanStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_span_status_equality() {
        assert_eq!(SpanStatus::Started, SpanStatus::Started);
        assert_ne!(SpanStatus::Started, SpanStatus::Ok);
        assert_ne!(SpanStatus::Ok, SpanStatus::Error);
    }

    #[test]
    fn test_span_tracer_default() {
        let tracer = SpanTracer::default();
        assert!(tracer.get_current().is_none());
        assert!(tracer.get_spans().is_empty());
    }

    #[test]
    fn test_span_tracer_nested_spans() {
        let mut tracer = SpanTracer::new();

        tracer.start_span("outer");
        let outer_id = tracer.get_current().unwrap().span_id.clone();

        tracer.start_span("inner");
        let inner = tracer.get_current().unwrap();
        assert_eq!(inner.parent_span_id.as_ref().unwrap(), &outer_id);

        tracer.end_span_ok(); // ends inner, current becomes None
        assert!(tracer.get_current().is_none());

        tracer.end_span_ok(); // no-op (already None)
        assert_eq!(tracer.get_spans().len(), 1);
    }

    #[test]
    fn test_span_tracer_end_span() {
        let mut tracer = SpanTracer::new();
        tracer.start_span("op");
        tracer.end_span();

        let spans = tracer.get_spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].status, SpanStatus::Started); // end_span doesn't change status
    }

    #[test]
    fn test_span_tracer_end_span_error() {
        let mut tracer = SpanTracer::new();
        tracer.start_span("op");
        tracer.end_span_error();

        let spans = tracer.get_spans();
        assert_eq!(spans.len(), 1);
        assert!(matches!(spans[0].status, SpanStatus::Error));
        assert!(spans[0].end_time.is_some());
    }

    #[test]
    fn test_span_tracer_end_span_empty() {
        let mut tracer = SpanTracer::new();
        tracer.end_span(); // no current span
        assert!(tracer.get_spans().is_empty());
    }

    #[test]
    fn test_span_tracer_clear() {
        let mut tracer = SpanTracer::new();
        tracer.start_span("op1");
        tracer.end_span_ok();
        tracer.start_span("op2");

        tracer.clear();
        assert!(tracer.get_current().is_none());
        assert!(tracer.get_spans().is_empty());
    }

    #[test]
    fn test_trace_collector_new() {
        let collector = TraceCollector::new();
        assert!(collector.traces.is_empty());
    }

    #[test]
    fn test_trace_collector_add_span() {
        let mut collector = TraceCollector::new();
        collector.add_span(TraceContext::new("op1"));
        collector.add_span(TraceContext::new("op2"));

        let json = collector.to_json();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_trace_collector_finish_trace() {
        let mut collector = TraceCollector::new();

        let mut span1 = TraceContext::new("op1");
        let trace_id = span1.trace_id.clone();
        span1.finish_ok();

        let mut span2 = TraceContext::new("op2");
        span2.trace_id = trace_id.clone();
        span2.finish_ok();

        let other = TraceContext::new("op3"); // different trace_id

        collector.add_span(span1);
        collector.add_span(span2);
        collector.add_span(other);

        let collected = collector.finish_trace(&trace_id);
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_trace_collector_finish_trace_removes_spans() {
        let mut collector = TraceCollector::new();
        let mut span = TraceContext::new("op");
        let trace_id = span.trace_id.clone();
        span.finish_ok();
        collector.add_span(span);

        collector.finish_trace(&trace_id);
        assert!(collector.traces.is_empty());
    }

    #[test]
    fn test_trace_collector_finish_trace_unknown_id() {
        let mut collector = TraceCollector::new();
        collector.add_span(TraceContext::new("op"));

        let result = collector.finish_trace("nonexistent");
        assert!(result.is_empty());
    }

    #[test]
    fn test_trace_collector_to_json_empty() {
        let collector = TraceCollector::new();
        assert_eq!(collector.to_json(), "[]");
    }

    #[test]
    fn test_trace_context_clone() {
        let trace = TraceContext::new("op").with_tag("k", "v");
        let cloned = trace.clone();
        assert_eq!(cloned.operation, "op");
        assert_eq!(cloned.tags.get("k"), Some(&"v".to_string()));
    }

    #[test]
    fn test_trace_context_unique_ids() {
        let t1 = TraceContext::new("op");
        let t2 = TraceContext::new("op");
        assert_ne!(t1.trace_id, t2.trace_id);
        assert_ne!(t1.span_id, t2.span_id);
    }
}
