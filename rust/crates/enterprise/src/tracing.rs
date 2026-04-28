//! Distributed tracing for request correlation

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
}
