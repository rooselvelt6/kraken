use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum context window size in tokens (Kimi K3 = 1M).
pub const MAX_CONTEXT_TOKENS: usize = 1_000_000;

/// Reserved tokens for system prompt + output.
pub const RESERVED_TOKENS: usize = 8_192;

/// Available context for code: MAX - RESERVED.
pub const AVAILABLE_CONTEXT_TOKENS: usize = MAX_CONTEXT_TOKENS - RESERVED_TOKENS;

/// Rough estimate: 1 token ≈ 4 bytes of code.
pub const BYTES_PER_TOKEN: usize = 4;

/// A chunk of code with relevance metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeChunk {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
    pub relevance_score: f64,
    pub token_estimate: usize,
    pub risk_rank: u8,
}

/// A filtered context window ready to send to an LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveContext {
    pub chunks: Vec<CodeChunk>,
    pub total_tokens: usize,
    pub total_files: usize,
    pub truncated: bool,
}

/// Caches previously computed contexts for re-analysis.
#[derive(Debug, Default)]
pub struct ContextCache {
    entries: HashMap<String, SelectiveContext>,
}

impl ContextCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&SelectiveContext> {
        self.entries.get(key)
    }

    pub fn insert(&mut self, key: String, context: SelectiveContext) {
        self.entries.insert(key, context);
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Estimates token count for a code string.
pub fn estimate_tokens(code: &str) -> usize {
    code.len().div_ceil(BYTES_PER_TOKEN)
}

/// Splits source code into line-based chunks with overlap.
pub fn chunk_source(
    path: &str,
    content: &str,
    chunk_lines: usize,
    overlap_lines: usize,
) -> Vec<CodeChunk> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let mut start = 0;

    while start < lines.len() {
        let end = (start + chunk_lines).min(lines.len());
        let chunk_content: String = lines[start..end].join("\n");
        let token_estimate = estimate_tokens(&chunk_content);

        chunks.push(CodeChunk {
            path: path.to_string(),
            start_line: start + 1,
            end_line: end,
            content: chunk_content,
            relevance_score: 0.0,
            token_estimate,
            risk_rank: 0,
        });

        if end >= lines.len() {
            break;
        }
        start = end - overlap_lines;
        if start >= lines.len() {
            break;
        }
    }

    chunks
}

/// Scores a chunk's relevance to a set of keywords.
pub fn score_relevance(chunk: &mut CodeChunk, keywords: &[String]) {
    if keywords.is_empty() {
        chunk.relevance_score = 0.5;
        return;
    }

    let lower = chunk.content.to_lowercase();
    let mut matches = 0;
    for kw in keywords {
        matches += lower.matches(&kw.to_lowercase()).count();
    }

    let keyword_density = matches as f64 / (chunk.content.len() as f64 + 1.0);
    let length_penalty = if chunk.token_estimate > 2000 {
        0.8
    } else {
        1.0
    };

    chunk.relevance_score = (keyword_density * 100.0 * length_penalty).min(1.0);
}

/// Ranks chunks by risk based on vulnerability-relevant patterns.
pub fn rank_risk(chunk: &mut CodeChunk) {
    let lower = chunk.content.to_lowercase();
    let mut risk: u8 = 0;

    let high_risk = [
        "unsafe",
        "transmute",
        "raw pointer",
        "strcpy",
        "sprintf",
        "gets(",
        "memcpy",
        "kfree",
        "copy_from_user",
        "ioctl",
    ];
    let medium_risk = [
        "malloc",
        "kmalloc",
        "unwrap()",
        "expect(",
        "as_ptr",
        "into_raw",
        "null",
        "free(",
    ];

    for pattern in &high_risk {
        if lower.contains(pattern) {
            risk = risk.max(3);
        }
    }
    for pattern in &medium_risk {
        if lower.contains(pattern) {
            risk = risk.max(2);
        }
    }
    if lower.contains("todo!") || lower.contains("fixme") || lower.contains("hack") {
        risk = risk.max(1);
    }

    chunk.risk_rank = risk;
}

/// Builds a selective context window that fits within token budget.
pub fn build_selective_context(
    chunks: &mut [CodeChunk],
    keywords: &[String],
    budget_tokens: usize,
) -> SelectiveContext {
    for chunk in chunks.iter_mut() {
        score_relevance(chunk, keywords);
        rank_risk(chunk);
    }

    chunks.sort_by(|a, b| {
        b.risk_rank
            .cmp(&a.risk_rank)
            .then_with(|| b.relevance_score.partial_cmp(&a.relevance_score).unwrap_or(std::cmp::Ordering::Equal))
    });

    let mut selected = Vec::new();
    let mut used_tokens = 0;
    let mut truncated = false;
    let mut seen_files: std::collections::HashSet<String> = std::collections::HashSet::new();

    for chunk in chunks {
        if used_tokens + chunk.token_estimate <= budget_tokens {
            seen_files.insert(chunk.path.clone());
            used_tokens += chunk.token_estimate;
            selected.push(chunk.clone());
        } else {
            truncated = true;
            break;
        }
    }

    SelectiveContext {
        chunks: selected,
        total_tokens: used_tokens,
        total_files: seen_files.len(),
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_tokens() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcdefgh"), 2);
    }

    #[test]
    fn test_chunk_source_basic() {
        let content = "line1\nline2\nline3\nline4\nline5";
        let chunks = chunk_source("test.c", content, 2, 0);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].start_line, 1);
        assert_eq!(chunks[0].end_line, 2);
        assert_eq!(chunks[1].start_line, 3);
        assert_eq!(chunks[1].end_line, 4);
        assert_eq!(chunks[2].start_line, 5);
        assert_eq!(chunks[2].end_line, 5);
    }

    #[test]
    fn test_chunk_source_with_overlap() {
        let content = "line1\nline2\nline3\nline4\nline5";
        let chunks = chunk_source("test.c", content, 3, 1);
        assert!(chunks.len() >= 2);
        assert_eq!(chunks[0].start_line, 1);
        assert_eq!(chunks[0].end_line, 3);
    }

    #[test]
    fn test_chunk_source_empty() {
        let chunks = chunk_source("test.c", "", 10, 0);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_score_relevance_keywords() {
        let mut chunk = CodeChunk {
            path: "test.c".into(),
            start_line: 1,
            end_line: 5,
            content: "void strcpy(char *dst, char *src) { unsafe { } }".into(),
            relevance_score: 0.0,
            token_estimate: 20,
            risk_rank: 0,
        };
        let keywords = vec!["unsafe".to_string(), "strcpy".to_string()];
        score_relevance(&mut chunk, &keywords);
        assert!(chunk.relevance_score > 0.0);
    }

    #[test]
    fn test_score_relevance_empty_keywords() {
        let mut chunk = CodeChunk {
            path: "test.c".into(),
            start_line: 1,
            end_line: 1,
            content: "hello world".into(),
            relevance_score: 0.0,
            token_estimate: 5,
            risk_rank: 0,
        };
        score_relevance(&mut chunk, &[]);
        assert_eq!(chunk.relevance_score, 0.5);
    }

    #[test]
    fn test_rank_risk_high() {
        let mut chunk = CodeChunk {
            path: "test.c".into(),
            start_line: 1,
            end_line: 1,
            content: "unsafe { transmute(ptr) }".into(),
            relevance_score: 0.0,
            token_estimate: 5,
            risk_rank: 0,
        };
        rank_risk(&mut chunk);
        assert_eq!(chunk.risk_rank, 3);
    }

    #[test]
    fn test_rank_risk_medium() {
        let mut chunk = CodeChunk {
            path: "test.c".into(),
            start_line: 1,
            end_line: 1,
            content: "let p = malloc(100);".into(),
            relevance_score: 0.0,
            token_estimate: 5,
            risk_rank: 0,
        };
        rank_risk(&mut chunk);
        assert_eq!(chunk.risk_rank, 2);
    }

    #[test]
    fn test_rank_risk_low() {
        let mut chunk = CodeChunk {
            path: "test.c".into(),
            start_line: 1,
            end_line: 1,
            content: "// todo! fix this later".into(),
            relevance_score: 0.0,
            token_estimate: 5,
            risk_rank: 0,
        };
        rank_risk(&mut chunk);
        assert_eq!(chunk.risk_rank, 1);
    }

    #[test]
    fn test_rank_risk_none() {
        let mut chunk = CodeChunk {
            path: "test.c".into(),
            start_line: 1,
            end_line: 1,
            content: "println!(\"hello\");".into(),
            relevance_score: 0.0,
            token_estimate: 5,
            risk_rank: 0,
        };
        rank_risk(&mut chunk);
        assert_eq!(chunk.risk_rank, 0);
    }

    #[test]
    fn test_build_selective_context_fits_budget() {
        let mut chunks: Vec<CodeChunk> = (0..10)
            .map(|i| CodeChunk {
                path: format!("file_{}.c", i),
                start_line: 1,
                end_line: 10,
                content: format!("unsafe {{ ptr_{} }}", i),
                relevance_score: 0.0,
                token_estimate: 100,
                risk_rank: 0,
            })
            .collect();
        let keywords = vec!["unsafe".to_string()];
        let ctx = build_selective_context(&mut chunks, &keywords, 500);
        assert!(ctx.total_tokens <= 500);
        assert!(ctx.total_files > 0);
    }

    #[test]
    fn test_build_selective_context_truncates() {
        let mut chunks: Vec<CodeChunk> = (0..20)
            .map(|i| CodeChunk {
                path: format!("file_{}.c", i),
                start_line: 1,
                end_line: 10,
                content: "code".repeat(100),
                relevance_score: 0.0,
                token_estimate: 500,
                risk_rank: 0,
            })
            .collect();
        let keywords = vec![];
        let ctx = build_selective_context(&mut chunks, &keywords, 1000);
        assert!(ctx.truncated);
        assert!(ctx.total_tokens <= 1000);
    }

    #[test]
    fn test_context_cache_operations() {
        let mut cache = ContextCache::new();
        assert!(cache.is_empty());

        let ctx = SelectiveContext {
            chunks: vec![],
            total_tokens: 0,
            total_files: 0,
            truncated: false,
        };
        cache.insert("key1".to_string(), ctx);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains("key1"));
        assert!(cache.get("key1").is_some());
        assert!(cache.get("key2").is_none());

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_CONTEXT_TOKENS, 1_000_000);
        assert_eq!(RESERVED_TOKENS, 8_192);
        assert_eq!(AVAILABLE_CONTEXT_TOKENS, MAX_CONTEXT_TOKENS - RESERVED_TOKENS);
    }
}
