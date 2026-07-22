use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Represents a function or method in the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionNode {
    pub name: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub is_pub: bool,
    pub risk_score: f64,
}

/// An edge in the call graph (caller → callee).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
    pub path: String,
    pub line: usize,
}

/// The full call graph for a codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub functions: HashMap<String, FunctionNode>,
    pub edges: Vec<CallEdge>,
    pub adjacency: HashMap<String, Vec<String>>,
}

/// A code slice: all code needed to understand a specific function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSlice {
    pub target_function: String,
    pub functions_included: Vec<String>,
    pub total_lines: usize,
    pub total_tokens: usize,
    pub risk_rank: u8,
    pub depth: usize,
}

/// Extracted source code for a slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceSource {
    pub slice: CodeSlice,
    pub sources: Vec<SliceFile>,
}

/// A single source file segment in a slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceFile {
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            edges: Vec::new(),
            adjacency: HashMap::new(),
        }
    }

    pub fn add_function(&mut self, node: FunctionNode) {
        self.adjacency
            .entry(node.name.clone())
            .or_default();
        self.functions.insert(node.name.clone(), node);
    }

    pub fn add_edge(&mut self, edge: CallEdge) {
        self.adjacency
            .entry(edge.caller.clone())
            .or_default()
            .push(edge.callee.clone());
        self.edges.push(edge);
    }

    pub fn callees_of(&self, name: &str) -> Vec<&str> {
        self.adjacency
            .get(name)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    pub fn callers_of(&self, name: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|e| e.callee == name)
            .map(|e| e.caller.as_str())
            .collect()
    }

    /// BFS from a target function to find all transitive callees.
    pub fn transitive_callees(&self, target: &str, max_depth: usize) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((target.to_string(), 0));
        visited.insert(target.to_string());

        let mut result = Vec::new();

        while let Some((current, depth)) = queue.pop_front() {
            if depth > 0 {
                result.push(current.clone());
            }
            if depth >= max_depth {
                continue;
            }
            for callee in self.callees_of(&current) {
                if visited.insert(callee.to_string()) {
                    queue.push_back((callee.to_string(), depth + 1));
                }
            }
        }

        result
    }

    /// BFS from a target function to find all transitive callers.
    pub fn transitive_callers(&self, target: &str, max_depth: usize) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((target.to_string(), 0));
        visited.insert(target.to_string());

        let mut result = Vec::new();

        while let Some((current, depth)) = queue.pop_front() {
            if depth > 0 {
                result.push(current.clone());
            }
            if depth >= max_depth {
                continue;
            }
            for caller in self.callers_of(&current) {
                if visited.insert(caller.to_string()) {
                    queue.push_back((caller.to_string(), depth + 1));
                }
            }
        }

        result
    }

    /// Number of functions in the graph.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

/// Extracts a code slice for a target function.
pub fn extract_slice(
    graph: &CallGraph,
    target: &str,
    max_depth: usize,
) -> Option<CodeSlice> {
    if !graph.functions.contains_key(target) {
        return None;
    }

    let callees = graph.transitive_callees(target, max_depth);
    let mut included: Vec<String> = callees;
    included.push(target.to_string());
    included.sort();
    included.dedup();

    let total_lines: usize = included
        .iter()
        .filter_map(|name| graph.functions.get(name))
        .map(|f| f.end_line - f.start_line + 1)
        .sum();

    let risk_score: f64 = included
        .iter()
        .filter_map(|name| graph.functions.get(name))
        .map(|f| f.risk_score)
        .sum::<f64>()
        / (included.len() as f64 + 1.0);

    let risk_rank = if risk_score > 0.7 {
        4
    } else if risk_score > 0.5 {
        3
    } else if risk_score > 0.3 {
        2
    } else if risk_score > 0.1 {
        1
    } else {
        0
    };

    Some(CodeSlice {
        target_function: target.to_string(),
        functions_included: included,
        total_lines,
        total_tokens: (total_lines * 4), // rough estimate
        risk_rank,
        depth: max_depth,
    })
}

/// Orders slices by risk for prioritized analysis.
pub fn risk_rank_slices(slices: &mut [CodeSlice]) {
    slices.sort_by(|a, b| {
        b.risk_rank
            .cmp(&a.risk_rank)
            .then_with(|| b.total_lines.cmp(&a.total_lines))
    });
}

/// Parses a C-like source file and extracts function definitions using regex heuristics.
/// This is a lightweight alternative to full tree-sitter parsing for simple cases.
pub fn parse_functions_from_source(path: &str, content: &str) -> (Vec<FunctionNode>, Vec<CallEdge>) {
    let mut functions = Vec::new();
    let mut edges = Vec::new();

    let mut current_func: Option<String> = None;
    let mut brace_depth: i32 = 0;
    let mut start_line: usize = 0;
    let mut is_pub = false;

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Detect function definitions: type name(args) { or pub fn name(args) {
        if brace_depth == 0 {
            let is_c_func = !trimmed.starts_with("//")
                && !trimmed.starts_with("#")
                && !trimmed.starts_with("/*")
                && (trimmed.contains("(") && trimmed.contains(")"))
                && (trimmed.ends_with('{') || trimmed.ends_with(';') && trimmed.contains('{'));

            let is_rust_func = trimmed.starts_with("pub fn ")
                || trimmed.starts_with("fn ")
                || trimmed.starts_with("pub(crate) fn ");

            if is_rust_func || is_c_func {
                let name = if is_rust_func {
                    extract_rust_func_name(trimmed)
                } else {
                    extract_c_func_name(trimmed)
                };

                if let Some(name) = name {
                    is_pub = trimmed.starts_with("pub");
                    start_line = idx + 1;
                    current_func = Some(name);
                    brace_depth = 0;
                }
            }
        }

        if current_func.is_some() {
            brace_depth += line.matches('{').count() as i32;
            brace_depth -= line.matches('}').count() as i32;

            if brace_depth <= 0 {
                if let Some(name) = current_func.take() {
                    functions.push(FunctionNode {
                        name,
                        path: path.to_string(),
                        start_line,
                        end_line: idx + 1,
                        is_pub,
                        risk_score: 0.0,
                    });
                }
                brace_depth = 0;
            }
        }

        // Extract call edges within a function body
        if current_func.is_some() && brace_depth > 0 {
            if let Some(callee) = extract_function_call(trimmed) {
                if let Some(ref caller) = current_func {
                    if *caller != callee {
                        edges.push(CallEdge {
                            caller: caller.clone(),
                            callee,
                            path: path.to_string(),
                            line: idx + 1,
                        });
                    }
                }
            }
        }
    }

    (functions, edges)
}

fn extract_rust_func_name(line: &str) -> Option<String> {
    let line = line.trim_start_matches("pub(crate)");
    let line = line.trim_start_matches("pub");
    let line = line.trim_start_matches("unsafe");
    let line = line.trim();
    let line = line.strip_prefix("fn ")?;
    let name = line.split('(').next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn extract_c_func_name(line: &str) -> Option<String> {
    let line = line.trim();
    let line = {
        let pos = line.rfind('(')?;
        &line[..pos]
    };
    let name = line.split_whitespace().last()?;
    let name = name.trim_start_matches('*');
    if name.is_empty() || name.chars().next().is_some_and(|c| c.is_numeric()) {
        None
    } else {
        Some(name.to_string())
    }
}

fn extract_function_call(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("//") || trimmed.starts_with("*") || trimmed.starts_with("#") {
        return None;
    }

    if let Some(pos) = trimmed.find('(') {
        let before = &trimmed[..pos];
        let name = before.split_whitespace().last()?;
        let name = name.rsplit('.').next().unwrap_or(name);
        if !name.is_empty()
            && name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == ':')
            && !["if", "while", "for", "match", "return", "unsafe", "else", "loop"]
                .contains(&name)
        {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_graph_new() {
        let graph = CallGraph::new();
        assert!(graph.is_empty());
        assert_eq!(graph.len(), 0);
    }

    #[test]
    fn test_call_graph_add_function() {
        let mut graph = CallGraph::new();
        graph.add_function(FunctionNode {
            name: "main".into(),
            path: "test.rs".into(),
            start_line: 1,
            end_line: 10,
            is_pub: true,
            risk_score: 0.5,
        });
        assert_eq!(graph.len(), 1);
        assert!(!graph.is_empty());
    }

    #[test]
    fn test_call_graph_edges() {
        let mut graph = CallGraph::new();
        graph.add_function(FunctionNode {
            name: "a".into(),
            path: "test.rs".into(),
            start_line: 1,
            end_line: 5,
            is_pub: true,
            risk_score: 0.0,
        });
        graph.add_function(FunctionNode {
            name: "b".into(),
            path: "test.rs".into(),
            start_line: 6,
            end_line: 10,
            is_pub: true,
            risk_score: 0.0,
        });
        graph.add_edge(CallEdge {
            caller: "a".into(),
            callee: "b".into(),
            path: "test.rs".into(),
            line: 3,
        });

        assert_eq!(graph.callees_of("a"), vec!["b"]);
        assert_eq!(graph.callers_of("b"), vec!["a"]);
        assert!(graph.callees_of("b").is_empty());
        assert!(graph.callers_of("a").is_empty());
    }

    #[test]
    fn test_transitive_callees() {
        let mut graph = CallGraph::new();
        for name in &["a", "b", "c", "d"] {
            graph.add_function(FunctionNode {
                name: name.to_string(),
                path: "test.rs".into(),
                start_line: 1,
                end_line: 5,
                is_pub: true,
                risk_score: 0.0,
            });
        }
        graph.add_edge(CallEdge {
            caller: "a".into(),
            callee: "b".into(),
            path: "test.rs".into(),
            line: 1,
        });
        graph.add_edge(CallEdge {
            caller: "b".into(),
            callee: "c".into(),
            path: "test.rs".into(),
            line: 2,
        });
        graph.add_edge(CallEdge {
            caller: "c".into(),
            callee: "d".into(),
            path: "test.rs".into(),
            line: 3,
        });

        let callees = graph.transitive_callees("a", 10);
        assert!(callees.contains(&"b".to_string()));
        assert!(callees.contains(&"c".to_string()));
        assert!(callees.contains(&"d".to_string()));
    }

    #[test]
    fn test_transitive_callees_max_depth() {
        let mut graph = CallGraph::new();
        for name in &["a", "b", "c"] {
            graph.add_function(FunctionNode {
                name: name.to_string(),
                path: "test.rs".into(),
                start_line: 1,
                end_line: 5,
                is_pub: true,
                risk_score: 0.0,
            });
        }
        graph.add_edge(CallEdge {
            caller: "a".into(),
            callee: "b".into(),
            path: "test.rs".into(),
            line: 1,
        });
        graph.add_edge(CallEdge {
            caller: "b".into(),
            callee: "c".into(),
            path: "test.rs".into(),
            line: 2,
        });

        let callees = graph.transitive_callees("a", 1);
        assert!(callees.contains(&"b".to_string()));
        assert!(!callees.contains(&"c".to_string()));
    }

    #[test]
    fn test_transitive_callers() {
        let mut graph = CallGraph::new();
        for name in &["a", "b", "c"] {
            graph.add_function(FunctionNode {
                name: name.to_string(),
                path: "test.rs".into(),
                start_line: 1,
                end_line: 5,
                is_pub: true,
                risk_score: 0.0,
            });
        }
        graph.add_edge(CallEdge {
            caller: "a".into(),
            callee: "b".into(),
            path: "test.rs".into(),
            line: 1,
        });
        graph.add_edge(CallEdge {
            caller: "b".into(),
            callee: "c".into(),
            path: "test.rs".into(),
            line: 2,
        });

        let callers = graph.transitive_callers("c", 10);
        assert!(callers.contains(&"a".to_string()));
        assert!(callers.contains(&"b".to_string()));
    }

    #[test]
    fn test_extract_slice() {
        let mut graph = CallGraph::new();
        for name in &["main", "helper", "util"] {
            graph.add_function(FunctionNode {
                name: name.to_string(),
                path: "test.rs".into(),
                start_line: 1,
                end_line: 10,
                is_pub: true,
                risk_score: 0.3,
            });
        }
        graph.add_edge(CallEdge {
            caller: "main".into(),
            callee: "helper".into(),
            path: "test.rs".into(),
            line: 5,
        });
        graph.add_edge(CallEdge {
            caller: "helper".into(),
            callee: "util".into(),
            path: "test.rs".into(),
            line: 8,
        });

        let slice = extract_slice(&graph, "main", 10).unwrap();
        assert_eq!(slice.target_function, "main");
        assert!(slice.functions_included.contains(&"main".to_string()));
        assert!(slice.functions_included.contains(&"helper".to_string()));
        assert!(slice.functions_included.contains(&"util".to_string()));
        assert!(slice.total_lines > 0);
    }

    #[test]
    fn test_extract_slice_not_found() {
        let graph = CallGraph::new();
        assert!(extract_slice(&graph, "nonexistent", 10).is_none());
    }

    #[test]
    fn test_risk_rank_slices() {
        let mut slices = vec![
            CodeSlice {
                target_function: "low".into(),
                functions_included: vec![],
                total_lines: 10,
                total_tokens: 40,
                risk_rank: 1,
                depth: 2,
            },
            CodeSlice {
                target_function: "high".into(),
                functions_included: vec![],
                total_lines: 100,
                total_tokens: 400,
                risk_rank: 4,
                depth: 2,
            },
            CodeSlice {
                target_function: "med".into(),
                functions_included: vec![],
                total_lines: 50,
                total_tokens: 200,
                risk_rank: 2,
                depth: 2,
            },
        ];
        risk_rank_slices(&mut slices);
        assert_eq!(slices[0].target_function, "high");
        assert_eq!(slices[1].target_function, "med");
        assert_eq!(slices[2].target_function, "low");
    }

    #[test]
    fn test_parse_rust_functions() {
        let source = r#"
pub fn public_func() {
    helper();
}

fn private_func() {
    util();
}
"#;
        let (funcs, edges) = parse_functions_from_source("test.rs", source);
        assert_eq!(funcs.len(), 2);
        assert!(funcs.iter().any(|f| f.name == "public_func" && f.is_pub));
        assert!(funcs.iter().any(|f| f.name == "private_func" && !f.is_pub));
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn test_parse_c_functions() {
        let source = r#"
int main(void) {
    helper();
    return 0;
}

void helper(void) {
    printf("hello");
}
"#;
        let (funcs, _edges) = parse_functions_from_source("test.c", source);
        assert!(funcs.len() >= 1);
        assert!(funcs.iter().any(|f| f.name == "main"));
    }

    #[test]
    fn test_extract_rust_func_name() {
        assert_eq!(extract_rust_func_name("pub fn foo()"), Some("foo".into()));
        assert_eq!(extract_rust_func_name("fn bar()"), Some("bar".into()));
        assert_eq!(
            extract_rust_func_name("pub(crate) fn baz()"),
            Some("baz".into())
        );
        assert_eq!(extract_rust_func_name("// comment"), None);
    }

    #[test]
    fn test_extract_c_func_name() {
        assert_eq!(extract_c_func_name("int main(void) {"), Some("main".into()));
        assert_eq!(
            extract_c_func_name("void helper(int x) {"),
            Some("helper".into())
        );
    }

    #[test]
    fn test_extract_function_call() {
        assert_eq!(extract_function_call("    foo(bar);"), Some("foo".into()));
        assert_eq!(
            extract_function_call("    obj.method(x);"),
            Some("method".into())
        );
        assert_eq!(extract_function_call("// comment"), None);
        assert_eq!(extract_function_call("if (x) {"), None);
        assert_eq!(extract_function_call("while (y) {"), None);
    }
}
