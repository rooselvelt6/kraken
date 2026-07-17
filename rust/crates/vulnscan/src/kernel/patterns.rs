use crate::{DiscoveryMethod, Finding, Severity};
use std::path::Path;
use tree_sitter::{Language, Node, Parser, Tree};

pub struct KernelPatternAnalyzer;

impl KernelPatternAnalyzer {
    pub fn analyze(content: &str, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if let Some(tree) = Self::parse(content) {
            let root = tree.root_node();
            findings.extend(Self::check_copy_from_user_ast(content, root, file_path));
            findings.extend(Self::check_copy_to_user_ast(content, root, file_path));
            findings.extend(Self::check_kmalloc_null_ast(content, root, file_path));
            findings.extend(Self::check_ioctl_handler_ast(content, root, file_path));
            findings.extend(Self::check_procfs_locks_ast(content, root, file_path));
            findings.extend(Self::check_double_fetch_ast(content, root, file_path));
            findings.extend(Self::check_stack_buf_ast(content, root, file_path));
            findings.extend(Self::check_use_after_free_ast(content, root, file_path));
            findings.extend(Self::check_double_free_ast(content, root, file_path));
            findings.extend(Self::check_integer_wraparound_ast(content, root, file_path));
            findings.extend(Self::check_type_confusion_ast(content, root, file_path));
        }
        findings
    }

    fn parse(content: &str) -> Option<Tree> {
        let mut parser = Parser::new();
        let lang: Language = tree_sitter_c::LANGUAGE.into();
        parser.set_language(&lang).ok()?;
        let tree = parser.parse(content, None)?;
        if tree.root_node().has_error() {
            return None;
        }
        Some(tree)
    }

    fn node_text<'a>(content: &'a str, node: &Node) -> &'a str {
        &content[node.start_byte()..node.end_byte()]
    }

    fn node_line(content: &str, node: &Node) -> usize {
        content[..node.start_byte()].lines().count()
    }

    fn is_kernel_path(file_path: &Path) -> bool {
        let s = file_path.to_string_lossy();
        s.contains("/kernel/")
            || s.contains("/drivers/")
            || s.contains("/arch/")
            || s.contains("/fs/")
            || s.contains("/net/")
            || s.contains("/sound/")
            || s.contains("/block/")
            || s.contains("/crypto/")
            || s.contains("/security/")
            || s.contains("/mm/")
            || s.contains("/include/linux/")
    }

    #[allow(dead_code)]
    fn collect_nodes<'a>(node: Node<'a>, kind: &str, buf: &mut Vec<Node<'a>>) {
        if node.kind() == kind {
            buf.push(node);
        }
        for child in node.children(&mut node.walk()) {
            Self::collect_nodes(child, kind, buf);
        }
    }

    fn resolve_call_name(content: &str, call_node: Node) -> Option<String> {
        let func = call_node.child_by_field_name("function")?;
        match func.kind() {
            "identifier" => Some(Self::node_text(content, &func).to_string()),
            "field_expression" => {
                let field = func.child_by_field_name("field")?;
                Some(Self::node_text(content, &field).to_string())
            }
            _ => Some(Self::node_text(content, &func).to_string()),
        }
    }

    fn get_call_args<'a>(_content: &'a str, call_node: Node<'a>) -> Vec<Node<'a>> {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            args.children(&mut args.walk())
                .filter(|c| c.kind() != "," && c.kind() != "(" && c.kind() != ")")
                .collect()
        } else {
            vec![]
        }
    }

    fn collect_assignments_with_calls<'a>(
        content: &'a str,
        node: Node<'a>,
        target_names: &[&str],
        buf: &mut Vec<(Node<'a>, String, Node<'a>)>,
    ) {
        if node.kind() == "expression_statement" {
            if let Some(expr) = node.child(0) {
                if expr.kind() == "assignment_expression" {
                    if let Some(rhs) = expr.child_by_field_name("right") {
                        if rhs.kind() == "call_expression" {
                            if let Some(name) = Self::resolve_call_name(content, rhs) {
                                if target_names.iter().any(|t| *t == name) {
                                    if let Some(lhs) = expr.child_by_field_name("left") {
                                        buf.push((node, Self::node_text(content, &lhs).to_string(), rhs));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for child in node.children(&mut node.walk()) {
            Self::collect_assignments_with_calls(content, child, target_names, buf);
        }
    }

    #[allow(dead_code)]
    fn collect_calls_in_block<'a>(
        content: &'a str,
        block: Node<'a>,
        _target: &str,
        buf: &mut Vec<(Node<'a>, String)>,
    ) {
        for child in block.named_children(&mut block.walk()) {
            Self::collect_all_calls(content, child, buf);
            if child.kind() == "compound_statement" {
                Self::collect_calls_in_block(content, child, _target, buf);
            }
        }
    }

    fn get_parent_function<'a>(node: Node<'a>) -> Option<Node<'a>> {
        let mut cur = Some(node);
        while let Some(n) = cur {
            if n.kind() == "function_definition" {
                return Some(n);
            }
            cur = n.parent();
        }
        None
    }

    fn get_function_body<'a>(func: Node<'a>) -> Option<Node<'a>> {
        func.child_by_field_name("body")
    }

    fn sibling_after<'a>(node: Node<'a>) -> Option<Node<'a>> {
        let parent = node.parent()?;
        let mut found = false;
        for child in parent.named_children(&mut parent.walk()) {
            if found {
                return Some(child);
            }
            if child == node {
                found = true;
            }
        }
        None
    }

    #[allow(dead_code, clippy::too_many_arguments)]
    fn make_finding(
        description: impl Into<String>,
        cwe: &str,
        severity: Severity,
        line_num: usize,
        snippet: impl Into<String>,
        file_path: &Path,
        remediation: impl Into<String>,
        confidence: f32,
    ) -> Finding {
        Finding {
            id: crate::new_finding_id(),
            severity,
            cwe: Some(cwe.to_string()),
            cve: None,
            description: description.into(),
            file_path: Some(file_path.to_path_buf()),
            line_number: Some(line_num as u32),
            vulnerable_code_snippet: Some(snippet.into()),
            remediation: Some(remediation.into()),
            confidence,
            discovery_method: DiscoveryMethod::StaticPatternMatching,
            exploit_code: None,
            exploit_type: None,
            chained_findings: vec![],
            poc_validated: false,
            status: crate::FindingStatus::Open,
            cvss_score: Some(match severity {
                Severity::Critical => 9.0,
                Severity::High => 7.0,
                Severity::Medium => 5.0,
                Severity::Low => 3.0,
                Severity::Info => 1.0,
            }),
            severity_confidence: confidence,
            discovered_at: chrono::Utc::now(),
            disclosed: false,
            disclosure_hash: None,
        }
    }

    fn has_validation_nearby(content: &str, call_node: Node) -> bool {
        let start_line = Self::node_line(content, &call_node);
        if let Some(func) = Self::get_parent_function(call_node) {
            if let Some(body) = Self::get_function_body(func) {
                let body_text = Self::node_text(content, &body);
                let keywords = [
                    "sizeof", ">=", "<=", "min(", "max(", "access_ok", "VERIFY",
                ];
                let before_text: String = content
                    .lines()
                    .skip(start_line.saturating_sub(5))
                    .take(15)
                    .collect::<Vec<_>>()
                    .join("\n");
                for kw in &keywords {
                    if body_text.contains(kw) && before_text.contains(kw) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn block_has_check_for(block_text: &str, var_name: &str) -> bool {
        let check_patterns = [
            "if (!",
            "if (NULL",
            "if (err",
            "if (ret",
            "if (!ptr",
            "== NULL",
            "!= NULL",
            "IS_ERR",
            "PTR_ERR",
        ];
        for pat in &check_patterns {
            if block_text.contains(pat) && (var_name.is_empty() || block_text.contains(var_name)) {
                return true;
            }
        }
        false
    }

    #[allow(dead_code)]
    fn has_kfree_before(content: &str, node: Node, var_name: &str) -> bool {
        if let Some(func) = Self::get_parent_function(node) {
            if let Some(body) = Self::get_function_body(func) {
                let body_start = body.start_byte();
                let node_start = node.start_byte();
                if node_start > body_start {
                    let region = &content[body_start..node_start];
                    return region.contains(&format!("kfree({})", var_name));
                }
            }
        }
        false
    }

    fn has_usage_after(content: &str, node: Node, var_name: &str) -> bool {
        if let Some(func) = Self::get_parent_function(node) {
            if let Some(body) = Self::get_function_body(func) {
                let node_end = node.end_byte();
                let body_end = body.end_byte();
                if body_end > node_end {
                    let region = &content[node_end..body_end];
                    let patterns = [
                        format!("{}->", var_name),
                        format!("{}.field", var_name),
                        format!("{}.members", var_name),
                    ];
                    return patterns.iter().any(|p| region.contains(p.as_str()));
                }
            }
        }
        false
    }

    fn has_double_kfree(content: &str, node: Node, var_name: &str) -> bool {
        if let Some(func) = Self::get_parent_function(node) {
            if let Some(body) = Self::get_function_body(func) {
                let body_start = body.start_byte();
                let node_end = node.end_byte();
                if body_end(body) > node_end {
                    let region = &content[node_end..body_end(body)];
                    let target = format!("kfree({})", var_name);
                    if region.contains(&target) {
                        let region_text = &content[body_start..body_end(body)];
                        let first = region_text.find(&target);
                        let second = region_text[node_end - body_start..].find(&target);
                        if let (Some(f), Some(s)) = (first, second) {
                            if s > f {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn collect_all_calls<'a>(content: &'a str, node: Node<'a>, buf: &mut Vec<(Node<'a>, String)>) {
        if node.kind() == "call_expression" {
            if let Some(name) = Self::resolve_call_name(content, node) {
                buf.push((node, name));
            }
        }
        for child in node.children(&mut node.walk()) {
            Self::collect_all_calls(content, child, buf);
        }
    }

    fn collect_cast_expressions<'a>(
        content: &'a str,
        node: Node<'a>,
        buf: &mut Vec<(Node<'a>, String)>,
    ) {
        if node.kind() == "cast_expression" {
            if let Some(type_node) = node.child_by_field_name("type") {
                buf.push((node, Self::node_text(content, &type_node).to_string()));
            }
        }
        for child in node.children(&mut node.walk()) {
            Self::collect_cast_expressions(content, child, buf);
        }
    }

    fn collect_decl_init<'a>(
        content: &'a str,
        node: Node<'a>,
        buf: &mut Vec<(Node<'a>, String, usize)>,
    ) {
        if node.kind() == "declaration" {
            if let Some(decl) = node.child_by_field_name("declarator") {
                let name = Self::node_text(content, &decl).to_string();
                let line = Self::node_line(content, &node);
                buf.push((node, name, line));
            }
        }
        for child in node.children(&mut node.walk()) {
            Self::collect_decl_init(content, child, buf);
        }
    }

    #[allow(dead_code)]
    fn collect_string_literal(content: &str, node: Node) -> Option<String> {
        if node.kind() == "string_literal" {
            let text = Self::node_text(content, &node);
            Some(text.trim_matches('"').to_string())
        } else {
            None
        }
    }

    // ──────────────────────────────────────────────────
    // CHECKER 1: copy_from_user without size validation
    // ──────────────────────────────────────────────────
    fn check_copy_from_user_ast(content: &str, root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let targets = [
            "copy_from_user",
            "__copy_from_user",
            "raw_copy_from_user",
        ];
        let mut calls = Vec::new();
        Self::collect_all_calls(content, root, &mut calls);

        for (call, name) in &calls {
            if !targets.contains(&name.as_str()) {
                continue;
            }
            if Self::has_validation_nearby(content, *call) {
                continue;
            }
            let args = Self::get_call_args(content, *call);
            if args.len() >= 3 {
                let third_arg = Self::node_text(content, &args[2]);
                if third_arg.contains("sizeof")
                    || third_arg.contains(">= ")
                    || third_arg.contains("<= ")
                    || third_arg.contains("min(")
                    || third_arg.contains("max(")
                {
                    continue;
                }
            }
            let line = Self::node_line(content, call) + 1;
            let snippet = Self::node_text(content, call);
            findings.push(Self::make_finding(
                "copy_from_user without size validation — potential kernel heap overflow",
                "CWE-120",
                Severity::Critical,
                line,
                snippet,
                file_path,
                "Validate the size argument: add bounds check (size > max_bytes) before copy_from_user, or use min(size, max_bytes)",
                0.85,
            ));
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 2: copy_to_user may leak kernel memory
    // ──────────────────────────────────────────────────
    fn check_copy_to_user_ast(content: &str, root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let targets = ["copy_to_user", "__copy_to_user"];
        let mut calls = Vec::new();
        Self::collect_all_calls(content, root, &mut calls);

        for (call, name) in &calls {
            if !targets.contains(&name.as_str()) {
                continue;
            }
            let body_text = Self::node_text(content, &root);
            if body_text.contains("kzalloc")
                || body_text.contains("memset")
                || body_text.contains("memset_s")
                || body_text.contains("zero")
                || body_text.contains("INIT_LIST_HEAD")
            {
                continue;
            }
            let line = Self::node_line(content, call) + 1;
            let snippet = Self::node_text(content, call);
            findings.push(Self::make_finding(
                "copy_to_user may leak uninitialized kernel memory",
                "CWE-200",
                Severity::High,
                line,
                snippet,
                file_path,
                "Zero-fill the buffer (kzalloc) before copy_to_user, or ensure all struct padding is initialized",
                0.75,
            ));
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 3: kmalloc without NULL check
    // ──────────────────────────────────────────────────
    fn check_kmalloc_null_ast(content: &str, root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let alloc_funcs = ["kmalloc", "kzalloc", "kcalloc", "kvmalloc", "vmalloc"];
        let mut assignments = Vec::new();
        Self::collect_assignments_with_calls(content, root, &alloc_funcs, &mut assignments);

        for (stmt, var_name, call) in &assignments {
            let line = Self::node_line(content, stmt) + 1;
            let snippet = Self::node_text(content, stmt);
            if let Some(next) = Self::sibling_after(*stmt) {
                let next_text = Self::node_text(content, &next);
                if Self::block_has_check_for(next_text, "") {
                    continue;
                }
            }
            if snippet.contains("NULL") || snippet.contains("IS_ERR") {
                continue;
            }
            let func = Self::get_parent_function(*stmt);
            if let Some(f) = func {
                if let Some(body) = Self::get_function_body(f) {
                    let body_text = Self::node_text(content, &body);
                    if Self::block_has_check_for(body_text, var_name) {
                        continue;
                    }
                }
            }
            findings.push(Self::make_finding(
                format!("{}() result not checked for NULL before use", Self::resolve_call_name(content, *call).unwrap_or_default()),
                "CWE-476",
                Severity::High,
                line,
                snippet,
                file_path,
                format!("Check {}() return value for NULL: `if (!ptr) return -ENOMEM;`", alloc_funcs.iter().find(|f| snippet.contains(*f)).unwrap_or(&"alloc")),
                0.80,
            ));
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 4: ioctl handler missing
    // ──────────────────────────────────────────────────
    fn check_ioctl_handler_ast(content: &str, _root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path_str = file_path.to_string_lossy();
        if (path_str.contains("ioctl") || path_str.ends_with("_ioctl.c"))
            && !content.contains("unlocked_ioctl")
            && !content.contains("compat_ioctl")
        {
            findings.push(Self::make_finding(
                "No unlocked_ioctl handler found in ioctl-related file",
                "CWE-269",
                Severity::Medium,
                0,
                "",
                file_path,
                "Implement unlocked_ioctl or compat_ioctl in struct file_operations, with proper privilege checks",
                0.70,
            ));
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 5: procfs locking
    // ──────────────────────────────────────────────────
    fn check_procfs_locks_ast(content: &str, _root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path_str = file_path.to_string_lossy();
        if path_str.contains("/proc/") || path_str.contains("procfs") {
            let has_lock = content.contains("mutex_lock")
                || content.contains("spin_lock")
                || content.contains("rcu_read_lock")
                || content.contains("seqlock");
            if !has_lock {
                findings.push(Self::make_finding(
                    "procfs file — verify seq_file operations have proper locking",
                    "CWE-667",
                    Severity::Medium,
                    0,
                    "",
                    file_path,
                    "Add mutex or RCU locks around seq_operations show/next/stop callbacks",
                    0.70,
                ));
            }
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 6: double fetch (AST-based)
    // ──────────────────────────────────────────────────
    fn check_double_fetch_ast(content: &str, root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let fetch_funcs = ["copy_from_user", "get_user", "__copy_from_user"];
        let mut all_calls = Vec::new();
        Self::collect_all_calls(content, root, &mut all_calls);

        let mut func_groups: std::collections::HashMap<String, Vec<(Node, String)>> =
            std::collections::HashMap::new();
        for (call, name) in &all_calls {
            if !fetch_funcs.contains(&name.as_str()) {
                continue;
            }
            if let Some(func) = Self::get_parent_function(*call) {
                let func_name = Self::node_text(content, &func);
                func_groups
                    .entry(func_name.to_string())
                    .or_default()
                    .push((*call, name.clone()));
            }
        }

        for calls in func_groups.values() {
            if calls.len() < 2 {
                continue;
            }
            for i in 0..calls.len() {
                for j in (i + 1)..calls.len() {
                    let (call_a, name_a) = &calls[i];
                    let (call_b, name_b) = &calls[j];
                    let line_a = Self::node_line(content, call_a);
                    let line_b = Self::node_line(content, call_b);
                    if line_b > line_a && line_b - line_a <= 20 {
                        let args_a = Self::get_call_args(content, *call_a);
                        let args_b = Self::get_call_args(content, *call_b);
                        let same_var = if !args_a.is_empty() && !args_b.is_empty() {
                            Self::node_text(content, &args_a[0]) == Self::node_text(content, &args_b[0])
                        } else {
                            false
                        };
                        let region = &content
                            [content.lines().take(line_a).map(|l| l.len() + 1).sum::<usize>()
                                ..content.lines().take(line_b).map(|l| l.len() + 1).sum::<usize>()];
                        let has_access_ok = region.contains("access_ok")
                            || region.contains("copy_from_user")
                            || region.contains("might_fault");

                        if (same_var || name_a == name_b) && !has_access_ok {
                            findings.push(Self::make_finding(
                                "Potential double fetch — userspace value read twice without access_ok between fetches",
                                "CWE-367",
                                Severity::High,
                                line_a + 1,
                                Self::node_text(content, call_a),
                                file_path,
                                "Read userspace data once into kernel buffer, validate it, then use the kernel copy",
                                0.85,
                            ));
                        }
                    }
                }
            }
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 7: stack buffer overflow (real AST)
    // ──────────────────────────────────────────────────
    fn check_stack_buf_ast(content: &str, root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut declarations = Vec::new();
        Self::collect_decl_init(content, root, &mut declarations);

        for (_decl, name, _line) in &declarations {
            if name.contains('[') && name.contains(']') {
                let size_str = name
                    .split('[')
                    .nth(1)
                    .and_then(|s| s.split(']').next())
                    .unwrap_or("");
                let buf_size: Option<usize> = size_str.parse().ok();
                if let Some(size) = buf_size {
                    if size > 256 {
                        let mut calls = Vec::new();
                        Self::collect_all_calls(content, root, &mut calls);
                        for (call, call_name) in &calls {
                            if matches!(
                                call_name.as_str(),
                                "sprintf" | "strcpy" | "strcat" | "gets" | "memcpy"
                            ) {
                                let call_line = Self::node_line(content, call);
                                let var = name.split('[').next().unwrap_or("");
                                let call_text = Self::node_text(content, call);
                                if call_text.contains(var) {
                                    findings.push(Self::make_finding(
                                        format!(
                                            "Stack buffer overflow: `char {}` ({} bytes) used with unbounded {}()",
                                            var, size, call_name
                                        ),
                                        "CWE-121",
                                        Severity::High,
                                        call_line + 1,
                                        call_text,
                                        file_path,
                                        format!(
                                            "Use snprintf with size bound, or kmalloc for buffers > 256 bytes. Replace {}() with {}()",
                                            call_name, "snprintf"
                                        ),
                                        0.85,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 8: Use-After-Free
    // ──────────────────────────────────────────────────
    fn check_use_after_free_ast(content: &str, root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut all_calls = Vec::new();
        Self::collect_all_calls(content, root, &mut all_calls);

        for (call, name) in &all_calls {
            if name != "kfree" {
                continue;
            }
            let args = Self::get_call_args(content, *call);
            if args.is_empty() {
                continue;
            }
            let var_name = Self::node_text(content, &args[0]).trim();
            if var_name.is_empty() || var_name.contains('(') {
                continue;
            }
            if Self::has_usage_after(content, *call, var_name) {
                let line = Self::node_line(content, call) + 1;
                findings.push(Self::make_finding(
                    format!("Use-after-free: `{}` is freed then dereferenced", var_name),
                    "CWE-416",
                    Severity::Critical,
                    line,
                    Self::node_text(content, call),
                    file_path,
                    format!("Set `{}` to NULL after kfree, or ensure no pointers are used after free", var_name),
                    0.85,
                ));
            }
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 9: Double Free
    // ──────────────────────────────────────────────────
    fn check_double_free_ast(content: &str, root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut all_calls = Vec::new();
        Self::collect_all_calls(content, root, &mut all_calls);

        for (call, name) in &all_calls {
            if name != "kfree" {
                continue;
            }
            let args = Self::get_call_args(content, *call);
            if args.is_empty() {
                continue;
            }
            let var_name = Self::node_text(content, &args[0]).trim();
            if var_name.is_empty() || var_name.contains('(') {
                continue;
            }
            if Self::has_double_kfree(content, *call, var_name) {
                let line = Self::node_line(content, call) + 1;
                findings.push(Self::make_finding(
                    format!("Double free: `{}` is freed twice without NULL assignment", var_name),
                    "CWE-415",
                    Severity::Critical,
                    line,
                    Self::node_text(content, call),
                    file_path,
                    format!("Set `{}` to NULL after first kfree: `kfree({}); {} = NULL;`", var_name, var_name, var_name),
                    0.85,
                ));
            }
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 10: Integer wraparound in alloc size
    // ──────────────────────────────────────────────────
    fn check_integer_wraparound_ast(content: &str, root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let alloc_funcs = ["kmalloc", "kzalloc", "kcalloc", "kvmalloc"];
        let mut all_calls = Vec::new();
        Self::collect_all_calls(content, root, &mut all_calls);

        for (call, name) in &all_calls {
            if !alloc_funcs.contains(&name.as_str()) {
                continue;
            }
            let args = Self::get_call_args(content, *call);
            if args.is_empty() {
                continue;
            }
            let size_expr = Self::node_text(content, &args[0]);
            let dangerous_patterns = [
                "count * ",
                "count *(",
                "size * ",
                "size *(",
                "n * ",
                "n *(",
                "num * ",
                "num *(",
                "len * ",
                "len *(",
                "nr * ",
                "nr *(",
            ];
            let has_danger = dangerous_patterns.iter().any(|p| size_expr.contains(p));
            if !has_danger {
                let mul_ops = count_char_in_expr(content, size_expr, '*');
                if mul_ops > 0 && !size_expr.contains("size_mul")
                    && !size_expr.contains("array_size")
                    && !size_expr.contains("struct_size")
                    && !size_expr.contains("check_mul")
                {
                    let line = Self::node_line(content, call) + 1;
                    findings.push(Self::make_finding(
                        format!(
                            "Integer overflow in allocation size: `{}` may wrap around",
                            size_expr
                        ),
                        "CWE-190",
                        Severity::Critical,
                        line,
                        Self::node_text(content, call),
                        file_path,
                        "Use size_mul(), array_size(), or check_mul() for safe multiplication. Validate that count * size does not overflow SIZE_MAX",
                        0.75,
                    ));
                }
            } else if !size_expr.contains("size_mul")
                && !size_expr.contains("array_size")
                && !size_expr.contains("struct_size")
                && !size_expr.contains("check_mul")
            {
                let line = Self::node_line(content, call) + 1;
                findings.push(Self::make_finding(
                    format!(
                        "Integer overflow in allocation size: `{}` may wrap around",
                        size_expr
                    ),
                    "CWE-190",
                    Severity::Critical,
                    line,
                    Self::node_text(content, call),
                    file_path,
                    "Use size_mul(), array_size(), or check_mul() for safe multiplication. Validate that count * size does not overflow SIZE_MAX",
                    0.80,
                ));
            }
        }
        findings
    }

    // ──────────────────────────────────────────────────
    // CHECKER 11: Type confusion via unsafe cast
    // ──────────────────────────────────────────────────
    fn check_type_confusion_ast(content: &str, root: Node, file_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        if !Self::is_kernel_path(file_path) {
            return findings;
        }
        let mut casts = Vec::new();
        Self::collect_cast_expressions(content, root, &mut casts);

        for (cast, type_text) in &casts {
            let suspicious = [
                "(unsigned long)",
                "(void *)",
                "(char *)",
                "(int *)",
                "(u32 *)",
                "(u64 *)",
                "(size_t)",
                "(loff_t)",
                "(pgoff_t)",
            ];
            let parent_text = Self::node_text(content, cast);
            let is_ioctl_pattern = parent_text.contains("ioctl")
                || parent_text.contains("_IOC")
                || parent_text.contains("copy_from_user");
            if suspicious.iter().any(|s| type_text.contains(s)) && is_ioctl_pattern {
                let line = Self::node_line(content, cast) + 1;
                findings.push(Self::make_finding(
                    format!(
                        "Type confusion: suspicious cast `{}` in ioctl/copy context",
                        type_text
                    ),
                    "CWE-704",
                    Severity::High,
                    line,
                    Self::node_text(content, cast),
                    file_path,
                    "Verify the cast type matches the actual struct layout. Use _IOC_SIZE() to extract the correct size before casting",
                    0.65,
                ));
            }
        }
        findings
    }
}

fn body_end(node: tree_sitter::Node) -> usize {
    node.end_byte()
}

fn count_char_in_expr(_content: &str, expr: &str, ch: char) -> usize {
    expr.chars().filter(|c| *c == ch).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(path: &str) -> PathBuf {
        PathBuf::from(path)
    }

    #[test]
    fn test_copy_from_user_no_size_check_ast() {
        let content = r#"
void handler(void) {
    copy_from_user(buf, arg, size);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(
            findings.iter().any(|f| f.description.contains("copy_from_user")),
            "Should detect unvalidated copy_from_user"
        );
    }

    #[test]
    fn test_copy_from_user_with_sizeof_suppressed() {
        let content = r#"
void handler(void) {
    copy_from_user(buf, arg, sizeof(struct foo));
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe120: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.cwe.as_deref() == Some("CWE-120"))
            .collect();
        assert!(cwe120.is_empty(), "sizeof should suppress the finding");
    }

    #[test]
    fn test_kmalloc_no_null_check_ast() {
        let content = r#"
void handler(void) {
    ptr = kmalloc(size, GFP_KERNEL);
    ptr->field = 1;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(
            findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-476")),
            "Should detect unchecked kmalloc"
        );
    }

    #[test]
    fn test_kmalloc_with_null_check_suppressed() {
        let content = r#"
void handler(void) {
    ptr = kmalloc(size, GFP_KERNEL);
    if (!ptr) return -ENOMEM;
    ptr->field = 1;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let null_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.cwe.as_deref() == Some("CWE-476"))
            .collect();
        assert!(null_findings.is_empty(), "NULL check should suppress finding");
    }

    #[test]
    fn test_double_fetch_detected_ast() {
        let content = r#"
void handler(void) {
    get_user(val, &arg);
    int x = val + 1;
    get_user(val, &arg);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(
            findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-367")),
            "Should detect double fetch"
        );
    }

    #[test]
    fn test_use_after_free_detected() {
        let content = r#"
void handler(void) {
    kfree(ptr);
    ptr->field = 1;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(
            findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-416")),
            "Should detect use-after-free"
        );
    }

    #[test]
    fn test_double_free_detected() {
        let content = r#"
void handler(void) {
    kfree(ptr);
    do_something();
    kfree(ptr);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(
            findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-415")),
            "Should detect double free"
        );
    }

    #[test]
    fn test_integer_wraparound_in_kmalloc() {
        let content = r#"
void handler(void) {
    ptr = kmalloc(count * size, GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(
            findings
                .iter()
                .any(|f| f.cwe.as_deref() == Some("CWE-190")),
            "Should detect integer overflow in alloc size"
        );
    }

    #[test]
    fn test_integer_wraparound_safe_suppressed() {
        let content = r#"
void handler(void) {
    ptr = kmalloc(size_mul(count, size), GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe190: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.cwe.as_deref() == Some("CWE-190"))
            .collect();
        assert!(
            cwe190.is_empty(),
            "size_mul should suppress integer overflow finding"
        );
    }

    #[test]
    fn test_stack_buffer_overflow_real() {
        let content = r#"
void handler(void) {
    char big_buf[1024];
    sprintf(big_buf, "%s", user_input);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(
            findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-121")),
            "Should detect stack buffer overflow"
        );
    }

    #[test]
    fn test_stack_buffer_small_suppressed() {
        let content = r#"
void handler(void) {
    char small_buf[32];
    sprintf(small_buf, "%s", user_input);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe121: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.cwe.as_deref() == Some("CWE-121"))
            .collect();
        assert!(cwe121.is_empty(), "Small buffers should not trigger");
    }

    #[test]
    fn test_parse_valid_c() {
        assert!(KernelPatternAnalyzer::parse("int foo(void) { return 0; }").is_some());
    }

    #[test]
    fn test_parse_empty() {
        assert!(KernelPatternAnalyzer::parse("").is_some());
    }

    #[test]
    fn test_parse_invalid_c() {
        assert!(KernelPatternAnalyzer::parse("struct {{{{{").is_none());
    }

    #[test]
    fn test_ioctl_handler_missing() {
        let content = "/* nothing here */\n";
        let findings =
            KernelPatternAnalyzer::check_ioctl_handler_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/kernel/drivers/ioctl_test.c"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_ioctl_handler_present() {
        let content = "const struct file_operations fops = { .unlocked_ioctl = my_ioctl };\n";
        let findings =
            KernelPatternAnalyzer::check_ioctl_handler_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/kernel/drivers/ioctl_test.c"));
        assert!(findings.is_empty());
    }
}
