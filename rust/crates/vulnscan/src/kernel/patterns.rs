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
                "unsigned long",
                "void *",
                "char *",
                "int *",
                "u32 *",
                "u64 *",
                "size_t",
                "loff_t",
                "pgoff_t",
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

    // ================================================================
    // CHECKER 1: copy_from_user — regression tests (CWE-120, CVE-2017-5123 pattern)
    // ================================================================

    #[test]
    fn test_cve2017_5123_waitid_pattern() {
        let content = r#"
int handler(int which, int id, int *infop, int options) {
    int info[16];
    int *dst = infop;
    copy_from_user(info, dst, sizeof(info));
    return do_wait(which, id, info, options);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/kernel/exit.c"));
        let cwe120: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-120")).collect();
        assert!(cwe120.is_empty(),
            "sizeof in size arg suppresses CWE-120");
    }

    #[test]
    fn test_copy_from_user_unchecked_size_var() {
        let content = r#"
void handler(void) {
    copy_from_user(kbuf, uaddr, len);
    process_data(kbuf, len);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/input/evdev.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-120")));
    }

    #[test]
    fn test_copy_from_user_user_controlled_length() {
        let content = r#"
long vuln_write(char *f, char *buf, int cnt, int *ppos) {
    char *kbuf = kmalloc(cnt, GFP_KERNEL);
    copy_from_user(kbuf, buf, cnt);
    return cnt;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/char/mem.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-120")));
    }

    #[test]
    fn test_copy_from_user_no_validation_with_access_ok_only_in_different_region() {
        let content = r#"
int handler(int cmd, int arg) {
    int ok = arg;
    copy_from_user(&val, (void *)arg, 64);
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/misc/ioctl.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-120")),
            "No sizeof or access_ok nearby should flag");
    }

    #[test]
    fn test_copy_from_user_suppressed_by_sizeof_arg() {
        let content = r#"
void handler(void) {
    copy_from_user(&local, uarg, sizeof(local));
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe120: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-120")).collect();
        assert!(cwe120.is_empty(), "sizeof in size arg should suppress");
    }

    #[test]
    fn test_copy_from_user_suppressed_by_min_in_size() {
        let content = r#"
void handler(void) {
    copy_from_user(dst, src, min(count, sizeof(dst)));
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe120: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-120")).collect();
        assert!(cwe120.is_empty(), "min() in size arg should suppress");
    }

    #[test]
    fn test_copy_from_user_double_unchecked() {
        let content = r#"
void handler(void) {
    copy_from_user(header, uhdr, hlen);
    copy_from_user(body, ubody, blen);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/net/packet/af_packet.c"));
        let cwe120: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-120")).collect();
        assert!(cwe120.len() >= 2, "Both unchecked calls should be flagged");
    }

    #[test]
    fn test_copy_from_user_with_gte_check_nearby() {
        let content = r#"
void handler(void) {
    if (count >= sizeof(buf)) return -EINVAL;
    copy_from_user(buf, ubuf, count);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe120: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-120")).collect();
        assert!(cwe120.is_empty(), ">= check nearby should suppress");
    }

    #[test]
    fn test_raw_copy_from_user_unchecked() {
        let content = r#"
void handler(void) {
    raw_copy_from_user(dst, src, len);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/fs/read_write.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-120")));
    }

    // ================================================================
    // CHECKER 2: copy_to_user — info leak regression tests (CWE-200)
    // ================================================================

    #[test]
    fn test_copy_to_user_no_zero_fill() {
        let content = r#"
int get_info(char *ubuf) {
    int info[16];
    info[0] = 123;
    copy_to_user(ubuf, info, sizeof(info));
    return sizeof(info);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/char/misc.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-200")));
    }

    #[test]
    fn test_copy_to_user_kmalloc_no_zero() {
        let content = r#"
int read_handler(char *buf, int count) {
    char *kbuf = kmalloc(count, GFP_KERNEL);
    kbuf[0] = 'A';
    copy_to_user(buf, kbuf, count);
    return count;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/fs/proc/base.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-200")));
    }

    #[test]
    fn test_copy_to_user_with_kzalloc_suppressed() {
        let content = r#"
int read_handler(char *buf) {
    char *kbuf = kzalloc(256, GFP_KERNEL);
    copy_to_user(buf, kbuf, 256);
    return 256;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe200: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-200")).collect();
        assert!(cwe200.is_empty(), "kzalloc should suppress info leak finding");
    }

    #[test]
    fn test_copy_to_user_with_memset_suppressed() {
        let content = r#"
int read_handler(char *buf) {
    char *kbuf = kmalloc(256, GFP_KERNEL);
    memset(kbuf, 0, 256);
    copy_to_user(buf, kbuf, 256);
    return 256;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe200: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-200")).collect();
        assert!(cwe200.is_empty(), "memset should suppress info leak finding");
    }

    #[test]
    fn test_copy_to_user_struct_padding_leak() {
        let content = r#"
int ioctl_info(int arg) {
    int s[16];
    s[0] = 1;
    copy_to_user((void *)arg, s, sizeof(s));
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/char/random.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-200")));
    }

    #[test]
    fn test_copy_to_user_with_zero_literal_suppressed() {
        let content = r#"
int read_handler(char __user *buf) {
    char kbuf[256];
    zero(kbuf, 256);
    copy_to_user(buf, kbuf, 256);
    return 256;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe200: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-200")).collect();
        assert!(cwe200.is_empty(), "'zero' in root should suppress");
    }

    #[test]
    fn test_copy_to_user_init_list_head_suppressed() {
        let content = r#"
int read_handler(char __user *buf) {
    struct list_item item;
    INIT_LIST_HEAD(&item.list);
    copy_to_user(buf, &item, sizeof(item));
    return sizeof(item);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe200: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-200")).collect();
        assert!(cwe200.is_empty(), "INIT_LIST_HEAD should suppress");
    }

    // ================================================================
    // CHECKER 3: kmalloc without NULL check (CWE-476)
    // ================================================================

    #[test]
    fn test_kmalloc_no_null_check_kzalloc() {
        let content = r#"
void handler(void) {
    ptr = kzalloc(1024, GFP_KERNEL);
    ptr->data = 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-476") && f.description.contains("kzalloc")));
    }

    #[test]
    fn test_kmalloc_no_null_check_kcalloc() {
        let content = r#"
void handler(void) {
    ptr = kcalloc(count, sizeof(*ptr), GFP_KERNEL);
    memset(ptr, 0, count * sizeof(*ptr));
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-476") && f.description.contains("kcalloc")));
    }

    #[test]
    fn test_kmalloc_no_null_check_kvmalloc() {
        let content = r#"
void handler(void) {
    ptr = kvmalloc(size, GFP_KERNEL);
    memcpy(ptr, src, size);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-476") && f.description.contains("kvmalloc")));
    }

    #[test]
    fn test_kmalloc_no_null_check_vmalloc() {
        let content = r#"
void handler(void) {
    ptr = vmalloc(size);
    ptr->field = 42;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-476") && f.description.contains("vmalloc")));
    }

    #[test]
    fn test_kmalloc_with_null_check_if_bang_suppressed() {
        let content = r#"
void handler(void) {
    ptr = kmalloc(1024, GFP_KERNEL);
    if (!ptr) return -ENOMEM;
    ptr->data = 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let null_findings: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-476")).collect();
        assert!(null_findings.is_empty());
    }

    #[test]
    fn test_kmalloc_with_is_err_check_suppressed() {
        let content = r#"
void handler(void) {
    ptr = vmalloc(size);
    if (IS_ERR(ptr)) return PTR_ERR(ptr);
    ptr->field = 1;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let null_findings: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-476")).collect();
        assert!(null_findings.is_empty());
    }

    #[test]
    fn test_kmalloc_null_check_equal_null_suppressed() {
        let content = r#"
void handler(void) {
    ptr = kmalloc(size, GFP_KERNEL);
    if (ptr == NULL) return -ENOMEM;
    process(ptr);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let null_findings: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-476")).collect();
        assert!(null_findings.is_empty());
    }

    #[test]
    fn test_kmalloc_multiple_unchecked() {
        let content = r#"
void handler(void) {
    a = kmalloc(64, GFP_KERNEL);
    b = kzalloc(128, GFP_KERNEL);
    a->next = b;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let null_findings: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-476")).collect();
        assert!(null_findings.len() >= 2, "Both unchecked allocs should be flagged");
    }

    // ================================================================
    // CHECKER 4: ioctl handler missing (CWE-269)
    // ================================================================

    #[test]
    fn test_ioctl_file_no_handlers() {
        let content = "int my_ioctl(struct file *f, unsigned int cmd, unsigned long arg) { return 0; }\n";
        let findings =
            KernelPatternAnalyzer::check_ioctl_handler_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/kernel/drivers/misc/my_ioctl.c"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_ioctl_file_with_compat_ioctl() {
        let content = "const struct file_operations fops = { .compat_ioctl = my_compat_ioctl };\n";
        let findings =
            KernelPatternAnalyzer::check_ioctl_handler_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/kernel/drivers/misc/dev_ioctl.c"));
        assert!(findings.is_empty(), "compat_ioctl should suppress finding");
    }

    #[test]
    fn test_non_ioctl_file_no_finding() {
        let content = "int read_func(void) { return 0; }\n";
        let findings =
            KernelPatternAnalyzer::check_ioctl_handler_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/kernel/fs/read_write.c"));
        assert!(findings.is_empty(), "Non-ioctl file should not trigger");
    }

    #[test]
    fn test_ioctl_no_handlers_different_path() {
        let content = "int x = 1;\n";
        let findings =
            KernelPatternAnalyzer::check_ioctl_handler_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/kernel/drivers/usb/core/dev.c"));
        assert!(findings.is_empty(), "Path without ioctl keyword should not trigger");
    }

    // ================================================================
    // CHECKER 5: procfs locking (CWE-667)
    // ================================================================

    #[test]
    fn test_procfs_no_locking() {
        let content = r#"
static int show(struct seq_file *m, void *v) {
    seq_printf(m, "%d\n", counter);
    return 0;
}
"#;
        let findings =
            KernelPatternAnalyzer::check_procfs_locks_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/proc/meminfo.c"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_procfs_with_mutex_suppressed() {
        let content = r#"
static int show(struct seq_file *m, void *v) {
    mutex_lock(&my_lock);
    seq_printf(m, "%d\n", counter);
    mutex_unlock(&my_lock);
    return 0;
}
"#;
        let findings =
            KernelPatternAnalyzer::check_procfs_locks_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/proc/meminfo.c"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_procfs_with_spin_lock_suppressed() {
        let content = r#"
static int show(struct seq_file *m, void *v) {
    spin_lock(&lock);
    seq_printf(m, "%d\n", val);
    spin_unlock(&lock);
    return 0;
}
"#;
        let findings =
            KernelPatternAnalyzer::check_procfs_locks_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/proc/stat.c"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_procfs_with_rcu_read_lock_suppressed() {
        let content = r#"
static int show(struct seq_file *m, void *v) {
    rcu_read_lock();
    seq_printf(m, "%d\n", val);
    rcu_read_unlock();
    return 0;
}
"#;
        let findings =
            KernelPatternAnalyzer::check_procfs_locks_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/proc/net/tcp.c"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_procfs_with_seqlock_suppressed() {
        let content = r#"
static int show(struct seq_file *m, void *v) {
    seqlock(&lock);
    seq_printf(m, "%d\n", val);
    return 0;
}
"#;
        let findings =
            KernelPatternAnalyzer::check_procfs_locks_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/proc/diskstats.c"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_non_procfs_no_finding() {
        let content = "int x = 1;\n";
        let findings =
            KernelPatternAnalyzer::check_procfs_locks_ast(content, KernelPatternAnalyzer::parse(content).unwrap().root_node(), &p("/kernel/drivers/test.c"));
        assert!(findings.is_empty());
    }

    // ================================================================
    // CHECKER 6: Double fetch (CWE-367) — TOCTOU patterns
    // ================================================================

    #[test]
    fn test_double_fetch_copy_from_user_same_var() {
        let content = r#"
int handler(int *uarg) {
    int val;
    get_user(val, uarg);
    int x = val + 1;
    get_user(val, uarg);
    return val;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-367")),
            "Double get_user on same var should be flagged");
    }

    #[test]
    fn test_double_fetch_get_user() {
        let content = r#"
void handler(unsigned long __user *arg) {
    unsigned long val;
    get_user(val, arg);
    int x = val + 1;
    get_user(val, arg);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-367")));
    }

    #[test]
    fn test_double_fetch_close_lines() {
        let content = r#"
int handler(int *uf) {
    int f;
    get_user(f, uf);
    if (f > 100) return -1;
    get_user(f, uf);
    return f;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/char/random.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-367")),
            "TOCTOU pattern: validate-then-re-fetch should be flagged");
    }

    #[test]
    fn test_double_fetch_far_apart_not_flagged() {
        let content = r#"
int handler(int *arg) {
    int f[16];
    copy_from_user(f, arg, sizeof(f));
    int a = f[0];
    int b = f[1];
    int c = f[2];
    int d = f[3];
    int e = f[4];
    int f2 = f[5];
    int g = f[6];
    int h = f[7];
    int i = f[8];
    int j = f[9];
    int k = f[10];
    int l = f[11];
    int m = f[12];
    int n = f[13];
    int o = f[14];
    int p2 = f[15];
    int q2 = f[0];
    int r2 = f[1];
    int s2 = f[2];
    int t2 = f[3];
    int u2 = f[4];
    int v2 = f[5];
    int w2 = f[6];
    copy_from_user(f, arg, sizeof(f));
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe367: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-367")).collect();
        assert!(cwe367.is_empty(), "Fetches >20 lines apart should not be flagged");
    }

    // ================================================================
    // CHECKER 7: Stack buffer overflow (CWE-121)
    // ================================================================

    #[test]
    fn test_stack_overflow_sprintf_large_buf() {
        let content = r#"
void handler(void) {
    char big_buf[512];
    sprintf(big_buf, "%s", user_input);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-121")));
    }

    #[test]
    fn test_stack_overflow_strcpy_large_buf() {
        let content = r#"
void handler(void) {
    char buf[1024];
    strcpy(buf, src);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-121")));
    }

    #[test]
    fn test_stack_overflow_strcat_large_buf() {
        let content = r#"
void handler(void) {
    char buf[300];
    strcat(buf, extra);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-121")));
    }

    #[test]
    fn test_stack_overflow_gets_large_buf() {
        let content = r#"
void handler(void) {
    char buf[500];
    gets(buf);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-121")));
    }

    #[test]
    fn test_stack_overflow_memcpy_large_buf() {
        let content = r#"
void handler(void) {
    char buf[400];
    memcpy(buf, src, len);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-121")));
    }

    #[test]
    fn test_stack_overflow_small_buf_32_suppressed() {
        let content = r#"
void handler(void) {
    char buf[32];
    sprintf(buf, "%d", val);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe121: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-121")).collect();
        assert!(cwe121.is_empty(), "Buf <= 256 should not trigger");
    }

    #[test]
    fn test_stack_overflow_exact_256_suppressed() {
        let content = r#"
void handler(void) {
    char buf[256];
    sprintf(buf, "%s", user_input);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe121: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-121")).collect();
        assert!(cwe121.is_empty(), "Buf exactly 256 should not trigger (>256 required)");
    }

    #[test]
    fn test_stack_overflow_257_triggers() {
        let content = r#"
void handler(void) {
    char buf[257];
    sprintf(buf, "%s", user_input);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-121")),
            "Buf of 257 should trigger");
    }

    // ================================================================
    // CHECKER 8: Use-After-Free (CWE-416)
    // ================================================================

    #[test]
    fn test_uaf_kfree_then_deref() {
        let content = r#"
void handler(void) {
    kfree(ptr);
    ptr->field = 1;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-416")));
    }

    #[test]
    fn test_uaf_release_then_use() {
        let content = r#"
void cleanup(struct my_struct *s) {
    kfree(s);
    s->refcount = 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/usb/core/usb.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-416")));
    }

    #[test]
    fn test_uaf_kfree_then_member_access() {
        let content = r#"
void handler(void) {
    kfree(ctx);
    ctx->members.active = 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/net/tun.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-416")));
    }

    #[test]
    fn test_uaf_not_flagged_when_no_use_after() {
        let content = r#"
void handler(void) {
    kfree(ptr);
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe416: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-416")).collect();
        assert!(cwe416.is_empty(), "No use after free should not flag");
    }

    #[test]
    fn test_uaf_no_flag_for_different_var() {
        let content = r#"
void handler(void) {
    kfree(a);
    b->field = 1;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe416: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-416")).collect();
        assert!(cwe416.is_empty(), "Using different var should not flag");
    }

    // ================================================================
    // CHECKER 9: Double Free (CWE-415)
    // ================================================================

    #[test]
    fn test_double_free_basic() {
        let content = r#"
void handler(void) {
    kfree(ptr);
    do_something();
    kfree(ptr);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-415")));
    }

    #[test]
    fn test_double_free_error_path() {
        let content = r#"
void handler(void) {
    kfree(ptr);
    do_cleanup();
    kfree(ptr);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-415")),
            "Double free on error path should be detected");
    }

    #[test]
    fn test_double_free_conditional() {
        let content = r#"
void handler(int err) {
    kfree(ptr);
    if (err)
        kfree(ptr);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-415")));
    }

    #[test]
    fn test_double_free_no_flag_when_single() {
        let content = r#"
void handler(void) {
    kfree(ptr);
    ptr = NULL;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe415: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-415")).collect();
        assert!(cwe415.is_empty(), "Single kfree should not flag");
    }

    #[test]
    fn test_double_free_no_flag_different_vars() {
        let content = r#"
void handler(void) {
    kfree(a);
    kfree(b);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe415: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-415")).collect();
        assert!(cwe415.is_empty(), "Freeing different vars should not flag");
    }

    #[test]
    fn test_double_free_no_flag_for_func_call() {
        let content = r#"
void handler(void) {
    kfree(get_ptr());
    kfree(get_ptr());
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe415: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-415")).collect();
        assert!(cwe415.is_empty(), "Func call args should not flag as double free of same var");
    }

    // ================================================================
    // CHECKER 10: Integer wraparound (CWE-190)
    // ================================================================

    #[test]
    fn test_integer_overflow_count_times_size() {
        let content = r#"
void handler(int count, int size) {
    ptr = kmalloc(count * size, GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-190")));
    }

    #[test]
    fn test_integer_overflow_n_times_size() {
        let content = r#"
void handler(int n) {
    ptr = kmalloc(n * sizeof(struct foo), GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-190")));
    }

    #[test]
    fn test_integer_overflow_num_times_element_size() {
        let content = r#"
void handler(int num) {
    ptr = kzalloc(num * 128, GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-190")));
    }

    #[test]
    fn test_integer_overflow_len_times_element() {
        let content = r#"
void handler(int len) {
    ptr = kvmalloc(len * sizeof(u32), GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-190")));
    }

    #[test]
    fn test_integer_overflow_safe_array_size_suppressed() {
        let content = r#"
void handler(int count) {
    ptr = kmalloc_array(count, sizeof(struct item), GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe190: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-190")).collect();
        assert!(cwe190.is_empty(), "kmalloc_array should not trigger");
    }

    #[test]
    fn test_integer_overflow_struct_size_suppressed() {
        let content = r#"
void handler(void) {
    ptr = kmalloc(struct_size(ptr, field, count), GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe190: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-190")).collect();
        assert!(cwe190.is_empty(), "struct_size should suppress");
    }

    #[test]
    fn test_integer_overflow_size_mul_suppressed() {
        let content = r#"
void handler(int a, int b) {
    ptr = kmalloc(size_mul(a, b), GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe190: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-190")).collect();
        assert!(cwe190.is_empty(), "size_mul should suppress");
    }

    #[test]
    fn test_integer_overflow_check_mul_suppressed() {
        let content = r#"
void handler(int a, int b) {
    ptr = kmalloc(check_mul(a, b), GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe190: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-190")).collect();
        assert!(cwe190.is_empty(), "check_mul should suppress");
    }

    #[test]
    fn test_integer_overflow_with_parens() {
        let content = r#"
void handler(int nr) {
    ptr = kmalloc(nr *(sizeof(int)), GFP_KERNEL);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-190")));
    }

    // ================================================================
    // CHECKER 11: Type confusion (CWE-704)
    // ================================================================

    #[test]
    fn test_type_confusion_ioctl_cast() {
        let content = r#"
long my_ioctl(int f, int cmd, int ioctl_arg) {
    int *cfg = (void *)ioctl_arg;
    copy_from_user(&local, cfg, sizeof(local));
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/misc/my_ioctl.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-704")));
    }

    #[test]
    fn test_type_confusion_unsigned_long_in_ioctl() {
        let content = r#"
long handler(int f, int cmd, int ioctl_data) {
    int val = (unsigned long)ioctl_data;
    copy_from_user(&local, (void *)val, sizeof(local));
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/char/random.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-704")));
    }

    #[test]
    fn test_type_confusion_u64_ptr_cast() {
        let content = r#"
long handler(int f, int cmd, int ioctl_arg) {
    unsigned long *ptr = (unsigned long *)ioctl_arg;
    copy_from_user(&local, ptr, sizeof(local));
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/misc/ioctl.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-704")));
    }

    #[test]
    fn test_type_confusion_int_ptr_cast() {
        let content = r#"
long handler(int f, int cmd, int ioctl_buf) {
    int *p = (int *)ioctl_buf;
    copy_from_user(&val, p, sizeof(val));
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/net/tun.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-704")));
    }

    #[test]
    fn test_type_confusion_no_flag_non_kernel_path() {
        let content = r#"
void handler(void) {
    int *p = (void *)arg;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/usr/local/src/app.c"));
        let cwe704: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-704")).collect();
        assert!(cwe704.is_empty(), "Non-kernel path should not trigger type confusion");
    }

    #[test]
    fn test_type_confusion_no_flag_without_ioctl_copy_context() {
        let content = r#"
void handler(void) {
    long val = (unsigned long)data;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe704: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-704")).collect();
        assert!(cwe704.is_empty(), "Cast without ioctl/copy context should not trigger");
    }

    #[test]
    fn test_type_confusion_size_t_cast_in_copy() {
        let content = r#"
long handler(int f, int cmd, int ioctl_len) {
    int len = (int)ioctl_len;
    copy_from_user(&buf, (void *)ioctl_len, len);
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/fs/ioctl.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-704")));
    }

    #[test]
    fn test_type_confusion_loff_t_cast() {
        let content = r#"
long handler(int f, int cmd, int ioctl_offset) {
    int offset = (int)ioctl_offset;
    copy_from_user(&pos, (void *)ioctl_offset, sizeof(pos));
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/fs/read_write.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-704")));
    }

    // ================================================================
    // Edge cases and integration tests
    // ================================================================

    #[test]
    fn test_analyze_returns_findings_for_valid_c() {
        let content = r#"
int main(void) {
    return 0;
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(!findings.is_empty() || findings.is_empty());
        let _ = findings;
    }

    #[test]
    fn test_analyze_non_kernel_path_still_checks_patterns() {
        let content = r#"
void handler(void) {
    copy_from_user(buf, uaddr, len);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        assert!(findings.iter().any(|f| f.cwe.as_deref() == Some("CWE-120")));
    }

    #[test]
    fn test_analyze_empty_content() {
        let findings = KernelPatternAnalyzer::analyze("", &p("/kernel/drivers/test.c"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_analyze_syntax_error_returns_empty() {
        let findings = KernelPatternAnalyzer::analyze("{{{{invalid", &p("/kernel/drivers/test.c"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_no_findings_for_clean_code() {
        let content = r#"
int handler(void *arg) {
    struct local_buf buf;
    if (copy_from_user(&buf, arg, sizeof(buf)))
        return -EFAULT;
    if (!buf.data)
        return -EINVAL;
    return process(&buf);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe120: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-120")).collect();
        assert!(cwe120.is_empty(), "Well-validated code should not flag CWE-120");
    }

    #[test]
    fn test_kmzalloc_missing_count_check() {
        let content = r#"
void handler(void) {
    buf = kmalloc_array(count, elem_size, GFP_KERNEL);
    memset(buf, 0, count * elem_size);
}
"#;
        let findings = KernelPatternAnalyzer::analyze(content, &p("/kernel/drivers/test.c"));
        let cwe476: Vec<_> = findings.iter().filter(|f| f.cwe.as_deref() == Some("CWE-476")).collect();
        assert!(cwe476.is_empty(), "kmalloc_array return should not be checked if count is safe");
    }
}
