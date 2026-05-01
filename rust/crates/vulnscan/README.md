# vulnscan

A comprehensive vulnerability scanner for the `claw-vzla` system, supporting multiple programming languages with both static pattern matching and LLM-powered analysis.

## Features

- **Multi-language support**: Rust, C/C++, Python, Ruby, JavaScript/TypeScript
- **Static pattern matching**: Detects common vulnerabilities (buffer overflows, SQL injection, XSS, etc.)
- **LLM Agent integration**: Uses local Ollama models for deep code analysis (Mythos-style)
- **Dependency scanning**: Integrates with `cargo audit`, `pip-audit`, `npm audit`, `bundle-audit`
- **Tool integrations**: Clippy, ASAN sanitizers, and cargo-fuzz
- **SQLite database**: Stores and retrieves findings locally
- **Colored CLI reports** and **JSON output**

## Supported Vulnerabilities by Language

| Language | Patterns Detected |
|----------|-------------------|
| Rust | Unsafe blocks, unwrap/expect patterns |
| C/C++ | Buffer overflows (strcpy/strcat), double-free, integer overflow, unsafe casts |
| Python | SQL injection, command injection, pickle deserialization, hardcoded secrets |
| Ruby | Command injection, marshal load, SQL injection, XSS |
| JavaScript/TypeScript | XSS (innerHTML), eval(), SQL injection, unsafe type assertions |

## Usage

### Basic Scan

```rust
use vulnscan::{ScanConfig, scan::VulnerabilityScanner};

let config = ScanConfig {
    target_paths: vec![std::path::PathBuf::from("./src")],
    enable_llm_agent: false,  // Set to true for LLM analysis
    min_severity: vulnscan::Severity::Medium,
    ..Default::default()
};

let scanner = VulnerabilityScanner::new(config);
let findings = scanner.scan();

for finding in &findings {
    println!("{}: {}", finding.severity, finding.description);
}
```

### With LLM Agent (Mythos-style)

```rust
use vulnscan::{ScanConfig, agent::VulnerabilityAgent};

let agent = agent::VulnerabilityAgent::with_ollama(
    "http://localhost:11434",
    "llama3.2"
);

let findings = agent.analyze_file(
    std::path::Path::new("src/main.rs"),
    vulnscan::Language::Rust
).await;
```

### Generate Reports

```rust
use vulnscan::{report, Finding};

// Colored CLI report
report::generate_cli_report(&findings);

// JSON report
let json = report::generate_json_report(&findings);
println!("{}", json);

// Quick summary
report::print_summary(&findings);
```

## Configuration

```rust
ScanConfig {
    target_paths: Vec<PathBuf>,           // Directories/files to scan
    languages: Vec<Language>,             // Filter by language
    enable_llm_agent: bool,              // Enable LLM analysis
    enable_fuzzing: bool,                // Enable cargo-fuzz
    enable_sanitizers: bool,             // Enable ASAN/TSAN
    enable_dependency_scan: bool,         // Enable dep audit tools
    min_severity: Severity,              // Minimum severity to report
    max_findings_per_path: Option<usize>, // Limit findings per file
}
```

## Integration with claw-vzla

The `vulnscan` crate integrates with:
- `runtime`: For orchestration and job execution
- `security`: For policy enforcement
- `localmodels`: For local LLM inference (Ollama)

## Dependencies

- `rusqlite` (0.32) - SQLite database for findings
- `reqwest` - HTTP client for Ollama API
- `tree-sitter-*` - For future AST-based analysis
- `termcolor` - Colored CLI output
- `walkdir` - Directory traversal
- `uuid` - Unique finding IDs

## Building

```bash
cd /home/tdy/Escritorio/claw-vzla/rust
cargo build -p vulnscan
```

## Testing

```bash
cargo test -p vulnscan
```

## License

MIT
