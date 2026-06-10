use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{DiscoveryMethod, Finding, ScanConfig, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub version: Option<String>,
    pub category: TechCategory,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TechCategory {
    Language,
    Framework,
    Database,
    Cache,
    WebServer,
    DependencyManager,
    BuildTool,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub path: String,
    pub method: String,
    pub source_file: PathBuf,
    pub line_number: u32,
    pub auth_required: bool,
    pub param_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    pub description: String,
    pub file_path: PathBuf,
    pub line_number: u32,
    pub entry_type: EntryType,
    pub risk: Severity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EntryType {
    NetworkListener,
    UnsafeFunction,
    ExternalInput,
    FileOperation,
    CommandExecution,
    Serialization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    pub technologies: Vec<Technology>,
    pub endpoints: Vec<Endpoint>,
    pub entry_points: Vec<EntryPoint>,
    pub dependencies: Vec<String>,
    pub total_files: usize,
    pub total_lines: usize,
}

pub struct SurfaceRecon;

impl SurfaceRecon {
    pub fn enumerate_attack_surface(path: &Path, config: &ScanConfig) -> AttackSurface {
        let technologies = Self::fingerprint_technologies(path);
        let endpoints = Self::map_endpoints(path, &technologies);
        let entry_points = Self::identify_entry_points(path, config);
        let dependencies = Self::discover_dependencies(path);
        let (total_files, total_lines) = Self::count_files_and_lines(path);

        AttackSurface {
            technologies,
            endpoints,
            entry_points,
            dependencies,
            total_files,
            total_lines,
        }
    }

    pub fn fingerprint_technologies(path: &Path) -> Vec<Technology> {
        let mut techs = Vec::new();
        let mut ext_counts: HashMap<String, usize> = HashMap::new();

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    if let Some(ext) = entry.path().extension() {
                        *ext_counts
                            .entry(ext.to_string_lossy().to_string())
                            .or_insert(0) += 1;
                    }
                }
            }
        }

        for (ext, count) in &ext_counts {
            let Some((name, category)) = (match ext.as_str() {
                "rs" => Some(("Rust", TechCategory::Language)),
                "c" | "h" => Some(("C", TechCategory::Language)),
                "cpp" | "hpp" => Some(("C++", TechCategory::Language)),
                "js" | "mjs" => Some(("JavaScript", TechCategory::Language)),
                "ts" | "tsx" => Some(("TypeScript", TechCategory::Language)),
                "py" => Some(("Python", TechCategory::Language)),
                "rb" => Some(("Ruby", TechCategory::Language)),
                "go" => Some(("Go", TechCategory::Language)),
                "java" => Some(("Java", TechCategory::Language)),
                "swift" => Some(("Swift", TechCategory::Language)),
                "sh" | "bash" => Some(("Shell", TechCategory::Language)),
                "toml" => Some(("TOML", TechCategory::DependencyManager)),
                "json" => Some(("JSON", TechCategory::Other)),
                "yaml" | "yml" => Some(("YAML", TechCategory::Other)),
                "sql" => Some(("SQL", TechCategory::Database)),
                "html" | "htm" => Some(("HTML", TechCategory::Other)),
                "css" => Some(("CSS", TechCategory::Other)),
                _ => None,
            }) else {
                continue;
            };
            techs.push(Technology {
                name: name.to_string(),
                version: None,
                category,
                confidence: (*count as f32 / ext_counts.values().sum::<usize>() as f32).min(1.0),
            });
        }

        if path.join("Cargo.toml").exists() {
            techs.push(Technology {
                name: "Cargo".to_string(),
                version: None,
                category: TechCategory::DependencyManager,
                confidence: 1.0,
            });
        }
        if path.join("package.json").exists() {
            techs.push(Technology {
                name: "npm".to_string(),
                version: None,
                category: TechCategory::DependencyManager,
                confidence: 1.0,
            });
        }
        if path.join("go.mod").exists() {
            techs.push(Technology {
                name: "Go Modules".to_string(),
                version: None,
                category: TechCategory::DependencyManager,
                confidence: 1.0,
            });
        }

        techs.dedup_by(|a, b| a.name == b.name);
        techs
    }

    pub fn map_endpoints(path: &Path, _techs: &[Technology]) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let route_patterns = [
            ("fn ", "get"),
            ("fn ", "post"),
            ("fn ", "put"),
            ("fn ", "delete"),
            ("fn ", "patch"),
            ("app\\.", "get"),
            ("router\\.", "get"),
            ("@app\\.route", "any"),
            ("def ", "any"),
        ];

        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let fpath = entry.path().to_path_buf();
            if let Ok(content) = std::fs::read_to_string(&fpath) {
                for (lineno, line) in content.lines().enumerate() {
                    for (pattern, method) in &route_patterns {
                        if line.contains(pattern)
                            && (line.contains("route")
                                || line.contains("get")
                                || line.contains("post")
                                || line.contains("put")
                                || line.contains("delete"))
                        {
                            endpoints.push(Endpoint {
                                path: line.trim().to_string(),
                                method: method.to_string(),
                                source_file: fpath.clone(),
                                line_number: (lineno + 1) as u32,
                                auth_required: line.contains("auth")
                                    || line.contains("login")
                                    || line.contains("token"),
                                param_count: line.matches("{}").count()
                                    + line.matches("{:").count(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        endpoints
    }

    pub fn identify_entry_points(path: &Path, config: &ScanConfig) -> Vec<EntryPoint> {
        let mut entries = Vec::new();
        let patterns = [
            ("unsafe {", EntryType::UnsafeFunction, Severity::High),
            (
                "std::net::TcpListener",
                EntryType::NetworkListener,
                Severity::Medium,
            ),
            ("bind(", EntryType::NetworkListener, Severity::Medium),
            ("listen(", EntryType::NetworkListener, Severity::Medium),
            ("read_line", EntryType::ExternalInput, Severity::Medium),
            ("std::io::stdin", EntryType::ExternalInput, Severity::Medium),
            ("std::fs::read", EntryType::FileOperation, Severity::Low),
            (
                "std::fs::File::open",
                EntryType::FileOperation,
                Severity::Low,
            ),
            (
                "std::process::Command",
                EntryType::CommandExecution,
                Severity::Critical,
            ),
            (
                "serde::Deserialize",
                EntryType::Serialization,
                Severity::Medium,
            ),
            (
                "serde_json::from_str",
                EntryType::Serialization,
                Severity::Medium,
            ),
            (
                "serde_json::from_reader",
                EntryType::Serialization,
                Severity::Medium,
            ),
        ];

        let target_exts: Vec<&str> = config
            .languages
            .iter()
            .flat_map(|l| l.extensions().iter().copied())
            .collect();

        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let fpath = entry.path().to_path_buf();
            if let Some(ext) = fpath.extension().and_then(|e| e.to_str()) {
                if !target_exts.contains(&ext) {
                    continue;
                }
            }
            if let Ok(content) = std::fs::read_to_string(&fpath) {
                for (lineno, line) in content.lines().enumerate() {
                    for (pattern, etype, risk) in &patterns {
                        if line.contains(pattern) {
                            entries.push(EntryPoint {
                                description: format!(
                                    "{} encontrado: {}",
                                    match etype {
                                        EntryType::UnsafeFunction => "Código unsafe",
                                        EntryType::NetworkListener => "Listener de red",
                                        EntryType::ExternalInput => "Entrada externa",
                                        EntryType::FileOperation => "Operación de archivos",
                                        EntryType::CommandExecution => "Ejecución de comandos",
                                        EntryType::Serialization => "Deserialización",
                                    },
                                    line.trim()
                                ),
                                file_path: fpath.clone(),
                                line_number: (lineno + 1) as u32,
                                entry_type: *etype,
                                risk: *risk,
                            });
                        }
                    }
                }
            }
        }

        entries
    }

    pub fn discover_dependencies(path: &Path) -> Vec<String> {
        let mut deps = Vec::new();

        if let Ok(content) = std::fs::read_to_string(path.join("Cargo.toml")) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("name") || trimmed.starts_with("version") {
                    deps.push(trimmed.to_string());
                }
            }
        }

        if let Ok(content) = std::fs::read_to_string(path.join("package.json")) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.contains("\"dependencies\"") || trimmed.contains("\"devDependencies\"") {
                    deps.push(trimmed.to_string());
                }
            }
        }

        deps
    }

    pub fn findings_from_attack_surface(surface: &AttackSurface) -> Vec<Finding> {
        let mut findings = Vec::new();

        for ep in &surface.entry_points {
            if ep.entry_type == EntryType::UnsafeFunction {
                findings.push(Finding::new(
                    ep.risk,
                    format!("Entry point unsafe: {}", ep.description),
                    Some(ep.file_path.clone()),
                    Some(ep.line_number),
                    None,
                    Some("Minimizar bloques unsafe; usar safe abstractions".to_string()),
                    Some("CWE-119".to_string()),
                    0.7,
                    DiscoveryMethod::ReverseEngineering,
                ));
            }
        }

        findings
    }

    fn count_files_and_lines(path: &Path) -> (usize, usize) {
        let mut files = 0;
        let mut lines = 0;

        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            files += 1;
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                lines += content.lines().count();
            }
        }

        (files, lines)
    }
}
