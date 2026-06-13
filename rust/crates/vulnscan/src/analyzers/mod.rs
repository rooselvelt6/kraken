pub mod c_cpp;
pub mod cloudformation;
pub mod docker;
pub mod go;
pub mod java;
pub mod kubernetes;
pub mod lua;
pub mod os;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod swift;
pub mod terraform;
pub mod web;

use crate::{Finding, Language, ScanConfig};
use std::path::Path;

pub trait LanguageAnalyzer {
    fn language(&self) -> Language;
    fn supported_extensions(&self) -> Vec<&'static str>;
    fn analyze(&self, content: &str, file_path: &Path, config: &ScanConfig) -> Vec<Finding>;
}

pub fn load_all_analyzers() -> Vec<Box<dyn LanguageAnalyzer + Send + Sync>> {
    vec![
        Box::new(rust::RustAnalyzer::default()),
        Box::new(python::PythonAnalyzer::default()),
        Box::new(ruby::RubyAnalyzer::default()),
        Box::new(c_cpp::CAnalyzer::default()),
        Box::new(c_cpp::CppAnalyzer::default()),
        Box::new(web::JavaScriptAnalyzer::default()),
        Box::new(web::TypeScriptAnalyzer::default()),
        Box::new(web::WebAppAnalyzer::default()),
        Box::new(os::LinuxKernelAnalyzer::default()),
        Box::new(os::OpenBSDAnalyzer::default()),
        Box::new(os::FreeBSDAnalyzer::default()),
        Box::new(go::GoAnalyzer::default()),
        Box::new(java::JavaAnalyzer::default()),
        Box::new(swift::SwiftAnalyzer::default()),
        Box::new(lua::LuaAnalyzer::default()),
        Box::new(docker::DockerAnalyzer::default()),
        Box::new(kubernetes::KubernetesAnalyzer::default()),
        Box::new(terraform::TerraformAnalyzer::default()),
        Box::new(cloudformation::CloudFormationAnalyzer::default()),
    ]
}

pub fn detect_language(file_path: &Path, content: Option<&str>) -> Language {
    let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if file_name == "Dockerfile" || file_name.starts_with("Dockerfile.") || file_name == "Containerfile" {
        return Language::Docker;
    }

    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let ext_lang = match ext {
        "rs" => Language::Rust,
        "c" | "h" => Language::C,
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => Language::Cpp,
        "js" | "mjs" | "cjs" => Language::JavaScript,
        "ts" | "tsx" | "mts" | "cts" => Language::TypeScript,
        "py" | "pyw" => Language::Python,
        "rb" => Language::Ruby,
        "go" => Language::Go,
        "java" => Language::Java,
        "swift" => Language::Swift,
        "lua" => Language::Lua,
        "sh" | "bash" => Language::Shell,
        "tf" => Language::Terraform,
        _ => Language::Other,
    };

    if ext == "yaml" || ext == "yml" || ext == "json" {
        if let Some(c) = content {
            if c.contains("apiVersion:") && c.contains("kind:") {
                return Language::Kubernetes;
            }
            if c.contains("Type: AWS::") || c.contains("Type : AWS::") || c.contains("AWS::") {
                return Language::Terraform;
            }
        }
        return Language::Other;
    }

    if ext == "dockerfile" || ext.is_empty() {
        if let Some(c) = content {
            if c.contains("FROM ") && (c.contains("RUN ") || c.contains("CMD ") || c.contains("ENTRYPOINT ")) {
                return Language::Docker;
            }
        }
        if !ext.is_empty() {
            return ext_lang;
        }
        return Language::Other;
    }

    ext_lang
}
