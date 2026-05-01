pub mod c_cpp;
pub mod os;
pub mod python;
pub mod ruby;
pub mod rust;
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
    ]
}

pub fn detect_language(file_path: &Path) -> Language {
    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "rs" => Language::Rust,
        "c" | "h" => Language::C,
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Language::Cpp,
        "js" | "mjs" => Language::JavaScript,
        "ts" | "tsx" => Language::TypeScript,
        "py" => Language::Python,
        "rb" => Language::Ruby,
        "sh" | "bash" => Language::Shell,
        _ => Language::Other,
    }
}
