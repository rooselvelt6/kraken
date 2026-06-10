use crate::Finding;
use std::path::Path;

pub struct ReverseEngineer;

impl ReverseEngineer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_binary(&self, _path: &Path) -> Vec<Finding> {
        vec![]
    }

    pub fn disassemble_section(&self, _path: &Path, _section: &str) -> Vec<Finding> {
        vec![]
    }

    pub fn extract_strings(&self, _path: &Path) -> Vec<String> {
        vec![]
    }
}

impl Default for ReverseEngineer {
    fn default() -> Self {
        Self::new()
    }
}
