use std::path::Path;

pub struct OpenBSDTcpSackMatcher;
impl Default for OpenBSDTcpSackMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenBSDTcpSackMatcher {
    pub fn new() -> Self {
        Self
    }
    pub fn matches(&self, _content: &str, _path: &Path) -> Vec<crate::Finding> {
        vec![]
    }
}
