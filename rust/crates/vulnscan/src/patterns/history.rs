use std::path::Path;

pub struct OpenBSDTcpSackMatcher;
impl OpenBSDTcpSackMatcher {
    pub fn new() -> Self {
        Self
    }
    pub fn matches(&self, _content: &str, _path: &Path) -> Vec<crate::Finding> {
        vec![]
    }
}
