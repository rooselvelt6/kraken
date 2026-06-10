pub struct Sandbox;

impl Sandbox {
    pub fn new() -> Self {
        Self
    }

    pub fn is_sandboxed(&self) -> bool {
        false
    }

    pub fn run_isolated<F, T>(&self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        f()
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}
