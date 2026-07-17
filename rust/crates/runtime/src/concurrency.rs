use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_CONCURRENCY: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConcurrencyCategory {
    Bash,
    Read,
    Write,
    Search,
    Mcp,
}

impl ConcurrencyCategory {
    #[must_use]
    pub fn default_limit(&self) -> usize {
        match self {
            Self::Bash => 5,
            Self::Read => 20,
            Self::Write => 3,
            Self::Search => 2,
            Self::Mcp => 10,
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Read => "read",
            Self::Write => "write",
            Self::Search => "search",
            Self::Mcp => "mcp",
        }
    }
}

#[derive(Debug)]
pub struct ConcurrencyManager {
    semaphores: HashMap<ConcurrencyCategory, Arc<Semaphore>>,
    active_count: HashMap<ConcurrencyCategory, Arc<AtomicUsize>>,
    limits: HashMap<ConcurrencyCategory, Arc<AtomicUsize>>,
}

impl Default for ConcurrencyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConcurrencyManager {
    #[must_use]
    pub fn new() -> Self {
        let mut semaphores = HashMap::new();
        let mut active_count = HashMap::new();
        let mut limits = HashMap::new();

        for category in &[
            ConcurrencyCategory::Bash,
            ConcurrencyCategory::Read,
            ConcurrencyCategory::Write,
            ConcurrencyCategory::Search,
            ConcurrencyCategory::Mcp,
        ] {
            let limit = category.default_limit();
            semaphores.insert(*category, Arc::new(Semaphore::new(MAX_CONCURRENCY)));
            active_count.insert(*category, Arc::new(AtomicUsize::new(0)));
            limits.insert(*category, Arc::new(AtomicUsize::new(limit)));
        }

        Self {
            semaphores,
            active_count,
            limits,
        }
    }

    pub async fn acquire(
        &self,
        category: ConcurrencyCategory,
    ) -> Option<ConcurrencyGuard> {
        let limit = self.limit(category);

        loop {
            let active = self.active_count(category);
            if active < limit {
                {
                    let semaphore = self.semaphores.get(&category)?;
                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            if let Some(counter) = self.active_count.get(&category) {
                                counter.fetch_add(1, Ordering::SeqCst);
                            }
                            return Some(ConcurrencyGuard {
                                _permit: Some(permit),
                                category,
                                active_count: self.active_count.get(&category).cloned(),
                            });
                        }
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            } else {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    #[must_use]
    pub fn try_acquire(
        &self,
        category: ConcurrencyCategory,
    ) -> Option<ConcurrencyGuard> {
        let limit = self.limit(category);
        let active = self.active_count(category);

        if active >= limit {
            return None;
        }

        if let Some(semaphore) = self.semaphores.get(&category) {
            match semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    if let Some(counter) = self.active_count.get(&category) {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                    Some(ConcurrencyGuard {
                        _permit: Some(permit),
                        category,
                        active_count: self.active_count.get(&category).cloned(),
                    })
                }
                Err(_) => None,
            }
        } else {
            None
        }
    }

    #[must_use]
    pub fn is_throttled(&self, category: ConcurrencyCategory) -> bool {
        let limit = self.limit(category);
        let active = self.active_count(category);
        active >= limit
    }

    #[must_use]
    pub fn available_permits(&self, category: ConcurrencyCategory) -> usize {
        let limit = self.limit(category);
        let active = self.active_count(category);
        limit.saturating_sub(active)
    }

    #[must_use]
    pub fn active_count(&self, category: ConcurrencyCategory) -> usize {
        self.active_count
            .get(&category)
            .map_or(0, |c| c.load(Ordering::SeqCst))
    }

    #[must_use]
    pub fn limit(&self, category: ConcurrencyCategory) -> usize {
        self.limits
            .get(&category)
            .map_or(0, |l| l.load(Ordering::SeqCst))
    }

    pub fn set_limit(&self, category: ConcurrencyCategory, new_limit: usize) {
        if let Some(limit) = self.limits.get(&category) {
            limit.store(new_limit, Ordering::SeqCst);
        }
    }

    #[must_use]
    pub fn status(&self) -> Vec<ConcurrencyStatus> {
        let mut statuses = Vec::new();
        for category in &[
            ConcurrencyCategory::Bash,
            ConcurrencyCategory::Read,
            ConcurrencyCategory::Write,
            ConcurrencyCategory::Search,
            ConcurrencyCategory::Mcp,
        ] {
            statuses.push(ConcurrencyStatus {
                name: category.name().to_string(),
                limit: self.limit(*category),
                active: self.active_count(*category),
                available: self.available_permits(*category),
                throttled: self.is_throttled(*category),
            });
        }
        statuses
    }
}

#[derive(Debug)]
pub struct ConcurrencyGuard {
    _permit: Option<OwnedSemaphorePermit>,
    category: ConcurrencyCategory,
    active_count: Option<Arc<AtomicUsize>>,
}

impl ConcurrencyGuard {
    #[must_use]
    pub fn category(&self) -> ConcurrencyCategory {
        self.category
    }
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        if let Some(counter) = &self.active_count {
            counter.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConcurrencyStatus {
    pub name: String,
    pub limit: usize,
    pub active: usize,
    pub available: usize,
    pub throttled: bool,
}

static GLOBAL_CONCURRENCY: OnceLock<ConcurrencyManager> = OnceLock::new();

pub fn global_concurrency_manager() -> &'static ConcurrencyManager {
    GLOBAL_CONCURRENCY.get_or_init(ConcurrencyManager::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrency_manager_acquire() {
        let manager = ConcurrencyManager::new();
        let guard = manager.acquire(ConcurrencyCategory::Bash).await;
        assert!(guard.is_some());
    }

    #[tokio::test]
    async fn test_concurrency_manager_try_acquire() {
        let manager = ConcurrencyManager::new();
        let guard = manager.try_acquire(ConcurrencyCategory::Bash);
        assert!(guard.is_some());
    }

    #[tokio::test]
    async fn test_concurrency_manager_limits() {
        let manager = ConcurrencyManager::new();
        assert_eq!(manager.limit(ConcurrencyCategory::Bash), 5);
        assert_eq!(manager.limit(ConcurrencyCategory::Read), 20);
        assert_eq!(manager.limit(ConcurrencyCategory::Write), 3);
    }

    #[tokio::test]
    async fn test_concurrency_manager_not_throttled_by_default() {
        let manager = ConcurrencyManager::new();
        assert!(!manager.is_throttled(ConcurrencyCategory::Bash));
    }

    #[tokio::test]
    async fn test_concurrency_manager_active_count() {
        let manager = ConcurrencyManager::new();
        let _guard = manager.acquire(ConcurrencyCategory::Bash).await;
        assert_eq!(manager.active_count(ConcurrencyCategory::Bash), 1);
    }

    #[tokio::test]
    async fn test_concurrency_manager_available_permits() {
        let manager = ConcurrencyManager::new();
        let _guard = manager.acquire(ConcurrencyCategory::Bash).await;
        assert_eq!(manager.available_permits(ConcurrencyCategory::Bash), 4);
    }

    #[tokio::test]
    async fn test_concurrency_manager_set_limit_increase() {
        let manager = ConcurrencyManager::new();
        manager.set_limit(ConcurrencyCategory::Bash, 10);
        assert_eq!(manager.limit(ConcurrencyCategory::Bash), 10);
        assert_eq!(manager.available_permits(ConcurrencyCategory::Bash), 10);
    }

    #[tokio::test]
    async fn test_concurrency_manager_set_limit_decrease() {
        let manager = ConcurrencyManager::new();
        manager.set_limit(ConcurrencyCategory::Bash, 2);
        assert_eq!(manager.limit(ConcurrencyCategory::Bash), 2);
        assert_eq!(manager.available_permits(ConcurrencyCategory::Bash), 2);
    }

    #[tokio::test]
    async fn test_concurrency_manager_concurrent_acquire() {
        let manager = ConcurrencyManager::new();
        let mut guards = Vec::new();

        for _ in 0..5 {
            let guard = manager.try_acquire(ConcurrencyCategory::Bash).unwrap();
            guards.push(guard);
        }

        assert_eq!(manager.active_count(ConcurrencyCategory::Bash), 5);
        assert!(manager.try_acquire(ConcurrencyCategory::Bash).is_none());

        drop(guards.remove(0));
        assert_eq!(manager.active_count(ConcurrencyCategory::Bash), 4);
        assert!(manager.try_acquire(ConcurrencyCategory::Bash).is_some());
    }

    #[tokio::test]
    async fn test_concurrency_manager_status() {
        let manager = ConcurrencyManager::new();
        let _guard = manager.acquire(ConcurrencyCategory::Bash).await;

        let statuses = manager.status();
        let bash_status = statuses.iter().find(|s| s.name == "bash").unwrap();

        assert_eq!(bash_status.limit, 5);
        assert_eq!(bash_status.active, 1);
        assert_eq!(bash_status.available, 4);
        assert!(!bash_status.throttled);
    }

    #[tokio::test]
    async fn test_concurrency_manager_guard_drop() {
        let manager = ConcurrencyManager::new();
        let guard = manager.acquire(ConcurrencyCategory::Bash).await;
        assert!(guard.is_some());
        drop(guard);

        for _ in 0..5 {
            assert!(manager.try_acquire(ConcurrencyCategory::Bash).is_some());
        }
    }

    #[test]
    fn test_concurrency_category_defaults() {
        assert_eq!(ConcurrencyCategory::Bash.default_limit(), 5);
        assert_eq!(ConcurrencyCategory::Read.default_limit(), 20);
        assert_eq!(ConcurrencyCategory::Write.default_limit(), 3);
        assert_eq!(ConcurrencyCategory::Search.default_limit(), 2);
        assert_eq!(ConcurrencyCategory::Mcp.default_limit(), 10);
    }

    #[test]
    fn test_concurrency_category_names() {
        assert_eq!(ConcurrencyCategory::Bash.name(), "bash");
        assert_eq!(ConcurrencyCategory::Mcp.name(), "mcp");
    }

    #[tokio::test]
    async fn test_global_concurrency_manager() {
        let manager = global_concurrency_manager();
        let guard = manager.acquire(ConcurrencyCategory::Read).await;
        assert!(guard.is_some());
    }

    #[tokio::test]
    async fn test_concurrency_guard_category() {
        let manager = ConcurrencyManager::new();
        let guard = manager.acquire(ConcurrencyCategory::Write).await.unwrap();
        assert_eq!(guard.category(), ConcurrencyCategory::Write);
    }

    #[tokio::test]
    async fn test_manager_throttled_when_exhausted() {
        let manager = ConcurrencyManager::new();
        manager.set_limit(ConcurrencyCategory::Bash, 1);
        let _guard = manager.acquire(ConcurrencyCategory::Bash).await;
        assert!(manager.is_throttled(ConcurrencyCategory::Bash));
    }
}
