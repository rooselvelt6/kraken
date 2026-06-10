#[allow(
    clippy::all,
    clippy::len_without_is_empty,
    clippy::unnecessary_map_or,
    clippy::field_reassign_with_default,
    clippy::manual_find
)]

/// Performance optimizations: connection pooling, caching:
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct PooledConnection {
    pub created_at: Instant,
    pub last_used: Instant,
    in_use: bool,
}

impl PooledConnection {
    pub fn new() -> Self {
        Self {
            created_at: Instant::now(),
            last_used: Instant::now(),
            in_use: false,
        }
    }

    pub fn mark_used(&mut self) {
        self.last_used = Instant::now();
        self.in_use = true;
    }

    pub fn release(&mut self) {
        self.in_use = false;
    }

    pub fn is_idle(&self) -> bool {
        !self.in_use
    }

    pub fn idle_duration(&self) -> Duration {
        self.last_used.elapsed()
    }
}

pub struct ConnectionPool {
    max_connections: usize,
    min_idle: usize,
    idle_timeout: Duration,
    connections: Mutex<VecDeque<PooledConnection>>,
}

impl ConnectionPool {
    pub fn new(max_connections: usize, min_idle: usize, idle_timeout: Duration) -> Self {
        Self {
            max_connections,
            min_idle,
            idle_timeout,
            connections: Mutex::new(VecDeque::new()),
        }
    }

    pub fn acquire(&self) -> Option<PooledConnection> {
        let mut guard = self.connections.lock().unwrap();

        while let Some(mut conn) = guard.pop_front() {
            if conn.idle_duration() > self.idle_timeout {
                continue;
            }
            conn.mark_used();
            return Some(conn);
        }

        if guard.len() < self.max_connections {
            Some(PooledConnection::new())
        } else {
            None
        }
    }

    pub fn release(&self, mut conn: PooledConnection) {
        conn.release();
        let mut guard = self.connections.lock().unwrap();

        while guard.len() > self.min_idle
            && guard
                .front()
                .is_some_and(|c| c.idle_duration() > self.idle_timeout)
        {
            guard.pop_front();
        }

        guard.push_back(conn);
    }

    pub fn stats(&self) -> PoolStats {
        let guard = self.connections.lock().unwrap();
        PoolStats {
            total: guard.len(),
            idle: guard.iter().filter(|c| c.is_idle()).count(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total: usize,
    pub idle: usize,
}

// ============================================================================
// Caching
// ============================================================================

pub struct CacheEntry<V> {
    pub value: V,
    pub created_at: Instant,
    pub expires_at: Option<Instant>,
}

pub struct TimedCache<K, V> {
    max_size: usize,
    entries: HashMap<K, CacheEntry<V>>,
}

impl<K: std::hash::Hash + Eq + Clone, V: Clone> TimedCache<K, V> {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            entries: HashMap::new(),
        }
    }

    pub fn get(&mut self, key: &K) -> Option<V> {
        if let Some(entry) = self.entries.get(key) {
            if let Some(expires) = entry.expires_at {
                if Instant::now() > expires {
                    self.entries.remove(key);
                    return None;
                }
            }
            return Some(entry.value.clone());
        }
        None
    }

    pub fn insert(&mut self, key: K, value: V, ttl_secs: Option<u64>) {
        if self.entries.len() >= self.max_size {
            if let Some(oldest) = self.entries.keys().next().cloned() {
                self.entries.remove(&oldest);
            }
        }

        let expires_at = ttl_secs.map(|ttl| Instant::now() + Duration::from_secs(ttl));

        self.entries.insert(
            key,
            CacheEntry {
                value,
                created_at: Instant::now(),
                expires_at,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_pool() {
        let pool = ConnectionPool::new(5, 1, Duration::from_secs(60));

        let conn = pool.acquire();
        assert!(conn.is_some());

        pool.release(conn.unwrap());

        let stats = pool.stats();
        assert_eq!(stats.total, 1);
    }

    #[test]
    fn test_timed_cache() {
        let mut cache = TimedCache::new(10);

        cache.insert("key1", "value1", None);
        assert!(cache.get(&"key1").is_some());
        assert_eq!(cache.len(), 1);
    }
}
