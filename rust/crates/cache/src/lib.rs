//! Cache multi-nivel para Venezuela
//! Reduce uso de API tokens mediante caching inteligente

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use thiserror::Error;

mod error;
pub use error::*;

/// Errores del cache
#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Error de base de datos: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("No encontrado")]
    NotFound,
    #[error("Expirado")]
    Expired,
    #[error("Serialización: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Nivel de cache
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheLevel {
    Memory,
    Disk,
}

/// Tipo de contenido cacheable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheType {
    Response,
    Prompt,
    Embedding,
    ToolResult,
}

/// Entry guardado en cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key_hash: String,
    pub cache_type: CacheType,
    pub content: String,
    pub compressed: bool,
    pub created_at: i64,
    pub expires_at: i64,
    pub hits: u32,
}

/// Política de eviction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvictionPolicy {
    LRU,
    LFU,
    FIFO,
    TTL,
}

impl Default for EvictionPolicy {
    fn default() -> Self {
        EvictionPolicy::LRU
    }
}

/// Settings del cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSettings {
    pub max_memory_mb: usize,
    pub max_disk_mb: usize,
    pub default_ttl_secs: i64,
    pub enable_compression: bool,
    pub eviction_policy: EvictionPolicy,
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            max_memory_mb: 100,
            max_disk_mb: 500,
            default_ttl_secs: 3600,
            enable_compression: true,
            eviction_policy: EvictionPolicy::LRU,
        }
    }
}

/// Cache manager
pub struct CacheManager {
    db: Mutex<rusqlite::Connection>,
    settings: CacheSettings,
    memory_hits: Mutex<u64>,
    memory_miss: Mutex<u64>,
}

impl CacheManager {
    pub fn new(data_dir: PathBuf) -> Result<Self, CacheError> {
        let db_path = data_dir.join("cache.db");
        let conn = rusqlite::Connection::open(&db_path)?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cache_entries (
                key_hash TEXT PRIMARY KEY,
                cache_type TEXT NOT NULL,
                content BLOB NOT NULL,
                compressed INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                hits INTEGER DEFAULT 0
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache_entries(expires_at)",
            [],
        )?;

        Ok(Self {
            db: Mutex::new(conn),
            settings: CacheSettings::default(),
            memory_hits: Mutex::new(0),
            memory_miss: Mutex::new(0),
        })
    }

    pub fn hash_key(&self, key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn set(&self, key: &str, cache_type: CacheType, content: &str) -> Result<(), CacheError> {
        let key_hash = self.hash_key(key);
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + self.settings.default_ttl_secs;
        
        let content_bytes = content.as_bytes().to_vec();
        let db = self.db.lock().unwrap();
        
        db.execute(
            "INSERT OR REPLACE INTO cache_entries 
             (key_hash, cache_type, content, compressed, created_at expires_at, hits) 
             VALUES (?1, ?2, ?3, 0, ?4, ?5, 1)",
            rusqlite::params![
                key_hash,
                format!("{:?}", cache_type),
                content_bytes,
                now,
                expires_at,
            ],
        )?;

        Ok(())
    }

    pub fn get(&self, key: &str, cache_type: CacheType) -> Result<String, CacheError> {
        let key_hash = self.hash_key(key);
        let now = chrono::Utc::now().timestamp();
        
        let db = self.db.lock().unwrap();
        
        let mut stmt = db.prepare(
            "SELECT content, expires_at, hits FROM cache_entries 
             WHERE key_hash = ?1 AND cache_type = ?2 AND expires_at > ?3"
        )?;

        let result = stmt.query_row(
            rusqlite::params![key_hash, format!("{:?}", cache_type), now],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, u32>(2)?,
                ))
            },
        );

        match result {
            Ok((content, _, hits)) => {
                db.execute(
                    "UPDATE cache_entries SET hits = hits + 1 WHERE key_hash = ?1",
                    rusqlite::params![key_hash],
                )?;
                
                *self.memory_hits.lock().unwrap() += 1;
                
                let content_str = String::from_utf8(content).map_err(|_| CacheError::NotFound)?;
                Ok(content_str)
            }
            Err(_) => {
                *self.memory_miss.lock().unwrap() += 1;
                Err(CacheError::NotFound)
            }
        }
    }

    pub fn contains(&self, key: &str, cache_type: CacheType) -> bool {
        let key_hash = self.hash_key(key);
        let now = chrono::Utc::now().timestamp();
        
        if let Ok(db) = self.db.lock() {
            if let Ok(mut stmt) = db.prepare(
                "SELECT 1 FROM cache_entries WHERE key_hash = ?1 AND cache_type = ?2 AND expires_at > ?3"
            ) {
                return stmt.exists(rusqlite::params![key_hash, format!("{:?}", cache_type), now]).unwrap_or(false);
            }
        }
        false
    }

    pub fn cleanup_expired(&self) -> Result<usize, CacheError> {
        let now = chrono::Utc::now().timestamp();
        let db = self.db.lock().unwrap();
        let deleted = db.execute(
            "DELETE FROM cache_entries WHERE expires_at < ?1",
            rusqlite::params![now],
        )?;
        Ok(deleted)
    }

    pub fn stats(&self) -> CacheStats {
        let db = self.db.lock().unwrap();
        
        let total_entries: i64 = db.query_row("SELECT COUNT(*) FROM cache_entries", [], |row| row.get(0)).unwrap_or(0);
        let expired_entries: i64 = db.query_row(
            "SELECT COUNT(*) FROM cache_entries WHERE expires_at < ?1",
            rusqlite::params![chrono::Utc::now().timestamp()],
            |row| row.get(0)
        ).unwrap_or(0);

        let hits = *self.memory_hits.lock().unwrap();
        let misses = *self.memory_miss.lock().unwrap();
        let total_requests = hits + misses;
        let hit_rate = if total_requests > 0 {
            (hits as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        CacheStats { total_entries, expired_entries, hits, misses, hit_rate }
    }

    pub fn clear(&self) -> Result<(), CacheError> {
        let db = self.db.lock().unwrap();
        db.execute("DELETE FROM cache_entries", [])?;
        Ok(())
    }
}

/// Estadísticas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: i64,
    pub expired_entries: i64,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_creation() {
        let tmp = TempDir::new().unwrap();
        let cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 0);
    }
}