//! Cache multi-nivel para Venezuela
//! Reduce uso de API tokens mediante caching inteligente

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use thiserror::Error;
use chrono::Utc;

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
    #[error("Error de compresión: {0}")]
    Compression(String),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EvictionPolicy {
    #[default]
    LRU,
    LFU,
    FIFO,
    TTL,
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

/// In-memory cache entry
#[derive(Debug, Clone)]
struct MemoryCacheEntry {
    content: String,
    expires_at: i64,
    hits: u32,
}

/// Cache manager
pub struct CacheManager {
    db: Mutex<rusqlite::Connection>,
    settings: CacheSettings,
    memory_cache: Mutex<HashMap<String, MemoryCacheEntry>>,
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

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_cache_type ON cache_entries(cache_type)",
            [],
        )?;

        Ok(Self {
            db: Mutex::new(conn),
            settings: CacheSettings::default(),
            memory_cache: Mutex::new(HashMap::new()),
            memory_hits: Mutex::new(0),
            memory_miss: Mutex::new(0),
        })
    }

    pub fn hash_key(&self, key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, CacheError> {
        if !self.settings.enable_compression {
            return Ok(data.to_vec());
        }
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).map_err(|e| CacheError::Compression(e.to_string()))?;
        encoder.finish().map_err(|e| CacheError::Compression(e.to_string()))
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, CacheError> {
        if !self.settings.enable_compression {
            return Ok(data.to_vec());
        }
        // Try to decompress, if fails return original (for backward compatibility)
        let mut decoder = flate2::read::ZlibDecoder::new(data);
        let mut result = Vec::new();
        match decoder.read_to_end(&mut result) {
            Ok(_) => Ok(result),
            Err(_) => Ok(data.to_vec()), // Return original if decompression fails
        }
    }

    fn evict_if_needed(&self) -> Result<(), CacheError> {
        let db = self.db.lock().unwrap();
        
        // Check disk size
        let disk_size: i64 = db.query_row(
            "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM cache_entries",
            [],
            |row| row.get(0)
        ).unwrap_or(0);

        let max_disk_bytes = (self.settings.max_disk_mb as i64) * 1024 * 1024;
        
        if disk_size > max_disk_bytes {
            match self.settings.eviction_policy {
                EvictionPolicy::LRU => {
                    db.execute(
                        "DELETE FROM cache_entries WHERE key_hash IN (
                            SELECT key_hash FROM cache_entries 
                            ORDER BY expires_at ASC LIMIT ?
                        )",
                        rusqlite::params![1i32], // Delete at least 1 entry
                    )?;
                }
                EvictionPolicy::LFU => {
                    db.execute(
                        "DELETE FROM cache_entries WHERE key_hash IN (
                            SELECT key_hash FROM cache_entries 
                            ORDER BY hits ASC LIMIT ?
                        )",
                        rusqlite::params![1i32],
                    )?;
                }
                EvictionPolicy::FIFO => {
                    db.execute(
                        "DELETE FROM cache_entries WHERE key_hash IN (
                            SELECT key_hash FROM cache_entries 
                            ORDER BY created_at ASC LIMIT ?
                        )",
                        rusqlite::params![1i32],
                    )?;
                }
                EvictionPolicy::TTL => {
                    // TTL is handled by expires_at, just clean expired
                    db.execute("DELETE FROM cache_entries WHERE expires_at < ?1", 
                              rusqlite::params![Utc::now().timestamp()])?;
                }
            }
        }
        
        // Check memory size - simplified for testing
        let mut mem_cache = self.memory_cache.lock().unwrap();
        if mem_cache.len() > (self.settings.max_memory_mb * 1024) {
            // Simple eviction: remove first entry
            if let Some(key) = mem_cache.keys().next().cloned() {
                mem_cache.remove(&key);
            }
        }
        
        Ok(())
    }

    pub fn set(&self, key: &str, cache_type: CacheType, content: &str) -> Result<(), CacheError> {
        let key_hash = self.hash_key(key);
        let now = Utc::now().timestamp();
        let expires_at = now + self.settings.default_ttl_secs;
        
        let content_bytes = self.compress(content.as_bytes())?;
        let compressed_flag = if self.settings.enable_compression { 1i32 } else { 0i32 };
        
        // Store in memory cache
        if let Ok(mut mem_cache) = self.memory_cache.lock() {
            if mem_cache.len() < self.settings.max_memory_mb * 1024 {
                mem_cache.insert(
                    format!("{}:{:?}", key_hash, cache_type),
                    MemoryCacheEntry {
                        content: content.to_string(),
                        expires_at,
                        hits: 0,
                    }
                );
            }
        }
        
        let db = self.db.lock().unwrap();
        
        db.execute(
            "INSERT OR REPLACE INTO cache_entries 
             (key_hash, cache_type, content, compressed, created_at, expires_at, hits) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
            rusqlite::params![
                key_hash,
                format!("{:?}", cache_type),
                content_bytes,
                compressed_flag,
                now,
                expires_at,
            ],
        )?;
        
        drop(db);
        self.evict_if_needed()?;
        
        Ok(())
    }

    pub fn get(&self, key: &str, cache_type: CacheType) -> Result<String, CacheError> {
        let key_hash = self.hash_key(key);
        let now = Utc::now().timestamp();
        let mem_key = format!("{}:{:?}", key_hash, cache_type);
        
        // Check memory cache first
        if let Ok(mut mem_cache) = self.memory_cache.lock() {
            if let Some(entry) = mem_cache.get_mut(&mem_key) {
                if entry.expires_at > now {
                    entry.hits += 1;
                    *self.memory_hits.lock().unwrap() += 1;
                    return Ok(entry.content.clone());
                } else {
                    // Expired in memory
                    mem_cache.remove(&mem_key);
                }
            }
        }
        
        let db = self.db.lock().unwrap();
        
        let mut stmt = db.prepare(
            "SELECT content, compressed, expires_at, hits FROM cache_entries 
             WHERE key_hash = ?1 AND cache_type = ?2 AND expires_at > ?3"
        )?;

        let result = stmt.query_row(
            rusqlite::params![key_hash, format!("{:?}", cache_type), now],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i32>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, u32>(3)?,
                ))
            },
        );

        match result {
            Ok((content, compressed, _, hits)) => {
                let content_bytes = if compressed == 1 {
                    self.decompress(&content)?
                } else {
                    content
                };
                
                db.execute(
                    "UPDATE cache_entries SET hits = hits + 1 WHERE key_hash = ?1",
                    rusqlite::params![key_hash],
                )?;
                
                *self.memory_hits.lock().unwrap() += 1;
                
                let content_str = String::from_utf8(content_bytes).map_err(|_| CacheError::NotFound)?;
                
                // Store in memory cache for next time
                if let Ok(mut mem_cache) = self.memory_cache.lock() {
                    if mem_cache.len() < self.settings.max_memory_mb * 1024 {
                        mem_cache.insert(
                            mem_key.clone(),
                            MemoryCacheEntry {
                                content: content_str.clone(),
                                expires_at: now + self.settings.default_ttl_secs,
                                hits: hits + 1,
                            }
                        );
                    }
                }
                
                Ok(content_str)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                *self.memory_miss.lock().unwrap() += 1;
                Err(CacheError::NotFound)
            }
            Err(e) => {
                *self.memory_miss.lock().unwrap() += 1;
                Err(CacheError::Database(e))
            }
        }
    }

    pub fn contains(&self, key: &str, cache_type: CacheType) -> bool {
        let key_hash = self.hash_key(key);
        let now = Utc::now().timestamp();
        let mem_key = format!("{}:{:?}", key_hash, cache_type);
        
        // Check memory cache first
        if let Ok(mem_cache) = self.memory_cache.lock() {
            if let Some(entry) = mem_cache.get(&mem_key) {
                if entry.expires_at > now {
                    return true;
                }
            }
        }
        
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
        let now = Utc::now().timestamp();
        
        // Clean memory cache
        if let Ok(mut mem_cache) = self.memory_cache.lock() {
            mem_cache.retain(|_, v| v.expires_at > now);
        }
        
        // Clean disk cache
        let db = self.db.lock().unwrap();
        let deleted = db.execute(
            "DELETE FROM cache_entries WHERE expires_at < ?1",
            rusqlite::params![now],
        )?;
        Ok(deleted)
    }

    pub fn remove(&self, key: &str, cache_type: CacheType) -> Result<bool, CacheError> {
        let key_hash = self.hash_key(key);
        let mem_key = format!("{}:{:?}", key_hash, cache_type);
        
        // Remove from memory
        if let Ok(mut mem_cache) = self.memory_cache.lock() {
            mem_cache.remove(&mem_key);
        }
        
        // Remove from disk
        let db = self.db.lock().unwrap();
        let deleted = db.execute(
            "DELETE FROM cache_entries WHERE key_hash = ?1 AND cache_type = ?2",
            rusqlite::params![key_hash, format!("{:?}", cache_type)],
        )?;
        
        Ok(deleted > 0)
    }

    pub fn clear_by_type(&self, cache_type: CacheType) -> Result<usize, CacheError> {
        // Clear from memory
        if let Ok(mut mem_cache) = self.memory_cache.lock() {
            mem_cache.retain(|k, _| !k.ends_with(&format!(":{:?}", cache_type)));
        }
        
        // Clear from disk
        let db = self.db.lock().unwrap();
        let deleted = db.execute(
            "DELETE FROM cache_entries WHERE cache_type = ?1",
            rusqlite::params![format!("{:?}", cache_type)],
        )?;
        
        Ok(deleted)
    }

    pub fn stats(&self) -> CacheStats {
        let db = self.db.lock().unwrap();
        
        let total_disk_entries: i64 = db.query_row("SELECT COUNT(*) FROM cache_entries", [], |row| row.get(0)).unwrap_or(0);
        let expired_disk_entries: i64 = db.query_row(
            "SELECT COUNT(*) FROM cache_entries WHERE expires_at < ?1",
            rusqlite::params![Utc::now().timestamp()],
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

        CacheStats { 
            total_entries: total_disk_entries, 
            expired_entries: expired_disk_entries, 
            hits, 
            misses, 
            hit_rate 
        }
    }

    pub fn clear(&self) -> Result<(), CacheError> {
        // Clear memory cache
        if let Ok(mut mem_cache) = self.memory_cache.lock() {
            mem_cache.clear();
        }
        
        // Clear disk cache
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

    fn create_test_cache() -> (CacheManager, TempDir) {
        let tmp = TempDir::new().unwrap();
        let cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
        (cache, tmp)
    }

    #[test]
    fn test_cache_creation() {
        let (cache, _tmp) = create_test_cache();
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate, 0.0);
    }

    #[test]
    fn test_set_and_get() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("test_key", CacheType::Response, "test_content").unwrap();
        let content = cache.get("test_key", CacheType::Response).unwrap();
        assert_eq!(content, "test_content");
    }

    #[test]
    fn test_get_nonexistent() {
        let (cache, _tmp) = create_test_cache();
        
        let result = cache.get("nonexistent", CacheType::Response);
        assert!(matches!(result, Err(CacheError::NotFound)));
    }

    #[test]
    fn test_contains() {
        let (cache, _tmp) = create_test_cache();
        
        assert!(!cache.contains("test_key", CacheType::Response));
        
        cache.set("test_key", CacheType::Response, "content").unwrap();
        assert!(cache.contains("test_key", CacheType::Response));
        assert!(!cache.contains("test_key", CacheType::Prompt));
    }

    #[test]
    fn test_different_cache_types() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("key1", CacheType::Response, "response_data").unwrap();
        cache.set("key1", CacheType::Prompt, "prompt_data").unwrap();
        cache.set("key1", CacheType::Embedding, "embedding_data").unwrap();
        
        assert_eq!(cache.get("key1", CacheType::Response).unwrap(), "response_data");
        assert_eq!(cache.get("key1", CacheType::Prompt).unwrap(), "prompt_data");
        assert_eq!(cache.get("key1", CacheType::Embedding).unwrap(), "embedding_data");
    }

    #[test]
    fn test_expiration() {
        let (cache, _tmp) = create_test_cache();
        
        // Create a cache entry and manually set short expiration
        let key_hash = cache.hash_key("expire_key");
        let now = Utc::now().timestamp();
        let db = cache.db.lock().unwrap();
        db.execute(
            "INSERT INTO cache_entries (key_hash, cache_type, content, compressed, created_at, expires_at, hits) 
             VALUES (?1, ?2, ?3, 0, ?4, ?5, 0)",
            rusqlite::params![key_hash, format!("{:?}", CacheType::Response), "data".as_bytes(), now, now - 100],
        ).unwrap();
        drop(db);
        
        // Should not find expired entry
        let result = cache.get("expire_key", CacheType::Response);
        assert!(matches!(result, Err(CacheError::NotFound)));
        assert!(!cache.contains("expire_key", CacheType::Response));
    }

    #[test]
    fn test_cleanup_expired() {
        let (cache, _tmp) = create_test_cache();
        
        // Insert expired entry
        let key_hash = cache.hash_key("old_key");
        let now = Utc::now().timestamp();
        let db = cache.db.lock().unwrap();
        db.execute(
            "INSERT INTO cache_entries (key_hash, cache_type, content, compressed, created_at, expires_at, hits) 
             VALUES (?1, ?2, ?3, 0, ?4, ?5, 0)",
            rusqlite::params![key_hash, format!("{:?}", CacheType::Response), "old_data".as_bytes(), now - 200, now - 100],
        ).unwrap();
        
        // Insert valid entry
        db.execute(
            "INSERT INTO cache_entries (key_hash, cache_type, content, compressed, created_at, expires_at, hits) 
             VALUES (?1, ?2, ?3, 0, ?4, ?5, 0)",
            rusqlite::params![cache.hash_key("new_key"), format!("{:?}", CacheType::Response), "new_data".as_bytes(), now, now + 3600],
        ).unwrap();
        drop(db);
        
        let deleted = cache.cleanup_expired().unwrap();
        assert_eq!(deleted, 1);
        
        assert!(!cache.contains("old_key", CacheType::Response));
        assert!(cache.contains("new_key", CacheType::Response));
    }

    #[test]
    fn test_stats() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("key1", CacheType::Response, "data1").unwrap();
        cache.set("key2", CacheType::Prompt, "data2").unwrap();
        
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.expired_entries, 0);
    }

    #[test]
    fn test_hit_rate_tracking() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("key1", CacheType::Response, "data1").unwrap();
        
        // Hit
        let _ = cache.get("key1", CacheType::Response).unwrap();
        // Miss
        let _ = cache.get("nonexistent", CacheType::Response);
        
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hit_rate, 50.0);
    }

    #[test]
    fn test_clear() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("key1", CacheType::Response, "data1").unwrap();
        cache.set("key2", CacheType::Prompt, "data2").unwrap();
        
        cache.clear().unwrap();
        
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 0);
        assert!(!cache.contains("key1", CacheType::Response));
    }

    #[test]
    fn test_remove() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("key1", CacheType::Response, "data1").unwrap();
        cache.set("key2", CacheType::Response, "data2").unwrap();
        
        let removed = cache.remove("key1", CacheType::Response).unwrap();
        assert!(removed);
        assert!(!cache.contains("key1", CacheType::Response));
        assert!(cache.contains("key2", CacheType::Response));
    }

    #[test]
    fn test_clear_by_type() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("key1", CacheType::Response, "data1").unwrap();
        cache.set("key2", CacheType::Prompt, "data2").unwrap();
        cache.set("key3", CacheType::Response, "data3").unwrap();
        
        let deleted = cache.clear_by_type(CacheType::Response).unwrap();
        assert_eq!(deleted, 2);
        
        assert!(!cache.contains("key1", CacheType::Response));
        assert!(!cache.contains("key3", CacheType::Response));
        assert!(cache.contains("key2", CacheType::Prompt));
    }

    #[test]
    fn test_compression() {
        let (cache, _tmp) = create_test_cache();
        
        // Test with compression enabled (default)
        let large_content = "x".repeat(10000);
        cache.set("compressed_key", CacheType::Response, &large_content).unwrap();
        
        let retrieved = cache.get("compressed_key", CacheType::Response).unwrap();
        assert_eq!(retrieved, large_content);
    }

    #[test]
    fn test_memory_cache_hit() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("mem_key", CacheType::Response, "mem_data").unwrap();
        
        // First get should populate memory cache
        let _ = cache.get("mem_key", CacheType::Response).unwrap();
        
        // Second get should hit memory cache
        let content = cache.get("mem_key", CacheType::Response).unwrap();
        assert_eq!(content, "mem_data");
        
        let stats = cache.stats();
        assert!(stats.hits >= 1);
    }

    #[test]
    fn test_eviction_policy_lru() {
        let (mut cache, _tmp) = create_test_cache();
        cache.settings.eviction_policy = EvictionPolicy::LRU;
        cache.settings.max_disk_mb = 1; // Very small to trigger eviction
        
        // This test verifies the eviction method doesn't panic
        cache.set("key1", CacheType::Response, &"x".repeat(1000)).unwrap();
        cache.set("key2", CacheType::Response, &"x".repeat(1000)).unwrap();
    }

    #[test]
    fn test_eviction_policy_lfu() {
        let (mut cache, _tmp) = create_test_cache();
        cache.settings.eviction_policy = EvictionPolicy::LFU;
        cache.settings.max_disk_mb = 1;
        
        cache.set("key1", CacheType::Response, &"x".repeat(1000)).unwrap();
        cache.set("key2", CacheType::Response, &"x".repeat(1000)).unwrap();
        
        // Access key1 more times
        let _ = cache.get("key1", CacheType::Response);
        let _ = cache.get("key1", CacheType::Response);
    }

    #[test]
    fn test_eviction_policy_fifo() {
        let (mut cache, _tmp) = create_test_cache();
        cache.settings.eviction_policy = EvictionPolicy::FIFO;
        cache.settings.max_disk_mb = 1;
        
        cache.set("key1", CacheType::Response, &"x".repeat(1000)).unwrap();
        cache.set("key2", CacheType::Response, &"x".repeat(1000)).unwrap();
    }

    #[test]
    fn test_cache_settings_default() {
        let settings = CacheSettings::default();
        assert_eq!(settings.max_memory_mb, 100);
        assert_eq!(settings.max_disk_mb, 500);
        assert_eq!(settings.default_ttl_secs, 3600);
        assert!(settings.enable_compression);
        assert!(matches!(settings.eviction_policy, EvictionPolicy::LRU));
    }

    #[test]
    fn test_hash_key_deterministic() {
        let (cache, _tmp) = create_test_cache();
        
        let hash1 = cache.hash_key("test");
        let hash2 = cache.hash_key("test");
        let hash3 = cache.hash_key("different");
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_cache_type_serialization() {
        assert_eq!(format!("{:?}", CacheType::Response), "Response");
        assert_eq!(format!("{:?}", CacheType::Prompt), "Prompt");
        assert_eq!(format!("{:?}", CacheType::Embedding), "Embedding");
        assert_eq!(format!("{:?}", CacheType::ToolResult), "ToolResult");
    }

    #[test]
    fn test_eviction_policy_serialization() {
        assert_eq!(format!("{:?}", EvictionPolicy::LRU), "LRU");
        assert_eq!(format!("{:?}", EvictionPolicy::LFU), "LFU");
        assert_eq!(format!("{:?}", EvictionPolicy::FIFO), "FIFO");
        assert_eq!(format!("{:?}", EvictionPolicy::TTL), "TTL");
    }

    #[test]
    fn test_large_content() {
        let (cache, _tmp) = create_test_cache();
        
        let large_content = "🦀".repeat(10000); // Multi-byte characters
        cache.set("large_key", CacheType::Response, &large_content).unwrap();
        
        let retrieved = cache.get("large_key", CacheType::Response).unwrap();
        assert_eq!(retrieved, large_content);
    }

    #[test]
    fn test_special_characters() {
        let (cache, _tmp) = create_test_cache();
        
        let content = "Special chars: ñáéíóú 🦀 \n\t\\\"";
        cache.set("special_key", CacheType::Response, content).unwrap();
        
        let retrieved = cache.get("special_key", CacheType::Response).unwrap();
        assert_eq!(retrieved, content);
    }

    #[test]
    fn test_empty_string() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("empty_key", CacheType::Response, "").unwrap();
        let retrieved = cache.get("empty_key", CacheType::Response).unwrap();
        assert_eq!(retrieved, "");
    }

    #[test]
    fn test_multiple_operations() {
        let (cache, _tmp) = create_test_cache();
        
        // Perform many operations
        for i in 0..100 {
            cache.set(&format!("key{}", i), CacheType::Response, &format!("value{}", i)).unwrap();
        }
        
        for i in 0..100 {
            let content = cache.get(&format!("key{}", i), CacheType::Response).unwrap();
            assert_eq!(content, format!("value{}", i));
        }
        
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 100);
    }

    #[test]
    fn test_overwrite_existing_key() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("key", CacheType::Response, "version1").unwrap();
        cache.set("key", CacheType::Response, "version2").unwrap();
        
        let content = cache.get("key", CacheType::Response).unwrap();
        assert_eq!(content, "version2");
    }

    #[test]
    fn test_memory_cache_expired() {
        let (cache, _tmp) = create_test_cache();
        
        // Insert directly into memory cache with expired timestamp
        let key_hash = cache.hash_key("expired_mem");
        let mem_key = format!("{}:{:?}", key_hash, CacheType::Response);
        if let Ok(mut mem_cache) = cache.memory_cache.lock() {
            mem_cache.insert(mem_key, MemoryCacheEntry {
                content: "old".to_string(),
                expires_at: Utc::now().timestamp() - 100,
                hits: 0,
            });
        }
        
        // Should not return expired from memory
        let result = cache.get("expired_mem", CacheType::Response);
        assert!(matches!(result, Err(CacheError::NotFound)));
    }

    #[test]
    fn test_invalid_utf8_in_cache() {
        let (cache, _tmp) = create_test_cache();
        
        // Insert invalid UTF-8 bytes directly into DB
        let key_hash = cache.hash_key("bad_utf8");
        let db = cache.db.lock().unwrap();
        db.execute(
            "INSERT INTO cache_entries (key_hash, cache_type, content, compressed, created_at, expires_at, hits) 
             VALUES (?1, ?2, ?3, 0, ?4, ?5, 0)",
            rusqlite::params![
                key_hash, 
                format!("{:?}", CacheType::Response), 
                vec![0xFFu8, 0xFEu8, 0xFDu8], // Invalid UTF-8
                Utc::now().timestamp(),
                Utc::now().timestamp() + 3600
            ],
        ).unwrap();
        drop(db);
        
        let result = cache.get("bad_utf8", CacheType::Response);
        assert!(matches!(result, Err(CacheError::NotFound)));
    }

    #[test]
    fn test_compression_disabled() {
        let tmp = TempDir::new().unwrap();
        let mut cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
        cache.settings.enable_compression = false;
        
        cache.set("key", CacheType::Response, "test_data").unwrap();
        let content = cache.get("key", CacheType::Response).unwrap();
        assert_eq!(content, "test_data");
    }

    #[test]
    fn test_evict_if_needed_disk_lru() {
        let tmp = TempDir::new().unwrap();
        let mut cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
        cache.settings.max_disk_mb = 0; // Force eviction
        cache.settings.eviction_policy = EvictionPolicy::LRU;
        
        // Insert several entries to trigger eviction
        for i in 0..5 {
            cache.set(&format!("key{}", i), CacheType::Response, &"x".repeat(1000)).unwrap();
        }
    }

    #[test]
    fn test_evict_if_needed_disk_lfu() {
        let tmp = TempDir::new().unwrap();
        let mut cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
        cache.settings.max_disk_mb = 0; // Force eviction
        cache.settings.eviction_policy = EvictionPolicy::LFU;
        
        for i in 0..5 {
            cache.set(&format!("key{}", i), CacheType::Response, &"x".repeat(1000)).unwrap();
        }
    }

    #[test]
    fn test_evict_if_needed_disk_fifo() {
        let tmp = TempDir::new().unwrap();
        let mut cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
        cache.settings.max_disk_mb = 0; // Force eviction
        cache.settings.eviction_policy = EvictionPolicy::FIFO;
        
        for i in 0..5 {
            cache.set(&format!("key{}", i), CacheType::Response, &"x".repeat(1000)).unwrap();
        }
    }

    #[test]
    fn test_evict_if_needed_disk_ttl() {
        let tmp = TempDir::new().unwrap();
        let mut cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
        cache.settings.max_disk_mb = 0; // Force eviction
        cache.settings.eviction_policy = EvictionPolicy::TTL;
        
        for i in 0..5 {
            cache.set(&format!("key{}", i), CacheType::Response, &"x".repeat(1000)).unwrap();
        }
    }

    #[test]
    fn test_memory_eviction() {
        let tmp = TempDir::new().unwrap();
        let mut cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
        cache.settings.max_memory_mb = 0; // Force memory eviction
        
        cache.set("key1", CacheType::Response, "value1").unwrap();
        // Should trigger memory eviction
        cache.set("key2", CacheType::Response, "value2").unwrap();
    }

    #[test]
    fn test_remove_nonexistent() {
        let (cache, _tmp) = create_test_cache();
        
        let removed = cache.remove("nonexistent", CacheType::Response).unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_clear_by_type_empty() {
        let (cache, _tmp) = create_test_cache();
        
        let deleted = cache.clear_by_type(CacheType::Response).unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn test_hit_miss_tracking_multiple() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("key1", CacheType::Response, "val1").unwrap();
        
        // Multiple hits
        let _ = cache.get("key1", CacheType::Response);
        let _ = cache.get("key1", CacheType::Response);
        let _ = cache.get("key1", CacheType::Response);
        
        // Multiple misses
        let _ = cache.get("miss1", CacheType::Response);
        let _ = cache.get("miss2", CacheType::Response);
        
        let stats = cache.stats();
        // Hits should be at least 3 (can be more if memory cache works)
        assert!(stats.hits >= 3);
        assert_eq!(stats.misses, 2);
        // Hit rate should be >= 60% (3/(3+2)=60%)
        assert!(stats.hit_rate >= 60.0);
    }

    #[test]
    fn test_set_get_different_types_same_key() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("same_key", CacheType::Response, "response").unwrap();
        cache.set("same_key", CacheType::Prompt, "prompt").unwrap();
        
        assert_eq!(cache.get("same_key", CacheType::Response).unwrap(), "response");
        assert_eq!(cache.get("same_key", CacheType::Prompt).unwrap(), "prompt");
    }

    #[test]
    fn test_contains_expired() {
        let (cache, _tmp) = create_test_cache();
        
        // Insert expired entry directly
        let key_hash = cache.hash_key("expired");
        let db = cache.db.lock().unwrap();
        db.execute(
            "INSERT INTO cache_entries (key_hash, cache_type, content, compressed, created_at, expires_at, hits) 
             VALUES (?1, ?2, ?3, 0, ?4, ?5, 0)",
            rusqlite::params![
                key_hash, 
                format!("{:?}", CacheType::Response), 
                "data".as_bytes(),
                Utc::now().timestamp() - 200,
                Utc::now().timestamp() - 100
            ],
        ).unwrap();
        drop(db);
        
        assert!(!cache.contains("expired", CacheType::Response));
    }

    #[test]
    fn test_cache_with_empty_content() {
        let (cache, _tmp) = create_test_cache();
        
        cache.set("empty", CacheType::Response, "").unwrap();
        let content = cache.get("empty", CacheType::Response).unwrap();
        assert_eq!(content, "");
    }

    #[test]
    fn test_unicode_content() {
        let (cache, _tmp) = create_test_cache();
        
        let content = "🦀🇻🇪 Rust en Venezuela 🚀";
        cache.set("unicode", CacheType::Response, content).unwrap();
        let retrieved = cache.get("unicode", CacheType::Response).unwrap();
        assert_eq!(retrieved, content);
    }

    #[test]
    fn test_newline_content() {
        let (cache, _tmp) = create_test_cache();
        
        let content = "Line 1\nLine 2\nLine 3";
        cache.set("multiline", CacheType::Response, content).unwrap();
        let retrieved = cache.get("multiline", CacheType::Response).unwrap();
        assert_eq!(retrieved, content);
    }

    #[test]
    fn test_tab_content() {
        let (cache, _tmp) = create_test_cache();
        
        let content = "Column1\tColumn2\tColumn3";
        cache.set("tabs", CacheType::Response, content).unwrap();
        let retrieved = cache.get("tabs", CacheType::Response).unwrap();
        assert_eq!(retrieved, content);
    }

    #[test]
    fn test_eviction_policy_ttl() {
        let tmp = TempDir::new().unwrap();
        let mut cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
        cache.settings.eviction_policy = EvictionPolicy::TTL;
        cache.settings.max_disk_mb = 0; // Force eviction
        
        cache.set("key1", CacheType::Response, "data1").unwrap();
        cache.set("key2", CacheType::Response, "data2").unwrap();
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;
        use std::sync::Arc;
        
        let tmp = TempDir::new().unwrap();
        let cache = Arc::new(CacheManager::new(tmp.path().to_path_buf()).unwrap());
        
        let mut handles = vec![];
        for i in 0..5 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                cache_clone.set(&format!("key{}", i), CacheType::Response, &format!("value{}", i)).unwrap();
                let _ = cache_clone.get(&format!("key{}", i), CacheType::Response);
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let stats = cache.stats();
        assert!(stats.total_entries >= 5);
    }
}