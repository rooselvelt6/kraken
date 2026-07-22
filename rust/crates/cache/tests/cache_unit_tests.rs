use cache::*;
use tempfile::TempDir;

fn create_test_cache() -> (CacheManager, TempDir) {
    let tmp = TempDir::new().unwrap();
    let cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
    (cache, tmp)
}

// ── CacheError ──

#[test]
fn cache_error_not_found_display() {
    assert_eq!(format!("{}", CacheError::NotFound), "Not found");
}

#[test]
fn cache_error_expired_display() {
    assert_eq!(format!("{}", CacheError::Expired), "Expired");
}

#[test]
fn cache_error_compression_display() {
    let e = CacheError::Compression("test".to_string());
    assert!(format!("{}", e).contains("Compression error"));
}

#[test]
fn cache_error_debug() {
    let d = format!("{:?}", CacheError::NotFound);
    assert!(d.contains("NotFound"));
}

#[test]
fn cache_error_debug_compression() {
    let d = format!("{:?}", CacheError::Compression("x".to_string()));
    assert!(d.contains("Compression"));
}

// ── CacheLevel ──

#[test]
fn cache_level_equality() {
    assert_eq!(CacheLevel::Memory, CacheLevel::Memory);
    assert_ne!(CacheLevel::Memory, CacheLevel::Disk);
}

#[test]
fn cache_level_clone() {
    let l = CacheLevel::Memory;
    let l2 = l;
    assert_eq!(l, l2);
}

#[test]
fn cache_level_debug() {
    assert_eq!(format!("{:?}", CacheLevel::Memory), "Memory");
    assert_eq!(format!("{:?}", CacheLevel::Disk), "Disk");
}

#[test]
fn cache_level_serde_roundtrip() {
    for lvl in [CacheLevel::Memory, CacheLevel::Disk] {
        let json = serde_json::to_string(&lvl).unwrap();
        let back: CacheLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(lvl, back);
    }
}

#[test]
fn cache_level_copy() {
    let l = CacheLevel::Disk;
    let l2 = l;
    assert_eq!(l, l2);
}

// ── CacheType ──

#[test]
fn cache_type_as_str_response() {
    assert_eq!(CacheType::Response.as_str(), "Response");
}

#[test]
fn cache_type_as_str_prompt() {
    assert_eq!(CacheType::Prompt.as_str(), "Prompt");
}

#[test]
fn cache_type_as_str_embedding() {
    assert_eq!(CacheType::Embedding.as_str(), "Embedding");
}

#[test]
fn cache_type_as_str_tool_result() {
    assert_eq!(CacheType::ToolResult.as_str(), "ToolResult");
}

#[test]
fn cache_type_equality() {
    assert_eq!(CacheType::Response, CacheType::Response);
    assert_ne!(CacheType::Response, CacheType::Prompt);
    assert_ne!(CacheType::Embedding, CacheType::ToolResult);
}

#[test]
fn cache_type_clone() {
    let t = CacheType::Embedding;
    let t2 = t;
    assert_eq!(t, t2);
}

#[test]
fn cache_type_debug() {
    assert_eq!(format!("{:?}", CacheType::Response), "Response");
    assert_eq!(format!("{:?}", CacheType::ToolResult), "ToolResult");
}

#[test]
fn cache_type_serde_roundtrip() {
    for ct in [CacheType::Response, CacheType::Prompt, CacheType::Embedding, CacheType::ToolResult] {
        let json = serde_json::to_string(&ct).unwrap();
        let back: CacheType = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, back);
    }
}

#[test]
fn cache_type_copy() {
    let t = CacheType::ToolResult;
    let t2 = t;
    assert_eq!(t, t2);
}

// ── CacheEntry ──

#[test]
fn cache_entry_fields() {
    let e = CacheEntry {
        key_hash: "abc".to_string(), cache_type: CacheType::Response,
        content: "data".to_string(), compressed: false,
        created_at: 1000, expires_at: 2000, hits: 5,
    };
    assert_eq!(e.key_hash, "abc");
    assert_eq!(e.hits, 5);
    assert!(!e.compressed);
}

#[test]
fn cache_entry_clone() {
    let e = CacheEntry {
        key_hash: "k".to_string(), cache_type: CacheType::Prompt,
        content: "c".to_string(), compressed: true,
        created_at: 0, expires_at: 0, hits: 0,
    };
    let e2 = e.clone();
    assert_eq!(e.key_hash, e2.key_hash);
    assert_eq!(e.compressed, e2.compressed);
}

#[test]
fn cache_entry_debug() {
    let e = CacheEntry {
        key_hash: "k".to_string(), cache_type: CacheType::Response,
        content: String::new(), compressed: false,
        created_at: 0, expires_at: 0, hits: 0,
    };
    assert!(format!("{:?}", e).contains("CacheEntry"));
}

#[test]
fn cache_entry_serde_roundtrip() {
    let e = CacheEntry {
        key_hash: "h".to_string(), cache_type: CacheType::ToolResult,
        content: "data".to_string(), compressed: true,
        created_at: 100, expires_at: 200, hits: 10,
    };
    let json = serde_json::to_string(&e).unwrap();
    let e2: CacheEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e.key_hash, e2.key_hash);
    assert_eq!(e.hits, e2.hits);
    assert_eq!(e.compressed, e2.compressed);
}

#[test]
fn cache_entry_serde_json_value() {
    let e = CacheEntry {
        key_hash: "x".to_string(), cache_type: CacheType::Response,
        content: "v".to_string(), compressed: false,
        created_at: 1, expires_at: 2, hits: 3,
    };
    let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
    assert_eq!(v["key_hash"], "x");
    assert_eq!(v["hits"], 3);
}

// ── EvictionPolicy ──

#[test]
fn eviction_policy_default_is_lru() {
    assert!(matches!(EvictionPolicy::default(), EvictionPolicy::LRU));
}

#[test]
fn eviction_policy_variants() {
    assert!(matches!(EvictionPolicy::LRU, EvictionPolicy::LRU));
    assert!(matches!(EvictionPolicy::LFU, EvictionPolicy::LFU));
    assert!(matches!(EvictionPolicy::FIFO, EvictionPolicy::FIFO));
    assert!(matches!(EvictionPolicy::TTL, EvictionPolicy::TTL));
}

#[test]
fn eviction_policy_equality() {
    assert_eq!(EvictionPolicy::LRU, EvictionPolicy::LRU);
    assert_ne!(EvictionPolicy::LRU, EvictionPolicy::LFU);
    assert_ne!(EvictionPolicy::FIFO, EvictionPolicy::TTL);
}

#[test]
fn eviction_policy_clone() {
    let p = EvictionPolicy::LFU;
    let p2 = p;
    assert_eq!(p, p2);
}

#[test]
fn eviction_policy_debug() {
    assert_eq!(format!("{:?}", EvictionPolicy::LRU), "LRU");
    assert_eq!(format!("{:?}", EvictionPolicy::FIFO), "FIFO");
}

#[test]
fn eviction_policy_serde_roundtrip() {
    for p in [EvictionPolicy::LRU, EvictionPolicy::LFU, EvictionPolicy::FIFO, EvictionPolicy::TTL] {
        let json = serde_json::to_string(&p).unwrap();
        let back: EvictionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

#[test]
fn eviction_policy_copy() {
    let p = EvictionPolicy::FIFO;
    let p2 = p;
    assert_eq!(p, p2);
}

// ── CacheSettings ──

#[test]
fn cache_settings_default_max_memory() {
    assert_eq!(CacheSettings::default().max_memory_mb, 100);
}

#[test]
fn cache_settings_default_max_disk() {
    assert_eq!(CacheSettings::default().max_disk_mb, 500);
}

#[test]
fn cache_settings_default_ttl() {
    assert_eq!(CacheSettings::default().default_ttl_secs, 3600);
}

#[test]
fn cache_settings_default_compression() {
    assert!(CacheSettings::default().enable_compression);
}

#[test]
fn cache_settings_default_eviction() {
    assert!(matches!(CacheSettings::default().eviction_policy, EvictionPolicy::LRU));
}

#[test]
fn cache_settings_clone() {
    let s = CacheSettings::default();
    let s2 = s.clone();
    assert_eq!(s.max_memory_mb, s2.max_memory_mb);
    assert_eq!(s.max_disk_mb, s2.max_disk_mb);
    assert_eq!(s.default_ttl_secs, s2.default_ttl_secs);
    assert_eq!(s.enable_compression, s2.enable_compression);
    assert_eq!(s.eviction_policy, s2.eviction_policy);
}

#[test]
fn cache_settings_debug() {
    assert!(format!("{:?}", CacheSettings::default()).contains("CacheSettings"));
}

#[test]
fn cache_settings_serde_roundtrip() {
    let s = CacheSettings {
        max_memory_mb: 200, max_disk_mb: 1000, default_ttl_secs: 7200,
        enable_compression: false, eviction_policy: EvictionPolicy::LFU,
    };
    let json = serde_json::to_string(&s).unwrap();
    let s2: CacheSettings = serde_json::from_str(&json).unwrap();
    assert_eq!(s.max_memory_mb, s2.max_memory_mb);
    assert_eq!(s.eviction_policy, s2.eviction_policy);
    assert!(!s2.enable_compression);
}

// ── CacheManager::new ──

#[test]
fn cache_manager_new_creates_db() {
    let (cache, _tmp) = create_test_cache();
    let stats = cache.stats();
    assert_eq!(stats.total_entries, 0);
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
    assert_eq!(stats.hit_rate, 0.0);
}

// ── hash_key ──

#[test]
fn cache_hash_key_deterministic() {
    let (cache, _tmp) = create_test_cache();
    let h1 = cache.hash_key("test");
    let h2 = cache.hash_key("test");
    assert_eq!(h1, h2);
}

#[test]
fn cache_hash_key_different() {
    let (cache, _tmp) = create_test_cache();
    let h1 = cache.hash_key("key1");
    let h2 = cache.hash_key("key2");
    assert_ne!(h1, h2);
}

#[test]
fn cache_hash_key_length() {
    let (cache, _tmp) = create_test_cache();
    assert_eq!(cache.hash_key("anything").len(), 64);
}

#[test]
fn cache_hash_key_empty() {
    let (cache, _tmp) = create_test_cache();
    assert_eq!(cache.hash_key("").len(), 64);
}

// ── set + get ──

#[test]
fn cache_set_and_get_response() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    assert_eq!(cache.get("k", CacheType::Response).unwrap(), "v");
}

#[test]
fn cache_set_and_get_prompt() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Prompt, "prompt_data").unwrap();
    assert_eq!(cache.get("k", CacheType::Prompt).unwrap(), "prompt_data");
}

#[test]
fn cache_set_and_get_embedding() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Embedding, "emb").unwrap();
    assert_eq!(cache.get("k", CacheType::Embedding).unwrap(), "emb");
}

#[test]
fn cache_set_and_get_tool_result() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::ToolResult, "result").unwrap();
    assert_eq!(cache.get("k", CacheType::ToolResult).unwrap(), "result");
}

#[test]
fn cache_get_nonexistent() {
    let (cache, _tmp) = create_test_cache();
    assert!(matches!(cache.get("missing", CacheType::Response), Err(CacheError::NotFound)));
}

#[test]
fn cache_overwrite_key() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v1").unwrap();
    cache.set("k", CacheType::Response, "v2").unwrap();
    assert_eq!(cache.get("k", CacheType::Response).unwrap(), "v2");
}

#[test]
fn cache_same_key_different_types() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "r").unwrap();
    cache.set("k", CacheType::Prompt, "p").unwrap();
    cache.set("k", CacheType::Embedding, "e").unwrap();
    cache.set("k", CacheType::ToolResult, "t").unwrap();
    assert_eq!(cache.get("k", CacheType::Response).unwrap(), "r");
    assert_eq!(cache.get("k", CacheType::Prompt).unwrap(), "p");
    assert_eq!(cache.get("k", CacheType::Embedding).unwrap(), "e");
    assert_eq!(cache.get("k", CacheType::ToolResult).unwrap(), "t");
}

// ── contains ──

#[test]
fn cache_contains_after_set() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    assert!(cache.contains("k", CacheType::Response));
}

#[test]
fn cache_contains_wrong_type() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    assert!(!cache.contains("k", CacheType::Prompt));
}

#[test]
fn cache_contains_nonexistent() {
    let (cache, _tmp) = create_test_cache();
    assert!(!cache.contains("missing", CacheType::Response));
}

// ── remove ──

#[test]
fn cache_remove_existing() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    assert!(cache.remove("k", CacheType::Response).unwrap());
    assert!(!cache.contains("k", CacheType::Response));
}

#[test]
fn cache_remove_nonexistent() {
    let (cache, _tmp) = create_test_cache();
    assert!(!cache.remove("missing", CacheType::Response).unwrap());
}

#[test]
fn cache_remove_does_not_affect_other_type() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "r").unwrap();
    cache.set("k", CacheType::Prompt, "p").unwrap();
    cache.remove("k", CacheType::Response).unwrap();
    assert!(!cache.contains("k", CacheType::Response));
    assert!(cache.contains("k", CacheType::Prompt));
}

#[test]
fn cache_get_after_remove() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    cache.remove("k", CacheType::Response).unwrap();
    assert!(matches!(cache.get("k", CacheType::Response), Err(CacheError::NotFound)));
}

// ── clear ──

#[test]
fn cache_clear() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k1", CacheType::Response, "v1").unwrap();
    cache.set("k2", CacheType::Prompt, "v2").unwrap();
    cache.clear().unwrap();
    assert_eq!(cache.stats().total_entries, 0);
}

#[test]
fn cache_clear_removes_contains() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    cache.clear().unwrap();
    assert!(!cache.contains("k", CacheType::Response));
}

// ── clear_by_type ──

#[test]
fn cache_clear_by_type() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k1", CacheType::Response, "r").unwrap();
    cache.set("k2", CacheType::Prompt, "p").unwrap();
    cache.set("k3", CacheType::Response, "r2").unwrap();
    let deleted = cache.clear_by_type(CacheType::Response).unwrap();
    assert_eq!(deleted, 2);
    assert!(!cache.contains("k1", CacheType::Response));
    assert!(!cache.contains("k3", CacheType::Response));
    assert!(cache.contains("k2", CacheType::Prompt));
}

#[test]
fn cache_clear_by_type_empty() {
    let (cache, _tmp) = create_test_cache();
    assert_eq!(cache.clear_by_type(CacheType::Response).unwrap(), 0);
}

// ── cleanup_expired ──

#[test]
fn cache_cleanup_expired_no_expired() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    let deleted = cache.cleanup_expired().unwrap();
    assert_eq!(deleted, 0);
    assert!(cache.contains("k", CacheType::Response));
}

// ── stats ──

#[test]
fn cache_stats_empty() {
    let (cache, _tmp) = create_test_cache();
    let s = cache.stats();
    assert_eq!(s.total_entries, 0);
    assert_eq!(s.expired_entries, 0);
    assert_eq!(s.hits, 0);
    assert_eq!(s.misses, 0);
    assert_eq!(s.hit_rate, 0.0);
}

#[test]
fn cache_stats_after_set() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k1", CacheType::Response, "v1").unwrap();
    cache.set("k2", CacheType::Prompt, "v2").unwrap();
    let s = cache.stats();
    assert_eq!(s.total_entries, 2);
    assert_eq!(s.expired_entries, 0);
}

#[test]
fn cache_stats_hit_rate() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    let _ = cache.get("k", CacheType::Response).unwrap();
    let _ = cache.get("miss", CacheType::Response);
    let s = cache.stats();
    assert_eq!(s.hits, 1);
    assert_eq!(s.misses, 1);
    assert_eq!(s.hit_rate, 50.0);
}

#[test]
fn cache_stats_hit_rate_all_hits() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    let _ = cache.get("k", CacheType::Response);
    let _ = cache.get("k", CacheType::Response);
    let s = cache.stats();
    assert!(s.hits >= 2);
    assert_eq!(s.hit_rate, 100.0);
}

#[test]
fn cache_stats_hit_rate_all_misses() {
    let (cache, _tmp) = create_test_cache();
    let _ = cache.get("m1", CacheType::Response);
    let _ = cache.get("m2", CacheType::Response);
    let s = cache.stats();
    assert_eq!(s.hit_rate, 0.0);
}

// ── CacheStats ──

#[test]
fn cache_stats_fields() {
    let s = CacheStats {
        total_entries: 10, expired_entries: 2, hits: 8, misses: 4, hit_rate: 66.7,
    };
    assert_eq!(s.total_entries, 10);
    assert_eq!(s.expired_entries, 2);
    assert_eq!(s.hits, 8);
    assert_eq!(s.misses, 4);
    assert!((s.hit_rate - 66.7).abs() < 0.1);
}

#[test]
fn cache_stats_clone() {
    let s = CacheStats {
        total_entries: 1, expired_entries: 0, hits: 5, misses: 2, hit_rate: 71.4,
    };
    let s2 = s.clone();
    assert_eq!(s.total_entries, s2.total_entries);
    assert_eq!(s.hit_rate, s2.hit_rate);
}

#[test]
fn cache_stats_debug() {
    let s = CacheStats {
        total_entries: 0, expired_entries: 0, hits: 0, misses: 0, hit_rate: 0.0,
    };
    assert!(format!("{:?}", s).contains("CacheStats"));
}

#[test]
fn cache_stats_serde_roundtrip() {
    let s = CacheStats {
        total_entries: 42, expired_entries: 3, hits: 100, misses: 50, hit_rate: 66.67,
    };
    let json = serde_json::to_string(&s).unwrap();
    let s2: CacheStats = serde_json::from_str(&json).unwrap();
    assert_eq!(s.total_entries, s2.total_entries);
    assert_eq!(s.hit_rate, s2.hit_rate);
}

// ── Content variations ──

#[test]
fn cache_empty_string() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "").unwrap();
    assert_eq!(cache.get("k", CacheType::Response).unwrap(), "");
}

#[test]
fn cache_unicode_content() {
    let (cache, _tmp) = create_test_cache();
    let content = "Rust en Venezuela";
    cache.set("k", CacheType::Response, content).unwrap();
    assert_eq!(cache.get("k", CacheType::Response).unwrap(), content);
}

#[test]
fn cache_special_characters() {
    let (cache, _tmp) = create_test_cache();
    let content = "Line1\nLine2\tTab\\Quote\"";
    cache.set("k", CacheType::Response, content).unwrap();
    assert_eq!(cache.get("k", CacheType::Response).unwrap(), content);
}

#[test]
fn cache_large_content() {
    let (cache, _tmp) = create_test_cache();
    let large = "x".repeat(100000);
    cache.set("k", CacheType::Response, &large).unwrap();
    let v = cache.get("k", CacheType::Response).unwrap();
    assert_eq!(v.len(), 100000);
    assert_eq!(v, large);
}

// ── Many operations ──

#[test]
fn cache_many_operations() {
    let (cache, _tmp) = create_test_cache();
    for i in 0..100 {
        cache.set(&format!("k{}", i), CacheType::Response, &format!("v{}", i)).unwrap();
    }
    for i in 0..100 {
        let v = cache.get(&format!("k{}", i), CacheType::Response).unwrap();
        assert_eq!(v, format!("v{}", i));
    }
    assert_eq!(cache.stats().total_entries, 100);
}

#[test]
fn cache_set_get_multiple_keys() {
    let (cache, _tmp) = create_test_cache();
    for i in 0..50 {
        cache.set(&format!("key_{}", i), CacheType::Response, &format!("val_{}", i)).unwrap();
    }
    for i in 0..50 {
        let v = cache.get(&format!("key_{}", i), CacheType::Response).unwrap();
        assert_eq!(v, format!("val_{}", i));
    }
}

#[test]
fn cache_clear_all_then_stats() {
    let (cache, _tmp) = create_test_cache();
    for i in 0..10 {
        cache.set(&format!("k{}", i), CacheType::Response, "v").unwrap();
    }
    cache.clear().unwrap();
    let s = cache.stats();
    assert_eq!(s.total_entries, 0);
}

#[test]
fn cache_contains_after_multiple_sets() {
    let (cache, _tmp) = create_test_cache();
    cache.set("a", CacheType::Response, "1").unwrap();
    cache.set("b", CacheType::Response, "2").unwrap();
    cache.set("c", CacheType::Response, "3").unwrap();
    assert!(cache.contains("a", CacheType::Response));
    assert!(cache.contains("b", CacheType::Response));
    assert!(cache.contains("c", CacheType::Response));
}

#[test]
fn cache_remove_middle_key() {
    let (cache, _tmp) = create_test_cache();
    cache.set("a", CacheType::Response, "1").unwrap();
    cache.set("b", CacheType::Response, "2").unwrap();
    cache.set("c", CacheType::Response, "3").unwrap();
    cache.remove("b", CacheType::Response).unwrap();
    assert!(cache.contains("a", CacheType::Response));
    assert!(!cache.contains("b", CacheType::Response));
    assert!(cache.contains("c", CacheType::Response));
}

#[test]
fn cache_remove_all_types_same_key() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "r").unwrap();
    cache.set("k", CacheType::Prompt, "p").unwrap();
    cache.set("k", CacheType::Embedding, "e").unwrap();
    cache.remove("k", CacheType::Response).unwrap();
    cache.remove("k", CacheType::Prompt).unwrap();
    cache.remove("k", CacheType::Embedding).unwrap();
    assert!(!cache.contains("k", CacheType::Response));
    assert!(!cache.contains("k", CacheType::Prompt));
    assert!(!cache.contains("k", CacheType::Embedding));
    assert!(!cache.contains("k", CacheType::ToolResult));
}

// ── Compression ──

#[test]
fn cache_compression_roundtrip() {
    let (cache, _tmp) = create_test_cache();
    let large = "x".repeat(10000);
    cache.set("big", CacheType::Response, &large).unwrap();
    let got = cache.get("big", CacheType::Response).unwrap();
    assert_eq!(got, large);
}

#[test]
fn cache_compression_repetitive_data() {
    let (cache, _tmp) = create_test_cache();
    let data = "abcde".repeat(5000);
    cache.set("k", CacheType::Response, &data).unwrap();
    assert_eq!(cache.get("k", CacheType::Response).unwrap(), data);
}

// ── Multiple hits tracking ──

#[test]
fn cache_hit_miss_tracking_multiple() {
    let (cache, _tmp) = create_test_cache();
    cache.set("key1", CacheType::Response, "val1").unwrap();
    let _ = cache.get("key1", CacheType::Response);
    let _ = cache.get("key1", CacheType::Response);
    let _ = cache.get("key1", CacheType::Response);
    let _ = cache.get("miss1", CacheType::Response);
    let _ = cache.get("miss2", CacheType::Response);
    let stats = cache.stats();
    assert!(stats.hits >= 3);
    assert_eq!(stats.misses, 2);
    assert!(stats.hit_rate >= 60.0);
}

// ── Concurrent access ──

#[test]
fn cache_concurrent_access() {
    use std::sync::Arc;
    use std::thread;
    let tmp = TempDir::new().unwrap();
    let cache = Arc::new(CacheManager::new(tmp.path().to_path_buf()).unwrap());
    let mut handles = vec![];
    for i in 0..5 {
        let c = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            c.set(&format!("k{}", i), CacheType::Response, &format!("v{}", i)).unwrap();
            let _ = c.get(&format!("k{}", i), CacheType::Response);
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert!(cache.stats().total_entries >= 5);
}

#[test]
fn cache_concurrent_reads() {
    use std::sync::Arc;
    use std::thread;
    let tmp = TempDir::new().unwrap();
    let cache = Arc::new(CacheManager::new(tmp.path().to_path_buf()).unwrap());
    cache.set("shared", CacheType::Response, "data").unwrap();
    let mut handles = vec![];
    for _ in 0..5 {
        let c = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            let v = c.get("shared", CacheType::Response).unwrap();
            assert_eq!(v, "data");
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ── Serde invalid inputs ──

#[test]
fn cache_settings_serde_invalid() {
    assert!(serde_json::from_str::<CacheSettings>("null").is_err());
}

#[test]
fn cache_entry_serde_invalid() {
    assert!(serde_json::from_str::<CacheEntry>("null").is_err());
}

#[test]
fn cache_stats_serde_invalid() {
    assert!(serde_json::from_str::<CacheStats>("null").is_err());
}

#[test]
fn cache_level_serde_invalid() {
    assert!(serde_json::from_str::<CacheLevel>("\"Invalid\"").is_err());
}

#[test]
fn cache_type_serde_invalid() {
    assert!(serde_json::from_str::<CacheType>("\"Unknown\"").is_err());
}

#[test]
fn eviction_policy_serde_invalid() {
    assert!(serde_json::from_str::<EvictionPolicy>("\"Random\"").is_err());
}
