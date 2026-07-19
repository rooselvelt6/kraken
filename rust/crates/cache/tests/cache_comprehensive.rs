use cache::*;
use tempfile::TempDir;

fn create_test_cache() -> (CacheManager, TempDir) {
    let tmp = TempDir::new().unwrap();
    let cache = CacheManager::new(tmp.path().to_path_buf()).unwrap();
    (cache, tmp)
}

#[test]
fn cache_creation_stats_zero() {
    let (cache, _tmp) = create_test_cache();
    let stats = cache.stats();
    assert_eq!(stats.total_entries, 0);
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
}

#[test]
fn cache_set_and_get() {
    let (cache, _tmp) = create_test_cache();
    cache.set("key1", CacheType::Response, "value1").unwrap();
    assert_eq!(cache.get("key1", CacheType::Response).unwrap(), "value1");
}

#[test]
fn cache_get_nonexistent() {
    let (cache, _tmp) = create_test_cache();
    assert!(matches!(cache.get("missing", CacheType::Response), Err(CacheError::NotFound)));
}

#[test]
fn cache_contains_after_set() {
    let (cache, _tmp) = create_test_cache();
    cache.set("key", CacheType::Response, "val").unwrap();
    assert!(cache.contains("key", CacheType::Response));
}

#[test]
fn cache_contains_wrong_type() {
    let (cache, _tmp) = create_test_cache();
    cache.set("key", CacheType::Response, "val").unwrap();
    assert!(!cache.contains("key", CacheType::Prompt));
}

#[test]
fn cache_contains_nonexistent() {
    let (cache, _tmp) = create_test_cache();
    assert!(!cache.contains("missing", CacheType::Response));
}

#[test]
fn cache_different_types_same_key() {
    let (cache, _tmp) = create_test_cache();
    cache.set("key", CacheType::Response, "resp").unwrap();
    cache.set("key", CacheType::Prompt, "prompt").unwrap();
    cache.set("key", CacheType::Embedding, "embed").unwrap();
    cache.set("key", CacheType::ToolResult, "tool").unwrap();
    assert_eq!(cache.get("key", CacheType::Response).unwrap(), "resp");
    assert_eq!(cache.get("key", CacheType::Prompt).unwrap(), "prompt");
    assert_eq!(cache.get("key", CacheType::Embedding).unwrap(), "embed");
    assert_eq!(cache.get("key", CacheType::ToolResult).unwrap(), "tool");
}

#[test]
fn cache_overwrite() {
    let (cache, _tmp) = create_test_cache();
    cache.set("key", CacheType::Response, "v1").unwrap();
    cache.set("key", CacheType::Response, "v2").unwrap();
    assert_eq!(cache.get("key", CacheType::Response).unwrap(), "v2");
}

#[test]
fn cache_remove() {
    let (cache, _tmp) = create_test_cache();
    cache.set("key", CacheType::Response, "val").unwrap();
    assert!(cache.remove("key", CacheType::Response).unwrap());
    assert!(!cache.contains("key", CacheType::Response));
}

#[test]
fn cache_remove_nonexistent() {
    let (cache, _tmp) = create_test_cache();
    assert!(!cache.remove("missing", CacheType::Response).unwrap());
}

#[test]
fn cache_clear() {
    let (cache, _tmp) = create_test_cache();
    cache.set("a", CacheType::Response, "1").unwrap();
    cache.set("b", CacheType::Prompt, "2").unwrap();
    cache.clear().unwrap();
    assert_eq!(cache.stats().total_entries, 0);
}

#[test]
fn cache_clear_by_type() {
    let (cache, _tmp) = create_test_cache();
    cache.set("a", CacheType::Response, "1").unwrap();
    cache.set("b", CacheType::Prompt, "2").unwrap();
    cache.set("c", CacheType::Response, "3").unwrap();
    let deleted = cache.clear_by_type(CacheType::Response).unwrap();
    assert_eq!(deleted, 2);
    assert!(!cache.contains("a", CacheType::Response));
    assert!(!cache.contains("c", CacheType::Response));
    assert!(cache.contains("b", CacheType::Prompt));
}

#[test]
fn cache_clear_by_type_empty() {
    let (cache, _tmp) = create_test_cache();
    let deleted = cache.clear_by_type(CacheType::Response).unwrap();
    assert_eq!(deleted, 0);
}

#[test]
fn cache_hit_rate() {
    let (cache, _tmp) = create_test_cache();
    cache.set("key", CacheType::Response, "val").unwrap();
    let _ = cache.get("key", CacheType::Response).unwrap();
    let _ = cache.get("miss", CacheType::Response);
    let stats = cache.stats();
    assert!(stats.hits >= 1);
    assert_eq!(stats.misses, 1);
}

#[test]
fn cache_stats_after_sets() {
    let (cache, _tmp) = create_test_cache();
    cache.set("a", CacheType::Response, "1").unwrap();
    cache.set("b", CacheType::Prompt, "2").unwrap();
    let stats = cache.stats();
    assert_eq!(stats.total_entries, 2);
    assert_eq!(stats.expired_entries, 0);
}

#[test]
fn cache_compression_large_content() {
    let (cache, _tmp) = create_test_cache();
    let large = "x".repeat(10000);
    cache.set("large", CacheType::Response, &large).unwrap();
    assert_eq!(cache.get("large", CacheType::Response).unwrap(), large);
}

#[test]
fn cache_empty_string() {
    let (cache, _tmp) = create_test_cache();
    cache.set("empty", CacheType::Response, "").unwrap();
    assert_eq!(cache.get("empty", CacheType::Response).unwrap(), "");
}

#[test]
fn cache_unicode_content() {
    let (cache, _tmp) = create_test_cache();
    let content = "Unicode: \u{00e9}\u{00e1}\u{00ed}\u{00f3}\u{00fa} \u{1f980}";
    cache.set("unicode", CacheType::Response, content).unwrap();
    assert_eq!(cache.get("unicode", CacheType::Response).unwrap(), content);
}

#[test]
fn cache_special_characters() {
    let (cache, _tmp) = create_test_cache();
    let content = "Newline\nTab\tQuote\"Backslash\\";
    cache.set("special", CacheType::Response, content).unwrap();
    assert_eq!(cache.get("special", CacheType::Response).unwrap(), content);
}

#[test]
fn cache_hash_deterministic() {
    let (cache, _tmp) = create_test_cache();
    let h1 = cache.hash_key("test");
    let h2 = cache.hash_key("test");
    assert_eq!(h1, h2);
}

#[test]
fn cache_hash_different_keys() {
    let (cache, _tmp) = create_test_cache();
    let h1 = cache.hash_key("key1");
    let h2 = cache.hash_key("key2");
    assert_ne!(h1, h2);
}

#[test]
fn cache_hash_length() {
    let (cache, _tmp) = create_test_cache();
    let hash = cache.hash_key("test");
    assert_eq!(hash.len(), 64);
}

#[test]
fn cache_hash_empty_string() {
    let (cache, _tmp) = create_test_cache();
    let hash = cache.hash_key("");
    assert_eq!(hash.len(), 64);
}

#[test]
fn cache_multiple_operations() {
    let (cache, _tmp) = create_test_cache();
    for i in 0..50 {
        cache.set(&format!("k{}", i), CacheType::Response, &format!("v{}", i)).unwrap();
    }
    for i in 0..50 {
        assert_eq!(cache.get(&format!("k{}", i), CacheType::Response).unwrap(), format!("v{}", i));
    }
    assert!(cache.stats().total_entries >= 50);
}

#[test]
fn cache_remove_only_target_type() {
    let (cache, _tmp) = create_test_cache();
    cache.set("key", CacheType::Response, "r").unwrap();
    cache.set("key", CacheType::Prompt, "p").unwrap();
    cache.remove("key", CacheType::Response).unwrap();
    assert!(!cache.contains("key", CacheType::Response));
    assert!(cache.contains("key", CacheType::Prompt));
}

#[test]
fn cache_clear_by_type_all_types() {
    let (cache, _tmp) = create_test_cache();
    cache.set("a", CacheType::Response, "1").unwrap();
    cache.set("b", CacheType::Prompt, "2").unwrap();
    cache.set("c", CacheType::Embedding, "3").unwrap();
    cache.set("d", CacheType::ToolResult, "4").unwrap();
    cache.clear_by_type(CacheType::Response).unwrap();
    assert!(!cache.contains("a", CacheType::Response));
    assert!(cache.contains("b", CacheType::Prompt));
    assert!(cache.contains("c", CacheType::Embedding));
    assert!(cache.contains("d", CacheType::ToolResult));
}

#[test]
fn cache_large_number_of_entries() {
    let (cache, _tmp) = create_test_cache();
    for i in 0..200 {
        cache.set(&format!("entry_{}", i), CacheType::Response, &format!("data_{}", i)).unwrap();
    }
    let stats = cache.stats();
    assert!(stats.total_entries > 0);
}

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
fn cache_type_serde_roundtrip() {
    for ct in [CacheType::Response, CacheType::Prompt, CacheType::Embedding, CacheType::ToolResult] {
        let json = serde_json::to_string(&ct).unwrap();
        let back: CacheType = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, back);
    }
}

#[test]
fn cache_level_serde_roundtrip() {
    for cl in [CacheLevel::Memory, CacheLevel::Disk] {
        let json = serde_json::to_string(&cl).unwrap();
        let back: CacheLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(cl, back);
    }
}

#[test]
fn eviction_policy_serde_roundtrip() {
    for ep in [EvictionPolicy::LRU, EvictionPolicy::LFU, EvictionPolicy::FIFO, EvictionPolicy::TTL] {
        let json = serde_json::to_string(&ep).unwrap();
        let back: EvictionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(ep, back);
    }
}

#[test]
fn eviction_policy_default() {
    assert!(matches!(EvictionPolicy::default(), EvictionPolicy::LRU));
}

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
    let c = s.clone();
    assert_eq!(c.max_memory_mb, 100);
}

#[test]
fn cache_settings_serde_roundtrip() {
    let s = CacheSettings::default();
    let json = serde_json::to_string(&s).unwrap();
    let back: CacheSettings = serde_json::from_str(&json).unwrap();
    assert_eq!(back.max_disk_mb, 500);
    assert!(back.enable_compression);
}

#[test]
fn cache_settings_custom() {
    let s = CacheSettings {
        max_memory_mb: 50,
        max_disk_mb: 200,
        default_ttl_secs: 1800,
        enable_compression: false,
        eviction_policy: EvictionPolicy::FIFO,
    };
    assert_eq!(s.max_memory_mb, 50);
    assert_eq!(s.eviction_policy, EvictionPolicy::FIFO);
}

#[test]
fn cache_entry_struct() {
    let ce = CacheEntry {
        key_hash: "abc123".into(),
        cache_type: CacheType::Response,
        content: "data".into(),
        compressed: false,
        created_at: 1000,
        expires_at: 2000,
        hits: 5,
    };
    assert_eq!(ce.key_hash, "abc123");
    assert_eq!(ce.hits, 5);
}

#[test]
fn cache_entry_clone() {
    let ce = CacheEntry {
        key_hash: "x".into(),
        cache_type: CacheType::Prompt,
        content: "y".into(),
        compressed: true,
        created_at: 1,
        expires_at: 2,
        hits: 0,
    };
    let c = ce.clone();
    assert!(c.compressed);
}

#[test]
fn cache_entry_serde_roundtrip() {
    let ce = CacheEntry {
        key_hash: "hash".into(),
        cache_type: CacheType::Embedding,
        content: "content".into(),
        compressed: true,
        created_at: 100,
        expires_at: 200,
        hits: 3,
    };
    let json = serde_json::to_string(&ce).unwrap();
    let back: CacheEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.key_hash, "hash");
    assert!(back.compressed);
    assert_eq!(back.hits, 3);
}

#[test]
fn cache_stats_struct() {
    let cs = CacheStats {
        total_entries: 10,
        expired_entries: 2,
        hits: 80,
        misses: 20,
        hit_rate: 80.0,
    };
    assert_eq!(cs.total_entries, 10);
    assert_eq!(cs.hit_rate, 80.0);
}

#[test]
fn cache_stats_clone() {
    let cs = CacheStats {
        total_entries: 1,
        expired_entries: 0,
        hits: 10,
        misses: 5,
        hit_rate: 66.67,
    };
    let c = cs.clone();
    assert_eq!(c.hits, 10);
}

#[test]
fn cache_stats_serde_roundtrip() {
    let cs = CacheStats {
        total_entries: 42,
        expired_entries: 3,
        hits: 100,
        misses: 50,
        hit_rate: 66.67,
    };
    let json = serde_json::to_string(&cs).unwrap();
    let back: CacheStats = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_entries, 42);
    assert_eq!(back.hit_rate, 66.67);
}

#[test]
fn cache_type_debug() {
    assert_eq!(format!("{:?}", CacheType::Response), "Response");
    assert_eq!(format!("{:?}", CacheType::Prompt), "Prompt");
    assert_eq!(format!("{:?}", CacheType::Embedding), "Embedding");
    assert_eq!(format!("{:?}", CacheType::ToolResult), "ToolResult");
}

#[test]
fn eviction_policy_debug() {
    assert_eq!(format!("{:?}", EvictionPolicy::LRU), "LRU");
    assert_eq!(format!("{:?}", EvictionPolicy::LFU), "LFU");
    assert_eq!(format!("{:?}", EvictionPolicy::FIFO), "FIFO");
    assert_eq!(format!("{:?}", EvictionPolicy::TTL), "TTL");
}

#[test]
fn cache_level_debug() {
    assert_eq!(format!("{:?}", CacheLevel::Memory), "Memory");
    assert_eq!(format!("{:?}", CacheLevel::Disk), "Disk");
}

#[test]
fn cache_level_eq() {
    assert_eq!(CacheLevel::Memory, CacheLevel::Memory);
    assert_ne!(CacheLevel::Memory, CacheLevel::Disk);
}

#[test]
fn cache_type_eq() {
    assert_eq!(CacheType::Response, CacheType::Response);
    assert_ne!(CacheType::Response, CacheType::Prompt);
}

#[test]
fn eviction_policy_eq() {
    assert_eq!(EvictionPolicy::LRU, EvictionPolicy::LRU);
    assert_ne!(EvictionPolicy::LRU, EvictionPolicy::LFU);
}

#[test]
fn cache_level_clone() {
    let cl = CacheLevel::Disk;
    assert_eq!(cl.clone(), CacheLevel::Disk);
}

#[test]
fn cache_type_clone() {
    let ct = CacheType::Embedding;
    assert_eq!(ct.clone(), CacheType::Embedding);
}

#[test]
fn eviction_policy_clone() {
    let ep = EvictionPolicy::FIFO;
    assert_eq!(ep.clone(), EvictionPolicy::FIFO);
}

#[test]
fn cache_level_copy() {
    let cl = CacheLevel::Memory;
    let c: CacheLevel = cl;
    assert_eq!(c, CacheLevel::Memory);
}

#[test]
fn cache_type_copy() {
    let ct = CacheType::ToolResult;
    let c: CacheType = ct;
    assert_eq!(c, CacheType::ToolResult);
}

#[test]
fn eviction_policy_copy() {
    let ep = EvictionPolicy::TTL;
    let c: EvictionPolicy = ep;
    assert_eq!(c, EvictionPolicy::TTL);
}

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
    for h in handles {
        h.join().unwrap();
    }
    assert!(cache.stats().total_entries >= 5);
}

#[test]
fn cache_cleanup_no_expired() {
    let (cache, _tmp) = create_test_cache();
    cache.set("fresh", CacheType::Response, "data").unwrap();
    let deleted = cache.cleanup_expired().unwrap();
    assert_eq!(deleted, 0);
}

#[test]
fn cache_hit_miss_ratio() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    for _ in 0..10 {
        let _ = cache.get("k", CacheType::Response);
    }
    for _ in 0..5 {
        let _ = cache.get("miss", CacheType::Response);
    }
    let stats = cache.stats();
    assert!(stats.hits >= 10);
    assert_eq!(stats.misses, 5);
    assert!(stats.hit_rate >= 60.0);
}

#[test]
fn cache_error_not_found_is_debug() {
    let err = CacheError::NotFound;
    let debug = format!("{:?}", err);
    assert!(debug.contains("NotFound"));
}

#[test]
fn cache_error_display() {
    let err = CacheError::NotFound;
    let msg = format!("{}", err);
    assert!(!msg.is_empty());
}

#[test]
fn cache_set_many_types_many_keys() {
    let (cache, _tmp) = create_test_cache();
    let types = [CacheType::Response, CacheType::Prompt, CacheType::Embedding, CacheType::ToolResult];
    for (i, ct) in types.iter().enumerate() {
        cache.set(&format!("key_{}", i), *ct, &format!("val_{}", i)).unwrap();
    }
    for (i, ct) in types.iter().enumerate() {
        assert!(cache.contains(&format!("key_{}", i), *ct));
    }
}

#[test]
fn cache_get_after_clear() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    cache.clear().unwrap();
    assert!(matches!(cache.get("k", CacheType::Response), Err(CacheError::NotFound)));
}

#[test]
fn cache_remove_idempotent() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    assert!(cache.remove("k", CacheType::Response).unwrap());
    assert!(!cache.remove("k", CacheType::Response).unwrap());
}

#[test]
fn cache_reinsert_after_remove() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v1").unwrap();
    cache.remove("k", CacheType::Response).unwrap();
    cache.set("k", CacheType::Response, "v2").unwrap();
    assert_eq!(cache.get("k", CacheType::Response).unwrap(), "v2");
}

#[test]
fn cache_stats_after_clear() {
    let (cache, _tmp) = create_test_cache();
    cache.set("k", CacheType::Response, "v").unwrap();
    cache.clear().unwrap();
    let stats = cache.stats();
    assert_eq!(stats.total_entries, 0);
}

#[test]
fn cache_hash_long_key() {
    let (cache, _tmp) = create_test_cache();
    let long_key = "a".repeat(10000);
    let hash = cache.hash_key(&long_key);
    assert_eq!(hash.len(), 64);
}

#[test]
fn cache_hash_unicode_key() {
    let (cache, _tmp) = create_test_cache();
    let hash = cache.hash_key("\u{00e9}\u{00e1}\u{00ed}");
    assert_eq!(hash.len(), 64);
}
