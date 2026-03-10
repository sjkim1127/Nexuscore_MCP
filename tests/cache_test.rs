//! Tests for the cache module

use nexuscore_mcp::utils::cache::{file_hash, get_cache, ResultCache};
use serde_json::json;
use std::fs;
use std::thread;
use std::time::Duration;

#[test]
fn test_cache_insert_and_get() {
    let db_path = "logs/.test_cache_1";
    let _ = fs::remove_dir_all(db_path);

    let cache = ResultCache::new(db_path, 60).expect("Failed to create cache");

    let key = "test:abc123".to_string();
    let value = json!({"result": "test_data"});

    cache.insert(key.clone(), value.clone());

    let retrieved = cache.get(&key);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap()["result"], "test_data");
}

#[test]
fn test_cache_miss() {
    let db_path = "logs/.test_cache_2";
    let _ = fs::remove_dir_all(db_path);
    let cache = ResultCache::new(db_path, 60).expect("Failed to create cache");

    let result = cache.get("nonexistent:key");
    assert!(result.is_none());
}

#[test]
fn test_cache_expiry() {
    let db_path = "logs/.test_cache_3";
    let _ = fs::remove_dir_all(db_path);
    let cache = ResultCache::new(db_path, 1).expect("Failed to create cache"); // 1 second TTL

    let key = "test:expiry".to_string();
    let value = json!({"data": "will_expire"});

    cache.insert(key.clone(), value);

    // Should exist immediately
    assert!(cache.get(&key).is_some());

    // Wait for expiry
    thread::sleep(Duration::from_secs(2));

    // Should be expired now
    assert!(cache.get(&key).is_none());
}

#[test]
fn test_global_cache() {
    let cache = get_cache();

    cache.insert("global:test".to_string(), json!({"global": true}));

    let result = cache.get("global:test");
    assert!(result.is_some());
}

#[cfg(test)]
mod file_hash_tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_file_hash_consistency() {
        // Create temp file
        let path = "test_hash_file.tmp";
        let mut file = File::create(path).unwrap();
        file.write_all(b"test content for hashing").unwrap();
        drop(file);

        // Hash should be consistent
        let hash1 = file_hash(path).unwrap();
        let hash2 = file_hash(path).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 = 64 hex chars

        // Cleanup
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_file_hash_nonexistent() {
        let result = file_hash("nonexistent_file.xyz");
        assert!(result.is_err());
    }
}
