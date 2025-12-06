use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use sha2::{Sha256, Digest};
use std::fs;

/// LRU-style cache for external tool results
pub struct ResultCache {
    cache: HashMap<String, CacheEntry>,
    max_entries: usize,
    ttl: Duration,
}

struct CacheEntry {
    result: serde_json::Value,
    timestamp: Instant,
}

impl ResultCache {
    pub fn new(max_entries: usize, ttl_seconds: u64) -> Self {
        Self {
            cache: HashMap::new(),
            max_entries,
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Get cached result by file hash
    pub fn get(&self, hash: &str) -> Option<&serde_json::Value> {
        self.cache.get(hash).and_then(|entry| {
            if entry.timestamp.elapsed() < self.ttl {
                Some(&entry.result)
            } else {
                None
            }
        })
    }

    /// Store result with file hash as key
    pub fn insert(&mut self, hash: String, result: serde_json::Value) {
        // Simple eviction: remove oldest if full
        if self.cache.len() >= self.max_entries {
            // Find oldest entry
            if let Some(oldest_key) = self.cache.iter()
                .min_by_key(|(_, v)| v.timestamp)
                .map(|(k, _)| k.clone()) 
            {
                self.cache.remove(&oldest_key);
            }
        }

        self.cache.insert(hash, CacheEntry {
            result,
            timestamp: Instant::now(),
        });
    }

    /// Clear expired entries
    pub fn cleanup(&mut self) {
        self.cache.retain(|_, entry| entry.timestamp.elapsed() < self.ttl);
    }
}

/// Calculate SHA256 hash of a file
pub fn file_hash(path: &str) -> Result<String, std::io::Error> {
    let content = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Global cache instance
static GLOBAL_CACHE: std::sync::OnceLock<Mutex<ResultCache>> = std::sync::OnceLock::new();

pub fn get_cache() -> &'static Mutex<ResultCache> {
    GLOBAL_CACHE.get_or_init(|| {
        Mutex::new(ResultCache::new(100, 3600)) // 100 entries, 1 hour TTL
    })
}

/// Check cache and return result if available
pub fn cached_or_execute<F>(file_path: &str, tool_name: &str, execute: F) -> anyhow::Result<serde_json::Value>
where
    F: FnOnce() -> anyhow::Result<serde_json::Value>,
{
    let hash = match file_hash(file_path) {
        Ok(h) => format!("{}:{}", tool_name, h),
        Err(_) => return execute(), // Can't hash, just execute
    };

    // Check cache
    {
        let cache = get_cache().lock().unwrap();
        if let Some(cached) = cache.get(&hash) {
            return Ok(serde_json::json!({
                "cached": true,
                "result": cached.clone()
            }));
        }
    }

    // Execute and cache
    let result = execute()?;
    
    {
        let mut cache = get_cache().lock().unwrap();
        cache.insert(hash, result.clone());
    }

    Ok(result)
}
