use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Persistent cache for external tool results using sled
pub struct ResultCache {
    db: sled::Db,
    ttl: Duration,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheEntry {
    result: serde_json::Value,
    timestamp: u64,
}

impl ResultCache {
    pub fn new(db_path: &str, ttl_seconds: u64) -> anyhow::Result<Self> {
        let db = sled::open(db_path)?;
        Ok(Self {
            db,
            ttl: Duration::from_secs(ttl_seconds),
        })
    }

    /// Get cached result by file hash
    pub fn get(&self, hash: &str) -> Option<serde_json::Value> {
        if let Ok(Some(value)) = self.db.get(hash) {
            if let Ok(entry) = serde_json::from_slice::<CacheEntry>(&value) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                if now - entry.timestamp < self.ttl.as_secs() {
                    return Some(entry.result);
                } else {
                    // Evict expired
                    let _ = self.db.remove(hash);
                }
            }
        }
        None
    }

    /// Store result with file hash as key
    pub fn insert(&self, hash: String, result: serde_json::Value) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = CacheEntry {
            result,
            timestamp: now,
        };
        if let Ok(value) = serde_json::to_vec(&entry) {
            let _ = self.db.insert(hash, value);
        }
    }
}

/// Calculate SHA256 hash of a file using streaming to avoid large memory allocations
pub fn file_hash(path: &str) -> Result<String, io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536]; // 64KB buffer
    
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Global sled cache instance
static GLOBAL_CACHE: std::sync::OnceLock<ResultCache> = std::sync::OnceLock::new();

pub fn get_cache() -> &'static ResultCache {
    GLOBAL_CACHE.get_or_init(|| {
        let cache_dir = "logs/.nexuscore_cache";
        // 7 days TTL for external analysis results
        ResultCache::new(cache_dir, 3600 * 24 * 7)
            .expect("Failed to initialize sled persistent cache")
    })
}

/// Check cache and return result if available
pub fn cached_or_execute<F>(
    file_path: &str,
    tool_name: &str,
    execute: F,
) -> anyhow::Result<serde_json::Value>
where
    F: FnOnce() -> anyhow::Result<serde_json::Value>,
{
    let hash = match file_hash(file_path) {
        Ok(h) => format!("{}:{}", tool_name, h),
        Err(_) => return execute(), // Can't hash, just execute
    };

    let cache = get_cache();
    if let Some(cached) = cache.get(&hash) {
        return Ok(serde_json::json!({
            "cached": true,
            "result": cached
        }));
    }

    // Execute and cache
    let result = execute()?;
    cache.insert(hash, result.clone());

    Ok(result)
}
