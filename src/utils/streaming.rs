use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use uuid::Uuid;

pub struct StreamManager {
    dump_dir: PathBuf,
}

impl StreamManager {
    pub fn new() -> Self {
        let dump_dir = PathBuf::from("logs/dumps");
        if !dump_dir.exists() {
            fs::create_dir_all(&dump_dir).unwrap_or(());
        }
        Self { dump_dir }
    }

    /// Saves a byte buffer to a unique file and returns the dump ID.
    pub fn save_dump(&self, data: &[u8]) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let path = self.dump_dir.join(format!("{}.bin", id));
        fs::write(&path, data).context("Failed to write dump file")?;
        Ok(id)
    }

    /// Reads a chunk from a dump file.
    pub fn read_chunk(&self, id: &str, offset: u64, size: usize) -> Result<Vec<u8>> {
        // Sanitize ID to prevent path traversal
        let sanitized_id = id
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();
        let path = self.dump_dir.join(format!("{}.bin", sanitized_id));

        if !path.exists() {
            anyhow::bail!("Dump not found: {}", sanitized_id);
        }

        use std::io::{Read, Seek, SeekFrom};
        let mut file = fs::File::open(path)?;
        let file_len = file.metadata()?.len();

        if offset >= file_len {
            return Ok(Vec::new());
        }

        let actual_size = std::cmp::min(size as u64, file_len - offset) as usize;
        let mut buffer = vec![0u8; actual_size];

        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    /// Reads a chunk and returns it as a hex string.
    pub fn read_chunk_as_hex(&self, id: &str, offset: u64, size: usize) -> Result<(String, usize)> {
        let bytes = self.read_chunk(id, offset, size)?;
        let len = bytes.len();
        Ok((hex::encode(bytes), len))
    }

    /// Checks if a dump exists and returns its path.
    pub fn get_dump_path(&self, id: &str) -> Option<PathBuf> {
        let sanitized_id = id
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();
        let path = self.dump_dir.join(format!("{}.bin", sanitized_id));
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }
}

pub fn get_stream_manager() -> &'static StreamManager {
    static INSTANCE: OnceLock<StreamManager> = OnceLock::new();
    INSTANCE.get_or_init(StreamManager::new)
}
