use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

pub mod process;
pub mod memory;
pub mod hook;
pub mod defender;
pub mod codeql;
pub mod network;
pub mod etw;
pub mod proxy;
pub mod yara;

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn execute(&self, args: Value) -> Result<Value>;
}
