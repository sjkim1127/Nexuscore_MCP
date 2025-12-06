use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

pub mod common;
pub mod malware;
pub mod wrappers;
pub mod system;
pub mod network;

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn execute(&self, args: Value) -> Result<Value>;
}
