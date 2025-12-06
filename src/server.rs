use anyhow::Result;
use async_trait::async_trait;
use rmcp::{
    protocol::{CallToolRequest, CallToolResult, Tool as McpToolDefinition, ListToolsResult},
    RequestHandler,
};
use std::collections::HashMap;
use serde_json::Value;

// Internal Tool Trait imports
use crate::tools::{self, Tool};

pub struct NexusCoreServer {
    tools: HashMap<String, Box<dyn Tool>>,
}

impl NexusCoreServer {
    pub fn new() -> Self {
        let mut tools: HashMap<String, Box<dyn Tool>> = HashMap::new();
        
        // Helper macro to register tools
        macro_rules! register {
            ($t:expr) => {
                let tool = $t;
                tools.insert(tool.name().to_string(), Box::new(tool));
            };
        }

        // --- Common Tools ---
        register!(tools::common::process::SpawnProcess);
        register!(tools::common::process::AttachProcess);
        register!(tools::common::process::ResumeProcess);
        // ... add other tools here ...
        register!(tools::malware::disasm::CodeDisassembler);
        register!(tools::malware::reconstruction::PeFixer);
        register!(tools::malware::iat::IatFixer);
        register!(tools::malware::unpacker::OepFinder);
        register!(tools::malware::sandbox_submit::CapeSubmitter);
        register!(tools::system::persistence::PersistenceHunter);
        register!(tools::system::handles::HandleScanner);
        
        // Note: Wrappers (Die, Capa, Yara) need to be registered too, assuming they impl Tool
        register!(tools::malware::wrappers::external::DieTool);
        register!(tools::malware::wrappers::external::CapaTool);
        register!(tools::malware::wrappers::external::FlossTool);
        // register!(tools::malware::yara::YaraScanner); // If available

        Self { tools }
    }
}

#[async_trait]
impl RequestHandler for NexusCoreServer {
    async fn list_tools(&self) -> Result<ListToolsResult> {
        let tools_list: Vec<McpToolDefinition> = self.tools.values().map(|t| McpToolDefinition {
            name: t.name().to_string(),
            description: Some(t.description().to_string()),
            input_schema: serde_json::json!({
                 "type": "object", 
                 "properties": {}, // Schema generation is TODO, defaulting to generic object
                 "additionalProperties": true 
            }), 
        }).collect();

        Ok(ListToolsResult { tools: tools_list, next_cursor: None })
    }

    async fn call_tool(&self, req: CallToolRequest) -> Result<CallToolResult> {
        let name = req.name;
        match self.tools.get(&name) {
            Some(tool) => {
                let args = req.arguments.unwrap_or(serde_json::json!({}));
                match tool.execute(args).await {
                    Ok(result) => {
                        // RMCP expects a list of Content (Text/Image/Resource)
                        // our tools return Value. We convert Value -> Text Content.
                        let text = serde_json::to_string_pretty(&result)?;
                        Ok(CallToolResult {
                            content: vec![rmcp::protocol::Content::Text(rmcp::protocol::TextContent {
                                text,
                                ..Default::default()
                            })],
                            is_error: Some(false),
                            meta: None // _meta field
                        })
                    },
                    Err(e) => {
                        Ok(CallToolResult {
                            content: vec![rmcp::protocol::Content::Text(rmcp::protocol::TextContent {
                                text: format!("Error executing {}: {}", name, e),
                                ..Default::default()
                            })],
                            is_error: Some(true),
                            meta: None
                        })
                    }
                }
            },
            None => Err(anyhow::anyhow!("Tool not found: {}", name)),
        }
    }
    
    // Other handler methods (resources, prompts) can be defaulted or implemented as empty
}
