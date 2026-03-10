use crate::tools::Tool;
use anyhow::Result;
use rmcp::{model::*, ServerHandler, ServiceExt};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

pub struct NexusCoreServer {
    tools: HashMap<String, Arc<dyn Tool>>,
}

impl NexusCoreServer {
    pub fn new() -> Self {
        let mut tools: HashMap<String, Arc<dyn Tool>> = HashMap::new();
        for reg in inventory::iter::<crate::tools::ToolRegistration> {
            let tool = (reg.create)();
            tools.insert(tool.name().to_string(), tool);
        }
        Self { tools }
    }

    pub fn print_tool_count(&self) {
        tracing::info!("NexusCore loaded {} tools", self.tools.len());
    }
}

impl ServerHandler for NexusCoreServer {
    async fn list_tools(
        &self,
        _req_param: Option<rmcp::model::PaginatedRequestParam>,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<ListToolsResult, rmcp::model::ErrorData> {
        let tools_list: Vec<rmcp::model::Tool> = self
            .tools
            .values()
            .map(|t| rmcp::model::Tool {
                name: Cow::Owned(t.name().to_string()),
                description: Some(Cow::Owned(t.description().to_string())),
                input_schema: Arc::new(if let Value::Object(m) = t.schema().to_json() {
                    m
                } else {
                    serde_json::Map::new()
                }),
                title: None,
                output_schema: None,
                annotations: None,
                icons: None,
                meta: None,
            })
            .collect();

        Ok(ListToolsResult {
            tools: tools_list,
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        param: rmcp::model::CallToolRequestParam,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResult, rmcp::model::ErrorData> {
        let name = param.name.to_string();
        let args_map = param.arguments.unwrap_or_else(serde_json::Map::new);
        let args = Value::Object(args_map);
        let tool = match self.tools.get(&name) {
            Some(tool) => tool,
            None => {
                return Ok(CallToolResult {
                    content: vec![Content::text(format!("Error: Unknown tool '{}'", name))],
                    is_error: Some(true),
                    meta: None,
                    structured_content: None,
                });
            }
        };

        match tool.execute(args).await {
            Ok(result) => Ok(CallToolResult {
                content: vec![Content::text(result.to_string())],
                is_error: Some(false),
                meta: None,
                structured_content: None,
            }),
            Err(e) => {
                let error_json = serde_json::json!({
                    "error_type": "ToolExecutionFailed",
                    "message": e.to_string()
                });
                Ok(CallToolResult {
                    content: vec![Content::text(error_json.to_string())],
                    is_error: Some(true),
                    meta: None,
                    structured_content: None,
                })
            }
        }
    }

    // --- Resources Support ---

    async fn list_resources(
        &self,
        _req_param: Option<PaginatedRequestParam>,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult {
            resources: vec![
                RawResource::new("mcp://logs/latest", "Latest Analysis Logs")
                    .optional_annotate(None),
                RawResource::new("mcp://cache/stats", "Cache Statistics").optional_annotate(None),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        param: ReadResourceRequestParam,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let uri = param.uri.to_string();

        let content = match uri.as_str() {
            "mcp://logs/latest" => {
                let log_path = "logs/nexuscore.json";
                std::fs::read_to_string(log_path).unwrap_or_else(|_| "[]".to_string())
            }
            "mcp://cache/stats" => serde_json::json!({
                "engine": "sled",
                "path": "logs/.nexuscore_cache",
                "ttl": "7 days"
            })
            .to_string(),
            _ if uri.starts_with("mcp://dumps/") => {
                let id = uri.trim_start_matches("mcp://dumps/");
                let manager = crate::utils::streaming::get_stream_manager();
                match manager.read_chunk_as_hex(id, 0, 4096) {
                    Ok((hex, _len)) => format!("Memory Dump Preview (First 4KB):\n\nHex: {}\n\n(Total ID: {}, Use read_memory_chunk for more)", hex, id),
                    Err(_) => "Dump not found or inaccessible".to_string(),
                }
            }
            _ => {
                return Err(ErrorData {
                    code: ErrorCode::INVALID_PARAMS,
                    message: Cow::Owned(format!("Unsupported resource URI: {}", uri)),
                    data: None,
                })
            }
        };

        Ok(ReadResourceResult {
            contents: vec![ResourceContents::text(content, uri)],
        })
    }

    // --- Prompts Support ---

    async fn list_prompts(
        &self,
        _req_param: Option<PaginatedRequestParam>,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let arg = PromptArgument {
            name: "file_path".to_string(),
            title: None,
            description: Some("Path to the suspicious file".to_string()),
            required: Some(true),
        };

        Ok(ListPromptsResult {
            prompts: vec![
                Prompt {
                    name: "Malware_Triage".to_string(),
                    title: None,
                    description: Some(
                        "Expert workflow for initial malware classification".to_string(),
                    ),
                    arguments: Some(vec![arg.clone()]),
                    icons: None,
                    meta: None,
                },
                Prompt {
                    name: "Yara_Auto_Correct".to_string(),
                    title: None,
                    description: Some(
                        "Workflow for generating and self-verifying YARA rules".to_string(),
                    ),
                    arguments: Some(vec![arg]),
                    icons: None,
                    meta: None,
                },
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn get_prompt(
        &self,
        param: GetPromptRequestParam,
        _ctx: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<GetPromptResult, ErrorData> {
        if param.name == "Malware_Triage" {
            let file_path = param
                .arguments
                .as_ref()
                .and_then(|a| a.get("file_path"))
                .map(|v| v.as_str().unwrap_or(""))
                .unwrap_or("unknown");

            Ok(GetPromptResult {
                description: Some("Initial triage prompt".to_string()),
                messages: vec![PromptMessage::new_text(
                    PromptMessageRole::User,
                    format!(
                        "Analyze this file: {}. \n\n1. Run `die_scan` to check signatures.\n2. Run `capa_scan` for capabilities.\n3. If suspicious, submit to CAPE using `cape_submit` and check progress.",
                        file_path
                    ),
                )],
            })
        } else if param.name == "Yara_Auto_Correct" {
            let file_path = param
                .arguments
                .as_ref()
                .and_then(|a| a.get("file_path"))
                .map(|v| v.as_str().unwrap_or(""))
                .unwrap_or("unknown");

            Ok(GetPromptResult {
                description: Some("Workflow for generating and self-verifying YARA rules".to_string()),
                messages: vec![PromptMessage::new_text(
                    PromptMessageRole::User,
                    format!(
                        "Generate and verify YARA rule for {}: \n\n1. Run `generate_yara` to create an initial rule.\n2. Extract the rule text from the output.\n3. Run `verify_yara` with the rule and path to check if it actually matches the sample.\n4. If it doesn't match, refine the rule (Check unique strings or hex patterns) and verify again until it works.",
                        file_path
                    ),
                )],
            })
        } else {
            Err(ErrorData {
                code: ErrorCode::INVALID_PARAMS,
                message: Cow::Owned(format!("Prompt not found: {}", param.name)),
                data: None,
            })
        }
    }
}

/// Start the MCP server
pub async fn run_server() -> Result<()> {
    let server = NexusCoreServer::new();
    server.print_tool_count();

    let service = server.serve(rmcp::transport::io::stdio()).await?;

    tokio::select! {
        res = service.waiting() => {
            if let Err(e) = res {
                tracing::error!("Server exited with error: {}", e);
            } else {
                tracing::info!("Server exited normally.");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl-C, initiating graceful shutdown...");

            #[cfg(feature = "dynamic-analysis")]
            {
                tracing::info!("Cleaning up Frida sessions...");
                crate::engine::frida_handler::get_session_manager().lock().unwrap().cleanup_all();
            }

            #[cfg(windows)]
            {
                tracing::info!("Cleaning up WinDbg sessions...");
                crate::tools::malware::debug::debugger::cleanup_all_sessions();
            }
        }
    }

    Ok(())
}
