use anyhow::Result;
use rmcp::{ServerHandler, ServiceExt, model::*, service::RequestContext, tool};
use serde_json::Value;
use std::collections::HashMap;
use crate::tools::Tool;
use crate::tools;
use std::sync::Arc;
use async_trait::async_trait;

pub struct NexusCoreServer {
    tools: HashMap<String, Arc<dyn Tool>>,
}

macro_rules! register {
    ($t:expr) => {{
        let tool: Arc<dyn Tool> = Arc::new($t);
        tools.insert(tool.name().to_string(), tool);
    }};
}

impl NexusCoreServer {
    pub fn new() -> Self {
        let mut tools: HashMap<String, Arc<dyn Tool>> = HashMap::new();

        // --- Common Tools ---
        register!(tools::common::process::SpawnProcess);
        register!(tools::common::process::AttachProcess);
        register!(tools::common::process::ResumeProcess);
        register!(tools::common::process::InjectFridaScript);
        
        // --- Frida Session Management ---
        register!(tools::common::frida_session::FridaSessionCreate);
        register!(tools::common::frida_session::FridaSessionInject);
        register!(tools::common::frida_session::FridaSessionResume);
        register!(tools::common::frida_session::FridaSessionMessages);
        register!(tools::common::frida_session::FridaSessionDestroy);
        register!(tools::common::frida_session::FridaSessionList);
        
        // --- Frida Tools (malware::frida) ---
        register!(tools::malware::frida::api_monitor::ApiMonitor);
        register!(tools::malware::frida::api_monitor::FileMonitor);
        register!(tools::malware::frida::api_monitor::RegistryMonitor);
        register!(tools::malware::frida::api_monitor::NetworkMonitor);
        register!(tools::malware::frida::api_monitor::InjectionMonitor);
        register!(tools::malware::frida::memory_dump::MemoryDumper);
        register!(tools::malware::frida::memory_dump::MemoryPatcher);
        register!(tools::malware::frida::stalker::ExecutionStalker);
        register!(tools::malware::frida::string_sniffer::StringSniffer);
        register!(tools::malware::frida::crypto_hook::CryptoHook);
        register!(tools::malware::frida::ssl_keylog::SslKeylogger);
        register!(tools::malware::frida::ssl_dumper::SslKeyDumper);
        register!(tools::malware::frida::time_warp::TimeWarper);
        register!(tools::malware::frida::child_trapper::ChildTrapper);
        register!(tools::malware::frida::spoof_return::ReturnSpoofer);
        register!(tools::malware::frida::spoof_return::AddressSpoofer);
        register!(tools::malware::frida::callstack::CallstackTracer);
        register!(tools::malware::frida::callstack::AddressTracer);
        
        // --- Analysis Tools (malware::analysis) ---
        register!(tools::malware::analysis::disasm::CodeDisassembler);
        register!(tools::malware::analysis::reconstruction::PeFixer);
        register!(tools::malware::analysis::iat::IatFixer);
        register!(tools::malware::analysis::unpacker::OepFinder);
        register!(tools::malware::analysis::shellcode_emu::ShellcodeEmulator);
        register!(tools::malware::analysis::config_extractor::ConfigExtractor);
        register!(tools::malware::analysis::pe_sieve::PeSieve);
        register!(tools::malware::analysis::doc_analyzer::DocAnalyzer);
        register!(tools::malware::analysis::yara_gen::YaraGenerator);
        
        // --- Debug Tools (malware::debug) ---
        register!(tools::malware::debug::debugger::SessionStart);
        register!(tools::malware::debug::debugger::SessionCommand);
        register!(tools::malware::debug::debugger::SessionBatch);
        register!(tools::malware::debug::debugger::SessionEnd);
        register!(tools::malware::debug::debugger::SessionList);
        register!(tools::malware::debug::debugger::CdbCommands);
        
        // --- Malware Root Level ---
        register!(tools::malware::sandbox_submit::CapeSubmitter);
        register!(tools::malware::wrappers::external::DieTool);
        register!(tools::malware::wrappers::external::CapaTool);
        register!(tools::malware::wrappers::external::FlossTool);
        
        // --- System Tools ---
        register!(tools::system::persistence::PersistenceHunter);
        register!(tools::system::handles::HandleScanner);
        register!(tools::system::input_sim::InputSimulator);
        register!(tools::system::diff::SystemDiff);
        register!(tools::system::gui_spy::GuiSpy);
        register!(tools::system::eventlog::EventLogQuery);
        
        // --- Network Tools ---
        register!(tools::network::fakenet::FakeNet);
        
        // --- Intel Tools ---
        register!(tools::intel::reputation::ReputationChecker);

        Self { tools }
    }

    pub fn print_tool_count(&self) {
        tracing::info!("NexusCore loaded {} tools", self.tools.len());
    }
}

// MCP Definition for tool listing
#[derive(Clone)]
struct McpToolDefinition {
    name: String,
    description: Option<String>,
    input_schema: Value,
}

#[async_trait]
impl RequestHandler for NexusCoreServer {
    async fn list_tools(&self) -> Result<ListToolsResult> {
        let tools_list: Vec<McpToolDefinition> = self.tools.values().map(|t| McpToolDefinition {
            name: t.name().to_string(),
            description: Some(t.description().to_string()),
            input_schema: t.schema().to_json(),
        }).collect();

        Ok(ListToolsResult { tools: tools_list, next_cursor: None })
    }

    async fn call_tool(&self, name: String, args: Value) -> Result<CallToolResult> {
        let tool = self.tools.get(&name).ok_or_else(|| anyhow::anyhow!("Unknown tool: {}", name))?;
        
        match tool.execute(args).await {
            Ok(result) => Ok(CallToolResult {
                content: vec![Content::text(result.to_string())],
                is_error: Some(false),
            }),
            Err(e) => Ok(CallToolResult {
                content: vec![Content::text(format!("Error: {}", e))],
                is_error: Some(true),
            }),
        }
    }
}

/// Start the MCP server
pub async fn run_server() -> Result<()> {
    tracing_subscriber::fmt::init();
    let server = NexusCoreServer::new();
    server.print_tool_count();
    
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
