use crate::tools;
use crate::tools::Tool;
use anyhow::Result;
use async_trait::async_trait;
use rmcp::{model::*, service::RequestContext, tool, ServerHandler, ServiceExt};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

pub struct NexusCoreServer {
    tools: HashMap<String, Arc<dyn Tool>>,
}

macro_rules! register {
    ($map:expr, $t:expr) => {{
        let tool: Arc<dyn Tool> = Arc::new($t);
        $map.insert(tool.name().to_string(), tool);
    }};
}

impl NexusCoreServer {
    pub fn new() -> Self {
        let mut tools: HashMap<String, Arc<dyn Tool>> = HashMap::new();
        Self::register_common_tools(&mut tools);
        Self::register_frida_session_tools(&mut tools);
        Self::register_frida_tools(&mut tools);
        Self::register_auto_deobfuscation_tools(&mut tools);
        Self::register_analysis_tools(&mut tools);
        Self::register_debug_tools(&mut tools);
        Self::register_malware_tools(&mut tools);
        Self::register_system_tools(&mut tools);
        Self::register_network_tools(&mut tools);
        Self::register_intel_tools(&mut tools);

        Self { tools }
    }

    fn register_common_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(tools, tools::common::process::SpawnProcess);
        register!(tools, tools::common::process::AttachProcess);
        register!(tools, tools::common::process::ResumeProcess);
        register!(tools, tools::common::process::InjectFridaScript);
    }

    fn register_frida_session_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(tools, tools::common::frida_session::FridaSessionCreate);
        register!(tools, tools::common::frida_session::FridaSessionInject);
        register!(tools, tools::common::frida_session::FridaSessionResume);
        register!(tools, tools::common::frida_session::FridaSessionMessages);
        register!(tools, tools::common::frida_session::FridaSessionDestroy);
        register!(tools, tools::common::frida_session::FridaSessionList);
    }

    fn register_frida_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(tools, tools::malware::frida::api_monitor::ApiMonitor);
        register!(tools, tools::malware::frida::api_monitor::FileMonitor);
        register!(tools, tools::malware::frida::api_monitor::RegistryMonitor);
        register!(tools, tools::malware::frida::api_monitor::NetworkMonitor);
        register!(tools, tools::malware::frida::api_monitor::InjectionMonitor);
        register!(tools, tools::malware::frida::memory_dump::MemoryDumper);
        register!(tools, tools::malware::frida::memory_dump::MemoryPatcher);
        register!(tools, tools::malware::frida::stalker::ExecutionStalker);
        register!(tools, tools::malware::frida::string_sniffer::StringSniffer);
        register!(tools, tools::malware::frida::crypto_hook::CryptoHook);
        register!(tools, tools::malware::frida::ssl_keylog::SslKeylogger);
        register!(tools, tools::malware::frida::ssl_dumper::SslKeyDumper);
        register!(tools, tools::malware::frida::time_warp::TimeWarper);
        register!(tools, tools::malware::frida::child_trapper::ChildTrapper);
        register!(tools, tools::malware::frida::spoof_return::ReturnSpoofer);
        register!(tools, tools::malware::frida::spoof_return::AddressSpoofer);
        register!(tools, tools::malware::frida::callstack::CallstackTracer);
        register!(tools, tools::malware::frida::callstack::AddressTracer);
    }

    fn register_auto_deobfuscation_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(
            tools,
            tools::malware::frida::auto_deobfuscate::AutoDeobfuscator
        );
        register!(
            tools,
            tools::malware::frida::auto_deobfuscate::DynamicApiCapture
        );
        register!(
            tools,
            tools::malware::frida::auto_deobfuscate::StringBirthTracker
        );
    }

    fn register_analysis_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(tools, tools::malware::analysis::disasm::CodeDisassembler);
        register!(tools, tools::malware::analysis::reconstruction::PeFixer);
        register!(tools, tools::malware::analysis::iat::IatFixer);
        register!(tools, tools::malware::analysis::unpacker::OepFinder);
        register!(
            tools,
            tools::malware::analysis::shellcode_emu::ShellcodeEmulator
        );
        register!(
            tools,
            tools::malware::analysis::config_extractor::ConfigExtractor
        );
        register!(tools, tools::malware::analysis::pe_sieve::PeSieve);
        register!(tools, tools::malware::analysis::doc_analyzer::DocAnalyzer);
        register!(tools, tools::malware::analysis::yara_gen::YaraGenerator);
    }

    fn register_debug_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(tools, tools::malware::debug::debugger::SessionStart);
        register!(tools, tools::malware::debug::debugger::SessionCommand);
        register!(tools, tools::malware::debug::debugger::SessionBatch);
        register!(tools, tools::malware::debug::debugger::SessionEnd);
        register!(tools, tools::malware::debug::debugger::SessionList);
        register!(tools, tools::malware::debug::debugger::CdbCommands);
    }

    fn register_malware_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(tools, tools::malware::sandbox_submit::CapeSubmitter);
        register!(tools, tools::malware::wrappers::external::DieTool);
        register!(tools, tools::malware::wrappers::external::CapaTool);
        register!(tools, tools::malware::wrappers::external::FlossTool);
    }

    fn register_system_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(tools, tools::system::persistence::PersistenceHunter);
        register!(tools, tools::system::handles::HandleScanner);
        register!(tools, tools::system::input_sim::InputSimulator);
        register!(tools, tools::system::diff::SystemDiff);
        register!(tools, tools::system::gui_spy::GuiSpy);
        register!(tools, tools::system::eventlog::EventLogQuery);
    }

    fn register_network_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(tools, tools::network::fakenet::FakeNet);
    }

    fn register_intel_tools(tools: &mut HashMap<String, Arc<dyn Tool>>) {
        register!(tools, tools::intel::reputation::ReputationChecker);
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
        let tools_list: Vec<McpToolDefinition> = self
            .tools
            .values()
            .map(|t| McpToolDefinition {
                name: t.name().to_string(),
                description: Some(t.description().to_string()),
                input_schema: t.schema().to_json(),
            })
            .collect();

        Ok(ListToolsResult {
            tools: tools_list,
            next_cursor: None,
        })
    }

    async fn call_tool(&self, name: String, args: Value) -> Result<CallToolResult> {
        let tool = match self.tools.get(&name) {
            Some(tool) => tool,
            None => {
                return Ok(CallToolResult {
                    content: vec![Content::text(format!("Error: Unknown tool '{}'", name))],
                    is_error: Some(true),
                });
            }
        };

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
    let server = NexusCoreServer::new();
    server.print_tool_count();

    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
