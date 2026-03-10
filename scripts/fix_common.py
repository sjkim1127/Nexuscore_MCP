import os

def fix_server():
    with open('src/server.rs', 'r') as f:
        c = f.read()
    c = c.replace('use rmcp::{model::*, server::stdio::stdio, ServerHandler, ServiceExt};', 'use rmcp::{model::*, ServerHandler, ServiceExt};')
    c = c.replace('server.serve(stdio())', 'server.serve(rmcp::transport::io::stdio())')
    with open('src/server.rs', 'w') as f:
        f.write(c)

def fix_config_extractor():
    with open('src/tools/malware/analysis/config_extractor.rs', 'r') as f:
        c = f.read()
    c = c.replace('use cipher::{KeyIvInit, StreamCipher};', 'use rc4::cipher::{KeyIvInit, StreamCipher};')
    with open('src/tools/malware/analysis/config_extractor.rs', 'w') as f:
        f.write(c)

def fix_gated_files():
    # Adding #![cfg(feature = "dynamic-analysis")] to common frida dependent files
    for file in ['src/tools/common/hook.rs', 'src/tools/common/memory.rs']:
        if os.path.exists(file):
            with open(file, 'r') as f:
                c = f.read()
            if '#![cfg(feature = "dynamic-analysis")]' not in c:
                with open(file, 'w') as f:
                    f.write('#![cfg(feature = "dynamic-analysis")]\n' + c)
                    
    # process.rs has SpawnProcess which is NOT frida dependent, but InjectFridaScript IS.
    # Actually, process.rs imports `frida_handler` unconditionally at the top.
    with open('src/tools/common/process.rs', 'r') as f:
        c = f.read()
    # It imports: `use crate::engine::frida_handler::FridaSessionManager;`
    # We should put it behind #[cfg(feature = "dynamic-analysis")]
    c = c.replace('use crate::engine::frida_handler::FridaSessionManager;', '#[cfg(feature = "dynamic-analysis")]\nuse crate::engine::frida_handler::FridaSessionManager;')
    c = c.replace('#[derive(Clone)]\npub struct InjectFridaScript;', '#[cfg(feature = "dynamic-analysis")]\n#[derive(Clone)]\npub struct InjectFridaScript;')
    c = c.replace('impl Tool for InjectFridaScript {', '#[cfg(feature = "dynamic-analysis")]\n#[async_trait]\nimpl Tool for InjectFridaScript {')
    c = c.replace('crate::tools::ToolRegistration::new(|| std::sync::Arc::new(InjectFridaScript)),', '#[cfg(feature = "dynamic-analysis")]\n    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(InjectFridaScript)),')
    with open('src/tools/common/process.rs', 'w') as f:
        f.write(c)

if __name__ == '__main__':
    fix_server()
    fix_config_extractor()
    fix_gated_files()
