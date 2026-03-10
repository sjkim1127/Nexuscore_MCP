import os

def fix_process():
    with open('src/tools/common/process.rs', 'r') as f:
        c = f.read()
    c = c.replace('#[cfg(feature = "dynamic-analysis")]\n#[derive(Clone)]\npub struct InjectFridaScript;', '#[derive(Clone)]\npub struct InjectFridaScript;')
    c = c.replace('#[cfg(feature = "dynamic-analysis")]\n#[async_trait]\nimpl Tool for InjectFridaScript {', '#[async_trait]\nimpl Tool for InjectFridaScript {')
    c = c.replace('#[cfg(feature = "dynamic-analysis")]\n    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(InjectFridaScript)),', '    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(InjectFridaScript)),')
    c = c.replace('#[cfg(feature = "dynamic-analysis")]\nuse crate::engine::frida_handler::FridaSessionManager;', 'use crate::engine::frida_handler::FridaSessionManager;')
    
    # ensure top of file has #![cfg(feature = "dynamic-analysis")]
    if '#![cfg(feature = "dynamic-analysis")]' not in c:
        c = '#![cfg(feature = "dynamic-analysis")]\n' + c
    with open('src/tools/common/process.rs', 'w') as f:
        f.write(c)

def fix_config_extractor():
    with open('src/tools/malware/analysis/config_extractor.rs', 'r') as f:
        c = f.read()
    c = c.replace('rc4.apply_keystream(&mut data);', '<Rc4 as StreamCipher>::apply_keystream(&mut rc4, &mut data);')
    with open('src/tools/malware/analysis/config_extractor.rs', 'w') as f:
        f.write(c)

if __name__ == '__main__':
    fix_process()
    fix_config_extractor()
