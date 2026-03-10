import os
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # We want to ensure #[async_trait] is present before `impl Tool for`
    # and we also need to add the import `use async_trait::async_trait;` if missing
    
    modified = False
    
    impl_pattern = r'(?<!#\[async_trait\]\n)(impl\s+Tool\s+for\s+[^{]+{)'
    if re.search(impl_pattern, content):
        content = re.sub(impl_pattern, r'#[async_trait]\n\1', content)
        modified = True
        
    if 'use async_trait::async_trait;' not in content and 'impl Tool for' in content:
        content = 'use async_trait::async_trait;\n' + content
        modified = True
        
    # Also fix SystemDiff::new() to SystemDiff
    if 'SystemDiff::new()' in content:
        content = content.replace('SystemDiff::new()', 'SystemDiff')
        modified = True
        
    # Fix the MutexGuard issue in diff.rs
    if 'diff.rs' in filepath and 'let lock = SNAPSHOT.lock().unwrap();' in content:
        content = content.replace('''let lock = SNAPSHOT.lock().unwrap();
                let old_files = match &*lock {
                    Some(f) => f.clone(),
                    None => {
                        return Ok(StandardResponse::error(
                            tool_name,
                            "No snapshot taken yet. Run with action='take' first.",
                        ))
                    }
                };
                drop(lock);''', '''let old_files = {
                    let lock = SNAPSHOT.lock().unwrap();
                    match &*lock {
                        Some(f) => f.clone(),
                        None => {
                            return Ok(StandardResponse::error(
                                tool_name,
                                "No snapshot taken yet. Run with action='take' first.",
                            ))
                        }
                    }
                };''')
        modified = True
    
    # Fix api_monitor.rs missing include
    if 'api_monitor.rs' in filepath or 'crypto_hook.rs' in filepath or 'ssl_dumper.rs' in filepath or 'ssl_keylog.rs' in filepath or 'string_sniffer.rs' in filepath:
        content = content.replace('include_str!("../../resources/scripts/', 'include_str!("../../../resources/scripts/')
        modified = True
        
    # Replace the remaining errors one by one
    if 'reconstruction.rs' in filepath:
        content = content.replace('info.insert("is_64", serde_json::json!(pe.is_64));', 'info.insert("is_64".to_string(), serde_json::json!(pe.is_64));')
        content = content.replace('info.insert("is_64", format!("{}", pe.is_64).into());', 'info.insert("is_64".to_string(), serde_json::json!(pe.is_64));')
        # Wait, the error was info.insert("is_64", serde_json::json!(pe.is_64)); expected String, found &str
        content = re.sub(r'info\.insert\("([^"]+)",', r'info.insert("\1".to_string(),', content)
        modified = True
        
    if 'config_extractor.rs' in filepath:
        if 'rc4.apply_keystream(&mut data)' in content and 'use cipher::StreamCipher;' not in content:
            content = 'use cipher::{KeyIvInit, StreamCipher};\n' + content
            modified = True
            
    if 'yara_gen.rs' in filepath:
        if 'Sha256::digest(' in content and 'use sha2::Digest;' not in content:
            content = 'use sha2::Digest;\n' + content
            modified = True

    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    root_dir = "src"
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            if f.endswith('.rs'):
                process_file(os.path.join(dirpath, f))

if __name__ == "__main__":
    main()
