import os
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # We only want to add #[async_trait] where there is `impl Tool for`
    # and we also need to add the import `use async_trait::async_trait;`
    if 'impl Tool for' in content and 'async_trait' not in content:
        content = 'use async_trait::async_trait;\n' + content
        content = re.sub(r'(impl Tool for\s+[^{]+{)', r'#[async_trait]\n\1', content)
        
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
