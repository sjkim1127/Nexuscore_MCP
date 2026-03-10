import os
import glob
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove `use async_trait::async_trait;`
    content = re.sub(r'use\s+async_trait::async_trait;\n?', '', content)
    # Remove `#[async_trait]`
    content = re.sub(r'#\[async_trait\]\n?', '', content)
    
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
