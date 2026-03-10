import os
import re
import glob

TOOLS_DIR = "/Users/sjkim1127/Nexuscore_MCP/src/tools"

STRUCT_PATTERN = re.compile(r"pub struct (\w+);?")
IMPL_TOOL_PATTERN = re.compile(r"impl\s+Tool\s+for\s+(\w+)\s*\{")

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    if "impl Tool for" not in content:
        return

    new_content = content
    structs = IMPL_TOOL_PATTERN.findall(content)
    
    for struct_name in structs:
        # Avoid duplicate inventory submits
        if f"std::sync::Arc::new({struct_name}" in new_content and "ToolRegistration" in new_content:
            continue
        
        instantiation = struct_name
        
        # Determine how to instantiate
        struct_decl = re.search(fr"pub\s+struct\s+{struct_name}(.*?)(?:\{{|;)", content, flags=re.DOTALL)
        if struct_decl:
            decl_suffix = struct_decl.group(1).strip()
            # If not a unit struct, we check for new() or Default
            if "{" in content.split(f"pub struct {struct_name}")[1].split("impl")[0]:
                if f"impl {struct_name} {{\n    pub fn new" in content or f"impl {struct_name} {{\n    fn new" in content:
                    instantiation = f"{struct_name}::new()"
                elif f"impl Default for {struct_name}" in content:
                    instantiation = f"{struct_name}::default()"
                else: 
                     # we assume new() or default() exists for others
                    instantiation = f"{struct_name}::new()"
        
        new_content += f"\n\ninventory::submit! {{\n    crate::tools::ToolRegistration::new(|| std::sync::Arc::new({instantiation}))\n}}\n"

    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated {filepath} with inventory")

def update_mod():
    filepath = os.path.join(TOOLS_DIR, "mod.rs")
    with open(filepath, 'r') as f:
        content = f.read()
    
    if "ToolRegistration" not in content:
        addition = """
pub struct ToolRegistration {
    pub create: fn() -> std::sync::Arc<dyn Tool>,
}

impl ToolRegistration {
    pub const fn new(create: fn() -> std::sync::Arc<dyn Tool>) -> Self {
        Self { create }
    }
}

inventory::collect!(ToolRegistration);
"""
        with open(filepath, 'a') as f:
            f.write(addition)
        print("Updated mod.rs with ToolRegistration")

if __name__ == "__main__":
    update_mod()
    for root, dirs, files in os.walk(TOOLS_DIR):
        for file in files:
            if file.endswith('.rs') and file != 'mod.rs':
                process_file(os.path.join(root, file))
