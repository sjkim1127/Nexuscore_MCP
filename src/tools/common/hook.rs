use anyhow::Result;
use serde_json::Value;
use crate::engine::frida_handler;
use crate::tools::Tool;
use async_trait::async_trait;

pub struct InstallHook;
#[async_trait]
impl Tool for InstallHook {
    fn name(&self) -> &str { "install_hook" }
    fn description(&self) -> &str { "Installs a JS hook on a target function. Args: pid (number), target (string), js_code (string, optional)" }
    async fn execute(&self, args: Value) -> Result<Value> {
        let pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))? as u32;
        let target = args["target"].as_str().ok_or(anyhow::anyhow!("Missing target function/address"))?;
        let code = args["js_code"].as_str().unwrap_or(""); 

        let script = format!(r#"
            var target = Module.findExportByName(null, "{}");
            if (!target) target = ptr("{}");
            
            Interceptor.attach(target, {{
                onEnter: function(args) {{
                    send({{ "type": "hook_enter", "target": "{}", "args": [args[0], args[1], args[2]] }});
                    {}
                }},
                onLeave: function(retval) {{
                    send({{ "type": "hook_leave", "retval": retval }});
                }}
            }});
        "#, target, target, target, code);

        frida_handler::execute_script(pid, &script)?;

        Ok(serde_json::json!({ "status": "hook_installed", "target": target }))
    }
}
