use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

pub mod common;
pub mod intel;
pub mod malware;
pub mod network;
pub mod system;

/// Parameter definition for tool schema
#[derive(Clone, Debug)]
pub struct ParamDef {
    pub name: &'static str,
    pub param_type: &'static str, // "string", "number", "boolean", "array", "object"
    pub required: bool,
    pub description: &'static str,
}

impl ParamDef {
    pub const fn new(
        name: &'static str,
        param_type: &'static str,
        required: bool,
        description: &'static str,
    ) -> Self {
        Self {
            name,
            param_type,
            required,
            description,
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "type": self.param_type,
            "description": self.description
        })
    }
}

/// Tool input schema
pub struct ToolSchema {
    pub params: Vec<ParamDef>,
}

impl ToolSchema {
    pub fn new(params: Vec<ParamDef>) -> Self {
        Self { params }
    }

    pub fn empty() -> Self {
        Self { params: vec![] }
    }

    pub fn to_json(&self) -> Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for param in &self.params {
            properties.insert(param.name.to_string(), param.to_json());
            if param.required {
                required.push(Value::String(param.name.to_string()));
            }
        }

        let mut schema = serde_json::json!({
            "type": "object",
            "properties": properties,
            "additionalProperties": false
        });

        if !required.is_empty() {
            schema
                .as_object_mut()
                .expect("tool schema must be an object")
                .insert("required".to_string(), Value::Array(required));
        }

        schema
    }
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;

    /// Returns the input schema for this tool (default: empty schema)
    fn schema(&self) -> ToolSchema {
        ToolSchema::empty()
    }

    async fn execute(&self, args: Value) -> Result<Value>;
}

/// Helper macro for defining tool parameters
#[macro_export]
macro_rules! tool_params {
    ($($name:literal : $type:literal $(, required: $req:literal)? $(, desc: $desc:literal)?);* $(;)?) => {
        vec![
            $(
                $crate::tools::ParamDef::new(
                    $name,
                    $type,
                    tool_params!(@req $($req)?),
                    tool_params!(@desc $($desc)?)
                )
            ),*
        ]
    };
    (@req) => { false };
    (@req $req:literal) => { $req };
    (@desc) => { "" };
    (@desc $desc:literal) => { $desc };
}
