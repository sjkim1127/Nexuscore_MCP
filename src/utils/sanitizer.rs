use crate::tools::{ParamDef, Tool, ToolSchema};
use crate::utils::response::StandardResponse;
use async_trait::async_trait;
use serde_json::Value;

pub struct ContentSanitizer;

impl ContentSanitizer {
    /// Sanitizes tool output for LLM consumption
    pub fn sanitize(text: &str) -> String {
        // 1. Wrap in markdown code blocks to prevent direct execution of hidden prompts
        // 2. Escape backticks
        let escaped = text.replace("```", "\\`\\`\\` ");
        format!("```\n{}\n```", escaped)
    }

    /// Truncates text to a reasonable length for LLM context
    pub fn truncate(text: &str, max_chars: usize) -> String {
        if text.len() <= max_chars {
            return text.to_string();
        }
        let truncated = &text[..max_chars];
        format!(
            "{}\n... [TRUNCATED {} characters for token optimization]",
            truncated,
            text.len() - max_chars
        )
    }
}

pub struct SanitizeOutputTool;

#[async_trait]
impl Tool for SanitizeOutputTool {
    fn name(&self) -> &str {
        "sanitize_output"
    }

    fn description(&self) -> &str {
        "Sanitizes or truncates large text output for safer LLM consumption. Prevents Indirect Prompt Injection."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![
            ParamDef::new("text", "string", true, "The text to sanitize"),
            ParamDef::new(
                "max_length",
                "number",
                false,
                "Optional max length (default: 5000)",
            ),
        ])
    }

    async fn execute(&self, args: Value) -> anyhow::Result<Value> {
        let text = args["text"].as_str().unwrap_or("");
        let max_len = args["max_length"].as_u64().unwrap_or(5000) as usize;

        let truncated = ContentSanitizer::truncate(text, max_len);
        let sanitized = ContentSanitizer::sanitize(&truncated);

        Ok(StandardResponse::success(
            self.name(),
            serde_json::json!({
                "sanitized_content": sanitized,
                "original_length": text.len(),
                "truncated": text.len() > max_len
            }),
        ))
    }
}

inventory::submit! {
    crate::tools::ToolRegistration::new(|| std::sync::Arc::new(SanitizeOutputTool))
}
