use nexuscore_mcp::tools::{Tool, ToolRegistration};
use serde_json::Value;

#[test]
fn test_all_registered_tools_validation() {
    let mut tool_count = 0;

    for registration in inventory::iter::<ToolRegistration>() {
        let tool = (registration.create)();
        let name = tool.name();
        let description = tool.description();
        let schema = tool.schema().to_json();

        tool_count += 1;

        // 1. Basic properties
        assert!(!name.is_empty(), "Tool at index {} has no name", tool_count);
        assert!(
            !description.is_empty(),
            "Tool '{}' has no description",
            name
        );

        // 2. Naming convention (snake_case)
        assert!(
            name.chars()
                .all(|c| c.is_lowercase() || c == '_' || c.is_numeric()),
            "Tool name '{}' must be snake_case",
            name
        );

        // 3. Schema validation
        assert_eq!(
            schema["type"], "object",
            "Tool '{}' schema must be an object type",
            name
        );
        assert!(
            schema.get("properties").is_some(),
            "Tool '{}' schema missing 'properties'",
            name
        );
    }

    println!("Validated {} registered tools", tool_count);
    assert!(tool_count > 0, "No tools were registered!");
}
