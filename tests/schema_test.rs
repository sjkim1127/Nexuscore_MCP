//! Tests for Tool schema generation

use nexuscore_mcp::tools::{ParamDef, ToolSchema};

#[test]
fn test_param_def_creation() {
    let param = ParamDef::new("test_param", "string", true, "A test parameter");

    assert_eq!(param.name, "test_param");
    assert_eq!(param.param_type, "string");
    assert!(param.required);
    assert_eq!(param.description, "A test parameter");
}

#[test]
fn test_param_def_to_json() {
    let param = ParamDef::new("pid", "number", true, "Process ID");
    let json = param.to_json();

    assert_eq!(json["type"], "number");
    assert_eq!(json["description"], "Process ID");
}

#[test]
fn test_tool_schema_empty() {
    let schema = ToolSchema::empty();
    let json = schema.to_json();

    assert_eq!(json["type"], "object");
    assert!(json["properties"].as_object().unwrap().is_empty());
    // required should be missing when there are no required parameters
    assert!(json.get("required").is_none());
}

#[test]
fn test_tool_schema_with_params() {
    let schema = ToolSchema::new(vec![
        ParamDef::new("pid", "number", true, "Process ID"),
        ParamDef::new("timeout", "number", false, "Timeout in ms"),
    ]);

    let json = schema.to_json();

    assert_eq!(json["type"], "object");
    assert_eq!(json["properties"]["pid"]["type"], "number");
    assert_eq!(json["properties"]["timeout"]["type"], "number");

    let required = json["required"].as_array().unwrap();
    assert!(required.contains(&serde_json::json!("pid")));
    assert!(!required.contains(&serde_json::json!("timeout")));
}

#[test]
fn test_tool_schema_additional_properties() {
    let schema = ToolSchema::empty();
    let json = schema.to_json();

    assert_eq!(json["additionalProperties"], false);
}

#[test]
fn test_schema_all_types() {
    let schema = ToolSchema::new(vec![
        ParamDef::new("str_param", "string", true, "String param"),
        ParamDef::new("num_param", "number", true, "Number param"),
        ParamDef::new("bool_param", "boolean", false, "Boolean param"),
        ParamDef::new("arr_param", "array", false, "Array param"),
        ParamDef::new("obj_param", "object", false, "Object param"),
    ]);

    let json = schema.to_json();
    let props = json["properties"].as_object().unwrap();

    assert_eq!(props.len(), 5);
    assert_eq!(props["str_param"]["type"], "string");
    assert_eq!(props["num_param"]["type"], "number");
    assert_eq!(props["bool_param"]["type"], "boolean");
    assert_eq!(props["arr_param"]["type"], "array");
    assert_eq!(props["obj_param"]["type"], "object");
}
