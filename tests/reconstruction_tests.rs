use nexuscore_mcp::tools::malware::disasm::CodeDisassembler;
use nexuscore_mcp::tools::malware::reconstruction::PeFixer;
use nexuscore_mcp::tools::malware::iat::IatFixer;
use nexuscore_mcp::tools::Tool;
use serde_json::json;

#[tokio::test]
async fn test_disassembler_metadata() {
    let tool = CodeDisassembler;
    assert_eq!(tool.name(), "disassemble_code");
}

#[tokio::test]
async fn test_disassembler_basic_instruction() {
    let tool = CodeDisassembler;
    // 90 = NOP
    let result = tool.execute(json!({"hex_code": "90", "bitness": 64})).await;
    assert!(result.is_ok());
    let output = result.unwrap();
    let instructions = output["instructions"].as_array().unwrap();
    assert_eq!(instructions.len(), 1);
    assert_eq!(instructions[0]["mnemonic"].as_str().unwrap(), "Nop");
}

#[tokio::test]
async fn test_pe_fixer_metadata() {
    let tool = PeFixer;
    assert_eq!(tool.name(), "pe_fixer");
}

#[tokio::test]
async fn test_iat_fixer_metadata() {
    let tool = IatFixer;
    assert_eq!(tool.name(), "iat_fixer");
}
