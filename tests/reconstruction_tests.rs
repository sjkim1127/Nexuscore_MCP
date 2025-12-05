use nexuscore_mcp::tools::malware::disasm::CodeDisassembler;
use nexuscore_mcp::tools::malware::reconstruction::PeFixer;
use nexuscore_mcp::tools::malware::iat::IatFixer;
use nexuscore_mcp::tools::Tool;
use serde_json::json;

#[tokio::test]
async fn test_disassembler_logic() {
    let tool = CodeDisassembler;
    
    // Test Case 1: Simple NOPs (0x90 0x90)
    let result = tool.execute(json!({"hex_code": "9090", "bitness": 64})).await;
    assert!(result.is_ok(), "Disassembly failed for NOPs");
    
    let json = result.unwrap();
    let insts = json["instructions"].as_array().expect("Output should contain instructions array");
    assert_eq!(insts.len(), 2, "Should have 2 instructions");
    assert_eq!(insts[0]["mnemonic"], "Nop");
    
    // Test Case 2: Invalid Hex
    let result = tool.execute(json!({"hex_code": "ZZZZ"})).await;
    assert!(result.is_err(), "Should catch invalid hex");
}

#[tokio::test]
async fn test_pe_fixer_logic() {
    let tool = PeFixer;
    
    // We need a dummy PE file. 
    // Creating a minimal PE header in memory or writing to a temp file.
    // For simplicity, we test 'File Not Found' first.
    let result = tool.execute(json!({"file_path": "non_existent_pe.exe"})).await;
    assert!(result.is_err());
    
    // To test success, we would need to write a valid PE header to a temp file.
    // But demonstrating robust error handling is good for now.
}
