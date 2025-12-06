use anyhow::Result;
use serde_json::Value;
use crate::tools::{Tool, ToolSchema, ParamDef};
use crate::utils::response::StandardResponse;
use async_trait::async_trait;
use std::time::Instant;

#[cfg(windows)]
use winapi::um::winuser::{EnumWindows, GetWindowThreadProcessId, GetWindowTextW, IsWindowVisible, GetWindowTextLengthW, GetClassNameW};
#[cfg(windows)]
use winapi::shared::minwindef::{BOOL, LPARAM, DWORD};
#[cfg(windows)]
use winapi::shared::windef::HWND;

pub struct GuiSpy;

#[cfg(windows)]
struct EnumState { target_pid: u32, windows: Vec<serde_json::Value> }

#[cfg(windows)]
unsafe extern "system" fn enum_window_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let state = &mut *(lparam as *mut EnumState);
    let mut window_pid: DWORD = 0;
    GetWindowThreadProcessId(hwnd, &mut window_pid);
    if window_pid == state.target_pid && IsWindowVisible(hwnd) != 0 {
        let title_len = GetWindowTextLengthW(hwnd);
        let title = if title_len > 0 {
            let mut buf = vec![0u16; (title_len + 1) as usize];
            GetWindowTextW(hwnd, buf.as_mut_ptr(), title_len + 1);
            String::from_utf16_lossy(&buf[..title_len as usize])
        } else { String::new() };
        let mut class_buf = vec![0u16; 256];
        let class_len = GetClassNameW(hwnd, class_buf.as_mut_ptr(), 256);
        let class_name = if class_len > 0 { String::from_utf16_lossy(&class_buf[..class_len as usize]) } else { String::new() };
        if !title.is_empty() || !class_name.is_empty() {
            state.windows.push(serde_json::json!({ "hwnd": format!("0x{:X}", hwnd as usize), "title": title, "class": class_name }));
        }
    }
    1
}

#[async_trait]
impl Tool for GuiSpy {
    fn name(&self) -> &str { "inspect_gui" }
    fn description(&self) -> &str { "Extracts window titles and class names. Args: pid" }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(vec![ ParamDef::new("pid", "number", true, "Target process ID") ])
    }

    async fn execute(&self, args: Value) -> Result<Value> {
        let start = Instant::now();
        let tool_name = self.name();
        
        let pid = match args["pid"].as_u64() {
            Some(p) => p as u32,
            None => return Ok(StandardResponse::error(tool_name, "Missing pid")),
        };

        #[cfg(windows)]
        {
            let mut state = EnumState { target_pid: pid, windows: Vec::new() };
            unsafe { EnumWindows(Some(enum_window_proc), &mut state as *mut _ as LPARAM); }
            Ok(StandardResponse::success_timed(tool_name, serde_json::json!({
                "pid": pid,
                "window_count": state.windows.len(),
                "windows": state.windows
            }), start))
        }

        #[cfg(not(windows))]
        Ok(StandardResponse::error(tool_name, "Only supported on Windows"))
    }
}
