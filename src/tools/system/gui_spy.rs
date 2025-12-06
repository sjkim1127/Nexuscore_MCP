use anyhow::Result;
use serde_json::Value;
use crate::tools::Tool;
use async_trait::async_trait;

#[cfg(windows)]
use winapi::um::winuser::{
    EnumWindows, GetWindowThreadProcessId, GetWindowTextW, IsWindowVisible, 
    GetWindowTextLengthW, GetClassNameW,
};
#[cfg(windows)]
use winapi::shared::minwindef::{BOOL, LPARAM, DWORD};
#[cfg(windows)]
use winapi::shared::windef::HWND;

/// GUI Spy - Inspects windows and UI elements of a process
pub struct GuiSpy;

#[cfg(windows)]
struct EnumState {
    target_pid: u32,
    windows: Vec<serde_json::Value>,
}

#[cfg(windows)]
unsafe extern "system" fn enum_window_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let state = &mut *(lparam as *mut EnumState);
    let mut window_pid: DWORD = 0;
    GetWindowThreadProcessId(hwnd, &mut window_pid);

    // Check if this window belongs to our target process
    if window_pid == state.target_pid && IsWindowVisible(hwnd) != 0 {
        // Get window title
        let title_len = GetWindowTextLengthW(hwnd);
        let title = if title_len > 0 {
            let mut buf = vec![0u16; (title_len + 1) as usize];
            GetWindowTextW(hwnd, buf.as_mut_ptr(), title_len + 1);
            String::from_utf16_lossy(&buf[..title_len as usize])
        } else {
            String::new()
        };

        // Get window class
        let mut class_buf = vec![0u16; 256];
        let class_len = GetClassNameW(hwnd, class_buf.as_mut_ptr(), 256);
        let class_name = if class_len > 0 {
            String::from_utf16_lossy(&class_buf[..class_len as usize])
        } else {
            String::new()
        };

        // Only add if we have some info
        if !title.is_empty() || !class_name.is_empty() {
            state.windows.push(serde_json::json!({
                "hwnd": format!("0x{:X}", hwnd as usize),
                "title": title,
                "class": class_name
            }));
        }
    }
    1 // Continue enumeration
}

#[async_trait]
impl Tool for GuiSpy {
    fn name(&self) -> &str { "inspect_gui" }
    fn description(&self) -> &str { "Extracts window titles and class names from a process. Args: pid (number)" }

    async fn execute(&self, args: Value) -> Result<Value> {
        let target_pid = args["pid"].as_u64().ok_or(anyhow::anyhow!("Missing pid"))? as u32;

        #[cfg(windows)]
        {
            let mut state = EnumState {
                target_pid,
                windows: Vec::new(),
            };

            unsafe {
                EnumWindows(Some(enum_window_proc), &mut state as *mut _ as LPARAM);
            }

            Ok(serde_json::json!({
                "pid": target_pid,
                "window_count": state.windows.len(),
                "windows": state.windows
            }))
        }

        #[cfg(not(windows))]
        Err(anyhow::anyhow!("GUI inspection only supported on Windows"))
    }
}
