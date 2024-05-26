use crate::structures::system_info::SYSTEM_INFO;
use crate::structures::system_structures::MEMORYSTATUSEX;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::ptr::null_mut;

extern "system" {
    pub fn LoadLibraryA(lpLibFileName: *const c_char) -> *mut c_void;
    pub fn GetProcAddress(hModule: *mut c_void, lpProcName: *const c_char) -> *mut c_void;
    pub fn GetUserNameA(lpBuffer: *mut c_char, pcbBuffer: *mut u32) -> i32;
    pub fn GetComputerNameA(lpBuffer: *mut c_char, nSize: *mut u32) -> i32;
    pub fn GetCurrentProcessId() -> u32;
    pub fn GetSystemInfo(lpSystemInfo: *mut SYSTEM_INFO) -> i32;
    pub fn GlobalMemoryStatusEx(lpBuffer: *mut MEMORYSTATUSEX) -> i32;
}
