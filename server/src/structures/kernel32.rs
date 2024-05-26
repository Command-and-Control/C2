use super::{FunctionPointer, FunctionRegistry};
use crate::structures::system_info::SYSTEM_INFO;
use std::ffi::CString;
use std::os::raw::c_int;

use crate::structures::system_info::SYSTEM_INFO;

pub unsafe fn get_system_info(sys_info: &mut SYSTEM_INFO) {
    let lib = LoadLibraryA(CString::new("kernel32.dll").unwrap().as_ptr());
    let func: unsafe extern "C" fn(*mut SYSTEM_INFO) = std::mem::transmute(GetProcAddress(
        lib,
        CString::new("GetSystemInfo").unwrap().as_ptr(),
    ));
    func(sys_info);
}

unsafe extern "C" fn get_system_info_wrapper(sys_info: *mut SYSTEM_INFO) {
    get_system_info(&mut *sys_info);
}

pub fn register_functions(registry: &mut FunctionRegistry) {
    registry.register(
        "kernel32.GetSystemInfo",
        get_system_info_wrapper as FunctionPointer,
    );
}
