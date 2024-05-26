pub mod kernel32;
use std::ffi::c_void;

pub type FunctionPointer = unsafe extern "C" fn() -> c_void;
