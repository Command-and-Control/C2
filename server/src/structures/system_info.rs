use crate::structures::CloneableAny;
use crate::winapi::kernel32::{GetComputerNameA, GetUserNameA};
use std::any::Any;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SYSTEM_INFO {
    pub wProcessorArchitecture: u16,
    pub wReserved: u16,
    pub dwPageSize: u32,
    pub lpMinimumApplicationAddress: *mut std::ffi::c_void,
    pub lpMaximumApplicationAddress: *mut std::ffi::c_void,
    pub dwActiveProcessorMask: usize,
    pub dwNumberOfProcessors: u32,
    pub dwProcessorType: u32,
    pub dwAllocationGranularity: u32,
    pub wProcessorLevel: u16,
    pub wProcessorRevision: u16,
}

impl CloneableAny for SYSTEM_INFO {
    fn clone_box(&self) -> Box<dyn CloneableAny> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
pub fn register_structures(registry: &mut super::StructureRegistry) {
    registry.register(
        "SYSTEM_INFO",
        SYSTEM_INFO {
            wProcessorArchitecture: 0,
            wReserved: 0,
            dwPageSize: 0,
            lpMinimumApplicationAddress: std::ptr::null_mut(),
            lpMaximumApplicationAddress: std::ptr::null_mut(),
            dwActiveProcessorMask: 0,
            dwNumberOfProcessors: 0,
            dwProcessorType: 0,
            dwAllocationGranularity: 0,
            wProcessorLevel: 0,
            wProcessorRevision: 0,
        },
    );
}

pub fn get_hostname() -> String {
    let mut buffer = [0u8; 256];
    let mut size = 256;
    unsafe {
        GetComputerNameA(buffer.as_mut_ptr() as *mut i8, &mut size);
    }
    String::from_utf8_lossy(&buffer)
        .trim_end_matches('\0')
        .to_string()
}

pub fn get_username() -> String {
    let mut buffer = [0u8; 256];
    let mut size = 256;
    unsafe {
        GetUserNameA(buffer.as_mut_ptr() as *mut i8, &mut size);
    }
    String::from_utf8_lossy(&buffer)
        .trim_end_matches('\0')
        .to_string()
}
