use crate::structures::system_structures::VIRTUALIZATIONSTATUS;
use crate::structures::FunctionRegistry;
use std::arch::asm;

pub fn check_virtualization(status: &mut VIRTUALIZATIONSTATUS) {
    unsafe {
        let mut ecx: u32;
        asm!(
            "mov eax, 1",
            "cpuid",
            out("ecx") ecx,
            options(nostack),
        );
        status.is_enabled = (ecx & (1 << 5)) != 0;
    }
}

unsafe extern "C" fn check_virtualization_wrapper(status: *mut VIRTUALIZATIONSTATUS) {
    check_virtualization(&mut *status);
}

pub fn register_functions(registry: &mut FunctionRegistry) {
    registry.register(
        "hypervisor.CheckVirtualization",
        check_virtualization_wrapper as unsafe extern "C" fn(*mut VIRTUALIZATIONSTATUS),
    );
}
