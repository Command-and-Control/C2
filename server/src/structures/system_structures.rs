#[repr(C)]
pub struct MEMORYSTATUSEX {
    pub dwLength: u32,
    pub dwMemoryLoad: u32,
    pub ullTotalPhys: u64,
    pub ullAvailPhys: u64,
    pub ullTotalPageFile: u64,
    pub ullAvailPageFile: u64,
    pub ullTotalVirtual: u64,
    pub ullAvailVirtual: u64,
    pub ullAvailExtendedVirtual: u64,
}

#[repr(C)]
pub struct CPUINFO {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[repr(C)]
pub struct MSRINFO {
    pub msr_number: u32,
    pub value: u64,
}

#[repr(C)]
pub struct VIRTUALIZATIONSTATUS {
    pub is_enabled: bool,
    pub vendor: [u8; 16],
}

impl Default for MEMORYSTATUSEX {
    fn default() -> Self {
        Self {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            dwMemoryLoad: 0,
            ullTotalPhys: 0,
            ullAvailPhys: 0,
            ullTotalPageFile: 0,
            ullAvailPageFile: 0,
            ullTotalVirtual: 0,
            ullAvailVirtual: 0,
            ullAvailExtendedVirtual: 0,
        }
    }
}

impl Default for CPUINFO {
    fn default() -> Self {
        Self {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    }
}

impl Default for MSRINFO {
    fn default() -> Self {
        Self {
            msr_number: 0,
            value: 0,
        }
    }
}

impl Default for VIRTUALIZATIONSTATUS {
    fn default() -> Self {
        Self {
            is_enabled: false,
            vendor: [0; 16],
        }
    }
}

#[repr(C)]
pub struct VIRTUALIZATION_INFO {
    pub is_enabled: bool,
}

impl Default for VIRTUALIZATION_INFO {
    fn default() -> Self {
        Self { is_enabled: false }
    }
}
