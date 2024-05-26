use crate::mlang::parser::MLangCommand;
use crate::structures::system_info::SYSTEM_INFO;
use crate::structures::system_structures::*;
use crate::structures::{initialize_registry, StructureRegistry};
use crate::winapi::kernel32::GetSystemInfo;
use crate::winapi::kernel32::GlobalMemoryStatusEx;
use crate::winapi::kernel32::{GetProcAddress, LoadLibraryA};
use std::any::Any;
use std::arch::asm;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ffi::CString;

pub struct MLangInterpreter {
    variables: HashMap<String, String>,
    functions: HashMap<String, Vec<MLangCommand>>,
    structure_registry: StructureRegistry,
}

impl MLangInterpreter {
    pub fn new() -> Self {
        let structure_registry = initialize_registry();
        Self {
            variables: HashMap::new(),
            functions: HashMap::new(),
            structure_registry,
        }
    }

    pub fn execute(&mut self, commands: Vec<MLangCommand>) -> HashMap<String, String> {
        let mut output = HashMap::new();
        for command in commands {
            match command.command.as_str() {
                "let" => {
                    if command.args.len() >= 2 {
                        let var_name = &command.args[0];
                        let value = if let Some(struct_instance_name) = &command.struct_instance {
                            if let Some(output) =
                                self.structure_registry.print_instance(struct_instance_name)
                            {
                                output
                            } else {
                                command.args[1..].join(" ")
                            }
                        } else {
                            command.args[1..].join(" ")
                        };
                        self.variables.insert(var_name.clone(), value);
                    } else {
                        eprintln!("Insufficient arguments for 'let' command");
                    }
                }
                "fn" => {
                    if command.args.len() >= 2 {
                        let func_name = &command.args[0];
                        let body = command.args[1..].join(" ");
                        self.functions.insert(
                            func_name.clone(),
                            vec![MLangCommand {
                                command: "body".to_string(),
                                args: vec![body],
                                output_struct: None,
                                struct_instance: None,
                                struct_field: None,
                            }],
                        );
                    } else {
                        eprintln!("Insufficient arguments for 'fn' command");
                    }
                }
                "call" => {
                    if command.args.len() >= 2 {
                        let func_name = &command.args[1];
                        let output_struct = command.output_struct.as_deref();
                        let struct_instance = command.struct_instance.as_deref();
                        if let Some(result) =
                            self.call_function(func_name, output_struct, struct_instance)
                        {
                            output.insert(func_name.clone(), result);
                        }
                    } else {
                        eprintln!("Insufficient arguments for 'call' command");
                    }
                }
                "print" => {
                    if !command.args.is_empty() {
                        let mut message = String::new();
                        for arg in &command.args {
                            if let Some(value) = self.variables.get(arg) {
                                message.push_str(value);
                            } else {
                                message.push_str(arg);
                            }
                        }
                        println!("{}", message);
                    } else {
                        eprintln!("Insufficient arguments for 'print' command");
                    }
                }
                _ => {
                    eprintln!("Unknown command: {}", command.command);
                }
            }
        }
        output
    }

    fn call_function(
        &mut self,
        func_name: &str,
        output_struct: Option<&str>,
        struct_instance: Option<&str>,
    ) -> Option<String> {
        match func_name {
            "GetCurrentProcessId" => {
                let pid = std::process::id();
                Some(pid.to_string())
            }
            "GlobalMemoryStatusEx" => {
                let memory_info = self.get_memory_info();
                let output = format!(
                    "Memory Status:\nTotal Physical Memory: {} bytes\nAvailable Physical Memory: {} bytes\n...",
                    memory_info.ullTotalPhys, memory_info.ullAvailPhys
                );
                Some(output)
            }
            "GetProcessorInfo" => {
                let cpu_info = self.get_processor_info();
                let output = format!(
                    "CPU Info:\nEAX: {}\nEBX: {}\nECX: {}\nEDX: {}",
                    cpu_info.eax, cpu_info.ebx, cpu_info.ecx, cpu_info.edx
                );
                Some(output)
            }
            "ReadMSR" => Some("MSR Info:\nMSR Number: 0x1B\nValue: 0".to_string()),
            "CheckVirtualization" => {
                let virt_info = self.check_virtualization();
                let output = format!("Virtualization Status:\nEnabled: {}", virt_info.is_enabled);
                Some(output)
            }
            _ => {
                eprintln!("Unknown function: {}", func_name);
                None
            }
        }
    }
    fn call_dll_function(
        &mut self,
        dll_name: &str,
        func_name: &str,
        args: &[String],
        output_struct: Option<&str>,
        struct_instance: Option<&str>,
    ) -> Option<String> {
        let full_func_name = format!("{}.{}", dll_name, func_name);
        unsafe {
            let lib_name = CString::new(format!("{}.dll", dll_name)).unwrap();
            let lib = LoadLibraryA(lib_name.as_ptr());
            if lib.is_null() {
                eprintln!("Failed to load library: {}.dll", dll_name);
                return None;
            }
            let cstr_func_name = CString::new(func_name).unwrap();
            let func_ptr = GetProcAddress(lib, cstr_func_name.as_ptr());
            if func_ptr.is_null() {
                eprintln!("Failed to get function address: {}", func_name);
                return None;
            }
            let result = match output_struct {
                Some("MEMORYSTATUSEX") => {
                    let func: unsafe extern "C" fn(*mut MEMORYSTATUSEX) =
                        std::mem::transmute(func_ptr);
                    let mut status = MEMORYSTATUSEX::default();
                    func(&mut status);
                    format!("Memory Status:\nTotal Physical Memory: {} bytes\nAvailable Physical Memory: {} bytes\n...", status.ullTotalPhys, status.ullAvailPhys)
                }
                Some("CPUINFO") => {
                    let func: unsafe extern "C" fn(*mut i32, *mut i32, *mut i32, *mut i32) =
                        std::mem::transmute(func_ptr);
                    let mut eax = 0;
                    let mut ebx = 0;
                    let mut ecx = 0;
                    let mut edx = 0;
                    func(&mut eax, &mut ebx, &mut ecx, &mut edx);
                    format!(
                        "CPU Info:\nEAX: {}\nEBX: {}\nECX: {}\nEDX: {}",
                        eax, ebx, ecx, edx
                    )
                }
                Some("MSRINFO") => {
                    let func: unsafe extern "C" fn(u32, *mut u64) = std::mem::transmute(func_ptr);
                    let mut value = 0;
                    func(0x1B, &mut value);
                    format!("MSR Info:\nMSR Number: 0x1B\nValue: {}", value)
                }
                Some("VIRTUALIZATIONSTATUS") => {
                    let func: unsafe extern "C" fn(*mut VIRTUALIZATIONSTATUS) =
                        std::mem::transmute(func_ptr);
                    let mut status = VIRTUALIZATIONSTATUS::default();
                    func(&mut status);
                    format!(
                        "Virtualization Status:\nEnabled: {}\nVendor: {:?}",
                        status.is_enabled, status.vendor
                    )
                }
                Some("VIRTUALIZATION_INFO") => {
                    let func: unsafe extern "C" fn(*mut bool) = std::mem::transmute(func_ptr);
                    let mut is_enabled = false;
                    func(&mut is_enabled);
                    format!("Virtualization Status:\nEnabled: {}", is_enabled)
                }
                Some("DWORD") => {
                    let func: unsafe extern "C" fn() -> u32 = std::mem::transmute(func_ptr);
                    func().to_string()
                }
                Some("STRING") => {
                    if let Some(var_name) = struct_instance {
                        let mut buffer = [0u8; 256];
                        let mut size = buffer.len() as u32;
                        let func: unsafe extern "C" fn(*mut i8, *mut u32) =
                            std::mem::transmute(func_ptr);
                        func(buffer.as_mut_ptr() as *mut i8, &mut size);
                        let result = String::from_utf8_lossy(&buffer[..size as usize])
                            .trim_end_matches('\0')
                            .to_string();
                        self.variables.insert(var_name.to_string(), result.clone());
                        format!("Called function: {}", full_func_name)
                    } else {
                        eprintln!("No variable name provided for STRING output");
                        return None;
                    }
                }
                Some(struct_name) => {
                    if let Some(struct_instance_name) = struct_instance {
                        if let Some(struct_instance) =
                            self.structure_registry.create_instance(struct_name)
                        {
                            let func: unsafe extern "C" fn(*mut c_void) =
                                std::mem::transmute(func_ptr);
                            let struct_ptr = struct_instance.as_any() as *const dyn Any
                                as *const c_void
                                as *mut c_void;
                            func(struct_ptr);
                            self.structure_registry
                                .register_instance(struct_instance_name, struct_instance);
                            if let Some(output) =
                                self.structure_registry.print_instance(struct_instance_name)
                            {
                                format!(
                                    "Called function: {} with output:\n{}",
                                    full_func_name, output
                                )
                            } else {
                                format!("Called function: {}", full_func_name)
                            }
                        } else {
                            eprintln!("Unknown struct: {}", struct_name);
                            return None;
                        }
                    } else {
                        eprintln!("No struct instance provided for {}", struct_name);
                        return None;
                    }
                }
                None => {
                    let func: unsafe extern "C" fn() = std::mem::transmute(func_ptr);
                    func();
                    format!("Called function: {}", full_func_name)
                }
            };
            Some(result)
        }
    }

    fn get_memory_info(&self) -> MEMORYSTATUSEX {
        let mut mem_info = MEMORYSTATUSEX::default();
        unsafe {
            mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            GlobalMemoryStatusEx(&mut mem_info);
        }
        mem_info
    }

    fn get_processor_info(&self) -> CPUINFO {
        let mut cpu_info = CPUINFO::default();
        unsafe {
            let mut regs: [u32; 4] = [0; 4];
            asm!(
                "mov eax, 1",
                "cpuid",
                "mov [{:e}], eax",
                "mov [{:e}], ebx",
                "mov [{:e}], ecx",
                "mov [{:e}], edx",
                out(reg) regs[0],
                out(reg) regs[1],
                out(reg) regs[2],
                out(reg) regs[3],
            );
            cpu_info.eax = regs[0];
            cpu_info.ebx = regs[1];
            cpu_info.ecx = regs[2];
            cpu_info.edx = regs[3];
        }
        cpu_info
    }
    fn check_virtualization(&self) -> VIRTUALIZATION_INFO {
        let mut virt_info = VIRTUALIZATION_INFO::default();
        unsafe {
            let mut regs: [u32; 4] = [0; 4];
            asm!(
                "mov eax, 1",
                "cpuid",
                "mov [{:e}], ebx",
                "mov [{:e}], ecx",
                "mov [{:e}], edx",
                out(reg) regs[1],
                out(reg) regs[2],
                out(reg) regs[3],
            );
            virt_info.is_enabled = (regs[2] & (1 << 5)) != 0;
        }
        virt_info
    }
}
