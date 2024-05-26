pub mod hypervisor;
pub mod system_info;
pub mod system_structures;
use std::any::Any;
use std::collections::HashMap;

pub trait CloneableAny: Any {
    fn clone_box(&self) -> Box<dyn CloneableAny>;
    fn as_any(&self) -> &dyn Any;
}

pub type FunctionPointer = Box<dyn Any>;

pub struct FunctionRegistry {
    functions: HashMap<String, FunctionPointer>,
}

impl FunctionRegistry {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    pub fn register<T: 'static>(&mut self, name: &str, function: T) {
        self.functions.insert(name.to_string(), Box::new(function));
    }

    pub fn get<T: 'static>(&self, name: &str) -> Option<&T> {
        self.functions.get(name).and_then(|f| f.downcast_ref::<T>())
    }
}

pub fn initialize_registries() -> (StructureRegistry, FunctionRegistry) {
    let mut structure_registry = StructureRegistry::new();
    system_info::register_structures(&mut structure_registry);

    let mut function_registry = FunctionRegistry::new();
    hypervisor::register_functions(&mut function_registry);

    (structure_registry, function_registry)
}

pub struct StructureRegistry {
    structures: HashMap<String, Box<dyn CloneableAny>>,
    instances: HashMap<String, Box<dyn CloneableAny>>,
}

impl StructureRegistry {
    pub fn new() -> Self {
        Self {
            structures: HashMap::new(),
            instances: HashMap::new(),
        }
    }

    pub fn register<T: CloneableAny + 'static>(&mut self, name: &str, structure: T) {
        self.structures
            .insert(name.to_string(), Box::new(structure));
    }

    pub fn get<T: 'static>(&self, name: &str) -> Option<&T> {
        self.structures
            .get(name)
            .and_then(|s| s.as_any().downcast_ref::<T>())
    }

    pub fn create_instance(&self, name: &str) -> Option<Box<dyn CloneableAny>> {
        self.structures.get(name).map(|s| s.clone_box())
    }

    pub fn register_instance(&mut self, name: &str, instance: Box<dyn CloneableAny>) {
        self.instances.insert(name.to_string(), instance);
    }

    pub fn get_instance(&self, name: &str) -> Option<&dyn CloneableAny> {
        self.instances.get(name).map(|s| s.as_ref())
    }

    pub fn print_instance(&self, name: &str) -> Option<String> {
        self.instances.get(name).and_then(|instance| {
            if let Some(struct_def) = instance.as_any().downcast_ref::<HashMap<String, String>>() {
                let mut output = String::new();
                for (key, value) in struct_def {
                    output.push_str(&format!("{}: {}\n", key, value));
                }
                Some(output)
            } else {
                eprintln!("Failed to downcast instance for {}", name);
                None
            }
        })
    }
}

pub fn initialize_registry() -> StructureRegistry {
    let mut registry = StructureRegistry::new();
    system_info::register_structures(&mut registry);
    registry
}

impl Clone for Box<dyn CloneableAny> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}
