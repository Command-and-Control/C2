pub struct MLangParser;

impl MLangParser {
    pub fn parse(code: &str) -> Vec<MLangCommand> {
        code.lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    return None;
                }
                let command = parts[0];
                let args = parts[1..].to_vec();
                let (output_struct, struct_instance, struct_field) =
                    if command == "call" && args.len() > 2 {
                        (Some(args[2].to_string()), None, None)
                    } else {
                        (None, None, None)
                    };
                Some(MLangCommand {
                    command: command.to_string(),
                    args: args.iter().map(|&s| s.to_string()).collect(),
                    output_struct,
                    struct_instance,
                    struct_field,
                })
            })
            .collect()
    }
}

pub struct MLangCommand {
    pub command: String,
    pub args: Vec<String>,
    pub output_struct: Option<String>,
    pub struct_instance: Option<String>,
    pub struct_field: Option<String>,
}
