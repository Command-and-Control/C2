use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use xorcrypt::{e, prepare_encryption};

prepare_encryption!();

pub async fn download_file(data: &Vec<u8>) {
    let start_seq = e!("::STARTFILE::");
    let start_seq = start_seq.as_bytes();
    let start_data = e!("::STARTDATA::");
    let start_data = start_data.as_bytes();
    let stop_seq = e!("::ENDFILE::");
    let stop_seq = stop_seq.as_bytes();

    let filename = String::from_utf8(find_between(start_seq, start_data, data).await).unwrap();
    let filedata = find_between(start_data, stop_seq, data).await;

    tokio::fs::write(filename, filedata).await.unwrap();
}

async fn find_between(start_seq: &[u8], stop_seq: &[u8], buf: &[u8]) -> Vec<u8> {
    let start_index = buf
        .windows(start_seq.len())
        .position(|x| x == start_seq)
        .unwrap();
    let stop_index = buf
        .windows(stop_seq.len())
        .position(|x| x == stop_seq)
        .unwrap();
    buf[start_index + start_seq.len()..stop_index].to_vec()
}

pub async fn read(conn: &mut TcpStream) -> Option<Vec<u8>> {
    let mut read_buffer: Vec<u8> = vec![];
    let termination_str = e!("::OVER::");
    let termination_str = termination_str.as_bytes();

    loop {
        let mut buf = vec![0u8; 4096];
        match conn.try_read(&mut buf) {
            Ok(0) => break,
            Ok(bytes_read) => {
                read_buffer.extend_from_slice(&buf[..bytes_read]);
                if substr_exists(&read_buffer, termination_str).await {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => {
                eprintln!("Error reading from socket: {}", e);
                return None;
            }
        }
    }

    if let Some(position) = find_position(&read_buffer, termination_str).await {
        read_buffer = read_buffer[..position].to_vec()
    }
    Some(read_buffer)
}

pub async fn write(conn: &mut TcpStream, mut data: Vec<u8>) -> std::io::Result<()> {
    data.append(&mut e!("::OVER::").as_bytes().to_vec());
    conn.write_all(data.as_slice()).await
}

async fn write_file(conn: &mut TcpStream, data: Vec<u8>, filename: &[u8]) -> std::io::Result<()> {
    let mut start_seq = e!("::STARTFILE::").as_bytes().to_vec();
    let mut start_data = e!("::STARTDATA::").as_bytes().to_vec();
    let mut stop_seq = e!("::ENDFILE::").as_bytes().to_vec();

    let mut file_data: Vec<u8> = vec![];

    file_data.append(&mut start_seq);
    file_data.append(&mut filename.to_vec());
    file_data.append(&mut start_data);
    file_data.append(&mut data.to_vec());
    file_data.append(&mut stop_seq);
    file_data.append(&mut e!("::OVER::").as_bytes().to_vec());

    conn.write_all(file_data.as_slice()).await
}

pub async fn upload_file(conn: &mut TcpStream, filename: &String, data: Vec<u8>) -> Result<(), ()> {
    if write_file(conn, data, filename.as_bytes()).await.is_err() {
        return Err(());
    };
    Ok(())
}

async fn find_position(buf: &Vec<u8>, needle: &[u8]) -> Option<usize> {
    buf.windows(needle.len()).position(|x| x == needle)
}

pub async fn substr_exists(buf: &Vec<u8>, needle: &[u8]) -> bool {
    match find_position(buf, needle).await {
        Some(_) => true,
        None => false,
    }
}
