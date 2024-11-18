use bytes::{buf, BufMut, BytesMut};
use cli::{Args, Command};
use anyhow::{Context, Error, Ok};
use clap::{self, Parser};
use tokio::{io::AsyncReadExt, stream, sync::Mutex};
use torrent::{Keys, Torrent};
use transport::Transport;
use core::str;
use peers::Peers;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{self};
use std::{io, path::PathBuf, sync::Arc, time::Duration};
use tokio::net::TcpStream;
// Available if you need it!
// use serde_bencode

mod cli;
mod torrent;
mod hs;
mod peers;
mod transport;


#[derive(Debug, Clone, Serialize)]
pub struct TrackerRequest {
    pub peer_id: String,
    pub port: u16,
    pub uploaded: usize,
    pub downloaded: usize,
    pub left: usize,
    pub compact: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrackerResponse {
    pub interval: usize,
    pub peers: Peers,
}

struct TorrentClient {
    pub torrent: Torrent
}

const DEFAULT_PROTOCOL_ID: &str = "BitTorrent protocol";
pub const SHA1_HASH_BYTE_LENGTH: usize = 20;

#[derive(Debug, Clone, Deserialize)]
pub struct HandshakeMessage {
    peer_id: String,
    info_hash: [u8; 20],
    protocol_id: String,
}

impl From<HandshakeMessage> for BytesMut {
    fn from(msg: HandshakeMessage) -> Self {
        let mut result = BytesMut::new();
        result.put_u8(msg.protocol_id.len() as u8);
        result.put_slice(msg.protocol_id.as_bytes());
        result.put_slice(&[0; 8]);
        result.put_slice(msg.info_hash.as_slice());
        result.put_slice(msg.peer_id.as_bytes());
        result
    }
}

impl TryFrom<Vec<u8>> for HandshakeMessage {
    type Error = Error;
    fn try_from(raw: Vec<u8>) -> Result<Self, Self::Error> {
        let protocol_id_length = raw.first().expect("Missing");
        let protocol_id_length = *protocol_id_length as usize;
        let message_size = protocol_id_length + 49; // from https://wiki.theory.org/BitTorrentSpecification#Handshake
        if raw.len() < message_size {
            return Err(Error::msg("Failed"));
        }
        let message = &raw[1..message_size];
        let protocol_id = &message[0..protocol_id_length];
        let info_hash: [u8; SHA1_HASH_BYTE_LENGTH] = message
            [protocol_id_length + 8..protocol_id_length + SHA1_HASH_BYTE_LENGTH + 8]
            .try_into()
            .map_err(|_| Error::msg("Failed"))?;
        let peer_id = &message[protocol_id_length + SHA1_HASH_BYTE_LENGTH + 8..];
        Ok(Self::new(
            String::from_utf8_lossy(peer_id).to_string(),
            info_hash,
            Some(String::from_utf8_lossy(protocol_id).to_string()),
        ))
    }
}

pub struct PeerConnection<S>
where
    S: Transport,
{
    stream: Arc<Mutex<S>>,
    io_timeout: Duration,
}

impl<T: Transport> PeerConnection<T> {
    pub fn new(stream: T, io_timeout: Duration) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            io_timeout,
        }
    }
}

impl HandshakeMessage {
    pub fn new(peer_id: String, info_hash: [u8; 20], protocol_id: Option<String>) -> Self {
        let mut protocol_id_final = DEFAULT_PROTOCOL_ID.to_string();
        if let Some(proto_id) = protocol_id {
            protocol_id_final = proto_id;
        }
        Self {
            peer_id,
            info_hash,
            protocol_id: protocol_id_final,
        }
    }
}

impl TorrentClient {
    pub async fn peers(self) -> Result<Peers, Error> {
        let hash_info_encoded = self.torrent.url_encoded();

        let tracker_request = TrackerRequest {
            peer_id: String::from("00112233445566778899"),
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: self.torrent.info.plength,
            compact: 1,
        };

        let url_params = serde_urlencoded::to_string(&tracker_request).context("paramaters")?;
        let tracker_url = format!(
            "{}?{}&info_hash={}",
            self.torrent.announce, url_params, hash_info_encoded
        );
        let url = Url::parse(&tracker_url).expect("Parsing URL");
        let response = reqwest::get(url).await?.bytes().await?;
        let tracker_response: TrackerResponse = serde_bencode::from_bytes(&response).context("Parsing tracker response")?;
        Ok(tracker_response.peers)
    }

    pub async fn handshake(self) -> Result<(), Error> {
        let info_hash = self.torrent.info_hash();
        let peers = self.peers().await?;
        
        for peer in peers.0 {
            let hanshake_message = HandshakeMessage::new(
                String::from("00112233445566778899"),
                info_hash,
                 None
            );
            let mut con = tokio::time::timeout(
                Duration::from_secs(30), 
                TcpStream::connect(peer)
            ).await??;

            let message: BytesMut = hanshake_message.into();
            loop {
                con.writable().await?;
                match con.try_write(message.as_ref()) {
                    Result::Ok(_) => {
                        break;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(error) => {
                        return Result::Err(Error::msg(error));
                    }
                }
            }

            let mut read_buf = [0u8; 1];
            loop {
                con.readable().await?;
                match con.try_read(&mut read_buf) {
                    Result::Ok(_) => break,
                    Err(_) => continue,
                }
            }
            if let Some(handshake_protocol_id_length) = read_buf.first() {
                let handshake_first_byte = *handshake_protocol_id_length;
                let handshake_length = handshake_first_byte as usize + 50;
                println!("Peer {}, Handshake response length: {}", peer, handshake_length);

                let mut buf = Vec::with_capacity(handshake_length);
                buf.push(handshake_first_byte);
                con.read_buf(&mut buf).await?;
                if !buf.is_empty() {
                    let response_handshake = HandshakeMessage::try_from(buf)?;
                    println!(
                        "[{0}:{1}] handshake response received: {2:?}",
                        peer.ip(),
                        peer.port(),
                        response_handshake
                    );
                    
                    if response_handshake.info_hash.as_slice() != info_hash.as_slice() {
                        println!("{0:?} != {1:?}", info_hash, response_handshake.info_hash);
                        return Result::Err(Error::msg("Invalid response"));
                    }

                    println!("[{0}:{1}] handshake is valid", peer.ip(), peer.port());
                }
            }
        }

        Ok(())
    }
}

#[allow(dead_code)]
fn decode(encoded_value: &str) -> (serde_json::Value, &str) {
    match encoded_value.chars().next() {
        Some('i') => {
            if let Some((n, rest)) =
                encoded_value
                    .split_at(1)
                    .1
                    .split_once('e')
                    .and_then(|(digits, rest)| {
                        let n = digits.parse::<i64>().ok()?;
                        Some((n, rest))
                    })
            {
                return (n.into(), rest);
            }
            return (0.into(), encoded_value);
        }
        Some('l') => {
            let mut values = Vec::new();
            let mut rest = encoded_value.split_at(1).1;

            while !rest.is_empty() && !rest.starts_with('e') {
                let (v, remainder) = decode(rest);
                values.push(v);
                rest = remainder;
            }
            return (values.into(), &rest[1..]);
        }
        Some('0'..='9') => {
            if let Some((len, rest)) = encoded_value.split_once(':') {
                if let std::result::Result::Ok(len) = len.parse::<usize>() {
                    return (rest[..len].to_string().into(), &rest[len..]);
                }
            }
        }
        Some('d') => {
            let mut dict = serde_json::Map::new();
            let mut rest = encoded_value.split_at(1).1;
            while !rest.is_empty() && !rest.starts_with('e') {
                let (k, remainder) = decode(rest);
                let k = match k {
                    serde_json::Value::String(k) => k,
                    _ => {
                        panic!("Missing string on k")
                    }
                };
                let (v, remainder) = decode(remainder);
                dict.insert(k, v);
                rest = remainder;
            }
            return (dict.into(), &rest[1..]);
        }
        _ => {}
    }
    panic!("aaaa")
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    match args.command {
        Command::Decode { value } => {
            let decoded = decode(&value).0;
            println!("{}", decoded.to_string());
            Ok(())
        }
        Command::Info { torrent } => {
            let t = parse_torrent(torrent)?;
            println!("Tracker URL: {}", t.announce);
            match t.info.keys {
                Keys::SingleFile { length } => {
                    println!("Length: {length}");
                }
                Keys::MultiFile { files: _ } => {
                    todo!()
                }
            };
            let hash_info: String = hex::encode(t.info_hash());
            println!("Info Hash: {hash_info}");
            println!("Piece Length: {}", t.info.plength);
            println!("Piece Hashes:");
            for ele in t.info.pieces.0 {
                println!("{}", hex::encode(&ele));
            }
            Ok(())
        }
        Command::Peers { torrent } => {
            let t = parse_torrent(torrent)?;
            let torrent_client= TorrentClient{torrent: t};
            let peers = torrent_client.peers().await?;
            for peer in peers.0 {
                println!("{}:{}", peer.ip(), peer.port())
            }
            Ok(())
        },
        Command::Handshake { torrent } => {
            let t = parse_torrent(torrent)?;
            let info_hash = t.info_hash();
            let torrent_client = TorrentClient{torrent: t};
            torrent_client.handshake().await?;
            Ok(())
        }
    }
}


fn parse_torrent(path: PathBuf) -> Result<Torrent, Error> {
    let torrent_file = std::fs::read(path).unwrap();
    return Ok(serde_bencode::from_bytes::<Torrent>(&torrent_file)?);
}
