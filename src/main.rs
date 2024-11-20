use anyhow::{Context, Error, Ok};
use bytes::{BufMut, BytesMut};
use clap::{self, Parser};
use cli::{Args, Command};
use core::str;
use peers::Peers;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{self};
use sha1::digest::typenum::bit;
use std::{io, net::SocketAddrV4, path::PathBuf, sync::Arc, time::Duration, vec};
use tokio::net::TcpStream;
use tokio::{io::AsyncReadExt, sync::Mutex};
use torrent::{Keys, Torrent};
use transport::Transport;
// Available if you need it!
// use serde_bencode

mod cli;
mod hs;
mod peers;
mod torrent;
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
        let message_size = protocol_id_length + 0x31; // from https://wiki.theory.org/BitTorrentSpecification#Handshake
        if raw.len() < message_size {
            return Err(Error::msg("Failed"));
        }
        let message = &raw[1..message_size];
        let protocol_id = &message[0..protocol_id_length];

        let info_hash: [u8; SHA1_HASH_BYTE_LENGTH] = message
            [protocol_id_length + 8..protocol_id_length + SHA1_HASH_BYTE_LENGTH + 8]
            .try_into()
            .map_err(|_| Error::msg("Failed"))?;
        let reserved: [u8; 8] = message[protocol_id_length..protocol_id_length + 8]
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

#[derive(Debug, Clone, Deserialize)]
struct PeerState {
    message_id: MessageId,
    bitfield: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Deserialize)]
enum MessageId {
    Choked = 0,
    Unchoked = 1,
    Interested = 2,
    NotInterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel = 8
}

impl From<PeerState> for BytesMut {
    fn from(value: PeerState) -> Self {
        let mut result = BytesMut::new();
        result.put_u32(1);
        match value.message_id {
            MessageId::Choked => result.put_u8(0),
            MessageId::Unchoked => result.put_u8(1),
            MessageId::Interested => result.put_u8(2),
            MessageId::NotInterested => result.put_u8(3),
            MessageId::Have => result.put_u8(4),
            MessageId::Bitfield => result.put_u8(5),
            MessageId::Request => result.put_u8(6),
            MessageId::Piece => result.put_u8(7),
            MessageId::Cancel => result.put_u8(8),
        }
        result
    }
}

impl PeerState {
    fn new() -> Self {
        PeerState {
            message_id: MessageId::Choked,
            bitfield: None,
        }
    }

    fn has_piece(&self, piece_index: usize) -> bool {
        let byte_index = piece_index / 8;
        let bit_index = 7 - (piece_index % 8);


        if let Some(bitfield) = &self.bitfield {
            if byte_index >= bitfield.len() {
                return false; // Out of range
            }
            (bitfield[byte_index] >> bit_index) & 1 == 1
        } else {
            return false
        }
    }
}

#[derive(Clone)]
struct TorrentClient {
    pub torrent: Torrent,
}

impl TorrentClient {
    pub async fn peers(torrent: Torrent) -> Result<TrackerResponse, Error> {
        let hash_info_encoded = torrent.url_encoded();

        let tracker_request = TrackerRequest {
            peer_id: String::from("00112233445566778899"),
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: torrent.info.plength,
            compact: 1,
        };

        let url_params = serde_urlencoded::to_string(&tracker_request).context("paramaters")?;
        let tracker_url = format!(
            "{}?{}&info_hash={}",
            torrent.announce, url_params, hash_info_encoded
        );
        let url = Url::parse(&tracker_url).expect("Parsing URL");
        let response = reqwest::get(url).await?.bytes().await?;
        let tracker_response: TrackerResponse =
            serde_bencode::from_bytes(&response).context("Parsing tracker response")?;
        Ok(tracker_response)
    }

    async fn handshake(&self, con: &mut TcpStream) -> Result<(), Error> {
        let info_hash = self.torrent.info_hash();

        let hanshake_message =
            HandshakeMessage::new(String::from("00112233445566778899"), info_hash, None);

        // Send handshake
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

        // Receive handshake
        loop {
            let mut buf = BytesMut::with_capacity(1);
            loop {
                con.readable().await.expect("Cannot read");
                con.read_buf(&mut buf).await.expect("Cannot read on buffer");
                break;
            }

            if let Some(handshake_protocol_id_length) = buf.first() {
                let handshake_first_byte = *handshake_protocol_id_length;

                if handshake_first_byte == 0 {
                    return Ok(());
                }

                let message_length = handshake_first_byte as usize + 50;
                let mut message_buf: Vec<u8> = Vec::with_capacity(message_length);
                message_buf.push(handshake_first_byte);

                con.read_buf(&mut message_buf)
                    .await
                    .expect("Cannot read on buffer");
                let handhsake_response = HandshakeMessage::try_from(message_buf).expect("A");

                if handhsake_response.info_hash != info_hash {
                    return Err(Error::msg(""));
                }
                break;
            }
        }
        Ok(())
    }

    async fn send_interested(con: &mut TcpStream) -> Result<(), Error> {
        let interested = PeerState {
            message_id: MessageId::Interested,
            bitfield: None,
        };
        con.writable().await?;
        let message: BytesMut = interested.into();
        con.try_write(message.as_ref())?;
        Ok(())
    }

    async fn send_unchoke(con: &mut TcpStream) -> Result<(), Error> {
        let interested = PeerState {
            message_id: MessageId::Unchoked,
            bitfield: None,
        };
        con.writable().await?;
        let message: BytesMut = interested.into();
        con.try_write(message.as_ref())?;
        Ok(())
    }

    pub async fn attempt_download(con: &mut TcpStream, index: usize) {
        
    }

    pub async fn new(&self, peer: SocketAddrV4) -> Result<(), Error> {
        let mut con =
            tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(peer)).await??;

        println!("Handshaking {:?}", peer);
        if let Err(error) = self.handshake(&mut con).await {
            panic!("Failed to handshake {}", error);
        }

        println!("Sending Unchoke to peer {:?}", peer);
        if let Err(_) = TorrentClient::send_unchoke(&mut con).await {
            panic!("Failed to interest torrent");
        }

        println!("Sending interesting to peer {:?}", peer);
        if let Err(_) = TorrentClient::send_interested(&mut con).await {
            panic!("Failed to interest torrent");
        }

        let peer_state = TorrentClient::process(&mut con).await?;
        println!("Peer {:?} of peer: {:?}", peer_state, peer);

        println!("Pieces hashes: {:?}", self.torrent.info.pieces.clone());

        for (i, _) in self.torrent.info.pieces.0.iter().enumerate() {
            println!("Peer contain piece of index {} -> {}", i, peer_state.has_piece(i))
        }
        println!("-----------------");
        Ok(())
    }

    async fn process(con: &mut TcpStream) -> Result<PeerState, Error> {
        loop {
            let mut length_buf = [0u8; 4];
            con.readable().await?;
            con.try_read(&mut length_buf)?;

            let message_length = u32::from_be_bytes(length_buf);
            if message_length == 0 {
                // Keep-alive message
                continue;
            }
            let mut message_buf: Vec<u8> = Vec::with_capacity(message_length as usize);
            con.read_buf(&mut message_buf).await?;

            match message_buf[0] {
                1 => {
                    return Ok(PeerState {
                        message_id: MessageId::Unchoked,
                        bitfield: None,
                    })
                }
                5 => {
                    let mut bitfield = Vec::new();
                    bitfield.push(message_buf[1]);
                    return Ok(PeerState {
                        message_id: MessageId::Unchoked,
                        bitfield: Some(bitfield),
                    });
                }
                a => println!("Received unknown message {}", a),
            }
        }
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
            println!("File name: {}", t.info.name);
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
            let peers = TorrentClient::peers(t).await?.peers;
            for peer in peers.0 {
                println!("{}:{}", peer.ip(), peer.port())
            }
            Ok(())
        }
        Command::Download { torrent } => {
            let t = parse_torrent(torrent)?;
            let peers = TorrentClient::peers(t.clone()).await?;

            let torrent_client = TorrentClient { torrent: t };
            for peer in peers.peers.0 {
                torrent_client.clone().new(peer).await?;
            }
            Ok(())
        }
    }
}

fn parse_torrent(path: PathBuf) -> Result<Torrent, Error> {
    let torrent_file = std::fs::read(path).unwrap();
    return Ok(serde_bencode::from_bytes::<Torrent>(&torrent_file)?);
}
