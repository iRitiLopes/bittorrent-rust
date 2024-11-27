use anyhow::{Context, Error, Ok};
use bytes::{Buf, BufMut, BytesMut};
use clap::{self, Parser};
use cli::{Args, Command};
use core::str;
use futures_util::{SinkExt, StreamExt};
use peers::Peers;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{self};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::{io, net::SocketAddrV4, path::PathBuf, time::Duration};
use tokio::net::TcpStream;
use tokio::io::AsyncReadExt;
use tokio_util::codec::{Decoder, Encoder};
use torrent::{Keys, Torrent};

mod cli;
mod hs;
mod peers;
mod torrent;

const MAX_BLOCK_SIZE: u32 = 1 << 14;

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

        let peer_id = &message[protocol_id_length + SHA1_HASH_BYTE_LENGTH + 8..];
        Ok(Self::new(
            String::from_utf8_lossy(peer_id).to_string(),
            info_hash,
            Some(String::from_utf8_lossy(protocol_id).to_string()),
        ))
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
pub struct Message {
    message_id: MessageId,
    payload: Option<Vec<u8>>,
}

pub struct MessageFramer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[repr(u8)]
enum MessageId {
    Choked = 0,
    Unchoked = 1,
    Interested = 2,
    NotInterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel = 8,
}

impl From<Message> for BytesMut {
    fn from(value: Message) -> Self {
        let mut result = BytesMut::new();
        if let Some(payload) = &value.payload {
            result.put_u32(1 + payload.len() as u32);
        } else {
            result.put_u32(1);
        }
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
        if let Some(payload) = value.payload {
            for bit in payload {
                result.put_u8(bit);
            }
        }

        result
    }
}

impl Decoder for MessageFramer {
    type Item = Message;

    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length == 0 {
            src.advance(4);
            return self.decode(src);
        }

        if src.len() < 5 {
            return Ok(None);
        }

        if length > MAX_BLOCK_SIZE as usize {
            //panic!("Frame of length {} is too large.", length);
        }

        if src.len() < 4 + length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        let tag = match src[4] {
            0 => MessageId::Choked,
            1 => MessageId::Unchoked,
            2 => MessageId::Interested,
            3 => MessageId::NotInterested,
            4 => MessageId::Have,
            5 => MessageId::Bitfield,
            6 => MessageId::Request,
            7 => MessageId::Piece,
            8 => MessageId::Cancel,
            _ => {
                return Err(Error::msg("a"));
            }
        };

        let data = if src.len() > 5 {
            src[5..4 + length].to_vec()
        } else {
            Vec::new()
        };

        src.advance(4 + length);

        Ok(Some(Message {
            message_id: tag,
            payload: Some(data),
        }))
    }
}

impl Encoder<Message> for MessageFramer {
    type Error = Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Don't send a message if it is longer than the other end will
        // accept.
        if let Some(payload) = item.payload {
            if payload.len() + 1 > MAX_BLOCK_SIZE as usize {
                return Err(Error::msg("a"));
            }

            // Convert the length into a byte array.
            let len_slice = u32::to_be_bytes(payload.len() as u32 + 1);

            // Reserve space in the buffer.
            dst.reserve(4 /* length */ + 1 /* tag */ + payload.len());

            // Write the length and string to the buffer.
            dst.extend_from_slice(&len_slice);
            dst.put_u8(item.message_id as u8);
            dst.extend_from_slice(&payload);
        }

        Ok(())
    }
}

impl Message {
    fn has_piece(&self, piece_index: usize) -> bool {
        let byte_index = piece_index / 8;
        let bit_index = 7 - (piece_index % 8);

        if let Some(bitfield) = &self.payload {
            if byte_index >= bitfield.len() {
                return false; // Out of range
            }
            (bitfield[byte_index] >> bit_index) & 1 == 1
        } else {
            return false;
        }
    }
}

pub struct Piece<T: ?Sized = [u8]> {
    index: [u8; 4],
    begin: [u8; 4],
    block: T,
}

impl Piece {
    pub fn index(&self) -> u32 {
        u32::from_be_bytes(self.index)
    }

    pub fn begin(&self) -> u32 {
        u32::from_be_bytes(self.begin)
    }

    pub fn block(&self) -> &[u8] {
        &self.block
    }

    const PIECE_LEAD: usize = std::mem::size_of::<Piece<()>>();
    pub fn ref_from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < Self::PIECE_LEAD {
            return None;
        }
        let n = data.len();
        // NOTE: The slicing here looks really weird. The reason we do it is because we need the
        // length part of the fat pointer to Piece to hold the length of _just_ the `block` field.
        // And the only way we can change the length of the fat pointer to Piece is by changing the
        // length of the fat pointer to the slice, which we do by slicing it. We can't slice it at
        // the front (as it would invalidate the ptr part of the fat pointer), so we slice it at
        // the back!
        let piece = &data[..n - Self::PIECE_LEAD] as *const [u8] as *const Piece;
        // Safety: Piece is a POD with repr(c) and repr(packed), _and_ the fat pointer data length
        // is the length of the trailing DST field (thanks to the PIECE_LEAD offset).
        Some(unsafe { &*piece })
    }
}

#[repr(C)]
#[repr(packed)]
pub struct Request {
    index: [u8; 4],
    begin: [u8; 4],
    length: [u8; 4],
}

impl Request {
    pub fn new(index: u32, begin: u32, length: u32) -> Self {
        Self {
            index: index.to_be_bytes(),
            begin: begin.to_be_bytes(),
            length: length.to_be_bytes(),
        }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        println!(
            "index: {} - begin: {} - length: {}",
            u32::from_be_bytes(self.index),
            u32::from_be_bytes(self.begin),
            u32::from_be_bytes(self.length)
        );
        let bytes = self as *mut Self as *mut [u8; std::mem::size_of::<Self>()];
        // Safety: Self is a POD with repr(c) and repr(packed)
        let bytes: &mut [u8; std::mem::size_of::<Self>()] = unsafe { &mut *bytes };
        bytes
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
        println!("{:?}", response);
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

    pub async fn attempt_download(
        con: &mut TcpStream,
        index: usize,
        torrent: &Torrent,
        file: &mut File,
    ) -> Result<(), Error> {
        let mut peer = tokio_util::codec::Framed::new(con, MessageFramer);

        let length = if let torrent::Keys::SingleFile { length } = torrent.info.keys {
            length
        } else {
            todo!();
        };

        let piece_size = if index == torrent.info.pieces.0.len() - 1 {
            let md = length % torrent.info.plength;
            if md == 0 {
                torrent.info.plength
            } else {
                md
            }
        } else {
            torrent.info.plength
        };

        let nblocks = (piece_size + (MAX_BLOCK_SIZE as usize - 1)) / MAX_BLOCK_SIZE as usize;
        let mut all_blocks: Vec<u8> = Vec::with_capacity(piece_size);
        for block in 0..nblocks {
            let block_size = if block == nblocks - 1 {
                let md = piece_size % MAX_BLOCK_SIZE as usize;
                if md == 0 {
                    MAX_BLOCK_SIZE as usize
                } else {
                    md
                }
            } else {
                MAX_BLOCK_SIZE as usize
            };
            let mut request = Request::new(
                index as u32,
                (block * MAX_BLOCK_SIZE as usize) as u32,
                block_size as u32,
            );
            let request_bytes = Vec::from(request.as_bytes_mut());
            peer.send(Message {
                message_id: MessageId::Request,
                payload: Some(request_bytes),
            })
            .await
            .with_context(|| format!("send request for block {block}"))?;

            let piece = peer
                .next()
                .await
                .expect("peer always sends a piece")
                .context("peer message was invalid")?;
            assert_eq!(piece.message_id, MessageId::Piece);
            assert!(!piece.payload.is_none());

            if let Some(piece) = &piece.payload {
                let piece = Piece::ref_from_bytes(&piece[..])
                    .expect("always get all Piece response fields from peer");
                assert_eq!(piece.index() as usize, index);
                assert_eq!(piece.begin() as usize, block * MAX_BLOCK_SIZE as usize);
                assert_eq!(piece.block().len(), block_size);
                println!("Piece size downloaded: {}", piece.block().len());
                all_blocks.extend(piece.block());
            }
        }

        file.write_all_at(&all_blocks, index as u64 * piece_size as u64)?;

        Ok(())
    }

    pub async fn new(&self, peer: SocketAddrV4) -> Result<(), Error> {
        let timeout = Duration::from_secs(30);
        let mut con = tokio::time::timeout(timeout, TcpStream::connect(peer)).await??;

        println!("Handshaking {:?}", peer);
        if let Err(error) = self.handshake(&mut con).await {
            panic!("Failed to handshake {}", error);
        }

        let mut peer_connection = tokio_util::codec::Framed::new(&mut con, MessageFramer);
        let bitfield = peer_connection
                .next()
                .await
                .expect("peer always sends an bitfield")
                .context("peer message was invalid")?;
        println!("Bitfield {:?}", bitfield.message_id);
        assert_eq!(bitfield.message_id, MessageId::Bitfield);

        peer_connection.send(Message { message_id: MessageId::Interested, payload: Some(Vec::new()) }).await?;
        let unchoked = peer_connection
                .next()
                .await
                .expect("peer always sends an unchoke")
                .context("peer message was invalid")?;
        println!("Unchoked {:?}", unchoked.message_id);
        assert_eq!(unchoked.message_id, MessageId::Unchoked);

        let peer_pieces = self
            .torrent
            .info
            .pieces
            .0
            .iter()
            .enumerate()
            .filter(|(idx, _)| bitfield.has_piece(*idx));

        let mut file = File::create(&self.torrent.info.name)?;
        if let Keys::SingleFile { length } = self.torrent.info.keys {
            println!("Creating file {} with size {}", self.torrent.info.name, length);
            //file.set_len(length as u64)?;
        }

        for (i, _) in peer_pieces {
            println!("Attempting to download the piece {}", i);
            TorrentClient::attempt_download(&mut con, i, &self.torrent, &mut file).await?;
        }
        println!("-----------------");
        file.sync_all()?;
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
            match &t.info.keys {
                Keys::SingleFile { length } => {
                    println!("Length: {length}");
                }
                Keys::MultiFile { files } => {
                    for (idx, f) in files.iter().enumerate() {
                        println!("File #{}: length {}", idx, f.length)
                    }
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
                println!("Downloading from Peer {}", peer);
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
