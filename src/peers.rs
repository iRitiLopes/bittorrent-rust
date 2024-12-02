use anyhow::{Error, Ok};
use bytes::{BufMut, BytesMut};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{io, net::SocketAddrV4};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use std::fmt;

use std::net::{Ipv4Addr};

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

#[derive(Debug, Clone)]
pub struct Peer{
    pub address: SocketAddrV4
}

impl Peer {
    pub async fn handshake(&self, con: &mut TcpStream, info_hash: [u8; 20]) -> Result<(), Error> {
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
}

#[derive(Debug, Clone)]
pub struct Peers(pub Vec<Peer>);
struct PeersVisitor;

impl<'de> Visitor<'de> for PeersVisitor {
    type Value = Peers;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("6 bytes, the first 4 bytes are ip address and last 2 is the port")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() % 6 != 0 {
            return Err(E::custom("Failed to parse ip address"));
        }
        let x = v
            .chunks_exact(6)
            .map(|slice_of| {
                let ipv4 = Ipv4Addr::new(slice_of[0], slice_of[1], slice_of[2], slice_of[3]);
                let port = u16::from_be_bytes([slice_of[4], slice_of[5]]);
                SocketAddrV4::new(ipv4, port)
            })
            .map(|p| Peer{address: p})
            .collect();

        std::result::Result::Ok(Peers(x))
    }
}

impl<'de> Deserialize<'de> for Peers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PeersVisitor)
    }
}

impl Serialize for Peers {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut single_slice = Vec::with_capacity(6 * self.0.len());
        for peer in &self.0 {
            single_slice.extend(peer.address.ip().octets());
            single_slice.extend(peer.address.port().to_be_bytes());
        }
        serializer.serialize_bytes(&single_slice)
    }
}
