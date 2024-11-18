use serde::de::{self, Deserialize, Deserializer, Visitor};

use serde::ser::{Serialize, Serializer};

use std::fmt;

use std::net::{Ipv4Addr, SocketAddrV4};
#[derive(Debug, Clone)]

pub struct Peers(pub Vec<SocketAddrV4>);
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
            single_slice.extend(peer.ip().octets());
            single_slice.extend(peer.port().to_be_bytes());
        }
        serializer.serialize_bytes(&single_slice)
    }
}
