use ::sha1::{Digest, Sha1};
use anyhow::{Context, Error, Ok};
use clap::{self, command, Parser, Subcommand};
use core::str;
use hashes::Hashes;
use peers::Peers;
use reqwest::{Method, Request, Url};
use serde::{Deserialize, Serialize};
use serde_json::{self, to_vec};
use sha1::{digest::core_api::CoreWrapper, Sha1Core};
use std::path::PathBuf;
// Available if you need it!
// use serde_bencode

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
#[allow(dead_code)]
enum Command {
    Decode { value: String },
    Info { torrent: PathBuf },
    Peers { torrent: PathBuf },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
struct Torrent {
    announce: String,
    info: Info,
}

impl Torrent {
    fn info_hash(&self) -> [u8; 20] {
        let mut hasher = Sha1::new();
        let info_encoded = serde_bencode::to_bytes(&self.info).expect("Reencoding");
        hasher.update(&info_encoded);
        return hasher.finalize().try_into().expect("Generating");
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
struct Info {
    name: String,

    #[serde(rename = "piece length")]
    plength: usize,

    pieces: Hashes,

    #[serde(flatten)]
    keys: Keys,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
#[serde(untagged)]
enum Keys {
    SingleFile { length: usize },
    MultiFile { files: Vec<File> },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
struct File {
    length: usize,
    path: Vec<String>,
}

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
                Keys::MultiFile { files } => {
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
            let hash_info: [u8; 20] = t.info_hash();
            let hash_info_encoded = urlencode(&hash_info);

            let tracker_request = TrackerRequest {
                peer_id: String::from("00112233445566778899"),
                port: 6881,
                uploaded: 0,
                downloaded: 0,
                left: t.info.plength,
                compact: 1,
            };

            let url_params = serde_urlencoded::to_string(&tracker_request).context("paramaters")?;
            let tracker_url = format!(
                "{}?{}&info_hash={}",
                t.announce, url_params, hash_info_encoded
            );
            let url = Url::parse(&tracker_url).expect("Parsing URL");
            let response = reqwest::get(url).await?.bytes().await?;
            let tracker_response: TrackerResponse =
                serde_bencode::from_bytes(&response).context("Parsing tracker response")?;
            for peer in tracker_response.peers.0 {
                println!("{} {}", peer.ip(), peer.port())
            }
            Ok(())
        }
    }
}

fn urlencode(t: &[u8; 20]) -> String {
    let mut encoded = String::with_capacity(3 * t.len());
    for &byte in t {
        encoded.push('%');
        encoded.push_str(&hex::encode(&[byte]));
    }
    encoded
}

fn parse_torrent(path: PathBuf) -> Result<Torrent, Error> {
    let torrent_file = std::fs::read(path).unwrap();
    return Ok(serde_bencode::from_bytes::<Torrent>(&torrent_file)?);
}

mod peers {
    use anyhow::Ok;
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
}

mod hashes {

    use serde::{
        de::{self, Deserialize, Deserializer, Visitor},
        ser::{self, Serialize, Serializer},
    };

    use std::fmt;

    #[derive(Debug, Clone)]

    pub struct Hashes(pub Vec<[u8; 20]>);

    struct HashesVisitor;

    impl Hashes {
        // fn to_sha1(&self) {
        //     return sha1::hash(self.0.to_vec());
        // }
    }

    impl<'de> Visitor<'de> for HashesVisitor {
        type Value = Hashes;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a byte string whose length is a multiple of 20")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v.len() % 20 != 0 {
                return Err(E::custom(format!("length is {}", v.len())));
            }

            // TODO: use array_chunks when stable

            Ok(Hashes(
                v.chunks_exact(20)
                    .map(|slice_20| slice_20.try_into().expect("guaranteed to be length 20"))
                    .collect(),
            ))
        }
    }

    impl<'de> Deserialize<'de> for Hashes {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(HashesVisitor)
        }
    }

    impl Serialize for Hashes {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let single_slice = self.0.concat();
            serializer.serialize_bytes(&single_slice)
        }
    }
}
