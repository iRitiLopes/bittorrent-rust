use anyhow::Context;
use clap::{self, command, Parser, Subcommand};
use ::hashes::sha1;
use ::sha1::{Sha1, Digest};
use core::{hash, str};
use hashes::Hashes;
use serde::{Deserialize, Serialize};
use serde_json::{self, to_vec};
use std::{hash::{DefaultHasher, Hash, Hasher}, path::PathBuf};
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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
struct Torrent {
    announce: String,
    info: Info,
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
                if let Ok(len) = len.parse::<usize>() {
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
fn main() {
    let args = Args::parse();
    
    match args.command {
        Command::Decode { value } => {
            let decoded = decode(&value).0;
            println!("{}", decoded.to_string())
        }
        Command::Info { torrent } => {
            let torrent_file = std::fs::read(torrent).unwrap();
            let t: Torrent = serde_bencode::from_bytes(&torrent_file).context("a").unwrap();
            println!("Tracker URL: {}", t.announce);
            match t.info.keys {
                Keys::SingleFile { length } => {
                    println!("Length: {length}");
                },
                Keys::MultiFile { files } => {
                    todo!()
                },
            };
            let mut hasher = Sha1::new();
            let info_encoded = serde_bencode::to_bytes(&t.info).expect("Reencoding");
            hasher.update(&info_encoded);
            let digest = hasher.finalize();
            println!("Info Hash: {digest:x}");
        }
    }
}

mod hashes {

    use serde::{de::{self, Deserialize, Deserializer, Visitor}, ser::{self, Serialize, Serializer}};

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
