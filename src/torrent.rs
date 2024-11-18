use ::sha1::{Digest, Sha1};
use core::str;
use serde::{Deserialize, Serialize};

use crate::hs::Hashes;


#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Torrent {
    pub announce: String,
    pub info: Info,
}

impl Torrent {
    pub fn info_hash(&self) -> [u8; 20] {
        let mut hasher = Sha1::new();
        let info_encoded = serde_bencode::to_bytes(&self.info).expect("Reencoding");
        hasher.update(&info_encoded);
        return hasher.finalize().try_into().expect("Generating");
    }

    pub fn url_encoded(&self) -> String {
        let hash_info = self.info_hash();
        let mut encoded = String::with_capacity(3 * hash_info.len());
        for &byte in &hash_info {
            encoded.push('%');
            encoded.push_str(&hex::encode(&[byte]));
        }
        encoded
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Info {
    pub name: String,

    #[serde(rename = "piece length")]
    pub plength: usize,

    pub pieces: Hashes,

    #[serde(flatten)]
    pub keys: Keys,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
#[serde(untagged)]
pub enum Keys {
    SingleFile { length: usize },
    MultiFile { files: Vec<File> },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct File {
    pub length: usize,
    pub path: Vec<String>,
}