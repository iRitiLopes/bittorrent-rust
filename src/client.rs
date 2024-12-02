use crate::message::{Message, MessageFramer, MessageId};
use crate::peers::{Peer, Peers};
use crate::piece::Piece;
use crate::torrent::{self, Keys, Torrent};
use anyhow::{Context, Error, Ok};
use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::time::Duration;
use tokio::net::TcpStream;

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
#[allow(dead_code)]
pub struct TrackerResponse {
    pub interval: usize,
    pub peers: Peers,
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
pub struct TorrentClient {
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

    pub async fn download(&self, peer: Peer) -> Result<(), Error> {
        let timeout = Duration::from_secs(30);
        let mut con = tokio::time::timeout(timeout, TcpStream::connect(peer.address)).await??;

        
        println!("Handshaking {:?}", peer);
        if let Err(error) = peer.handshake(&mut con, self.torrent.info_hash()).await {
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

        peer_connection
            .send(Message {
                message_id: MessageId::Interested,
                payload: Some(Vec::new()),
            })
            .await?;
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
            println!(
                "Creating file {} with size {}",
                self.torrent.info.name, length
            );
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
}
