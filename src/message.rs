use anyhow::{Error, Ok};
use bytes::{Buf, BufMut, BytesMut};
use serde::Deserialize;
use tokio_util::codec::{Decoder, Encoder};

const MAX_BLOCK_SIZE: u32 = 1 << 14;

#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    pub message_id: MessageId,
    pub payload: Option<Vec<u8>>,
}

pub struct MessageFramer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[repr(u8)]
pub enum MessageId {
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
    pub fn has_piece(&self, piece_index: usize) -> bool {
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