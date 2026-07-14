use ed25519_dalek::Signature;
use aes_gcm::{Nonce, Tag};

use super::{Authenticating, LinkState, NodeId, Up};

use core::convert::TryFrom;

pub enum LinkFrame<'a> {
    Packet(DataPacket<'a>),
    Authentication(AuthenticationPacket<'a>),
    Control(ControlPacket),
}

pub enum LinkFrameType {
    Packet,
    Authentication,
}

impl TryFrom<u8> for LinkFrameType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => LinkFrameType::Packet,
            1 => LinkFrameType::Authentication,
            _ => return Err("Invalid Packet Type"),
        })
    }
}

impl<'a> LinkFrame<'a> {
    pub fn parse(data: &'a mut [u8], state: &LinkState) -> Result<Self, &'static str> {
        let (&mut ty, data) = data.split_first_mut().ok_or("Error")?;
        let ty = LinkFrameType::try_from(ty)?;
        match (ty, state) {
            (LinkFrameType::Packet, LinkState::Up(state)) => {
                let (nonce, data) = data.split_at_mut_checked(12).ok_or("Error")?;
                let nonce = Nonce::from_slice(nonce);
                let (tag, data) = data.split_at_mut_checked(16).ok_or("Error")?;
                let tag = Tag::from_slice(tag);
                state.decrypt_in_place_detached(nonce, Default::default(), data, tag);

                let (&mut src, data) = data.split_first_chunk_mut().ok_or("Error")?;
                let src = u64::from_le_bytes(src);
                let (&mut dst, data) = data.split_first_chunk_mut().ok_or("Error")?;
                let dst = u64::from_le_bytes(dst);
                let (&mut hops, data) = data.split_first_mut().ok_or("Error")?;
                return Ok(Self::Packet(DataPacket {
                    src: src.into(),
                    dst: dst.into(),
                    hops,
                    data,
                }));
            }
            (LinkFrameType::Authentication, LinkState::Authenticating(secret)) => {}
            _ => {
                todo!()
            }
        }
        Ok(todo!())
    }
}

pub struct DataPacket<'a> {
    pub src: NodeId,
    pub dst: NodeId,
    pub hops: u8,
    pub data: &'a mut [u8],
}

pub struct AuthenticationPacket<'a> {
    pub pub_key: &'a VerifyingKey,
    pub sig: &'a Signature,
    pub dh_key: &'a PublicKey,
    pub dh_sig: &'a Signature,
}

pub struct ControlPacket;
