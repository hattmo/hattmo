use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::key_store::KeyStore;

use super::NodeId;

use core::convert::TryFrom;

pub struct LinkFrame<'a> {
    pub src: NodeId,
    pub dst: NodeId,
    pub hops: u8,
    pub data: &'a mut [u8],
}

pub enum LinkFrameType {
    Data,
    Authentication,
}

impl TryFrom<u8> for LinkFrameType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => LinkFrameType::Data,
            1 => LinkFrameType::Authentication,
            _ => return Err("Invalid Packet Type"),
        })
    }
}

pub struct Link<'ca> {
    state: LinkState,
    ca: &'ca VerifyingKey
}

pub enum LinkState {
    Authenticating(Option<EphemeralSecret>),
    Up(Aes256Gcm),
}

impl<'ca> Link<'ca> {
    pub fn new<T>(rng: T, ca: &'ca VerifyingKey) -> Self
    where
        T: RngCore + CryptoRng,
    {
        Self {
            ca,
            state: LinkState::Authenticating(Some(EphemeralSecret::random_from_rng(rng))),
        }
    }

    pub fn recieve<'a>(
        &mut self,
        data: &'a mut [u8],
    ) -> Result<Option<LinkFrame<'a>>, &'static str> {
        let (&mut ty, data) = data.split_first_mut().ok_or("Error")?;
        let ty = LinkFrameType::try_from(ty)?;
        match (ty, &mut self.state) {
            (LinkFrameType::Data, LinkState::Up(symetric_key)) => {
                let (nonce, data) = data.split_at_mut_checked(12).ok_or("Error")?;
                let (tag, data) = data.split_at_mut_checked(16).ok_or("Error")?;

                let nonce = Nonce::from_slice(nonce);
                let tag = Tag::from_slice(tag);
                symetric_key.decrypt_in_place_detached(nonce, Default::default(), data, tag);

                let (&mut src, data) = data.split_first_chunk_mut().ok_or("Error")?;
                let src = u64::from_le_bytes(src);
                let (&mut dst, data) = data.split_first_chunk_mut().ok_or("Error")?;
                let dst = u64::from_le_bytes(dst);
                let (&mut hops, data) = data.split_first_mut().ok_or("Error")?;
                Ok(Some(LinkFrame {
                    src: src.into(),
                    dst: dst.into(),
                    hops,
                    data,
                }))
            }

            // || DH_Key
            (LinkFrameType::Authentication, LinkState::Authenticating(dh_secret)) => {
                let data = KeyStore::verify(data, self.ca).or(Err("Invalid Auth Data"))?;
                let dh_pub: [u8; 32] = data.try_into().unwrap();
                let dh_pub = PublicKey::try_from(dh_pub).unwrap();
                let dh_secret = dh_secret.take().unwrap();
                let shared_secret = dh_secret.diffie_hellman(&dh_pub).to_bytes();
                let symetric_key = Aes256Gcm::new(&shared_secret.into());
                self.state = LinkState::Up(symetric_key);
                Ok(None)
            }
            _ => {
                todo!()
            }
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct LinkHandle(u32);

impl From<u32> for LinkHandle {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
