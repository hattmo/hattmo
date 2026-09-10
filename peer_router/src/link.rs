use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit, Nonce, Tag, aead::consts::U12, aes::cipher::InOutBuf};
use x25519_dalek::{rand_core::CryptoRng, PublicKey, ReusableSecret};

use crate::{
    key_store::{KeyStore, SIGNED_DATA_HEADER_SIZE},
    NodeId,
};

use core::convert::TryFrom;

pub struct LinkFrame<'a> {
    pub src: NodeId,
    pub dst: NodeId,
    pub hops: u8,
    buf: &'a mut [u8],
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

pub struct Link<'a> {
    state: LinkState,
    key_store: &'a KeyStore,
}

pub enum LinkState {
    Authenticating(ReusableSecret),
    Up(Aes256Gcm),
}

impl<'ks> Link<'ks> {
    pub fn new<'rng, T>(rng: &'rng mut T, key_store: &'ks KeyStore) -> Self
    where
        T: CryptoRng + ?Sized,
    {
        Self {
            key_store,
            state: LinkState::Authenticating(ReusableSecret::random_from_rng(rng)),
        }
    }

    pub fn recieve<'a>(
        &mut self,
        buf: &'a mut [u8],
    ) -> Result<Option<LinkFrame<'a>>, &'static str> {
        let (&mut ty, rest) = buf.split_first_mut().ok_or("Error")?;
        let ty = LinkFrameType::try_from(ty)?;
        match (ty, &mut self.state) {
            (LinkFrameType::Data, LinkState::Up(symetric_key)) => {
                let (nonce, rest) = rest.split_first_chunk::<12>().ok_or("Error")?;
                let (tag, rest) = rest.split_at_mut_checked(16).ok_or("Error")?;

                let nonce: Nonce<U12> = nonce.into();
                let tag: Tag = tag.try_into().unwrap();
                let data: InOutBuf<u8> = rest.into();
                symetric_key.decrypt_inout_detached(&nonce, Default::default(), data, &tag);

                let (&mut src, rest) = rest.split_first_chunk_mut().ok_or("Error")?;
                let src = u64::from_le_bytes(src);
                let (&mut dst, rest) = rest.split_first_chunk_mut().ok_or("Error")?;
                let dst = u64::from_le_bytes(dst);
                let (&mut hops, _) = rest.split_first_mut().ok_or("Error")?;
                Ok(Some(LinkFrame {
                    src: src.into(),
                    dst: dst.into(),
                    hops,
                    buf ,
                }))
            }

            // || DH_Key
            (LinkFrameType::Authentication, LinkState::Authenticating(dh_secret)) => {
                let (sig, data) = rest.split_at_checked(SIGNED_DATA_HEADER_SIZE).unwrap();
                self.key_store
                    .verify(data, sig.try_into().unwrap())
                    .or(Err("Invalid Auth Data"))?;
                let dh_pub: [u8; 32] = data.try_into().unwrap();
                let dh_pub = PublicKey::try_from(dh_pub).unwrap();
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
    pub fn get_sender(&mut self) -> SendState {
        match &mut self.state {
            LinkState::Authenticating(reusable_secret) => SendState::Authenticating(AuthSender {
                secret: reusable_secret,
                key_store: self.key_store,
            }),
            LinkState::Up(aes_gcm) => SendState::Up(UpSender(aes_gcm)),
        }
    }
}

enum SendState<'a> {
    Authenticating(AuthSender<'a>),
    Up(UpSender<'a>),
}

struct AuthSender<'a> {
    secret: &'a ReusableSecret,
    key_store: &'a KeyStore,
}

impl<'a> AuthSender<'a> {
    pub fn send(self, buf: &mut [u8]) -> &[u8] {
        let pub_key: PublicKey = self.secret.into();
        let pub_key = pub_key.as_bytes();
        let (buf, _) = buf
            .split_at_mut_checked(SIGNED_DATA_HEADER_SIZE + pub_key.len())
            .unwrap();
        let (header, data) = buf
            .split_first_chunk_mut::<SIGNED_DATA_HEADER_SIZE>()
            .unwrap();
        self.key_store.sign(pub_key, header);
        data.copy_from_slice(pub_key);
        buf
    }
}

struct UpSender<'a>(&'a mut Aes256Gcm);

impl<'a> UpSender<'a> {
    pub fn send(self, frame: LinkFrame) -> &[u8] {
        let UpSender(secret) = self;
        let LinkFrame { src, dst, hops, buf }  = frame;
        Nonce::generate();
        secret.encrypt_in_place_detached(nonce, Default::default(), buffer)
        todo!()

    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct LinkHandle(u32);

impl From<u32> for LinkHandle {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
