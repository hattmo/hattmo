use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce, Tag};
use x25519_dalek::{ReusableSecret, PublicKey};

use crate::{
    key_store::{KeyStore, SIGNED_DATA_HEADER_SIZE},
    NodeId,
};

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const NODE_ID_SIZE: usize = size_of::<NodeId>();
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const HOP_SIZE: usize = size_of::<Hop>();

pub const SYNC_MESSAGE_SIZE: usize = SIGNED_DATA_HEADER_SIZE + PUBLIC_KEY_SIZE;

type Hop = u8;

pub struct LinkFrame<'a> {
    pub src: NodeId,
    pub dst: NodeId,
    pub hops: Hop,
    buffer: &'a mut [u8],
}

impl<'a> LinkFrame<'a> {
    pub fn data(&mut self) -> &mut [u8] {
        &mut self.buffer[(2 * NODE_ID_SIZE + HOP_SIZE + NONCE_SIZE + TAG_SIZE)..]
    }
}

pub struct Link {
    key: Aes256Gcm,
}

impl Link {
    pub fn recieve<'a>(&self, data: &'a mut [u8]) -> Result<LinkFrame<'a>, &'static str> {
        let (nonce, rest) = data.split_at_mut_checked(NONCE_SIZE).ok_or("Error")?;
        let (tag, rest) = rest.split_at_mut_checked(TAG_SIZE).ok_or("Error")?;
        let nonce = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag);
        self.key
            .decrypt_in_place_detached(nonce, Default::default(), rest, tag);
        let (&mut src, rest) = rest.split_first_chunk_mut().ok_or("Error")?;
        let src = u64::from_le_bytes(src);
        let (&mut dst, rest) = rest.split_first_chunk_mut().ok_or("Error")?;
        let dst = u64::from_le_bytes(dst);
        let (&mut hops, _) = rest.split_first_mut().ok_or("Error")?;
        Ok(LinkFrame {
            src: src.into(),
            dst: dst.into(),
            hops,
            buffer: data,
        })
    }
    pub fn send(&self, data: LinkFrame) -> Result<&[u8], &'static str> {
        todo!()
    }
}

struct UnestablishedLink<'ks> {
    secret: ReusableSecret,
    keystore: &'ks KeyStore,
}

impl<'ks> UnestablishedLink<'ks> {
    pub fn recieve(&self, data: &[u8]) -> Result<Link, &'static str> {
        let Self { secret, keystore } = self;
        let (header, rest) = data.split_first_chunk().unwrap();
        let (public_bytes, _) = rest.split_first_chunk::<PUBLIC_KEY_SIZE>().unwrap();
        if let Err(_) = keystore.verify(public_bytes, header) {
            return Err("Unsigned Data");
        };
        let dh_pub: PublicKey = (*public_bytes).into();
        let shared_secret = secret.diffie_hellman(&dh_pub).to_bytes();
        let key = Aes256Gcm::new(&shared_secret.into());
        Ok(Link { key })
    }
    pub fn send<'a, 'b>(&'a self, data: &'b mut [u8]) -> &'b [u8] {
        let (header, rest) = data.split_first_chunk_mut().unwrap();
        let (public_bytes, _) = rest.split_first_chunk_mut::<PUBLIC_KEY_SIZE>().unwrap();
        let public_key: PublicKey = (&self.secret).into();
        public_bytes.copy_from_slice(public_key.as_bytes());
        self.keystore.sign(public_bytes, header);
        &data[..SYNC_MESSAGE_SIZE]
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct LinkHandle(u32);

impl From<u32> for LinkHandle {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
