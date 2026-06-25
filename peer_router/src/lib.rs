#![no_std]

extern crate core;

use rand_core::{CryptoRng, RngCore};

use core::convert::TryFrom;

use arrayvec::ArrayVec;

use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Nonce, Tag};

use ed25519_dalek::{
    ed25519::signature::SignerMut, Signature, SignatureError, SigningKey, Verifier, VerifyingKey,
};

use x25519_dalek::{EphemeralSecret, PublicKey};

enum LinkFrame<'a> {
    Packet(DataPacket<'a>),
    Authentication(AuthenticationPacket<'a>),
}
enum LinkFrameType {
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
                return Ok(LinkFrame::Packet(DataPacket {
                    src,
                    dst,
                    hops,
                    data,
                }));
            }
            _ => {}
        }
        Ok(todo!())
    }
}

pub struct DataPacket<'a> {
    src: u64,
    dst: u64,
    hops: u8,
    data: &'a mut [u8],
}

impl<'a> DataPacket<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            src: 0,
            dst: 0,
            hops: 0,
            data: buffer,
        }
    }
}

pub struct AuthenticationPacket<'a> {
    pub_key: &'a VerifyingKey,
    sig: &'a Signature,
    dh_key: &'a PublicKey,
    dh_sig: &'a Signature,
}

#[derive(PartialEq, Eq)]
pub struct LinkHandle(usize);

enum LinkState {
    Authenticating(EphemeralSecret),
    Up(Aes256Gcm),
}

struct Route {
    to: u64,
    via: u16,
    hops: u8,
}

impl Route {
    fn new(to: u64, via: u16, hops: u8) -> Self {
        Self { to, via, hops }
    }
}

struct KeyStore {
    key_pair: SigningKey,
    ca: VerifyingKey,
    sig: Signature,
}

impl KeyStore {
    fn new(key_pair: &[u8; 64], sig: &[u8; 64], ca: &[u8; 32]) -> Result<Self, SignatureError> {
        let key_pair = SigningKey::from_keypair_bytes(key_pair)?;
        let cert = key_pair.verifying_key();
        let ca = VerifyingKey::from_bytes(ca)?;
        let sig = Signature::from_bytes(sig);
        ca.verify(cert.as_bytes(), &sig)?;

        Ok(Self { key_pair, ca, sig })
    }
}

pub struct Router<'a, const MAX_PACKET: usize, T>
where
    T: CryptoRng + RngCore,
{
    id: u64,
    keystore: KeyStore,
    route_table: [Option<Route>; 128],
    links: [Option<(LinkHandle, LinkState)>; 32],
    packet_buffers: &'a mut [[u8; MAX_PACKET]],
    rng_source: T,
}

pub enum RouterError {
    SignatureError(SignatureError),
}

impl From<SignatureError> for RouterError {
    fn from(value: SignatureError) -> Self {
        RouterError::SignatureError(value)
    }
}

pub struct CreateLinkError;

impl<'a, 'b, const MAX_PACKET: usize, T> Router<'a, MAX_PACKET, T>
where
    T: CryptoRng + RngCore,
{
    pub fn new(
        id: u64,
        key_pair: &'b [u8; 64],
        sig: &'b [u8; 64],
        ca: &'b [u8; 32],
        buffers: &'a mut [u8],
        rng_source: T,
    ) -> Result<Self, RouterError> {
        let keystore = KeyStore::new(key_pair, sig, ca)?;
        let (_, packet_buffers, _) = unsafe { buffers.align_to_mut::<[u8; MAX_PACKET]>() };
        Result::Ok(Self {
            id,
            keystore,
            packet_buffers,
            links: [const { Option::None }; 32],
            route_table: [const { Option::None }; 128],
            rng_source
        })
    }

    pub fn process(&mut self, from_link: LinkHandle, data: &mut [u8]) {
        let Some((_, state)) = self
            .links
            .iter_mut()
            .flatten()
            .find(|(h, _)| h == &from_link)
        else {
            return;
        };
        let Ok(data) = LinkFrame::parse(data, state) else {
            return;
        };
    }

    pub fn create_link_client(&mut self) -> Result<LinkHandle, CreateLinkError> {
        let secret: EphemeralSecret = EphemeralSecret::random_from_rng(&mut self.rng_source);
        todo!()
    }

    pub fn destroy_interface(link: LinkHandle) {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use aes_gcm::{
        aead::{consts::U12, AeadInPlace},
        Aes256Gcm, Key, KeyInit, Nonce,
    };

    use crate::Router;

    //#[test]
    //fn foo() {
    //    let mut buffer = [0u8; 1024];
    //    let key = [0u8; 64];
    //    let Ok(mut router) = Router::new(1337, &key, &key[..32].try_into().unwrap()) else {
    //        return;
    //    };
    //    let Ok(link_token) = router.create_link(&mut buffer) else {
    //        return;
    //    };
    //    let Some(link) = router.get_link(&link_token) else {
    //        return;
    //    };
    //    let key: &Key<Aes256Gcm> = &[0; 32].into();
    //    let nonce: Nonce<U12> = [0u8; 12].into();
    //    let mut cipher = Aes256Gcm::new(key);
    //    let mut inplace = [0u8; 100];
    //    let tag = cipher
    //        .encrypt_in_place_detached(&nonce, &[0], &mut inplace)
    //        .unwrap();
    //    let foo = cipher
    //        .decrypt_in_place_detached(&nonce, &[0], &mut inplace, &tag)
    //        .unwrap();
    //}
}
