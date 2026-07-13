#![no_std]

extern crate core;

use aes_gcm::{AeadInPlace, Aes256Gcm, Nonce, Tag};
use core::convert::TryFrom;
use ed25519_dalek::{Signature, SignatureError, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};

enum LinkFrame<'a> {
    Packet(DataPacket<'a>),
    Authentication(AuthenticationPacket<'a>),
    Control(ControlPacket),
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
    src: NodeId,
    dst: NodeId,
    hops: u8,
    data: &'a mut [u8],
}

pub struct AuthenticationPacket<'a> {
    pub_key: &'a VerifyingKey,
    sig: &'a Signature,
    dh_key: &'a PublicKey,
    dh_sig: &'a Signature,
}

pub struct ControlPacket;

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct NodeId(u64);

impl From<u64> for NodeId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct LinkHandle(u32);

impl From<u32> for LinkHandle {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

enum LinkState {
    Authenticating(EphemeralSecret),
    Up(Aes256Gcm),
}

struct Route {
    to: NodeId,
    via: LinkHandle,
    hops: u8,
}

impl Route {
    fn new(to: NodeId, via: LinkHandle, hops: u8) -> Self {
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

pub struct Router<T>
where
    T: CryptoRng + RngCore,
{
    id: u64,
    keystore: KeyStore,
    route_table: [Option<Route>; 128],
    links: [Option<(LinkHandle, LinkState)>; 32],
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

pub struct ProcessError;

pub enum FrameDestination {
    Local,
    LinkHandle(LinkHandle),
}

impl<'a, 'b, T> Router<T>
where
    T: CryptoRng + RngCore,
{
    pub fn new(
        id: u64,
        key_pair: &'b [u8; 64],
        sig: &'b [u8; 64],
        ca: &'b [u8; 32],
        rng_source: T,
    ) -> Result<Self, RouterError> {
        let keystore = KeyStore::new(key_pair, sig, ca)?;
        Result::Ok(Self {
            id,
            keystore,
            links: [const { Option::None }; 32],
            route_table: [const { Option::None }; 128],
            rng_source,
        })
    }

    pub fn process_inbound(
        &mut self,
        from_link: LinkHandle,
        data: &'a mut [u8],
    ) -> Result<(FrameDestination, &'a [u8]), ProcessError> {
        let (_, state) = self
            .links
            .iter_mut()
            .flatten()
            .find(|(h, _)| h == &from_link)
            .ok_or(ProcessError)?;
        let data = LinkFrame::parse(data, state).or(Err(ProcessError))?;
        match data {
            LinkFrame::Packet(data) => {
                self.update_route_table(&data, from_link);
                todo!()
            }
            LinkFrame::Authentication(authentication_packet) => todo!(),
            LinkFrame::Control(control_packet) => todo!(),
        }
    }

    pub fn process_finish(&mut self) -> (FrameDestination, &[u8]) {
        todo!()
    }

    pub fn create_link_client(&mut self) -> Result<LinkHandle, CreateLinkError> {
        let secret: EphemeralSecret = EphemeralSecret::random_from_rng(&mut self.rng_source);
        let state = LinkState::Authenticating(secret);
        let open = self
            .links
            .iter_mut()
            .find(|i| i.is_none())
            .ok_or(CreateLinkError)?;
        let handle: LinkHandle = self.rng_source.next_u32().into();
        let _ = open.insert((handle, state));
        todo!()
    }

    pub fn destroy_interface(link: LinkHandle) {
        todo!()
    }

    fn update_route_table(
        &mut self,
        DataPacket {
            src,
            dst,
            hops,
            data,
        }: &DataPacket,
        from_link: LinkHandle,
        time: Instant
    ) {
        if let Some(route) = self.route_table.iter_mut().flatten().find(|i| &i.to == src) {
            if route.hops > *hops {
                route.via = from_link;
                route.hops = *hops;
            }
        }else {
            if let Some(free) = self.route_table.iter_mut().find(|i|Option::is_none(i)) {
                let _ = free.insert(Route::new(*src, from_link, *hops));

            };
        }


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
