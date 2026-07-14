#![no_std]

extern crate core;

use aes_gcm::Aes256Gcm;
use ed25519_dalek::SignatureError;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::EphemeralSecret;

use crate::{key_store::KeyStore, link_frame::{DataPacket, LinkFrame}};

mod link_frame;
mod key_store;

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

impl<T> Router<T>
where
    T: CryptoRng + RngCore,
{
    pub fn new(
        id: u64,
        key_pair: &[u8; 64],
        sig: &[u8; 64],
        ca: &[u8; 32],
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

    pub fn process_inbound<'a>(
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

    pub fn destroy_link(link: LinkHandle) {
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
        time: Instant,
    ) {
        if let Some(route) = self.route_table.iter_mut().flatten().find(|i| &i.to == src) {
            if route.hops > *hops {
                route.via = from_link;
                route.hops = *hops;
            }
        } else {
            if let Some(free) = self.route_table.iter_mut().find(|i| Option::is_none(i)) {
                let _ = free.insert(Route::new(*src, from_link, *hops));
            };
        }
        todo!()
    }
}
