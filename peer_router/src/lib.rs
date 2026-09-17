#![no_std]

extern crate core;

use ed25519_dalek::SignatureError;
use x25519_dalek::EphemeralSecret;

use rand_core::{CryptoRng, RngCore};

use key_store::KeyStore;
use link::{Link, LinkHandle};

mod key_store;
mod link;

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct NodeId(u64);

impl From<u64> for NodeId {
    fn from(value: u64) -> Self {
        Self(value)
    }
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
    T: CryptoRng,
{
    id: u64,
    keystore: KeyStore,
    route_table: [Option<Route>; 128],
    links: [Option<(LinkHandle, Link)>; 32],
    rng_source: T,
}

pub enum RouterError {
    KeyStoreError,
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
    T: CryptoRng,
{
    pub fn new(
        id: u64,
        key_pair: &[u8; 64],
        sig: &[u8; 64],
        ca: &[u8; 32],
        rng_source: T,
    ) -> Result<Self, RouterError> {
        let keystore = KeyStore::new(key_pair, sig, ca).or(Err(RouterError::KeyStoreError))?;
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
        data: &mut [u8],
    ) -> Result<(FrameDestination, &[u8]), ProcessError> {
        let (_, state) = self
            .links
            .iter_mut()
            .flatten()
            .find(|(h, _)| h == &from_link)
            .ok_or(ProcessError)?;
        match state.recieve(data) {
            Ok(Some(frame)) => if frame.dst == self.id {},
            Ok(None) => todo!(),
            Err(_) => todo!(),
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
        DataFrame {
            src,
            dst,
            hops,
            data,
        }: &DataFrame,
        from_link: LinkHandle,
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
