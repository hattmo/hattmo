use bincode::{
    config::{self, Configuration},
    error::DecodeError,
};
use proto::{
    request::{Open, Request, RequestType},
    response::Response,
};
use std::{collections::HashMap, fs, future::pending, path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, MutexGuard},
};
use tokio_rustls::{
    rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        server::WebPkiClientVerifier,
        RootCertStore, ServerConfig, ServerConnection,
    },
    TlsAcceptor,
};
use x509_parser::prelude::*;
use zbus::{connection, interface};



#[derive(Default, Clone)]
struct AgentStore(Arc<Mutex<HashMap<String, AgentContext>>>);

impl AgentStore {
    fn new() -> Self {
        AgentStore::default()
    }

    async fn get_agent_context(&self, agent: &str) -> AgentContext {
        let mut lock = self.0.lock().await;
        let context = lock.entry(agent.to_owned()).or_default();
        context.clone()
    }
    async fn get_agent_names(&self) -> Vec<String> {
        self.0.lock().await.keys().cloned().collect()
    }
}

struct Transaction {
    req: Request,
    res: Vec<Response>,
}

impl From<Request> for Transaction {
    fn from(value: Request) -> Self {
        Transaction {
            req: value,
            res: Vec::new(),
        }
    }
}

#[derive(Default, Clone)]
struct AgentContext {
    sessions: Arc<Mutex<HashMap<u64, u64>>>,
    transactions: Arc<Mutex<Vec<Transaction>>>,
}

struct PendingRequests<'a> {
    lock: MutexGuard<'a, Vec<Transaction>>,
}

impl<'a> PendingRequests<'a> {
    fn iter(&'a self) -> impl Iterator<Item = &'a Request> {
        self.lock
            .iter()
            .filter(|i| i.res.is_empty())
            .map(|i| &i.req)
    }
}

impl AgentContext {
    async fn put_request(&self, req: Request) {
        let mut lock = self.transactions.lock().await;
        lock.push(req.into());
    }

    async fn put_responses(&self, ress: impl IntoIterator<Item = Response>) {
        let mut lock = self.transactions.lock().await;
        for new_res in ress {
            if let Some(i) = lock
                .iter_mut()
                .find(|i| i.req.sess == new_res.sess && i.req.seq == new_res.seq)
            {
                i.res.push(new_res)
            };
        }
    }

    async fn pending_requests(&self) -> PendingRequests<'_> {
        PendingRequests {
            lock: self.transactions.lock().await,
        }
    }

    async fn next_seq(&self, sess: u64) -> u64 {
        let mut lock = self.sessions.lock().await;
        let seq = lock.entry(sess).or_default();
        *seq += 1;
        *seq
    }
}

#[tokio::main]
async fn main() {
    let ca_cert = fs::read("./crypto/ca.crt").unwrap();
    let server_cert = fs::read("./crypto/server.crt").unwrap();
    let server_key = fs::read("./crypto/server.key").unwrap();
    let config = new_server_config(&ca_cert, &server_cert, &server_key).unwrap();
    let store = AgentStore::new();
    let _dbus_task = {
        let store = store.clone();
        tokio::spawn(async {
            let _conn = connection::Builder::session()
                .err_str()?
                .name("com.hattmo.Weasy")
                .err_str()?
                .serve_at("/com/hattmo/Weasy", Weasy { store })
                .err_str()?
                .build()
                .await
                .err_str()?;
            pending::<()>().await;
            Ok::<(), Box<str>>(())
        })
    };
    let _server_task = tokio::spawn(async move {
        while let Ok((conn, _)) = tokio::net::TcpListener::bind("0.0.0.0:1337")
            .await
            .err_str()?
            .accept()
            .await
        {
            let store = store.clone();
            let config = config.clone();
            tokio::spawn(async {
                if let Err(e) = handle_conn(config, conn, store).await {
                    println!("{e}");
                };
            });
        }
        Ok::<(), Box<str>>(())
    });
}

const BC_CONF: Configuration = config::standard();

async fn handle_conn(
    config: Arc<ServerConfig>,
    conn: tokio::net::TcpStream,
    store: AgentStore,
) -> Result<(), Box<str>> {
    let acceptor: TlsAcceptor = config.into();
    let mut tls_conn = acceptor.accept(conn).await.err_str()?;
    let (_, ctx) = tls_conn.get_ref();
    let peer = get_peer(ctx).ok_or("No Peer")?;
    // let mut ctx = ServerConnection::new(config).err_str()?;
    // while ctx.is_handshaking() {
    //     ctx.complete_io(&mut conn).err_str()?;
    // }
    // let peer = get_peer(&ctx).ok_or("Unknow peer in cert")?;
    let agent_ctx = store.get_agent_context(&peer).await;

    let mut buf = vec![0; 32];
    let mut read = 0;
    let res = loop {
        read += tls_conn.read(&mut buf[read..]).await.err_str()?;

        let res: Result<(Vec<Response>, _), _> =
            bincode::decode_from_slice(&mut buf[..read], BC_CONF);
        match res {
            Ok((data, _)) => break data,
            Err(DecodeError::UnexpectedEnd { additional }) => {
                buf.resize(read + additional, 0);
            }
            Err(_) => return Err("Failed to parse".into()),
        };
    };
    agent_ctx.put_responses(res).await;

    let requests = agent_ctx.pending_requests().await;
    let requests: Box<[&Request]> = requests.iter().collect();
    let out = bincode::encode_to_vec(&requests, BC_CONF).err_str()?;
    tls_conn.write_all(&out).await.err_str()?;

    Ok(())
}

fn get_peer(ctx: &ServerConnection) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(ctx.peer_certificates()?.first()?).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .map(AttributeTypeAndValue::as_str)?
        .ok()?
        .to_owned();
    Some(cn)
}

fn new_server_config(
    ca_cert: &[u8],
    server_cert: &[u8],
    server_key: &[u8],
) -> Result<Arc<ServerConfig>, Box<str>> {
    let mut store = RootCertStore::empty();
    store
        .add(CertificateDer::from_pem_slice(ca_cert).err_str()?)
        .err_str()?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(store))
        .build()
        .unwrap();
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(server_cert).err_str()?],
            PrivateKeyDer::from_pem_slice(server_key).err_str()?,
        )
        .unwrap();
    Ok(config.into())
}

trait ErrorString<T> {
    fn err_str(self) -> Result<T, Box<str>>;
}

impl<T, E> ErrorString<T> for Result<T, E>
where
    E: ToString,
{
    fn err_str(self) -> Result<T, Box<str>> {
        self.map_err(|e| e.to_string().into())
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test() {
        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        let val = vec![1, 2, 3];
        bincode::encode_into_std_write(&val, &mut buf1, bincode::config::standard()).unwrap();
        bincode::encode_into_std_write(val, &mut buf2, bincode::config::standard()).unwrap();
        assert_eq!(buf1, buf2)
    }
}
