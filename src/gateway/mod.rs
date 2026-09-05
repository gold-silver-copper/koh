//! Authenticated remote access to a local Unix service. Application state stays in that service.
//! No multiplexer or observer dependency is required by this transport boundary.
mod resume;
mod sessions;
use crate::embed::NetworkProfile;
use crate::identity::Identity;
use crate::transport_iroh::{
    bind_endpoint_alpns, bind_endpoint_local_alpns, bind_endpoint_with_relay_alpns,
    parse_endpoint_id, parse_relay_url,
};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

pub const ALPN: &[u8] = b"koh/local-gateway/2";
const HANDSHAKE: Duration = Duration::from_secs(10);
const MAX_CLIENTS: usize = 64;

pub struct Service {
    endpoint: iroh::Endpoint,
    _identity: Identity,
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl Service {
    pub fn endpoint_id(&self) -> String {
        self.endpoint.id().to_string()
    }
    pub fn direct_addr(&self) -> Option<SocketAddr> {
        self.endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .map(|address| ([127, 0, 0, 1], address.port()).into())
    }
    pub async fn close(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), self.endpoint.close()).await;
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn bind(
    identity: &Identity,
    profile: NetworkProfile,
    accept: bool,
) -> anyhow::Result<iroh::Endpoint> {
    let alpns = if accept {
        vec![ALPN.to_vec()]
    } else {
        Vec::new()
    };
    Ok(match profile {
        NetworkProfile::Default => bind_endpoint_alpns(identity.secret.clone(), alpns).await?,
        NetworkProfile::Local => bind_endpoint_local_alpns(identity.secret.clone(), alpns).await?,
        NetworkProfile::Relay(url) => {
            bind_endpoint_with_relay_alpns(identity.secret.clone(), alpns, parse_relay_url(&url)?)
                .await?
        }
    })
}

pub async fn serve(
    identity: Identity,
    allow: BTreeSet<String>,
    profile: NetworkProfile,
    socket: PathBuf,
) -> anyhow::Result<Service> {
    validate_socket(&socket)?;
    anyhow::ensure!(
        !allow.is_empty() && allow.len() <= 1024,
        "gateway requires 1-1024 authorized peers"
    );
    let allow = allow
        .into_iter()
        .map(|id| parse_endpoint_id(&id))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let endpoint = bind(&identity, profile, true).await?;
    let listener = endpoint.clone();
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let task = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        let registry = std::sync::Arc::new(sessions::Registry::default());
        let mut reap = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                _ = reap.tick() => registry.reap(),
                Some(_) = clients.join_next(), if !clients.is_empty() => {},
                incoming = listener.accept() => {
                    let Some(incoming) = incoming else { break };
                    if clients.len() >= MAX_CLIENTS { incoming.refuse(); continue; }
                    let allow = allow.clone();
                    let socket = socket.clone();
                    let registry = std::sync::Arc::clone(&registry);
                    clients.spawn(async move {
                        let result = async {
                            let connection = tokio::time::timeout(HANDSHAKE, incoming).await??;
                            if !allow.contains(&connection.remote_id()) {
                                connection.close(1_u32.into(), b"not authorized");
                                anyhow::bail!("gateway peer is not authorized");
                            }
                            // Authorization precedes any access to the local application.
                            let result = async {
                                tokio::time::timeout(HANDSHAKE, crate::transport_iroh::admission::admit(&connection)).await??;
                                registry.attach(&connection, &socket).await
                            }.await;
                            connection.close(0_u32.into(), b"gateway attachment closed");
                            result
                        }.await;
                        if let Err(error) = result { tracing::debug!(%error, "gateway connection ended"); }
                    });
                }
            }
        }
        clients.abort_all();
        while clients.join_next().await.is_some() {}
    });
    Ok(Service {
        endpoint,
        _identity: identity,
        cancel,
        task: Some(task),
    })
}

pub struct ConnectConfig {
    pub server: String,
    pub socket: PathBuf,
    pub direct: Option<SocketAddr>,
    pub relay_url: Option<String>,
}

pub async fn connect(identity: Identity, config: ConnectConfig) -> anyhow::Result<Service> {
    let server = parse_endpoint_id(&config.server)?;
    let profile = if config.direct.is_some() {
        NetworkProfile::Local
    } else if let Some(url) = &config.relay_url {
        NetworkProfile::Relay(url.clone())
    } else {
        NetworkProfile::Default
    };
    let target = if let Some(address) = config.direct {
        crate::transport_iroh::direct_addr(server, address)
    } else if let Some(url) = &config.relay_url {
        crate::transport_iroh::relay_addr(server, parse_relay_url(url)?)
    } else {
        server.into()
    };
    let socket = OwnedSocket::bind(&config.socket)?;
    let listener = tokio::net::UnixListener::from_std(socket.listener.try_clone()?)?;
    let endpoint = bind(&identity, profile, false).await?;
    let dialer = endpoint.clone();
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let task = tokio::spawn(async move {
        let _socket = socket;
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                () = stop.cancelled() => break,
                Some(_) = clients.join_next(), if !clients.is_empty() => {},
                accepted = listener.accept() => {
                    let Ok((local, _)) = accepted else { break };
                    if clients.len() >= MAX_CLIENTS || authorize_peer(&local).is_err() { continue; }
                    let dialer = dialer.clone();
                    let target = target.clone();
                    clients.spawn(async move {
                        let result = sessions::run_client(local, dialer, target).await;
                        if let Err(error) = result { tracing::debug!(%error, "gateway attachment ended"); }
                    });
                }
            }
        }
        clients.abort_all();
        while clients.join_next().await.is_some() {}
    });
    Ok(Service {
        endpoint,
        _identity: identity,
        cancel,
        task: Some(task),
    })
}

fn authorize_peer(stream: &UnixStream) -> anyhow::Result<()> {
    anyhow::ensure!(
        stream.peer_cred()?.uid() == nix::unistd::geteuid().as_raw(),
        "local peer belongs to another user"
    );
    Ok(())
}
#[allow(
    clippy::verbose_bit_mask,
    reason = "Unix permission masks are clearer in octal"
)]
fn validate_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.permissions().mode() & 0o077 == 0,
        "gateway socket directory must be private and owned by this user"
    );
    Ok(())
}
#[allow(
    clippy::verbose_bit_mask,
    reason = "Unix permission masks are clearer in octal"
)]
fn validate_socket(path: &Path) -> anyhow::Result<()> {
    validate_directory(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("socket has no parent"))?,
    )?;
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.permissions().mode() & 0o077 == 0,
        "unsafe local service socket"
    );
    Ok(())
}
struct OwnedSocket {
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl OwnedSocket {
    fn bind(path: &Path) -> anyhow::Result<Self> {
        validate_directory(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("socket has no parent"))?,
        )?;
        let listener = std::os::unix::net::UnixListener::bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let bound = Self {
            listener,
            path: path.to_owned(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        bound.listener.set_nonblocking(true)?;
        Ok(bound)
    }
}
impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.dev() == self.dev
                && metadata.ino() == self.ino
                && metadata.file_type().is_socket()
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(feature = "cli")]
pub mod cli;
