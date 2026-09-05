use crate::server::{Hosts, SessionHost, SharedHost};
use crate::transport_iroh::{
    bind_endpoint_alpns, bind_endpoint_local_alpns, bind_endpoint_with_relay_alpns,
    format_endpoint_id, parse_endpoint_id, parse_relay_url,
};
use std::collections::{BTreeSet, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const ENDPOINT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkProfile {
    Default,
    Local,
    Relay(String),
}

pub struct Server {
    _endpoint: iroh::Endpoint,
    _identity: crate::identity::Identity,
    endpoint_id: String,
    direct_addr: SocketAddrV4,
    shutdown: CancellationToken,
    accept_task: Option<std::thread::JoinHandle<()>>,
    active_tasks: Arc<AtomicUsize>,
    disconnect: tokio::sync::watch::Sender<u64>,
}

struct ActiveTask(Arc<AtomicUsize>);

fn build_worker_runtime(
    build: impl FnOnce() -> std::io::Result<tokio::runtime::Runtime>,
) -> anyhow::Result<tokio::runtime::Runtime> {
    build().map_err(anyhow::Error::from)
}

impl ActiveTask {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self(count)
    }
}

impl Drop for ActiveTask {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Binds a workspace using caller-supplied key material, useful when key storage is external.
impl Server {
    pub async fn bind<H, F>(
        identity: crate::identity::Identity,
        allow: &BTreeSet<String>,
        alpn: &'static [u8],
        profile: NetworkProfile,
        max_connections: usize,
        make_host: F,
    ) -> anyhow::Result<Self>
    where
        H: SessionHost,
        F: Fn() -> anyhow::Result<H> + Send + Sync + 'static,
    {
        anyhow::ensure!(max_connections > 0, "max_connections must be at least 1");
        let secret = identity.secret.clone();
        let mut allowed = HashSet::new();
        for value in allow {
            allowed.insert(
                parse_endpoint_id(value)
                    .map_err(|_| anyhow::anyhow!("invalid endpoint ID or relay URL"))?,
            );
        }
        if allowed.is_empty() {
            return Err(anyhow::anyhow!(
                "at least one authorized participant is required"
            ));
        }
        let hosts = Arc::new(Hosts::new().with(alpn, SharedHost::new(make_host)));
        let alpns = hosts.alpns();
        let endpoint = match profile {
            NetworkProfile::Default => bind_endpoint_alpns(secret, alpns).await,
            NetworkProfile::Local => bind_endpoint_local_alpns(secret, alpns).await,
            NetworkProfile::Relay(url) => {
                let relay = parse_relay_url(&url)
                    .map_err(|_| anyhow::anyhow!("invalid endpoint ID or relay URL"))?;
                bind_endpoint_with_relay_alpns(secret, alpns, relay).await
            }
        }
        .map_err(|error| anyhow::Error::from(std::io::Error::other(error.to_string())))?;
        let direct_addr = endpoint
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .map(|address| SocketAddrV4::new(Ipv4Addr::LOCALHOST, address.port()))
            .ok_or_else(|| {
                anyhow::Error::from(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "iroh endpoint has no IPv4 socket",
                ))
            })?;
        let endpoint_id = format_endpoint_id(&endpoint.id());
        let shutdown = CancellationToken::new();
        let accept_endpoint = endpoint.clone();
        let accept_shutdown = shutdown.clone();
        let allowed = Arc::new(allowed);
        let limit = Arc::new(tokio::sync::Semaphore::new(max_connections));
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let worker_active = Arc::clone(&active_tasks);
        let (disconnect, _) = tokio::sync::watch::channel(0_u64);
        let worker_disconnect = disconnect.clone();
        let worker_runtime = match build_worker_runtime(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
        }) {
            Ok(runtime) => runtime,
            Err(error) => {
                endpoint.close().await;
                return Err(error);
            }
        };
        let accept_task = match std::thread::Builder::new()
        .name("koh-hosted-sessions".into())
        .spawn(move || {
            worker_runtime.block_on(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        () = accept_shutdown.cancelled() => break,
                        completed = connections.join_next(), if !connections.is_empty() => {
                            let _ = completed;
                        }
                        incoming = accept_endpoint.accept() => {
                            let Some(incoming) = incoming else { break };
                            let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                                incoming.refuse();
                                continue;
                            };
                            let hosts = Arc::clone(&hosts);
                            let allowed = Arc::clone(&allowed);
                            let active = Arc::clone(&worker_active);
                            let mut disconnect = worker_disconnect.subscribe();
                            connections.spawn(async move {
                                let _active = ActiveTask::new(active);
                                let _permit = permit;
                                let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(10), incoming).await else { return };
                                if !allowed.contains(&connection.remote_id()) {
                                    connection.close(1_u32.into(), b"not authorized");
                                    return;
                                }
                                let control = connection.clone();
                                let serve = hosts.serve_connection(connection);
                                tokio::pin!(serve);
                                tokio::select! {
                                    () = &mut serve => {},
                                    _ = disconnect.changed() => {
                                        control.close(0_u32.into(), b"session reconnect requested");
                                        serve.await;
                                    }
                                }
                            });
                        }
                    }
                }
                let _ = tokio::time::timeout(ENDPOINT_SHUTDOWN_TIMEOUT, accept_endpoint.close()).await;
                let deadline = tokio::time::sleep(ENDPOINT_SHUTDOWN_TIMEOUT);
                tokio::pin!(deadline);
                while !connections.is_empty() {
                    tokio::select! {
                        _ = &mut deadline => {
                            connections.abort_all();
                            while connections.join_next().await.is_some() {}
                            break;
                        }
                        completed = connections.join_next() => {
                            if completed.is_none() { break; }
                        }
                    }
                }
            });
        }) {
        Ok(task) => task,
        Err(error) => {
            endpoint.close().await;
            return Err(anyhow::Error::from(error));
        }
    };
        Ok(Self {
            _identity: identity,
            _endpoint: endpoint,
            endpoint_id,
            direct_addr,
            shutdown,
            accept_task: Some(accept_task),
            active_tasks,
            disconnect,
        })
    }

    /// Disconnect current participants while retaining hosted application state for reattachment.
    pub fn disconnect_clients(&self) {
        self.disconnect
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }

    pub fn endpoint_id(&self) -> &str {
        &self.endpoint_id
    }
    pub fn direct_addr(&self) -> SocketAddrV4 {
        self.direct_addr
    }
    pub fn close(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.accept_task.take() {
            let _ = task.join();
        }
    }
    pub fn active_tasks(&self) -> usize {
        self.active_tasks.load(Ordering::Acquire)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_runtime_build_failure_is_returned_to_the_factory() {
        let result = build_worker_runtime(|| {
            Err(std::io::Error::other(
                "injected runtime construction failure",
            ))
        });
        assert!(result.is_err_and(|error| {
            error
                .to_string()
                .contains("injected runtime construction failure")
        }));
    }
}
