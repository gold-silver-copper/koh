//! Authenticated session retention. Tokens are scoped to the TLS peer, not bearer credentials.
use super::{authorize_peer, resume, validate_socket, ALPN, HANDSHAKE, MAX_CLIENTS};
use rand::RngCore;
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time::Instant;

const RETENTION: Duration = Duration::from_secs(30);
const RETRY: Duration = Duration::from_millis(100);
const ACCEPTED: u8 = 0;
const REJECTED: u8 = 1;
const BUSY: u8 = 2;
const COMPLETE: u8 = 3;
async fn reply(
    send: &mut iroh::endpoint::SendStream,
    code: u8,
    committed: Option<u64>,
) -> anyhow::Result<()> {
    tokio::time::timeout(HANDSHAKE, async {
        send.write_u8(code).await?;
        if let Some(next) = committed {
            send.write_u64(next).await?;
        }
        send.finish()?;
        let _ = send.stopped().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await?
}
type Key = (iroh::EndpointId, [u8; 32]);

struct Retained {
    session: Option<resume::Session>,
    complete: bool,
    dead: bool,
    expires: Instant,
}
#[derive(Default)]
pub(super) struct Registry {
    entries: std::sync::Mutex<BTreeMap<Key, Arc<Mutex<Retained>>>>,
}
impl Registry {
    fn entries(&self) -> std::sync::MutexGuard<'_, BTreeMap<Key, Arc<Mutex<Retained>>>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(super) fn reap(&self) {
        let now = Instant::now();
        self.entries()
            .retain(|_, entry| entry.try_lock().map_or(true, |entry| entry.expires > now));
    }
    fn lookup(&self, key: Key, create: bool) -> Option<Arc<Mutex<Retained>>> {
        self.reap();
        let mut entries = self.entries();
        if let Some(entry) = entries.get(&key) {
            return Some(Arc::clone(entry));
        }
        if !create || entries.len() >= MAX_CLIENTS {
            return None;
        }
        let entry = Arc::new(Mutex::new(Retained {
            session: None,
            complete: false,
            dead: false,
            expires: Instant::now() + RETENTION,
        }));
        entries.insert(key, Arc::clone(&entry));
        Some(entry)
    }
    /// Called only after TLS peer authorization. The local target is fixed by the server.
    pub(super) async fn attach(
        &self,
        connection: &iroh::endpoint::Connection,
        socket: &Path,
    ) -> anyhow::Result<()> {
        let (mut send, mut recv) =
            tokio::time::timeout(HANDSHAKE, connection.accept_bi()).await??;
        let (create, token) = tokio::time::timeout(HANDSHAKE, async {
            let mode = recv.read_u8().await?;
            anyhow::ensure!(mode <= 1, "invalid gateway session mode");
            let mut token = [0; 32];
            recv.read_exact(&mut token).await?;
            Ok::<_, anyhow::Error>((mode == 0, token))
        })
        .await??;
        let Some(entry) = self.lookup((connection.remote_id(), token), create) else {
            reply(&mut send, REJECTED, None).await?;
            anyhow::bail!("gateway session expired or capacity reached");
        };
        let Ok(mut retained) = entry.try_lock() else {
            reply(&mut send, BUSY, None).await?;
            return Ok(());
        };
        if retained.dead || retained.expires <= Instant::now() {
            reply(&mut send, REJECTED, None).await?;
            anyhow::bail!("gateway session ended");
        }
        let was_complete = retained.complete;
        let result = async {
            if retained.session.is_none() {
                validate_socket(socket)?;
                let local = tokio::time::timeout(HANDSHAKE, UnixStream::connect(socket)).await??;
                authorize_peer(&local)?;
                retained.session = Some(resume::Session::new(local));
            }
            if retained.complete {
                let next = retained
                    .session
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing completed session"))?
                    .committed();
                reply(&mut send, COMPLETE, Some(next)).await?;
                return Ok(());
            }
            send.write_u8(ACCEPTED).await?;
            let session = retained
                .session
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("missing gateway session"))?;
            match session.exchange(recv, send).await {
                Ok(()) => retained.complete = true,
                Err(resume::Failure::Link(error)) => {
                    tracing::debug!(%error, "gateway session waiting for reconnect");
                }
                Err(resume::Failure::Session(error)) => {
                    retained.dead = true;
                    retained.session = None;
                    return Err(error.into());
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        // Retain completed sessions too: the peer may have lost our final ACK.
        if !was_complete {
            retained.expires = Instant::now() + RETENTION;
        }
        result
    }
}

pub(super) async fn run_client(
    local: UnixStream,
    endpoint: iroh::Endpoint,
    target: iroh::EndpointAddr,
) -> anyhow::Result<()> {
    let mut token = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let mut session = resume::Session::new(local);
    let mut established = false;
    let mut expires = Instant::now() + RETENTION;
    loop {
        let mut rejected = false;
        let attempt = tokio::time::timeout_at(expires, async {
            let connection =
                tokio::time::timeout(HANDSHAKE, endpoint.connect(target.clone(), ALPN)).await??;
            let result = async {
                tokio::time::timeout(
                    HANDSHAKE,
                    crate::transport_iroh::admission::await_admission(&connection),
                )
                .await??;
                let (mut send, mut recv) =
                    tokio::time::timeout(HANDSHAKE, connection.open_bi()).await??;
                let reply = tokio::time::timeout(HANDSHAKE, async {
                    send.write_u8(u8::from(established)).await?;
                    send.write_all(&token).await?;
                    recv.read_u8().await.map_err(anyhow::Error::from)
                })
                .await??;
                match reply {
                    ACCEPTED => {
                        established = true;
                        // Only the handshake/retry period is bounded by the retention window.
                        Ok(Some((connection.clone(), send, recv)))
                    }
                    BUSY => Ok(None),
                    COMPLETE => {
                        let committed = tokio::time::timeout(HANDSHAKE, recv.read_u64()).await??;
                        rejected = true; // Invalid completion is a protocol failure, not an outage.
                        session.confirm_complete(committed)?;
                        Ok(None)
                    }
                    _ => {
                        rejected = true;
                        anyhow::bail!("gateway rejected session resume");
                    }
                }
            }
            .await;
            if !matches!(result, Ok(Some(_))) {
                connection.close(0_u32.into(), b"gateway handshake ended");
            }
            result
        })
        .await;
        match attempt {
            Ok(Ok(Some((connection, send, recv)))) => {
                let result = session.exchange(recv, send).await;
                connection.close(0_u32.into(), b"gateway link ended");
                match result {
                    Ok(()) => return Ok(()),
                    Err(resume::Failure::Session(error)) => return Err(error.into()),
                    Err(resume::Failure::Link(error)) => {
                        tracing::debug!(%error, "reconnecting gateway attachment");
                    }
                }
                expires = Instant::now() + RETENTION;
            }
            Ok(Ok(None)) if session.is_complete() => return Ok(()),
            Ok(Ok(None)) => {}
            Ok(Err(error)) if established && !rejected => {
                tracing::debug!(%error, "gateway reconnect attempt failed");
            }
            Ok(Err(error)) => return Err(error),
            Err(error) => return Err(error.into()),
        }
        anyhow::ensure!(Instant::now() < expires, "gateway reconnect grace expired");
        tokio::time::sleep_until((Instant::now() + RETRY).min(expires)).await;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "test failures retain operation context")]
mod tests {
    use super::*;
    use crate::{embed::NetworkProfile, identity::Identity};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn registry_scopes_tokens_to_peers_and_never_recreates_expired_resumes() {
        let registry = Registry::default();
        let peer = Identity::generate().secret.public();
        let other = Identity::generate().secret.public();
        let token = [7; 32];
        let entry = registry.lookup((peer, token), true).expect("new session");
        assert!(registry.lookup((other, token), false).is_none());
        assert!(Arc::ptr_eq(
            &entry,
            &registry.lookup((peer, token), false).expect("same session")
        ));
        entry.lock().await.expires = Instant::now();
        registry.reap();
        assert!(registry.lookup((peer, token), false).is_none());
        for number in 0..MAX_CLIENTS {
            let mut token = [0; 32];
            token[0] = u8::try_from(number).expect("bounded session count");
            assert!(registry.lookup((peer, token), true).is_some());
        }
        assert!(registry.lookup((peer, [255; 32]), true).is_none());
    }

    #[tokio::test]
    async fn active_resume_is_serialized_and_expiry_releases_the_local_connection() {
        let registry = Registry::default();
        let key = (Identity::generate().secret.public(), [9; 32]);
        let entry = registry.lookup(key, true).expect("new session");
        let (local, mut app) = UnixStream::pair().expect("application pair");
        let mut active = entry.lock().await;
        active.session = Some(resume::Session::new(local));
        active.expires = Instant::now();
        registry.reap();
        let concurrent = registry.lookup(key, false).expect("active entry retained");
        assert!(Arc::ptr_eq(&entry, &concurrent));
        assert!(
            concurrent.try_lock().is_err(),
            "two links acquired the same session"
        );
        drop(concurrent);
        drop(active);
        drop(entry);
        registry.reap();
        assert!(registry.lookup(key, false).is_none());
        assert!(tokio::time::timeout(Duration::from_secs(1), app.read_u8())
            .await
            .expect("expiry closes local socket")
            .is_err());
    }

    #[tokio::test]
    async fn forced_quic_loss_redials_without_reopening_or_repeating_application_input(
    ) -> anyhow::Result<()> {
        let root = std::path::PathBuf::from(format!("/tmp/kr-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let socket = root.join("app.sock");
        let listener = tokio::net::UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let accepts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepts);
        let app = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted?;
                        count.fetch_add(1, Ordering::AcqRel);
                        workers.spawn(async move {
                            let mut applied = 0_u64;
                            while stream.read_u8().await.is_ok() {
                                applied += 1;
                                stream.write_u64(applied).await?;
                            }
                            stream.shutdown().await
                        });
                    }
                    Some(_) = workers.join_next(), if !workers.is_empty() => {},
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });
        let server = super::super::bind(&Identity::generate(), NetworkProfile::Local, true).await?;
        let client_identity = Identity::generate();
        let client_id = client_identity.secret.public();
        let client = super::super::bind(&client_identity, NetworkProfile::Local, false).await?;
        let target = crate::transport_iroh::loopback_addr(&server);
        let acceptor = server.clone();
        let (links, mut connections) = mpsc::channel(1);
        let server_task = tokio::spawn(async move {
            let registry = Arc::new(Registry::default());
            let mut workers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = acceptor.accept() => {
                        let Some(incoming) = incoming else { break; };
                        let connection = incoming.await?;
                        anyhow::ensure!(connection.remote_id() == client_id, "test peer authorization");
                        links.send(connection.clone()).await?;
                        let registry = Arc::clone(&registry);
                        let socket = socket.clone();
                        workers.spawn(async move {
                            crate::transport_iroh::admission::admit(&connection).await?;
                            let result = registry.attach(&connection, &socket).await;
                            connection.close(0_u32.into(), b"test link finished");
                            result
                        });
                    }
                    Some(_) = workers.join_next(), if !workers.is_empty() => {},
                }
            }
            Ok::<(), anyhow::Error>(())
        });
        let (local, mut viewer) = UnixStream::pair()?;
        let client_endpoint = client.clone();
        let mut client_task = tokio::spawn(run_client(local, client_endpoint, target));
        let result = tokio::time::timeout(Duration::from_secs(15), async {
            let mut connection = connections
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("first connection"))?;
            for expected in 1..=6 {
                viewer.write_u8(b'x').await?;
                anyhow::ensure!(
                    viewer.read_u64().await? == expected,
                    "input applied more than once"
                );
                if expected < 6 {
                    connection.close(77_u32.into(), b"forced transport loss");
                    connection = connections
                        .recv()
                        .await
                        .ok_or_else(|| anyhow::anyhow!("redial"))?;
                }
            }
            viewer.shutdown().await?;
            anyhow::ensure!(
                viewer.read_u8().await.is_err(),
                "application stream did not end"
            );
            Ok::<(), anyhow::Error>(())
        })
        .await;
        // Each test owns only these tasks and endpoints; always close them before returning errors.
        let client_result = tokio::time::timeout(Duration::from_secs(2), &mut client_task).await;
        if client_result.is_err() {
            client_task.abort();
            let _ = client_task.await;
        }
        server_task.abort();
        let _ = server_task.await;
        app.abort();
        let _ = app.await;
        client.close().await;
        server.close().await;
        std::fs::remove_dir_all(root)?;
        result??;
        client_result???;
        anyhow::ensure!(
            accepts.load(Ordering::Acquire) == 1,
            "reconnect reopened the local application"
        );
        Ok(())
    }
}

#[cfg(all(test, feature = "cli"))]
#[path = "sessions_real_fux.rs"]
#[allow(
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "integration assertions retain failure context"
)]
mod real_fux_tests;
