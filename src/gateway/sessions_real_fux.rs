//! Real application coverage for the resumable gateway; enabled only with the koh CLI JSON feature.
use super::*;
use crate::{embed::NetworkProfile, identity::Identity};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;
#[tokio::test]
async fn real_fux_keeps_its_pane_and_applies_input_once_across_five_quic_losses(
) -> anyhow::Result<()> {
    real_fux_reconnect(false).await
}

#[tokio::test]
async fn real_fux_rejects_resume_after_actual_retention_and_allows_fresh_attachment(
) -> anyhow::Result<()> {
    real_fux_reconnect(true).await
}

async fn real_fux_reconnect(expire: bool) -> anyhow::Result<()> {
    let Some(binary) = std::env::var_os("FUX_BIN") else {
        anyhow::ensure!(
            std::env::var_os("KOH_REQUIRE_FUX_BIN").is_none(),
            "FUX_BIN is required"
        );
        return Ok(());
    };
    let root = std::path::PathBuf::from(format!("/tmp/krf-{}-{expire}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let _directory = OwnedDirectory(root.clone());
    let fux = ChildGuard(
        std::process::Command::new(binary)
            .arg("serve")
            .env("HOME", &root)
            .env("XDG_RUNTIME_DIR", &root)
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_STATE_HOME", root.join("state"))
            .env("SHELL", "/bin/sh")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?,
    );
    let fux_socket = root.join("fux/default.attach.sock");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fux_socket.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
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
                    let fux_socket = fux_socket.clone();
                    workers.spawn(async move {
                        let mut application = UnixStream::connect(fux_socket).await?;
                        tokio::io::copy_bidirectional(&mut stream, &mut application).await?;
                        Ok::<(), std::io::Error>(())
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
    let registry = Arc::new(Registry::default());
    let server_registry = Arc::clone(&registry);
    let server_task = tokio::spawn(async move {
        let registry = server_registry;
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
    let mut client_task = tokio::spawn(run_client(local, client_endpoint, target.clone()));
    let result = tokio::time::timeout(Duration::from_secs(if expire { 75 } else { 15 }), async {
            let mut connection = connections
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("first connection"))?;
            hello(&mut viewer).await?;
            let mut pane_pid = None;
            for expected in 1..=6 {
                let command = format!("n=$(( ${{n:-0}} + 1 )); printf x >> {}/effects; printf '%s' \"$$\" > {}/pane-pid; printf 'RESUMED_%s\\n' \"$n\"\n", root.display(), root.display());
                message(&mut viewer, serde_json::json!({"type":"input", "bytes":command.as_bytes()})).await?;
                wait_text(&mut viewer, &format!("RESUMED_{expected}")).await?;
                let current = std::fs::read_to_string(root.join("pane-pid"))?;
                if let Some(previous) = &pane_pid {
                    anyhow::ensure!(previous == &current, "reconnect replaced the shell process");
                }
                pane_pid = Some(current);
                if expected < 6 {
                    connection.close(77_u32.into(), b"forced transport loss");
                    connection = connections
                        .recv()
                        .await
                        .ok_or_else(|| anyhow::anyhow!("redial"))?;
                }
            }
            anyhow::ensure!(std::fs::read(root.join("effects"))? == b"xxxxxx", "input effects were replayed or lost");
            if expire {
                // Stop automatic redial so the authenticated session actually remains detached
                // beyond the production retention window. Do not alter registry timestamps.
                client_task.abort();
                let _ = (&mut client_task).await;
                client_task = tokio::spawn(async { Ok(()) });
                connection.close(77_u32.into(), b"outage beyond retention");
                let key = *registry.entries().keys().next().ok_or_else(|| anyhow::anyhow!("retained session key"))?;
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        let released = registry.entries().get(&key)
                            .is_some_and(|entry| entry.try_lock().is_ok());
                        if released { break; }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await?;
                tokio::time::sleep(RETENTION + Duration::from_secs(1)).await;
                let expired = client.connect(target.clone(), ALPN).await?;
                crate::transport_iroh::admission::await_admission(&expired).await?;
                let (mut send, mut recv) = expired.open_bi().await?;
                send.write_u8(1).await?;
                send.write_all(&key.1).await?;
                send.finish()?;
                anyhow::ensure!(recv.read_u8().await? == REJECTED, "expired token was accepted");
                expired.close(0_u32.into(), b"expired resume checked");
                let _ = connections.recv().await.ok_or_else(|| anyhow::anyhow!("expired connection"))?;
                anyhow::ensure!(accepts.load(Ordering::Acquire) == 1, "expired resume reopened application");
                anyhow::ensure!(std::fs::read(root.join("effects"))? == b"xxxxxx", "expired resume replayed input");
                let (local, replacement) = UnixStream::pair()?;
                viewer = replacement;
                client_task = tokio::spawn(run_client(local, client.clone(), target.clone()));
                let _ = connections.recv().await.ok_or_else(|| anyhow::anyhow!("fresh connection"))?;
                hello(&mut viewer).await?;
                let command = format!("n=$(( ${{n:-0}} + 1 )); printf x >> {}/effects; printf '%s' \"$$\" > {}/pane-pid; printf 'RESUMED_%s\\n' \"$n\"\n", root.display(), root.display());
                message(&mut viewer, serde_json::json!({"type":"input", "bytes":command.as_bytes()})).await?;
                wait_text(&mut viewer, "RESUMED_7").await?;
                anyhow::ensure!(Some(std::fs::read_to_string(root.join("pane-pid"))?) == pane_pid, "expiry killed or replaced local pane");
                anyhow::ensure!(std::fs::read(root.join("effects"))? == b"xxxxxxx", "fresh attachment replayed or lost input");
            }
            message(&mut viewer, serde_json::json!({"type":"detach"})).await?;
            viewer.shutdown().await?;
            let mut tail = Vec::new();
            viewer.read_to_end(&mut tail).await?;
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
    drop(fux);
    std::fs::remove_dir_all(root)?;
    result??;
    client_result???;
    anyhow::ensure!(
        accepts.load(Ordering::Acquire) == if expire { 2 } else { 1 },
        "unexpected local application connection count"
    );
    Ok(())
}
#[cfg(feature = "cli")]
async fn message(
    stream: &mut tokio::net::UnixStream,
    value: serde_json::Value,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(&value)?;
    stream.write_u32(u32::try_from(bytes.len())?).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}
#[cfg(feature = "cli")]
async fn frame(stream: &mut tokio::net::UnixStream) -> anyhow::Result<serde_json::Value> {
    let length = stream.read_u32().await? as usize;
    anyhow::ensure!(length <= 16 * 1024 * 1024, "oversized fux frame");
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}
#[cfg(feature = "cli")]
async fn hello(stream: &mut tokio::net::UnixStream) -> anyhow::Result<()> {
    message(
        stream,
        serde_json::json!({"type":"hello","version":6,"rows":24,"columns":80}),
    )
    .await?;
    let value = tokio::time::timeout(Duration::from_secs(15), frame(stream)).await??;
    assert_eq!(
        value
            .pointer("/hello/version")
            .and_then(serde_json::Value::as_u64),
        Some(6),
        "{value}"
    );
    Ok(())
}
#[cfg(feature = "cli")]
async fn wait_text(stream: &mut tokio::net::UnixStream, needle: &str) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let value = frame(stream).await?;
            let text: String = value
                .pointer("/state/state/panes")
                .and_then(serde_json::Value::as_object)
                .into_iter()
                .flat_map(|panes| panes.values())
                .flat_map(|pane| {
                    pane.get("cells")
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                })
                .filter_map(|cell| cell.get("text").and_then(serde_json::Value::as_str))
                .collect();
            if text.contains(needle) {
                return Ok::<(), anyhow::Error>(());
            }
        }
    })
    .await?
}

#[cfg(feature = "cli")]
struct ChildGuard(std::process::Child);
#[cfg(feature = "cli")]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Ok(pid) = i32::try_from(self.0.id()) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct OwnedDirectory(std::path::PathBuf);
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
