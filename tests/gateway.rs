#![allow(
    clippy::panic_in_result_fn,
    reason = "integration assertions report contract failures"
)]
#![allow(clippy::expect_used, reason = "test failures retain operation context")]
use koh::{embed::NetworkProfile, gateway, identity::Identity};
use std::collections::BTreeSet;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn gateway_authenticates_before_touching_the_local_service_and_copies_bytes_exactly(
) -> anyhow::Result<()> {
    let root = std::path::PathBuf::from(format!("/tmp/kg-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let socket = root.join("application.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    let app = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await?;
            count.fetch_add(1, Ordering::AcqRel);
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.into_split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                let _ = writer.shutdown().await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });
    let allowed = Identity::generate();
    let mut server = gateway::serve(
        Identity::generate(),
        BTreeSet::from([allowed.endpoint_id()]),
        NetworkProfile::Local,
        socket,
    )
    .await?;
    let config = |path| gateway::ConnectConfig {
        server: server.endpoint_id(),
        direct: server.direct_addr(),
        relay_url: None,
        socket: path,
    };
    let outsider_socket = root.join("denied.sock");
    let mut outsider =
        gateway::connect(Identity::generate(), config(outsider_socket.clone())).await?;
    let mut denied = tokio::net::UnixStream::connect(outsider_socket).await?;
    denied.write_all(b"must not reach application").await?;
    let mut bytes = [0; 8];
    let ended = tokio::time::timeout(Duration::from_secs(15), denied.read(&mut bytes)).await?;
    assert!(ended.is_err() || matches!(ended, Ok(0)));
    assert_eq!(accepted.load(Ordering::Acquire), 0);
    outsider.close().await;
    let viewer_socket = root.join("viewer.sock");
    let mut client = gateway::connect(allowed, config(viewer_socket.clone())).await?;
    let mut viewer = tokio::net::UnixStream::connect(viewer_socket).await?;
    let expected: Vec<_> = (0..65536).map(|value| (value % 256) as u8).collect();
    viewer.write_all(&expected).await?;
    viewer.shutdown().await?;
    let mut received = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(15),
        viewer.take(65537).read_to_end(&mut received),
    )
    .await??;
    assert_eq!(received.len(), expected.len());
    assert!(received == expected, "gateway changed payload bytes");
    assert_eq!(accepted.load(Ordering::Acquire), 1);
    client.close().await;
    server.close().await;
    app.abort();
    let _ = app.await;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(feature = "cli")]
#[tokio::test]
async fn optional_gateway_failure_leaves_real_fux_panes_running() -> anyhow::Result<()> {
    let Some(binary) = std::env::var_os("FUX_BIN") else {
        anyhow::ensure!(
            std::env::var_os("KOH_REQUIRE_FUX_BIN").is_none(),
            "FUX_BIN is required"
        );
        return Ok(());
    };
    let root = std::path::PathBuf::from(format!("/tmp/kg-fux-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut app = ChildGuard(
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
    let socket = root.join("fux/default.attach.sock");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !socket.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let identity = Identity::generate();
    let mut server = gateway::serve(
        Identity::generate(),
        BTreeSet::from([identity.endpoint_id()]),
        NetworkProfile::Local,
        socket.clone(),
    )
    .await?;
    let proxy = root.join("proxy.sock");
    let mut client = gateway::connect(
        identity,
        gateway::ConnectConfig {
            server: server.endpoint_id(),
            socket: proxy.clone(),
            direct: server.direct_addr(),
            relay_url: None,
        },
    )
    .await?;
    let mut remote = tokio::net::UnixStream::connect(proxy).await?;
    hello(&mut remote).await?;
    message(&mut remote, serde_json::json!({"type":"input", "bytes":b"FUX_GATEWAY=preserved; printf 'REMOTE_OK\\n'\n".to_vec()})).await?;
    wait_text(&mut remote, "REMOTE_OK").await?;
    client.close().await;
    server.close().await;
    assert!(
        app.0.try_wait()?.is_none(),
        "gateway stopped the local server"
    );
    let mut local = tokio::net::UnixStream::connect(socket).await?;
    hello(&mut local).await?;
    message(&mut local, serde_json::json!({"type":"input", "bytes":b"printf 'LOCAL_%s\\n' \"$FUX_GATEWAY\"\n".to_vec()})).await?;
    wait_text(&mut local, "LOCAL_preserved").await?;
    drop(local);
    drop(remote);
    drop(app);
    std::fs::remove_dir_all(root)?;
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
        serde_json::json!({"type":"hello","version":2,"rows":24,"columns":80}),
    )
    .await?;
    let value = tokio::time::timeout(Duration::from_secs(15), frame(stream)).await??;
    assert_eq!(
        value
            .pointer("/hello/version")
            .and_then(serde_json::Value::as_u64),
        Some(2)
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
