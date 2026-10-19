//! What the tests that run the `koh` binary share: a home, a PTY to run it on, a loopback
//! server to connect it to, and a `koh serve` found by its banner.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use koh::pty::{Home, Pty};
use koh::server::cli::serve_endpoint;
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key};
use koh_testkit::Capture;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// The home every program here gets.
pub fn home() -> Home {
    Home::isolated(koh_testkit::home!())
}

/// `koh id` for the key at `key`, creating it: the endpoint id, as the binary prints it.
pub fn endpoint_id(key: &std::path::Path) -> anyhow::Result<String> {
    let out = koh_testkit::command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())?
        .args(["id", "--key-file"])
        .arg(key)
        .output()?;
    anyhow::ensure!(out.status.success(), "koh id: {out:?}");
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// `argv` on a 24×80 PTY, and what it prints.
pub fn on_pty(argv: &[String]) -> anyhow::Result<(Pty, Capture)> {
    let reaper = koh::pty::Reaper::start()?;
    let (pty, output) = Pty::spawn(
        24,
        80,
        argv,
        &[],
        ("xterm-256color", &home(), None),
        &reaper,
    )?;
    Ok((pty, Capture::new(output)))
}

/// `argv` (a `koh connect`) on a PTY, with `typed` typed until `marker` shows: keys typed before
/// the session is up are dropped, so `marker` must be what only the remote shell prints. The PTY,
/// what it printed, and the byte after the marker.
pub async fn connected(
    argv: &[String],
    typed: &[u8],
    marker: &str,
) -> anyhow::Result<(Pty, Capture, usize)> {
    let (client, seen) = on_pty(argv)?;
    let at = seen
        .type_until(0, marker, 20, || {
            let _ = client.write(typed.to_vec());
        })
        .await
        .map_err(anyhow::Error::msg)?;
    Ok((client, seen, at))
}

/// An in-process loopback server hosting bash (marked, as `koh serve` marks it) for the client
/// `allow`, as `koh serve` does: its endpoint id, its IPv4 port, and its task.
pub async fn loopback_server(allow: &str) -> anyhow::Result<(String, u16, JoinHandle<()>)> {
    let config = koh::server::ServeConfig {
        allow: vec![koh::transport_iroh::parse_endpoint_id(allow)?],
        command: vec!["bash".to_owned()],
        home: home(),
        ..koh::server::ServeConfig::default()
    };
    serve_in_process(&config).await
}

/// Serve `config` in process on a loopback endpoint: its id, its IPv4 port, and its task.
pub async fn serve_in_process(
    config: &koh::server::ServeConfig,
) -> anyhow::Result<(String, u16, JoinHandle<()>)> {
    let hosting = koh::server::cli::Hosting::from_config(config)?;
    let endpoint = bind_endpoint_local(generate_secret_key()?, true).await?;
    let id = endpoint.id().to_string();
    let port = endpoint
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map(std::net::SocketAddr::port)
        .ok_or_else(|| anyhow::anyhow!("no IPv4 socket"))?;
    let task = koh_testkit::spawn(async move {
        let _ = serve_endpoint(endpoint, hosting, CancellationToken::new()).await;
    });
    Ok((id, port, task))
}

/// A running `koh serve`: killed when dropped.
pub struct Served {
    pub child: Child,
    pub id: String,
    /// The UDP port it bound, as its banner says.
    pub port: u16,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `koh serve` as `command` sets it up, once its banner says its endpoint id and port, and the
/// banner to that line.
pub fn serve(mut command: Command) -> anyhow::Result<(Served, Vec<String>)> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let lines = koh_testkit::stderr_lines(&mut child);
    let mut served = Served {
        child,
        id: String::new(),
        port: 0,
    };
    let mut banner = Vec::new();
    while served.port == 0 {
        let line = lines
            .recv_timeout(Duration::from_secs(20))
            .map_err(|e| anyhow::anyhow!("{e}: no banner: {banner:?}"))?;
        if let Some((_, id)) = line.split_once("endpoint id : ") {
            id.trim().clone_into(&mut served.id);
        }
        if let Some((_, port)) = line.split_once("udp port    : ") {
            served.port = port
                .split_whitespace()
                .next()
                .and_then(|port| port.parse().ok())
                .unwrap_or(0);
        }
        banner.push(line);
    }
    Ok((served, banner))
}
