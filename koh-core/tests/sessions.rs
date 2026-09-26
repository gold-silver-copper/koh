//! Sessions with real programs behind them: the registry's lifecycle, and connections to it over
//! loopback iroh with a minimal koh/3 client.
//!
//! Every session's program starts through the `koh-launch` binary, as `koh serve`'s start through
//! `koh __launch`; unit tests cannot reach a binary, so these live here.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context as _;
use koh_core::proto::{
    decode_frame, encode_client, ClientMsg, Frame, FrameNum, InputSeq, MAX_FRAME,
};
use koh_core::pty::Launcher;
use koh_core::server::cli::{serve_endpoint, Hosting, ServeConfig};
use koh_core::server::run_session;
use koh_core::server::session::AttachKind;
use koh_core::server::{Registry, SessionSpec};
use koh_core::terminal::{clamp_dims, TerminalScreen};
use koh_core::transport_iroh::admission::await_admission;
use koh_core::transport_iroh::{
    bind_endpoint_local, format_endpoint_id, generate_secret_key, loopback_addr, ALPN,
};
use tokio_util::sync::CancellationToken;

/// The launcher every session in these tests starts through.
fn launcher() -> Launcher {
    Launcher::new(env!("CARGO_BIN_EXE_koh-launch"))
}

/// The runtime for a test. `#[tokio::test]` is not used: its expansion `allow`s
/// `clippy::expect_used`, which koh-core forbids, and a `forbid` rejects that `allow`.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}

fn registry(command: &[&str], max_sessions: usize, ttl: Duration) -> Registry {
    Registry::spawn(SessionSpec {
        command: command.iter().map(|arg| (*arg).to_owned()).collect(),
        scrollback: 0,
        max_sessions,
        ttl,
        launcher: launcher(),
    })
}

/// Attach `peer` and say how.
async fn attach_kind(reg: &Registry, peer: iroh::EndpointId) -> Option<AttachKind> {
    reg.attach(peer).await.map(|(_, kind)| kind)
}

fn peer() -> std::io::Result<iroh::EndpointId> {
    Ok(generate_secret_key()?.public())
}

#[test]
fn attach_creates_then_reattaches_the_same_peer() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let reg = registry(&["sleep", "30"], 4, Duration::from_secs(30));
        let peer = peer()?;
        let (client, kind) = reg.attach(peer).await.context("first attach")?;
        anyhow::ensure!(kind == AttachKind::Created, "first attach: {kind:?}");
        let (_c2, kind) = reg.attach(peer).await.context("second attach")?;
        anyhow::ensure!(
            matches!(kind, AttachKind::Reattached { .. }),
            "same peer reattaches: {kind:?}"
        );
        drop(client);
        reg.shutdown().await;
        Ok(())
    })
}

#[test]
fn max_sessions_refuses_a_new_peer_but_allows_a_reattach() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let reg = registry(&["sleep", "30"], 1, Duration::from_secs(30));
        let (a, b) = (peer()?, peer()?);
        let (a_client, _) = reg
            .attach(a)
            .await
            .context("A creates the one allowed session")?;
        anyhow::ensure!(
            reg.attach(b).await.is_none(),
            "a second distinct peer is refused at the cap"
        );
        anyhow::ensure!(
            matches!(
                attach_kind(&reg, a).await,
                Some(AttachKind::Reattached { .. })
            ),
            "the existing peer still reattaches at the cap"
        );
        drop(a_client);
        reg.shutdown().await;
        Ok(())
    })
}

#[test]
fn the_last_detach_starts_the_ttl_a_concurrent_one_does_not() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let reg = registry(&["sleep", "30"], 4, Duration::from_millis(150));
        let peer = peer()?;
        let (a, _) = reg.attach(peer).await.context("A")?;
        let (b, _) = reg
            .attach(peer)
            .await
            .context("B (concurrent, same session)")?;
        // Dropping ONE of two attached clients must not start the TTL.
        drop(a);
        tokio::time::sleep(Duration::from_millis(400)).await;
        anyhow::ensure!(
            matches!(
                attach_kind(&reg, peer).await,
                Some(AttachKind::Reattached { .. })
            ),
            "with one client still attached the session must survive past the TTL"
        );
        // Now drop every client; after the TTL the session is reaped and a fresh attach creates one.
        drop(b);
        drop(reg.attach(peer).await.context("reattach C")?.0);
        tokio::time::sleep(Duration::from_millis(500)).await;
        anyhow::ensure!(
            attach_kind(&reg, peer).await == Some(AttachKind::Created),
            "after the last detach and the TTL the session is gone"
        );
        reg.shutdown().await;
        Ok(())
    })
}

#[test]
fn a_session_whose_shell_exited_is_torn_down() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let reg = registry(&["sh", "-c", "exit 0"], 4, Duration::from_secs(30));
        let peer = peer()?;
        let (mut client, kind) = reg.attach(peer).await.context("attach")?;
        anyhow::ensure!(kind == AttachKind::Created, "attach: {kind:?}");
        // Wait for the final (exited) screen, then detach.
        for _ in 0..100 {
            if client.screen().exit_code().is_some() {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(50), client.next_screen()).await;
        }
        anyhow::ensure!(
            client.screen().exit_code().is_some(),
            "the exit code reaches the screen"
        );
        drop(client);
        // The session tears down once the client that saw the exit detaches; a fresh attach creates.
        let mut created = false;
        for _ in 0..100 {
            if attach_kind(&reg, peer).await == Some(AttachKind::Created) {
                created = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        anyhow::ensure!(
            created,
            "an exited session is torn down and the next attach creates a new one"
        );
        reg.shutdown().await;
        Ok(())
    })
}

/// A bare koh/3 client: writes messages, applies frames whose base it holds, and acks them.
struct RawClient {
    conn: iroh::endpoint::Connection,
    send: iroh::endpoint::SendStream,
    frames: tokio::sync::mpsc::Receiver<Frame>,
    screens: HashMap<FrameNum, TerminalScreen>,
    newest: FrameNum,
    echo_ack: InputSeq,
    last_seq: InputSeq,
    _endpoint: iroh::Endpoint,
}

impl RawClient {
    /// Connect to `addr` as `secret`, waiting for the admission ack if the server sends one.
    async fn connect(
        addr: iroh::EndpointAddr,
        secret: iroh::SecretKey,
        admitted: bool,
    ) -> anyhow::Result<Self> {
        let endpoint = bind_endpoint_local(secret, false).await?;
        let conn = endpoint.connect(addr, ALPN).await?;
        if admitted {
            await_admission(&conn).await?;
        }
        let send = conn.open_uni().await?;
        let (tx, frames) = tokio::sync::mpsc::channel(64);
        let reader = conn.clone();
        tokio::spawn(async move {
            while let Ok(mut recv) = reader.accept_uni().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(bytes) = recv.read_to_end(MAX_FRAME).await {
                        if let Ok(frame) = decode_frame(&bytes) {
                            let _ = tx.send(frame).await;
                        }
                    }
                });
            }
        });
        Ok(Self {
            conn,
            send,
            frames,
            screens: HashMap::from([(FrameNum::BLANK, TerminalScreen::default())]),
            newest: FrameNum::BLANK,
            echo_ack: InputSeq(0),
            last_seq: InputSeq(0),
            _endpoint: endpoint,
        })
    }

    async fn write(&mut self, msg: &ClientMsg) -> anyhow::Result<()> {
        self.send.write_all(&encode_client(msg)?).await?;
        Ok(())
    }

    async fn type_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.last_seq = self.last_seq.next();
        let msg = ClientMsg::Input {
            seq: self.last_seq,
            bytes: bytes.to_vec(),
        };
        self.write(&msg).await
    }

    /// Apply and ack frames for `ms`.
    async fn pump(&mut self, ms: u64) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(ms))
            .context("deadline within range")?;
        while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, self.frames.recv()).await {
            if frame.num <= self.newest {
                continue;
            }
            let Some(base) = self.screens.get(&frame.base) else {
                continue;
            };
            let mut next = base.clone();
            next.apply(&frame.diff);
            self.screens.insert(frame.num, next);
            self.newest = frame.num;
            self.echo_ack = self.echo_ack.max(frame.echo_ack);
            self.write(&ClientMsg::Ack { frame: frame.num }).await?;
        }
        Ok(())
    }

    fn screen(&self) -> Option<&TerminalScreen> {
        self.screens.get(&self.newest)
    }
}

#[test]
fn run_session_delivers_keys_and_clamped_resizes_then_kills_the_shell() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
        let addr = loopback_addr(&server_ep);
        let accept = tokio::spawn(async move {
            let incoming = server_ep.accept().await.context("incoming")?;
            let conn = incoming.await?;
            run_session(conn, &["cat".to_owned()], 0, launcher()).await
        });
        let mut client = RawClient::connect(addr, generate_secret_key()?, false).await?;
        client
            .write(&ClientMsg::Resize {
                rows: 65000,
                cols: 1,
            })
            .await?;
        client.type_bytes(b"xy").await?;
        let clamped = clamp_dims(65000, 1);
        let done = |c: &RawClient| {
            c.screen()
                .is_some_and(|s| s.screen().contents().contains("xy") && s.size() == clamped)
                && c.echo_ack >= InputSeq(1)
        };
        for _ in 0..100 {
            client.pump(100).await?;
            if done(&client) {
                break;
            }
        }
        let screen = client.screen().context("a screen")?;
        anyhow::ensure!(
            screen.screen().contents().contains("xy"),
            "input reached the program"
        );
        anyhow::ensure!(screen.size() == clamped, "the resize arrives clamped");
        anyhow::ensure!(
            client.echo_ack == InputSeq(1),
            "the input is acknowledged as echoed: {:?}",
            client.echo_ack
        );
        client.conn.close(0u32.into(), b"done");
        tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .context("run_session returns after the connection ends")???;
        Ok(())
    })
}

#[test]
fn echo_ack_is_tracked_per_connection_so_a_second_connection_sees_only_its_own_input(
) -> anyhow::Result<()> {
    runtime()?.block_on(async {
        // Two connections on ONE session (a peer's reconnect racing its old connection). A types
        // many times, B once. Each must only ever be acked for input it sent.
        let secret = generate_secret_key()?;
        let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
        let addr = loopback_addr(&server_ep);
        let config = ServeConfig {
            allow: vec![format_endpoint_id(&secret.public())],
            command: vec!["cat".to_owned()],
            scrollback: 0,
            launcher: launcher(),
            ..ServeConfig::default()
        };
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(serve_endpoint(
            server_ep,
            Hosting::from_config(&config)?,
            shutdown.clone(),
        ));
        // Both connections share one client identity, so they land on ONE session.
        let mut a = RawClient::connect(addr.clone(), secret.clone(), true).await?;
        let mut b = RawClient::connect(addr, secret, true).await?;
        for _ in 0..30 {
            a.type_bytes(b"a").await?;
            a.pump(20).await?;
            b.pump(20).await?;
            anyhow::ensure!(
                a.echo_ack <= a.last_seq,
                "A was acked for input it never sent"
            );
            anyhow::ensure!(b.echo_ack == InputSeq(0), "B was handed A's echo-ack");
        }
        b.type_bytes(b"b").await?;
        for _ in 0..50 {
            a.pump(20).await?;
            b.pump(20).await?;
            if b.echo_ack == InputSeq(1) && a.echo_ack == a.last_seq {
                break;
            }
        }
        anyhow::ensure!(
            b.echo_ack == InputSeq(1),
            "B is acked for its own one input: {:?}",
            b.echo_ack
        );
        anyhow::ensure!(
            a.echo_ack == a.last_seq,
            "A is acked up to its own last input: {:?} of {:?}",
            a.echo_ack,
            a.last_seq
        );
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        Ok(())
    })
}
