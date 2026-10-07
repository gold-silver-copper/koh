//! Sessions with real programs behind them: the registry's lifecycle, and connections to it over
//! loopback iroh with a minimal koh/3 client.
//!
//! Every session's program starts through the `koh` binary's `__launch`, as `koh serve`'s do; unit
//! tests cannot reach a binary, so these live here.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context as _;
use koh::proto::{
    decode_frame_body, decode_server, dictionary_for, encode_client, ClientMsg, FrameNum, InputSeq,
    ServerMsg, MAX_FRAME,
};
use koh::pty::Launcher;
use koh::server::cli::{serve_endpoint, Hosting, ServeConfig};
use koh::server::run_session;
use koh::server::session::AttachKind;
use koh::server::{Registry, SessionSpec};
use koh::terminal::{clamp_dims, RowEncodings, Size, TerminalScreen};
use koh::transport_iroh::admission::await_admission;
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr, ALPN};
use tokio_util::sync::CancellationToken;

/// The launcher every session in these tests starts through.
fn launcher() -> Launcher {
    Launcher::new(env!("CARGO_BIN_EXE_koh"))
}

/// The runtime for a test. `#[tokio::test]` is not used: its expansion `allow`s
/// `clippy::expect_used`, which koh forbids, and a `forbid` rejects that `allow`.
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
    /// Each frame's base, rows and compressed body, to inflate once its base is found.
    frames: tokio::sync::mpsc::Receiver<(FrameNum, Vec<u16>, Vec<u8>)>,
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
                        if let Ok(ServerMsg::Frame { base, rows, body }) = decode_server(&bytes) {
                            let _ = tx.send((base, rows, body)).await;
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
        while let Ok(Some((base, rows, body))) =
            tokio::time::timeout_at(deadline, self.frames.recv()).await
        {
            let Some(base_screen) = self.screens.get(&base) else {
                continue;
            };
            let Ok(frame) = decode_frame_body(
                base,
                &body,
                &dictionary_for(base, base_screen, &rows, &mut RowEncodings::default()),
            ) else {
                continue;
            };
            if frame.num <= self.newest {
                continue;
            }
            let base = base_screen;
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
            .write(&ClientMsg::Resize(Size::new(65000, 1)))
            .await?;
        client.type_bytes(b"xy").await?;
        let clamped = clamp_dims(Size::new(65000, 1));
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
            allow: vec![secret.public()],
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

/// A single-threaded runtime, so the registry, session and forwarding tasks interleave the same
/// way every run.
fn current_thread_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

/// A reconnect that races its exited session's teardown creates a new session, and that one stays
/// registered: the next attach while it is live reattaches to it.
#[test]
fn a_late_ended_from_a_torn_down_session_does_not_unregister_its_replacement() -> anyhow::Result<()>
{
    current_thread_runtime()?.block_on(async {
        let reg = registry(&["true"], 1, Duration::from_secs(30));
        let a = peer()?;
        let (mut c1, kind) = reg.attach(a).await.context("first attach")?;
        anyhow::ensure!(kind == AttachKind::Created, "first attach: {kind:?}");
        for _ in 0..100 {
            if c1.screen().exit_code().is_some() {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(50), c1.next_screen()).await;
        }
        anyhow::ensure!(c1.screen().exit_code().is_some(), "the program exits");
        drop(c1);
        // Reconnect at once, racing the exited session's teardown: a new session is created.
        let (c2, kind) = reg.attach(a).await.context("reconnect")?;
        anyhow::ensure!(kind == AttachKind::Created, "reconnect: {kind:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
        // c2 is still attached to its live session, so this must reattach to it.
        let third = attach_kind(&reg, a).await;
        let other = attach_kind(&reg, peer()?).await;
        drop(c2);
        reg.shutdown().await;
        anyhow::ensure!(
            matches!(third, Some(AttachKind::Reattached { .. })),
            "a second connection while c2 is live must reattach to c2's session, got {third:?}"
        );
        anyhow::ensure!(
            other.is_none(),
            "max_sessions=1 with a live session must refuse another peer, got {other:?}"
        );
        Ok(())
    })
}

/// More detaches than the session's control queue holds, at once, must all count: after the TTL
/// the session is reaped and the next attach creates a new one.
#[test]
fn a_burst_of_detaches_larger_than_the_control_queue_still_starts_the_ttl() -> anyhow::Result<()> {
    current_thread_runtime()?.block_on(async {
        let reg = registry(&["sleep", "30"], 4, Duration::from_millis(200));
        let p = peer()?;
        let mut clients = Vec::new();
        for _ in 0..20 {
            clients.push(reg.attach(p).await.context("attach")?.0);
        }
        drop(clients);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let kind = attach_kind(&reg, p).await;
        reg.shutdown().await;
        anyhow::ensure!(
            kind == Some(AttachKind::Created),
            "every client left 1.3 s past a 200 ms TTL, so the session is reaped; got {kind:?}"
        );
        Ok(())
    })
}

/// Shutdown ends every session, even one a connection is still attached to, and waits for it.
#[test]
fn shutdown_ends_a_session_that_still_has_a_client() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let reg = registry(&["sleep", "30"], 4, Duration::from_secs(30));
        let (mut client, _) = reg.attach(peer()?).await.context("attach")?;
        tokio::time::timeout(Duration::from_secs(5), reg.shutdown())
            .await
            .context("shutdown returns")?;
        // A screen published before shutdown may still be unseen: drain it, then the end.
        let drained = tokio::time::timeout(Duration::from_secs(1), async {
            while client.next_screen().await.is_some() {}
        })
        .await;
        anyhow::ensure!(
            drained.is_ok(),
            "after shutdown the held client's session has ended"
        );
        anyhow::ensure!(!client.can_send(), "the ended session takes no input");
        Ok(())
    })
}

/// A reconnect right after the program exited and its last client left never reattaches to the
/// dead session, and is answered even when its request lands as that session ends, however the
/// session and registry tasks interleave across worker threads.
#[test]
fn a_reconnect_right_after_exit_never_reattaches_the_exited_session() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(async {
            let reg = registry(&["true"], 4, Duration::from_secs(30));
            let a = peer()?;
            let mut client = reg.attach(a).await.context("first attach")?.0;
            for round in 0..100 {
                for _ in 0..100 {
                    if client.screen().exit_code().is_some() {
                        break;
                    }
                    let _ =
                        tokio::time::timeout(Duration::from_millis(50), client.next_screen()).await;
                }
                anyhow::ensure!(
                    client.screen().exit_code().is_some(),
                    "round {round}: exits"
                );
                drop(client);
                let (next, kind) = tokio::time::timeout(Duration::from_secs(5), reg.attach(a))
                    .await
                    .with_context(|| format!("round {round}: the reconnect is answered"))?
                    .context("reconnect")?;
                anyhow::ensure!(
                    kind == AttachKind::Created,
                    "round {round}: a reconnect after exit gets a new session, got {kind:?}"
                );
                client = next;
            }
            drop(client);
            reg.shutdown().await;
            Ok(())
        })
}

/// A program that exits while no client is attached ends its session: an attach before the next
/// TTL check starts a new one, rather than reattaching to the exited one.
#[test]
fn a_session_whose_program_exited_while_detached_is_not_reattached() -> anyhow::Result<()> {
    current_thread_runtime()?.block_on(async {
        let reg = registry(&["sleep", "0.3"], 4, Duration::from_secs(30));
        let p = peer()?;
        let (client, kind) = reg.attach(p).await.context("attach")?;
        anyhow::ensure!(kind == AttachKind::Created, "first attach: {kind:?}");
        drop(client);
        // The program exits while detached, well before the TTL's next check.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let kind = attach_kind(&reg, p).await;
        reg.shutdown().await;
        anyhow::ensure!(
            kind == Some(AttachKind::Created),
            "the exited session must not be reattached; got {kind:?}"
        );
        Ok(())
    })
}
