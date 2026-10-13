//! Sessions with real programs behind them: the registry's lifecycle, and connections to it over
//! loopback iroh with a minimal koh/6 client.
//!
//! Every session's program starts through the `koh` binary's `__launch`, as `koh serve`'s do; unit
//! tests cannot reach a binary, so these live here.
#![forbid(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context as _;
use koh::proto::{
    decode_frame_body, decode_server, dictionary_for, encode_client, ClientMsg, Close, FrameNum,
    InputSeq, ServerMsg, MAX_FRAME,
};
use koh::pty::Launcher;
use koh::server::cli::{serve_endpoint, Hosting, ServeConfig};
use koh::server::session::AttachKind;
use koh::server::{Registry, SessionSpec};
use koh::terminal::{clamp_dims, RowEncodings, Size, TerminalScreen};
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr, ALPN};
use tokio_util::sync::CancellationToken;

/// The accept loop on a loopback endpoint, allowing `client` and hosting `command`: its address,
/// the token that stops it, and its task.
async fn loopback_serve(
    client: iroh::EndpointId,
    command: &[&str],
) -> anyhow::Result<(
    iroh::EndpointAddr,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
)> {
    let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
    let addr = loopback_addr(&server_ep);
    let config = ServeConfig {
        allow: vec![client],
        command: command.iter().map(|arg| (*arg).to_owned()).collect(),
        launcher: launcher(),
        ..ServeConfig::default()
    };
    let shutdown = CancellationToken::new();
    let task = koh_testkit::spawn(serve_endpoint(
        server_ep,
        Hosting::from_config(&config)?,
        shutdown.clone(),
    ));
    Ok((addr, shutdown, task))
}

/// The launcher every session in these tests starts through.
fn launcher() -> Launcher {
    Launcher::isolated(env!("CARGO_BIN_EXE_koh"), koh_testkit::home!())
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    koh_testkit::multi_thread(2)
}

/// A registry allowing every peer.
fn registry(command: &[&str], max_sessions: usize, ttl: Duration) -> std::io::Result<Registry> {
    registry_allowing(command, max_sessions, ttl, |_| true)
}

fn registry_allowing(
    command: &[&str],
    max_sessions: usize,
    ttl: Duration,
    allows: impl Fn(&iroh::EndpointId) -> bool + Send + 'static,
) -> std::io::Result<Registry> {
    let spec = SessionSpec {
        command: command.iter().map(|arg| (*arg).to_owned()).collect(),
        scrollback: 0,
        max_sessions,
        ttl,
        launcher: launcher(),
    };
    Registry::spawn(spec, allows)
}

/// Attach `peer` and say how.
async fn attach_kind(reg: &Registry, peer: iroh::EndpointId) -> Option<AttachKind> {
    reg.attach(peer).await.ok().map(|(_, kind)| kind)
}

fn peer() -> std::io::Result<iroh::EndpointId> {
    Ok(generate_secret_key()?.public())
}

#[test]
fn attach_creates_then_reattaches_the_same_peer() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let reg = registry(&["sleep", "30"], 4, Duration::from_secs(30))?;
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
        let reg = registry(&["sleep", "30"], 1, Duration::from_secs(30))?;
        let (a, b) = (peer()?, peer()?);
        let (a_client, _) = reg
            .attach(a)
            .await
            .context("A creates the one allowed session")?;
        anyhow::ensure!(
            matches!(reg.attach(b).await, Err(Close::AtCapacity)),
            "a second distinct peer is refused at the cap, for now"
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
        let reg = registry(&["sleep", "30"], 4, Duration::from_millis(150))?;
        let peer = peer()?;
        let (a, _) = reg.attach(peer).await.context("A")?;
        let (b, _) = reg
            .attach(peer)
            .await
            .context("B (concurrent, same session)")?;
        // Dropping ONE of two attached clients must not start the TTL.
        drop(a);
        // Time must pass here: the session must outlive its TTL. (Polling would attach, and a
        // detach restarts the TTL.)
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
        // Past the TTL, by time: polling would attach, and a detach restarts it.
        tokio::time::sleep(Duration::from_millis(500)).await;
        anyhow::ensure!(
            attach_kind(&reg, peer).await == Some(AttachKind::Created),
            "after the last detach and the TTL the session is gone"
        );
        reg.shutdown().await;
        Ok(())
    })
}

/// A bare koh/6 client: writes messages, applies frames whose base it holds, and acks them.
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
    /// Connect to `addr` as `secret`, and wait for the first frame, which admits it.
    async fn connect(addr: iroh::EndpointAddr, secret: iroh::SecretKey) -> anyhow::Result<Self> {
        let endpoint = bind_endpoint_local(secret, false).await?;
        let conn = endpoint.connect(addr, ALPN).await?;
        let send = conn.open_uni().await?;
        let (tx, frames) = tokio::sync::mpsc::channel(64);
        let reader = conn.clone();
        koh_testkit::spawn(async move {
            while let Ok(mut recv) = reader.accept_uni().await {
                let tx = tx.clone();
                koh_testkit::spawn(async move {
                    if let Ok(bytes) = recv.read_to_end(MAX_FRAME).await {
                        if let Ok(ServerMsg::Frame { base, rows, body }) = decode_server(&bytes) {
                            let _ = tx.send((base, rows, body)).await;
                        }
                    }
                });
            }
        });
        let mut client = Self {
            conn,
            send,
            frames,
            screens: HashMap::from([(FrameNum::BLANK, TerminalScreen::default())]),
            newest: FrameNum::BLANK,
            echo_ack: InputSeq(0),
            last_seq: InputSeq(0),
            _endpoint: endpoint,
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            while client.newest == FrameNum::BLANK {
                client.pump(20).await?;
            }
            anyhow::Ok(client)
        })
        .await
        .context("no frame came")?
    }

    async fn write(&mut self, msg: &ClientMsg) -> anyhow::Result<()> {
        self.send.write_all(&encode_client(msg)?).await?;
        Ok(())
    }

    async fn type_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.last_seq = self.last_seq.next();
        let mut decoder = fux_vt::keys::decode::Decoder::default();
        let mut inputs = Vec::new();
        decoder.bytes(bytes, &mut inputs);
        decoder.timeout(&mut inputs);
        let events = inputs
            .into_iter()
            .filter_map(|input| match input {
                fux_vt::keys::decode::Input::Key(key) => {
                    Some(koh::events::InputEvent::Key(key.into()))
                }
                fux_vt::keys::decode::Input::Paste(_)
                | fux_vt::keys::decode::Input::PasteTooLong
                | fux_vt::keys::decode::Input::FocusIn
                | fux_vt::keys::decode::Input::FocusOut
                | fux_vt::keys::decode::Input::Mouse(_)
                | fux_vt::keys::decode::Input::Reply(_) => None,
            })
            .collect();
        let msg = ClientMsg::Keys {
            seq: self.last_seq,
            events,
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
            next.apply(&frame.diff)?;
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
fn a_session_takes_keys_and_clamped_resizes_then_ends_with_the_server() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let secret = generate_secret_key()?;
        // The program sees the clamped size too, on its terminal.
        let program = ["sh", "-c", "read l; stty size; cat"];
        let (addr, shutdown, serve) = loopback_serve(secret.public(), &program).await?;
        let mut client = RawClient::connect(addr, secret).await?;
        client
            .write(&ClientMsg::Resize(Size::new(65000, 1)))
            .await?;
        client.type_bytes(b"xy\r").await?;
        let clamped = clamp_dims(Size::new(65000, 1));
        let size = format!("{} {}", clamped.rows, clamped.cols);
        let done = |c: &RawClient| {
            c.screen().is_some_and(|s| {
                let shown = s.screen().contents();
                shown.contains("xy") && shown.contains(&size) && s.size() == clamped
            }) && c.echo_ack >= InputSeq(1)
        };
        for _ in 0..100 {
            client.pump(100).await?;
            if done(&client) {
                break;
            }
        }
        let screen = client.screen().context("a screen")?;
        let shown = screen.screen().contents();
        anyhow::ensure!(shown.contains("xy"), "input reached the program: {shown:?}");
        anyhow::ensure!(screen.size() == clamped, "the resize arrives clamped");
        anyhow::ensure!(
            shown.contains(&size),
            "and the program's terminal is that size: {shown:?}"
        );
        anyhow::ensure!(
            client.echo_ack == InputSeq(1),
            "the input is acknowledged as echoed: {:?}",
            client.echo_ack
        );
        client.conn.close(0u32.into(), b"done");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .context("the server ends its session and returns")???;
        Ok(())
    })
}

#[test]
fn echo_ack_is_tracked_per_connection_and_only_the_newest_ones_input_reaches_the_program(
) -> anyhow::Result<()> {
    runtime()?.block_on(async {
        // Two connections on ONE session (a peer's reconnect racing its old connection). A types
        // many times, B once. Each must only ever be acked for input it sent, and only B's, the
        // newest attachment's, reaches the program: A's is an old connection's, sent late.
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
        let server = koh_testkit::spawn(serve_endpoint(
            server_ep,
            Hosting::from_config(&config)?,
            shutdown.clone(),
        ));
        // Both connections share one client identity, so they land on ONE session.
        let mut a = RawClient::connect(addr.clone(), secret.clone()).await?;
        let mut b = RawClient::connect(addr, secret).await?;
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
            let typed = b
                .screen()
                .is_some_and(|s| s.screen().contents().contains('b'));
            if typed && b.echo_ack == InputSeq(1) && a.echo_ack == a.last_seq {
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
        let shown = b.screen().context("a screen")?.screen().contents();
        anyhow::ensure!(
            shown.contains('b') && !shown.contains('a'),
            "only the newest attachment types: {shown:?}"
        );
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        Ok(())
    })
}

/// A reconnect after the program exited (the link dropped before the final frame was acknowledged)
/// finds its final screen and status, not a new shell, and the session holds its slot. Once a
/// client has that screen the session ends, and the next attach starts a new one, which stays
/// registered while it lives.
#[test]
fn a_reconnect_after_exit_sees_the_exit_until_a_client_has_it() -> anyhow::Result<()> {
    // The first session's program leaves `marker` and exits 3 at once; its replacement's lives.
    // The path reaches `sh` as `$1`, never spliced into the script.
    let dir = koh_testkit::scratch!("reconnect-after-exit")?;
    let marker = dir.join("marker");
    let path = marker.to_str().context("a UTF-8 scratch dir")?;
    let script = r#"[ -e "$1" ] && exec sleep 30; : > "$1"; exit 3"#;
    koh_testkit::current_thread()?.block_on(async {
        let reg = registry(
            &["sh", "-c", script, "sh", path],
            1,
            Duration::from_secs(30),
        )?;
        let a = peer()?;
        let (mut c1, kind) = reg.attach(a).await.context("first attach")?;
        anyhow::ensure!(kind == AttachKind::Created, "first attach: {kind:?}");
        await_exit(&mut c1).await?;
        drop(c1);
        let (mut c2, kind) = reg.attach(a).await.context("reconnect")?;
        anyhow::ensure!(
            matches!(kind, AttachKind::Reattached { .. }),
            "reconnect: {kind:?}"
        );
        anyhow::ensure!(c2.screen().exit_code() == Some(3), "the exit is seen");
        anyhow::ensure!(
            attach_kind(&reg, peer()?).await.is_none(),
            "the exited session holds its slot"
        );
        // The client has the final screen: the session ends.
        c2.ended().await;
        while c2.next_screen().await.is_some() {}
        let (c3, kind) = reg.attach(a).await.context("after the end")?;
        anyhow::ensure!(kind == AttachKind::Created, "after the end: {kind:?}");
        // c3 is still attached to its live session, so this must reattach to it.
        let again = attach_kind(&reg, a).await;
        let other = attach_kind(&reg, peer()?).await;
        drop(c3);
        reg.shutdown().await;
        anyhow::ensure!(
            matches!(again, Some(AttachKind::Reattached { .. })),
            "c3's session stays registered, got {again:?}"
        );
        anyhow::ensure!(other.is_none(), "and holds the one slot, got {other:?}");
        Ok(())
    })
}

/// A reconnect that lands as a session whose program exited is ending, however the session and
/// registry tasks interleave across worker threads, is answered: by that session, still showing
/// the exit, or by a new one. A client that left without the final screen always finds it.
#[test]
fn a_reconnect_racing_the_end_of_an_exited_session_is_answered() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let reg = registry(&["true"], 4, Duration::from_secs(30))?;
        let a = peer()?;
        let mut client = reg.attach(a).await.context("first attach")?.0;
        // An acknowledgement the reconnect overtook ends the session it reattached to, once the
        // reconnect was shown the exit: the next reconnect finds a new session.
        let mut ending = false;
        for round in 0..100 {
            await_exit(&mut client)
                .await
                .with_context(|| format!("round {round}: exits"))?;
            // Every other round the client has the final screen just as the reconnect is asked.
            let acknowledged = round % 2 == 0;
            let ended = async {
                if acknowledged {
                    client.ended().await;
                }
            };
            let (attached, ()) = tokio::join!(
                tokio::time::timeout(Duration::from_secs(5), reg.attach(a)),
                ended
            );
            drop(client);
            let (next, kind) = attached
                .with_context(|| format!("round {round}: the reconnect is answered"))?
                .context("reconnect")?;
            let shown = next.screen().exit_code();
            anyhow::ensure!(
                match kind {
                    AttachKind::Created => acknowledged || ending,
                    AttachKind::Reattached { .. } => shown == Some(0),
                },
                "round {round}: acknowledged {acknowledged}, got {kind:?} showing exit {shown:?}"
            );
            ending = acknowledged && kind != AttachKind::Created;
            client = next;
        }
        drop(client);
        reg.shutdown().await;
        Ok(())
    })
}

/// A session whose program exited, left before any client had its final screen, is kept for the
/// TTL and then reaped: the next attach starts a new one.
#[test]
fn an_exited_session_no_client_saw_end_is_reaped_after_the_ttl() -> anyhow::Result<()> {
    koh_testkit::current_thread()?.block_on(async {
        let reg = registry(&["true"], 4, Duration::from_millis(200))?;
        let a = peer()?;
        let (mut client, _) = reg.attach(a).await.context("attach")?;
        await_exit(&mut client).await?;
        drop(client);
        // Past the TTL, by time: polling would attach, and an attach restarts it.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let kind = attach_kind(&reg, a).await;
        reg.shutdown().await;
        anyhow::ensure!(kind == Some(AttachKind::Created), "{kind:?}");
        Ok(())
    })
}

/// A peer removed from the allowlist has its session ended, its program hung up, and starts no
/// other: an attach the registry takes once the list no longer allows it is refused, even one on its
/// way as the peer was removed. Allowed again, it gets a new session.
#[test]
fn ending_a_peers_session_ends_it_at_once() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    runtime()?.block_on(async {
        let allowed = std::sync::Arc::new(AtomicBool::new(true));
        let allows = std::sync::Arc::clone(&allowed);
        let reg = registry_allowing(&["sleep", "30"], 4, Duration::from_secs(30), move |_| {
            allows.load(Relaxed)
        })?;
        let a = peer()?;
        let (mut client, _) = reg.attach(a).await.context("attach")?;
        allowed.store(false, Relaxed);
        let refused = reg.attach(a).await.err();
        anyhow::ensure!(refused == Some(Close::NotAuthorized), "{refused:?}");
        reg.end(a).await;
        allowed.store(true, Relaxed);
        tokio::time::timeout(Duration::from_secs(5), async {
            while client.next_screen().await.is_some() {}
        })
        .await
        .context("the session ends")?;
        let kind = attach_kind(&reg, a).await;
        reg.shutdown().await;
        anyhow::ensure!(kind == Some(AttachKind::Created), "{kind:?}");
        Ok(())
    })
}

/// More detaches than the session's control queue holds, at once, must all count: after the TTL
/// the session is reaped and the next attach creates a new one.
#[test]
fn a_burst_of_detaches_larger_than_the_control_queue_still_starts_the_ttl() -> anyhow::Result<()> {
    koh_testkit::current_thread()?.block_on(async {
        let reg = registry(&["sleep", "30"], 4, Duration::from_millis(200))?;
        let p = peer()?;
        let mut clients = Vec::new();
        for _ in 0..20 {
            clients.push(reg.attach(p).await.context("attach")?.0);
        }
        drop(clients);
        // Past the TTL, by time: polling would attach, and a detach restarts it.
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
        let reg = registry(&["sleep", "30"], 4, Duration::from_secs(30))?;
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
        Ok(())
    })
}

#[test]
fn a_session_ends_when_its_program_does_whatever_holds_its_terminal() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        // A job left in the background keeps the terminal open after the shell exited; a program
        // that closed its terminal runs on with none. Either way the session ends, with a status.
        // On macOS the terminal stays open while its session leader runs, whatever it closed, so
        // the session rightly stays: only Linux reports the terminal closed.
        let closed = cfg!(any(target_os = "linux", target_os = "android"))
            .then_some(("exec </dev/null >/dev/null 2>&1; sleep 3600", 129));
        for (script, code) in std::iter::once(("sleep 3600 & exit 7", 7)).chain(closed) {
            let reg = registry(&["sh", "-c", script], 4, Duration::from_secs(30))?;
            let (mut client, _) = reg.attach(peer()?).await.context("attach")?;
            await_exit(&mut client).await.context(script)?;
            anyhow::ensure!(
                client.screen().exit_code() == Some(code),
                "{script}: {:?}",
                client.screen().exit_code()
            );
            drop(client);
            tokio::time::timeout(Duration::from_secs(5), reg.shutdown())
                .await
                .context("shutdown waits only for the hang-up")?;
        }
        Ok(())
    })
}

/// Wait until `client`'s screen carries the program's exit code.
async fn await_exit(client: &mut koh::server::session::SessionClient) -> anyhow::Result<()> {
    for _ in 0..100 {
        if client.screen().exit_code().is_some() {
            return Ok(());
        }
        let _ = tokio::time::timeout(Duration::from_millis(50), client.next_screen()).await;
    }
    anyhow::bail!("the exit code never reached the screen")
}

/// A connection whose session has already exited when it attaches is told so: `run_attached`
/// sends the final frame and closes saying the session ended, rather than waiting for a screen change
/// that never comes.
#[test]
fn a_connection_attached_to_an_already_exited_session_is_told_it_ended() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        // `true` has exited by the time the connection's loop first looks.
        let secret = generate_secret_key()?;
        let (addr, shutdown, serve) = loopback_serve(secret.public(), &["true"]).await?;
        let mut raw = RawClient::connect(addr, secret).await?;
        let mut close = None;
        for _ in 0..30 {
            // An ack written as the server closes fails: the close is what is looked for.
            let _ = raw.pump(100).await;
            close = raw.conn.close_reason();
            if close.is_some() {
                break;
            }
        }
        shutdown.cancel();
        let _ = serve.await;
        let ended = koh::transport_iroh::closed_because(&raw.conn) == Some(Close::SessionEnded);
        anyhow::ensure!(
            ended,
            "the connection is closed as ended within 3s: {close:?}"
        );
        Ok(())
    })
}

/// A program that cannot start is not reported as the server being full, nor as a refusal for
/// good: no frame comes, and the connection is closed saying the session could not start.
#[test]
fn a_program_that_cannot_start_is_refused_as_such() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let secret = generate_secret_key()?;
        let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
        let addr = loopback_addr(&server_ep);
        let config = ServeConfig {
            allow: vec![secret.public()],
            command: vec!["/nonexistent/koh-test-program".to_owned()],
            launcher: launcher(),
            ..ServeConfig::default()
        };
        let shutdown = CancellationToken::new();
        let server = koh_testkit::spawn(serve_endpoint(
            server_ep,
            Hosting::from_config(&config)?,
            shutdown.clone(),
        ));
        let endpoint = bind_endpoint_local(secret, false).await?;
        let dialed = tokio::time::timeout(
            Duration::from_secs(10),
            koh::client::IrohConnector::new(endpoint, addr).connect(),
        )
        .await;
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        let Err(error) = dialed.context("the server answers")? else {
            anyhow::bail!("admitted with no session");
        };
        anyhow::ensure!(
            error.downcast_ref::<Close>() == Some(&Close::CouldNotStart),
            "{error:#}"
        );
        Ok(())
    })
}

/// A UDP relay on loopback to `server`, from its own socket: each datagram waits `delay` (the
/// link's latency, which is what is tested), and the server's are dropped unless `answers`, so a
/// handshake through it stalls. Its address.
async fn relay(
    server: std::net::SocketAddr,
    delay: Duration,
    answers: bool,
) -> std::io::Result<std::net::SocketAddr> {
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    let (near, far) = (
        Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
        Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
    );
    let at = near.local_addr()?;
    let (client, client_at) = tokio::sync::watch::channel(None);
    let later = move |socket: &Arc<UdpSocket>, bytes: Vec<u8>, to| {
        let socket = Arc::clone(socket);
        koh_testkit::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = socket.send_to(&bytes, to).await;
        });
    };
    let (inward, outward) = (Arc::clone(&near), Arc::clone(&far));
    koh_testkit::spawn(async move {
        let mut buf = Vec::with_capacity(65_536);
        while let Ok((_, from)) = inward.recv_buf_from(&mut buf).await {
            client.send_replace(Some(from));
            later(&outward, std::mem::take(&mut buf), server);
            buf.reserve(65_536);
        }
    });
    koh_testkit::spawn(async move {
        let mut buf = Vec::with_capacity(65_536);
        while far.recv_buf(&mut buf).await.is_ok() {
            let bytes = std::mem::take(&mut buf);
            buf.reserve(65_536);
            let to = *client_at.borrow();
            if let Some(to) = to.filter(|_| answers) {
                later(&near, bytes, to);
            }
        }
    });
    Ok(at)
}

/// A flood of handshakes that never finish, from the allowed client's own address, takes neither
/// the one connection a server allows (`--max-connections 1`) nor the room for the client's own
/// handshake, which takes several round trips of 100 ms: the flood is asked to show it gets the
/// server's answers (a QUIC retry), and it never does, as a spoofed address could not.
#[test]
fn an_allowed_client_far_away_gets_in_through_a_flood_of_stalled_handshakes() -> anyhow::Result<()>
{
    koh_testkit::multi_thread(3)?.block_on(async {
        let good = generate_secret_key()?;
        let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
        let server = server_ep.id();
        let port = server_ep
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .context("an IPv4 socket")?
            .port();
        let config = ServeConfig {
            allow: vec![good.public()],
            command: vec!["sleep".to_owned(), "30".to_owned()],
            launcher: launcher(),
            max_connections: std::num::NonZeroU32::MIN,
            ..ServeConfig::default()
        };
        let shutdown = CancellationToken::new();
        let serving = koh_testkit::spawn(serve_endpoint(
            server_ep,
            Hosting::from_config(&config)?,
            shutdown.clone(),
        ));
        let at = move |relayed| koh::transport_iroh::direct_addr(server, relayed);
        let server_udp = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        // Some 200 dials a second, each stalled.
        let (stalled, black_hole) = (
            bind_endpoint_local(generate_secret_key()?, false).await?,
            at(relay(server_udp, Duration::ZERO, false).await?),
        );
        let (flooding, flood_on) = tokio::sync::oneshot::channel();
        let flood = koh_testkit::spawn(async move {
            let mut flooding = Some(flooding);
            for n in 0..10_000 {
                let (endpoint, to) = (stalled.clone(), black_hole.clone());
                koh_testkit::spawn(async move {
                    let _ = tokio::time::timeout(WAIT, endpoint.connect(to, ALPN)).await;
                });
                if n == 100 {
                    flooding.take().map(|on| on.send(()));
                }
                // The flood's rate.
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let _ = flood_on.await;
        let near = bind_endpoint_local(good, false).await?;
        let far = at(relay(server_udp, Duration::from_millis(50), true).await?);
        let mut admitted = false;
        for _ in 0..3 {
            if let Ok(Ok(conn)) = tokio::time::timeout(WAIT, near.connect(far.clone(), ALPN)).await
            {
                // Its first frame admits it.
                admitted = matches!(
                    tokio::time::timeout(WAIT, conn.accept_uni()).await,
                    Ok(Ok(_))
                );
            }
            if admitted {
                break;
            }
        }
        flood.abort();
        shutdown.cancel();
        let _ = tokio::time::timeout(WAIT, serving).await;
        anyhow::ensure!(admitted, "the allowed client never got in");
        Ok(())
    })
}

/// How long the flood test waits on anything.
const WAIT: Duration = Duration::from_secs(5);
