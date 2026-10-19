//! Hostile peers on koh/14, both directions.
//!
//! A malicious client (admitted, so on the allowlist) throws malformed and oversized traffic at a
//! real server; a malicious server throws it at a real client. Neither may crash or hang the
//! other, and a protocol violation closes the connection.

use std::time::Duration;

use anyhow::Context as _;
use iroh::endpoint::Connection;
use iroh::{EndpointId, SecretKey};
use koh::proto::{
    encode_client, encode_shown, ClientMsg, Close, InputSeq, Shown, MAX_CLIENT_MESSAGE, SHOWN_TAG,
};
use koh::request::{Attached, Pick, Request, Resume, RunId, SessionNum, MAX_REPLY, MAX_REQUEST};
use koh::terminal::Size;
use koh::transport_iroh::{generate_secret_key, ALPN};

use crate::harness::{identity, Client, Options, Server};
use crate::link::{FaultNet, Profile};

const WAIT: Duration = Duration::from_secs(20);

fn net() -> FaultNet {
    FaultNet::new(Profile::default(), 1)
}

/// Connect to `server` as `secret`, ask for a shell on the first stream, wait for the server's
/// first stream, which admits it, and keep the endpoint and that stream alive; the caller then
/// speaks koh/14 by hand.
async fn admitted(
    net: &FaultNet,
    secret: SecretKey,
    server: EndpointId,
) -> anyhow::Result<Connection> {
    let endpoint = net.endpoint(secret, false).await?;
    let conn = endpoint.connect(FaultNet::addr(server), ALPN).await?;
    let request = koh::request::encode(
        &Request::Shell {
            pick: Pick::Latest,
            size: Size::new(24, 80),
            program: None,
            cwd: None,
        },
        MAX_REQUEST,
    )?;
    raw_client_stream(&conn, &request).await?;
    conn.accept_uni().await?;
    Box::leak(Box::new(endpoint));
    Ok(conn)
}

/// The client typed `text`, as its first input.
fn typed(text: &str) -> ClientMsg {
    use koh::events::{InputEvent, WireKey, WireKeyCode};
    let key = |c| match c {
        '\r' => WireKeyCode::Enter,
        c => WireKeyCode::Char(c),
    };
    ClientMsg::Keys {
        seq: InputSeq(1),
        events: text
            .chars()
            .map(|c| {
                InputEvent::Key(WireKey {
                    key: key(c),
                    mods: 0,
                    kitty: None,
                })
            })
            .collect(),
    }
}

/// Open a client stream, write `bytes`, and keep it open (a real client keeps its streams).
async fn raw_client_stream(conn: &Connection, bytes: &[u8]) -> anyhow::Result<()> {
    let mut send = conn.open_uni().await?;
    send.write_all(bytes).await?;
    Box::leak(Box::new(send));
    Ok(())
}

/// A server hosting `sh` for `evil` plus a well-behaved client, so the attack races real traffic.
async fn server_under_attack(net: &FaultNet, evil: EndpointId) -> anyhow::Result<(Server, Client)> {
    let good = identity()?;
    let server = Server::start(net, &[evil, good.public()], &["sh"]).await?;
    let client = Client::connect(net, good, server.id).await?;
    Ok((server, client))
}

/// Wait for `conn` to close, and check the server closed it for breaking the protocol: not for a
/// crash, a timeout or any other reason.
async fn closed_for_breaking_the_protocol(conn: &Connection, what: &str) -> anyhow::Result<()> {
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .with_context(|| format!("the server must close a connection that sent {what}"))?;
    anyhow::ensure!(
        matches!(&closed, iroh::endpoint::ConnectionError::ApplicationClosed(c)
            if c.error_code == Close::ProtocolError.code().into()),
        "{what}: closed with {closed:?}"
    );
    Ok(())
}

async fn assert_good_client_still_works(client: &mut Client) -> anyhow::Result<()> {
    client.send(b"echo STILL_A''LIVE\r").await?;
    anyhow::ensure!(
        client
            .wait_until(WAIT, |t| t.contains("STILL_ALIVE"))
            .await
            .is_some(),
        "the good client's session broke; screen:\n{}",
        client.screen()
    );
    Ok(())
}

#[test]
fn an_oversized_client_message_closes_the_connection_only() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = net();
        let evil = identity()?;
        let (server, mut good) = server_under_attack(&net, evil.public()).await?;
        let conn = admitted(&net, evil, server.id).await?;
        // A length prefix claiming far more than the cap: rejected on the header.
        let huge = u32::try_from(MAX_CLIENT_MESSAGE + 1)
            .context("the bound fits u32")?
            .to_be_bytes();
        raw_client_stream(&conn, &huge).await?;
        closed_for_breaking_the_protocol(&conn, "an oversized message's length").await?;
        assert_good_client_still_works(&mut good).await?;
        let _ = good.finish().await;
        server.stop().await?;
        Ok(())
    })
}

/// A client that sends input no terminal sends (a modifier bit no key has, a paste piece over
/// the cap, a palette past 16 entries) loses its connection, each, and
/// the server goes on serving the good client.
#[test]
fn malformed_keys_and_colours_close_the_connection_only() -> anyhow::Result<()> {
    use koh::events::{InputEvent, WireColours, WireKey, WireKeyCode, MAX_PASTE, PALETTE};
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = net();
        let evil = identity()?;
        let (server, mut good) = server_under_attack(&net, evil.public()).await?;
        let keys = |events| ClientMsg::Keys {
            seq: InputSeq(1),
            events,
        };
        let key = |key, mods| {
            InputEvent::Key(WireKey {
                key,
                mods,
                kitty: None,
            })
        };
        for msg in [
            keys(vec![key(WireKeyCode::Char('x'), 0x80)]),
            keys(vec![InputEvent::Paste("x".repeat(MAX_PASTE + 1))]),
            ClientMsg::Colours(WireColours {
                palette: vec![None; PALETTE + 1],
                ..WireColours::default()
            }),
        ] {
            // Built by hand: `encode_client` refuses to.
            let body = postcard::to_allocvec(&msg)?;
            let mut stream = u32::try_from(body.len())?.to_be_bytes().to_vec();
            stream.extend_from_slice(&body);
            let conn = admitted(&net, evil.clone(), server.id).await?;
            raw_client_stream(&conn, &stream).await?;
            closed_for_breaking_the_protocol(&conn, &format!("{msg:?}")).await?;
        }
        assert_good_client_still_works(&mut good).await?;
        let _ = good.finish().await;
        server.stop().await?;
        Ok(())
    })
}

/// A session whose program stops reading, its input queue then filled, does not stop its
/// connection: the server stops reading the client, and only that, so what the program prints
/// still goes out.
#[test]
fn a_full_session_queue_does_not_stop_the_output() -> anyhow::Result<()> {
    use koh::events::{InputEvent, MAX_PASTE};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = net();
        let evil = identity()?;
        let printing = "stty raw -echo; while :; do echo tick; sleep 0.05; done";
        let server = Server::start(&net, &[evil.public()], &["sh", "-c", printing]).await?;
        let conn = admitted(&net, evil, server.id).await?;
        let frames = Arc::new(AtomicUsize::new(0));
        let reader = {
            let (conn, frames) = (conn.clone(), frames.clone());
            koh_testkit::spawn(async move {
                while let Ok(mut recv) = conn.accept_uni().await {
                    let frames = frames.clone();
                    koh_testkit::spawn(async move {
                        // Each `tick` the program prints is a few bytes of the stream.
                        while let Ok(Some(chunk)) = recv.read_chunk(64 * 1024).await {
                            frames.fetch_add(chunk.len(), Ordering::Relaxed);
                        }
                    });
                }
            })
        };
        // Two pastes fill the PTY and what waits for it; then keys fill the session's queue, and
        // those after it wait in QUIC's windows until those are full too.
        let mut send = conn.open_uni().await?;
        let written = Arc::new(AtomicUsize::new(0));
        let writer = {
            let written = written.clone();
            koh_testkit::spawn(async move {
                for seq in 1.. {
                    let events = if seq <= 2 {
                        vec![InputEvent::Paste("x".repeat(MAX_PASTE))]
                    } else {
                        let ClientMsg::Keys { events, .. } = typed("x") else {
                            return;
                        };
                        events
                    };
                    let message = ClientMsg::Keys {
                        seq: InputSeq(seq),
                        events,
                    };
                    let Ok(bytes) = encode_client(&message) else {
                        return;
                    };
                    if send.write_all(&bytes).await.is_err() {
                        return;
                    }
                    written.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        // The writer stalls: the server stopped reading the client. Telling a stall from a slow
        // write takes time passing with nothing written; that wait is what is measured.
        let mut stalled = None;
        for _ in 0..40 {
            let before = written.load(Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(500)).await;
            if written.load(Ordering::Relaxed) == before && before > 2 {
                stalled = Some(before);
                break;
            }
        }
        let stalled = stalled.context("the server never stopped reading the client")?;
        // And frames still come, while it stays stalled.
        let before = frames.load(Ordering::Relaxed);
        let deadline = tokio::time::Instant::now() + WAIT;
        while frames.load(Ordering::Relaxed) < before + 100
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let after = frames.load(Ordering::Relaxed);
        let still = written.load(Ordering::Relaxed);
        writer.abort();
        reader.abort();
        server.stop().await?;
        anyhow::ensure!(
            after >= before + 100,
            "the output stopped while the session's queue was full: {before} then {after}"
        );
        anyhow::ensure!(
            still == stalled,
            "the server read the client again ({stalled} then {still} messages), so the queue \
             was not full while the frames came"
        );
        Ok(())
    })
}

#[test]
fn an_opening_request_that_is_no_request_closes_the_connection_only() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = net();
        let evil = identity()?;
        let (server, mut good) = server_under_attack(&net, evil.public()).await?;
        // Garbage where the request goes, then a command holding a NUL (`Request::Exec`, the
        // third kind, of 3 bytes), which no command line can.
        let nul = vec![0, 0, 0, 5, 2, 3, b'a', 0, b'b'];
        for request in [vec![0, 0, 0, 3, 0xff, 0xff, 0xff], nul] {
            let endpoint = net.endpoint(evil.clone(), false).await?;
            let conn = endpoint.connect(FaultNet::addr(server.id), ALPN).await?;
            raw_client_stream(&conn, &request).await?;
            closed_for_breaking_the_protocol(&conn, "a malformed request").await?;
        }
        assert_good_client_still_works(&mut good).await?;
        let _ = good.finish().await;
        server.stop().await?;
        Ok(())
    })
}

#[test]
fn a_client_cannot_open_a_third_stream() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = net();
        let evil = identity()?;
        let (server, mut good) = server_under_attack(&net, evil.public()).await?;
        let conn = admitted(&net, evil, server.id).await?;
        raw_client_stream(&conn, &encode_client(&typed("echo hi\r"))?).await?;
        // The server permits two uni streams from the client, control (its request's) and input,
        // so a third never opens: QUIC's stream-count flow control is the bound, before any koh
        // code runs.
        let third = tokio::time::timeout(Duration::from_secs(2), conn.open_uni()).await;
        anyhow::ensure!(
            third.is_err(),
            "a third client stream must not be grantable"
        );
        assert_good_client_still_works(&mut good).await?;
        let _ = good.finish().await;
        server.stop().await?;
        Ok(())
    })
}

#[test]
fn a_flood_of_connections_and_garbage_does_not_take_the_server_down() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = net();
        let evil = identity()?;
        let (server, mut good) = server_under_attack(&net, evil.public()).await?;
        for _ in 0..50 {
            let conn = admitted(&net, evil.clone(), server.id).await?;
            // A length prefix and a truncated body, over and over.
            raw_client_stream(&conn, &[0, 0, 16, 0, 1, 2, 3]).await?;
            conn.close(0u32.into(), b"next");
        }
        assert_good_client_still_works(&mut good).await?;
        let _ = good.finish().await;
        server.stop().await?;
        Ok(())
    })
}

/// What admits a client: its request read, the first stream says it attached session 1. The
/// request's stream, kept open as the client's control stream.
async fn admit(conn: &Connection) -> anyhow::Result<iroh::endpoint::RecvStream> {
    let mut control = conn.accept_uni().await?;
    koh::transport_iroh::read_framed(&mut control, MAX_REQUEST).await?;
    let attached = Attached {
        at: Resume {
            run: RunId(0),
            session: SessionNum(1),
        },
    };
    let mut send = conn.open_uni().await?;
    send.write_all(&koh::request::encode(&attached, MAX_REPLY)?)
        .await?;
    send.finish()?;
    Ok(control)
}

/// Bind a hand-rolled server for `allow`, admit it, and run `frames` on its connection. Returns the
/// server's id.
async fn evil_server<F>(net: &FaultNet, allow: EndpointId, frames: F) -> anyhow::Result<EndpointId>
where
    F: FnOnce(Connection) -> tokio::task::JoinHandle<()> + Send + 'static,
{
    let secret = generate_secret_key()?;
    let id = secret.public();
    let endpoint = net.endpoint(secret, true).await?;
    koh_testkit::spawn(async move {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let Ok(conn) = incoming.await else { return };
        if conn.remote_id() != allow {
            return;
        }
        let Ok(control) = admit(&conn).await else {
            return;
        };
        Box::leak(Box::new(control));
        let handle = frames(conn);
        Box::leak(Box::new(endpoint));
        let _ = handle.await;
    });
    Ok(id)
}

/// Send `bytes` on an epoch stream of its own, numbered `epoch`.
async fn send_epoch(conn: &Connection, epoch: u32, bytes: &[u8]) {
    if let Ok(mut send) = conn.open_uni().await {
        let mut header = vec![SHOWN_TAG];
        header.extend_from_slice(&epoch.to_be_bytes());
        let _ = send.write_all(&header).await;
        let _ = send.write_all(bytes).await;
        let _ = send.finish();
    }
}

/// `shown`, framed.
fn framed(shown: &[Shown]) -> Vec<u8> {
    shown
        .iter()
        .filter_map(|s| encode_shown(s).ok())
        .flatten()
        .collect()
}

/// What a hostile server sends a client.
#[derive(Clone, Copy, Debug)]
enum Hostile {
    /// A length past the bound, then plain garbage, then a message that does not decode.
    Oversized,
    /// Streams of epochs the client has past, and of no kind it knows.
    StaleEpochs,
    /// Megabytes of output full of sequences, questions and marks among them.
    Flood,
}

/// Send `hostile` on `conn`.
async fn send_hostile(hostile: Hostile, conn: &Connection) {
    match hostile {
        Hostile::Oversized => {
            send_epoch(conn, 1, &u32::MAX.to_be_bytes()).await;
            send_epoch(conn, 2, &[0xff; 4096]).await;
            // A mark carrying a nonce, which no relayed mark does.
            let mut bad = vec![0, 0, 0, 20, 1, 18];
            bad.extend_from_slice(b"D;0;nonce=12345678");
            send_epoch(conn, 3, &bad).await;
        }
        Hostile::StaleEpochs => {
            send_epoch(conn, 1000, &framed(&[Shown::Out(b"epoch 1000".to_vec())])).await;
            for n in (0..1000).rev() {
                send_epoch(
                    conn,
                    n,
                    &framed(&[Shown::Out(format!("stale {n}").into_bytes())]),
                )
                .await;
            }
            for tag in (0..=255_u8).filter(|&tag| tag != SHOWN_TAG) {
                if let Ok(mut send) = conn.open_uni().await {
                    let _ = send
                        .write_all(&[tag, 0xff, 0xff, 0xff, 0xff, 1, 2, 3])
                        .await;
                    let _ = send.finish();
                }
            }
        }
        Hostile::Flood => {
            let mut shown = Vec::new();
            for n in 0..2000 {
                shown.push(Shown::Out(
                    format!("\x1b[6n\x1b]52;c;?\x07\x1b[{n}m\x1b]133;D;9\x07line {n}\r\n\x1b[2J")
                        .into_bytes(),
                ));
            }
            send_epoch(conn, 1, &framed(&shown)).await;
        }
    }
}

/// A client running against a server that sends it `hostile`, then a new epoch it takes,
/// neither crashes nor hangs: it shows that epoch, and quits when told.
#[test]
fn hostile_streams_leave_the_client_running() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let runs = [Hostile::Oversized, Hostile::StaleEpochs, Hostile::Flood]
            .map(|hostile| koh_testkit::spawn(survives(hostile)));
        for run in runs {
            run.await??;
        }
        Ok(())
    })
}

/// Whether a client survives `hostile`, as [`hostile_streams_leave_the_client_running`] says.
async fn survives(hostile: Hostile) -> anyhow::Result<()> {
    let net = net();
    let good = identity()?;
    let evil_id = evil_server(&net, good.public(), move |conn| {
        koh_testkit::spawn(async move {
            send_hostile(hostile, &conn).await;
            // Numbered past every epoch before it.
            let survived = framed(&[Shown::Out(b"\x1b[H\x1b[2JSURVIVED".to_vec())]);
            send_epoch(&conn, 2_000_000_000, &survived).await;
            conn.closed().await;
        })
    })
    .await?;
    let endpoint = net.endpoint(good, false).await?;
    let mut client = Client::connect_on(endpoint, evil_id, Options::default()).await?;
    anyhow::ensure!(
        client
            .wait_until(WAIT, |t| t.contains("SURVIVED"))
            .await
            .is_some(),
        "{hostile:?}: the epoch after never showed; screen:\n{}",
        client.screen()
    );
    let quit = client.quit(Duration::from_secs(5)).await;
    anyhow::ensure!(matches!(quit, Some(Ok(None))), "{hostile:?}: {quit:?}");
    Ok(())
}
