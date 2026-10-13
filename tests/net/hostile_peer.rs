//! Hostile peers on koh/6, both directions.
//!
//! A malicious client (admitted, so on the allowlist) throws malformed and oversized traffic at a
//! real server; a malicious server throws it at a real client. Neither may crash or hang the
//! other, and a protocol violation closes the connection. What each end keeps of the other's
//! traffic is bounded by the unit tests of its frame window and history cache.

use std::time::Duration;

use anyhow::Context as _;
use iroh::endpoint::Connection;
use iroh::{EndpointId, SecretKey};
use koh::proto::{
    decode_server, encode_client, ClientMsg, Close, Frame, FrameEncoder, FrameNum, InputSeq,
    ServerMsg, MAX_FRAME, MAX_PENDING_HISTORY,
};
use koh::terminal::{ServerTerminal, TerminalScreen};
use koh::transport_iroh::{generate_secret_key, ALPN};

use crate::harness::{identity, Client, Options, Server};
use crate::link::{FaultNet, Profile};

const WAIT: Duration = Duration::from_secs(20);

fn net() -> FaultNet {
    FaultNet::new(Profile::default(), 1)
}

/// Connect to `server` as `secret`, wait for its first frame, which admits it, and keep the
/// endpoint alive; the caller then speaks koh/6 by hand.
async fn admitted(
    net: &FaultNet,
    secret: SecretKey,
    server: EndpointId,
) -> anyhow::Result<Connection> {
    let endpoint = net.endpoint(secret, false).await?;
    let conn = endpoint.connect(FaultNet::addr(server), ALPN).await?;
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

/// Open the one client stream, write `bytes`, and keep it open (a real client keeps its stream).
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
        let huge = u32::try_from(MAX_FRAME)
            .context("MAX_FRAME fits u32")?
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
/// the cap, a palette past 16 entries, a function key past F12) loses its connection, each, and
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
            keys(vec![key(WireKeyCode::F(99), 0)]),
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
/// connection: the server stops reading the client, and only that, so frames of what the program
/// prints still go out.
#[test]
fn a_full_session_queue_does_not_stop_the_frames() -> anyhow::Result<()> {
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
                        if recv.read_to_end(MAX_FRAME).await.is_ok() {
                            frames.fetch_add(1, Ordering::Relaxed);
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
        while frames.load(Ordering::Relaxed) < before + 10 && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let after = frames.load(Ordering::Relaxed);
        let still = written.load(Ordering::Relaxed);
        writer.abort();
        reader.abort();
        server.stop().await?;
        anyhow::ensure!(
            after >= before + 10,
            "frames stopped while the session's queue was full: {before} then {after}"
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
fn a_client_cannot_open_a_third_stream() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = net();
        let evil = identity()?;
        let (server, mut good) = server_under_attack(&net, evil.public()).await?;
        let conn = admitted(&net, evil, server.id).await?;
        raw_client_stream(&conn, &encode_client(&typed("echo hi\r"))?).await?;
        // The server permits two uni streams from the client, input and control, so a third
        // never opens: QUIC's stream-count flow control is the bound, before any koh code runs.
        let _second = conn.open_uni().await?;
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

#[test]
fn history_requests_are_answered_within_bounds_and_a_flood_of_them_closes_the_connection(
) -> anyhow::Result<()> {
    use koh::terminal::{HistoryRequest, MAX_HISTORY_ROWS};
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = net();
        let evil = identity()?;
        let (server, mut good) = server_under_attack(&net, evil.public()).await?;
        let conn = admitted(&net, evil, server.id).await?;
        let mut send = conn.open_uni().await?;
        let lines = "i=0; while [ $i -lt 300 ]; do echo line $i; i=$((i+1)); done\r";
        send.write_all(&encode_client(&typed(lines))?).await?;
        // As many as may wait, each for every row there could be: answered, each within the bound.
        let mut asks = Vec::new();
        for name in 1..=u64::try_from(MAX_PENDING_HISTORY)? {
            asks.extend(encode_client(&ClientMsg::History(HistoryRequest {
                id: 0,
                newest: name * 100,
                count: u16::MAX,
            }))?);
        }
        send.write_all(&asks).await?;
        let mut answers = 0;
        let deadline = tokio::time::Instant::now() + WAIT;
        while answers < MAX_PENDING_HISTORY {
            let mut recv = tokio::time::timeout_at(deadline, conn.accept_uni())
                .await
                .context("the answers never came")??;
            // A frame superseded by a newer one is reset; only history is read here.
            let Ok(bytes) = recv.read_to_end(MAX_FRAME).await else {
                continue;
            };
            if let ServerMsg::History(body) = decode_server(&bytes)? {
                let reply = koh::proto::decode_history(&body)?;
                answers += 1;
                anyhow::ensure!(reply.rows.len() <= usize::from(MAX_HISTORY_ROWS));
                anyhow::ensure!(reply.rows.len() <= 300, "more than the history holds");
            }
        }
        // A flood past what may wait breaks the protocol: this connection closes, no other.
        let mut flood = Vec::new();
        for _ in 0..100 {
            flood.extend(encode_client(&ClientMsg::History(HistoryRequest {
                id: 0,
                newest: 1,
                count: 1,
            }))?);
        }
        send.write_all(&flood).await?;
        Box::leak(Box::new(send));
        closed_for_breaking_the_protocol(&conn, "a flood of history requests").await?;
        assert_good_client_still_works(&mut good).await?;
        let _ = good.finish().await;
        server.stop().await?;
        Ok(())
    })
}

// --- a malicious server against a real client ---

/// What admits a client: a first stream, here an empty one.
async fn admit(conn: &Connection) -> anyhow::Result<()> {
    conn.open_uni().await?.finish()?;
    Ok(())
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
        if conn.remote_id() != allow || admit(&conn).await.is_err() {
            return;
        }
        let handle = frames(conn);
        Box::leak(Box::new(endpoint));
        let _ = handle.await;
    });
    Ok(id)
}

/// Send `bytes` as one frame on its own stream.
async fn send_frame_bytes(conn: &Connection, bytes: Vec<u8>) {
    if let Ok(mut send) = conn.open_uni().await {
        let _ = send.write_all(&bytes).await;
        let _ = send.finish();
    }
}

/// What a hostile server sends a client.
#[derive(Clone, Copy, Debug)]
enum Hostile {
    /// An inflate bomb, then plain garbage.
    Bomb,
    /// Frames on bases the client never held.
    UnknownBases,
    /// History rows the client never asked for.
    HistoryRows,
}

/// Send `hostile` on `conn`.
async fn send_hostile(hostile: Hostile, conn: &Connection) {
    use koh::terminal::{HistoryReply, HistoryRow};
    match hostile {
        Hostile::Bomb => {
            // 64 MiB of zeros deflates tiny; the client's 16 MiB limit rejects it.
            let bomb = miniz_oxide::deflate::compress_to_vec(&vec![0u8; 4 * MAX_FRAME], 9);
            send_frame_bytes(conn, bomb).await;
            send_frame_bytes(conn, vec![0xff; 4096]).await;
        }
        Hostile::UnknownBases => {
            // 1000 frames, numbered far apart, each diffing from a base the client never holds.
            let base = TerminalScreen::default();
            for n in 1..=1000u64 {
                let Ok(mut emu) = ServerTerminal::new(24, 80, 0) else {
                    return;
                };
                emu.process(format!("frame {n}").as_bytes());
                let frame = Frame {
                    num: FrameNum(n.wrapping_mul(1000)),
                    base: FrameNum(n.wrapping_mul(1000).wrapping_sub(1)),
                    echo_ack: InputSeq(0),
                    diff: emu.snapshot().diff_from(&base),
                };
                if let Ok(bytes) = FrameEncoder::default().encode(&frame, &base) {
                    send_frame_bytes(conn, bytes).await;
                }
            }
        }
        Hostile::HistoryRows => {
            // A screen whose history claims a million rows, then rows the client never asked
            // for: too many, too wide, named outside the history, over and over.
            let Ok(mut emu) = ServerTerminal::new(24, 80, 1000) else {
                return;
            };
            for n in 0..200 {
                emu.process(format!("line {n}\r\n").as_bytes());
            }
            let mut diff = emu.snapshot().diff_from(&TerminalScreen::default());
            diff.history = Some(koh::terminal::HistoryMark {
                newest: 1_000_000,
                len: 1_000_000,
            });
            if let Ok(bytes) = FrameEncoder::default().encode(
                &Frame {
                    num: FrameNum(1),
                    base: FrameNum::BLANK,
                    echo_ack: InputSeq(0),
                    diff,
                },
                &TerminalScreen::default(),
            ) {
                send_frame_bytes(conn, bytes).await;
            }
            let newest = emu.snapshot().history().newest;
            let real = emu
                .history(koh::terminal::HistoryRequest {
                    id: 0,
                    newest,
                    count: 1,
                })
                .rows;
            let Some(template) = real.into_iter().next() else {
                return;
            };
            let wide = |name: u64| HistoryRow {
                name,
                runs: std::iter::repeat_n(template.runs.clone(), 100)
                    .flatten()
                    .collect(),
                ..template.clone()
            };
            for round in 0..50_u64 {
                let rows: Vec<HistoryRow> = (0..300)
                    .map(|n| {
                        wide(1_000_000_u64.wrapping_sub(round.wrapping_mul(300).wrapping_add(n)))
                    })
                    .collect();
                if let Ok(bytes) =
                    FrameEncoder::default().encode_history(&HistoryReply { id: 0, rows })
                {
                    send_frame_bytes(conn, bytes).await;
                }
            }
        }
    }
}

/// A client running against a server that sends it `hostile`, then one frame it takes, neither
/// crashes nor hangs: it shows that frame, and quits when told.
#[test]
fn hostile_frames_and_history_leave_the_client_running() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let runs = [Hostile::Bomb, Hostile::UnknownBases, Hostile::HistoryRows]
            .map(|hostile| koh_testkit::spawn(survives(hostile)));
        for run in runs {
            run.await??;
        }
        Ok(())
    })
}

/// Whether a client survives `hostile`, as [`hostile_frames_and_history_leave_the_client_running`]
/// says.
async fn survives(hostile: Hostile) -> anyhow::Result<()> {
    let net = net();
    let good = identity()?;
    let evil_id = evil_server(&net, good.public(), move |conn| {
        koh_testkit::spawn(async move {
            send_hostile(hostile, &conn).await;
            // Numbered past every frame before it, from the blank screen.
            let base = TerminalScreen::default();
            let frame = Frame {
                num: FrameNum(2_000_000_000),
                base: FrameNum::BLANK,
                echo_ack: InputSeq(0),
                diff: TerminalScreen::from_bytes(24, 80, b"SURVIVED").diff_from(&base),
            };
            if let Ok(bytes) = FrameEncoder::default().encode(&frame, &base) {
                send_frame_bytes(&conn, bytes).await;
            }
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
        "{hostile:?}: the frame after never showed; screen:\n{}",
        client.screen()
    );
    let quit = client.quit(Duration::from_secs(5)).await;
    anyhow::ensure!(matches!(quit, Some(Ok(None))), "{hostile:?}: {quit:?}");
    Ok(())
}

#[test]
fn a_servers_hostile_links_are_shown_as_text_or_dropped() -> anyhow::Result<()> {
    use koh::terminal::{WireLink, MAX_LINK_BYTES, MAX_ROW_LINKS};
    // Ten rows of the most and longest links are past what a diff may carry.
    const { assert!(10 * MAX_ROW_LINKS * fux_vt::URI_LIMIT > MAX_LINK_BYTES) };
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = net();
        let good = identity()?;
        let evil_id = evil_server(&net, good.public(), |conn| {
            koh_testkit::spawn(async move {
                let base = TerminalScreen::default();
                // Each frame from the blank screen, with links its rows should not have.
                let frame = |num: u64, text: &str, links: &dyn Fn(&mut koh::terminal::RowDiff)| {
                    let screen = TerminalScreen::from_bytes(24, 80, text.as_bytes());
                    let mut diff = screen.diff_from(&base);
                    for row in &mut diff.rows {
                        links(row);
                    }
                    FrameEncoder::default().encode(
                        &Frame {
                            num: FrameNum(num),
                            base: FrameNum::BLANK,
                            echo_ack: InputSeq(0),
                            diff,
                        },
                        &TerminalScreen::default(),
                    )
                };
                let evil = |row: &mut koh::terminal::RowDiff| {
                    row.links = vec![WireLink {
                        uri: "x\x1b]52;c;Y3VybCBldmlsfHNo\x07".to_owned(),
                        id: String::new(),
                    }];
                    for run in &mut row.runs {
                        run.cell.link = 1;
                    }
                };
                let lacking = |row: &mut koh::terminal::RowDiff| {
                    for run in &mut row.runs {
                        run.cell.link = 1;
                    }
                };
                let heavy = |row: &mut koh::terminal::RowDiff| {
                    let long = WireLink {
                        uri: "u".repeat(fux_vt::URI_LIMIT),
                        id: String::new(),
                    };
                    row.links = vec![long; MAX_ROW_LINKS];
                };
                let frames = [
                    frame(1, "shown as text", &evil),
                    frame(2, "lacking", &lacking),
                    // Ten rows of the most links a row may have, each the longest: past the bytes a
                    // diff may carry.
                    frame(3, &format!("{}heavy", "row\r\n".repeat(9)), &heavy),
                    frame(4, "after", &|_| {}),
                ];
                for bytes in frames.into_iter().flatten() {
                    send_frame_bytes(&conn, bytes).await;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                conn.closed().await;
            })
        })
        .await?;
        let endpoint = net.endpoint(good, false).await?;
        let mut client = Client::connect_on(endpoint, evil_id, Options::default()).await?;
        anyhow::ensure!(
            client
                .wait_until(WAIT, |t| t.contains("after"))
                .await
                .is_some(),
            "the client kept going; screen:\n{}",
            client.screen()
        );
        let shown: Vec<String> = client.history().into_iter().map(|p| p.text).collect();
        anyhow::ensure!(
            shown.iter().any(|t| t.contains("shown as text")),
            "an unsafe link's text is shown"
        );
        anyhow::ensure!(
            !shown
                .iter()
                .any(|t| t.contains("lacking") || t.contains("heavy")),
            "a frame naming a link its row lacks, or with too many link bytes, is dropped"
        );
        client.abort();
        Ok(())
    })
}
