//! Hostile peers on koh/3, both directions.
//!
//! A malicious client (admitted, so on the allowlist) throws malformed and oversized traffic at a
//! real server; a malicious server throws it at a real client. Neither may crash, hang or grow the
//! other's memory past the fixed frame window; a protocol violation closes the connection.

use std::time::Duration;

use anyhow::Context as _;
use iroh::endpoint::Connection;
use iroh::{EndpointId, SecretKey};
use koh::proto::{encode_client, encode_frame, ClientMsg, Frame, FrameNum, InputSeq, MAX_FRAME};
use koh::terminal::{ServerTerminal, TerminalScreen};
use koh::transport_iroh::{admission, generate_secret_key, ALPN};

use crate::harness::{identity, Client, Options, Server};
use crate::link::{FaultNet, Profile};

const WAIT: Duration = Duration::from_secs(20);

fn net() -> FaultNet {
    FaultNet::new(Profile::default(), 1)
}

/// Connect to `server` as `secret`, complete admission, and keep the endpoint alive; the caller
/// then speaks koh/3 by hand.
async fn admitted(
    net: &FaultNet,
    secret: SecretKey,
    server: EndpointId,
) -> anyhow::Result<Connection> {
    let endpoint = net.endpoint(secret, false).await?;
    let conn = endpoint.connect(FaultNet::addr(server), ALPN).await?;
    admission::await_admission(&conn).await?;
    Box::leak(Box::new(endpoint));
    Ok(conn)
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
    crate::harness::runtime()?.block_on(async {
        let net = net();
        let evil = identity()?;
        let (server, mut good) = server_under_attack(&net, evil.public()).await?;
        let conn = admitted(&net, evil, server.id).await?;
        // A length prefix claiming far more than the cap: rejected on the header.
        let huge = u32::try_from(MAX_FRAME)
            .context("MAX_FRAME fits u32")?
            .to_be_bytes();
        raw_client_stream(&conn, &huge).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_good_client_still_works(&mut good).await?;
        let _ = good.finish().await;
        server.stop().await;
        Ok(())
    })
}

#[test]
fn a_client_cannot_open_a_second_stream() -> anyhow::Result<()> {
    crate::harness::runtime()?.block_on(async {
        let net = net();
        let evil = identity()?;
        let (server, mut good) = server_under_attack(&net, evil.public()).await?;
        let conn = admitted(&net, evil, server.id).await?;
        raw_client_stream(
            &conn,
            &encode_client(&ClientMsg::Input {
                seq: InputSeq(1),
                bytes: b"echo hi\r".to_vec(),
            })?,
        )
        .await?;
        // The server permits one uni stream from the client, so a second never opens: QUIC's
        // stream-count flow control is the bound, before any koh code runs.
        let second = tokio::time::timeout(Duration::from_secs(2), conn.open_uni()).await;
        anyhow::ensure!(
            second.is_err(),
            "a second client stream must not be grantable"
        );
        assert_good_client_still_works(&mut good).await?;
        let _ = good.finish().await;
        server.stop().await;
        Ok(())
    })
}

#[test]
fn a_flood_of_connections_and_garbage_does_not_take_the_server_down() -> anyhow::Result<()> {
    crate::harness::runtime()?.block_on(async {
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
        server.stop().await;
        Ok(())
    })
}

// --- a malicious server against a real client ---

/// Bind a hand-rolled server for `allow`, admit it, and run `frames` on its connection. Returns the
/// server's id.
async fn evil_server<F>(net: &FaultNet, allow: EndpointId, frames: F) -> anyhow::Result<EndpointId>
where
    F: FnOnce(Connection) -> tokio::task::JoinHandle<()> + Send + 'static,
{
    let secret = generate_secret_key()?;
    let id = secret.public();
    let endpoint = net.endpoint(secret, true).await?;
    tokio::spawn(async move {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let Ok(conn) = incoming.await else { return };
        if conn.remote_id() != allow || admission::admit(&conn).await.is_err() {
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

/// A client running against a hand-rolled server survives its frames without crashing or hanging.
async fn client_survives(net: &FaultNet, good: SecretKey, evil: EndpointId) -> anyhow::Result<()> {
    let endpoint = net.endpoint(good, false).await?;
    let mut client = Client::connect_on(endpoint, evil, Options::default()).await?;
    // A crash would abort the client task; a hang would trip this wait. Neither must happen.
    tokio::time::sleep(Duration::from_secs(3)).await;
    anyhow::ensure!(
        client
            .wait_until(Duration::from_secs(1), |_| false)
            .await
            .is_none(),
        "the client painted nothing it should have; it must simply keep running"
    );
    client.abort();
    Ok(())
}

#[test]
fn an_oversized_or_bomb_frame_never_grows_the_client() -> anyhow::Result<()> {
    crate::harness::runtime()?.block_on(async {
        let net = net();
        let good = identity()?;
        let evil_id = evil_server(&net, good.public(), |conn| {
            tokio::spawn(async move {
                // An inflate bomb: 64 MiB of zeros deflates tiny; the client's 16 MiB limit rejects it.
                let bomb = miniz_oxide::deflate::compress_to_vec(&vec![0u8; 4 * MAX_FRAME], 9);
                send_frame_bytes(&conn, bomb).await;
                send_frame_bytes(&conn, vec![0xff; 4096]).await; // plain garbage
                conn.closed().await;
            })
        })
        .await?;
        client_survives(&net, good, evil_id).await
    })
}

#[test]
fn frames_with_unknown_bases_never_grow_the_client() -> anyhow::Result<()> {
    crate::harness::runtime()?.block_on(async {
        let net = net();
        let good = identity()?;
        let evil_id = evil_server(&net, good.public(), |conn| {
            tokio::spawn(async move {
                // 1000 frames, numbered far apart, each diffing from a base the client never holds.
                let base = TerminalScreen::default();
                for n in 1..=1000u64 {
                    let Ok(mut emu) = ServerTerminal::new(24, 80, 0) else {
                        return;
                    };
                    emu.process(format!("frame {n}").as_bytes());
                    let Ok(diff) = std::panic::catch_unwind(|| emu.snapshot().diff_from(&base))
                    else {
                        return;
                    };
                    let frame = Frame {
                        num: FrameNum(n.wrapping_mul(1000)),
                        base: FrameNum(n.wrapping_mul(1000).wrapping_sub(1)),
                        echo_ack: InputSeq(0),
                        diff,
                    };
                    if let Ok(bytes) = encode_frame(&frame) {
                        send_frame_bytes(&conn, bytes).await;
                    }
                }
                conn.closed().await;
            })
        })
        .await?;
        client_survives(&net, good, evil_id).await
    })
}

#[test]
fn a_bad_admission_byte_is_rejected_not_treated_as_admitted() -> anyhow::Result<()> {
    crate::harness::runtime()?.block_on(async {
        let net = net();
        let good = identity()?;
        // A server that opens the admission stream but writes the wrong byte.
        let secret = generate_secret_key()?;
        let evil_id = secret.public();
        let endpoint = net.endpoint(secret, true).await?;
        tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await {
                if let Ok(conn) = incoming.await {
                    if let Ok((mut send, _recv)) = conn.open_bi().await {
                        let _ = send.write_all(&[0u8]).await; // 0 != ADMIT
                        let _ = send.finish();
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
            Box::leak(Box::new(endpoint));
        });
        // The client must fail to connect, not proceed as if admitted.
        let endpoint = net.endpoint(good, false).await?;
        let result = Client::connect_on(endpoint, evil_id, Options::default()).await;
        anyhow::ensure!(result.is_err(), "a non-ADMIT byte must be rejected");
        Ok(())
    })
}
