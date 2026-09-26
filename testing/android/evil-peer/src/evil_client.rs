//! A deliberately-MALICIOUS koh CLIENT for the emulator suite. It authenticates (or deliberately
//! fails to) like a real client, then sends crafted koh/3 traffic a stock peer never would, to
//! exercise koh's server-side defenses. Every attack reuses koh's PUBLIC `proto`/`transport_iroh`
//! code, so the malicious client allocates almost nothing — the SERVER is the one that must stay
//! bounded. The equivalent CI tests live in `tests/net/hostile_peer.rs`; this is the on-device
//! probe.
//!
//! Usage: evil-client <server-id> <ip:port> <attack> [args...]
//!   The malicious client must be on the server's `--allow` list to reach the data plane, so the
//!   harness pre-creates its key and sets `$EVIL_KEY_FILE`.
//!
//! Attacks (defense each probes):
//!   resize <rows> <cols>     oversized/zero terminal geometry            (clamp_dims)
//!   bomb                     a length prefix over the message cap        (per-message size cap)
//!   oversized                one message body over the input cap         (input size cap)
//!   accumulate <n>           a flood of input messages                   (fixed frame window)
//!   resize-flood <n>         one read packed with n resize messages      (resize coalescing)
//!   keys-flood <mib>         a mib-MiB paste, split into capped messages  (PTY backpressure)
//!   garbage <n>              n random byte blobs on the stream           (decoder robustness)
//!   second-stream            open a second client stream                 (one-stream limit)
//!   bad-alpn                 connect with the wrong ALPN                  (handshake rejects)
//!   stall-admission          connect but never accept the admission ack  (3s admission timeout)
//!
//! `empty-frags`, `partial-frags` and `bad-version` are accepted as aliases of `garbage` /
//! `bad-alpn`, the nearest koh/3 attacks: koh/3 has no fragments and the ALPN is the version. The
//! Android scripts still call them by those names.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};
use koh::proto::{encode_client, ClientMsg, InputSeq, MAX_CLIENT_MESSAGE, MAX_INPUT_BYTES};
use koh::transport_iroh::{
    admission, bind_endpoint_local, direct_addr, generate_secret_key, load_or_create_secret_key,
    parse_endpoint_id, IrohChannel, ALPN,
};
use iroh::endpoint::{Connection, SendStream};

const MIB: usize = 1024 * 1024;

macro_rules! evil_secret {
    () => {
        match std::env::var_os("EVIL_KEY_FILE") {
            Some(p) => load_or_create_secret_key(&PathBuf::from(p))?,
            None => generate_secret_key()?,
        }
    };
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let usage =
        "usage: evil-client <server-id> <ip:port> <attack> [args...]  (see file header for attacks)";
    let id = args.get(1).ok_or_else(|| anyhow!(usage))?;
    let addr = args.get(2).ok_or_else(|| anyhow!(usage))?;
    let attack = args.get(3).map(String::as_str).ok_or_else(|| anyhow!(usage))?;
    let num = |i: usize, default: u64| -> u64 {
        args.get(i).and_then(|a| a.parse().ok()).unwrap_or(default)
    };

    let server_id = parse_endpoint_id(id)?;
    let saddr: SocketAddr = addr.parse()?;

    // Attacks that do NOT complete admission: they exercise the handshake/admission bounds.
    if attack == "stall-admission" {
        return admission_stall(server_id, saddr).await;
    }
    if attack == "bad-alpn" || attack == "bad-version" {
        let ep = bind_endpoint_local(evil_secret!(), false).await?;
        eprintln!("evil-client: connecting with a bad ALPN (the handshake must reject us)");
        let bad = ep.connect(direct_addr(server_id, saddr), b"koh/iroh/2").await;
        eprintln!("evil-client: bad-ALPN connect returned {:?}", bad.map(|_| ()));
        return Ok(());
    }

    // Everything else gets admitted first, then opens the one client stream and writes crafted
    // messages on it.
    let ep = bind_endpoint_local(evil_secret!(), false).await?;
    let conn = ep.connect(direct_addr(server_id, saddr), ALPN).await?;
    admission::await_admission(&conn).await?;
    eprintln!("evil-client: admitted; running attack '{attack}'");

    match attack {
        "second-stream" => second_stream(&conn).await?,
        _ => {
            let mut send = conn.open_uni().await?;
            match attack {
                "resize" => {
                    let (r, c) = (num(4, 65000) as u16, num(5, 1) as u16);
                    resize(&mut send, r, c).await?;
                }
                "bomb" => bomb(&mut send).await?,
                "oversized" => oversized(&mut send).await?,
                "accumulate" => accumulate(&mut send, num(4, 3000)).await?,
                "resize-flood" => resize_flood(&mut send, num(4, 500_000) as usize).await?,
                "keys-flood" => keys_flood(&mut send, num(4, 6) as usize).await?,
                "garbage" | "empty-frags" | "partial-frags" => {
                    garbage(&mut send, num(4, 30000) as usize).await?;
                }
                other => return Err(anyhow!("unknown attack '{other}'\n{usage}")),
            }
            let _ = send.finish();
        }
    }

    tokio::time::sleep(Duration::from_millis(800)).await;
    eprintln!("evil-client: attack '{attack}' done");
    let _ = IrohChannel::new(conn);
    drop(ep);
    Ok(())
}

/// Write one length-prefixed client message.
async fn write_msg(send: &mut SendStream, msg: &ClientMsg) -> Result<()> {
    send.write_all(&encode_client(msg)?).await?;
    Ok(())
}

/// clamp_dims: an oversized or zero terminal geometry, sent many times.
async fn resize(send: &mut SendStream, rows: u16, cols: u16) -> Result<()> {
    eprintln!("evil-client: injecting resize({rows}, {cols})");
    for _ in 0..30 {
        write_msg(send, &ClientMsg::Resize { rows, cols }).await?;
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    Ok(())
}

/// A length prefix claiming more than the message cap: the server must reject it on the header.
async fn bomb(send: &mut SendStream) -> Result<()> {
    eprintln!("evil-client: a length prefix over the {MAX_CLIENT_MESSAGE}-byte cap");
    let len = u32::try_from(MAX_CLIENT_MESSAGE + 1).unwrap_or(u32::MAX);
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&[0u8; 64]).await?;
    Ok(())
}

/// A single well-framed message whose input body is over the per-input cap.
async fn oversized(send: &mut SendStream) -> Result<()> {
    eprintln!("evil-client: one input message over the {MAX_INPUT_BYTES}-byte cap");
    let msg = ClientMsg::Input {
        seq: InputSeq(1),
        bytes: vec![b'a'; MAX_INPUT_BYTES + 4096],
    };
    // Encode by hand: `encode_client` refuses to build an over-cap message, which is the point.
    let body = postcard::to_allocvec(&msg)?;
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&body).await?;
    Ok(())
}

/// A flood of input messages: the server applies them and keeps only its fixed frame window.
async fn accumulate(send: &mut SendStream, n: u64) -> Result<()> {
    eprintln!("evil-client: {n} input messages (the server's frame window must stay bounded)");
    for seq in 1..=n {
        write_msg(
            send,
            &ClientMsg::Input {
                seq: InputSeq(seq),
                bytes: b"a".to_vec(),
            },
        )
        .await?;
        if seq % 256 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    Ok(())
}

/// Many resize messages in one burst: the server coalesces to the last per read.
async fn resize_flood(send: &mut SendStream, n: usize) -> Result<()> {
    eprintln!("evil-client: {n} resize messages (the server must coalesce)");
    for k in 0..n {
        let (rows, cols) = if k % 2 == 0 { (1000, 1000) } else { (2, 2) };
        write_msg(send, &ClientMsg::Resize { rows, cols }).await?;
    }
    Ok(())
}

/// A big paste, split into capped input messages: the PTY write queue and QUIC flow control bound it.
async fn keys_flood(send: &mut SendStream, mib: usize) -> Result<()> {
    eprintln!("evil-client: a {mib} MiB paste in capped messages");
    let chunk = vec![b'x'; MAX_INPUT_BYTES];
    let count = mib * MIB / MAX_INPUT_BYTES;
    for seq in 1..=count as u64 {
        write_msg(
            send,
            &ClientMsg::Input {
                seq: InputSeq(seq),
                bytes: chunk.clone(),
            },
        )
        .await?;
    }
    Ok(())
}

/// Random byte blobs on the stream: the decoder must reject them and the server close the connection.
async fn garbage(send: &mut SendStream, n: usize) -> Result<()> {
    eprintln!("evil-client: {n} garbage byte blobs");
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..n {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let len = (seed % 40) as usize;
        let buf: Vec<u8> = (0..len).map(|k| (seed >> (k % 8)) as u8).collect();
        if send.write_all(&buf).await.is_err() {
            break; // the server closed on the malformed stream, as it should
        }
    }
    Ok(())
}

/// Open a second client stream: the server permits one, so this must not be grantable.
async fn second_stream(conn: &Connection) -> Result<()> {
    let mut first = conn.open_uni().await?;
    write_msg(
        &mut first,
        &ClientMsg::Input {
            seq: InputSeq(1),
            bytes: b"echo hi\r".to_vec(),
        },
    )
    .await?;
    eprintln!("evil-client: trying a second client stream (the one-stream limit must block it)");
    match tokio::time::timeout(Duration::from_secs(3), conn.open_uni()).await {
        Err(_) => eprintln!("evil-client: second stream blocked by the limit, as expected"),
        Ok(_) => eprintln!("evil-client: WARNING second stream opened — limit not enforced"),
    }
    let _ = first.finish();
    Ok(())
}

/// Connect but never accept the admission ack: the server's 3s admission timeout must fire.
async fn admission_stall(server_id: iroh::EndpointId, saddr: SocketAddr) -> Result<()> {
    let ep = bind_endpoint_local(evil_secret!(), false).await?;
    let conn = ep.connect(direct_addr(server_id, saddr), ALPN).await?;
    eprintln!("evil-client: connected; NOT accepting the admission ack (server timeout must fire)");
    tokio::time::sleep(Duration::from_secs(8)).await;
    drop(conn);
    drop(ep);
    Ok(())
}
