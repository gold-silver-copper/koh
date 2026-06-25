//! A deliberately-MALICIOUS koh SERVER. It impersonates a `koh serve` to attack a real
//! `koh connect` on the **admission** direction (koh no longer has an over-the-wire passphrase
//! second factor — that PAKE handshake was removed in 0.7.0; the node-id is authenticated by the
//! QUIC/TLS handshake and admission is a single ADMIT byte the server writes). It prints its
//! endpoint id + port (machine-readable) so the harness can point a koh client at it, accepts one
//! connection, and then misbehaves on the admission step.
//!
//! Usage: evil-server <attack>
//!   bad-admit   open the admission stream and write a NON-ADMIT byte → the client must reject the
//!               connection (`AdmissionError::Rejected`) instead of proceeding as if admitted.
//!   stall-admit accept the connection but never open the admission stream → the client's admission
//!               await must not hang forever; its bounded connect/admission timeout must fire.

use std::time::Duration;

use anyhow::{anyhow, Result};
use koh::transport_iroh::{bind_endpoint_local, format_endpoint_id, generate_secret_key};

#[tokio::main]
async fn main() -> Result<()> {
    let attack = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: evil-server <bad-admit|stall-admit>"))?;

    let secret = generate_secret_key();
    let id = secret.public();
    let ep = bind_endpoint_local(secret, true).await?;
    let port = ep
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map(std::net::SocketAddr::port)
        .ok_or_else(|| anyhow!("no bound ipv4 socket"))?;

    // Machine-readable lines the test harness greps to drive a koh client at us.
    println!("EVIL_ID={}", format_endpoint_id(&id));
    println!("EVIL_PORT={port}");
    eprintln!("evil-server: attack '{attack}' listening on 127.0.0.1:{port}");

    let incoming = ep.accept().await.ok_or_else(|| anyhow!("endpoint closed"))?;
    let conn = incoming.await?;

    match attack.as_str() {
        // The real server opens the admission bi-stream and writes ADMIT (= 1). We open it and write
        // a different byte; the koh client's `await_admission` must surface this as a rejection, not
        // silently proceed.
        "bad-admit" => {
            eprintln!("evil-server: writing a NON-ADMIT admission byte (client must reject)");
            let (mut send, _recv) = conn.open_bi().await?;
            send.write_all(&[0u8]).await?; // 0 != ADMIT(1)
            let _ = send.finish();
        }
        // Never open the admission stream at all: the client's admission await must be bounded by its
        // own connect/admission timeout rather than hanging on us forever.
        "stall-admit" => {
            eprintln!("evil-server: accepting but never opening the admission stream (client timeout must fire)");
        }
        other => return Err(anyhow!("unknown attack '{other}'")),
    }

    // Hold the connection briefly so the client fully observes our (mis)behavior before we drop.
    tokio::time::sleep(Duration::from_secs(2)).await;
    drop(ep);
    Ok(())
}
