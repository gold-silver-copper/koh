//! A deliberately-MALICIOUS koh SERVER. It impersonates a `koh serve` to attack a real
//! `koh connect` on the **admission** direction (there is no over-the-wire second factor: the
//! node-id is authenticated by the QUIC/TLS handshake, and the server's first frame admits the
//! client). It prints its
//! endpoint id + port (machine-readable) so the harness can point a koh client at it, accepts one
//! connection, and then misbehaves on the admission step.
//!
//! Usage: evil-server <attack>
//!   stall-admit accept the connection but never send a frame → the client's wait to be admitted
//!               must not hang forever; its bounded connect timeout must fire.

use std::time::Duration;

use anyhow::{anyhow, Result};
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key};

#[tokio::main]
async fn main() -> Result<()> {
    let attack = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: evil-server stall-admit"))?;

    let secret = generate_secret_key()?;
    let id = secret.public();
    let ep = bind_endpoint_local(secret, true).await?;
    let port = ep
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map(std::net::SocketAddr::port)
        .ok_or_else(|| anyhow!("no bound ipv4 socket"))?;

    // Machine-readable lines the test harness greps to drive a koh client at us.
    println!("EVIL_ID={id}");
    println!("EVIL_PORT={port}");
    eprintln!("evil-server: attack '{attack}' listening on 127.0.0.1:{port}");

    let incoming = ep
        .accept()
        .await
        .ok_or_else(|| anyhow!("endpoint closed"))?;
    // Held, never written to.
    let _conn = incoming.await?;

    match attack.as_str() {
        // Never send a frame: the client's wait to be admitted must be bounded by its own connect
        // timeout rather than hanging on us forever.
        "stall-admit" => {
            eprintln!(
                "evil-server: accepting but never sending a frame (client timeout must fire)"
            );
        }
        other => return Err(anyhow!("unknown attack '{other}'")),
    }

    // Hold the connection briefly so the client fully observes our (mis)behavior before we drop.
    tokio::time::sleep(Duration::from_secs(2)).await;
    drop(ep);
    Ok(())
}
