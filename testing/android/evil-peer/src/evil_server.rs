//! A deliberately-MALICIOUS koh SERVER. It impersonates a `koh serve` to attack a real
//! `koh connect` on the auth direction, proving the client's mutual-authentication defenses. It
//! prints its endpoint id + port (machine-readable) so the test harness can point a koh client at
//! it, accepts one connection, and runs a malicious passphrase handshake.
//!
//! Usage: evil-server <attack>
//!   impostor   require a passphrase it does NOT know  → the client's mutual key-confirmation must
//!              reject it; an impostor server cannot authenticate (closes KOH-03).
//!   downgrade  claim NO passphrase to a client that HAS one → the client must fail closed rather
//!              than silently drop the second factor it was configured with (KR-13).

use std::time::Duration;

use anyhow::{anyhow, Result};
use koh::transport_iroh::{
    auth, bind_endpoint_local, format_endpoint_id, generate_secret_key,
};

#[tokio::main]
async fn main() -> Result<()> {
    let attack = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: evil-server <impostor|downgrade>"))?;

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

    let passphrase: Option<&str> = match attack.as_str() {
        // Require a passphrase we do NOT know: our SPAKE2 confirmation can't match the client's, so
        // the client (holding the real passphrase) rejects us — an impostor can't authenticate.
        "impostor" => Some("an-impostor-server-does-not-know-the-real-passphrase"),
        // Claim NO passphrase to a client configured with one: the client must fail closed.
        "downgrade" => None,
        other => return Err(anyhow!("unknown attack '{other}'")),
    };

    let result = auth::handshake_server(&conn, passphrase).await;
    eprintln!("evil-server: our handshake returned {result:?} (the koh CLIENT's verdict is the real assertion)");
    // Hold the connection briefly so the client fully observes our (mis)behavior before we drop.
    tokio::time::sleep(Duration::from_secs(2)).await;
    drop(ep);
    Ok(())
}
