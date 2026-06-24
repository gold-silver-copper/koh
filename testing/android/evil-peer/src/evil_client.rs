//! A deliberately-MALICIOUS koh CLIENT. It authenticates (or deliberately fails to) like a real
//! client, then sends crafted protocol traffic a stock peer never would, to exercise koh's
//! server-side defenses on the emulator. Every attack reuses koh's PUBLIC wire/transport code, so
//! the malicious client allocates almost nothing — the SERVER is the one that must stay bounded.
//!
//! Usage: evil-client <server-id> <ip:port> <attack> [args...]   ($KOH_PASSPHRASE if the server needs one)
//!
//! Attacks (defense each probes):
//!   resize <rows> <cols>     oversized/zero terminal geometry            (H-1 / M-2 clamp_dims)
//!   bomb <mib>               decompression bomb: tiny wire, huge inflate (KOH-02 per-dir decode cap)
//!   empty-frags <n>          flood of empty non-final fragments          (KR-08 empty-frag drop)
//!   partial-frags <n>        never-completing payload fragments          (KOH-07 reassembly byte cap)
//!   accumulate <n> [bytes]   distinct states off the num-0 base          (KOH-01 received-states budget)
//!   resize-flood <n>         one diff packed with n resize events        (KOH-05 resize coalescing)
//!   keys-flood <mib>         one diff of mib MiB of keystrokes (under cap) (bounded PTY write/budget)
//!   garbage <n>              n random/short datagrams                    (Fragment::decode robustness)
//!   bad-version              an Instruction with a bogus protocol ver    (PROTOCOL_VERSION reject)
//!   stall-pake               accept the auth bi-stream, never answer     (KR-01 3s handshake timeout)
//!   bad-pake                 a garbage SPAKE2 message                     (PAKE finish() reject)

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use koh::input::WireEvent;
use koh::transport_iroh::{
    auth, bind_endpoint_local, direct_addr, generate_secret_key, parse_endpoint_id, IrohChannel,
    ALPN,
};
use koh::wire::{Fragment, Fragmenter, Instruction, PROTOCOL_VERSION};

const MIB: usize = 1024 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let usage =
        "usage: evil-client <server-id> <ip:port> <attack> [args...]  (see file header for attacks)";
    let id = args.get(1).ok_or_else(|| anyhow!(usage))?;
    let addr = args.get(2).ok_or_else(|| anyhow!(usage))?;
    let attack = args.get(3).map(String::as_str).ok_or_else(|| anyhow!(usage))?;
    let num = |i: usize| -> Result<u64> {
        args.get(i)
            .ok_or_else(|| anyhow!("attack '{attack}' needs a numeric arg #{}", i - 3))?
            .parse::<u64>()
            .map_err(Into::into)
    };

    let server_id = parse_endpoint_id(id)?;
    let saddr: SocketAddr = addr.parse()?;

    // The raw-bistream auth attacks do NOT run the normal handshake — they manually accept the
    // server's auth stream and misbehave on it.
    if matches!(attack, "stall-pake" | "bad-pake") {
        return auth_attack(id, addr, attack).await;
    }

    // Everything else passes the handshake first (KOH_PASSPHRASE if the server requires one), then
    // injects crafted datagrams on the established connection.
    let pass = std::env::var("KOH_PASSPHRASE").ok();
    let ep = bind_endpoint_local(generate_secret_key(), false).await?;
    let conn = ep.connect(direct_addr(server_id, saddr), ALPN).await?;
    auth::handshake_client(&conn, pass.as_deref()).await?;
    eprintln!("evil-client: authenticated; running attack '{attack}'");
    let ch = IrohChannel::new(conn);

    match attack {
        "resize" => resize(&ch, num(4)? as u16, num(5)? as u16).await,
        "bomb" => bomb(&ch, num(4).unwrap_or(12) as usize).await,
        "empty-frags" => empty_frags(&ch, num(4).unwrap_or(20000) as u16).await,
        "partial-frags" => partial_frags(&ch, num(4).unwrap_or(20000) as u16).await,
        "accumulate" => {
            accumulate(&ch, num(4).unwrap_or(3000), num(5).unwrap_or(4096) as usize).await;
        }
        "resize-flood" => resize_flood(&ch, num(4).unwrap_or(500_000) as usize).await,
        "keys-flood" => keys_flood(&ch, num(4).unwrap_or(6) as usize).await,
        "garbage" => garbage(&ch, num(4).unwrap_or(20000) as usize).await,
        "bad-version" => bad_version(&ch).await,
        other => return Err(anyhow!("unknown attack '{other}'\n{usage}")),
    }

    // Hold the connection open briefly so the unreliable datagrams flush before we drop it.
    tokio::time::sleep(Duration::from_millis(800)).await;
    eprintln!("evil-client: attack '{attack}' done");
    drop(ep);
    Ok(())
}

// --- crafting helpers --------------------------------------------------------------------------

/// A `UserInput` diff (the client→server direction) as the opaque bytes koh puts in `Instruction.diff`.
fn ui_diff(events: &[WireEvent]) -> Vec<u8> {
    postcard::to_allocvec(events).unwrap_or_default()
}

fn instr(old: u64, new: u64, throwaway: u64, version: u32, diff: Vec<u8>) -> Instruction {
    Instruction {
        protocol_version: version,
        old_num: old,
        new_num: new,
        ack_num: 0,
        throwaway_num: throwaway,
        diff,
    }
}

/// Fragment `instr` and fire every fragment as a datagram, `times` times (retransmits raise the
/// odds of delivery over the unreliable datagram channel; the server dedups by fragment id).
fn blast(ch: &IrohChannel, f: &mut Fragmenter, instr: &Instruction, times: usize) {
    let mtu = ch.max_datagram_size();
    for _ in 0..times {
        if let Ok(frags) = f.fragment(instr, mtu) {
            for fr in &frags {
                if let Ok(dg) = fr.encode() {
                    ch.send(&dg);
                }
            }
        }
    }
}

// --- attacks -----------------------------------------------------------------------------------

/// H-1 / M-2: an oversized or zero terminal geometry. The clamp must keep the server from
/// allocating a giant (or panicking on a degenerate) vt100 grid.
async fn resize(ch: &IrohChannel, rows: u16, cols: u16) {
    let i = instr(0, 1, 0, PROTOCOL_VERSION, ui_diff(&[WireEvent::Resize { rows, cols }]));
    let mut f = Fragmenter::new();
    eprintln!("evil-client: injecting resize({rows}, {cols})");
    for _ in 0..30 {
        blast(ch, &mut f, &i, 1);
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

/// KOH-02: a decompression bomb — a few-KB wire payload that inflates past the server's per-direction
/// decode cap. The server must reject it at inflate time, never allocating the full payload.
async fn bomb(ch: &IrohChannel, mib: usize) {
    let i = instr(0, 1, 0, PROTOCOL_VERSION, vec![0u8; mib * MIB]); // compresses to ~KB
    let mut f = Fragmenter::new();
    eprintln!("evil-client: bomb inflating to ~{mib} MiB (server must reject at the cap)");
    blast(ch, &mut f, &i, 6);
}

/// KR-08: a flood of empty-payload non-final fragments. They add 0 to the byte cap, so the server's
/// up-front empty-fragment drop is what keeps `parts` from accumulating one slot per index.
async fn empty_frags(ch: &IrohChannel, n: u16) {
    eprintln!("evil-client: flooding {n} empty non-final fragments");
    for index in 0..n {
        let fr = Fragment { id: 7, index, final_: false, payload: Vec::new() };
        if let Ok(dg) = fr.encode() {
            ch.send(&dg);
        }
    }
}

/// KOH-07: non-completing payload fragments under one id. The reassembly byte cap must bound the
/// buffered scratch and reset, never growing unbounded.
async fn partial_frags(ch: &IrohChannel, n: u16) {
    eprintln!("evil-client: flooding {n} non-completing 1 KB fragments");
    for index in 0..n {
        let fr = Fragment { id: 9, index, final_: false, payload: vec![0u8; 1000] };
        if let Ok(dg) = fr.encode() {
            ch.send(&dg);
        }
    }
}

/// KOH-01: many distinct states all based on the never-collapsing num-0 base (old=0, throwaway=0).
/// The received-states count cap + per-direction byte budget must bound resident memory.
async fn accumulate(ch: &IrohChannel, n: u64, bytes: usize) {
    eprintln!("evil-client: accumulating {n} states of ~{bytes} B (server budget must cap)");
    let diff = ui_diff(&[WireEvent::Keys(vec![b'a'; bytes])]);
    let mut f = Fragmenter::new();
    for new in 1..=n {
        let i = instr(0, new, 0, PROTOCOL_VERSION, diff.clone());
        blast(ch, &mut f, &i, 1);
        if new % 256 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await; // let the channel drain
        }
    }
}

/// KOH-05: one diff packed with `n` alternating-dimension resize events. The server must coalesce to
/// the final resize (one ioctl + grid realloc), not run one synchronous op per event under the lock.
async fn resize_flood(ch: &IrohChannel, n: usize) {
    eprintln!("evil-client: one diff with {n} resize events (server must coalesce)");
    let events: Vec<WireEvent> = (0..n)
        .map(|k| {
            if k % 2 == 0 {
                WireEvent::Resize { rows: 1000, cols: 1000 }
            } else {
                WireEvent::Resize { rows: 2, cols: 2 }
            }
        })
        .collect();
    let i = instr(0, 1, 0, PROTOCOL_VERSION, ui_diff(&events));
    let mut f = Fragmenter::new();
    blast(ch, &mut f, &i, 3);
}

/// One diff of `mib` MiB of keystrokes (kept UNDER the decode cap, so it decodes and applies) —
/// exercises the server's bounded PTY write + per-state budget. The decode cap itself is covered by
/// the `bomb` attack; for a single Keys blob the byte cap and the event budget coincide at ~8 MiB,
/// so this probe deliberately stays below both.
async fn keys_flood(ch: &IrohChannel, mib: usize) {
    eprintln!("evil-client: one diff of {mib} MiB of keystrokes");
    let i = instr(0, 1, 0, PROTOCOL_VERSION, ui_diff(&[WireEvent::Keys(vec![b'x'; mib * MIB])]));
    let mut f = Fragmenter::new();
    blast(ch, &mut f, &i, 3);
}

/// Random/short datagrams that aren't valid fragments — `Fragment::decode` must reject them without
/// panicking or consuming resources.
async fn garbage(ch: &IrohChannel, n: usize) {
    eprintln!("evil-client: {n} garbage datagrams");
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..n {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let len = (seed % 40) as usize; // mostly shorter than a fragment header -> ShortFragment
        let buf: Vec<u8> = (0..len).map(|k| (seed >> (k % 8)) as u8).collect();
        ch.send(&buf);
    }
}

/// An Instruction carrying a bogus protocol version — must be rejected at decode, before any state
/// is touched.
async fn bad_version(ch: &IrohChannel) {
    let bad = PROTOCOL_VERSION + 99;
    eprintln!("evil-client: Instruction with protocol_version = {bad}");
    let i = instr(0, 1, 0, bad, ui_diff(&[WireEvent::Keys(b"x".to_vec())]));
    let mut f = Fragmenter::new();
    blast(ch, &mut f, &i, 4);
}

// --- raw-bistream auth attacks -----------------------------------------------------------------

// The koh passphrase auth tags (private in koh::transport_iroh::auth) — hardcoded here because this
// harness crafts raw bytes on the wire. Keep in sync with auth.rs if the tags ever change.
const TAG_NO_PASS: u8 = 0;
const TAG_PAKE_REQUIRED: u8 = 1;

/// `stall-pake` / `bad-pake`: connect, accept the server's auth bi-stream, and either stall (never
/// answer → the server's 3s handshake timeout must fire and release the permit) or send a garbage
/// SPAKE2 message (→ the server's `finish` must reject it cleanly).
async fn auth_attack(id_str: &str, addr_str: &str, attack: &str) -> Result<()> {
    let server_id = parse_endpoint_id(id_str)?;
    let saddr: SocketAddr = addr_str.parse()?;
    let ep = bind_endpoint_local(generate_secret_key(), false).await?;
    let conn = ep.connect(direct_addr(server_id, saddr), ALPN).await?;
    // koh's server OPENS the auth bi-stream; the client ACCEPTS it.
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag).await?;
    if tag[0] == TAG_NO_PASS {
        eprintln!("evil-client: server requires no passphrase; nothing to attack");
        return Ok(());
    }
    if tag[0] != TAG_PAKE_REQUIRED {
        return Err(anyhow!("unexpected auth tag {}", tag[0]));
    }
    // Read the server's framed SPAKE2 message: [len:u8][bytes].
    let mut len = [0u8; 1];
    recv.read_exact(&mut len).await?;
    let mut server_msg = vec![0u8; len[0] as usize];
    recv.read_exact(&mut server_msg).await?;

    match attack {
        "stall-pake" => {
            eprintln!("evil-client: stalling the passphrase handshake (server 3s timeout must fire)");
            tokio::time::sleep(Duration::from_secs(8)).await; // > the server's 3s bound
        }
        "bad-pake" => {
            eprintln!("evil-client: sending a garbage SPAKE2 message (server must reject)");
            let garbage = [0xABu8; 33]; // valid length, invalid curve element
            send.write_all(&[garbage.len() as u8]).await?;
            send.write_all(&garbage).await?;
            let _ = send.finish();
            // Drain whatever the server sends (its confirmation/verdict) before exiting.
            let mut sink = [0u8; 64];
            let _ = recv.read(&mut sink).await;
        }
        _ => unreachable!(),
    }
    drop(ep);
    Ok(())
}
