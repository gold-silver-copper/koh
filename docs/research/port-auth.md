# Porting notes: optional passphrase second auth factor (P2)

> **ARCHIVAL — NOT ADOPTED (historical research note).** This describes the abandoned
> multi-crate layout (`crates/transport-iroh`, `rmosh-`/`moshers-` naming) and proposes a
> passphrase **second factor** that koh deliberately did **not** ship: a brief SPAKE2/PAKE
> factor was tried (v0.4.0) and then removed in v0.7.0. koh authorizes on the node-id allowlist
> alone; the leaked-key risk is instead handled by mandatory at-rest key encryption. Code
> snippets below (`allow_any`, the multi-crate paths) no longer match the single-crate tree.
> Kept only as design history.

Goal: add the reference's BLAKE3 nonce-challenge passphrase handshake (a second auth
factor on top of the node-id allowlist) to the `rmosh-` crate. The passphrase NEVER
crosses the wire — only `BLAKE3(passphrase || nonce)` does, with a fresh random nonce per
attempt so replays are useless.

Reference: `/Users/kisaczka/Desktop/code/moshers/crates/moshers-iroh/src/auth.rs`
(lines 49–108), wired in `moshers-server/src/main.rs` and `moshers-client/src/main.rs`.
Current: `/Users/kisaczka/Desktop/code/moshers2/crates/transport-iroh/src/lib.rs`
(node-id allowlist + persistent key are in `server/main.rs`; **no passphrase yet**).

Both repos resolve **iroh = 1.0.0** and **blake3 = 1.8.5** (identical lockfile versions),
so the iroh API surface (`open_bi`, `accept_bi`, `SecretKey::generate().to_bytes()`,
`conn.close`) and the `blake3::hash` API are byte-for-byte transferable. No API translation
is needed.

---

## 1. The exact handshake (what the reference does, and why it is correct)

### Channel
A **reliable bidirectional QUIC stream** (`conn.open_bi()` / `conn.accept_bi()`), NOT
datagrams. Correct: the challenge/response must be ordered and lossless, and it is a
one-shot pre-session exchange — exactly what a bi-stream is for. The steady SSP flow stays
on unreliable datagrams (untouched).

### Stream direction (SUBTLE — do not invert)
- **Server** opens the stream: `let (mut send, mut recv) = conn.open_bi().await?;`
- **Client** accepts the stream: `let (mut send, mut recv) = conn.accept_bi().await?;`

This is the reverse of the naive "client initiates" intuition. The server is the active
party (it owns the secret to challenge against), so it drives. In iroh/QUIC a bi-stream is
only observable on the peer once the opener writes data, so the server writing the tag byte
is what unblocks the client's `accept_bi()`. **If you port this with the directions swapped,
both sides will hang on their respective `*_bi()` calls (deadlock).** Keep server=open,
client=accept.

### Message protocol (two tag bytes)
```rust
const NO_PASS: u8 = 0;
const PASS_REQUIRED: u8 = 1;
```

**Case A — server has no passphrase configured (`None`):**
1. Server writes a single byte `[NO_PASS]` (= `0u8`), then `send.finish()`.
2. Client reads 1 byte; tag != `PASS_REQUIRED`, so it does nothing and returns `Ok`.
No nonce, no hash. Server returns `Ok(())` immediately.

**Case B — server has a passphrase (`Some(pass)`):**
1. Server generates a fresh 32-byte nonce, writes `[PASS_REQUIRED] ++ nonce` (33 bytes total).
2. Server reads exactly 32 bytes back (the response hash).
3. Server computes `expect = BLAKE3(pass_bytes || nonce)` and compares (constant-len `[u8;32]`
   equality). Mismatch ⇒ `bail!("passphrase challenge failed")`.
4. Client reads the 1-byte tag, sees `PASS_REQUIRED`, reads the 32-byte nonce, computes
   `resp = BLAKE3(pass_bytes || nonce)`, writes the 32-byte digest, `send.finish()`.

### Exact serialization
- Challenge from server: `Vec<u8>` of length 33 = `tag (1) ++ nonce (32)`. Built with
  `Vec::with_capacity(33)`, `msg.push(PASS_REQUIRED)`, `msg.extend_from_slice(&nonce)`.
- Response from client: raw 32 bytes = `blake3::hash(...).as_bytes()` (`&[u8; 32]`).
- No length prefixes, no serde, no framing crate. Reads use `read_exact` with fixed-size
  buffers (`[0u8; 1]`, `[0u8; 32]`), which is why exact byte counts matter.

### The exact BLAKE3 input (copy-paste accurate)
Server (`auth.rs:83`):
```rust
let expect = blake3::hash(&[pass.as_bytes(), &nonce[..]].concat());
```
Client (`auth.rs:103`):
```rust
let resp = blake3::hash(&[pass.as_bytes(), &nonce[..]].concat());
```
Input bytes = `passphrase.as_bytes()` **immediately followed by** the 32 nonce bytes,
concatenated into one contiguous buffer, hashed with the **plain keyed-less** `blake3::hash`
(a 256-bit digest). Output compared as `*expect.as_bytes() == resp` where `resp: [u8; 32]`.

- Nonce generator (server only): `iroh::SecretKey::generate().to_bytes()` — i.e. it reuses
  iroh's key generator purely as a 32-byte OS-RNG source (`auth.rs:75`). The comment says
  "32 random bytes from the OS RNG." Any CSPRNG 32-byte value works; the reference just
  avoids pulling in a separate RNG path.
- **No domain-separation / salt string.** The hash is literally `BLAKE3(passphrase ++ nonce)`
  with no prefix label, no HMAC key. (If you want to harden, you could switch to
  `blake3::keyed_hash` or prepend a fixed context label — but to PORT FAITHFULLY, do NOT add
  one, or client and server digests will diverge across versions.)

### Passphrase never on the wire — confirmed
Only `[tag] ++ nonce` (server→client) and the 32-byte digest (client→server) are written.
`pass.as_bytes()` is only ever fed into `blake3::hash` locally on each side. The plaintext
passphrase is never `write_all`'d. ✔

### Replay prevention — confirmed
A fresh random 32-byte nonce is generated per handshake (`SecretKey::generate().to_bytes()`
on every server call). The valid response is `BLAKE3(pass || nonce)`, which changes every
attempt; a captured response is worthless against a different nonce. ✔ (Note: the whole
exchange already rides inside an authenticated, encrypted QUIC connection, so on-path
capture is itself not possible; this is defense-in-depth for the case where a client node
key leaks.)

### Client-with-no-passphrase-vs-server-with-passphrase
Client uses `let pass = passphrase.unwrap_or("")` (`auth.rs:102`). A client that supplies no
passphrase against a server that requires one will hash the empty string, produce a wrong
digest, and the server will `bail!`. Failure is on the server side.

---

## 2. Dependencies and serialization details

- `blake3 = "1"` — declared directly in `moshers-iroh/Cargo.toml:17`. In the CURRENT repo,
  blake3 1.8.5 is already in `Cargo.lock` (transitively), but `transport-iroh/Cargo.toml`
  does **not** declare it — **you must add it**.
- Nonce RNG: the reference does NOT use the `rand` crate for the nonce; it uses
  `iroh::SecretKey::generate()`. The current `transport-iroh` already depends on `rand`
  (0.8) and has `generate_secret_key()` using `rand::rngs::OsRng`. Either path is fine; the
  simplest faithful port is to reuse `iroh::SecretKey::generate().to_bytes()` so no new RNG
  code is needed.
- Reference workspace: `iroh = "1.0"`, `rand = "0.9"`. Current workspace: `iroh = "=1.0.0"`,
  `rand = "0.8"`. The rand mismatch is irrelevant because we won't use rand for the nonce.
- Serialization: hand-rolled fixed-size byte buffers as in §1. No serde/postcard/bincode.

---

## 3. How auth is invoked in the reference (and failure handling)

### Server (`moshers-server/src/main.rs:73–104`)
After `accept_authorized` returns an allowlist-approved `Connection`, BEFORE the session:
```rust
let passphrase = args
    .passphrase
    .clone()
    .or_else(|| std::env::var("MOSHERS_PASSPHRASE").ok());
// ...
match tokio::time::timeout(
    std::time::Duration::from_secs(10),
    moshers_iroh::auth::handshake_server(&conn, passphrase.as_deref()),
)
.await
{
    Ok(Ok(())) => {}
    Ok(Err(e)) => {
        tracing::warn!(error = %e, "passphrase handshake rejected");
        conn.close(0u32.into(), b"auth failed");
        continue;
    }
    Err(_) => {
        tracing::warn!("passphrase handshake timed out");
        conn.close(0u32.into(), b"auth timeout");
        continue;
    }
}
// then: serve_session(conn)
```
Key points:
- **10-second timeout** wrapping the whole handshake (a stalled/malicious client cannot
  pin a session slot).
- On reject: `conn.close(0u32.into(), b"auth failed")` (QUIC app close code `0`, reason
  `"auth failed"`); on timeout: reason `"auth timeout"`. Then `continue` to the next client.
- Close code is `0` for both — the same code used by the allowlist reject path
  (`endpoint.rs:71`, `conn.close(0u32.into(), b"unauthorized")`). The reason string carries
  the distinction.

### Client (`moshers-client/src/main.rs:73–82`)
After `endpoint::connect`, BEFORE `run_client`:
```rust
let passphrase = args
    .passphrase
    .clone()
    .or_else(|| std::env::var("MOSHERS_PASSPHRASE").ok());
moshers_iroh::auth::handshake_client(&conn, passphrase.as_deref())
    .await
    .context("passphrase handshake")?;
```
No timeout on the client side; if the server closes mid-handshake the `accept_bi`/`read_exact`
returns an error which propagates via `?`.

### CLI surface (reference)
- Server arg: `#[arg(long)] passphrase: Option<String>` (`main.rs:36–39`), help: "Require a
  shared passphrase (defense-in-depth on top of the node-id allowlist). Also read from
  $MOSHERS_PASSPHRASE."
- Client arg: identical `#[arg(long)] passphrase: Option<String>` (`main.rs:27–29`).
- Both fall back to `$MOSHERS_PASSPHRASE` env var via `.or_else(|| std::env::var(...).ok())`.

---

## 4. Current crate state (the defect)

There is **no passphrase handshake at all** in `rmosh-`. The only auth is:
- node-id allowlist, inline in `server/main.rs:147–151`:
  ```rust
  if !allow_any && !allow.contains(&peer) {
      warn!(...);
      conn.close(1u32.into(), b"not authorized");
      return;
  }
  ```
  (note: rmosh uses close code **`1`** for the allowlist reject, vs reference's `0`).
- `transport-iroh/src/lib.rs` has NO `auth` module and no `handshake_*` functions.

Defect: a leaked/guessed client node key is sufficient to get a shell; there is no second
factor. The server's `run_session(conn, ...)` is called immediately after the allowlist
check with no further verification.

Structural note for wiring: in rmosh the server passes the raw `Connection` into
`run_session(conn, shell, scrollback)` (server `lib.rs:17`, which then builds `IrohChannel`
internally at `lib.rs:22`). The client builds `IrohChannel::new(conn)` in `client/main.rs:153`
then calls `run_client(channel, ...)`. **The handshake must run on the raw `&conn` BEFORE
those wrappings** (server: before `run_session`; client: after `connect`, before
`IrohChannel::new`). The handshake takes `&Connection`, so it does not consume `conn`.

---

## 5. Concrete plan + Rust sketch (port into `rmosh-`)

### Step A — new module `crates/transport-iroh/src/auth.rs`
Faithful port (only crate-name/comment cosmetics changed; logic identical):
```rust
//! Optional passphrase second auth factor (defense-in-depth on top of the node-id allowlist).
//!
//! The connection is already cryptographically authenticated to a node public key and gated
//! by the allowlist. A shared passphrase adds a second factor for the case where a client key
//! leaks. The server opens a reliable bi-stream, sends a fresh random nonce, and verifies
//! `BLAKE3(passphrase || nonce)` — so the passphrase never crosses the wire and each
//! handshake is replay-unique.

use anyhow::{bail, Result};
use iroh::endpoint::Connection;

const NO_PASS: u8 = 0;
const PASS_REQUIRED: u8 = 1;

/// Server side of the passphrase handshake. With no passphrase configured it announces
/// `NO_PASS` and returns. Otherwise it challenges and verifies before the session starts.
pub async fn handshake_server(conn: &Connection, passphrase: Option<&str>) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    match passphrase {
        None => {
            send.write_all(&[NO_PASS]).await?;
            let _ = send.finish();
        }
        Some(pass) => {
            let nonce = iroh::SecretKey::generate().to_bytes(); // 32 random bytes from the OS RNG
            let mut msg = Vec::with_capacity(33);
            msg.push(PASS_REQUIRED);
            msg.extend_from_slice(&nonce);
            send.write_all(&msg).await?;

            let mut resp = [0u8; 32];
            recv.read_exact(&mut resp).await?;
            let expect = blake3::hash(&[pass.as_bytes(), &nonce[..]].concat());
            let _ = send.finish();
            if resp != *expect.as_bytes() {
                bail!("passphrase challenge failed");
            }
        }
    }
    Ok(())
}

/// Client side of the passphrase handshake. Reads the challenge and, if required,
/// answers with `BLAKE3(passphrase || nonce)`.
pub async fn handshake_client(conn: &Connection, passphrase: Option<&str>) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag).await?;
    if tag[0] == PASS_REQUIRED {
        let mut nonce = [0u8; 32];
        recv.read_exact(&mut nonce).await?;
        let pass = passphrase.unwrap_or("");
        let resp = blake3::hash(&[pass.as_bytes(), &nonce[..]].concat());
        send.write_all(resp.as_bytes()).await?;
        let _ = send.finish();
    }
    Ok(())
}
```

Notes on the port (verify against rmosh's iroh 1.0.0 API — identical version, should compile
as-is):
- `SendStream::write_all` and `RecvStream::read_exact` are async (`.await?`) on iroh 1.0 —
  matches. `send.finish()` is **synchronous and returns Result** (rmosh's own
  `IrohChannel::send_reliable` at `lib.rs:230` already uses `send.finish()?` synchronously),
  so `let _ = send.finish();` is correct here too.
- `recv.read_exact` returns the iroh `ReadExactError`; with anyhow `?` it converts fine.

### Step B — register the module in `crates/transport-iroh/src/lib.rs`
Add at the top (near the other items, e.g. just after the `use` block / before `pub const ALPN`):
```rust
pub mod auth;
```
The functions are then `rmosh_transport_iroh::auth::handshake_server` /
`...::auth::handshake_client`.

### Step C — `crates/transport-iroh/Cargo.toml`: add blake3
Append to `[dependencies]`:
```toml
blake3 = "1"
```
(blake3 1.8.5 already resolves in `Cargo.lock`; this just makes it a direct dep. `anyhow`
and `iroh` are already deps of this crate, so no other Cargo change is needed for the lib.)

### Step D — server CLI + call site (`crates/server/src/main.rs`)
1. Add to `struct Args` (after the existing `local` field, ~line 55):
```rust
    /// Require a shared passphrase (defense-in-depth on top of the node-id allowlist).
    /// Also read from $RMOSH_PASSPHRASE.
    #[arg(long)]
    passphrase: Option<String>,
```
2. In `main`, before the accept loop, after `let allow = ...; let allow_any = ...;`
   (~line 133), resolve the passphrase and make it cheaply cloneable into the spawned task:
```rust
    let passphrase = std::sync::Arc::new(
        args.passphrase
            .clone()
            .or_else(|| std::env::var("RMOSH_PASSPHRASE").ok()),
    );
```
3. Inside the `tokio::spawn` accept body, clone it alongside `allow`/`shell`:
```rust
    let passphrase = passphrase.clone();
```
   (add `let passphrase = passphrase.clone();` next to the existing
   `let allow = allow.clone(); let shell = shell.clone();` at ~lines 136–137).
4. After the allowlist check passes and before `run_session` (between current lines 152 and
   153, i.e. right after the "client authorized" `info!`), insert the timed handshake:
```rust
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        rmosh_transport_iroh::auth::handshake_server(&conn, passphrase.as_deref()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(error = %e, "passphrase handshake rejected");
            conn.close(1u32.into(), b"auth failed");
            return;
        }
        Err(_) => {
            warn!("passphrase handshake timed out");
            conn.close(1u32.into(), b"auth timeout");
            return;
        }
    }
```
   Notes: `passphrase.as_deref()` on `Arc<Option<String>>` needs
   `passphrase.as_ref().as_deref()` (Arc derefs to `Option<String>`, then `.as_deref()` →
   `Option<&str>`). Use `conn.close(1u32.into(), ...)` to match rmosh's existing reject code
   `1` (the reference uses `0`; staying with `1` keeps rmosh internally consistent — pick one
   and document it). `return;` (not `continue;`) because each connection runs in its own
   spawned task here, unlike the reference's single-threaded `loop`.

### Step E — client CLI + call site (`crates/client/src/main.rs`)
1. Add to `struct Args` (after `show_id`, ~line 71):
```rust
    /// Shared passphrase, if the server requires one. Also read from $RMOSH_PASSPHRASE.
    #[arg(long)]
    passphrase: Option<String>,
```
2. After `let conn = endpoint.connect(...).await...?;` and the "connected" eprintln
   (~line 151), BEFORE `let channel = rmosh_transport_iroh::IrohChannel::new(conn);`
   (line 153), insert:
```rust
    let passphrase = args
        .passphrase
        .clone()
        .or_else(|| std::env::var("RMOSH_PASSPHRASE").ok());
    rmosh_transport_iroh::auth::handshake_client(&conn, passphrase.as_deref())
        .await
        .context("passphrase handshake")?;
```
   `conn` is consumed by `IrohChannel::new(conn)` on the next line, and the handshake takes
   `&conn`, so ordering is: connect → handshake(&conn) → IrohChannel::new(conn). No Cargo
   change needed for the client (it already depends on `rmosh-transport-iroh` and `anyhow`).
   The server binary also needs no Cargo change (already depends on
   `rmosh-transport-iroh` + `tokio` + `anyhow`).

### Step F (optional) — integration test
Mirror `moshers-iroh/tests/session.rs::passphrase_handshake_over_iroh`
(reference lines 47–81): connect a loopback pair via `bind_endpoint_local` +
`loopback_addr` (already in `transport-iroh/lib.rs`), then `tokio::join!` the two handshakes
for: (a) `None`/`None` ⇒ both Ok; (b) `Some("hunter2")`/`Some("hunter2")` ⇒ both Ok;
(c) `Some("hunter2")`/`Some("nope")` ⇒ server `is_err()`. Put it in
`crates/transport-iroh/tests/auth.rs`. Reuse the existing test's two-endpoint pattern from
`transport-iroh/src/lib.rs::two_endpoints_exchange_datagram_over_loopback` (lines 311–340)
for the connect setup. IMPORTANT: when testing case (c) the wrong-passphrase response still
completes the bi-stream, so only assert on the SERVER result; do not assert the client errors
(client just writes a digest and returns Ok).

---

## 6. Gotchas / invariants to preserve (concrete)

1. **Stream direction**: server `open_bi`, client `accept_bi`. Inverting deadlocks both.
2. **Exact byte counts**: server writes 1 byte (NO_PASS) or 33 bytes (tag+nonce); client
   reads 1 then (if PASS_REQUIRED) 32; client writes exactly 32; server reads exactly 32.
   `read_exact` will hang or error on any size drift — do not add framing.
3. **Hash input order**: `passphrase_bytes ++ nonce` (passphrase FIRST). Reversing it breaks
   compatibility silently (both sides must agree; if you port one side reversed, auth always
   fails).
4. **No salt/domain label** in the faithful port. If you add one later, add it to BOTH sides
   identically.
5. **Nonce freshness**: generate inside `handshake_server` per call (it is, via
   `SecretKey::generate()`), never cache it — caching would defeat replay protection.
6. **Run BEFORE session wrapping**: server before `run_session(conn,...)`; client before
   `IrohChannel::new(conn)`. The handshake borrows `&conn`, so it must precede the move.
7. **Timeout only on server** (10 s). Don't wrap the client side in a timeout — it blocks on
   the server's first write, which the server's own timeout already bounds.
8. **Close codes**: rmosh uses code `1` for allowlist reject; keep `1` for the passphrase
   reject/timeout for internal consistency (reference uses `0` — divergence is intentional,
   just be consistent within rmosh). Reasons: `b"auth failed"` / `b"auth timeout"`.
9. **Env var name**: reference uses `$MOSHERS_PASSPHRASE`; use `$RMOSH_PASSPHRASE` to match
   the rmosh naming convention (the rmosh client already uses `$RMOSH_LOG`).
