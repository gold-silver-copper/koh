# koh — Security Audit (v0.3.1)

## 1. Executive summary

koh's transport security (iroh QUIC + TLS, endpoint authentication by public-key NodeId) is sound, and the seven fixes from the 0.3.1 hardening pass all hold. The remaining risk is concentrated in the **post-authentication data plane**: once a peer holds a valid connection, several attacker-controlled wire fields drive **unbounded memory growth, CPU/syscall amplification, and one reachable client-side panic** that the crate's `panic`/`string_slice` lints do not catch. There is also one **cryptographic design weakness** (offline-crackable passphrase challenge with a fixed public salt and no server-identity binding) and a handful of local/config footguns.

**Counts by consensus severity:** 0 critical · 5 high · 3 medium · 7 low · 4 info.

**The single most important thing to fix:** bound the receiver/sender state machine and the per-instruction diff. The `received_states` list is capped by *count* (1024) but never by *bytes*, and a single inbound instruction can inflate to ~16 MiB of diff and ~95 MiB of resident state. Composing these (KOH-01, KOH-02, KOH-07) yields a ~6000× memory-amplification DoS that can OOM-kill the server host (where the real shell runs) or a connecting client from a handful of small datagrams. Adding a per-direction diff-size cap plus a byte budget on `received_states` closes the most severe vector and shrinks the blast radius of the related CPU findings.

---

## 2. Scope & method

**Subsystems audited (8 dimensions):**
1. **wire-deser** — `src/wire.rs`, `src/ssp/transport.rs`, `src/ssp/mod.rs`, `src/ssp/rtt.rs`, and the diff-applying sinks (`src/input.rs`, `src/terminal/mod.rs`, `src/terminal/server.rs`).
2. **auth-crypto** — `src/transport_iroh/auth.rs`, `mod.rs`, `ratelimit.rs`, the accept/attach paths, and the client handshake invocation.
3. **terminal-render** — `src/terminal/mod.rs`, `src/terminal/server.rs`, `src/client/render.rs`, `src/predict.rs`, `src/input.rs`.
4. **pty-session** — `src/pty.rs`, `src/server/session.rs`, `src/server/mod.rs`, `src/server/cli.rs`, `src/terminal/server.rs`.
5. **dos-resource** — rate-limiting, connection/session caps, fragment reassembly, decompression, state accumulation.
6. **secrets-fs** — key persistence, file/dir permissions, passphrase handling, env scrub.
7. **supply-chain** — `cargo audit`, `cargo tree`, crypto/TLS backend, pinned versions.
8. **prior-fix-regression** — re-audit of the 0.3.1 fixes (H-1, M-1, M-2, L-1..L-4).

**Threat model.** iroh already provides on-wire encryption, integrity, and endpoint authentication by NodeId, so passive eavesdropping and on-path tampering of an established connection are **out of scope**. Effort focused on: (1) a hostile/compromised peer holding a valid connection — what a malicious client can do to the server host, and what a malicious server can do to a connecting client; (2) unauthorized peers / auth bypass / replay / session hijack; (3) resource exhaustion / DoS; (4) local secret-handling; (5) memory-safety / reachable panics in `forbid(unsafe)` code.

**Verification.** Every finding below was confirmed against real code (Read/Grep/Bash, exact `file:line` + verbatim snippets) and survived a ≥2/3 adversarial **three-lens panel** (code-reality, exploitability, severity-calibration). Where the panel's reasoning showed a claimed severity was inflated, the consensus severity below reflects the calibrated value, not the claimed one. The 0.3.1 prior fixes were independently re-checked (Section 4).

---

## 3. Findings

Ordered by consensus severity. Three wire/DoS findings (KOH-01, KOH-02, KOH-07) share a common root cause — the missing per-direction size/byte bound — and are reported separately because each has a distinct primitive and remediation; their corroboration is noted inline.

---

### KOH-01 — `received_states` is bounded by count but not by bytes (state-accumulation OOM)

- **Severity:** High (consensus 3/3) · **Category:** DoS / resource exhaustion
- **Location:** `src/ssp/transport.rs:616-652` (quench + unconditional insert), `src/ssp/mod.rs:60` (`RECEIVED_STATES_CAP = 1024`), composed with `src/input.rs:128-135` / `src/terminal/mod.rs:285-296` (per-state size)
- **Corroboration:** Reported independently by the *wire-deser* and *dos-resource* dimensions (client `Remote = TerminalScreen` ~32 MB/state; server `Remote = UserInput` ~95 MiB/state). Same root cause, merged here.

**Evidence:**
```rust
// Anti-DoS quench once the received list is huge.
if self.received_states.len() > RECEIVED_STATES_CAP {
    if now < self.receiver_quench_timer {
        return RecvOutcome::Quenched;
    }
    self.receiver_quench_timer = now + RECEIVER_QUENCH_MS;
}
...
// Insert sorted by num (handles reordering).
if let Some(pos) = self.received_states.iter().position(|s| s.num > ts.num) {
    self.received_states.insert(pos, ts);   // unconditional
} else {
    self.received_states.push(ts);
}
```

The quench is a **rate limiter, not a hard cap**. While `len <= RECEIVED_STATES_CAP` every accepted instruction inserts unconditionally; even the datagram that first crosses the cap falls through and inserts (the quench only arms a 15 s timer for *subsequent* datagrams). The list shrinks only via `process_throwaway_until(throwaway_num)`, which is **peer-controlled**: with `throwaway_num = 0` the seeded num-0 base never GCs and every distinct `new_num` resolves its `old_num = 0` base. `get_remote_diff`'s `subtract_prefix` runs against that empty num-0 base, so divergent states reclaim nothing. There is **no per-state byte accounting anywhere**.

**Attack scenario:** An attacker (authorized client → server, or malicious server → client) sends instructions with `old_num = 0`, `throwaway_num = 0`, distinct increasing `new_num`, each carrying a large divergent diff. On the **client**, each `TerminalScreen` clone holds a full `vt100::Screen`; a resize to (1000,1000) clamps to MAX_DIM but is still ~32 MB/state → ~1024 × 32 MB ≈ 32 GB → OOM. On the **server**, each `UserInput` diff expands one 6-byte `InputEvent` per input byte, so a ~16 MiB Keys diff → ~95 MiB/state; pipelined up to ~1024 distinct states → tens of GB resident → OOM-kill of the host that runs the real shell. The damaging path engages well before the quench (which throttles by count only) ever fires.

**Remediation:** Make `received_states` a true bounded structure — when an insert would exceed `RECEIVED_STATES_CAP`, **drop or evict** rather than insert-then-rate-limit. Add a **byte budget** (track aggregate resident bytes and quench/evict on a memory threshold, not only count) and cap per-state size at insert time. For the server `UserInput` state specifically, drop states below `last_delivered` aggressively rather than trusting the peer's `throwaway_num`. Lowering `RECEIVED_STATES_CAP` and capping the per-instruction diff (see KOH-07) further reduce the ceiling.

---

### KOH-02 — Client/server input-apply decompression amplification (~6000× → host OOM)

- **Severity:** High (consensus 3/3) · **Category:** DoS / allocation bomb
- **Location:** `src/wire.rs:79,127-138` (`MAX_DECOMPRESSED = 16 MiB`, inflate), `src/ssp/transport.rs:612-637` (clone base + apply diff), `src/input.rs:55-58,128-135` (one `InputEvent` per byte), `src/server/mod.rs:134-161` (drain + PTY write)

**Evidence:**
```rust
wire.rs:79    const MAX_DECOMPRESSED: usize = 16 * 1024 * 1024;
wire.rs:128   let raw = miniz_oxide::inflate::decompress_to_vec_with_limit(bytes, MAX_DECOMPRESSED)?;
transport.rs:626  Ok(d) => new_state.apply(&d),
input.rs:131  WireEvent::Keys(bytes) => self.push_bytes(bytes),   // 1 InputEvent (6 B) / input byte
```

The wire payload is DEFLATE-compressed and the **only** bound on the inflated instruction is 16 MiB. A single `WireEvent::Keys` of ~16 MiB of a repeated byte compresses (~1000:1) to ~16 KB on the wire (~14 datagrams), inflates to 16 MiB, and `UserInput::apply` expands it to ~16.7M `InputEvent` entries ≈ **95 MiB** resident in one state slot. The same `recv` also retains the 16 MiB decoded `Instruction.diff`; `get_remote_diff` clones the newest state into `last_delivered_remote` (~95 MiB again) and materializes another ~16 MiB `Vec<WireEvent>`; the drain loop writes the full 16 MiB straight to the PTY. Verifiers reproduced this with a PoC against the pinned deps: 16,465 wire bytes / 14 datagrams → 16,776,192 resident `InputEvent`s, a ~6113× amplification. `size_of::<InputEvent>() == 6` was confirmed.

**Attack scenario:** An authorized-but-malicious client (on `--allow`, or any client under `--allow-any`, passphrase passed once if set) sends one such instruction with `old_num = 0` (always-present base) and a distinct `new_num`. Per shot: ~200 MiB transient + ~95 MiB resident + a 16 MiB PTY flood, from ~16 KB of traffic. Repeated/pipelined (composing with KOH-01), this OOM-kills the server host.

**Remediation:** Cap the **client→server** direction far below 16 MiB — keystroke input is a few KB even for a huge paste; 64–256 KiB is ample. Either give `Instruction::decode` a direction-specific decompressed limit, or cap post-apply `UserInput` event count / total diff bytes in `Transport::recv` before storing the state, rejecting (and optionally closing) anything larger. Independently consider lowering `MAX_DECOMPRESSED` overall (a 1000×1000 `state_formatted` repaint is well under 1 MiB).

---

### KOH-03 — Fixed public KDF salt + server-chosen nonce → offline passphrase brute-force

- **Severity:** Medium (consensus: high / medium / medium → **medium**) · **Category:** Crypto
- **Location:** `src/transport_iroh/auth.rs:67-71` (`kdf_salt`), `84-95` (`derive_psk`), `130-135` (`challenge_response`), `159-196` / `204-231` (handshakes); client connect path `src/client/mod.rs:86-101`
- **Severity note:** Claimed high; downgraded to **medium** on consensus. The structural defect is real, but exploitability is gated by (a) Argon2id at 64 MiB / t=3 / p=1 — genuinely memory-hard, so only weak/dictionary passphrases are realistically crackable; (b) it is a documented *second* factor layered on the NodeId allowlist; and (c) it requires luring the victim onto an attacker-controlled NodeId.

**Evidence:**
```rust
fn kdf_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blake3::hash(b"koh-pass-kdf-v1").as_bytes()[..16]);
    salt
}
fn challenge_response(psk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(psk);
    input[32..].copy_from_slice(nonce);
    *blake3::hash(&input).as_bytes()
}
```

The response is `BLAKE3(K || nonce)` where `K = Argon2id(passphrase, kdf_salt())` and `kdf_salt()` is a hardcoded public constant. **No** server NodeId, client NodeId, per-deployment secret, or TLS exporter is mixed into `K` or the response (verified: grep found no `export_keying_material`/`remote_node_id` folded into the nonce or response path). The server chooses the nonce; the client computes and sends the response before any server-authenticating step. So a malicious server the user dials obtains a `(nonce, response)` transcript and can mount a **fully offline** dictionary attack: for each candidate `p`, compute `Argon2id(p, fixed_salt)` then `BLAKE3(K'||nonce)` and compare. The per-peer `FailureLimiter` and the Argon2 cost only throttle *online* guessing against the real server.

**Attack scenario:** A user is induced to `koh connect <attacker-id>` (phished/typo'd/rotated connect string) with `KOH_PASSPHRASE` set. The attacker's server sends `PASS_REQUIRED` + an arbitrary nonce, captures the response, and cracks the passphrase offline on its own hardware. Combined with the leaked-but-still-allowlisted-key residual case the passphrase exists to cover, this defeats the second factor.

**Remediation:** Bind the response to the server's iroh-authenticated identity so a transcript is useless against any other server, e.g. `response = BLAKE3(K || server_node_id || nonce)` with `K = Argon2id(passphrase, H(server_node_id))`, and/or channel-bind to the QUIC exporter. Ideally replace the hash-challenge with an augmented PAKE (OPAQUE / SPAKE2+) so no server can mount an offline dictionary attack from a transcript. Document loudly that the passphrase must be high-entropy.

---

### KOH-04 — `String::truncate` on a multi-byte status line panics the client (remote DoS)

- **Severity:** Medium (consensus: high / high / medium → **medium**) · **Category:** DoS / reachable panic
- **Location:** `src/client/render.rs:170-175`; status strings at `src/client/mod.rs:456` and `:736`
- **Severity note:** Claimed high; consensus settles at **medium**. It is a deterministic, remotely-triggerable crash, but the blast radius is a single connecting client process that voluntarily attached to a malicious/compromised server — not a server-wide or cross-tenant crash. (Two verifiers rated high; the calibration lens rated medium, and the rubric reserves high for server-wide crash / RCE / auth-bypass.)

**Evidence:**
```rust
if let Some(st) = status {
    let mut line = format!(" {st} ");
    let max = cols as usize;
    if line.len() > max {
        line.truncate(max);   // panics if max is not a UTF-8 char boundary
    }
```

`cols` comes from `screen.size()` on the server-synced screen, whose dimensions are set by `ScreenDiff.resize`, clamped only to `[2, 1000]`. The status strings are non-ASCII: `"[koh] link down — resuming… {}s"` and `"[koh] disconnected — reconnecting… {secs}s ..."` both contain the em-dash `—` (U+2014, 3 bytes) and ellipsis `…` (U+2026, 3 bytes). Verifiers compiled the exact framed line and confirmed `truncate(18/19/30/31)` panics on the link-down status (em-dash at bytes 17–19, ellipsis at 29–31). The crate's panic-prevention lints miss this: `string_slice = deny` only catches `s[a..b]` syntax and `panic = deny` only catches the `panic!` macro — neither flags `String::truncate`. No `catch_unwind` exists; the panic unwinds the main client task and crashes the process.

**Attack scenario:** A malicious/compromised server resizes the client to cols ∈ {18,19,30,31} via one `ScreenDiff`, then goes silent > 3 s (triggering the link-down status) or drops the link (triggering the reconnect banner). The next `render()` panics — a deterministic remote crash of the client with no auth bypass required.

**Remediation:** Truncate by characters, not bytes — `line = line.chars().take(max).collect()`, or walk back to a char boundary (`while max > 0 && !line.is_char_boundary(max) { max -= 1 }`) before truncating, mirroring the existing `capped_bytes`/`capped_chars` helpers. Add a test asserting `render()` is panic-free across all `cols` in `[MIN_DIM, MAX_DIM]` with the real status strings, since the lints do not cover `String::truncate`.

---

### KOH-05 — Unbounded per-frame Resize/Keys event flood under the session lock (CPU/syscall DoS)

- **Severity:** High (consensus 3/3) · **Category:** DoS / amplification
- **Location:** `src/server/mod.rs:138-160` (apply loop under the lock), `src/input.rs:92-95,118-126` (resizes never coalesced), `src/terminal/server.rs:160-162` (vt100 `set_size`), `src/pty.rs:266-275` (TIOCSWINSZ)
- **Corroboration:** Reported by *pty-session* (consensus high) and, as a narrower variant, by *dos-resource* (consensus medium — see KOH-09). Merged: the high-severity framing (lock held across the whole burst, SIGWINCH storm, sustainable) is KOH-05; the count-bound observation is the same root cause.

**Evidence:**
```rust
let mut s = handle.session.lock().await;   // held across the whole loop, no .await inside
for w in &input_diff {
    match w {
        WireEvent::Keys(b) => { ... s.pty.write_input(&bytes) ... }
        WireEvent::Resize { rows, cols } => {
            let (rows, cols) = crate::terminal::clamp_dims(*rows, *cols);
            let _ = s.pty.resize(rows, cols);   // ioctl(TIOCSWINSZ) -> SIGWINCH to child
            s.emu.resize(rows, cols);           // vt100 set_size: reallocates up to 1000x1000 cells
        }
    }
}
```

`UserInput::diff_from` never coalesces `Resize` events (each is one `WireEvent`), and there is no per-frame event-count cap. A `WireEvent::Resize` postcard-encodes to ~3–5 bytes, so a 16 MiB inflated diff packs ~3M resize events, and a repetitive resize log DEFLATEs to a few KB on the wire. Each resize then costs a real `ioctl(TIOCSWINSZ)` + SIGWINCH and a vt100 `set_size` (no no-op short-circuit; O(rows·cols), up to 1M cells). The H-1/M-2 `clamp_dims` fix bounds each resize's *dimensions* but not the *count*. The whole burst runs under the per-session `Mutex`, also blocking the drain task. Verifiers measured ~793 µs/call for alternating (1000,1000)/(2,2) resizes against the pinned vt100, extrapolating one ~19 KiB burst to ~44 minutes of single-thread CPU plus ~3.35M SIGWINCH to the child.

**Attack scenario:** An authorized-but-malicious client sends one small datagram set encoding millions of alternating-dimension resizes. The drain loop fires millions of synchronous ioctls + grid reallocs under the session lock, pinning a tokio worker at 100% CPU, freezing that session's rendering/input, and flooding the child shell with SIGWINCH. Trivially repeatable/sustainable.

**Severity / blast-radius note:** Sessions are keyed per-peer (`EndpointId`), so the held `Mutex` is per-session; on the default multi-threaded runtime other tenants' sessions are not lock-blocked. The high rating reflects the ~1000× amplification, the tens-of-minutes CPU burn from one tiny burst, and the SIGWINCH storm — not a clean server-wide kill.

**Remediation:** Coalesce consecutive resizes — apply only the **last** resize in a drained diff (intermediate sizes have no observable effect). Cap total events processed per `recv`. Do not hold the session lock across the entire per-event loop (process the diff in bounded chunks, or outside the lock). The `Keys` arm is a milder variant (a 16 MiB `normalize` alloc + a 16 MiB `to_vec` clone per frame) — capped by the same KOH-02 diff-size bound.

---

### KOH-06 — State dir created in world-writable shared locations (`$TMPDIR/koh`, `/data/local/tmp/koh`)

- **Severity:** Medium (consensus: medium / low / low → **low–medium**; reported as low-leaning) · **Category:** Config / local
- **Location:** `src/transport_iroh/mod.rs:194-210` (`state_dir_from`), `106-121` (`create_dir_private`), `88-100` (`load_or_create_secret_key`)
- **Severity note:** Claimed medium; consensus splits medium/low/low. The calibration lenses lowered it to **low** because the vulnerable fallback is reached only when `ProjectDirs` yields nothing AND `$HOME` is unset AND `$KOH_STATE_DIR` is unset (stripped container / bare ADB shell — Termux sets `$HOME`), and the key file itself is still born 0600 so the key cannot be *read*. The damaging capability is parent-dir write (unlink/replace), not disclosure.

**Evidence:**
```rust
if let Some(t) = nonempty(tmpdir) {
    return std::path::PathBuf::from(t).join("koh");
}
std::path::PathBuf::from("/data/local/tmp/koh")
...
std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
```

When `ProjectDirs` yields nothing, the key path falls back to `$TMPDIR/koh` or hardcoded `/data/local/tmp/koh` — shared, world-writable, multi-user parents. `DirBuilderExt::mode(0o700)` applies only to components this call *creates*; a pre-existing attacker-owned/world-writable `koh` dir is reused without tightening. The key file is 0600 (`create_new` + atomic rename), so it cannot be read or symlink-redirected, but **write access to the parent dir grants unlink/rename**: a co-tenant can delete the server's identity key (forcing a fresh NodeId → every allowlisted client rejects the server) or pre-stage the dir.

**Attack scenario:** On a shared host with no `ProjectDirs` config dir, the victim runs `koh serve`. A co-located uid pre-creates `/data/local/tmp/koh` (or it is world-writable), then `rm`s `server.key` between runs to force identity churn / persistent allowlist breakage. Not network-triggerable.

**Remediation:** After `create_dir_private`, `stat` the resolved leaf: refuse (with a message pointing to `--key-file` / `$KOH_STATE_DIR`) if it is not owned by the current uid or is group/other-writable (`mode & 0o022 != 0`). Prefer a per-user base (XDG_DATA_HOME / `$HOME`) over `/tmp`; on Android prefer the app's private files dir. Use `create_new` semantics on the leaf so a pre-existing foreign dir is detected, not silently reused.

---

### KOH-07 — Fragment reassembly buffers up to ~39 MiB pre-decompression with no total-bytes cap

- **Severity:** Low (consensus 3/3) · **Category:** DoS / resource
- **Location:** `src/wire.rs:313-373` (`FragmentAssembly::add`), `54` (`MAX_FRAGMENT_INDEX = 0x7fff`)

**Evidence:**
```rust
self.parts.insert(frag.index, frag.payload);
let needed = final_idx as usize + 1;
if self.parts.len() != needed || self.parts.keys().next_back() != Some(&final_idx) { return Ok(None); }
```

`FragmentAssembly` holds all parts for the current id in a `BTreeMap` until completion. The only cap is the index ceiling (32768 indices); there is **no cap on the sum of payload bytes**, and `MAX_DECOMPRESSED` is enforced only *after* completion. Each fragment payload is ~MTU-sized (~1190 B), so an attacker sending ~32768 distinct non-final fragments (never completing) holds ~39 MiB of scratch, then bumps the id to clear and repeat. The buffer is per-connection (a higher id clears it), so it is bounded, not unbounded growth — hence low. Multiplied across `max_connections` (default 64) under `--allow-any` it reaches ~2.5 GiB.

**Attack scenario:** An authorized peer churns ~39 MiB allocate/clear cycles per id by sending only the high-index fragments of instructions it never completes. Bandwidth-symmetric (must send ~39 MiB to hold ~39 MiB), so no amplification.

**Remediation:** Track and cap the total buffered payload bytes in `FragmentAssembly` (reset once the sum exceeds the same direction-specific budget from KOH-02), so reassembly cannot hold materially more than the decompressed-instruction limit.

---

### KOH-08 — Slowloris: peers can hold connection-cap permits ~10 s each via stalled handshakes

- **Severity:** Low (consensus 3/3) · **Category:** DoS / availability
- **Location:** `src/server/cli.rs:290-294` (permit acquire pre-handshake), `331-341` (10 s handshake timeout); `src/transport_iroh/auth.rs:181` (blocking `read_exact`)

**Evidence:**
```rust
let Ok(permit) = conn_limit.clone().try_acquire_owned() else { ... incoming.refuse() ... };
...
match tokio::time::timeout(std::time::Duration::from_secs(10),
    crate::transport_iroh::auth::handshake_server(...))
```

The permit is acquired before the handshake (good — excess dials are refused cheaply via `incoming.refuse()`), but once held, the task can sit in `handshake_server`'s blocking `read_exact` for the 32-byte response for the full 10 s timeout. With `max_connections = 64`, 64 stalled handshakes pin all permits and refuse legitimate clients. The per-peer `FailureLimiter` (5 fails / 60 s) blunts this for a single leaked-but-allowlisted key, but under `--allow-any` an attacker mints fresh iroh keypairs per connection, and an unknown `EndpointId` always passes the limiter — so all 64 permits can be pinned continuously by rotating dials.

**Attack scenario:** Under `--allow-any` (or with a leaked allowlisted key), open 64 connections that complete QUIC + open the auth bi-stream but never answer the nonce challenge; re-open on each 10 s expiry to keep the server saturated.

**Remediation:** Shorten the handshake timeout (2–3 s is ample for a LAN/same-host nonce exchange). Add a global cap on concurrently-pending (un-authenticated) handshakes separate from the established-connection cap. The `FailureLimiter` already records timeouts, but it is per-`EndpointId` and thus evaded under `--allow-any` by fresh keys.

---

### KOH-09 — Resize-event flood: variant of KOH-05 (dos-resource framing)

- **Severity:** Medium (consensus: low / medium / medium → **medium**) · **Category:** DoS / amplification
- **Location:** `src/server/mod.rs:138-160`, `src/input.rs:131-134`, `src/terminal/server.rs:160-162`
- **Note:** This is the same vector as **KOH-05**, reported by the *dos-resource* dimension at a lower (medium) consensus because it emphasizes the per-event ioctl/realloc cost over the lock-held-CPU-burn framing. It is retained here only to record the corroboration and the calibration nuance: one verifier rated it **low**, scoping the impact to the attacker's *own* session (the per-session `Mutex` does not block other tenants' sessions, and the session store is not globally locked during the loop). **Treat KOH-05 as the canonical entry; fix once.**

**Remediation:** Same as KOH-05 — coalesce to the final resize per drained diff, cap events per datagram, and avoid holding the session lock across the loop.

---

### KOH-10 — `teardown()` Err-path discards `kill()` result and never joins PTY pump threads

- **Severity:** Low (consensus: low / info / low → **low**) · **Category:** DoS / resource leak
- **Location:** `src/server/session.rs:188-198`; `Pty` has no `Drop` (`src/pty.rs:225-243` joins threads only in `shutdown`)

**Evidence:**
```rust
Err(h) => {
    let _ = h.session.lock().await.pty.kill();   // result discarded; Pty later dropped, never shutdown()
}
```

`Pty` has no `Drop`; its two pump threads are joined only in `Pty::shutdown`. In the Err branch (taken while the drain task still holds an `Arc`, e.g. shell alive but detach TTL expired), only `pty.kill()` is called and its result is dropped — unlike `Pty::shutdown` which at least logs a warning. **Correction to the original framing (which strengthens, not weakens, the finding):** portable-pty 0.9.0's cloned `ProcessSignaller::kill` sends `SIGHUP` only (no SIGKILL escalation), and `libc::kill(pid, SIGHUP)` returns `Ok` even when the child ignores SIGHUP. So the realistic trigger is a **SIGHUP-immune child** (`trap '' HUP`, a re-parenting daemon), not a `kill` syscall failure: the reader thread stays blocked on `read()` forever, the drain `Arc` never drops, and one blocked thread + master/slave fds + the session's scrollback leak permanently — defeating the reaper for that slot.

**Attack scenario:** A malicious authorized client spawns a SIGHUP-ignoring process, detaches, and lets the detach TTL expire. The reaper's `kill()` is ignored, the session wedges, and resources leak. Bounded by `max_sessions` (default 64) per identity; accumulating toward true thread/fd exhaustion needs many identities (`--allow-any`) or a slow grind.

**Remediation:** Give `Pty` a `Drop` impl that kills (with SIGKILL escalation) and joins/signals both pump threads, so dropping without an explicit `shutdown()` can never leave a permanently-blocked reader. On the Err path, **log** the failed `kill()` instead of discarding it. Fix the cloned killer to escalate to SIGKILL after SIGHUP (the `pty.rs:292` doc comment claims this escalation but the cloned signaller does not perform it).

---

### KOH-11 — Empty `KOH_PASSPHRASE` advertises "passphrase required" while accepting everyone

- **Severity:** Low (consensus 3/3) · **Category:** Config / false assurance
- **Location:** `src/server/cli.rs:205-233,331-339`

**Evidence:**
```rust
if args.passphrase.is_some() || std::env::var("KOH_PASSPHRASE").is_ok() {
    eprintln!("│ 2nd factor  : passphrase required");
}
...
args.passphrase.clone()
    .or_else(|| std::env::var("KOH_PASSPHRASE").ok())
    .map(SecretString::from)
```

An exported-but-empty `KOH_PASSPHRASE=` makes `env::var` return `Ok("")`, so `.ok()` → `Some("")` and the server is configured with the empty-string passphrase. The banner prints "passphrase required" (`is_ok()` is true for an empty value) and the server enters the `Some(pass)` branch, but any client supplying nothing derives `cached_psk("")` (`passphrase.unwrap_or("")`) and produces the matching response — so the "required" factor is satisfied by everyone. `--passphrase ''` hits the same path. Notably, the client already filters empty env values elsewhere (`client/cli.rs:122 .filter(|v| !v.is_empty())`), which this path conspicuously omits. Not network-triggerable — the empty factor still sits behind the NodeId allowlist (enforced at `cli.rs:315` before the handshake).

**Remediation:** Treat an empty passphrase as "none" (`.filter(|p| !p.is_empty())` on both the `--passphrase` and env paths), or reject startup with an explicit error when a passphrase source is present but empty, so the banner and enforcement agree.

---

### KOH-12 — `create_dir_private` does not enforce 0700 on a pre-existing state dir

- **Severity:** Low (consensus 3/3) · **Category:** Config / local
- **Location:** `src/transport_iroh/mod.rs:106-121`

**Evidence:**
```rust
// `recursive(true)` is idempotent if the dir already exists; the mode applies to the
// components it creates.
std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
```

If the state dir already exists with looser permissions (e.g. a `~/.config/koh` left at 0755 by another tool), the `mode(0o700)` is a no-op and no warning is emitted. `warn_if_key_world_readable` checks only the key *file*'s mode, never the containing directory. The M-1 test only exercises the freshly-created path, so this gap is untested. The key file is still 0600, so a 0755 dir grants only traverse (not read of the secret); the damaging case (unlink/replace) requires a group/other-*writable* dir — a narrower precondition. Local-only.

**Remediation:** After `create_dir_private`, `stat` the resolved dir and warn (or chmod when koh-owned) when `mode & 0o077 != 0`; extend the world-readable check to the parent dir. Add a regression test that pre-creates the dir at 0755.

---

### KOH-13 — Client never enforces that a configured passphrase was actually used (silent downgrade)

- **Severity:** Low (consensus: low / not-a-bug / info → **info–low**) · **Category:** Auth-bypass (defense-in-depth)
- **Location:** `src/transport_iroh/auth.rs:204-231`
- **Severity note:** Claimed low; consensus is split low / not-a-bug / info, settling at **info-grade hardening**. Two of three lenses concluded it crosses **no security boundary** in this threat model: the passphrase is a *server-side* second factor (it lets the server authenticate the client), not a server authenticator — server identity is already established by iroh's NodeId TLS. Only the server the client deliberately dialed can send `NO_PASS`, and that server already controls all session content. Reported as a UX/robustness footgun, **not** a network-triggerable bypass.

**Evidence:**
```rust
let mut tag = [0u8; 1];
recv.read_exact(&mut tag).await?;
if tag[0] == PASS_REQUIRED {
    ... // do the challenge
}
Ok(())   // NO_PASS or any junk byte -> success, passphrase argument unused
```

`handshake_client` branches only on `PASS_REQUIRED`; for `NO_PASS` or any byte in `2..=255` it returns `Ok(())` with no auth performed, even when the client was configured with a passphrase. A user's explicit "require the second factor" intent is not honored (false assurance), and an unknown/malformed tag is silently accepted instead of rejected.

**Remediation:** When `passphrase.is_some()`, require `PASS_REQUIRED`; return `ChallengeFailed` otherwise. Treat any tag other than the two known constants as a hard protocol error. Both are cheap robustness improvements.

---

### KOH-14 — `ServeArgs`/`ConnectArgs` derive `Debug` while holding the passphrase in plaintext (latent leak)

- **Severity:** Info (consensus 3/3) · **Category:** Info-leak (latent)
- **Location:** `src/server/cli.rs:42-43,86-87`; `src/client/cli.rs:42-43,63-66`

**Evidence:**
```rust
#[derive(ClapArgs, Debug)]
pub struct ServeArgs {
    #[arg(long)]
    passphrase: Option<String>,   // plaintext, not SecretString; never zeroized
```

Both arg structs (and the nesting `Cli`/`Cmd`) derive `Debug` and store the passphrase as a plaintext `Option<String>`, at odds with the otherwise-careful `SecretString` discipline. The `SecretString` is built from a `.clone()`, so the original plaintext lingers un-zeroized for the process lifetime. **This is latent, not live:** verifiers grepped the tree and found no production `{:?}`/`debug!`/`trace!` formatting the args (the only `Debug`-format sites are `#[cfg(test)]` asserts). A future `tracing::debug!(?args)` or a panic carrying the args would print the passphrase — and `$KOH_LOG` is created world-readable via `std::fs::File::create` (`client/cli.rs:154`, no `mode()`), unlike the 0600 key file. Not network-exploitable.

**Remediation:** Type the field as `secrecy::SecretString` in the arg structs (custom clap parser), or add a redacting `Debug` impl, or drop the `Debug` derive on the secret-carrying structs; zeroize the original `String` after moving it into the `SecretString`; create `$KOH_LOG` 0600. Add a test asserting `format!("{args:?}")` does not contain the passphrase.

---

### KOH-15 — L-4 env-scrub list omits `KOH_SERVER_NETWORK_TMOUT` (server-read)

- **Severity:** Info (consensus 3/3) · **Category:** Info-leak (config)
- **Location:** `src/pty.rs:20-26` (`KOH_ENV_SCRUB`); server reader at `src/server/cli.rs:72`

**Evidence:**
```rust
const KOH_ENV_SCRUB: &[&str] = &[
    "KOH_PASSPHRASE", "KOH_LOG", "KOH_STATE_DIR", "KOH_DNS", "KOH_CLIPBOARD",
];
```

The scrub list is a hardcoded enumeration; `KOH_SERVER_NETWORK_TMOUT` (read via clap `env = "KOH_SERVER_NETWORK_TMOUT"`) is not included, so if the operator set it, it is inherited by the spawned child shell. The leaked value is a u64 idle-timeout integer (default 0), **not a secret**, observable only by an already-authorized client running `env` inside its own shell. The security-critical var — `KOH_PASSPHRASE` — *is* scrubbed (verified, with a unit test). Client-only vars (`KOH_TITLE_NOPREFIX`, `KOH_PREDICT_OVERWRITE`) never reach a spawned shell. A completeness gap, not a vulnerability.

**Remediation:** Prefer a **prefix-based scrub** — iterate the inherited env and `env_remove` every key starting with `KOH_` — so future `KOH_*` vars are covered by default. (Or add the missing var explicitly.)

---

### KOH-16 — M-1 leaves a pre-existing world-readable key in place (warn-only, never re-tightened)

- **Severity:** Info (consensus 3/3) · **Category:** Config (local, upgrade-in-place)
- **Location:** `src/transport_iroh/mod.rs:76-86`; `warn_if_key_world_readable` at `154-171`

**Evidence:**
```rust
if path.exists() {
    warn_if_key_world_readable(path);     // advisory only; never chmods
    let text = std::fs::read_to_string(path)?;
    ...
    Ok(SecretKey::from_bytes(&arr))
}
```

The M-1 fix writes **new** keys 0600, but for an **existing** key it only warns (advisory `tracing::warn!`) and uses the key regardless of mode. A key written by a pre-fix build (plain `std::fs::write`, umask → typically 0644) remains group/other-readable after upgrade; the upgrade does not heal it. The node secret key is the whole identity, so a co-tenant on a shared host could read it and impersonate the node. The commit explicitly chose warn-only ("We don't silently chmod a file the user may manage themselves"), making this a deliberate trade-off. **Correction to the reporter's framing:** the warning is *not* silent for the most sensitive key — `koh serve` always initializes a stderr tracing subscriber (`server/cli.rs:136-142`), so the server-key warning prints on every start; only the *client* key warning is suppressed when `$KOH_LOG` is unset. Local-only, conditional on an upgrade-in-place from a pre-fix build.

**Remediation:** When the existing key is owned by the current user and group/other-readable, proactively chmod it to 0600 on load; at minimum surface the warning to stderr unconditionally and document in the README that upgrading does not re-permission an existing key.

---

### KOH-17 — Supply chain: unmaintained `atomic-polyfill` (RUSTSEC-2023-0089) via postcard default features

- **Severity:** Info (consensus: info / info / info; one lens marked *not-a-bug* on reachability) · **Category:** Supply-chain
- **Location:** `Cargo.toml:30`

**Evidence:**
```toml
postcard = { version = "=1.1.3", features = ["use-std"] }
# atomic-polyfill v1.0.3 <- heapless 0.7.17 "atomic-polyfill" feature <- "cas"
#   <- postcard "heapless-cas" <- postcard "default" <- koh v0.3.1
```

`cargo audit` flags `atomic-polyfill 1.0.3` as unmaintained (an *unmaintained* advisory, not a CVE). It reaches koh directly because the postcard dep lacks `default-features = false`, so postcard's default `heapless-cas` feature pulls it. **Important caveat the panel surfaced:** `heapless 0.7.17` gates `atomic-polyfill` as a *target-conditional* dependency for embedded/no-native-CAS triples (AVR, riscv32i*, thumbv6m, xtensa) only. On koh's actual hosted-OS targets it is **not compiled into the binary** and not on the runtime deserialization path — it appears only in the all-targets lock graph that `cargo audit` scans. So there is no current runtime exposure; this is build-graph hygiene.

**Remediation:** Add `default-features = false` to the postcard dep and re-add only the needed features (`use-std`/`alloc`); verify with `cargo tree -i atomic-polyfill --target all` that the koh-direct edge disappears (the iroh-relay edge remains until iroh updates). Optionally relax the `=1.1.3` pin so future heapless/atomic-polyfill-free releases can be adopted.

---

### KOH-18 — Supply chain: unmaintained `paste` (RUSTSEC-2024-0436) via iroh's netlink stack

- **Severity:** Info (consensus 3/3) · **Category:** Supply-chain
- **Location:** `Cargo.lock` (`paste 1.0.15`)

**Evidence:**
```
paste v1.0.15 (proc-macro)
└── netlink-packet-core v0.8.1 <- netdev/netwatch <- iroh v1.0.0 <- koh v0.3.1
```

`paste 1.0.15` is flagged unmaintained (archived). It is a **compile-time proc-macro** (code-generation only, never linked into the runtime binary) pulled exclusively through iroh's Linux netlink deps. No runtime attack surface; koh cannot remove it without iroh updating `netlink-packet-*`.

**Remediation:** No direct action required. Track upstream iroh updates that migrate off `paste`. Optionally add `ignore = ["RUSTSEC-2024-0436"]` to `.cargo/audit.toml` for a clean CI exit, documenting the build-time-only rationale.

---

### KOH-19 — Supply chain: pre-release crypto (`ed25519-dalek 3.0.0-rc.0` / `curve25519-dalek 5.0.0-rc.0`)

- **Severity:** Info (consensus 3/3) · **Category:** Supply-chain
- **Location:** `Cargo.lock` (transitive via iroh `=1.0.0`)

**Evidence:**
```
ed25519-dalek 3.0.0-rc.0 / curve25519-dalek 5.0.0-rc.0  <- iroh 1.0.0 / iroh-base 1.0.0 <- koh
```

koh's NodeId endpoint authentication ultimately rests on release-candidate dalek crates. No RUSTSEC advisory targets these rc versions and `cargo audit` is clean. The forward concern is that pre-stable crypto can receive breaking/security changes before the final 3.0.0/5.0.0, and the exact `iroh = "=1.0.0"` pin freezes koh on whatever rc iroh locked. No concrete attack today.

**Remediation:** Track iroh releases; move to an iroh version depending on the stable dalek releases once available, and loosen the `=1.0.0` iroh pin to a compatible range when the API has settled so dalek-chain patches flow via `cargo update`.

---

## 4. Prior-fix re-verification (0.3.1)

All seven 0.3.1 fixes were re-read against current code and traced for bypasses. None regressed; two have non-security completeness gaps already captured above.

| Prior ID | Subject | Status | Notes |
|----------|---------|--------|-------|
| **H-1 / M-2** | Resize OOM / panic clamp (`clamp_dims` [2,1000]) | **Solid** | Applied on every vt100 allocation path — server emu (`terminal/server.rs:160-163`), server resize handler (`server/mod.rs:154-157`), client `apply` (`terminal/mod.rs:292-296`). No `rows*cols` overflow (≤1e6 fits u32). 6/6 clamp tests pass. *Bounds dimensions, not the count of resizes — see KOH-05.* |
| **M-1** | Key file 0600 (`create_new`+`mode`+atomic rename) | **Solid for new keys; incomplete for upgrade-in-place** | Correct, no write-then-chmod TOCTOU. But an existing pre-fix key (umask 0644) is warn-only, never re-tightened — see **KOH-16 (info)**. |
| **L-1** | OSC-52 clipboard default-off | **Solid** | Gated by local `--clipboard`/`KOH_CLIPBOARD` only (not peer-flippable); strict-base64 + size validation rejects control-char/OSC-break injection; gate survives `invalidate()`. |
| **L-2** | Client-side caps (title/icon/clipboard) | **Solid** | Title/icon capped to `MAX_TITLE_LEN`, clipboard to 16 KiB via `capped_chars`/`capped_bytes` in `apply`, correct UTF-8 boundaries; `sanitize_osc` strips control chars before emit. Not order-bypassable. |
| **L-3** | Connection + session caps | **Solid** | `try_acquire_owned` + `incoming.refuse()` pre-handshake; permit held for the whole task (no leak); session cap in `attach`, reattach keyed by iroh-authenticated `EndpointId` (no cap-bypass, no cross-peer hijack). *Slowloris on permit-hold time is a separate, lesser issue — KOH-08.* |
| **L-4** | Env scrub of `KOH_PASSPHRASE` from child shell | **Solid for the secret; list incomplete** | `KOH_PASSPHRASE` scrubbed on the single spawn path (with test). `KOH_SERVER_NETWORK_TMOUT` (non-secret) omitted — see **KOH-15 (info)**. |

---

## 5. Hardening recommendations (defense-in-depth)

1. **Fuzz the postcard/reassembler path.** `cargo fuzz` the full inbound chain (`Fragment::decode` → `FragmentAssembly::add` → `Instruction::decode` → `postcard::from_bytes` → `apply`) with arbitrary attacker bytes. This is the single most attacker-exposed surface and the home of KOH-01/02/04/05/07.
2. **Per-direction size budgets.** Client→server keystroke input never needs 16 MiB; cap it at 64–256 KiB and reject (close) over-cap diffs. Give `received_states` (and `sent_states`) a byte budget in addition to the 1024 count cap. This is the common remediation for KOH-01, KOH-02, and KOH-07.
3. **Coalesce resizes and bound per-frame work.** Apply only the final resize per drained diff; cap events processed per `recv`; do not hold the session `Mutex` across the per-event loop (KOH-05/09).
4. **Char-safe string handling everywhere.** Replace `String::truncate` with char-boundary-safe truncation and add a lint/test, since `string_slice`/`panic` lints do not catch method-based panics (KOH-04). Audit for other `truncate`/`split_at`/byte-index call sites on peer-influenced strings.
5. **Handshake timeouts and pending-handshake caps.** Lower the 10 s handshake timeout to 2–3 s; add a global cap on un-authenticated in-flight handshakes distinct from the connection cap (KOH-08).
6. **Bind the passphrase challenge to identity / use a PAKE.** Mix the server NodeId (and ideally the QUIC exporter) into the KDF/response so a transcript is useless cross-server; prefer an augmented PAKE to eliminate offline cracking entirely (KOH-03). Until then, document the high-entropy passphrase requirement. Argon2id params (64 MiB / t=3 / p=1) are reasonable for an interactive factor — keep them, and reconsider only if shifting to a non-PAKE design.
7. **Fail-closed client auth.** Enforce `PASS_REQUIRED` when a passphrase is configured and reject unknown handshake tags (KOH-13).
8. **State-dir and key hygiene.** Verify ownership + mode of the (possibly pre-existing) state dir; refuse world-writable shared fallbacks; create `$KOH_LOG` 0600; prefix-scrub `KOH_*`; type secret CLI fields as `SecretString` and zeroize the source string (KOH-06, KOH-12, KOH-14, KOH-15, KOH-16).
9. **PTY teardown robustness.** Give `Pty` a `Drop` that kills (with SIGKILL escalation) and reaps both pump threads; log discarded `kill()` errors (KOH-10).
10. **Supply-chain agility.** Drop postcard default features, relax exact pins where safe, and track iroh for the move off rc-dalek and unmaintained transitive crates (KOH-17/18/19).

---

## 6. What was checked and found clean

- **DEFLATE decompression:** `miniz_oxide 0.8.9 decompress_to_vec_with_limit` grows incrementally to at most `MAX_DECOMPRESSED` and errors on overflow — no unbounded allocation. (The 16 MiB limit being *too large for input* is KOH-02, a tuning issue, not an unbounded-alloc bug.)
- **Fragmenter/reassembler integrity:** `parts` is a `BTreeMap` (a lone high-index fragment is one entry, not a 32K pre-alloc); the `total > MAX_FRAGMENT_INDEX+1` check precedes the `as u16` cast (no truncation/OOB); `Fragment::decode` uses `split_first_chunk` (no indexing/unwrap, cannot panic); completion requires the final marker + exactly indices `0..=final`.
- **postcard targets:** fixed-shape structs only; no peer-supplied count drives a `with_capacity` (the sole `with_capacity(33)` is constant).
- **Sequence/ack/throwaway arithmetic:** shutdown `new_num` uses `saturating_add`; throwaway-GC-drops-base panic already fixed (base cloned before GC, with regression test); fragmenter id uses `wrapping_add`; RTT estimator guards `is_finite()` and clamps before casts.
- **Constant-time compare + nonce:** response compared with `constant_time_eq_32` over `[u8;32]` (no early length check, no `==` on secrets); fresh 32-byte OsRng nonce per handshake (replay-safe within the challenge).
- **Reattach / session hijack:** sessions keyed by iroh-authenticated `EndpointId`; a peer can only reattach to its own session; no cross-peer takeover.
- **KDF DoS:** PSK derived before any network write and cached by `BLAKE3(passphrase)`; a mid-handshake hang-up cannot force repeated Argon2; 10 s timeout + per-peer `FailureLimiter` (5/60 s) bound online guessing.
- **Rate limiter:** token math sound; `saturating_add`; GC bounds the keyspace under `--allow-any`; check runs **after** allowlist (no keyspace pollution by unauthorized peers) and **before** the Argon2 KDF (no KDF-grind by a leaked-but-allowlisted key).
- **Terminal render / predictor:** OSC-52 default-off and re-validated; title/icon `sanitize_osc`'d (strips C0 + C1) and capped; glyphs come from vt100-parsed `contents()`; predictor width/cursor math uses saturating ops bounded by the clamped screen size; UTF-8 reassembly bounded to ≤4 bytes; backspace left-shift overflow already fixed and tested. (The one render panic is KOH-04.)
- **PTY spawn:** shell is operator-chosen (`--shell`/`$SHELL`); no peer-controlled data reaches the child program/argv — no command/argument injection.
- **Key persistence (desktop/ProjectDirs path):** `create_new(true).mode(0o600)` on a same-dir temp + fsync + atomic rename; symlink-on-destination safe; single create path (no rewrite). (Shared-fallback and pre-existing-dir gaps are KOH-06/KOH-12.)
- **Crypto/TLS backend:** `ring 0.17.14`, `rustls 0.23.40`, `rustls-webpki 0.103.13`, `aes-gcm 0.10.3`, `blake3 1.8.5` — current, no advisories, no `aws-lc` in the lock. `cargo audit`: **0 vulnerabilities**, only the two unmaintained-crate warnings (KOH-17/18).

---

*End of report.*
