# Changelog

All notable changes to koh are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and koh aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) for the **binary's CLI, the on-disk
key format, and the wire protocol (its ALPN)**. The `koh` library is internal: it exists so the
binary, its tests and the fuzz targets share code, and any release may change it.

> **A note on versions.** [crates.io](https://crates.io/crates/koh) is the source of truth for what
> was actually released. Two git-tag-only gaps exist from koh's early, fast-moving security-review
> period: **v0.4.0–v0.4.3** were tagged during a rapid follow-up series but superseded by **0.4.4**
> before publishing, and **v0.6.0** (encrypted-at-rest keys, vt100 containment, per-node-id authz) was
> developed and folded into **0.7.0** rather than released on its own. Published versions:
> 0.1.0–0.3.2, 0.4.4, 0.5.0, 0.7.0–0.12.0 and 0.13.0 (0.12.1 is tag-only).

## [Unreleased]

### Added
- **`koh exec SERVER -- COMMAND...`** runs a command on the server with no terminal, as ssh does:
  the words joined with spaces and run by the server user's shell (`$SHELL -c`) in their home,
  local stdin streamed to it, its stdout and stderr back apart, and koh exiting with its status
  (128+N when signal N killed it; 255 on koh's own errors). It works with no terminal at all, and
  a lost connection or a signal hangs the command up (SIGHUP to its process group, SIGKILL after
  a second).
- **`koh cp SRC... SERVER:PATH`** and **`koh cp SERVER:PATH... DST`** copy files and whole
  directories both ways, done in process by the server: modes, modification times, odd names and
  symlinks kept, streamed in bounded memory, and nothing landing until all of it has (each item
  staged beside its target under a hidden name, then renamed into place); a directory is never
  merged into one already there. `~`, `~/x` and relative remote paths are in the server user's
  home. scp's `-r` and `-p` are taken, as what it always does.
- **Several sessions per client.** `koh connect SERVER --new` starts another; `koh connect SERVER
  --session N` attaches to one by number; `koh connect SERVER` attaches to the one attached last.
  `koh sessions SERVER` lists them, one a line: number, attached or detached (and for how long),
  age, size, whether the program runs or exited, and title. `--max-sessions` bounds them all
  together, and the TTL applies to each.
- **A saved server remembers how to dial it.** `koh servers add NAME ID --direct IP:PORT` (or
  `--relay-url URL`) saves it in `servers` as `name id direct=IP:PORT` (or `relay=URL`), and
  `connect`, `exec`, `cp`, `sessions` and the menu dial that name so unless given `--direct` or
  `--relay-url` themselves. `koh servers` and the menu show it.

### Changed
- **`koh connect` with no terminal says what to use instead**: that it needs one, and that `koh
  exec SERVER -- COMMAND` runs a command without one and `koh cp` copies files, rather than
  `acquiring the terminal: No such device or address`. It says so before dialing.
- **The wire protocol is now `koh/7`**. A connection opens with a request on the client's first
  stream saying what it is for (a shell by pick, a listing, a command or a copy), and the server
  attaches or starts nothing before it; a client that makes none in 10 s is closed. A shell's
  admission says the session it reached, and a reconnect goes back to that session by number,
  never to another: one gone meanwhile (expired, or the server restarted) ends the client with
  "no such session", where it used to land in a new shell. A paste goes whole in one message (up to 1 MiB), and the
  raw-bytes `Input` message is gone; history requests carry ids and every one is answered; a
  refusal is a close code; screen modes say whether the alternate screen is shown; the admission
  stream is gone: the server attaches the client's session before it sends anything, and the
  first frame admits it; the client sends input and control messages on two streams, so a resize,
  acknowledgement or history request never waits behind input a program has not read; rows carry
  a prompt flag beside the wrap flag, and screens the shell's commands (OSC 133).
- The remote shell's marks (OSC 133) reach the user's terminal: prompts' rows, and each command's
  start and its end with its status, told once (`fux`'s `· done` and `last-output` work through
  koh). The painter moves every row that moved, so what a terminal keeps of a row moves with it.
- Painting is a diff of the whole terminal with autowrap off: a terminal larger or smaller than the
  screen shows the screen clipped and nothing else, the status line repaints only when it changes,
  switching mouse modes turns the old one off, and the window title is restored on exit and
  suspend.
- Prediction runs only on the primary screen with the PTY's modes known, on cells that keep their
  style; a grapheme typed in pieces is one glyph; Backspace and Left stop where the line began,
  which comes only from the real cursor; focus changes leave predictions alone.
- The terminal's answers to the start-up questions are read by the session's own input decoder.
- `Ctrl-^ Ctrl-^` or `Ctrl-^ ^` sends one Ctrl-^.
- Removing a client with `koh clients rm` ends its session as well as its connection.
- At most 2 handshakes are pending per address (an IPv6 /48 is one), its oldest given up for a new
  one, which is never refused, and they hold no connection permit; when giving one up would cost
  a handshake under way, an address not yet validated answers a QUIC retry first, so spoofed
  addresses take no room. The client holds at most about 40 MiB of compressed server streams and
  inflates history replies one at a time, no further than a legal reply; the server keeps a
  clipboard only as base64 within its cap; a key, list or `$KOH_LOG` file with another hard link
  is refused.
- `--max-connections` and `--max-sessions` are at least 1.
- A server started under `nohup` (SIGHUP ignored) survives the terminal's close; its sessions'
  programs still get SIGHUP's default. Turned-away peers are logged at most once every 10 s.
- Frames land on slow links: a frame is given up only once the client has acknowledged nothing for
  a retry interval, the link's rate is what deliveries prove, and the client keeps the base the
  server diffs against however many frames pass. Output that is no echo of typing waits 10 ms for
  the PTY's modes to be read again, so a prompt printed just before echo goes off (PAM's order) is
  never told with echo on.
- A title or icon reaches the terminal only through `OscText`, stripped of every C0 and C1
  control.
- The tests start every program with a home of their own, no history file and no `ENV` script:
  a test run never writes to the developer's shell history.
- Every queue in koh has a bound, and `clippy.toml` bans unbounded ones; the wire's sequences are
  refused as they are decoded once past their bound.
- `koh serve` reads the saved clients every 1.5 s: `koh clients rm` takes effect within 2 s. A read
  that drops a client counts only once the next, 0.5 s later, agrees.
- A session's program is hung up and given a second to exit (a shell saves its history) before it
  is killed.
- More keys in one read than anyone types (a paste into a terminal without bracketed paste, a
  program writing to the client's terminal) are sent but not predicted one by one, which cost a
  screenful of work each.
- Updated `fux-vt` 0.3.4 → 0.7.0 and `fuxix` 0.1.7 → 0.5.0, including the test harnesses. The
  minimum Rust version is unchanged.
  - **`--scrollback` is now `--scrollback-bytes`**, the history each session keeps in bytes, 8 MiB
    by default (about 20,000 lines of 50 characters), at most 1 GiB, as fux-vt bounds it.
  - A session's program is started on its PTY as a session leader by fuxix between `fork` and
    `exec`: the hidden `koh __launch` is gone.
  - The server's terminal follows the standards more closely (fux's "refined" audit): among
    others, primary device attributes now name selective erase, horizontal scrolling and
    rectangular editing, which it carries out, and `CSI 3 J` clears the scrollback.
  - Kitty's F13 to F35 reach the program; a mouse press on the wire always names its button.
  - The client paints each style in one SGR, as fux-vt writes it, the underline colour in its
    colon form, which a terminal that does not know it skips whole.
- PTY input is bounded by bytes, including in-flight writes; backpressure retains pending
  buffers and terminal replies stay behind earlier input. Reply overflow is bounded and logged.
- Hyperlink snapshots allocate strings only for distinct links in a row. Terminal dimensions
  are normalized once for the hosted emulator and PTY, and history traversal uses retained rows.
- CI checks the standalone benchmark, test kit and hostile-peer harnesses. The tests start
  programs, spawn tasks and make scratch directories (under `target/`, never the system temp dir)
  only through `koh-testkit`; the comparison oracle is gone.

### Fixed
- A line typed in one go past 1 KiB (as an agent's terminal types it) no longer waits for the next
  key: the client read stdin through a buffer `poll` cannot see, so the line's end, its Enter
  among it, sat there until something more was typed.
- A sixel picture can no longer make the server allocate: fux-vt 0.8 decodes pictures only for a
  host that asks, and koh does not, so a crafted header of a few bytes no longer costs ~34 MiB.
- A frame drawn in synchronized output ends where fux-vt says it does (an ESU, XTRESTORE, DECSTR
  or RIS), not only at an ESU koh's own scanner found; the scanner is gone.
- A reconnect that landed as its exited session ended could wait for ever: the attach the
  session had queued was kept alive until the next one. Sessions are reaped as they end.
- An editor saving the `clients` file (missing or empty for a moment) could disconnect every saved
  client and end their sessions.
- Backspace or Left typed fast at a fresh line could appear to erase the prompt; a key could be
  shown and then never sent when the outgoing queue was full; a terminal's answer cut by a drop
  was reported as typing not sent.
- A palette change scanned the whole history at every snapshot; a history reply served while a
  frame was held could keep a colour the program had already restored.
- `koh key info` and the menu said "none yet" for a key that exists but cannot be loaded.
- A kitty-protocol key whose code is no Unicode scalar (a terminal's garbage) no longer makes a
  message the client cannot send, losing the keys typed with it: the code is dropped.
- A typo in the saved `clients` file disconnected every saved client and refused their redials;
  the last list read well is now kept.
- A server at capacity, or whose program could not start, left the client redialing forever with
  no reason shown; a capacity close could also end a client for good. Both are redialed now, and
  the banner says why; only "not authorized" ends the client.
- A reconnect after the program exited got a fresh shell and never saw the exit; the final screen
  could miss the program's last output; the exit status could be lost when the connection closed.
- A double SIGHUP on a terminal's close skipped the drain; a forced exit returned 0.
- Log lines could interleave on stderr, and a server's close reason could add lines to it.
- A lost or late history reply stopped scrollback filling until a reconnect; a search through more
  history than the cache holds could loop forever.
- Anyone who could reach the UDP port could block new connections with stalled handshakes.
- A wide glyph in the bottom-right cell scrolled the user's terminal every frame; a change to only
  a row's hyperlinks was never painted.
- A slow answer to the start-up questions reached the remote program as keys; a server granting no
  stream could make the client impossible to quit; a suspend could take the terminal back before
  the client was stopped.
- tmux's or screen's `Ctrl-A` prefix was predicted as readline's; predicted text lost its colours;
  the password hold missed prompts at the bottom of the screen.
- Tests wrote under the system temp dir, and could lift the bans on starting programs.
- A hostile server's close reason reached the user's terminal raw when the first connection was
  refused (writing the clipboard despite `--no-clipboard`); stderr and every log line now escape
  control characters, and log lines are uncoloured.
- A hostile server could make the client hold gigabytes of history through link text and
  unrequested replies, or build a dictionary of one row a thousand times per frame.
- A program that closed its terminal and kept running left its client waiting forever; a
  program that ignores SIGHUP outlived `koh serve`. `koh serve` handles SIGHUP, and a second
  signal stops it waiting.
- `koh clients rm` left the removed client's live connection open; a refused redial retried
  forever.
- Another local user could hang koh by locking its key directory; the menu's replace could lose
  the saved name; `koh serve --key-file` needed `$HOME`; stalled handshakes could hold every
  connection slot.
- A test typed a wrong password into the real `sudo` and `passwd`.
- A program that stopped reading its input, under a large paste, froze its connection's frames,
  and a client that left meanwhile kept its session attached and its connection slot held.
- Frames a client never took made the server's list of frames in flight grow for good.
- More than 1 MiB of hyperlinks on a screen left the client and server compressing frames against
  different dictionaries, so frames failed to decode.
- Quitting a program on the alternate screen, or a reattach at the same window size, renamed every
  history row, so the client fetched its history again.
- A paste cut off by a reconnect left the program's bracketed paste open.
- Resuming from `Ctrl-^ Ctrl-Z` replayed the server's last clipboard and bell, and kept the window
  size from before the suspend; a client's first frame forwarded the session's old clipboard and
  bells.
- `Esc` and then a key was predicted as `Alt` and the key; arrows were predicted under kernel
  echo, which echoes them as `^[[D`.
- A session's program that could not start was reported as the server being at capacity, and
  starting one held up every other peer's attach.
- Keys typed in the same read after leaving the scrollback view, or after `Ctrl-^ Ctrl-Z`, were
  lost; a resize could wait behind a stream of frames, and a flood of input starved the frames.
- Forced PTY shutdown and ordinary drops reap children. Shutdown also stops pump threads when
  a program leaves input unread or the output receiver is full.
- Unwritable CLI output returns an error instead of panicking; diagnostic output is best effort.
- Scrollback search keeps UTF-8 characters whole at its limit, handles decoded keys directly,
  and keeps the end of a long query visible.
- An incomplete paste begun before an outage cannot finish into a reconnected shell. Fresh
  keys after its end marker remain usable.

## [0.13.0] — 2026-10-08

koh is a remote shell again, not a transport for other programs: everything that existed only
for embedders or for fux is gone. **The wire protocol is new**: koh no longer runs mosh's State
Synchronization Protocol over QUIC datagrams, but its own stream protocol, ALPN `koh/3`. A 0.12
client and a 0.13 server (or the reverse) refuse each other at the TLS handshake with a clear
error.

### Added
- **Hyperlinks.** A program's OSC 8 links (`ls --hyperlink`, delta, compilers, claude) now reach
  your terminal as links, on by default; `koh connect --no-hyperlinks` paints them as plain text.
  Each is checked before it is painted, and a server's links are bounded on the wire (64 a row,
  fux-vt's URI and id limits, 1 MiB a frame). The koh/3 encoding gains each row's links and each
  cell's link.
- **Underline styles.** A curly, double, dotted or dashed underline (neovim's diagnostics, for
  one) now reaches your terminal as it was set, if your terminal draws them: `koh connect` asks it
  once at start-up (XTGETTCAP for `Smulx`, and DECRQSS of a curly pen), and paints a plain
  underline otherwise. The server answers DECRQSS, so neovim knows it may use them. The koh/3
  encoding gains the underline's style; a plain underline encodes as before.
- `koh serve --port <PORT>` binds that UDP port (IPv4, and IPv6 where the host has it) instead of
  an ephemeral one, in every profile, and the banner shows the port. A client dialing
  `--direct <ip:port>` redials the address it first dialed, so with a fixed port it finds a
  restarted server and reattaches, to a fresh session. A port already in use is a clear error.

### Changed
- **Clipboard writes are on by default.** A remote program's OSC 52 copy now sets your clipboard
  without `--clipboard`, which is gone; `koh connect --no-clipboard` turns it off. A hostile server
  can therefore replace what you copied, so pass `--no-clipboard` to a server you do not trust.
  Only base64 of at most 16 KiB is forwarded, and the clipboard is never read.
- The server's terminal re-wraps the screen and its history on a resize (reflow), answers the size
  query and in-band resize (mode 2048), keeps a program's colours (OSC 4, 10, 11) and draws them as
  RGB without changing your terminal's palette, and answers device attributes and XTVERSION as
  koh. A frame a program draws with synchronized output (DEC 2026) is no longer sent half drawn.
- Updated `fux-vt` 0.2.0 → 0.3.4. Bold and dim can now be on together (`SGR 1;2`), as in xterm,
  where before the later one replaced the earlier; CBT (`CSI Z`) and CHT (`CSI I`) now move between
  tab stops, as mosh's emulator does; 0.3.4 brings fux's second audit's fixes (cursor moves stop at
  the scroll margins, a resize without reflow keeps a pending wrap). The wire is unchanged.
- Updated `iroh` 1.2.0 → 1.3.0, `fuxix` 0.1.2 → 0.1.7 and `tokio` 1.53.1 → 1.53.2.
- **`koh serve` starts each session's program through `koh __launch`**, a hidden subcommand of
  its own binary that makes the program a session leader with the PTY as its controlling
  terminal, then becomes it. The program sees what it did before: argv verbatim, `TERM`, no
  `KOH_*` variables, default signal handling, and no descriptor beyond stdio. `portable-pty` and
  `nix` are no longer dependencies; fux's `fuxix` makes the system calls (Linux, Android and
  macOS, as before).
- **`RUST_LOG` takes `target=level` directives and bare levels only**, such as
  `RUST_LOG=koh::server=debug,iroh=warn` or `RUST_LOG=debug`. Span, field and regex filters
  are no longer understood; a `RUST_LOG` koh cannot read gives the default filter, as before. koh
  no longer depends on `rand`, `data-encoding` or tracing-subscriber's `env-filter` (8 fewer
  crates in a build).
- **Keys typed while `koh connect` starts are kept**, as with ssh and mosh: entering raw mode no
  longer discards pending input, so a command typed before the connection is up reaches the remote
  shell. The same holds when resuming after `Ctrl-^ Ctrl-Z`.
- **Breaking: identity keys are no longer encrypted at rest.** A key file is the key's 32 raw
  bytes, protected by its permissions (0600) like an SSH host key: anyone who can read it is that
  identity. koh never prompts for a passphrase; `koh key passwd`, `$KOH_KEY_PASSPHRASE` and
  `$KOH_KEY_NEW_PASSPHRASE` are gone. Existing key files are rejected. `argon2`, `aes-gcm` (as a direct dependency), `rpassword`, `secrecy`, `signal-hook`
  and `zeroize` are no longer dependencies.
- **Terminal emulation is `fux-vt`, and the client runs no parser.** The server's emulator is
  `fux_vt::Parser`, a bounded, panic-free emulator; `vt100` is no longer a dependency. The screen
  diff is now structured: the rows that only moved (a scroll, in or out of a scroll region, an
  inserted or deleted line) as row shifts, every other changed row whole, as run-length-encoded
  cells, plus the cursor and modes. It replaces vt100's escape-sequence patch, which the client used to replay through its
  own vt100 parser. The client validates every row and cell, a cell's text included (it may hold
  no control character, so it cannot carry an escape sequence to the user's terminal), and drops a
  malformed frame whole, so server bytes never reach a terminal parser on the client. The `catch_unwind` containment and the
  64 KiB control-string pre-filter are gone: fux-vt cannot panic, retains no DCS/APC/PM/SOS payload
  and caps OSC strings at 64 KiB.
- **Breaking: the koh/3 stream protocol replaces SSP over datagrams.** Keystrokes travel on one
  reliable QUIC stream; each screen update is a frame on its own stream, diffed against a frame the
  client acknowledged, and the server resets a frame's stream once a newer one supersedes it. QUIC
  does the loss recovery, retransmission and RTT estimation SSP did by hand, and each end keeps a
  fixed window of 16 recent screens instead of budgeting received states. An unacknowledged frame
  is resent after a round trip plus a frame interval, so heavy loss does not wait out QUIC's
  backed-off probe timeout, and the link recovers from an outage within a round trip. A program that stops
  reading its input now pushes back on the client: typing beyond 1 MiB queued is dropped with an
  "input paused" status line instead of piling up, and `Ctrl-^ .` still quits at once.
- Emulation follows fux-vt's documented sequence contract, which is vt100 0.16's plus two
  corrections: DECAWM (`CSI ? 7 l`, autowrap off) now works, and insert/delete-line outside the
  scroll region is ignored. Terminal replies: primary device attributes now answer as a VT100
  with advanced video (`CSI ? 1 ; 2 c`) instead of claiming VT220, and DECRQM reports the real
  state of every mode the emulator tracks (it used to know only bracketed paste).
- `--scrollback` is limited to 65,000 lines (was 1,000,000): fux-vt caps each buffer at 64 Mi
  cells, and the history must leave room for a 1000×1000 screen. Scrollback stays server-side.
- The minimum Rust version is 1.95 (was 1.91), from fux-vt.
- **Breaking (hidden API):** the `#[doc(hidden)]` test harnesses `koh::ssp::testkit` and
  `koh::sim` are now behind the new `test-support` feature. They panic by design and no longer
  ship in normal builds.
- The client's `Ctrl-^` escape keys are always on (only embedders could turn them off), and
  `run_client` takes the bell hook directly.
- Production code is now panic-free under `forbid`, not only `deny`. The SSP transport keeps its
  sent and received state lists in a structurally non-empty type, and the `koh` binary builds its
  Tokio runtime explicitly.
- `koh serve` takes far less CPU to read a burst of small client messages, such as a flood of
  resizes: it no longer moves the rest of a read after each message it decodes.
- Both ends need much less memory and CPU for the recent screens they keep: screens share the rows
  they have in common instead of each holding a full copy (about 32 MB at 1000×1000), so a new
  screen costs only the rows that changed, including rows that scrolled.
- Screen updates take less CPU at both ends: a frame's cell text is stored inline, so building and
  decoding a frame no longer allocates once per run of cells.
- `koh connect` writes far less to your terminal: a frame paints only the cells that changed, not
  the whole screen, so a keystroke's echo is a few bytes and the link-down banner no longer repaints
  every cell every 50 ms. What the terminal shows is unchanged; the whole screen is still repainted
  on the first frame, after a resize or `Ctrl-^ Ctrl-Z`, and when the status line appears or goes.
- Output that scrolls sends far less: rows that only moved are moved by the client, not sent again,
  so a line scrolling in costs that line, not the screen: `seq` at one line per frame sends under a
  third of the bytes it did at 80×24 and a sixth at 200×50, full-width lines at 200×50 a
  fourteenth. The server's diff and the client's apply take a fraction of the CPU they did, and its
  snapshots no longer compare the rows the program left alone (fux-vt versions each row): full-width
  lines scrolling a 1000×1000 screen cost the server 0.4 ms a frame instead of 69 ms.
  `koh connect` scrolls your terminal too, in a scroll region, instead of repainting the rows that
  moved, where that writes less: a third of the terminal output for `seq` at 80×24 and a scroll
  region at 200×50, a thirtieth for full-width lines at 200×50, with the client's paint taking about
  a thirtieth of the CPU there. What the terminal shows is unchanged.
- Typed CJK and emoji are predicted as the server then shows them: a predicted wide glyph covers the
  cell to its right instead of being cut by it, a typed character before a wide glyph moves it
  whole, and a prediction over half of a wide glyph blanks the other half, as the terminal does.
  Frames with predicted wide glyphs are no longer repainted whole, nor is the frame after them.
- Updated `iroh` 1.0.0 → 1.2.0 (with its QUIC backend `noq` 1.0.0 → 1.3.0), which clears Cargo's
  warning that iroh 1.0.0 contains code a future Rust will reject. Also `serde` 1.0.228 → 1.0.229
  and `miniz_oxide` 0.8 → 0.9; every other dependency's minimum version is now the release koh is
  tested against (for example `tokio` 1.53.1, `fux-vt` 0.1.3).
- Updated `fux-vt` 0.1.5 → 0.2.0. Each grapheme cluster (an emoji with its joiners or modifiers, a
  flag, a letter with its marks) is kept whole in one cell and shown as one glyph, where it was
  split across cells before, and a variation selector that makes a character wide now does. Cells
  also carry the underline colour (SGR 58), hidden, strikeout and slow or rapid blink, which
  `koh connect` draws. The koh/3 cell encoding changes with it: a cell's text may be up to 128
  bytes, its style is two bytes, and it carries an underline colour.
- Updated `fux-vt` 0.1.3 → 0.1.5, which changes a row's version only when an edit changes the row.
  A program that redraws lines it left as they were (each line's text, then erase to its end) no
  longer makes `koh serve` compare the whole screen: such a redraw costs the server 7 µs a frame
  instead of 30 µs at 200×50, and 0.1 ms instead of 2.4 ms at 1000×1000.
- Frames that change few rows cost far less at both ends on large screens: a screen's list of rows
  is shared until a row is replaced, a snapshot matches rows by their place before searching, and
  the memory the recent frames hold is counted from the rows that differ. At 1000×1000 a frame in
  which nothing changed takes the server 8 µs to snapshot instead of 82 µs, the client 6 µs to take
  instead of 222 µs and 10 µs to paint instead of 84 µs; a keystroke's frame takes 21, 51 and 32 µs
  instead of 80, 204 and 99 µs.

### Security
- Updated `rustls` 0.23.40 → 0.23.45 (and `rustls-webpki` 0.103.13 → 0.103.15 with it) for
  RUSTSEC-2026-0285: rustls accepted TLS 1.3 handshake messages sent at the wrong encryption
  level. koh reaches rustls through iroh's DNS resolver (hickory).
- Replaced three yanked transitive crates with their patch releases: `chacha20` 0.10.0 → 0.10.2,
  `der` 0.8.0 → 0.8.2 and `spin` 0.10.0 → 0.10.1.

### Fixed
- A skin-tone modifier or combining mark a program placed in a cell of its own (vim and micro
  place 👍 and 🏽 with a cursor move between) is painted there, not joined to the glyph before it:
  the client moves the cursor before a glyph that would continue the cluster printed just before.
- **A server could make `koh connect` hold about half a gigabyte**, enough to get it killed on a
  phone. The client keeps the screens of its last 16 frames as bases for the next ones, each a full
  copy: a server on a 1000×1000 terminal (about 32 MB a screen), or a hostile one, sending full
  repaints made it hold 16 of them. Screens now share their unchanged rows, and the older frames
  hold at most one screen of that size beyond the current one; a frame whose base was dropped asks
  for a resync, as before. The wire protocol is unchanged.
- **One client could make `koh serve` hold over half a gigabyte**, enough for Android to kill it
  and every session in it. A client that never acknowledged a frame was resent the screen every
  round trip, and the server kept a full copy of it for each of the 16 frames it remembers: at the
  largest size a client may ask for (1000×1000, about 32 MB a screen) that was about 680 MB, from
  one resize. Frames now share the screen they show, and the unacknowledged ones hold at most one
  screen of that size beyond the newest; the wire protocol is unchanged.
- A session at a large size whose program wrote a lot at once could make `koh serve` briefly take
  gigabytes of memory: the server took a whole new snapshot of the screen for every 8 KiB the
  program wrote. It now takes one per burst of output (up to 64 reads).
- `koh serve` could take over ten seconds to exit after SIGTERM or Ctrl-C, when a client had just
  vanished without closing its connection while iroh was still trying paths to the client's other
  addresses (common on a phone, which has several). Closing the endpoint now waits at most two
  seconds for peers to see it, as `koh connect` already did.
- **A session whose program stopped reading its input could keep `koh serve` from ever exiting**
  on Linux and Android. Input is written to the terminal from a dedicated thread; once the
  terminal's input queue was full that write blocked, and the kernel never woke it — not even once
  the program was dead — so tearing the session down waited on it for good. A large paste into a
  program that reads nothing (`sleep`, a wedged shell) was enough. The thread now waits in `poll`
  and gives up what the program never read as soon as the session is torn down.
- **koh could not create a key on Android** (since 0.12.1): `koh serve`, `connect` and `id` failed
  with "Permission denied" whenever the key file did not exist yet. A new key was published with a
  hard link, which Android's SELinux policy denies to the shell and to apps. It is now renamed into
  place with the key's directory locked, which keeps two first runs racing to one identity.
- On macOS, starting a session could fail with "Unknown error: -6", stall for up to about half a
  second, or, rarely, hang for good, while PTYs were being allocated concurrently anywhere on the
  machine. These are two races in the macOS kernel's PTY driver; fuxix 0.1.2 works around both
  ([fux#64](https://github.com/gold-silver-copper/fux/pull/64), which also has a report for Apple),
  and koh no longer serializes PTY allocation itself.
- A short-lived hosted program could lose **all** of its output on macOS (about 3 in 1000 spawns
  under load): the PTY reader started only after the child was spawned, and when a child wrote and
  exited before anything read the master, the queued output was discarded. The reader now runs
  before the child is spawned.
- Concurrent PTY spawns in one process intermittently failed in `openpty` on macOS, whose libc
  `openpty` is not thread-safe. PTY allocation is now serialized.
- `koh connect` truncated the remote exit status to 8 bits, so a server reporting 256 (or any
  multiple of 256) made the client exit 0, reporting a failed session as a success. A status that
  does not fit in 8 bits now exits 255.

### Removed
- **The local-service gateway**: `koh gateway serve|connect`, the `koh::gateway` module and the
  `gateway` feature. It forwarded fux's attach socket, and fux no longer uses koh.
- **The embedding API**: `koh::embed` (`Connection`, `Server`, `NetworkProfile`),
  `Identity::transfer`/`receive`, `identity::transfer_pair`/`receive_pair` and `IdentityStore`.
  `koh connect`'s own dial-and-run path is now private to the client.
- **The generic session host and client state (0.11)**: `SessionHost`, `HostProvider`, `PtyHosts`,
  `SharedHost`, `Hosts`, `serve_with`, `ClientId`, `AttachKind::Joined`, `ClientState`,
  `run_client_with`, `IrohConnector::with_alpn`, `TERMINAL_ALPN`, the `*_alpns` endpoint binders
  and the `TerminaTerminal` alias. The server hosts a PTY per peer; the client renders a
  `TerminalScreen`; `ClientTerminal` is no longer generic.
- **Host-side hooks only fux read**: `Pty::process_id` (now private),
  `Pty::terminate_process_group`/`shutdown_process_group`, `ServerTerminal::progress` and the
  OSC 9;4 `Progress` parser, the unhandled-OSC ring (`take_unhandled_oscs`, `UNHANDLED_OSC_*`)
  and `ServerTerminal::with_scrollback_screen`.
- **The `shell` and `cli` features.** The library and the binary are one crate again, and the
  binary always builds: its command line uses clap's builder API, so no feature is needed to keep
  clap's derive out of the library. The `*Args` types are gone; build the `*Config` structs
  (`ServeConfig`, `ConnectConfig`, `IdConfig`, `KeyConfig`) instead. `cargo install koh` and every
  flag, help text and error message are unchanged.
- **The SSP transport and its test harnesses**: `koh::ssp` (`SyncState`, `Transport`, `testkit`),
  `koh::wire` (`Instruction`, the fragmenter and reassembler, `PROTOCOL_VERSION`), `koh::input`,
  `koh::sim`, the `chaos` example, the `test-support` feature and `MonoClock`. koh/3 replaces them.
- **The terminal backend features**: `backend-termina`, `backend-crossterm` and `backend-qwertty`,
  with `TerminaBackend`, `CrosstermBackend` and `QwerttyBackend`. The client drives the tty itself
  through `fuxix::terminal` (`client::backend::Tty`); its output is byte-for-byte unchanged.
  `termina`, `crossterm`, `qwertty` and `rustix` are no longer dependencies.

## [0.12.1] — 2026-09-04

### Fixed
- Concurrent first-time identity creation now atomically elects one persistent key, and every
  contender loads that key using the documented new-key passphrase in headless environments.

## [0.12.0] — 2026-09-03

### Added
- Public cancellation-aware terminal input and resize producers for embedded clients.
- Documented `Pty::process_id` inspection and reaped-safe process-group teardown for lifecycle
  coordination by generic hosts.

### Fixed
- Embedded client teardown now cancels producers blocked by full input or resize channels.
- Terminal parsing bounds OSC, DCS, SOS, PM, and APC control strings at 64 KiB, discarding an
  oversized string through its terminator before resuming normal input.

## [0.11.0] — 2026-09-03

### Changed
- **The server hosts any `SyncState` producer, not only a PTY** (KH-01). `session::Session`,
  `SessionHandle`, `SessionStore`, `attach_with`, `detach`, `reap`, `run_reaper`, `ServerSession`,
  `run_attached` (now also taking a `ClientId`) and `run_session_with` are generic over a
  `SessionHost`; `PtyHost` is the previous PTY + emulator code behind that trait. The echo-ack
  debounce moved out of `ServerTerminal` into the per-connection loop (KS-02): a host only
  implements `stamp_echo_ack`, and `ServerTerminal::snapshot` leaves `echo_ack` at 0 for the loop
  to stamp (`TerminalScreen::set_echo_ack`). `SessionHandle::changed` is a `ChangeSignal` (a `watch`
  version counter) rather than a `Notify`, so one pulse wakes every attached viewer (KS-03);
  `SessionHost::attach_notify` receives it. The K-16 unwind guard releases a connection's attach through
  its `HostProvider`, so a shared host is never pinned by a panicking connection task (KS-04). `serve` is
  unchanged in behaviour and is `serve_with(config, Hosts::new().with(TERMINAL_ALPN, PtyHosts))`
  underneath. `serve` installs its tracing subscriber with `try_init`, so an embedding binary that
  already owns one no longer panics.
- **The client renders any `ClientState`** (KC-01). `ClientSession<S>`, `run_client`,
  `ClientTerminal<S>::render(state, overlay, status)` (the window state now comes from
  `ClientState::window`), and the input-mode mirroring go through `client::InputModes` (byte-identical
  to vt100's sequences). `connect` is unchanged and is `connect_with(config, TERMINAL_ALPN, …)`.
- **`predict` reads screens through `predict::ScreenView`** instead of `&vt100::Screen` directly
  (implemented for `vt100::Screen`; still no `crate::` imports).
- `ssp::NEVER`, `ssp::testkit` and `Transport::current` are public (the latter two `#[doc(hidden)]`).

### Added
- **`SessionHost`, `HostProvider`, `PtyHosts`, `SharedHost`, `serve_with`, `cli::Hosts`,
  `ClientId`** — the server seam, including shared sessions (KS-01): every authorized peer attaches
  to one host with its own connection loop and `ClientId`; the reaper collects it only once every
  viewer has left.
- **`ClientState`, `ClientTerminal<S>`, `connect_with`, `run_client_with`, `InputModes`** — the
  client seam.
- **The synced state type is selected by ALPN** (KH-02): `transport_iroh::TERMINAL_ALPN`
  (`koh/iroh/1`, the existing ALPN) for `TerminalScreen`; `bind_endpoint*_alpns` bind several;
  `IrohConnector::with_alpn` dials one. A client dialing an ALPN the server does not bind fails the
  TLS handshake before any SSP bytes flow, with an error naming the ALPN.
- **`ServerTerminal::progress()` and `take_unhandled_oscs()`** (KO-01): OSC 9;4 progress reports
  and a bounded ring (16 × 256 bytes) of unhandled OSC payloads, host-side only.
- **`--on-bell <CMD>` / `ConnectConfig::bell_command` / `client::BellHook`** (KB-01): run a shell
  command when the remote bell rings; detached, `KOH_*`-scrubbed except `KOH_BELL_COUNT` and
  `KOH_TITLE`, at most one spawn per second. Bells from before the attach do not fire it; bells
  during a reconnect do (KB-02).
- Test infrastructure: `ssp::testkit::GridState`, `sim::run_generic_session`, three new
  integration targets (`e2e_generic_host`, `shared_session`, `bell_hook`), a `server_process`
  fuzz target, and a KS-01 proptest over shared-session refcounting.

### Unchanged
- Wire protocol, `PROTOCOL_VERSION` (3), the terminal ALPN, `TerminalScreen`/`ScreenDiff` on the
  wire, the `koh-key-v1` key format, and every CLI flag and default. `cargo install koh` builds
  the same binary behaviour, plus `--on-bell`.

## [0.10.0] — 2026-09-03

### Changed
- **License: MIT** (was GPL-3.0-or-later). Releases before 0.10.0 remain available under their
  original license. Motivation: koh is now consumed as a library by an MIT-licensed downstream
  (`fux`), and a GPL library would force that crate's license.
- **`cli` Cargo feature (on by default) now owns clap.** The `koh` binary, the `*Args` clap adapter
  structs, the `chaos` example and the pty-binary e2e test are gated on it. `cargo install koh` is
  unchanged; library users build with `default-features = false` plus one `backend-*` feature and
  get a clap-free tree.
- **Plain config types are the stable library surface.** `serve`, `connect`, `run_id` and
  `keycmd::run` take `impl Into<…Config>`: `ServeConfig`, `ConnectConfig`, `IdConfig`, `KeyConfig`
  (all public fields; `From<…Args>` under `cli`). Their `Default`/`new` match the CLI defaults,
  and `serve` re-checks the ranges clap used to enforce so a library caller gets the same errors.
- `session::spawn_session`, `session::attach`, `server::run_session` and `pty::Pty::spawn` take
  the hosted program as an argv slice (`&[String]`) instead of `Option<&str>`; empty still means
  the login shell.

### Added
- **`ServeConfig::command`: host any program, with arguments.** `command[0]` is the program and the
  rest its argv, passed verbatim — no whitespace splitting, so a path with a space still works. On
  the CLI, `--shell` may now be repeated to build the argv (`--shell zellij --shell attach --shell
  -c --shell main`); a single `--shell` behaves exactly as before.

### Unchanged
- Wire protocol, `PROTOCOL_VERSION`/ALPN, the `koh-key-v1` key format, and every CLI flag and
  default.

### Added (carried from the unreleased 0.9.x line)
- **Pluggable terminal backends for the client renderer** (`client::backend::KohBackend`), so an
  alternate terminal crate can drive `koh connect` without touching the protocol, prediction, or
  session code. The render path now speaks only to the backend trait — its default methods emit the
  same standard ANSI/DEC koh always did (byte-for-byte with the previous `termina` output), so a
  backend only has to wire up raw-mode + size. The backend is chosen at build time by cargo feature:
  `backend-termina` (default — `cargo install koh` is unchanged), `backend-crossterm`, or
  `backend-qwertty` (e.g. `--no-default-features --features backend-crossterm`). The out-of-band mode ledger
  (forwarded-mode reset on drop/suspend) and the OSC-52 clipboard opt-in stay backend-independent, so
  every backend restores the terminal identically. Implements
  [#11](https://github.com/gold-silver-copper/koh/issues/11).

## [0.9.1] — 2026-06-29

### Changed
- Shortened the README into a concise install/usage + highlights landing page.

## [0.9.0] — 2026-06-25

### Changed
- **Local-echo prediction is always on.** Keystrokes now always render speculatively; the engine's
  epoch gate still suppresses the echo at non-echoing (password) prompts, and high-RTT links still
  underline-flag unconfirmed predictions. Previously the shipped default (`adaptive`) hid predictions
  entirely on low-latency links.
- **The "link down — resuming…" banner no longer flashes on a single lost keepalive.** Its grace
  was 3 s — exactly the keepalive interval — so one dropped or jittered keepalive on a lossy link
  briefly tripped it. The grace is now three keepalive intervals (~9 s), so transient packet loss is
  absorbed and the banner only appears on a genuine stall (`Ctrl-^ .` still quits immediately).

### Removed
- **`koh connect --predict <always|never|adaptive>`** — there is no prediction toggle; prediction is
  unconditionally on (see above).

## [0.8.0] — 2026-06-25

A large security/minimalism + release-maturity pass. **Breaking** (flags, env vars, and the default
key location changed).

### Removed
- **`--allow-any`** — there is no "accept any peer" mode; at least one `--allow <id>` is required, so a
  stray `koh serve` can never publish an open shell.
- **`--read-only`** — the observer mode is gone; the node-id allowlist is the sole access control.
- **`--allow-file` / per-peer authorization** and three low-value config knobs; the clipboard handling
  was consolidated.
- **`$KOH_STATE_DIR`** and the `directories` dependency.

### Changed
- **All koh-owned files now live under `~/.config/koh` only** (`$XDG_CONFIG_HOME/koh` is honored).
  Removed the platform-specific dir (macOS *Application Support*) and every `/tmp` / `/data/local/tmp`
  / CWD fallback; koh now errors rather than scattering a key when `~/.config` can't be located
  (`--key-file` remains the explicit override).
- **Identity-key hardening:** passphrase floor raised from 8 to **12 characters**, and Argon2id
  `t_cost` 3 → 4 (both apply to newly-written keys only; existing keys still decrypt).
- **Stricter builds:** `overflow-checks = true` in release, `dead_code = "deny"`.

### Added
- Property tests for the attacker-reachable parsers (`Transport::recv`, `FragmentAssembly::add`,
  `decrypt_key`); the terminal parser rebuild now runs through the vt100 panic-containment path.
- Release/maturity tooling: a `COPYING` (GPL-3.0) license file, this changelog, and CI that verifies
  the MSRV, builds on macOS, and treats clippy warnings as errors.

### Fixed
- Idle empty-ack flood (an idle side re-sent an empty ack every ~100 ms instead of settling onto the
  3 s keepalive); the prediction engine now resets its byte decoder on resize; redundant server-side
  re-snapshots on the input path.

## [0.7.0] — 2026-06-25
- **Removed the SPAKE2/PAKE passphrase second factor.** Identity keys are now **always encrypted at
  rest** (`koh-key-v1`: Argon2id + AES-256-GCM), and authorization is the node-id allowlist alone. Also
  ships the prior 0.6.0 work: vt100 panic containment on both sides and per-node-id authorization.

## [0.5.0] — 2026-06-24
- Architectural review follow-ups: a pure, I/O-free `ServerSession` core; required per-state DoS bounds
  (`RECV_DECODE_LIMIT` / `RECEIVE_BUDGET_UNITS`); RAII attach guards; a CI layering guard.

## [0.4.4] — 2026-06-24
- Engineering-quality pass: fuzz targets + property tests on the untrusted decoders, an idle-snapshot
  gate, CI + `cargo-deny`, and docs. Supersedes the unpublished 0.4.0–0.4.3 interim security fixes.

## [0.3.2] — 2026-06-23
- Security-audit hardening of the post-auth data plane (inflation / reassembly / accumulation caps) and
  a screen-off reconnect fix.

## [0.3.1] — 2026-06-23
- Hardening against hostile or compromised peers (transport-level fixes).

## [0.3.0] — 2026-06-23
- Detachable/reattachable sessions, terminal-reply synthesis (DSR/DA/DECRQM), remote exit-status
  propagation, and the opt-in Android-emulator test suite.

## [0.2.0] — 2026-06-23
- Early iteration of the transport + terminal core.

## [0.1.0] — 2026-06-23
- Initial release: the SSP protocol core, the terminal model, the PTY host, the local-echo predictor,
  and the iroh QUIC transport.

[Unreleased]: https://github.com/gold-silver-copper/koh/compare/v0.13.0...HEAD
[0.13.0]: https://github.com/gold-silver-copper/koh/compare/v0.12.1...v0.13.0
[0.9.1]: https://github.com/gold-silver-copper/koh/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.9.0
[0.8.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.8.0
[0.7.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.7.0
[0.5.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.5.0
[0.4.4]: https://github.com/gold-silver-copper/koh/releases/tag/v0.4.4
[0.3.2]: https://github.com/gold-silver-copper/koh/releases/tag/v0.3.2
[0.3.1]: https://github.com/gold-silver-copper/koh/releases/tag/v0.3.1
[0.3.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.3.0
[0.2.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.2.0
[0.1.0]: https://github.com/gold-silver-copper/koh/releases/tag/v0.1.0
