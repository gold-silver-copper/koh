# koh architecture

How koh is built. The [README](../README.md) covers what it does and how to use it; this is the
internals. Pair it with the [threat model](THREAT_MODEL.md) and the porting-research notes under
[`research/`](research/).

## The one idea

koh keeps a **copy of the server's screen** on the client, not a byte stream from the shell. The
server runs the terminal emulator; the client only ever receives screens, as diffs against a screen
it already holds, and a newer screen replaces an older one. If the screen changed 100 times in
40 ms, the client gets the latest, not 100 updates. That gives instant re-sync after a drop (never a
backlog), responsiveness on lossy links, and no head-of-line blocking of the screen behind stale
output. Keystrokes are the opposite: every byte matters and order matters, so they travel on one
reliable, ordered stream. QUIC (through iroh) provides both, plus encryption, authentication, loss
recovery, congestion control, RTT estimates, roaming and NAT traversal.

## Module layout

One crate, `koh`: a library (`src/lib.rs`) with everything but the command line, and the binary
(`src/main.rs`, `src/args.rs`). `Cargo.toml` forbids the panic lints for all of it, tests
included, so nothing uses a macro whose expansion `allow`s one: the command line is built with
clap's builder API rather than its derive, and tests build their tokio runtimes explicitly.

```
src/
├── main.rs          the binary: serve / connect / id / key dispatch, and the hidden `__launch`
├── args.rs          the command line (clap's builder API) and the config structs it produces
├── lib.rs           crate root: module declarations + the architecture overview
├── proto.rs         the koh/3 wire protocol: client messages, screen frames, caps, pacing
├── terminal/        TerminalScreen (a cell grid + structured diff) + ServerTerminal (fux-vt)
├── predict.rs       local-echo prediction engine (overlays, epochs)
├── transport_iroh/  iroh endpoint setup, the identity key file, path RTT, admission
├── pty.rs           PTYs over fuxix, the `__launch` launcher sessions start through, reaping
├── server/          session tasks + registry, the per-connection loop (ServerConn), `serve`
├── client/          the connection loop + ClientSession core + predictor + render + `connect`
│   └── backend/     KohBackend (escape emission) + Tty (raw mode and size through fuxix::terminal)
├── identity.rs      unlocked identities + the key lease `koh key reset` respects
├── log.rs           the `RUST_LOG` filter `serve` and `connect` install (`target=level` directives)
└── keycmd.rs        `koh id` and `koh key` — print the endpoint id, show the identity, reset it
tests/net/           koh over a fault-injecting link between real iroh endpoints
tests/               PTYs, sessions, loopback e2e, admission, the binary on a PTY, upgrade in
                     place, key creation races, the corpus, and the Android suites (opt-in)
testing/corpus/      113 real programs' output (from fux), replayed by tests, oracle and bench
testing/oracle/      koh at the working tree beside koh at a commit (`testing/oracle.sh`)
testing/bench/       the scoreboard: koh beside mosh and ssh (`testing/scoreboard.sh`)
```

Dependency direction is strict: `proto` sits on `terminal`; `server` and `client` (+ the `koh`
binary) build on both. The protocol cores (`proto`, `terminal`, `predict`, `server::ServerConn`,
`client::ClientSession`) do no I/O and are tested with no network at all. `predict` imports nothing
from `crate::` (CI checks it), so it is a standalone terminal-prediction library.

## The protocol (koh/3)

The ALPN `koh/3` is the version check: a peer on another version fails the TLS handshake with a
clear error. After the handshake the server checks the allowlist and opens a bi-stream carrying one
ADMIT byte, so a rejected client can tell "not authorized" from a network error. Then
(`src/proto.rs`):

- **Client to server: one uni stream** of length-prefixed postcard `ClientMsg`s: `Keys { seq,
  events }`, the input the client decoded (`src/events.rs`: keys, mouse events, focus changes and
  paste pieces, at most 512 a message), `Input { seq, bytes }`, raw bytes the server forwards as they
  are (at most 64 KiB; the client sends none now), `Resize`, `Resync` when a frame's base is
  unknown, `History { newest, count }` for scrollback rows, `Ack { frame }`, now only a nudge
  (below), and `Colours`, the user's terminal's colours, on each connection unless `--no-colours`.
  `seq` numbers each input on the connection.
- **Input is decoded on the client and encoded on the server.** The client reads what the user's
  terminal sends with fux-vt's decoder (legacy bytes, xterm's modifiers, the kitty keyboard
  protocol, which it pushes in a terminal that speaks it, SGR mouse reports, focus changes,
  bracketed pastes) and sends events; the session encodes each with fux-vt for the program's modes
  at that moment (`ServerTerminal::encode_input`: the kitty flags, modifyOtherKeys and cursor keys;
  the mouse tracking mode and encoding; mode 1004; bracketed paste, framed once over a paste's
  pieces with every end marker removed). A program gets what it asked for from any terminal, and a
  reattach from another terminal changes nothing for it. The client keeps the user's terminal in
  the modes it decodes in rather than mirroring the program's: bracketed paste and focus reporting
  on, normal cursor keys and keypad, SGR mouse reports while the program wants the mouse.
- **Colours.** The client asks its terminal's foreground, background, palette 0–15 and scheme at
  start-up (and again when the terminal reports a new scheme, mode 2031) and tells the server; the
  server's terminal answers programs' OSC 10, OSC 11, OSC 4 for entries 0–15 and `CSI ? 996 n`
  from them, and sends a
  program that subscribed to mode 2031 the new scheme when a client brings one.
- **Server to client: one uni stream per message**: a tag byte, then for a frame its base's number
  and the frame (`num`, `base`, `echo_ack` and a `ScreenDiff` from frame `base` to frame `num`)
  DEFLATE-compressed against the base screen's dictionary; for history rows, the rows compressed.
  Either inflates with a 16 MiB limit. Frame 0 is the blank default screen, which both ends always
  hold; real frames count from 1.
- **Compressed against the base.** Both ends hold a frame's base screen, so the compressor starts
  from a dictionary made of it (`TerminalScreen::dictionary`): the base's rows encoded as a frame
  encodes them, those nearest the cursor last, at most DEFLATE's 32 KiB window. A row the frame
  changes then compresses against what it was: a typed character or a ticking clock costs a few
  bytes. The client refuses a frame whose base it lacks, so the dictionaries cannot disagree.
- **Rows as runs of text.** A row is runs: identical cells as one run with a count, and
  same-looking characters as one run of their text (`CellKind::Chars`, `CellKind::WideChars`), so
  text costs about a byte a cell before compression.
- **Delivery is the acknowledgement.** The client sends no acknowledgement per frame: when QUIC
  reports a frame's stream wholly delivered (`stopped` with no code), the server takes it as
  acknowledged. The client applies every frame it gets on a base it holds, and keeps a frame that
  arrives after a newer one as a base, so the server may diff against any delivered frame. The
  server asks the client's QUIC stack to acknowledge within 2 ms (the ACK-frequency extension)
  rather than 25. A superseded frame that was wholly written gets a round trip and that delay to
  report its delivery before its stream is reset.
- **Scrollback by name.** The server names each row as it enters its history with the next number
  of a session counter, so the history's rows always carry consecutive names (a resize, which
  reflows the history, names every row afresh). Each screen carries a `HistoryMark`: the newest
  row's name and how many rows the history holds. The client asks for the rows it lacks, by the
  newest name and a count (at most 256 rows); the server answers one request at a time, each on a
  stream below frames in priority, the next only once the last is delivered, so history never
  delays a frame or outruns the link. A named row's cells never change, so a row the client holds
  is never sent again. The client keeps at most `HISTORY_CACHE_CELLS` (a million) cells of history,
  dropping the rows farthest from its view; the server queues at most 8 requests, and one more is
  a protocol error.
- **Bases are acknowledged frames.** The server diffs against the newest frame delivered, so a lost
  frame only delays the screen until the next one. When the server sends a
  frame it resets the streams of older unacknowledged frames, so QUIC never retransmits a screen a
  newer one has replaced.
- **Pacing by what the link takes:** never more than about a round trip of frame bytes in flight.
  The server tracks the frames sent and not yet delivered, and judges the link's rate by recent
  deliveries (the quickest delivery is near the round trip alone, so what a frame took beyond it is
  its bytes' time); the budget is that rate times the round trip. A changed screen goes once the
  frame floor (`FRAME_FLOOR`, 5 ms, which only batches a burst) has passed and the bytes in flight
  are under the budget, or none are in flight. While frames would queue, the screens between are
  skipped for the newest. A small change (at most four rows) while typed input awaits its echo
  goes at once, room or not, at most a millisecond apart: the program's echo is never stuck behind
  a flood. A heartbeat frame goes at least every 3 s so the client can tell a quiet session from a
  dead link.
- **Retries without QUIC's backoff:** on a lossy, jittery path QUIC's probe timeout is several
  round trips and doubles on each loss. So an unacknowledged newest frame is resent, as a new frame
  that supersedes it, after a round trip, the frame floor and QUIC's acknowledgement delay; and
  input the echo-ack has not confirmed after the same wait makes the client send an `Ack`, a later
  packet that lets QUIC detect the loss and retransmit at once.
- **Bounded state:** each end keeps at most `FRAME_WINDOW` (16) recent screens — the client its
  last applied frames, the server the frames sent since the last acknowledged one. A count alone is
  not a memory bound when a screen can be a million cells (about 32 MB at the 1000×1000 a client may
  ask for, 32 bytes a cell), so both ends also bound the cells their window holds at
  `WINDOW_CELLS`, one screen of that size, counting each row once however many screens share it:
  the server's unacknowledged frames together, the client's older frames beyond the current one.
  Past it the oldest are dropped, which only costs the peer a base (a frame on a dropped base makes
  the client ask for a resync). Screens are shared, not copied — a resent frame holds the session's
  own snapshot, a client screen shares every row a frame did not carry with its base — and the
  session takes one snapshot per burst of program output rather than per read. That, plus QUIC flow
  control and the stream limits (the server accepts one client stream; the client a handful of
  frame streams), bounds memory; a peer cannot make either end accumulate.
- **Backpressure:** PTY input goes through a bounded writer queue. While it is full the server
  stops reading the client's stream, QUIC flow control stops the client's writes, and the client
  keeps at most 1 MiB of typing before dropping it with an "input paused" status line. The keyboard
  loop never waits on the network, so `Ctrl-^ .` always works.
- **The scrollback view** (`Ctrl-^ [`, `client::scrollback`): the server's history above the live
  screen, fetched as the user scrolls with the arrows, Page Up/Down, `k`/`j`, `b`/`f`, `u`/`d`,
  `g`/`G` or the mouse wheel (the view turns mouse reporting on), and `q` or Escape to leave. `/`
  searches the history for text, older from the view's top, fetching rows as it goes (a search
  waits on the rows it needs first); `n` goes to the next older match, `N` to the next newer. The
  view is anchored to its rows: output that scrolls into history moves it up with them, so what
  is being read stays still while the live screen goes on below. Out of the view, a client idle for
  2 s fetches the newest screenful ahead, so opening the view shows rows at once.
- **Shutdown:** when the shell exits, the server sends the final frame (carrying the exit code),
  waits up to 1 s for its ack, then closes the connection with code 0 and reason `session ended`.

`TerminalScreen` is a plain `Grid` of `fux_vt::Cell`s (with a cursor, per-row soft-wrap flags and
the input modes the client mirrors) plus the side channels: title, icon, OSC 52 clipboard, bell count
and exit code. The grid stores each row as its own reference-counted slice of cells, shared by every
screen that holds the row unchanged: a snapshot shares the rows the program left alone (found by
fux-vt's row ids, so rows that scrolled are shared too) with the snapshot before it, and a client
screen shares every row a diff did not carry with the base it was applied to. So a screen costs the
rows that changed, two screens compare and diff by skipping the rows they share, and each end's
memory for its recent screens is counted in distinct rows. The list of rows is itself shared by
every screen holding all of them, and copied only when a row is replaced, so copying a screen
touches no row. A snapshot reads each live row's fux-vt id and version, which fux-vt changes only
when an edit changes the row: a row at the id and version the last snapshot saw at its place is
taken as it was, one seen elsewhere is found by id, and if no row changed the snapshot shares the
last one's list whole. Counting a window's memory looks only at the rows that differ from the
newest screen's at the same place. The server's live emulator is `fux_vt::Parser` (`ServerTerminal`), with the options in
`terminal::OPTIONS`, each for what koh carries: events (title, icon, bell, clipboard), extended
replies (DECRQM, DECXCPR, secondary DA), in-band resize and the size query, the palette (a
program's colours, drawn as RGB in snapshots, so the user's palette never changes), reflow, and
koh's identity for device attributes and XTVERSION. A frame a program draws with synchronized
output is not sent half drawn (`FrameHold`): while it is drawn the screen from before it goes out,
and it is let go after 150 ms. The diff (`ScreenDiff`) carries every changed row whole as run-length-encoded cells, the
cursor and the modes; after a resize the client starts from a blank grid and receives every
non-blank row.

Rows that only moved are moved, not sent. A scroll, of the whole screen or inside a scroll region,
and an inserted or deleted line leave the rows they move holding the same cells, so the server finds
them by the cells they share with the base, in runs that moved by the same offset, and sends each
run as a `Shift { top, len, by }`: rows `top..top + len` of the base go to `top + by`. All shifts
read the base, no two share a source or a destination row, and a row a shift left and none filled
is blank, which is what a scroll brings in. The client moves those rows' cells (shared, not copied)
before replacing the rows the diff carries, so a one-line scroll sends the shift (4 bytes on a
24-row screen) and the new line, not the screen. Decoding checks what needs no screen size (at
most 32 shifts, no zero length or offset, both ranges within 1000 rows, no shared rows); `apply`
checks the ranges against the screen and refuses shifts with a resize, and drops the frame whole
if anything is wrong. What a shift cannot say is sent as rows: a row moved and changed, a row that
appears twice, a horizontal shift inside a row, and the shortest runs past the 32nd.

A program may also scroll only some columns, between left and right margins (DECLRMM, DECSLRM),
which fux-vt has and the server's terminal says it has when asked (DECRQM of mode 69): nvim then
scrolls a split window between margins. A shift moves whole rows, so those rows go as rows. That
costs nothing measurable: nvim run under koh, splitting a window and scrolling in both halves at
40x120, sent 92.9 KB to the client with mode 69 answered as known and 92.8 KB with it answered as
unknown (three runs each, 0.3% apart), so the server answers it as known.

The client validates and copies cells and never runs a terminal parser, so server
bytes never reach one. That includes the user's terminal, which the client prints a cell's text to
as is: decoding refuses a cell whose text holds a control character, so no escape sequence can
ride in one.

A cell is one grapheme cluster, as fux-vt segments output (UAX #29): a ZWJ emoji sequence, a
flag or a base with its marks stays in one cell, whose width is the cluster's. A cluster of up to 17
bytes is held in the cell; a longer one, up to 128, in its row's text (`fux_vt::Cells`), which the
client rebuilds as it decodes the row. On the wire a cell carries its cluster (at most 128 bytes),
its kind, its colours, its underline colour and its style bits: bold, dim, italic, underline
and the underline's style (single, double, curly, dotted, dashed), inverse, hidden, strikeout and
a slow or rapid blink. The client paints an underline's style (`4:n`) only if the user's terminal
draws them, which it asks the terminal once at start-up (XTGETTCAP for `Smulx`, and the pen with a
curly underline through DECRQSS, before primary device attributes; `client::probe`); otherwise
it paints a plain underline, as a terminal that does not know `4:n` would draw none.

A row also carries its hyperlinks (OSC 8): its distinct links once (at most 64, each URI and id
within fux-vt's limits), and each cell the index of its link, so a row moved or shared keeps its
links with it and needs no screen-wide table. A diff carries at most 1 MiB of links; the server
leaves off a row's links past that, and the client drops a frame over it. The client paints a
link with OSC 8 (with the program's id, if it gave one) unless `--no-hyperlinks`, after checking
it again, and closes it before any cell without it and at the frame's end.

## Headless drivers (the protocol is I/O-free; the shells are thin)

Both ends split into a synchronous, I/O-free core and a thin async shell. The client's
**`ClientSession`** (`client/session.rs`) holds the recent screens, the predictor and the
escape/render state, and exposes pure steps: `on_input` (the `Ctrl-^`-prefix machine, prediction
seeding, input queueing), `on_frame`, `on_resize` and `on_tick` (the link-down and input-paused
banners), with the outgoing messages taken from a queue. The server's **`ServerConn`**
(`server/mod.rs`) decodes the client's stream, tracks the echo-ack, and decides which frame to
send against which base. None of it touches tokio, iroh or a terminal, and time is an argument, so
both are deterministically unit-testable. The shells own the `tokio::select!` (the client's kept
`biased` for input priority), a writer task for the client's stream, a task per frame stream, and
the rendering.

On the server side, **PTY writes are non-blocking**: a dedicated `koh-pty-writer` thread drains a
bounded channel, so forwarding a keystroke (or a synthesized DSR/DA reply) only enqueues and never
blocks a tokio worker on a slow child. The PTY master itself is non-blocking and both pump threads
wait in `poll`: on Linux and Android a write blocked on a program's full input queue is never woken,
not even once the program dies, so the writer gives up unread input as soon as the session is torn
down instead of wedging the teardown. Both producers share
one sender and enqueue under the session lock, so byte order is preserved (a query reply can't
overtake the keystroke that triggered it).

## Rendering

The client paints the synced grid, the predictions over it and an optional status line through
`KohBackend`, whose provided methods write the ANSI; every frame is wrapped in synchronized output
(DEC 2026), so the terminal shows it at once. `BackendTerminal` keeps what it last painted: the
grid (whose rows are shared with the session's screen, so keeping it copies no cells), the
predictions and whether a status line was up. A frame then paints only the cells that differ from
it, skipping rows it shares without reading them, moving the cursor only to reach a changed cell,
and repainting a wide glyph whole when either half changed. So a keystroke's echo writes a few
bytes, and the banners, which repaint every 50 ms, write their own row.

Rows that only moved since the last paint (the painted grid's rows, shared with the new screen at
other indices) are moved on the terminal, not repainted: in a scroll region (`CSI t;b r`), `CSI n S`
scrolls up and `CSI n T` down, and `CSI r` resets the region. The painter finds these moves itself,
by the cells the rows share with the grid it painted, because that grid may be several frames
behind; each scroll's region must overlap no other, so they can run one after another, and a scroll
is only made when it writes less than repainting its rows in place, by an estimate that counts a
byte a differing cell and a cursor move a run of them (lines that differ in a few digits, or share
most of their blanks, are cheaper repainted). SGR is reset first, so the rows a scroll brings in
have the default background, and each row is then compared with the row the scroll put there, or
with a blank one. It scrolls only on a terminal exactly the screen's size, since a scroll moves
whole terminal lines, and never the status line's row.

A frame is painted whole, byte for byte as every frame was before, when the terminal may not show
what was painted: the first frame, after a resume or a window resize, when the screen's size
changes, when the status line appears or goes, and while the terminal is smaller than the screen.
It is also painted whole, and the next one too, when a glyph does not fill exactly the cells it is
given (a hostile server's wide glyph in the last column, say), because the terminal then lays the
row out its own way. Predictions never cause that: a predicted wide glyph comes with the cell it
covers, which is skipped as a grid continuation is, and a glyph of the grid that a prediction half
hides is drawn as a blank in the prediction's style, as a terminal leaves a wide glyph one of whose
halves is overwritten. A property test feeds both ways of painting into a fux-vt terminal and checks
it shows the same thing after every frame, scrolling included; there a printed space and an erased
cell of the same attributes count as the same, since a whole repaint prints spaces where a scroll
brings in erased cells.

## The predictor

The client guesses what each keystroke does to the screen and shows it immediately, then confirms
or corrects when the authoritative server frame arrives. Confirmation
is driven by the server's **echo-ack** (a 50 ms-debounced "your input up to frame N is now on
screen"), not the raw network ack.

**The PTY's modes.** Each screen carries how the program's PTY takes typed keys (`TtyModes`: the
kernel's echo and line mode, read with `tcgetattr` through fuxix at every snapshot and every 100 ms
while a client is attached, as a program may turn echo off without writing). Line mode without
echo is a password prompt (`getpass`, `read -s`, sudo, ssh, passwd): nothing typed is predicted
and every prediction is dropped, however trusted the session was. The modes the client holds
can lag the PTY's by a read interval (a program that prints its prompt, then turns echo off), so a
key typed within 200 ms of a frame that moved the cursor to another row (a fresh prompt) is not
predicted until the server has reflected it (`PredictionEngine::hold`). Kernel echo is trusted
from the first key otherwise. Otherwise (a line editor, a full-screen program) the epoch logic decides: the first key
of an epoch stays hidden until the server's echo confirms it, and a mispredict kills its epoch. A
reconnect to the same session carries the trust it had, given once the first frame shows no
password prompt. Prediction is **always on** in koh (`DisplayPreference::
Always`), so keystrokes engage on every link. Predictions are drawn plain, not underlined,
and a cell it knows changed but not to what is not drawn at all, so the real cell shows.

The port faithfully implements epoch-gated confirmation, glitch escalation,
and no-echo suppression. It predicts ASCII printables (with insert-mode row shift),
backspace, CR/LF, the left/right arrow keys (CSI **and** SS3/application-cursor form), the line
editor's keys where the guess is sure (`Ctrl-W` and `Alt-Backspace` back to a word's boundary,
never into what is left of the line's start; `Ctrl-U`, `Ctrl-A` and Home only when where the line
began is known, from the first key typed after Enter; `Ctrl-E` and End to the end of an unwrapped
row; `Alt-B` and `Alt-F` by readline's words), and whole UTF-8 graphemes including double-width CJK/emoji (cursor advances by two cells). A wide glyph is
predicted as two cells, the glyph and the cell it covers; the covered cell is right when the
server shows a wide glyph's right half there, and never confirms an epoch. The insert-mode shift
moves each wide glyph with its right half; one the shift splits (at the right edge, or typed
inside) becomes unknown rather than half drawn. Backspace over a wide glyph, which a line editor
takes back two cells, is not modelled. Control/escape sequences it doesn't model open a fresh epoch
but make no concrete guess (they fall back to the server's real echo). A wrong or unconfirmed guess
is always reconciled away — it never corrupts the display.

## Reconnect & detachable sessions

Sessions are **detachable**: the server keeps your shell (and its live screen) running after a
disconnect, keyed by your client endpoint id, so reconnecting from the same client drops you back
exactly where you left off. A detached session is reaped after `--session-ttl-secs` (default 24 h)
or immediately when its shell exits. There is one session per peer, one shell — no multiplexing.

The reconnect is **automatic and in-process**: the client doesn't exit when the link drops. A brief
outage (e.g. a phone screen-off — Android freezes the process, so QUIC keepalives stop) is ridden
out on the same connection thanks to a 5-minute connection idle timeout. A longer outage times the
connection out; the client then transparently re-dials and reattaches to the same server session,
holding the last screen under a `reconnecting…` banner in the meantime. One `ClientSession` lives
for the whole run and one loop drives it, connected or not: only what belongs to a connection (its
frames, echo-ack and acknowledgements) is dropped (`detach`) and made anew (`attach`), so the
escape keys, the scrollback view, the window size and the colours work during the outage and carry
across it. Typed input does not: what is typed while the link is down (and the banner stays up until
the new connection's first frame shows which shell it reached) is not taken (nor predicted), what was not yet
sent when the connection is made anew is dropped, and the status line says so; it also says when
input handed to the lost connection was never confirmed, as what follows may run without it. A reattach may land on a new shell (the session expired, the shell
exited, or the server restarted), which the client cannot tell from its own (the server's
`AttachKind` is not on the wire), and keys typed at the old screen must not run there; nor may the
end of a line whose start was lost with the link run alone (`false && rm …` typed across the drop
must not run `rm …`). Sending them would take the session's identity on the wire. The history rows
held are the server session's too, so `attach` drops them and the new connection's frames say the
history again. A **wall-clock freeze
detector** turns a multi-minute wake-up hang into a ~1–2 s reattach: if real time jumps more than
20 s between two (≤50 ms-cadence) loop iterations, the client concludes the process was suspended,
drops the (almost certainly dead) connection, and re-dials immediately. The first iteration
measures from when the connection was dialed, so a freeze while the client starts (probing the
user's terminal, entering raw mode) counts too. A sub-20 s glance still rides out silently on the
existing connection.

> **`--direct` and server restarts:** transparent re-dial targets the *same* address it first
> dialed. By default `koh serve` binds an ephemeral UDP port, so a restarted server is elsewhere and
> a `--direct <ip:port>` client redials the old port forever. `koh serve --port <PORT>` binds a fixed
> port (IPv4, and IPv6 where the host has it), so the restarted server is where the client looks,
> and it reattaches, to a fresh session: the old session's program died with the old server. A
> server stopped with SIGTERM closes its connections, so clients redial at once; one that died
> without closing them (SIGKILL, a crash, a power cut) leaves them to notice through the 5-minute
> idle timeout. The relay/discovery path (a bare endpoint id) re-dials by node id and follows the
> server across address changes.

## Sessions, connections and the bell hook

A session is one PTY + emulator per authorized peer (`server::session`). Its program starts
through the launcher, `koh __launch PROGRAM ARGS…`: making a program a session leader with the
PTY as its controlling terminal needs code between `fork` and `exec`, which std allows only
through `unsafe`, so the launcher does it as a program of its own. It marks every inherited
descriptor close-on-exec, calls `setsid`, takes the PTY as its controlling terminal and `exec`s
the program, reporting a failure (including a failed `exec`) on a pipe the `exec` closes. On
Linux the launcher is `/proc/self/exe`, so a server whose binary was upgraded in place still
launches sessions; `__launch`'s interface is fixed for the same reason. Two connections from the
same peer can briefly share it, when a reconnect races the old connection's teardown, so the
per-connection state never lives in the session:

- **Echo-ack is per connection.** Input sequence numbers are the client's (one client's rise
  across its reconnects; two clients' have nothing in common), so the input history and the 50 ms
  debounce live in the per-connection `ServerConn` (`server::EchoAck`), not in the session, and
  each frame carries its connection's own echo-ack. A session-global ack would hand one
  connection another's numbers, and its predictor would treat every keystroke as already acked.
- **A change wakes every connection.** The session task publishes each new screen on a
  `tokio::sync::watch`; each connection holds a receiver and `select!`s on it. Every connection
  wakes on one change; a burst coalesces into the latest screen; and a change landing between a
  connection's read and its wait is never lost, because the receiver keeps the latest value.
- **Detach on drop.** A connection holds a `SessionClient`; dropping it (on return **or**
  panic) sends the session task a detach, so a panicking connection can't pin a session. The
  session task counts attached clients and starts the TTL only when the last one leaves; it tears
  itself down at the TTL or once its shell exits, and tells the registry to forget it.
- **The bell hook.** `--on-bell <cmd>` / `ConnectConfig::bell_command` runs `sh -c` when
  the remote bell count climbs: detached (fds on `/dev/null`), `KOH_*` scrubbed except
  `KOH_BELL_COUNT` / `KOH_TITLE`, rate-limited to one spawn per second with bursts coalesced, the
  child reaped off the session loop. The decision is a pure `BellHook::observe`.
- **The hook's environment and its first frame.** `BellHook::command(count, title,
  parent_env)` builds the child from an explicit parent environment (`env_clear`, then everything
  but `KOH_*`, sharing `pty::is_koh_env_key` with the PTY spawn), so the scrub is tested with a
  synthetic environment rather than assumed. The bell count is cumulative per server session, so
  the first synced frame `prime`s the hook: bells from before this attach do not fire it. The hook
  outlives a reconnect and is not re-primed, so bells during an outage do.

The client renders through `client::ClientTerminal`, so tests can capture frames instead of
driving a real terminal, and the predictor reads screens through `predict::ScreenView`
(implemented for the client `Grid` and for `fux_vt::Screen`), which keeps `predict.rs` free of
`crate::` imports.

## Security internals

The full picture is in the [threat model](THREAT_MODEL.md). In brief, the relevant boundaries:

- **Authorization** is a node-id allowlist, the *sole* gate; the peer's Ed25519 node-id is
  authenticated by iroh's QUIC + TLS 1.3 handshake *by construction* (no TOFU window — the client
  pins the id it dialed). There is no "accept any peer" mode and no passphrase/PAKE second factor.
- **The data plane treats every authorized peer as untrusted**: a resize is clamped to `[2, 1000]`
  before any grid allocation; client messages and frames are size-capped and frames inflate under a
  limit; each end keeps a fixed window of screens; QUIC stream limits and flow control bound what is
  in flight; the QUIC handshake and the 1-byte admission ack are deadline-bounded; and a screen
  diff is fully validated before it is applied, with no terminal parser on the client (the
  server's fux-vt emulator is panic-free and bounded).
- **The identity key is protected by its file permissions**, like an SSH host key: the file is the
  raw 32-byte secret, created 0600 by a born-private atomic write, read with `O_NOFOLLOW` and
  re-tightened to 0600 through the open descriptor. Anyone who can read the file is that identity.
  koh keeps every file it owns under `~/.config/koh` and nowhere else.
- The crate is `forbid(unsafe)` and forbids the panic lint family (`unwrap`/`expect`/`panic`/
  indexing/slicing), unchecked arithmetic (`arithmetic_side_effects`) and lossy `as` casts in
  production code, with `overflow-checks` on in release too — so the panic-free-by-construction
  property holds against adversarial input.

## Testing tiers

You never need a second *machine* to develop koh — you need a second *process* and occasionally a
second *container*. The verification is layered cheapest-first; everything but Tier 3 is headless.

### Tier 0 — pure logic, no infra (`cargo test`)

The protocol, diff/apply, predictor and session registry need no network or TTY, so they're tested
deterministically:

- **State round-trip** — `apply(diff(base→target))` over `base` equals `target`, for screens (incl.
  wide chars / emoji / combining marks).
- **Protocol cores** — `ClientSession` and `ServerConn` driven with synthesized frames and
  messages: bases, acknowledgements, resyncs, the frame window, pacing, retries, heartbeats,
  backpressure and shutdown; `proto` round-trips, size caps, truncation and inflate bombs.
- **Terminal / predictor** — diff+resize, predict→confirm→clear, predict→no-echo→suppress.
- **Property tests and fuzzing** on the attacker-reachable parsers — assert never-panic and bounded.
  Coverage-guided fuzz targets: `screen_apply` (the structured diff), `server_process` and
  `proto_decode` (both directions of the wire).
- **The corpus** (`tests/corpus.rs`) — 113 recordings of real programs (`testing/corpus/`, from
  fux: shells, editors, pagers, TUIs, compilers, claude) through the whole pipeline in PTY-sized
  pieces with their resizes: snapshot, frame, encoder and decoder, `ClientSession`, koh's own
  `BackendTerminal`. After every frame, a fux-vt terminal reading every painted byte must show
  what a fux-vt parser fed the same output shows; over a lossy link too, where it must converge on
  every step. The recordings known to show otherwise are listed with the reason
  (`testing/corpus/recording.rs`).

### Tier 1 — real iroh endpoints on one machine (`cargo test`)

A second host is just a second endpoint, and a TTY is just an allocated PTY.

- **`tests/net/`** — a real `koh serve` accept loop and a real `koh connect` client loop on iroh
  endpoints whose only path is an in-process fault-injecting link (`tests/net/link.rs`, an iroh
  custom transport): loss, delay, jitter, duplication, reordering and outages under real QUIC. It
  covers screen convergence (and that a stale screen is never shown), exactly-once ordered input,
  reattach, a forced mid-session drop, exit status, resize, XON/XOFF, input backpressure, the bell
  hook, prediction and the no-echo property, and hostile clients and servers. The corpus runs
  here too, through a real server and client under loss (eleven recordings by default, every one
  with `KOH_NET_CORPUS=all`). An `#[ignore]`d baseline measures echo latency, output bursts, bytes
  and outage recovery per network profile.
- **`tests/pty.rs`** and **`tests/sessions.rs`** — real programs on real PTYs, started through
  the `koh` binary's `__launch`: output streaming and teardown, exit statuses, the
  reaped-PID gate, a program that cannot start, no leaked descriptors, a session leader owning its
  terminal; the session registry's attach/reattach/cap/TTL/teardown; `run_session` and the
  per-connection echo-ack over loopback iroh. On macOS `tests/pty.rs` first grows the kernel's PTY
  table past what its tests hold at once: an open that finds the table full while another PTY is
  being freed fails with ENXIO (the table grows 16 slots at a time and never shrinks), which its
  many short-lived PTYs hit on a fresh machine.
- **`tests/e2e_loopback.rs`** — the whole loop over loopback: scripted keystroke → client → iroh →
  server → PTY-hosted `sh` → fux-vt → iroh → client render.
- **`tests/e2e_pty_binary.rs`** — the **real `koh` binary** attached to an allocated PTY (so
  `isatty()` is true and raw mode runs for real), driven by scripted keystrokes with rendered
  frames read back from the master, connected with `--direct` to an in-process server; the
  `Ctrl-^ Ctrl-Z` suspend under a job-control bash; and a `koh serve --local --port` process
  restarted under a connected client, which finds it again.
- **`tests/upgrade_in_place.rs`** (Linux) — a running `koh serve` whose binary file is removed
  still starts sessions, because it launches them from `/proc/self/exe`.

Two harnesses sit beside the tests, each its own Cargo workspace:

- **The oracle** (`testing/oracle.sh`, [`testing/oracle/`](../testing/oracle/README.md)) runs koh
  at the working tree and koh at a commit (the merge base with `origin/main` by default) on the
  same sessions (the corpus, and random output, keystrokes, lost frames, time and resizes) and
  compares what the user's terminal would show, the replies and the client's messages after every
  step, reporting each side's frame bytes. A difference is shrunk and saved. It finds each of five
  planted bugs (`testing/oracle.sh --plants`).
- **The scoreboard** (`testing/scoreboard.sh`, [`testing/bench/`](../testing/bench/README.md))
  writes [`SCOREBOARD.md`](SCOREBOARD.md): koh beside mosh and ssh by bytes on the wire for each
  recording and synthetic workload, keystroke latency beside a flood on three links, server memory
  per session and instructions retired.

Terminal I/O is behind `ClientTerminal`, so the same session loop runs against the real terminal
(binary) or a capturing mock (tests). One layer down, `client::backend::KohBackend`'s provided
methods emit all the ANSI, so the bytes are pinned by tests against a capturing backend.

### Tier 2 — Android emulator: runtime, network realism, resilience ([`testing/android/`](../testing/android/))

The layer a single in-process test can't reach: the **real `koh` binary on a real Android OS**,
driven over `adb`. Opt-in (`KOH_ANDROID_EMULATOR=1`), never part of `cargo test`. A **smoke** suite
proves the Android iroh/DNS path binds without the `ndk-context` panic (a runtime-only bug
cross-compilation can't catch); a **stress** suite hammers koh under load, churn, and adverse
conditions (connection churn, concurrent sessions, throughput + memory-longevity leak checks, signal
handling, a short screen-off freeze and a long one, reattach continuity, `tc netem`
loss/jitter/reorder beneath real QUIC, a total-outage roaming analogue, and a bare-id connection over
the public relay); and a **security** suite proves the data-plane and key defenses against a
cross-compiled malicious-peer harness. The memory checks are part of the point: an emulator has the
RAM to survive what would get the server killed on a phone, so the suites bound the server's RSS
under attack rather than only its survival. Every check first proves its precondition (the attack
ran, the client was attached) from the server's log, so a result cannot pass vacuously. The netem
tests root only `tc` (`su 0`, on a userdebug image), never the shell koh runs in.

### Tier 3 — real devices (manual)

A small final human acceptance pass: paste the endpoint id on an actual phone, connect to an actual
Mac over the public relay, type on a laggy cell link, and feel the predictions. The headless tiers
prove correctness; only a real two-device run over a real radio proves *feel* and migration.

## Acceptance criteria (mosh feel)

| Property | How koh delivers it |
|---|---|
| Keystrokes appear instantly on every link | predictor (shows once the server proves it echoes; confirmed by later frames) |
| Survives suspend/resume + IP change, re-syncs to current screen | QUIC connection migration + a fresh frame against an acknowledged base (no backlog) |
| A burst of superseded output never delays the current screen | one stream per frame, older frames reset; only the latest screen is sent |
| Password prompts show no predicted echo | emergent no-echo suppression in the predictor |
| Reconnect lands you where the screen is *now* | a new connection starts from the blank screen and gets the current one |
| Detach and reattach later, shell still running | server-side detachable sessions keyed by client id (reattach test) |
| Interactive apps (vim/htop/fzf) that probe the terminal work | server synthesizes DSR/DA/DECRQM replies |
| Client exits with the remote shell's status | exit code rides the final frame (`tests/net` session test) |
| `Ctrl-^ Ctrl-Z` suspends like a terminal's suspend key | the client sends itself SIGTSTP, so the shell reports it "Stopped" and `fg` resumes (`tests/e2e_pty_binary.rs`) |
