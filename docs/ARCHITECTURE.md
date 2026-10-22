# koh architecture

How koh is built. The [README](../README.md) covers what it does and how to use it; this is the
internals. Pair it with the [threat model](THREAT_MODEL.md).

## The one idea

koh relays the program's **output** to the user's terminal, as ssh does, and keeps the **screen**
on the server, as mosh does. The server runs the program on a PTY and feeds its output to a
terminal emulator of its own, which answers every question the program asks its terminal (device
attributes, cursor reports, colours), so the user's terminal is never asked; what the program wrote
otherwise goes to the client as it wrote it, and the client writes it to the user's terminal. The
user's terminal does the drawing, the scrollback, the search, the selection; nothing is drawn twice.

The screen on the server is what makes the link not matter: a client that attaches, redials or
falls behind is sent a **redraw** of the screen as it is, painted from the server's emulator, never
the backlog, so a drop costs a screen, not the minutes of output the link missed. And it is what
lets a script ask how a session stands (`koh sessions`, `koh wait --session`, `koh output`) with
no terminal at all. Keystrokes travel the other way on one reliable, ordered stream, as decoded
events the server encodes for the program. QUIC (through iroh) provides both, plus encryption,
authentication, loss recovery, congestion control, roaming and NAT traversal.

## Module layout

One crate, `koh`: a library (`src/lib.rs`) with everything but the command line, and the binary
(`src/main.rs`, `src/args.rs`). `Cargo.toml` forbids the panic lints for all of it, tests
included, so nothing uses a macro whose expansion `allow`s one: the command line is built with
clap's builder API rather than its derive, and tests build their tokio runtimes explicitly.

```
src/
├── main.rs          the binary: dispatch, exit codes, --json errors
├── args.rs          the command line (clap's builder API), `koh help-agents`
├── lib.rs           crate root: module declarations
├── request.rs       the opening request (what a connection is for) and the replies sent whole
├── proto.rs         the koh/17 shell protocol: client messages, what the program shows, caps
├── stream.rs        the output filter both ends run: questions out, marks apart, bounds
├── events.rs        decoded input (keys, mouse, focus, paste) and terminal colours on the wire
├── bounded.rs       fixed-capacity containers; the wire's bounded sequence decoding
├── terminal/        the server's emulator (ServerTerminal, fux-vt), Activity, sizes
│   └── redraw.rs    a screen painted for a terminal that shows nothing of it yet
├── predict.rs       local-echo prediction engine (overlays, epochs)
├── sync/            `koh cp`: a sync of trees, either way (send, receive, fsat, glob)
├── transport_iroh/  iroh endpoint setup, the default key path, idle timeouts
├── pty.rs           PTYs over fuxix: the session leader on each, its pumps, reaping
├── server/          `serve`: the gate, the registry and sessions, one task per connection
│   ├── cli.rs       the accept loop, the allowlist and scopes, the request's dispatch
│   ├── session.rs   detachable sessions and their registry; session/reports.rs, sessions.rs
│   ├── attach.rs    one connection to a session: input in, epochs of what is shown out, pacing
│   ├── exec.rs      `koh exec`'s command: a process group with no terminal, its pipes
│   ├── jobs.rs      `koh run`'s jobs, their logs, `koh logs`, `kill` and `jobs`
│   ├── wait.rs      `koh wait`: a job's end or text, a session's command or state, a file
│   ├── copy.rs      `koh cp` on the server
│   ├── place.rs     where a request's paths are, and a scoped key's directory
│   └── marks.rs     the startup files that mark a shell's commands
├── client/          `koh connect`'s loop and the commands that dial
│   ├── display.rs   the user's terminal: output, marks, reports, the overlay
│   ├── input.rs     what the user's terminal sends, decoded; the escape prefix
│   ├── cli.rs       sessions, output, run, jobs, logs, kill, wait, connect; exit codes
│   ├── exec.rs      `koh exec`: stdin to the command, its output back apart, its status
│   ├── copy.rs      `koh cp` at this end, and its summary
│   ├── probe.rs     the start-up questions to the user's terminal
│   └── backend/     KohBackend (raw mode, size, bytes, marks) + Tty (through fuxix::terminal)
├── identity.rs      loading and making identity keys
│   └── key_file.rs  KeyFile, the one owner of trust in a key path, and $KOH_LOG
├── log.rs           the `RUST_LOG` filter `serve` and `connect` install (`target=level` directives)
├── keycmd.rs        `koh id` and `koh key` — print the endpoint id, show the identities, reset one
├── names.rs         names for ids: `servers` and `clients` beside the keys, and client scopes
├── menu.rs          the menu `koh` alone opens on a terminal, over a reader and a writer
└── test_runtime.rs  unit tests' runtime and scratch directories, through koh-testkit
tests/net/           koh over a fault-injecting link between real iroh endpoints
tests/               PTYs, sessions, the binary on a PTY, commands, jobs and copies, names,
                     key creation races, the wire's round-trips and the corpus
testkit/             koh-testkit: what the tests share (starting programs, tasks, scratch dirs)
testing/corpus/      real programs' output (from fux), replayed by tests and bench
testing/bench/       the scoreboard: koh beside mosh and ssh (`testing/scoreboard.sh`)
```

`predict` and `proto` import nothing of the client or the server (CI checks it); `stream`,
`proto`, `request` and `sync`'s item types are pure.

## The protocol (koh/17)

The ALPN `koh/17` is the version check: a peer on another version fails the TLS handshake with a
clear error. A client dials from a key made for its process alone: iroh routes by endpoint id, and
two endpoints sharing one take each other's place at a relay and each other's paths, so every `koh`
the client runs at once would knock the others' links down. Its own key, the one the allowlist
names, it proves instead, as the first message on its first uni stream: a `KeyProof`, the key and
its signature over a label and 32 bytes exported from this connection's TLS session, which nothing
but this connection can reuse (`src/transport_iroh/mod.rs`, `prove` and `proven`; at most 128
bytes). The server reads it within the handshake's deadline, in the handshake's place, then checks
the allowlist for the proven key and takes a connection permit; a peer that proves no allowed key is
closed as not allowed. Then the client says what the connection is for, as the next message on that
stream (`src/request.rs`), a 4-byte length and its postcard encoding, at most 1 MiB, and the server
attaches or starts nothing before it. A client that makes no request within 10 s (the handshake's
deadline) is closed as breaking the protocol, and so is one whose request does not decode: a path
holding a NUL, a command over 256 KiB or 4096 words, no sources or more than 1024 are refused as
they are decoded. The request is one of:

- `Shell { pick, size, program, cwd }`: a session, at the client's window size; with a `program`
  (`koh connect SERVER -- PROG ARG...`), a new one running it in place of the shell; with a
  `cwd` (`-C DIR`), a new one starting there, refused with the close code `NoSuchDir` if it is
  not a directory. `Pick::Latest` is the peer's
  session attached last, else a new one; `New` always a new one; `Id(n)` that one, if it is the
  peer's; `Resume { run, session }` that one of that server run, which is how a client redials.
  The rest of the stream is the session's control stream. The server's first stream carries
  `Attached { at: Resume }`, which admits the client and says which session it reached.
- `Sessions`, `Output { session, last }`: the peer's sessions with how each stands, or one's text;
  answered whole on a stream.
- `Exec { run, together }`, `Start { name, run }`: a command, with no terminal, for the
  connection's life or as a job ([below](#commands-jobs-and-copies)); `Run` is its `Command` (`Argv`, words passed as they
  are, or `Shell`, a line for `$SHELL -c`) and the directory it starts in.
- `Jobs`, `Logs { job, follow, tail }`, `Kill { job, signal }`, `Wait(Wait)`: on the peer's jobs, and a
  wait on the server (a job, a session, a file).
- `Copy(Get { sources, opts } | Put { dest, sources, opts })`: a sync from or to the server.

Each answer is an `Answer<T>`: the reply, or a `Problem` (a kind, `ProblemKind`, and a message),
which the client says as text or as `{"error":{"kind","message"}}`, and maps to its exit code.
A refusal is a close code, never prose to match (`proto::Close`: `NotAuthorized` 1, `ProtocolError`
2, `SessionEnded` 3, `AtCapacity` 4, `CouldNotStart` 5, `NoSuchSession` 6, `OutOfScope` 7,
`Busy` 8). Only
`NotAuthorized`, `NoSuchSession` and `OutOfScope` make a shell's client give up; on the others it
redials and its status line says why. Then, for a shell (`src/proto.rs`):

- **Client to server: two uni streams** of length-prefixed postcard `ClientMsg`s, one for control
  (the first, its request's: `ClientMsg::stream` says which messages) and one for input (`Keys` and
  `Colours`), so a control message never waits behind input a program has not read: `Keys { seq,
  events }`, the input the client decoded (`src/events.rs`: keys, mouse events, focus changes and
  whole pastes of at most 1 MiB, at most 512 events a message), `Resize`, `Read { epoch, bytes }`,
  how much of the server's stream the client has read, `Redraw`, when it wants the screen afresh,
  and `Colours`, the user's terminal's colours, on each connection unless `--no-colours`. `seq`
  numbers each input on the connection.
- **Input is decoded on the client and encoded on the server.** The client reads what the user's
  terminal sends with fux-vt's decoder (legacy bytes, xterm's modifiers, the kitty keyboard
  protocol, SGR mouse reports, focus changes, bracketed pastes) and sends events; the session
  encodes each with fux-vt for the program's modes at that moment (`ServerTerminal::encode_input`:
  the kitty flags, modifyOtherKeys and cursor keys; the mouse tracking mode and encoding; mode 1004;
  bracketed paste, a whole paste framed in one go with every end marker removed, so no paste is
  ever left open). The program's modes reach the user's terminal with its output, so the terminal
  sends what the program asked for; a reattach from another terminal is sent them in the redraw,
  and changes nothing for the program.
- **Colours.** The client asks its terminal's foreground, background, palette 0–15 and scheme at
  start-up (and again when the terminal reports a new scheme, mode 2031) and tells the server; the
  server's terminal answers programs' OSC 10, OSC 11, OSC 4 for entries 0–15 and `CSI ? 996 n`
  from them, and sends a program that subscribed to mode 2031 the new scheme when a client brings
  one.
- **Server to client: a uni stream per epoch**, a tag byte (`SHOWN_TAG`) and the epoch's number,
  then length-prefixed `Shown` messages: `Out`, the program's output as the filter passed it, in
  pieces of at most 16 KiB that end where a sequence and a UTF-8 character end; `Mark`, a shell
  mark relayed apart; `Report`, the program's state; `Tty`, the PTY's echo and line modes, before
  the output they apply to; `Echo(seq)`, that the input up to `seq` had its time to show; `Bell`,
  the session's bell count; `Title`; `Exit`, the program's status; and `Beat`, at least every 3 s,
  so the client can tell a quiet session from a dead link.
- **An epoch begins with a redraw.** `terminal::redraw` paints the server's screen for a terminal
  that shows nothing of it yet: from a reset, the primary screen (with as much history above it as
  asked, as lines that scroll into the terminal's own scrollback), the alternate screen if it is
  shown, then the scroll region and margins, origin mode, the cursor and its shape, the pen and
  the open link, the input modes, the kitty keyboard flags, the title, and marks on the rows that
  start a prompt. What it cannot put back (character sets, tab stops, a cursor saved with DECSC, a
  palette the program set) comes right again once the program redraws. A client attaching afresh
  is sent 1000 rows of history; a redial none, as its terminal has them.
- **Pacing by what the client read.** The server writes an epoch no further than a budget past
  what the client said it read (`Read`): 256 KiB until the client's rate is known, then the rate
  it reads at times about a round trip, between 64 KiB and 4 MiB. So what the server has written
  is never far behind the program, and a slow link holds no backlog in QUIC's buffers.
- **A client too far behind is sent a new epoch.** The session publishes what the program shows
  as events on a broadcast channel of 128 (each event at most an `Out` of 16 KiB, so at most
  2 MiB of output a session); a connection that falls further behind than that, or whose client
  asks (`Redraw`), resets the epoch's stream, so QUIC stops sending what it missed, and opens the
  next with a redraw. The client takes an epoch's stream only if it is newer than the one it
  reads, and resets its mirror of the terminal with it.
- **Echo and the predictor.** The session tells each connection when its input had its time to
  show (`Echo`): once the program read it and its output since was relayed, or 50 ms after, as an
  echo-ack. The PTY's modes (`Tty`) go before the output they apply to, read from the PTY with
  `tcgetattr` at each read and every 100 ms while a client is attached. A resize waits until the
  program has read what was typed before it.
- **Backpressure:** PTY input goes through a writer queue of at most 1 MiB, and the session's
  input queue holds a bounded number of messages. While they are full the connection stops reading
  the client's input stream, and only that: it goes on reading the control stream, sending what is
  shown and seeing the connection close. The client keeps at most 1 MiB of typing behind its
  writer with an "input paused" status line, and its keyboard loop never waits on the network, so
  `Ctrl-^ .` always works.
- **Every queue is bounded** (`src/bounded.rs`): `clippy.toml` bans `VecDeque` and unbounded
  channels outside it, and every task spawned says, in an `#[expect]`, what bounds how many run.
  The wire's sequences (events, palette entries, words, sources, listed entries) are refused as
  they are decoded once past their bound, before anything is allocated for them.
- **Shutdown:** when the shell exits, the session drains its output and sends `Exit`; the server
  closes with `Close::SessionEnded` (3) once the client has read it. A session whose end no client
  was told keeps it for the client's redial, until the TTL.

### The filter

The program's output goes through `stream::Filter` twice: in the session, so that its clients
never see a question its emulator answered nor a mark the shell did not sign, and in the client,
so that a hostile server cannot make the user's terminal answer it either. The filter reads
output however it is split, and judges each escape sequence whole: questions (device attributes,
DSR and DECXCPR, DECRQM, XTVERSION, the kitty flags query, XTSMGRAPHICS, DECREQTPARM, the
locator, window reports, DECRQSS and XTGETTCAP, colour and palette queries, clipboard reads,
ENQ, DECID) are dropped; OSC 133 is taken out, relayed as a `Piece::Mark` (the session's nonce
removed, a state report never) or dropped; clipboard writes pass only as base64 of at most 16 KiB
and titles cut to 256 characters with no control; the clipboard and links are dropped when the
user turned them off. Everything else passes as the program wrote it. A control string longer
than 1 MiB, or a control sequence longer than 256 bytes, is dropped to its end, so a filter
holds at most that.

### The display

`client::Display` writes to the user's terminal. It feeds what it writes to a mirror, a fux-vt
parser with no history, which says where the cursor is, which screen is shown, what is under a
cell; the predictor reads the mirror's `fux_vt::Screen`.
Over the program's output it paints an overlay: the predicted echo of what was typed, and the
status line on the last row. The overlay is taken back before anything else is written (the cells
it covered painted again from the mirror, the pen and the cursor put back), so the terminal is
always where the program left it, and it is painted only where that can be done: on the primary
screen, the cursor not waiting to wrap, no origin or insert mode, no link open, no synchronized
frame under way, and between two sequences. On leaving and on a suspend, the display puts back
every mode the program set and resets the palette and the dynamic colours.

### The shell's marks (OSC 133)

A shell with shell integration marks where each prompt starts (`OSC 133 ; A`), where a command's
output starts (`C`) and where it ends, with its status (`D ; status`), so a terminal (or fux, which
answers `· done STATUS` and `last-output` by them) knows when a command typed into it ended, how, and
which output was its. The server's emulator keeps them (fux-vt's `Feature::PromptMarks`), for
`koh sessions`, `koh wait --session` and `koh output --last`, and its filter relays them to the
client as `Shown::Mark`, apart from the output, at the place in the output they came: the client
writes each again where the output before it left the cursor, with the nonce the user's terminal
asks for (`FUX_MARK_NONCE`). So every mark the shell wrote reaches the terminal once, in order,
at its place, however the commands came: two commands ending between two of the client's reads
are two ends, each with its status. The redraw a client is sent on attaching marks the rows the
screen shows that start a prompt, and where a running command's output began, if it shows.

**The state report** (`OSC 133 ; S ; activity=STATE`, the contract fux wrote with koh) tells a
terminal what the remote program is doing, which it cannot see itself: locally it sees only `koh
connect` waiting on the network. The session probes its PTY's foreground program (`Pty::activity`,
fuxix's `terminal_activity`, the probe fux runs on its own panes, `busy` as fux's own check has it
while keys wait unread in the terminal or output waits unread on the master): `reading` its terminal with no
time limit, `polling` it with one, `waiting` on something else, `busy`, `idle` (macOS) or
`unknown`. The session makes a report (`server/session/reports.rs`, time passed in) once input is
written to the program, though the state is unchanged; on a change, probed every 20 ms while a
client is attached; after the shell's `C` or `D`, right behind the mark on the stream; and after a
resize. An unchanged state is reported again no sooner than 10 ms after the last, but after a
mark. The report goes as `Shown::Report { activity, input }` in its place among the output, after
the output read before it (none left unread in the reader's queue, and what is held for the
modes' read let go first), with the newest of this attachment's inputs written to the program
before it was probed; the client writes it only if that covers all the input it sent on the
connection (one made before the server had its last keys is dropped: the one owed after them
follows), and writes the last one again after any mark (fux forgets a report at a mark). A program that polls
its terminal while it prints is told `polling`: it may draw on its own.

The program's end says whether it read every key written to it: `Shown::Exit { code, read }`,
`read` the newest of this attachment's inputs written to it if none was left in its terminal or
on its way there as it ended (`Pty::keys_left`, which on Linux still counts what a program left
unread in a terminal it closed; macOS empties that queue at the last close, so there `read` is
`None` once the program closed its terminal). A client whose every input that covers writes `activity=ended` before it
leaves, once: a terminal that saw no report after its last keys (an editor that read its save and
quit at once, and ended without reading again) knows they reached it, and that any it sent after
went nowhere.

What a terminal can rely on: a report written after its own last input to `koh connect` was probed
after that input was written to the remote program's terminal; a report follows every mark koh
writes; and every report and mark carries the terminal's nonce. What it cannot: a state from
between two probes. On macOS the probe says only `busy`, `idle` or `unknown`. `koh sessions` says
each session's last report and whether a command runs, so a script sees the same state without a
terminal.

**koh marks the shells it starts** (`server/marks.rs`), as fux marks its own, so that this works on
a server nobody set up: a session's bash, zsh or fish, started plainly (`$SHELL`, or a lone
`--shell`, with no argument; one given any is left as it is, as is any other program), reads the
user's own startup files, then marks each command. bash is given `--rcfile` with a file that
sources `~/.bashrc` and then puts the marks first in `PROMPT_COMMAND` (an array's first element,
after which the user's own hooks run with `$?` and `PIPESTATUS` as without koh), at the start of
`PS1` and at the end of `PS0` (a bash older than 4.4, such as macOS's 3.2, is left unmarked); a
variable the user made readonly is left unmarked. zsh is given a shim `ZDOTDIR`
whose `.zshenv` puts the user's `ZDOTDIR` back, sources their `.zshenv` and adds a `preexec` and a
`precmd` hook; fish an `--init-command` adding two event handlers. The files are written once a
shell needs them, in a directory of this server run (`koh-shell-marks-PID-RANDOM`, 0700) under
`$XDG_RUNTIME_DIR`, else the system's temporary directory; it is made with `mkdir`, which never
follows a symlink, and checked to be the user's own and private before each write, its parent
checked to be writable by no other user (or sticky), and each file written beside its name and
renamed into place; the directory is removed as the server stops. `koh serve --no-shell-marks`
starts the shells as they are, for a user with an integration of their own or a shell koh
misreads.

Each marked shell is given a nonce (`__koh_k`, 64 random bits, a new one for every session, not
exported to what the shell runs), its marks carry it (`133;D;1;nonce=…`), and its session counts
and relays only marks that do (fux-vt's `require_mark_nonce`, and the filter's `Marks::Signed`).
So a program the shell runs cannot end or start a command: not `cat` of a file holding marks, not
a shell of its own (ssh, a nested koh, a terminal multiplexer's shells), and not a shell's own
integration, which is how fish 4 (which marks natively) or a user's own bash integration is not
counted twice. For a program koh does not mark, and with `--no-shell-marks`, every mark counts:
then the marks are whatever the program and what it runs send. The marks a client writes never
carry the session's nonce, and the client drops every mark in the output itself, so only the
relayed ones reach the user's terminal.

## The predictor

The client guesses what each keystroke does to the screen and shows it immediately, as the
overlay, then confirms or corrects it against the mirror once the program's echo came. Confirmation
is driven by the server's **echo-ack** (`Echo(seq)`: "your input up to `seq` had its time to
show"), not the raw network ack.

**The PTY's modes.** Each screen carries how the program's PTY takes typed keys (`TtyModes`: the
kernel's echo and line mode, read with `tcgetattr` through fuxix at every read and every 100 ms
while a client is attached, as a program may turn echo off without writing; `Shown::Tty`). Line mode without
echo is a password prompt (`getpass`, `read -s`, sudo, ssh, passwd): nothing typed is predicted
and every prediction is dropped, however trusted the session was. The modes the client holds
can lag the PTY's by a read interval (a program that prints its prompt, then turns echo off), so a
key typed within 200 ms of a frame that moved the cursor to another row (a fresh prompt) is not
predicted until the server has reflected it (`PredictionEngine::hold`); the hold keys on the cursor
row's index, the history's newest row and the rows the frame moved, so it engages at the bottom of
a full screen, where Enter scrolls. Kernel echo is trusted
from the first key otherwise, until a key the predictor does not model (Tab, say), whose echo it
then waits for. Otherwise (a line editor, a full-screen program) the epoch logic decides: the first key
of an epoch stays hidden until the server's echo confirms it, and a mispredict kills its epoch. A
reconnect to the same session carries the trust it had, given once the first output shows no
password prompt, and only once the modes are known.

The predictor takes edit keys only (focus changes never reach it), and predicts only in a
`Context`, which can be built only on the primary screen with the PTY's modes known and not a
password prompt, so tmux's or screen's prefix and full-screen programs are never read as readline.
A typed glyph is guessed only onto blank cells, borrowing its left neighbour's style (hidden
included), and nothing else on the row moves, so a right-side prompt (zsh's `RPROMPT`, fish's) or
a full-screen program's border never contradicts a guess; typing over text waits for the echo. A
line starts where the screen shows the Enter that began it, and dies with discarded guesses;
Backspace and Left stop at it. A character that continues the glyph before the cursor (a combining
mark, a skin-tone modifier) joins it, or nothing is predicted. Prediction is **always on** in koh, so keystrokes engage on every link. Predictions are drawn plain, not underlined,
and a cell it knows changed but not to what is not drawn at all, so the real cell shows.

It predicts typed keys, whatever bytes the user's terminal sent for them (more than 32 in one read
are a paste or a program writing to the terminal, not typing, and are not predicted): printable
graphemes, double-width ones as two cells (the right one never confirms an epoch), Backspace at the
end of the line, Enter, and the left and right arrows (not under kernel echo, which echoes them as
`^[[D`). The line editor's own keys (`Ctrl-W`, `Ctrl-U`, `Ctrl-A`, `Ctrl-E`, Home, End, `Alt-B`,
`Alt-F`) are not guessed: they wait one round trip. Other keys and control sequences open a fresh
epoch but make no guess. A wrong or unconfirmed guess is always reconciled away: the overlay is
taken back before the program's output is written.

## Reconnect & detachable sessions

Sessions are **detachable**: the server keeps your shell (and its live screen) running after a
disconnect, keyed by your client endpoint id and a number, so reconnecting from the same client
drops you back exactly where you left off. A client may have several: `koh connect --new` starts
another, `--session N` picks one, and `koh connect` alone the one attached last (a new one if it
has none); `koh sessions` lists them. Numbers are server-wide and only rise during a server's run,
and `--max-sessions` bounds all peers' together; a reattach is always allowed. A detached session
is reaped after `--session-ttl-secs` (default 24 h).
One whose shell exited is kept until a client was told its end (or the TTL ends), so a
reconnect after the exit sees the exit and its status, not a fresh shell.

The reconnect is **automatic and in-process**: the client doesn't exit when the link drops. A brief
outage (e.g. a phone screen-off — Android freezes the process, so QUIC keepalives stop) is ridden
out on the same connection thanks to a 5-minute connection idle timeout. A longer outage times the
connection out; the client then transparently re-dials and reattaches to the same server session,
holding the last screen under a `reconnecting…` status line in the meantime. One display and
one input machine live for the whole run and one loop drives them, connected or not: only what
belongs to a connection (its streams, epoch and echo-ack) is made anew, so the escape keys, the
window size and the colours work during the outage and carry across it; the redial's epoch begins
with a redraw of the screen as it is. Typed input does not: what is typed while the link is down is not taken (nor predicted),
and the status line says so. A redial asks
for the session the first connection reached, by its number in that server's run
(`Pick::Resume`), never for another: if it is gone (it expired, its shell's end was seen, or the
server restarted) the server says `NoSuchSession` and the client ends saying so, rather than
landing in a new shell where keys typed at the old screen would run. Typing is still not carried
across the drop: the end of a line whose start was lost with the link must not run alone
(`false && rm …` typed across the drop must not run `rm …`). A **wall-clock freeze
detector** turns a multi-minute wake-up hang into a ~1–2 s reattach: if real time jumps more than
20 s between two (≤50 ms-cadence) loop iterations, the client concludes the process was suspended,
drops the (almost certainly dead) connection, and re-dials immediately. The first iteration
measures from when the connection was dialed, so a freeze while the client starts (probing the
user's terminal, entering raw mode) counts too. A sub-20 s glance still rides out silently on the
existing connection.

The client loop's `select!` is the only place it waits: each writer task opens its stream,
a redial is a polled future, and a closed resize channel is disabled, so a server that grants no
stream cannot block quitting or signals. The session's first phase asks the user's terminal its
start-up questions on stdin's one decoder, with answers expected, so a late answer is still an
answer and never reaches the program as keys. On a `SessionEnded` close, what is in flight is
written first, so the exit status is not lost. A suspend waits for SIGCONT (or a key, or a fatal
signal) before taking the terminal back. A refused redial (`NotAuthorized`, `NoSuchSession`) ends
the client with the reason; any other close is redialed, the status line saying why.

> **`--direct` and server restarts:** transparent re-dial targets the *same* address it first
> dialed. By default `koh serve` binds an ephemeral UDP port, so a restarted server is elsewhere and
> a `--direct <ip:port>` client redials the old port forever. `koh serve --port <PORT>` binds a fixed
> port (IPv4, and IPv6 where the host has it), so the restarted server is where the client looks,
> and finds that its session died with the old server: it ends saying so, and `koh connect` again
> starts a new one. A
> server stopped with SIGTERM closes its connections, so clients redial at once; one that died
> without closing them (SIGKILL, a crash, a power cut) leaves them to notice through the 5-minute
> idle timeout. The relay/discovery path (a bare endpoint id) re-dials by node id and follows the
> server across address changes.

## Sessions, connections and the bell hook

A session is one PTY + emulator, a peer's, by number (`server::session`). Its program leads a
session of its own with the PTY as its controlling terminal: `fuxix::pty::Slave::spawn` marks
every inherited descriptor close-on-exec, calls `setsid` and takes the PTY between `fork` and
`exec` (the `unsafe` that needs stays in fuxix), and std reports a failed `exec` to the spawn.
Two connections from the
same peer can briefly share it, when a reconnect races the old connection's teardown, so the
per-connection state never lives in the session:

- **Echo-ack is per connection.** Input sequence numbers are the client's (one client's rise
  across its reconnects; two clients' have nothing in common), so each input's echo is told only
  to the connection that sent it (`Event::Echo { attach, seq }`). A session-global ack would hand
  one connection another's numbers, and its predictor would treat every keystroke as already
  acked.
- **What is shown goes to every connection.** The session task publishes what the program shows
  on a `tokio::sync::broadcast` of 128 events; each connection holds a receiver, and one that lags
  past it is sent a new epoch (a redraw), so no connection holds the session back.
- **Detach on drop.** A connection holds a `SessionClient`, whose presence receiver is its
  attachment, so dropping one (on return **or** panic) detaches with no message to lose. The
  session starts the TTL when the last one drops and tears itself down at the TTL. Input comes only
  from the newest attachment, and only while the program runs. `Registry::end(peer)` ends all of a
  peer's sessions, and `Jobs::end(peer)` its jobs, as revoking it does.
- **A listing asks each session.** `Registry::sessions(peer)` takes the peer's sessions from the
  registry, which never waits on one, then asks each how it stands (attached or since when not,
  its size, title, exit, its program's state, whether a command runs and the last one's status),
  waiting 2 s at most.
- **How a session ends.** Its program's exit is looked for at every tick. It ends once the exit is
  known and its output drained; after a 1 s grace if the program closed its terminal and ran on
  (as hung up, 129, which teardown makes true); or 5 s after the exit if a job left in the
  background keeps writing. Its `Exit` goes to every client attached; once one has read it, the
  session ends and the server closes with `SessionEnded`; else the session is kept, with its end,
  for the reconnect. Teardown is
  awaited, the reaper is drained, and the registry's `Sessions` forgets a session only once its task
  has ended, so a late end cannot unregister the session that replaced it.
- **The bell hook.** `--on-bell <cmd>` / `ConnectConfig::bell_command` runs `sh -c` when
  the remote bell count climbs: detached (fds on `/dev/null`), `KOH_*` scrubbed except
  `KOH_BELL_COUNT` / `KOH_TITLE`, rate-limited to one spawn per second with bursts coalesced, the
  child reaped off the session loop. The decision is a pure `BellHook::observe`.
- **The hook's environment and its first frame.** `BellHook::command(count, title,
  parent_env)` builds the child from an explicit parent environment (`env_clear`, then everything
  but `KOH_*`, sharing `pty::is_koh_env_key` with the PTY spawn), so the scrub is tested with a
  synthetic environment rather than assumed. The bell count is cumulative per server session, so
  the first count the run hears (`Shown::Bell`, in each epoch's start) `prime`s the hook: bells
  from before this attach do not fire it. The hook
  outlives a reconnect and is not re-primed, so bells during an outage do.

## Commands, jobs and copies

`koh exec`, `koh run` and the requests on jobs, `koh wait` and `koh cp` are a connection each,
with no session and no terminal, through the same gate, permits and request as a shell. Where a
request's paths are is `server::Place`: as the server user's shell takes them (`~`, `~/x`,
relative in the home, unglobbed), or, for a scoped key, beneath its directory.

- **`koh exec`** (`server::exec`, `client::exec`) runs its words as they are, the program found
  on the server's `PATH`, or with `--sh` a line by `$SHELL -c` (else the platform's `sh`), in the
  server user's home or the directory asked (`-C`), with a session's environment but `TERM`, as
  the leader of a session of its own (`fuxix::process::lead_session`, which also closes every
  inherited descriptor), so it has no controlling terminal. It starts at once: the rest of the
  client's stream is its stdin, read by the client from its own stdin on a thread
  (`client::io::spawn_stdin`), whose end is the command's. Its stdout and stderr go back on a
  stream each, tagged (`request::ExecStream`), a chunk at a time, flushed as they come. Two pipes
  and two streams do not keep the order between them that a program wrote them in, so when the
  client's stdout and stderr are one file (`2>&1`, a terminal) it asks for them `together`: the
  command's stderr is its stdout's pipe, all of it sent as its stdout, in its order. Then its
  `ExitStatus` on a third (its code, or 128 plus the signal; or that it did not start, which the
  client says as 127 for no such program and 126 for the rest, as `koh run` says a job that did
  not start), once both have ended, or, once it
  exited, gone quiet for 100 ms (a job it left in the background holds the pipes). A slow reader
  on either end holds the other back through the pipes and QUIC's flow control. A lost connection
  (the command connection's idle timeout is 10 s, so a killed client is found within it),
  revocation, the server's shutdown or the client's signal hangs the command up: SIGHUP to its
  process group, and the reaper sends SIGKILL to the group after a second's grace, reaping the
  leader only then, so the group's id cannot have been reused. The client exits with the status
  (141 if its own stdout closed, as SIGPIPE would), or 255 on its own errors, as ssh does.
- **Jobs** (`server::jobs`): `koh run` starts a command as `koh exec` does, with stdin
  `/dev/null`, its stdout and stderr one pipe, into a log of the newest `--job-log-bytes` (4 MiB
  by default; the oldest dropped and counted), and answers with its name at once; the job runs
  until it exits, is signalled (`koh kill`, to its process group), or the server stops, which
  hangs it up (129). A job is its peer's, by name (given, or the next number; one that ended is
  replaced by a new one of its name); at most 64 are kept, an ended one given up first for a new
  one, and an ended one is forgotten after the session TTL. `koh logs` sends the log, its last
  `tail` lines if asked (the client asks for 200 unless `--all`, saying how many it left out:
  `LogMsg::Cut`), and with `--follow` what comes until the job ends; then its status if it ended
  and how long it ran or has run (`LogMsg::Dropped`, `Cut`, `Data`, `End { exit, secs }`), which
  the client says on stderr (`· running 34s`, `· exited 101 after 34s`). `koh wait` on a job's
  end then asks for its last lines (200 unless `--tail N`). `koh jobs` lists them.
- **`koh wait`** (`server::wait`) waits on the server, for as long as its connection lasts: for a
  job to end (its status), its log to hold a text, or a file to exist; for a session's running
  command to end (the one running as the wait began: at once if none), its program to read its
  terminal (the state report's `reading`), or a text on its screen. A file under a scoped key is
  looked for through no symlink. The client gives up at `--timeout` (124).
- **`koh cp`** (`sync`, `server::copy`, `client::copy`) is a sync, the same whichever end is the
  server. The sender walks its sources (each followed if it is a symlink, as `cp` follows its
  arguments, but not under a scoped key), its tree as it is (symlinks as symlinks, fifos, sockets
  and devices said `Skipped`), at most `MAX_DEPTH` directories deep, and sends a header for each
  entry (`sync::Item`: `Dir`, `File`, `Symlink`, with a `Name`, no `/`, NUL, `.` or `..`, a mode
  of at most `0o7777` and a time), each at most `MAX_ITEM`, running ahead of the answers by
  `WINDOW` files (the receiver refuses more waiting than that). The receiver answers each file
  (`sync::Answer`): `Want { have, prefix }`, all of it or the rest of a part it kept (whose
  start's hash the sender checks), or `Check { hash }`, the blake3 hash of a file of the same size
  it has, which the sender answers with the bytes or `Same`. A file's bytes go in chunks of at
  most `CHUNK` to `.koh-HASH.part` beside it and are renamed over it once whole. In a dry run
  (`Opts::dry_run`) the receiver makes, writes and removes nothing, and the sender answers each
  file it would send with `Differs` in place of its bytes; the receiver lists each change in its
  `Summary`. Every entry is reached from the directory above it by its descriptor with
  `O_NOFOLLOW` (`sync::fsat`), so no name reaches outside the destination or through a symlink.
  Directories merge; the destination's missing parents are made; a file written gets its arrival
  time unless `-p`, and modes land less setuid and setgid; a directory gets its mode and time once
  none of its files waits for bytes. `--delete` removes what the source does not have from each
  directory it merges into, once the source said all it holds; `--exclude` patterns
  (`sync::glob`) match a name, or, holding a `/`, a path from the top of the tree copied, the same
  at both ends. The receiver ends with a `Summary`, which the client says in one line or as JSON.
  Each end runs on a blocking thread, joined to the stream's task by a bounded channel
  (`sync::send_on`, `sync::receive_on`).
- **Scoped keys** (`names::Scope`, `server::cli::permitted`): a client saved with `cp=DIR` gets
  copies beneath `DIR` and waits for a file there; with `exec=DIR`, commands and jobs started in
  `DIR`; with no scope, everything. Any other request closes with `OutOfScope`. A scope changed
  in `clients` closes the client's connections, as a removal does.

## Output for scripts

Every command but `connect` works with no terminal. `--json` makes a command say one JSON value on
stdout (`client::cli::Format`), and a failure `{"error":{"kind","message"}}`, its `kind` the
`ProblemKind`'s name. Exit codes are one table (`main.rs`): 0 ok, 1 failed, 2 usage, 3 not
reached, 4 refused or out of scope, 124 a wait timed out; `exec`, `wait` and `logs --follow` pass
the remote status through (255 for koh's own error). `koh help-agents` is the page a script or an
agent needs, kept short. While `exec` or `wait` runs inside a terminal that reads state reports,
the client reports `busy` (`report_busy`), so the terminal does not take the wait for a program
waiting for input.

## Security internals

The trust boundaries and the defenses at each are in the [threat model](THREAT_MODEL.md); each
finding fixed, with the tests that guard it, is in [SECURITY.md](../SECURITY.md). These hold by
construction rather than by care at each call:

- **What a peer chose is escaped where it is written.** koh writes outside the session only to one
  sink, its stderr and its log, a whole line per write, so lines never interleave. A peer's text
  goes in only as `log::Peer`, one line of printable ASCII; `std::io::stderr`, `eprint!` and
  `eprintln!` are banned elsewhere (`clippy.toml`). Close reasons are codes, not text.
- **Unknown is never "no".** The saved allowlist is read by one task; a read that fails keeps the
  last good list and warns once, and one that drops a client is taken only once the next, 0.5 s
  later, agrees, so neither a typo nor an editor saving the file (missing or empty a moment)
  disconnects anyone. A client added or removed is seen within 2 s. Removing one closes its
  connection and ends its session, and the registry attaches no peer the list no longer allows.
- **What a server makes the client keep is bounded.** The client reads one epoch's stream at a
  time, a message at a time (at most 17 KiB), into a filter that holds at most one sequence and a
  mirror with no history; a reply is read whole only up to its bound (`MAX_REPLY`, `MAX_OUTPUT`
  for a session's text).
- **Shutdown and handshakes.** One task counts SIGTERM, SIGINT and SIGHUP (unless SIGHUP was ignored at start,
  as `nohup` does): the first drains, a
  repeat within 1 s (a double SIGHUP on a terminal's close) is the same, and a later one forces an
  exit with a nonzero status. At most 256 handshakes are pending; when all the room is taken, a
  new one gives up the oldest of the address holding the most (an IPv6 /48 counts as one, and
  those through a relay as one), so a burst from one client (an agent's parallel commands) is all
  let through while a flood gives up only its own. They hold no connection permit. When room would
  cost one under way, an address not yet validated is first sent a QUIC retry, which a spoofed one
  never answers. So a flood from spoofed addresses takes no room; one from enough real addresses
  can still give up an allowed client's handshake, and delay it, while it lasts. An allowed
  client's connection past `--max-connections` waits up to 10 s for room, among at most as many
  waiting; past them it is closed as `Busy` ("server busy: too many connections at once; retry"),
  which the client says, exiting 75.

## Testing

Everything but real devices runs headless, on one machine, in `cargo test`; each test says what
it guards in its name and comment.

- **Unit tests** beside the code: the filter, the redraw, the wire's round-trips and caps, the
  pacing budget, the display's overlay, the predictor, and the sync (cut anywhere and resumed,
  nothing landed through a symlink or outside a scoped directory).
- **`tests/net/`**: a real server and client on iroh endpoints joined only by an in-process
  fault-injecting link (`tests/net/link.rs`): loss, delay, reordering and outages under real QUIC;
  convergence, ordered input, reattach, resize, backpressure, the bell hook, prediction, and
  hostile clients and servers.
- **`tests/pty.rs`, `tests/sessions.rs`**: real programs on real PTYs, the session registry, and
  the real accept loop over loopback iroh.
- **`tests/e2e_pty_binary.rs`, `tests/commands.rs`**: the real `koh` binary, on a PTY or as a
  command: connect, suspend, exec, jobs, waits, copies, scoped keys, and a relay shared by one
  key's processes.
- **`tests/corpus.rs`**: real programs' output (`testing/corpus/`, from fux) through the server,
  the wire and the client's display; a terminal reading what the client wrote must show what one
  reading the program's output does, and so must one fed the server's redraw.
- **Fuzzing** (`fuzz/`, weekly in CI): every decoder a peer reaches, the program's output through
  the emulator and filter, and the user's terminal's input.

Test crates start with `#![forbid(clippy::disallowed_methods)]`: they start programs, spawn tasks
and make scratch directories only through **`koh-testkit`** (`testkit/`). Terminal I/O is behind
`client::backend::KohBackend`, so the client's loop runs against a capturing terminal in tests.

Beside the tests: the scoreboard (`testing/scoreboard.sh`, `testing/bench/`) measures koh beside
mosh and ssh (bytes on the wire, keystroke latency under a flood, server memory); the Android
scripts (`testing/android/`) run the real binary on an emulator over `adb`: the Android DNS path,
stress, netem loss, and a malicious peer. A real phone over a real radio is the last, manual check.

## Acceptance criteria (mosh feel)

| Property | How koh delivers it |
|---|---|
| Keystrokes appear instantly on every link | predictor (shows once the server proves it echoes; confirmed by its echo) |
| Survives suspend/resume + IP change, re-syncs to current screen | QUIC connection migration + a redraw of the screen as it is (no backlog) |
| A burst of output on a slow link never delays the current screen | pacing by what the client read; a client too far behind gets a new epoch, the old stream reset |
| Password prompts show no predicted echo | emergent no-echo suppression in the predictor |
| Reconnect lands you where the screen is *now* | a redial's epoch starts with a redraw of the current screen |
| Detach and reattach later, shell still running | server-side detachable sessions keyed by client id (reattach test) |
| Interactive apps (vim/htop/fzf) that probe the terminal work | server synthesizes DSR/DA/DECRQM replies |
| Client exits with the remote shell's status | `Shown::Exit` (`tests/net` session test) |
| `Ctrl-^ Ctrl-Z` suspends like a terminal's suspend key | the client sends itself SIGTSTP, so the shell reports it "Stopped" and `fg` resumes (`tests/e2e_pty_binary.rs`) |
