# koh

Ultra-minimal peer-to-peer remote shell, headless jobs, delta file sync, and interactive
[`fux`](https://github.com/gold-silver-copper/fux) sessions over [iroh](https://iroh.computer) QUIC.

Rewritten from scratch on `fux` 0.43 and `fuxix` 0.12 (about 6,200 lines of `src/` without its tests, down from ~22,000):

- **Layer 1 — Transport & Scoped Auth:** iroh QUIC (`koh/20`) with TLS-bound Ed25519 client proofs,
  compatible with existing `~/.config/koh/{client.key,server.key,servers,clients}` files, QR codes
  on `koh serve` / `koh id --qr`, and `--cp`/`--exec` path-scoped keys.
- **Layer 2 — Raw Streams & Delta Sync (no PTY):**
  - `koh exec`: raw separate stdout/stderr, binary-clean, stdin EOF, SIGHUP on disconnect.
  - `koh run` / `jobs` / `logs` / `wait` / `kill`: detached headless jobs backed by raw append-only
    log files (no 80-column wrapping, no screen truncation). The server ends them with `kill(1)`,
    which must be on its `PATH`; so must `id(1)` where `XDG_RUNTIME_DIR` is not set.
  - `koh cp` / `--sync`: `blake3` delta file sync (single or multi-source, `--delete`, `--exclude`,
    `-p`, `--dry-run`).
- **Layer 3 — Sessions are `fux` panes:**
  - A session is a `fux` pane on the server, in a `fux` session of koh's own beneath its state
    directory (`STATE/fux/koh-sessions/NAME`; `koh serve` prints the folder). `koh` has `fux`
    in it: the server starts a session with `koh fux start`, and the pane is kept by `fux`'s
    holder (the process `koh hold …`), not by `koh serve`: sessions live on when `koh serve`
    is stopped, and are there when it is started again. `koh fux …` is `fux …`, and it and
    `koh hold …` are words of this machine: they ask no server anything.
  - A session is shown by its **viewer, which runs on the server**: `fux`'s viewer, this
    binary again, on a terminal of the client's size that `koh serve` makes for it. What it
    draws is sent as it draws it, and what is typed at the client is typed into it (`koh/20`):
    the client's terminal shows the bytes, as with ssh. Nothing of the session's folder
    leaves the server, and the client keeps nothing: no copy, no file, no viewer of its own.
    Each `koh connect` has a viewer to itself, started when it attaches and gone when it
    leaves; a session nobody looks at costs its holder and its program, and nothing more.
  - `koh connect SERVER [--session NAME | --new] [-C DIR] [-- PROG…]` shows a session in
    your terminal. With a name it is that session, started if there is none; with none, the
    newest that lives, or a new one. Leave it with `Ctrl-] .` (`Ctrl-] Ctrl-]` types one
    Ctrl-]; any other key after it is typed after it). That is koh's one key, as `~.` is
    ssh's: `koh connect` reads it where you type it, in whatever form your terminal sends
    it, so it leaves with a link or without one, and also while the session's program reads
    nothing. What you typed before it is typed before koh leaves, where there is a link: it
    has a second for that, and a link that takes nothing holds the leaving no longer (with no
    link what is held is not typed, and koh leaves at once). What is no key going down
    between `Ctrl-]` and the dot (a click or a move of the mouse, a key let go, where the
    session's program asked to hear of those) is not typed when koh leaves. Every other key
    is the session's: `C-b` reaches a `tmux` or a `fux` there as it is typed. It ends with the session's program: with its status, with 128 + N if signal N
    ended it, and with 1 if nothing says how it ended (its holder was killed, the machine was
    restarted, its folder was moved). Left, hung up (a terminal that is closed) or told to
    end (SIGTERM), it ends with 0 and the session runs on.
  - **Your terminal is asked what it is like by `koh connect` itself, once**, and nothing is
    asked of it across the link, where an answer may come late and be taken for typing. Once
    it has dialled, before its first attach, koh asks which of the kitty keyboard protocol's
    flags the terminal takes, its foreground, background and cursor colours, and last what
    it is, which every terminal answers and which ends the asking: the first screen waits
    for that answer, a millisecond or so. (What you typed before koh asked, while it
    dialled, is typed: it is read first.) The answers go with every attach, with `TERM` and
    the size, cells and pixels, and the server writes them where the session's programs are
    answered from (`colours` and `keyboard` in koh's `fux` session: they are the server's,
    not one session's, and of two clients the last to attach is believed). So vim is told
    your background, and a program that asks for the kitty keyboard protocol has its keys in
    that form. What the terminal sends up to that last answer are its answers (one that
    tells no colour, or does not know the protocol, has those it gave and the plain
    keyboard); what it sends after it is what you typed, to the byte, and koh looks for no
    answer in it. **What you type between koh's question and that last answer is lost**: it
    is taken for answers. In a terminal on your machine that is a millisecond; where `koh
    connect` runs inside another session that is slow, it is that session's round trip. A terminal that does not give that last answer is waited on for a second,
    once for a `koh connect` and not again when a link comes back: it has no colours and the
    plain keyboard, and all it sent in that second was typed. Your terminal is taken to draw
    sixel pictures and 24-bit colours (one that does not shows nothing where the picture is).
  - **Without a link** koh says so and dials again: `koh: no link; reconnecting`, on your
    terminal's own screen, which is put back the moment the link is lost (nothing of the
    viewer's stays on: not the mouse, not the alternate screen). What you type while it says
    so is held and typed when the link is back, and `Ctrl-] .` leaves at once. A
    link that is silent is known to be lost after eight seconds. What was on its way when a
    link died may be lost. Nothing is ever typed twice. When the link is back a new viewer
    draws the whole screen as it is then: nothing of the old one is gone on from.
  - Sixel is the one picture format, as in `fux` 0.43, and your terminal is taken to draw it:
    one that does not shows nothing where the picture is. A picture is scaled by the size of
    a cell in pixels, which your terminal's window says (one that says none gets a line in
    the corner instead). A program that draws with the Kitty graphics protocol alone
    (`kitten icat`) shows nothing in a session.
  - `koh sessions SERVER`, `koh output SERVER --session NAME [--last]` and `koh wait SERVER
    --session NAME [--timeout SECS]` (each with `--json`) are answered on the server from a
    session's files, for a key with no scope. They read what a script there could. What is
    of several files (a line of `sessions`; for `--last`, and for what a `wait` returns, the
    marks and the text) is read between two looks at the same even `generation`; what is of
    one file (`output`'s screen, a wait's look at `marks`) is read as it is, since `fux`
    replaces a file whole. A session lives while its holder has the lock on its folder.
    - `sessions` lists each folder that has a `status`, the oldest first: its name, whether a
      client is attached, what `state` says became of its program (`running` only while the
      holder lives; `ended` where none does and nothing says how), whether a command runs,
      the last command's exit code, the size and the title.
    - `output` is the screen the session shows. With `--last` it is what the last command
      that has ended printed: the text from where its output began to where it ended, out of
      `history.1`, `history` and the main screen, each line whole however the screen wrapped
      it. The marks' lines and bytes say where that is; what is printed is text: a line
      break is added to a last line that has none, and bytes that are no UTF-8 are shown as
      U+FFFD. Where the shell has marked no output that ended, it is the screen.
    - `wait` is for the first command that ends after the server took the request: it prints
      what that command printed and exits with its code, the two read together. A second
      command that has ended by the time it looks is not the one it gives. When the session
      ends instead, it prints the last screen and exits as `koh connect` does; so too, with
      1 and nothing printed, when the session's folder is gone or another run has its name.
      After `SECS`: the screen, and 124. A `wait` is for a job or for a session: `JOB`,
      `--text` and `--tail` are not said with `--session` (exit 2).
    - `--last`, `wait` and "a command runs" go by the marks a shell puts at its prompts (OSC
      133): `prompt`, `command`, `output`, `end` in the pane's `marks`. A command runs while
      the last mark is `output`. `fux` numbers a pane's marks (`marks.dropped` and a mark's
      line in `marks`): a command has ended when an `end` is there with a higher number than
      the last `end` had when the wait was asked. Where a mark is on the screen is not
      asked, so a screen that scrolls, has a line inserted or is cleared ends nothing, and
      nothing is inferred. koh sets up no shell: `koh help-agents` has the lines for
      bash, and nearly the same three commands as a script over the files, for `koh exec`. In
      a shell that marks an `end` at every prompt, an empty line entered is an `end` too: a
      `wait` then returns the output and the code of the command before, again.

### Sessions: don't, and do

koh adds nothing to stop these. What happens instead is said.

**Don't**

- Don't `mv` a session's folder while clients are attached: they are told the session ended
  (1). It lives on, and is a session of its new name.
- Don't `kill -9` a `koh connect`: nothing is left to put your terminal back, which stays
  raw, on the alternate screen, with whatever the session's program had turned on. Type
  `reset` and Enter (you will not see it typed). Every other end puts it back.
- Don't look for the session's past in your terminal's own scrollback: the viewer draws on
  the alternate screen, which has none. `koh output SERVER --session NAME --last` prints what
  the last command printed, the session's `history` file on the server has all of it, and a
  `tmux` or a pager in the session scrolls as it does anywhere.
- Don't paste megabytes into a program that reads nothing and expect the rest of what you
  type to arrive: what is typed is typed as the program reads, in its order, and nothing of
  it is dropped, so it waits, as on any terminal. About a megabyte and a half waits on its
  way; past that your terminal itself waits with the paste, and takes no key, `Ctrl-] .`
  neither. Close the terminal then (koh is hung up and ends), or let the program read.
- Don't run `koh connect` in a terminal that takes longer than a second to say what it is
  (one reached over a path that slow) and expect a clean first line: its answers come after
  koh has stopped waiting, and are typed into the session, once, as the answers to any
  program that asks a terminal are when they come late.
- Don't expect `Ctrl-] .` to leave every time where your terminal sends keys in the kitty
  form over a path so slow that it cuts one key into pieces more than 10 ms apart: the first
  piece is an Escape by then, and is typed, and koh may not leave that time. Press it again.
  (koh keeps no piece back to see what follows: it would hold every Escape you type.)
- Don't type Escape and `Ctrl-] .` within a few milliseconds of each other and expect the
  Escape to be typed: `fux`'s viewer holds an Escape by itself for a moment, to see whether
  it starts a sequence, and ends with it when you leave. No hand is that fast; a script is.
- Don't expect a key's echo at once while a program floods the screen over a very slow link:
  at 64 kbit/s it was about five seconds and at most seven (measured: some 44 KiB of the
  flood's frames wait ahead of the link, in the server's pty and the stream's window, and the
  echo is drawn behind them); at 256 kbit/s under a tenth of a second. Typing with no flood
  is not held up.
- Don't start panes of your own in the sessions workspace: they are sessions to koh, counted
  against `--max-sessions`, attached to by a `koh connect` that names none, and the oldest
  ended one is removed to make room. A `fux view` of that workspace invites it: its keys for a
  new shell, the editor, the picker and the search start a pane where you look.
- Don't run `keys/.restore` on koh's `fux` session (it must be named for that: `.restore` alone
  does not look there): it starts every session that has ended anew, with whatever `fux` is on
  the path.
- Don't write `kill` to a session's `ctl` unless you mean it: it hangs up the program for
  every client. Any key with no scope may; it may run any command.
- Don't look at a session's folder with a `fux` of another version than koh was built with:
  `koh fux view` is the one that reads what koh's holders write.

**Do**

- After a stall, look at the screen before you type on. What you type while koh says there is
  no link is held (64 KiB; what is typed past that is lost) and typed on return; what was on
  its way when a link died may be lost, so a line can arrive without its beginning. A link
  that dies without a word, or a server that does (killed, its machine gone), is noticed when
  the connection has been silent for the eight seconds koh allows a session: what was typed
  in those seconds is lost with it. After a long cut the link is not back at once with the
  path: koh gives each dial five seconds and waits five between two, so a path whose
  handshake takes longer than that is not dialled with success.
- To take a session's size back, resize your terminal. A session has the size of the terminal
  that last changed: a second client of another size, or one that left, leaves it as it is,
  and a smaller terminal shows the top left of a larger session. A terminal resized while
  there was no link has its size taken when the link is back.
- To start a name again that has ended, remove its folder on the server (`koh exec box -- rm
  -r PATH/NAME`, the path `koh serve` printed). Until then `--session NAME` shows how it
  ended, and ends the same.
- On Linux, restart `koh serve` after you replace the `koh` binary. Until then no new session
  starts: koh runs itself by its own path, which is gone, and says "cannot run PATH (deleted):
  No such file or directory". Sessions that run go on.
- After the upgrade to this koh, end the sessions an older one started: a session is known
  by its `run`, which holders write since `fux` 0.43.3, and a pane without one is no session
  to koh (not listed, not attached to; its name cannot be started until its folder is
  removed). A holder keeps the code it was started with.
- If `koh serve` was killed outright, start it again before you count what is left: a viewer
  reads the end of its terminal and leaves by itself, and the folder of one that was killed
  too (`STATE/fux/.view.PID`) is removed when `koh serve` starts.
- Under systemd, give `koh serve`'s unit `KillMode=process` and the user
  `loginctl enable-linger`: else stopping the service, or logging out, kills every session.
  A session's holder and its program inherit the descriptors `koh serve` was itself given
  that are not close-on-exec (a socket the unit was passed, say): pass `koh serve` nothing
  its sessions should not hold.
- To see every session on the server as tabs: `koh fux view PATH`, the path `koh serve` printed.
- For `koh output --last` and `koh wait --session`, have the session's shell mark its prompts
  (OSC 133). Without marks `--last` is the screen, and a `wait` ends with the session or its
  time. For bash from 4.4, in the server's `~/.bashrc` (fux's README has the same lines):

  ```sh
  PS1='\[\e]133;A\a\]'$PS1'\[\e]133;B\a\]'; PS0='\e]133;C\a'
  PROMPT_COMMAND='printf "\e]133;D;%s\a" "$?"'
  ```
- Ask `koh wait --session` before you type the command it is to wait for (`koh wait … &`,
  type, `wait $!`): a command that has ended when the server takes the request is not waited
  for, and the wait is then for the next.
- If a `koh wait --session` says `the oldest still kept, not known to be the first (N marks
  came and went unread)`, more marks came between two of its looks than a pane keeps (a
  thousand: some 250 commands inside a tenth of a second, a script's doing). The first
  command that ended is then no longer listed: what it gives is the oldest that is, its code
  and its output, and it says so on that line (`detail`, with `--json`).
- End the sessions that a koh built on a `fux` before 0.43.2 started, if you `koh wait` on
  them: such a session's holder does not number its marks (its folder has no
  `marks.dropped`), and a wait for it is refused with a line that says so (exit 1). `koh
  sessions`, `koh output` and `koh connect` go on with it as it is.
- In a session, `fux start x` (or `koh fux start x`) starts `main/x` of **your own** `fux`
  session, not a koh session: `fux` reads no variable, and a name is a name in the default
  session.

## Quick start

```sh
# Client: print endpoint id
koh id

# Server: allow client and start serving
koh clients add laptop <client-id>
koh serve

# Client: save server and use it
koh servers add box <server-id>
koh exec box -- uname -a
koh exec box --sync proj -- cargo test
koh run box --name build -- make -j4 && koh wait box build
koh cp -r --exclude target ./src box:proj/
koh connect box
koh sessions box                       # each session: attached, running, busy, last exit code
koh wait box --session 1 --timeout 600 # until the command there ends: its output, its code
koh output box --session 1 --last      # what the last command printed
```

Run `koh --help` for the complete command reference and exit-code contract; `koh help-agents`
is the same and, after it, recipes: a session's files, and the three commands as a script.
