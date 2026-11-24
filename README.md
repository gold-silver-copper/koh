# koh

Ultra-minimal peer-to-peer remote shell, headless jobs, delta file sync, and interactive
[`fux`](https://github.com/gold-silver-copper/fux) sessions over [iroh](https://iroh.computer) QUIC.

Rewritten from scratch on `fux` 0.43 and `fuxix` 0.12 (~5,800 lines, down from ~22,000):

- **Layer 1 — Transport & Scoped Auth:** iroh QUIC (`koh/19`) with TLS-bound Ed25519 client proofs,
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
  - A client has a **mirror** of the session: a copy of the pane's folder that koh makes and
    alone writes, brought up to date in rounds (`koh/19`). A round is checked whole before
    anything of it is done to the mirror, and what a server may not send changes nothing. (A
    disk that fails while a round is done can leave it part done, under an odd `generation`:
    the next attach that succeeds puts it right.) What is typed into the mirror's `in` and `ctl` is typed
    into the session's.
  - `koh connect SERVER [--session NAME | --new] [-C DIR] [-- PROG…]` shows a private mirror
    with `fux`'s viewer, in the same process. With a name it is that session, started if there is
    none; with none, the newest that lives, or a new one. Leave it with `Ctrl-] .` or `C-b d`
    (`Ctrl-] Ctrl-]` and `C-b C-b` type the key itself). It ends with the session's program:
    with its status, with 128 + N if signal N ended it, and with 1 if nothing says how it
    ended (its holder was killed, the machine was restarted, its folder was moved).
  - `koh mount SERVER [--session NAME | --new] [-C DIR] [MIRROR] [-- PROG…]` keeps a mirror
    for any `fux view`, `cat` or script: in `MIRROR`, which koh makes (a folder that is there
    is not taken), or with none in a `fux` session of koh's own on the client,
    `K/fux/koh-mounts/SERVER.NAME` (`K` is `$XDG_RUNTIME_DIR/koh`, else `~/.cache/koh`; the
    server's part is cut to fit a pane's name, 64 characters). Nothing of koh's is in your own
    `fux` session unless you name a folder there. It ends as `koh connect` does, with the
    session's program and its status. The mirror is removed when the session ends or koh is
    stopped: SIGINT, SIGTERM, or SIGHUP, which a terminal that is closed sends (`koh connect`
    removes its private folder then, too). Stopped so, both end with 0. A mirror has no `status` and no `command`: its program
    and its holder are on the server.
  - **Without a link** koh says so (in the viewer's corner; `koh mount` on its standard error)
    and dials again. What you type while it says so is held and typed when the link is back.
    What was on its way when a link died may be lost. Nothing is ever typed twice.
  - Sixel is the one picture format, as in `fux` 0.43. A program that draws with the Kitty
    graphics protocol alone (`kitten icat`) shows nothing in a session, and a picture is drawn
    only in a terminal that draws sixel.
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
      the last mark is `output`. A command has ended when there is one more `end`: where the
      marks are on the screen is not asked, so a screen that scrolls, has a line inserted or
      is cleared ends nothing. koh sets up no shell: `koh help-agents` has the lines for
      bash, and nearly the same three commands as a script over the files, for `koh exec`. In
      a shell that marks an `end` at every prompt, an empty line entered is an `end` too: a
      `wait` then returns the output and the code of the command before, again.

### Sessions: don't, and do

koh adds nothing to stop these. What happens instead is said.

**Don't**

- Don't `mv` a session's folder while clients are attached: they are told the session ended.
  It lives on, and is a session of its new name.
- Don't change a session's folder by hand and expect clients to follow. A file rewritten in
  its middle in place goes whole each time, or is not seen if its length and time did not
  change (replace it, or add to its end). A file made a folder, or a folder a file, ends every
  attached client with "no name for it". A name with a dot first, a folder inside a folder,
  and anything that is no file, folder, link or FIFO are not carried.
- Don't start panes of your own in the sessions workspace: they are sessions to koh, counted
  against `--max-sessions`, attached to by a `koh connect` that names none, and the oldest
  ended one is removed to make room. A `fux view` of that workspace invites it: its keys for a
  new shell, the editor, the picker and the search start a pane where you look.
- Don't run `keys/.restore` on koh's `fux` session (it must be named for that: `.restore` alone
  does not look there): it starts every session that has ended anew, with whatever `fux` is on
  the path.
- Don't make, in a session's folder, a FIFO other than `in` and `ctl`, a link that leads to
  no folder of it, more than 256 names, or two names that differ only in the case of their
  letters; and don't `mv` a file there into a folder, or rename one twice while a client is
  away. Each ends every attached client with a line that says which.
- Don't keep a file over 32 MiB in a session's folder: a mirror has its first 32 MiB, and one
  that is replaced is sent again at every look.
- Don't make a file in a session's folder unreadable: no client gets a round while it is.
- Don't write into a mirror, but for its `in` and `ctl`: it is koh's alone to write. A client
  whose mirror is not what koh left there (another folder's files, a file renamed after
  another) is ended when it attaches next.
- Don't write `kill` to a session's `ctl`, or a mirror's, unless you mean it: it hangs up the
  program for every client. Any key with no scope may; it may run any command.
- Don't write to a mirror's `ctl` while it has no link: only the last `resize` written then is
  sent, and koh says that the other lines were dropped.
- Don't keep a mirror after a `koh mount` that was killed: it is a still picture. Remove it; a
  mount does not take a folder that is there.
- Don't look at a session or a mirror with a `fux` of another version than koh was built with:
  `koh fux view` is the one that reads what koh's holders write.

**Do**

- After a stall, look at the screen before you type on. What you type while koh says there is
  no link is held (64 KiB of what is written to `in`, beside what its pipe holds; past that
  whoever writes waits) and typed on return; what was on its way when a link died may be
  lost, so a line can arrive without its beginning. A link that dies without a word, or a
  server that does (killed, its machine gone), is noticed when the connection has been
  silent for the thirty seconds koh allows a session, which is not thirty seconds from the
  moment it died: what was typed since may be lost with it. After a long cut the link is not
  back at once with the path: koh gives each dial five seconds and waits five between two,
  so a path whose handshake takes longer than that is not dialled with success.
- To take a session's size back, resize your terminal. A session has the size of the terminal
  that last changed: a second client of another size, or one that left, leaves it as it is,
  and a smaller terminal shows the top left of a larger session.
- To start a name again that has ended, remove its folder on the server (`koh exec box -- rm
  -r PATH/NAME`, the path `koh serve` printed). Until then `--session NAME` shows how it
  ended, and ends the same.
- On Linux, restart `koh serve` after you replace the `koh` binary. Until then no new session
  starts: koh runs itself by its own path, which is gone, and says "cannot run PATH (deleted):
  No such file or directory". Sessions that run go on.
- After an upgrade that changes the pane format (the release notes say when), end the sessions
  started before it: a holder keeps the code it was started with, and nothing in a pane says
  which format it writes. (A client and a server of two formats refuse each other, before
  anything is started.)
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
- In a session of some 250 commands or more, `koh wait --session` counts by a second fact.
  The pane's `marks` keeps the last thousand and drops one from its front for each it takes,
  so there are never more `end`s there than before: koh finds the file's first mark in the
  file as it was, and so knows how many went. Two things can then go wrong, and only then.
  Where the oldest marks are several alike at one place (commands of one exit code that were
  on a screen when it was cleared, 250 commands ago), fewer are taken for gone than are: a
  command's end is then seen late, once the file's front has passed them, a few commands
  on; the wait returns then, still for the first command that ended. And where all thousand
  marks are still on the screen (250 commands, none scrolled out: a pane of 250 rows or
  more), a screen that moves can be taken for an end.
- On a kernel before 6.13 a file's time is the clock's tick: a file of a session's folder
  rewritten in place to the same length within one tick is not seen by a client until it
  changes again. Replace it, or add to its end.
- In a session, `fux start x` (or `koh fux start x`) starts `main/x` of **your own** `fux`
  session, not a koh session: `fux` reads no variable, and a name is a name in the default
  session.
- To have a session beside your local panes, name a folder in your own `fux` session:
  `koh mount box "$(fux dir)/main/box"`. koh makes it; it must not be there.

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
koh mount box   # a mirror of the session, for `koh fux view`, `cat` or a script
koh sessions box                       # each session: attached, running, busy, last exit code
koh wait box --session 1 --timeout 600 # until the command there ends: its output, its code
koh output box --session 1 --last      # what the last command printed
```

Run `koh --help` for the complete command reference and exit-code contract; `koh help-agents`
is the same and, after it, recipes: a session's files, and the three commands as a script.
