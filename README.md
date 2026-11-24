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
    is stopped, and are there when it is started again. `koh fux …` is `fux …`.
  - A client has a **mirror** of the session: a copy of the pane's folder that koh makes and
    alone writes, brought up to date in rounds, each applied whole or not at all (`koh/19`).
    What is typed into the mirror's `in` and `ctl` is typed into the session's.
  - `koh connect SERVER [--session NAME | --new] [-- PROG…]` shows a private mirror with
    `fux`'s viewer, in the same process. With a name it is that session, started if there is
    none; with none, the newest that lives, or a new one. Leave it with `Ctrl-] .` or `C-b d`
    (`Ctrl-] Ctrl-]` and `C-b C-b` type the key itself). It ends with the session's program:
    with its status, with 128 + N if signal N ended it, and with 1 if nothing says how it
    ended (its holder was killed, the machine was restarted, its folder was moved).
  - `koh mount SERVER [--session NAME | --new] [DIR]` keeps a mirror for any `fux view`, `cat`
    or script: in `DIR`, which koh makes (a folder that is there is not taken), or with none in
    a `fux` session of koh's own on the client, `K/fux/koh-mounts/SERVER.NAME` (`K` is
    `$XDG_RUNTIME_DIR/koh`, else `~/.cache/koh`). Nothing of koh's is in your own `fux`
    session unless you name a folder there. The mirror is removed when the session ends or
    koh is stopped (SIGINT, SIGTERM). A mirror has no `status` and no `command`: its program
    and its holder are on the server.
  - **Without a link** koh says so (in the viewer's corner; `koh mount` on its standard error)
    and dials again. What you type while it says so is held and typed when the link is back.
    What was on its way when a link died may be lost. Nothing is ever typed twice.
  - Sixel is the one picture format, as in `fux` 0.43. A program that draws with the Kitty
    graphics protocol alone (`kitten icat`) shows nothing in a session, and a picture is drawn
    only in a terminal that draws sixel.
  - `koh sessions`, `koh output` and `koh wait --session` are not in this build: they answer
    so and exit 1. A session's files are on the server, where `koh exec` reads them.

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
- Don't write `kill` to a session's `ctl`, or a mirror's, unless you mean it: it hangs up the
  program for every client. Any allowed key may; it may run any command.
- Don't write to a mirror's `ctl` while it has no link: only the last `resize` written then is
  sent, and koh says that the other lines were dropped.
- Don't keep a mirror after a `koh mount` that was killed: it is a still picture. Remove it; a
  mount does not take a folder that is there.
- Don't look at a session or a mirror with a `fux` of another version than koh was built with:
  `koh fux view` is the one that reads what koh's holders write.

**Do**

- After a stall, look at the screen before you type on. What you type while koh says there is
  no link is held and typed on return; what was on its way when a link died may be lost, so a
  line can arrive without its beginning. A link that dies without a word is noticed after
  thirty seconds: what is typed in that time is lost with it.
- On Linux, restart `koh serve` after you replace the `koh` binary. Until then no new session
  starts: koh runs itself by its own path, which is gone, and says "cannot run PATH (deleted):
  No such file or directory". Sessions that run go on.
- After an upgrade that changes the pane format (the release notes say when), end the sessions
  started before it: a holder keeps the code it was started with, and nothing in a pane says
  which format it writes. (A client and a server of two formats refuse each other, before
  anything is started.)
- Under systemd, give `koh serve`'s unit `KillMode=process` and the user
  `loginctl enable-linger`: else stopping the service, or logging out, kills every session.
- To see every session on the server as tabs: `koh fux view PATH`, the path `koh serve` printed.
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
```

Run `koh --help` (or `koh help-agents`) for the complete command reference and exit-code contract.
