# Security Policy

koh is a young, single-maintainer project. It was rewritten from scratch in 0.18.0, and that
code has had internal reviews only: **no external or professional audit**. Please calibrate trust
accordingly (see the [threat model](docs/THREAT_MODEL.md)). `forbid(unsafe_code)` and the denied
panic lints shrink what needs auditing; they do not replace independent eyes.

## Reporting a vulnerability

Please report suspected security issues **privately**, not in a public issue or PR:

- **Preferred:** GitHub private vulnerability reporting — open a draft advisory at
  <https://github.com/gold-silver-copper/koh/security/advisories/new>.
- **Backup:** email the maintainer at `stephen.korzen@gmail.com` with `[koh security]` in the subject.

Helpful to include: a description and impact, the affected version (`koh --version`), and a
reproduction if you have one. We aim to **acknowledge within 7 days** and to coordinate a fix and
disclosure within **90 days** of a confirmed report (sooner for an actively-exploited issue). We'll
credit reporters who want it.

## Scope

**In scope** (code koh authors):

- The identity key on disk and its directory (`src/keys.rs`, `load_or_create_key`): the key file
  is the raw 32-byte secret, protected by its permissions (0600) like an SSH host key; and the
  lock that keeps two servers off one key (`hold_for_serving`).
- The proof of a client's key on each request (`src/net.rs`, `open_authed_stream` and
  `verify_client`), the allowlist and what each key may ask (`src/server.rs`, `authorize` and
  `dispatch`; `src/keys.rs`, `Scope`), and what bounds a peer before and after that
  (`src/server.rs`, `start_server` and `handle_connection`; `src/session.rs`, `Sessions`).
- Sessions on the server (`src/session.rs`): which pane an attach is given or starts, the
  check of a client's run and of what it says of its terminal before anything is made, a
  client's one stream on a run, the viewer koh starts for an attach (on what pty, of which
  pane, and that it ends with the attach), and what a client may have written into koh's own
  `fux` session (`told`); and what a key with no scope is told of a session's folder
  (`src/pane.rs`: `koh sessions`, `koh output`, `koh wait --session`).
- The wire decoders and their bounds (`src/proto.rs`), on both ends.
- The paths a scoped key may name (`src/keys.rs`, `Scope`). Where a symlink leads is not in
  scope: see below.
- Commands and jobs the server starts (`src/server.rs`, `handle_exec`; `src/jobs.rs`).
- What a server can do to a client: a session, which is what a terminal's output can do and no
  more (`src/client.rs`: `attach`, `Console`, `reset`). koh writes a session's bytes to the
  terminal unread; the [threat model](docs/THREAT_MODEL.md) lists what a terminal lets output
  do. In scope is that nothing else of the client is reached (no file, no command), that the
  terminal is put back at every end of `koh connect` and when a link is lost, and that what is
  typed is never typed twice.

**Out of scope: report upstream** (dependencies koh does not author):

- Transport crypto, QUIC and TLS: **iroh** and its QUIC backend, **rustls**, **ring**.
- **`fux`**, which is in koh's binary under `koh fux …` and `koh hold …`: the holder that keeps
  a session's program and writes its pane's folder, with its terminal emulator **`fux-vt`**;
  the viewer that `koh serve` runs for each attach to draw a session, and what it writes to
  a terminal; and the system-call layer **`fuxix`** (PTYs, sessions, signals). What a pane's
  files mean and what a viewer does with them is fux's: a parse or drawing bug there belongs
  to the [fux](https://github.com/gold-silver-copper/fux) project. Which pane a viewer is
  started on, and who may ask, is koh's.
- **The user's terminal emulator.** What it does with the bytes a session sends is its own:
  a server reaches its parser as `ssh` to that server would.

## What a key can do

- A key with no scope is a shell as the server's user: commands, jobs, and sessions. A session is a `fux` pane of that user, in koh's own `fux`
  session: such a key starts them, types into them, resizes them and hangs them up, and says
  what its terminal is like into that `fux` session's `colours` and `keyboard` (the two are
  the session's, not a pane's: a program of any session that asks its terminal is answered
  from them, where they are there). `koh fux …`
  and `koh hold …` are no requests: they are fux, run by whoever runs koh, on his machine.
- A `--cp DIR` key is kept in `clients` until scoped keys are removed; with file copy removed
  from the protocol, every request under it is refused (exit 4).
- A `--exec DIR` key runs commands and starts jobs, which must start in a directory beneath
  `DIR` by the text of the path (`DIR` itself is resolved; the path a client names is not, so a
  symlink beneath `DIR` leads where it leads). **It is not a sandbox**: only the starting
  directory's path is checked, and the command is any command, run as the server's user. Give it
  only to a peer you would give a shell.

## Past audits

The audits before 0.18.0 covered code the rewrite replaced; they are in the git history. An
internal audit of the rewrite in November 2026 found a server lock that locked nothing and no
bound on connections or sessions; the tests that guard those fixes are in `tests/e2e.rs`. It
also found a scoped key's copy writing through symlinks. That one was fixed and then, by the
maintainer's decision, undone: koh has no anti-symlink mechanics, and a scope is what the
section above says it is.

## Please do not

Run automated scanning that degrades a third party (relays, the public DNS discovery service), or test
against servers / keys you do not own.
