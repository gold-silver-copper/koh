# koh

A Rust, peer-to-peer remote shell inspired by [mosh](https://mosh.org), built on [iroh](https://iroh.computer) / QUIC.

koh gives you a responsive remote shell that survives network changes, suspend/resume, and reconnects — without SSH, port forwarding, or server-side accounts.

## Install and usage

```sh
cargo install --locked koh
```

koh authorizes by endpoint id. There are no passwords or accounts.

```sh
# On the client, print its id:
koh id

# On the server, allow that client by name, and start a shell host (it prints its own id):
koh clients add phone <client-id>
koh serve

# On the client, save the server by name, and connect:
koh servers add laptop <server-id>
koh connect laptop
```

The same server runs commands and jobs, and copies files, with no shell session at all:

```sh
koh exec laptop -- make test          # its stdout and stderr apart; koh exits with its status
git diff | koh exec laptop -C src/app -- git apply
koh run laptop --name build -- cargo build   # a job: it outlives koh and the link
koh wait laptop build                 # until it ends: its last lines, then its status
koh cp -r ./site laptop:              # a tree into the server user's home, as a sync
koh cp laptop:notes.md laptop:todo .  # back here, into the current directory
koh cp -r src/. laptop:x/src && koh exec laptop -C x -- cargo test  # edit here, build there
koh run laptop --name b -- cargo build && koh wait laptop b --timeout 600  # a long build that outlives a drop
```

Or run `koh` alone on a terminal for a menu of this machine's keys, the servers it connects to
and the clients allowed here: pick one by number to connect, rename or delete it; `a` adds one,
`k` shows both keys in full with QR codes and resets one, saying first who will lose access.

Useful commands:

```sh
koh                       # on a terminal: the menu of keys, servers and clients
koh id                    # print this machine's endpoint id (its client key's)
koh servers               # the servers you connect to: add <name> <id> [--direct IP:PORT],
                          # rm <name>, rename <old> <new>
koh clients               # the clients allowed here, likewise; add --cp DIR / --exec DIR
                          # scopes a client's key (below)
koh serve                 # host shells, commands, jobs and copies for the saved clients
                          # (--allow <id> adds one for this run)
koh connect <name|id>     # a shell there: your session attached last, else a new one
koh connect <name> --new  # a new session beside your others; --session N picks one by number
koh connect <name> -- PROG ARG...  # a new session running PROG on a terminal in place of the
                          # shell (an editor, a debugger, a TUI); ends with its status; -C DIR
                          # starts it (or a new shell) in DIR
koh sessions <name>       # your sessions: number, attached or not, age, size, what its program
                          # is doing (reading, busy, ...), the last command's status, title
koh output <name> --session N [--last]  # a session's screen, or its last command's output
koh exec <name> -- PROG ARG...  # run PROG with no terminal, each word as it is (no shell), and
                          # exit with its status; --sh 'LINE' runs a shell line; -C DIR
                          # (quote a ~: -C '~/proj', or -C proj, relative to the home)
koh run <name> [--name N] -- PROG ARG...  # start a job; koh jobs, logs, wait and kill find it
koh wait <name> JOB       # until the job ends, then its last 200 lines (--tail N); or --text T,
                          # --file PATH; --session N [--reading]
koh logs <name> JOB       # its last 200 lines (--tail N, --all; --follow), then whether it runs
koh cp SRC... <name>:DST  # copy files and trees there, or `koh cp <name>:SRC... DST` back
koh key info              # show both identity key files and their endpoint ids
koh key reset [client|server] --yes  # delete a key (client by default); the next use makes a new id
koh help-agents           # the page for scripts and agents
```

Useful flags:

```sh
--no-clipboard            # ignore the server's OSC-52 clipboard writes (on by default)
--no-hyperlinks           # drop the server's hyperlinks (OSC 8; passed by default)
--no-colours              # don't tell the server your terminal's colours (told by default, so
                          # vim, bat and delta pick a matching theme)
--on-bell <cmd>           # run a shell command whenever the remote bell rings
--shell <program>         # host a program instead of $SHELL (repeat to pass args)
--key-file <path>         # use a custom identity-key path
--direct <ip:port>        # dial a server directly (LAN, loopback), on any command that dials;
                          # saved with `koh servers add`, every command dialing that name does
--json                    # on sessions, output, exec, run, jobs, kill, wait, cp: one JSON value
--session-ttl-secs <n>    # keep detached sessions, and ended jobs, around longer/shorter
--job-log-bytes <n>       # output each job keeps, its newest (4 MiB by default)
--max-connections <n>     # limit concurrent connections
--max-sessions <n>        # limit sessions, all clients' together
```

**`koh cp` is a sync.** A source lands in the destination if that is a directory (or ends in `/`,
or there are several sources: then it is made), else as the destination, its parents made.
Directories merge into what is there. A file the destination already has with the same size and
content (by hash) is not sent again; one that changed is written beside its target under a
hidden `.koh-….part` name and renamed into place once whole, so a cut copy leaves nothing
half-written that looks complete, and the next copy resumes the part. A file written gets the
time it arrived (so `make` and `cargo` see it changed) unless `-p` keeps the source's. `dir/.`
copies what is in `dir`. `--delete` removes what the source does not have, `--exclude PAT`
leaves entries alone, and `--atomic` lands nothing until the whole copy came. `--dry-run`
changes nothing and sends no file's bytes: it lists each change it would make (`new`,
`replaced`, `deleted`, `dir`, `link`, and the path, with a file's size and that of the one it
replaces), then the summary; `--diff` is that dry run, each replaced text file (up to 1 MiB)
followed by a unified diff of it (`a/` the destination's, `b/` the source's), for which the
source's file goes to the destination's end, nothing else coming back but the diff. Without `--delete`, what the destination has that the source lacks
is kept, and the summary counts it (`2 there not in the source, kept: --delete removes them`), but for directories, most often made there (a build's `target/`). It ends with one
line saying where it landed: `3 files sent, 41 KB → laptop:proj/src (1 new, 2 replaced; 120 unchanged)` (`files received` for a download), or
`--json`. A tree copied to a directory of its own name that is there already updates it, as `src/.` does
(`koh cp -r src laptop:src` run twice, which `cp` would land as `src/src`); `laptop:src/` or
`laptop:src/src` nests it. A
source given on the command line is followed if it is a symlink, as `cp` does; symlinks inside a tree are copied
as symlinks, never followed on either side, and fifos, sockets and devices are skipped and said
so. Remote paths are taken as the server user's shell would take them, but not globbed: no
remote shell runs.

**Exit codes** are the same for every command: 0 ok, 1 failed, 2 usage, 3 the server was not
reached, 4 refused (not allowed, or out of the key's scope), 75 the server was busy (more
connections at once than `--max-connections`, and as many waiting: nothing ran, so a retry is
safe), 124 a wait timed out. `exec`, `wait` and `logs --follow` exit with the remote command's
status (75 too when busy), and 255 on koh's other errors,
as ssh does. A command that did not start exits 127 when there is no such program and 126 when
it could not start (no `-C` directory there, say), from `exec` and `run` alike; `connect -C`
with no such directory exits 126 too.

**Scoped keys.** `koh clients add ci <id> --cp /srv/drop` lets that client copy to and from
`/srv/drop` and below only, and nothing else: no shell, no commands. `--exec DIR` lets it run
commands and jobs, started in `DIR` (not a sandbox: a command reaches what the server user
can). A scoped client's paths that leave the directory (`..`, an absolute path outside it, a
symlink inside it) are refused.

Keys live under `$XDG_CONFIG_HOME/koh/` (else `~/.config/koh/`) by default (`client.key`,
`server.key`), and the names beside them: `servers` beside the client key and `clients` beside the
server key, one `name id` a line (`#` comments allowed); a server's may end `direct=IP:PORT` or
`relay=URL`, how to dial it, and a client's `cp=DIR` or `exec=DIR`, its scope. They are checked as
the keys are, since `clients` decides who may open a shell: a file that is a symlink or someone
else's is refused, and a loose mode is tightened.

**Keys, mouse and pastes** reach the remote program as it asked, whatever terminal you type on:
the program's keyboard, mouse and paste modes reach your terminal with its output (and with the
redraw when you attach from another terminal), the client decodes what your terminal sends, and
the server encodes each key for the program, kitty's encoding to nvim or helix, legacy bytes to
the rest.

**Platforms:** Linux, macOS, and Android via [Termux](https://termux.dev). Windows is not supported; use WSL2.

## Scripts and agents

`koh help-agents` is the whole of it on one page. `koh connect` needs a terminal; run with none
(from a script, or an agent's tool call), it says so and points at the rest, none of which needs
one.

Save a server with how to reach it, once, and every command dialing its name uses that:

```sh
koh servers add box <server-id> --direct 192.168.1.20:4433   # or --relay-url URL
```

Run a command: its stdout, stderr and exit status come back as a local command's would, and sent
to one file (`2>&1`, or a terminal) its stdout and stderr keep the order it wrote them in. A koh
stopped by a signal hangs the command up at once; one killed outright (SIGKILL) or cut off,
within 10 s.

```sh
koh exec box -- cargo test -j 4
koh exec box -C app --sh 'git status --short' > status.txt
```

Start something that should outlive the call, and wait for it on the server:

```sh
koh run box --name srv -- python3 -m http.server 8000
koh wait box srv --text 'Serving HTTP' --timeout 30   # past 30s: exit 124, how the job
                                      # stands (processes, CPU time) and its last lines
koh logs box srv                      # its last 200 lines so far, then `· running 12s`;
koh logs box srv --follow             # and on as it writes, until it ends: its status
koh kill box srv
```

Copy files and trees either way, sending only what changed:

```sh
koh cp -r ./src box:app/              # here to there: lands as app/src
koh cp box:app/target/report.json .   # there to here
koh cp --diff -r ./src box:app/       # change nothing: which files differ, and how
```

To build there what you edit here, sync in the same call as the build: an unchanged tree costs
only hashes, and the build never sees stale code. koh has no watch mode, since a build started
right after an edit could still beat its sync.

```sh
koh cp -r ./src/. box:app/src && koh exec box -C app -- cargo build
```

Shell sessions, opened with `koh connect` (in fux, or any terminal), can be read and waited on
from anywhere:

```sh
koh sessions box --json               # each session's state: reading, busy, running a command
koh wait box --session 1              # until the command running there ends; its status
koh output box --session 1 --last     # that command's output
```

Prompt marks (OSC 133) from the remote shell pass through to your terminal, with the nonce your
terminal asks for (`FUX_MARK_NONCE`), and so do reports of what the remote program is doing
(`OSC 133;S;activity=reading`), so a terminal that reads them, as
[fux](https://github.com/gold-silver-copper/fux) does, sees where each remote command starts and
ends, its status, and whether it waits for input, as it would a local one's.

## Android / Termux install

1. Install Termux from the [Termux GitHub releases](https://github.com/termux/termux-app/releases). Do not use the old Play Store build.
2. In Termux, install Rust and build tools:

   ```sh
   pkg update
   pkg install rust clang pkg-config
   ```

3. Install koh:

   ```sh
   cargo install --locked koh
   ```

If DNS resolution is broken on your Android device, try setting an explicit resolver:

```sh
KOH_DNS=1.1.1.1 koh connect <server-id>
```

To get a phone notification when the remote shell rings the bell (a finished build, an agent
waiting for input), hook `termux-notification`:

```sh
koh connect <server-id> --on-bell 'termux-notification -t "koh bell"'
```

The hook runs detached from the terminal at most once per second; `KOH_BELL_COUNT` and
`KOH_TITLE` are set in its environment, and every other `KOH_*` variable is scrubbed. Bells that
rang before you attached do not fire it; bells during a reconnect do.

## Library

The `koh` crate also builds as a library, but only so the binary, its tests and the fuzz targets
can share code. Its modules are internal and may change in any release; depend on the `koh`
binary, not the library.

## Highlights

- Built in Rust on iroh peer-to-peer QUIC; connects by endpoint id instead of hostname/port.
- Mosh-style predictive local echo, painted over the program's output and taken back before
  more of it is written, for responsive shells on bad networks.
- The program's output reaches your terminal as it wrote it, as over ssh, less the questions
  the server's own terminal answers; your terminal's scrollback and search are its own. A client
  attaching to a session is sent its screen and up to 1000 rows of history above it; one that
  redials after a drop, or falls far behind on a slow link, the screen as it is now, never a
  backlog.
- Detachable sessions survive suspend/resume, IP changes, and reconnects without tmux; a client
  may have several, by number, and read their state, screen and last command from scripts.
- No SSH bootstrap and no port forwarding: the server listens on one UDP port (random unless
  `--port`), reached through iroh's relays and hole-punching, and admits only allowlisted keys,
  which may be scoped to copying or commands in one directory.
- Shell integration marks (OSC 133) reach your terminal: the rows where the remote shell's prompts
  start, and each command's start and end with its status. `koh serve` starts bash, zsh and fish
  so that they send the marks, after your own startup files (your prompt and hooks unchanged),
  and counts only the shell's own marks, not ones a program prints; `koh serve --no-shell-marks`
  starts the shell as it is.
- Runs commands (`koh exec`), jobs (`koh run`) and syncs files and trees (`koh cp`) over the same
  connection and allowlist as a shell, with no SSH or remote shell needed.
- Not wire-compatible with mosh or SSH; koh is its own protocol/tool.
- Intended for personal machines you control; not a full SSH replacement. Does not provide
  multi-user accounts, port forwarding, or Windows support.

## Status

koh is experimental and intended for personal use on machines you control.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model, [`SECURITY.md`](SECURITY.md) for vulnerability reporting, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for implementation details.

## License

MIT, from 0.10.0 onward. Releases before 0.10.0 remain available under GPL-3.0-or-later.
