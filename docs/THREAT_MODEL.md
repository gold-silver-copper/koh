# koh threat model

Who koh defends against, where the trust boundaries are, and what it does not try to do. It is
written against the code as it is (`src/`), for a reviewer to check; pair it with
[`SECURITY.md`](../SECURITY.md). koh is a single-operator tool for a few machines you control,
not a multi-user service.

## What koh is

A server (`koh serve`) is reached by its Ed25519 endpoint id over [iroh](https://iroh.computer)
QUIC, directly or through relays. Every request is one QUIC stream that begins with a proof of
the client's key: a signature over keying material exported from that TLS session, so a proof
cannot be replayed on another connection (`src/net.rs`). The server then looks the key up in
its `clients` file, read anew for each request, or among `--allow` (`src/server.rs`,
`authorize`), and only then reads the request.

## 1. A peer that has proved nothing

Anyone who can reach the server's UDP port, or a relay that knows its endpoint id, can complete
a QUIC handshake: the transport does not know the allowlist.

- **What it gets:** nothing. No request is read before a key the server allows is proved.
- **What it can make the server hold:** a connection takes one of `--max-connections` places
  (64) from when the server takes it up until it is gone: closed by either end, or silent for
  its idle timeout (15 s for a command or a copy, 30 s for a session; a client that is killed
  goes that way). The server takes a connection up when it comes to it, after its first packet
  has arrived: the time the packet waited for that is not counted. A connection has 10 s from
  when it was taken up to finish its handshake and prove a key the server allows: one that has
  not by then is closed and its place given back, wherever it got to. With no place free, as
  many more are let connect only to be told "busy". One of those that has connected is told
  when it asks, and 2 s after it was taken up at the latest; one whose handshake is not
  finished by then is dropped without being told. Past those a peer is refused unheard (a koh
  client takes that for "busy" too, and exits 75). On a connection, at most 16 streams are
  open at once; on each the server reads one proof of at most 512 bytes, checks one signature
  and, unless the key is one given by `--allow` or the proof is bad, reads the `clients` file
  once.
- **Not defended:** peers that keep taking the places as they come free shut allowed clients
  out for as long as they keep at it. Each stream may also hold unread data up to the
  transport's window (about 1.25 MB) until its connection is closed.

## 2. A client with an allowed key and no scope

It is the server's user: it runs any command (`koh exec`, `koh run`), reads and writes any file
that user can (`koh cp`), and attaches to any session. There is nothing to escalate to. Its
sessions are `fux` panes of the server's user, in a `fux` session of koh's own beneath the
server's state (`src/session.rs`): it starts them, types into them, resizes them and hangs
them up (a pane's `ctl`), and writes that `fux` session's `colours` and `keyboard`.

- **Bounds:** a message is refused before it is read past its length (`src/proto.rs`): 512
  bytes for a proof; 1 MiB for a request, the answer that it was taken, and the short answers
  (a list of jobs); 256 KiB for a piece of a file, of input or of output, and for every message
  of a session, either way; 4 MiB for what a copy says it needs and for its summary; 8 MiB
  for a copy's manifest and what a wait returns. Of a session's client the server takes
  16 KiB a message of typed bytes, and stops taking messages while 64 KiB wait for one of a
  pane's two FIFOs: so up to 80 KiB can wait for a FIFO, and beside them the stream's reader
  holds up to seventeen messages it has read (256 KiB each at the most). It takes a list of
  at most 256 names of what a mirror has, of which it believes nothing its own bytes do not
  bear out. What it holds of a pane to send (a round, whole, and what it keeps of the files
  it sent) is as large as the pane's folder: fux's bounds, not a figure of koh's. A message that is
  more than it should be, or one that has bytes after it, ends the stream. What a pane's
  folder holds is bounded by fux's holder, not by koh. A copy's tree is at most 100,000 entries, each at
  most 128 directories beneath it. With `--delete` that holds for what the destination already
  has: something deeper there fails the whole copy (exit 1) before anything is removed or any
  file is written, even where the copy would have removed it. At most `--max-sessions`
  sessions (64) are kept: folders in the sessions' folder, whoever made them. The oldest that
  has ended and that no client is attached to makes room for a new one, once that has
  started; with none such the client is told the server is busy.
- **Not bounded:** how many jobs it starts, the size of a job's log, and what a command it runs
  uses. A request that waits (`koh wait`, `koh logs -f`) is not stopped when its connection
  goes; it ends with what it waits for.
- **No deadline once a key is proved.** The 10 s are for the proof alone: after it, the request
  itself may come as slowly as its sender likes, and a connection that has proved a key may
  stay, asking nothing, for as long as it is kept alive. So a client with any allowed key, a
  scoped one too, can hold places idle, up to all of them; a key taken out of `clients` keeps
  the connections it has until they ask for something again.

## 3. A client with a scoped key

`koh clients add NAME ID --cp DIR` or `--exec DIR` (`src/keys.rs`, `Scope`).

- **`--cp DIR`** copies to and from paths that are beneath `DIR` by their text. The path a
  client names must begin with `DIR` and go on with plain names (no `..`, no NUL). `DIR` is
  resolved for this, each time, and the path may begin with it as `clients` has it or as it
  resolves; the path itself is not resolved (`src/keys.rs`, `check_beneath`). The names a copy
  then sends are held to plain names the same way (`src/sync.rs`, `wire_names`). **It is not a
  confinement:** the server uses the path as the file system resolves it, so a symlink beneath
  `DIR` leads where it leads, and a key that finds one leading out of `DIR` reads and writes
  there as the server's user. The scope keeps a script or a slip of the hand in `DIR`; the
  operator trusts his machines and what is on them. A copy makes no symlinks: one in a tree
  that is read is not sent, `--delete` leaves it, one in the tree a copy lands in is followed,
  and a file that lands where one is replaces it (a file is written under a new name of its
  own beside where it lands and renamed, with mode 0644 or 0755 and never setuid). Every other
  request is refused (exit 4).
- A `DIR` written in `clients` as its resolved path refuses a path that reaches it by another
  name (`/var/home/u` for `/home/u`, `/private/tmp` for `/tmp`): only `DIR` is resolved. That
  refuses more, never less.
- **`--exec DIR`** runs commands and starts jobs whose starting directory is beneath `DIR` by
  the same rule, and copies as above. **It is not a sandbox:** the command is any command,
  run as the server's user, and reaches whatever that user can. Every other request is refused:
  a session (the scope is looked at before the format, the run or anything else of an
  attach, and before anything is made) and everything about jobs but starting one (their
  list, their logs, a wait for one, killing one). Treat it as a full key
  that cannot open a terminal.
- A scope is read with each request, so narrowing or removing a key takes effect on its next
  request; what it already started goes on.

## 4. A server a client dials

A wrong endpoint id, or a host someone else now controls.

- **A copy from it** (`koh cp SERVER:SRC DST`) lands beneath `DST` by the text of its names:
  each is a plain name (no `..`, no `/`), and where they lead is the file system's to say, so
  a symlink already in `DST` is followed, as the user's own `cp` would follow it. The client
  takes at most 100,000 entries, only the files it asked for, and no file longer than the
  server said.
- **A session from it** (`koh connect`, `koh mount`) is a mirror on the client: a folder of
  files that the server chooses, **names and contents**. It is confined by five rules
  (`src/carry.rs`, `Mirror`; `src/client.rs`), and by nothing layered on them:
  1. **The mirror is a folder koh makes**, mode 0700, in koh's own directory or where the
     user said; a folder that is there is not taken, cleared or written into. The session's
     name, which the server says and a mirror's default place is made of, is one plain name
     or the client ends.
  2. **Names** are one or two plain names (letters, digits, `.`, `_`, `-`, 64 at most, no dot
     first); a name of two has a folder the mirror made as its first. One name has one
     spelling: a name that differs from one the mirror has only in the case of its letters
     is refused.
  3. **Three names at the mirror's root are never written**, by any message, in any case of
     their letters: `generation`, which koh writes itself; `command`, which is what fux's
     `.restore` would run; and `status`, which names processes of the server. (In a folder
     of the mirror they are names as any other: nothing reads them there.)
  4. **One kind of link:** at the mirror's root, to a folder at its root, true of every link
     when it comes and after every round. Nothing can be written through it, as a name of
     two needs a folder for its first.
  5. **A name keeps its kind.** A thing of one kind is refused where a thing of another is; a
     FIFO is `in` or `ctl`.

  A round is checked whole before anything of it is done: its files wait in the mirror, in a
  folder whose name has a dot first (`.koh`: fux passes it over, and no message can name
  it), until the round is whole and every rule holds of what it would leave. Then it is
  done, under an odd `generation`. What the server sends can therefore change nothing or
  all of a round; a failure of the client's own disk in the middle can leave a round part
  done, the number odd, and the next attach sends what puts it right. At most 256 names, 32 MiB a file,
  128 MiB a mirror and as much waiting, 4,096 messages a round, 256 KiB a message; thirty
  seconds between two messages of an open round and ten minutes for all of it. Past any of
  it, or at any message the rules refuse, the client ends, having changed nothing; a round
  that stands still is thrown away and the client dials again.
- **What the server's files do on the client.** The viewer (`koh connect`'s, or any
  `fux view` of a mount) draws them, and fux's default keys act on some. koh adds no switch
  for any of it; `koh connect`'s own key set has only its detach keys.

  | A file the server chooses | fux's viewer | fux's default keys (a `fux view` of a mount) |
  |---|---|---|
  | the screens, `size`, `cursor`, `modes`, `state` | drawn: text and colour codes only | |
  | `title` | given to the terminal as its title, without control characters | the pane picker shows it |
  | `clipboard` | when it changes in the pane that has the keys: put on the terminal's clipboard (up to 1 MiB), **replacing what the user copied** | |
  | `notice` | a bell or a notice to the terminal | |
  | `links` | addresses of links on cells: printable ASCII, 2,048 bytes | |
  | `pictures`, `pic-N.sixel` | passed to the terminal once the viewer has found one whole sixel picture inside its tile | |
  | `cwd` | | a new shell starts in that directory of the client, if it has one |
  | `marks`, `history`, the main screen | | opened as text in the local editor |
  | `in`, `ctl` (the mirror's own FIFOs) | keys and `resize` go there, and so to the server | `kill` hangs up the session's program; removing the pane's folder ends the mount |
  | `status`, `command` | never in a mirror: `.here` and `.restore` pass it over | |
- **A command's output from it** (`koh exec`, `koh logs`) is written to the client's stdout and
  stderr as it came, as ssh writes it: escape sequences included, if those are a terminal.
- **It learns** every key typed into a session (what was typed while there was no link too,
  on return), the client's terminal colours and keyboard flags (from `koh connect`'s
  viewer; from a mount, those of the `fux` session its mirror was put in, viewer or none),
  what the client's mirror holds (names, lengths and hashes, at each attach), and every
  file sent to it.
- **Not defended:** a server can mislead a user who chose to connect to it. The endpoint id is
  all that ties a name to a server: check it out of band.

## Local users of the server's machine

Not defended against: koh trusts the machines it runs on. The key file is 0600 in a directory
that koh makes 0700 and refuses if group or others may write to it; whose directory it is, koh
does not check, and a key that is a symlink is read as the file it leads to (`src/keys.rs`).
Sessions and jobs' logs are kept in the server's state: `$XDG_RUNTIME_DIR/koh`; where that is
not set, the system's temporary directory under `koh-UID` (the number `id -u` gives), which koh
does not check the ownership of. A state directory that is there is taken as it is; the
sessions' folder beneath it (`fux/koh-sessions`) is made 0700 where koh makes it, and a
pane's folder 0700 by fux. Anything that runs as the server's user can type into a session,
resize it, hang it up and remove it, and start a pane there that koh takes for a session:
the files are the interface. A session's holder is no child of `koh serve` and is not ended
with it. On a client, a mirror and `koh connect`'s private folder are 0700 in
`$XDG_RUNTIME_DIR` (else the temporary directory, or `~/.cache/koh` for a mount).
