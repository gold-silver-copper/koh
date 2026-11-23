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
that user can (`koh cp`), and attaches to any session. There is nothing to escalate to.

- **Bounds:** a message is refused before it is read past its length (`src/proto.rs`): 512
  bytes for a proof; 1 MiB for a request, the answer that it was taken, and the short answers
  (lists of jobs and sessions); 256 KiB for a piece of a file, of input or of output; 4 MiB for
  what a copy says it needs and for its summary; 8 MiB for a copy's manifest, a screen, a
  session's text and what a wait returns. A copy's tree is at most 100,000 entries, each at
  most 128 directories beneath it. With `--delete` that holds for what the destination already
  has: something deeper there fails the whole copy (exit 1) before anything is removed or any
  file is written, even where the copy would have removed it. At most `--max-sessions`
  sessions (64) are kept, an ended one that no client is attached to making room for a new one
  that has started.
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

- **`--cp DIR`** copies to and from paths beneath `DIR`. The path it names must begin with
  `DIR` and go on with plain names (no `..`); nothing of it is resolved (`src/keys.rs`,
  `check_beneath`), and the names a copy then sends are held to plain names the same way
  (`src/sync.rs`, `wire_names`). **That is the text of the path, and it is not a confinement:**
  the server uses the path as the file system resolves it, so a symlink beneath `DIR` leads
  where it leads, and a key that finds one leading out of `DIR` reads and writes there as the
  server's user. The scope keeps a script or a slip of the hand in `DIR`; the operator trusts
  his machines and what is on them. A copy makes no symlinks: one in a tree that is read is not
  sent, `--delete` leaves it, and a file that lands where one is replaces it (a file is written
  under a name of its own beside where it lands and renamed, with mode 0644 or 0755 and never
  setuid). Every other request is refused (exit 4).
- **`--exec DIR`** runs commands and starts jobs whose starting directory is beneath `DIR` by
  the same rule, and copies as above. **It is not a sandbox:** the command is any command,
  run as the server's user, and reaches whatever that user can. Every other request is refused:
  sessions (attaching, their list, their text, a wait for one) and everything about jobs but
  starting one (their list, their logs, a wait for one, killing one). Treat it as a full key
  that cannot open a terminal.
- A scope is read with each request, so narrowing or removing a key takes effect on its next
  request; what it already started goes on.

## 4. A server a client dials

A wrong endpoint id, or a host someone else now controls.

- **A copy from it** (`koh cp SERVER:SRC DST`) lands beneath `DST`: every name it sends is a
  plain name (no `..`, no `/`), so none takes a file outside. A symlink already in `DST` is
  followed, as the user's own `cp` would. The client takes at most 100,000 entries, only the
  files it asked for, and no file longer than the server said.
- **A session from it** (`koh connect`, `koh mount`) is mirrored into a pane folder on the
  client. The server chooses the contents of that folder's files (the screen, title, links,
  clipboard, notice, pictures), never their names. The viewer then draws them, so the server
  can show anything, set the terminal's title, and **replace what the user copied** (the
  clipboard, as a program in a local terminal can). A frame is at most 8 MiB, its size and
  cursor are held to 500 by 500, and at most 16 pictures or 32 MiB of them are kept.
- **A command's output from it** (`koh exec`, `koh logs`) is written to the client's stdout and
  stderr as it came, as ssh writes it: escape sequences included, if those are a terminal.
- **It learns** every key typed into a session, the client's terminal colours and keyboard
  flags, and every file sent to it.
- **Not defended:** a server can mislead a user who chose to connect to it. The endpoint id is
  all that ties a name to a server: check it out of band.

## Local users of the server's machine

Not defended against: koh trusts the machines it runs on. The key file is 0600 in a directory
that koh makes 0700 and refuses if group or others may write to it; whose directory it is, koh
does not check, and a key that is a symlink is read as the file it leads to (`src/keys.rs`).
Sessions' pane folders and jobs' logs are kept in `$XDG_RUNTIME_DIR/koh`; where that is not set
they are in the system's temporary directory under `koh-UID` (the number `id -u` gives), which
koh does not check the ownership of.
