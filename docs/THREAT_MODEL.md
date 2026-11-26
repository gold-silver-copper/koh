# koh threat model

Who koh defends against, where the trust boundaries are, and what it does not try to do. It is
written against the code as it is (`src/`), for a reviewer to check; pair it with
[`SECURITY.md`](../SECURITY.md). koh is a single-operator tool for a few machines you control,
not a multi-user service.

## What koh is

A server (`koh serve`) is reached by its Ed25519 endpoint id over [iroh](https://iroh.computer)
QUIC, directly or through relays. Each client process dials from a fresh endpoint key of its
own, so parallel processes of one client do not collide on a relay or at the server. Every
request is one QUIC stream that begins with a proof of the client's key: a signature over keying
material exported from that TLS session, so a proof cannot be replayed on another connection
(`src/net.rs`). The server ignores the connection's own endpoint id, looks the proved key up in
its `clients` file, read anew for each request, or among `--allow` (`src/server.rs`,
`authorize`), and only then reads the request.

## 1. A peer that has proved nothing

Anyone who can reach the server's UDP port, or a relay that knows its endpoint id, can complete
a QUIC handshake: the transport does not know the allowlist.

- **What it gets:** nothing. No request is read before a key the server allows is proved.
- **What it can make the server hold:** a connection takes one of `--max-connections` places
  (64) from when the server takes it up until it is gone: closed by either end, or silent for
  its idle timeout (30 s at the most; a koh client asks for 15 s, and for 8 s for a session; a client that is killed
  goes that way), and its requests have ended, which those still going 5 s after it are made
  to. The server takes a connection up when it comes to it, after its first packet
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

## 2. A client with an allowed key

It is the server's user: it runs any command (`koh exec`, `koh rsh`, `koh run`), and attaches to
any session, lists them, reads their text and
waits for their commands (`koh sessions`, `koh output`, `koh wait --session`, which read a
session's folder as a script of that user would: `src/pane.rs`). There is no narrower key, and
there is nothing to escalate to; to separate trust, run `koh serve` under another user account
or on another machine. Its
sessions are `fux` panes of the server's user, in a `fux` session of koh's own beneath the
server's state (`src/session.rs`): it starts them, types into them, resizes them and hangs
them up (a pane's `ctl`), and says what its terminal is like, which the server writes into
that `fux` session's `colours` and `keyboard`. Each attach has a viewer of its own on the
server, `fux`'s viewer of one pane, which has no keys and takes no command: a client cannot
have it show another pane, another workspace, or run a script.

- **Bounds:** a message is refused before it is read past its length (`src/proto.rs`): 512
  bytes for a proof; 1 MiB for a request, the answer that it was taken, and the short answers
  (a list of jobs); 256 KiB for a piece of input or of output; 16 KiB for every message of a
  session, either way; 8 MiB for what a job's wait returns. A session's text (`koh output`, `koh
  wait --session`) and the list of sessions are sent in pieces of 64 KiB and are as long as
  the pane's files, and the folders kept, make them: for files that fux wrote, fux's bounds,
  not a figure of koh's. A pane's files are read whole, whatever is in them (one that the
  server's user wrote there himself, of any length, too), and what has a file's name and is
  none (a FIFO, a link) is not read and not waited on. An attach says of the client's terminal
  its size, its `TERM` (printable, 64 bytes at most), a number for its keyboard and at most
  three lines of colours (`foreground`, `background`, `cursor`, each `#` and six hex
  digits): what is anything else is refused before a session is started or a file written,
  and the two files are written once the attach will be shown a session, not before (one
  that is refused for its run, its name or the server's cap changes nothing; one whose
  program then cannot be started has written them).
  The two files are the server's and not one session's: a client with an allowed key
  chooses what the programs of every session there are told of their terminal's colours and
  keyboard, until the next attach says otherwise. For each attach
  the server runs one viewer on one pty, and ends it with the attach; a client's newer
  attach to a run (by the number it chose) ends its older one first, and a connection has at
  most 16 streams. Of a session's client the server takes 16 KiB a message, typed bytes or a
  size, and reads the next when the viewer's pty has taken the last: what the viewer does
  not take waits in QUIC's window and the pty's buffer, not in koh. What the viewer draws is
  sent 8 KiB a message as the link takes it, and nothing of it is kept. A message that is
  more than it should be, or one that has bytes after it, ends the stream. What a pane's
  folder holds is bounded by fux's holder, not by koh. At most `--max-sessions`
  sessions (64) are kept: folders in the sessions' folder, whoever made them. The oldest that
  has ended and that no client is attached to makes room for a new one, once that has
  started; with none such the client is told the server is busy. The cap can be over by one:
  a client that comes back to the session that was chosen to go, while the new one starts,
  keeps it, and both stay until a later start finds an ended one without a client.
- **Not bounded:** how many jobs it starts, the size of a job's log, and what a command it runs
  uses. A request that waits for a job (`koh wait`, `koh logs -f`) ends with what it waits
  for, or when its client's stream has ended. (`koh wait --session` looks at the pane ten
  times a second, and between two looks sees that its client's stream has ended: it looks no
  more. A look that has begun is finished; so is a read for `koh output` or `koh sessions`,
  whose client is not looked for until the answer is sent.)
- **Allowlist (`clients`).** Every line must be `NAME ID` (plus blank lines and `#` comments).
  Any other line (including an older `cp=…` or `exec=…` line) grants no access: its key is
  refused (exit 4) unless independently allowed by another valid line or by `koh serve --allow
  ID`. `koh clients` names each skipped line on stderr with its line number; a successful `koh
  clients add`, `rm`, or `rename` rewrites the file from accepted lines only (dropping skipped
  lines, comments, and blank lines), while `rm` or `rename` of a name that appears only on a
  skipped line fails (`no client named`) and leaves the file unchanged. A `clients` file that is
  not UTF-8 is refused whole: no key from it is allowed, and `koh clients` fails without naming
  a line. For every id not given by `--allow` (which holds for the life of that `koh serve`
  regardless of the file), `clients` is read anew on each request, so removing its last valid
  line takes effect on its next request: jobs and sessions it already started go on, while a
  refused request closes its connection, hanging up any command still streaming on that same
  connection.
- **No deadline once a key is proved.** The 10 s are for the proof alone: after it, the request
  itself may come as slowly as its sender likes, and a connection that has proved a key may
  stay, asking nothing, for as long as it is kept alive. So a client with any allowed key can
  hold places idle, up to all of them; a key taken out of `clients` keeps the connections it has
  until they ask for something again.

## 3. A server a client dials

A wrong endpoint id, or a host someone else now controls.

- **A session from it** (`koh connect`) is what a terminal's output is, and no more. What
  the server sends as drawn is written to the user's terminal as it came, 16 KiB a message;
  koh reads none of it, and nothing of a session is a file, a folder, a script or a command
  on the client. Beside those bytes koh takes two things from the server: the session's name
  and its run, checked to be a plain name and kept only to ask for the same session again;
  and the last word, a number, which is the exit code (what is no code of a process is 1).
  A message over its bound, or one that is none, ends the client.
- **What a terminal's output can do** is the terminal's to say, and differs from one to the
  next. A server a user connected to can, on most:
  - show any text, anywhere on the screen, in any colour: a prompt that is not the shell's, a
    line that looks like koh's own;
  - set the window's title, ring the bell, raise a notice;
  - write the clipboard (OSC 52), replacing what the user copied; and read it, on a terminal
    that allows that (few do unasked);
  - make a link of any text, to any address: a click opens it;
  - draw pixels (sixel);
  - turn on what a program may turn on: mouse reports, marked pastes, the alternate screen,
    keyboard flags, a hidden cursor, a scroll region, another character set;
  - ask the terminal a question. The answer is typed into the session, so it reaches the
    server (the terminal's kind, its colours, the cursor's place, the window's size; its
    title, on a terminal that tells it). An answer that comes after `koh connect` has ended
    is typed at whatever reads the terminal next, the user's shell: a terminal that reports
    back text a server chose (a title report, which terminals now refuse or strip) makes
    that a typed command. This is the oldest attack on a terminal, and is the same for
    `ssh` to that server or `cat` of a file from it;
  - reach any bug the terminal's parser has.

  koh undoes what fux's viewer turns on, in one string (`src/client.rs`, `reset`): what was
  cut is ended (CAN, ST), then the frame, the scroll region, the mouse, marked pastes, the
  focus reports, the keys' modes, the cursor's shape and colour, the colours of text, a link
  left open, the alternate screen and the title; and one level of keyboard flags, if the
  terminal said it takes any (koh's viewer sets them aside once then; where it said none, none
  is taken back: they would be the user's shell's). It is written when the link is lost, and
  at every end of `koh connect` short of `kill -9`. What a server turned on beyond that list
  (a character set, keyboard flags set aside more than once) stays until the user types
  `reset`.
- **A command's output from it** (`koh exec`, `koh logs`), and what it says a session shows
  or printed (`koh output`, `koh wait --session`), is written to the client's stdout and
  stderr as it came, as ssh writes it: escape sequences included, if those are a terminal.
  What is printed at the end (`koh output`, a `wait`) is held whole until then, as much as the
  server sends; `koh logs` streams chunks directly to stdout as they arrive.
- **It learns** what is typed into a session and reaches it (what was typed while there
  was no link too, on return; not what was lost with a link), the terminal's size in cells
  and pixels, its `TERM`, the keyboard flags it takes and its foreground, background and
  cursor colours (which `koh connect` asked the terminal itself, once, and sends with each
  attach: three colours and a number more than a server learned before, enough to tell a
  light theme from a dark one and one terminal from some others), and whatever the terminal
  answers to what the server asks it: a server's questions reach the terminal, as any
  program's output does, and what the terminal sends after koh's own asking is typed into
  the session as it is.
- **Not defended:** a server can mislead a user who chose to connect to it. The endpoint id is
  all that ties a name to a server: check it out of band.

## Local users of the server's machine

Not defended against: koh trusts the machines it runs on. The key file is 0600 in a directory
that koh makes 0700 and refuses if group or others may write to it; whose directory it is, koh
does not check, and a key that is a symlink is read as the file it leads to (`src/keys.rs`).
Sessions and jobs' logs are kept in the server's state: `$XDG_RUNTIME_DIR/koh`; where that is
not set, the system's temporary directory under `koh-UID` (the effective user id), which koh
does not check the ownership of. A state directory that is there is taken as it is; the
sessions' and jobs' folders beneath it (`fux/koh-sessions` and `fux/koh-jobs`) are made 0700
where koh makes them, and a pane's folder 0700 by fux. Anything that runs as the server's user
can type into a session, resize it, hang it up and remove it, and start a pane there that koh
takes for a session: the files are the interface. A session's holder is no child of `koh serve`
and is not ended with it; nor is a session's viewer when `koh serve` is killed outright: it
reads the end of its terminal and leaves. A viewer's folder (`fux/.view.PID`) is in the server's
state; a viewer has no keys there. On a client a session leaves nothing.
