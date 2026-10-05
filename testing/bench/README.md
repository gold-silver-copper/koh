# The scoreboard

`testing/scoreboard.sh` writes `docs/SCOREBOARD.md`: koh beside mosh and plain ssh, on the
corpus's 113 recordings (`testing/corpus/`) and on four synthetic workloads, by bytes on the wire and
on the user's terminal, keystroke latency beside a flood, the time to a settled screen, server
memory per session, and the instructions koh retires. It opens with a table of who wins each
axis, so a reader who skips the rest knows the answer.
It is modelled on fux's scoreboard (`fux-vt/compare/`): every number is measured, and says how.

```sh
testing/scoreboard.sh                              # everything, about 30 minutes
testing/scoreboard.sh --recordings bash,vim-resize # two recordings, the synthetic workloads
testing/scoreboard.sh --recordings none --skip latency
testing/scoreboard.sh --systems koh --out /tmp/koh.md
testing/scoreboard.sh --runs 3 --repeats 5         # the defaults: latency and settling 3 times
testing/scoreboard.sh --profiles Mbit,kbit         # latency and settling on the slow links only
```

Latency and settling vary from run to run, so each is measured `--runs` times (3 by default) and
given as the median with its range; bytes, memory and instructions are measured once.

mosh is measured when `mosh-server` and `mosh-client` are on `PATH`, ssh when `ssh`, `sshd` and
`ssh-keygen` are, and instructions when `perf` (or `valgrind`) is; the scoreboard says which were
not. None needs root: the harness runs its own `sshd` on loopback with keys it makes, and a
distribution's mosh and perf packages work unpacked into a home directory with `PATH` and
`LD_LIBRARY_PATH` pointing there.

## Bytes on the wire

Each workload is played as the program: a script (`Workload::script`) puts the PTY in raw mode,
waits for the workload's size, and writes a step's bytes when the harness types `0x01` (which no
reply to a query contains), logging each step it wrote. The harness waits for the connection's
setup to finish (the link quiet for 500 ms) and counts from there; for each step it resizes if the
step does, types, waits for the script to log the step, and waits for the link to carry nothing for
300 ms. The redraw workload is timed instead: the script writes a frame every 33 ms by itself.

- **koh** runs as its real server and client loops (`serve_endpoint`, `run_client`) in the
  harness, its client painting with koh's own `BackendTerminal`, over the fault link of koh's tests
  (`tests/net/link.rs`, included by path). The link is the endpoints' only path, so every packet
  is counted: UDP payload bytes delivered, each way.
- **mosh** runs as `mosh-server new` hosting the script and `mosh-client` on a koh PTY, through a
  UDP proxy on loopback that counts payload bytes delivered.
- **ssh** runs as `ssh -tt` on a koh PTY to the harness's `sshd`, through a TCP proxy that counts
  payload bytes delivered. ssh is as it ships, with OpenSSH's keystroke-timing chaff.

No IP, UDP or TCP header is counted, for any of them.

**What the user's terminal is given:** the bytes each client wrote to the user's terminal (koh's
`BackendTerminal`, the PTY mosh-client and ssh write to), and for koh how many times it painted a
second. A remote shell that sends few bytes but repaints the user's terminal heavily still costs
the user: a slow terminal, or one over a serial line, shows it.

## Keystroke latency beside a flood

The program writes a counter to the top row as fast as `awk` can, saving and restoring its cursor
around each write, while `cat` echoes typed keys below it. The harness types `x` 100 times, 150–250
ms apart, and times each from being typed to showing in the user's terminal: a fux-vt parser
reading what the client painted (for mosh and ssh, the client's PTY output). That is what the user
sees, with prediction where the client predicts. For koh it also times the key to showing on the
screen the server sent, which is the server's echo without prediction.

Links: clean; 25 ms each way; 25 ms each way with 5% of packets lost each way; 1 Mbit/s and 256
kbit/s, each with 25 ms each way and a 100 ms buffer, tail-dropped when full. koh's link is the
fault link with that profile (the rate limits each direction). mosh and ssh run inside a network namespace of the harness's own
(`netns.rs`): `unshare --user --map-root-user --net` gives one without root, in which the harness
puts a kernel queueing discipline on loopback (`tc netem delay … loss …`). Each packet crosses
loopback once, so delay and loss apply once each way, to mosh's UDP and to ssh's TCP alike: TCP's
retransmissions are paid for as a user pays for them. The measure runs again inside a nested
namespace that maps the user back to itself (`koh-bench --netns-child …`); `sshd` stays outside,
since it wants users and a tty group the namespace lacks, and is reached through a Unix socket
carried on to loopback inside. netem's rate on loopback is one queue for both directions, so mosh's
and ssh's slow links share it between them, where koh's are a queue each way: what the client sends
is small beside the screens, so this favours neither much.

## Time to a settled screen

What a user waits for after an action: the time from the action to the screen's last change before
it stays the same for 500 ms, as a fux-vt parser reading the user's terminal sees it. Each action
is repeated `--repeats` times (5 by default) in one session, on the 25 ms each way, 5% loss link,
in the same namespaces as latency:

- a key typed into a quiet `cat`;
- in `nvim --clean` on a 300-line Rust file: a page down, a search jump (`/fn`), a split opened or
  closed;
- `clear; ls -l` of a directory of 2,000 files;
- a resize, alternating 30x100 and 40x120, with nvim open.

The median repeat is the run's figure.

## Scrollback

Each workload played into a server emulator keeping the default 1,000 lines, then every row of its
history fetched as koh's scrollback view fetches them (`Ctrl-^ [`, requests of up to 256 rows):
the compressed history streams' bytes. In process, with no link. mosh keeps no history; ssh's is
the user's terminal's, which the output's bytes already paid for, and a reconnect loses.

## Server memory per session

A child process (`--footprint-child`) makes server emulators at 40x120 with the given scrollback,
fills them (or not) with enough lines of text to fill the scrollback and the screen, takes a
snapshot of each as a session holds one, and reports how much its resident memory (`VmRSS`) grew,
per session. It counts the terminal and its screens, not the session's PTY, threads or
connection.

## Instructions

Each count runs in a child process of its own (`--instructions-child`) under `perf stat -e
instructions:u` (or valgrind's cachegrind), as fux's `bench --instructions` does: the fewest of
three runs, less the fewest of three baseline runs that make the same inputs and do nothing with
them. Instructions retired do not change with the machine's load.

- **Emulator, per byte:** the output fed to the server's emulator in 4 KiB reads.
- **Server, per byte:** the same, with the snapshot, diff and encoded frame after every read: an
  interactive program's pace, and more than a flood costs a real session, which takes one
  snapshot per burst of up to 65 reads and sends frames at most once per frame interval.
- **Client, per frame:** those frames decoded, applied and painted.

## When to run it

At the end of each phase of work that changes what koh sends, and before and after any change
meant to make koh faster or smaller: the scoreboard says whether it did. The numbers are from one
machine and one run; latency depends on the machine's load, so compare runs from the same machine,
and read the load averages at the scoreboard's foot.
