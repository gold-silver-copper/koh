# The scoreboard

`testing/scoreboard.sh` writes `docs/SCOREBOARD.md`: koh beside mosh and plain ssh, on the
corpus's 113 recordings (`testing/corpus/`) and on four synthetic workloads, by bytes on the wire,
keystroke latency beside a flood, server memory per session, and the instructions koh retires.
It is modelled on fux's scoreboard (`fux-vt/compare/`): every number is measured, and says how.

```sh
testing/scoreboard.sh                              # everything, about 30 minutes
testing/scoreboard.sh --recordings bash,vim-resize # two recordings, the synthetic workloads
testing/scoreboard.sh --recordings none --skip latency
testing/scoreboard.sh --systems koh --out /tmp/koh.md
```

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

## Keystroke latency beside a flood

The program writes a counter to the top row as fast as `awk` can, saving and restoring its cursor
around each write, while `cat` echoes typed keys below it. The harness types `x` 100 times, 150–250
ms apart, and times each from being typed to showing in the user's terminal: a fux-vt parser
reading what the client painted (for mosh and ssh, the client's PTY output). That is what the user
sees, with prediction where the client predicts. For koh it also times the key to showing on the
screen the server sent, which is the server's echo without prediction.

Links: clean; 25 ms each way; 25 ms each way with 5% of packets lost each way. koh's link is the
fault link with that profile, mosh's the UDP proxy with the same. ssh has no figure with loss: a TCP
proxy cannot drop data without TCP hiding the drop, which needs a kernel queueing discipline
(`tc netem`, root) this harness does not use.

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
