# koh's agent benchmark

How well can an AI agent work on a remote machine through koh? Each task is a job on a "remote
machine", given to a fresh agent (`--model`: `codex-sol` or `codex-sol-fast`, `codex exec` with
gpt-6.1-sol at the standard or fast tier; or `haiku`, `claude -p`) that reaches the remote only through
the tool under test. The same tasks run over ssh as the control.

```sh
cd ~/code/koh/testing/agentbench
python3 -I bench.py validate --set A                      # every task sound: see "Validation"
python3 -I bench.py run --set A --configs koh-master --out ~/.cache/claude-tmp/koh-agentbench/results/a-master.json
python3 -I report.py ~/.cache/claude-tmp/koh-agentbench/results/a-master.json
```

Configurations (`bench.py`'s `CONFIGS`): `koh-master` and `koh-branch` (release binaries built
once into `~/.cache/claude-tmp/koh-agentbench/bins/`, each with its README in `docs/<config>/`),
and `ssh` (OpenSSH, a private `sshd`). At most 12 agents run at once (`--workers`); run it in a
memory-capped scope (`systemd-run --user --scope -p MemoryMax=32G -- python3 -I bench.py run …`), so
a runaway is killed alone. Two runners can go side by side with distinct `--slot-base`s (ports).

## The setting

Both "machines" are this computer, kept apart:

- **The remote** is a HOME of its own, served by a private `koh serve --local` on a loopback UDP
  port (its own server key, allowing only the run's client key), or by a private `sshd` on a
  loopback TCP port (its own host key, `authorized_keys` and config; never the system's sshd or
  the user's `~/.ssh`). Its shell is bash, in that HOME, with `PS1='bench:\w\$ '`, and its PATH
  starts with `~/bin`. It has python3, coreutils, grep/sed/awk, git, vim, nvim, less, rustc and
  cargo (offline: std only, no crates.io), and `CARGO_BUILD_JOBS=2`.
- **The local side** is the agent's working directory, its own fux server, and the tool's client
  config (koh's key and a saved server `bench`; or an `ssh_config` with a host `bench`). The
  agent's tool calls go through wrappers that log each `koh`, `ssh`, `scp`, `sftp`, `rsync`,
  `fux` and `sleep`.
- **The remote runs in bubblewrap too**, in a process namespace of its own under `remote_init.py`
  (process 1, which also runs the checker, so the checker sees the remote's processes as it does):
  the user's home is hidden but for the toolchain and the binaries, `/tmp` is its own, and the server
  and what it runs see neither the run's local side nor the tasks. A remote `pkill` reaches nothing
  else.
- **The agent runs in bubblewrap**: every remote side, the task sets, this repository and the
  results are hidden from it, it has a process namespace and a `/tmp` of its own, and a shell it
  starts reads a `~/.bashrc` of the run's (the wrappers first in PATH, no history), with the user's
  `~/.cargo/bin` hidden. Its fux server runs in
  the same view. So the remote's files and processes are reachable only through koh or ssh.

The agent is told: how to reach the remote with the tool (`--direct 127.0.0.1:PORT` for koh),
that fux is there for interactive programs, where its local directory is, and the task's goal.
It ends with a `FRICTION:` line.

## A task

A directory under `tasks/<SET>/`, named by its id (`TA-001`, `TB-0001`):

```
TA-001/
├── task.toml        the goal and metadata
├── check.py         check(local, remote) -> (ok, why)
├── solve.sh         a reference solution over ssh (validation only; agents never see it)
└── setup/
    ├── local/       copied into the agent's local directory
    └── remote/      copied into the remote HOME; remote/bin/ is on its PATH, made executable
```

`task.toml`:

```toml
id = "TA-001"
title = "Count the warnings"                  # a few words
cat = "run"                                   # one of the categories below
difficulty = "easy"                           # easy, moderate or hard
goal = """
On the remote machine, run `~/bin/build` and write the number of warnings it reports to
`answer.txt` in your local directory.
"""
# optional:
timeout = 1200                                # seconds for the agent (default 1200)
solve_timeout = 300                           # seconds for solve.sh (default 300)
[drop]                                        # the connection is dropped mid-task:
when = "job.started"                          # once this file exists in the remote HOME,
after = 0.5                                   # and this many seconds later, every client
                                              # process (koh, or ssh/scp/sftp) is killed
```

**The goal** is what the agent reads, stated as outcomes, the same for every tool:

- Never name koh, ssh, scp, fux or any command for reaching the remote. Name the remote's own
  programs and files freely ("run `~/bin/build`", "the file `logs/app.log` in the remote home").
- Say exactly what counts as done and where any answer goes (a file in the local directory, or a
  file on the remote), and its exact form ("only the number", "one name per line").
- Remote paths are relative to the remote HOME (`~/...`); local paths are in the agent's local
  directory.
- A task may tell the agent that something will happen ("the connection will drop while the job
  runs; make sure the job still finishes and collect its result").

**`check.py`** has `check(local, remote) -> (bool, str)`, given the two directories' paths, run
outside the sandbox once the agent has finished. It judges the final state: files on either side,
what fixtures recorded (their exit codes, the input they got, their pids), and whether processes
the fixtures recorded are still running (`/proc/PID`). The string says why, especially on failure.
Python standard library only. Never judge by time taken or by the agent's words.

**`solve.sh`** is a bash script run in the local directory with `ssh bench`, `scp`, `sftp` and
`rsync` set up (`bench:PATH`), the drop included. It proves the task can be done and that the
checker passes a right answer. It may use anything ssh offers (`ssh -tt`, `nohup`, `setsid`); for
an interactive program, `ssh -tt` with a here-doc or `expect`-like Python over `ssh -tt` is fine.

**Fixtures** are programs in `setup/remote/bin/` (or `setup/local/`): python3 or bash, standard
library only, deterministic (seeded randomness only), no network, writing only inside the remote
HOME (or local directory). A program the agent must stop records its pid in a file, so the
checker can see whether it still runs. A program that must run to completion records that it did
(`done.txt` with its result), so the checker can tell "finished" from "started". Make a fixed
`sleep` the wrong way to solve a task: a job's duration should vary with seeded input or be long
enough that guessing fails, and a task should not pass by reading a screen early.

## Categories

Cover each, roughly in these shares:

| cat | what | share |
| --- | --- | --- |
| `run` | run a command, get its output and its exit status | 10% |
| `output` | long output; a marker far back in it; wide or wrapped lines | 10% |
| `wait` | a long-running job: wait for it, for a line, for one of several outcomes | 10% |
| `crash` | a program that fails: its status, its error line, after a delay | 6% |
| `stdin` | feed input: pipes, a local file into a remote program, binary data | 6% |
| `files` | copy files both ways: a large one, a directory tree, odd names, modes kept | 12% |
| `tui` | edit a file in a TUI editor, drive a pager or a menu | 8% |
| `repl` | drive a REPL to an answer | 6% |
| `prompt` | answer a program's questions (a confirmation, a password-like prompt) | 6% |
| `drop` | the connection drops mid-job; the job must survive and the work be picked back up | 8% |
| `sessions` | a second shell beside a busy first; finding a job left running earlier | 6% |
| `process` | find and stop a runaway process; signals; clean shutdown | 6% |
| `multi` | several steps: build and test a crate, fix a failing test, collect results | 6% |

Difficulty: about 40% easy, 40% moderate, 20% hard.

## Validation

`bench.py validate --set S` runs, for every task, the checker on the untouched state (it must
fail) and `solve.sh` over ssh (the checker must pass). A task that fails either is not used.

## Sealing

A set is written, validated, then sealed before it is used: `seal.py seal tasks/B` records a
SHA-256 of every task (all its files together) in `tasks/B.ledger` and locks the folder
(`chmod 000`); `seal.py open tasks/B` checks every hash before unlocking. Set B is written by an
agent that never sees Set A or its results, sealed before any design change, and opened only after
the branch is locked, so its before and after measure koh, not tuning to the tasks.

## Grades

The checker says whether the job got done. Each run is also graded from its transcript, by a
stronger model's review, not by the agent's own report:

- **worked:** the checker passes, done plainly: it waits on conditions, not on time; reads what it
  needs directly; makes no blind retries; needs no encoding tricks to move data.
- **hack:** the checker passes, but through a workaround: guessed sleeps or polling loops,
  scraping a screen for what the tool should report, base64 or here-doc tricks to move a file,
  sentinel lines to learn an exit status, raw escape sequences.
- **failed:** the checker fails, or the agent gave up or ran out of time.
