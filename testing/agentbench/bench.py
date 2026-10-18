#!/usr/bin/env python3
"""koh's agent benchmark: a fresh agent per task and configuration, working on
a "remote machine" it reaches only through the tool under test.

    python3 -I bench.py run --set A --configs koh-master --out results/a-master.json
    python3 -I bench.py run --set B --configs koh-master,koh-branch,ssh --repeats 1 --out results/b.json
    python3 -I bench.py run --set A --tasks TA-003,TA-010 --configs ssh --out results/try.json

Each run gets, under the scratch directory:
- a local side: the agent's working directory, its own fux server, and the
  tool's client config (koh's keys and saved servers, or an ssh_config);
- a remote side: a HOME of its own that a private `koh serve` (on loopback,
  `--local`) or a private `sshd` (a high loopback port, its own host key and
  authorized_keys) serves. The system's sshd and the user's ~/.ssh are never
  used.

The agent (`claude -p`, a small model) runs in bubblewrap: every run's remote
side, the task sets and the results are hidden from it, and it has a process
namespace of its own, so the remote machine is reachable only through koh or
ssh. Its fux server runs in the same view. What it did is read from its tool
calls (wrappers in PATH log each koh, ssh, scp, sftp, rsync, fux and sleep);
whether it succeeded, from the task's checker, run outside the sandbox.

A task is a directory: `task.toml` (the goal, stated as outcomes, never as
commands), `check.py` (`check(local, remote) -> (ok, why)`), and optionally
`setup/local/` and `setup/remote/` (copied in; `setup/remote/bin/` is on the
remote PATH). See README.md.
"""
import argparse
import concurrent.futures
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import tomllib

sys.dont_write_bytecode = True  # no __pycache__ in a task: it would change a sealed hash

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SCRATCH = os.path.expanduser("~/.cache/claude-tmp/koh-agentbench")
REMOTES = os.path.join(SCRATCH, "remote")
RUNS = os.path.join(SCRATCH, "runs")
BINS = os.path.join(SCRATCH, "bins")
DOCS = os.path.join(SCRATCH, "docs")
NOTES = os.path.expanduser("~/code/notes/projects/koh")
CLAUDE = shutil.which("claude") or os.path.expanduser("~/.local/bin/claude")
CODEX = shutil.which("codex") or os.path.expanduser("~/.local/bin/codex")


def agent_argv(agent, prompt, local):
    """The agent's command line: a fresh `claude -p` with a small model, or `codex exec` with
    gpt-6.1-sol at the standard tier, both told to act without asking (bubblewrap is the sandbox)."""
    if agent in ("codex-sol", "codex-sol-fast"):
        tier = "fast" if agent.endswith("-fast") else "default"
        return [CODEX, "exec", "-m", "gpt-6.1-sol", "-c", f'service_tier="{tier}"',
                "-c", 'model_reasoning_effort="high"', "--dangerously-bypass-approvals-and-sandbox",
                "--ephemeral", "--skip-git-repo-check", "--ignore-rules", "-C", local, "--json", prompt]
    return [CLAUDE, "-p", "--model", agent, "--output-format", "stream-json", "--verbose",
            "--permission-mode", "bypassPermissions", "--max-turns", "80", prompt]
FUX = os.path.join(BINS, "fux")  # a copy: ~/.cargo/bin is hidden from the agent
LOGGED = ["koh", "ssh", "scp", "sftp", "rsync", "fux", "sleep"]
SPOILERS = ["FUX_SOCKET", "FUX_PANE", "FUX_SERVER", "TMUX", "TMUX_PANE", "SSH_AUTH_SOCK",
            "SSH_AGENT_PID", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"]
PORT_BASE = 47200

CONFIGS = {
    "koh-master": {"tool": "koh", "bin": os.path.join(BINS, "koh-master")},
    "koh-branch": {"tool": "koh", "bin": os.path.join(BINS, "koh-branch")},
    # koh-next (the rewrite) and the commit it was measured against.
    "koh-156dbe4": {"tool": "koh", "bin": os.path.join(BINS, "koh-156dbe4")},
    "koh-next": {"tool": "koh", "bin": os.path.join(BINS, "koh-next")},
    "ssh": {"tool": "ssh"},
}

LEARN = {
    "koh": "koh, a remote shell. Learn it from `koh --help` (and `koh help COMMAND`) and its "
           "README at {readme}. The remote machine is saved in koh as the server `bench`; it "
           "listens on 127.0.0.1:{port}, so dial it with `--direct 127.0.0.1:{port}`.",
    "ssh": "ssh (OpenSSH). The remote machine is saved as the host `bench`: `ssh bench`, and "
           "`scp`, `sftp` and `rsync` know it too (`bench:PATH`). Learn them from their man pages.",
}

PROMPT = """You are an AI agent doing a job on a remote machine. You reach it with {learn}

The remote machine's files and programs can be reached only through that tool: nothing on it is
visible from your own shell. Your local working directory is {local}; local files mentioned in
the task are there, and any answer goes there.

You also have fux, a terminal multiplexer, for driving interactive programs: learn it with
`fux help-agents` (start there). A private fux server is already running for you (FUX_SOCKET points
to it), and nothing in this environment reaches anyone else's, so you may use any fux command.

Your task:
{goal}

Rules:
- Do not build or install software on this local machine (no cargo here). Building on the remote
  machine is fine when the task asks for it.
- Write any answer file with exactly what is asked in it, nothing else.
- When you are done, end with a line `FRICTION:` followed by anything about the tools that made
  the task harder than it should have been (or `none`).
"""


# ------------------------------------------------------------------ tasks

def load_set(name):
    """The tasks of set NAME, in id order."""
    root = os.path.join(HERE, "tasks", name)
    out = []
    for slug in sorted(os.listdir(root)):
        path = os.path.join(root, slug)
        if not os.path.isfile(os.path.join(path, "task.toml")):
            continue
        with open(os.path.join(path, "task.toml"), "rb") as f:
            task = tomllib.load(f)
        task["dir"] = path
        out.append(task)
    return out


# ------------------------------------------------------------------ processes

def marked(marker):
    """Pids of every process whose environment carries KOHBENCH=marker."""
    want = f"KOHBENCH={marker}".encode()
    pids = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/environ", "rb") as f:
                if want in f.read().split(b"\0"):
                    pids.append(int(name))
        except OSError:
            pass
    return pids


def kill_marked(marker, only=None):
    """Kills the run's processes (or, with ONLY, those whose program's name is in it)."""
    killed = []
    for pid in marked(marker):
        if pid == os.getpid():
            continue
        if only is not None:
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    argv0 = os.path.basename(f.read().split(b"\0")[0].decode(errors="replace"))
            except OSError:
                continue
            if argv0 not in only:
                continue
        try:
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except (ProcessLookupError, PermissionError):
            pass
    return killed


def wait_for(pred, seconds, what):
    end = time.time() + seconds
    while time.time() < end:
        got = pred()
        if got:
            return got
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {what}")


# ------------------------------------------------------------------ one run

class Run:
    def __init__(self, tag, config, task, slot, repeat):
        self.config, self.task, self.slot = config, task, slot
        self.tool = CONFIGS[config]["tool"]
        self.name = f"{tag}-{config}-{task['id']}-r{repeat}"
        self.marker = self.name
        self.root = os.path.join(RUNS, tag, config, f"{task['id']}-r{repeat}")
        self.local = os.path.join(self.root, "local")
        self.remote = os.path.join(REMOTES, self.name)
        self.port = PORT_BASE + slot
        self.state = os.path.join(self.root, "state")
        self.procs = []

    # -- layout
    def lay_out(self):
        for d in (self.root, self.remote):
            shutil.rmtree(d, ignore_errors=True)
        for d in (self.local, self.state, self.remote, os.path.join(self.remote, "bin")):
            os.makedirs(d)
        for side, dest in (("local", self.local), ("remote", self.remote)):
            src = os.path.join(self.task["dir"], "setup", side)
            if os.path.isdir(src):
                shutil.copytree(src, dest, dirs_exist_ok=True)
        for d, _, files in os.walk(os.path.join(self.remote, "bin")):
            for f in files:
                os.chmod(os.path.join(d, f), 0o755)
        with open(os.path.join(self.remote, ".bashrc"), "w") as f:
            f.write("PS1='bench:\\w\\$ '\nHISTFILE=/dev/null\n")
        with open(os.path.join(self.remote, ".profile"), "w") as f:
            f.write("[ -f ~/.bashrc ] && . ~/.bashrc\n")

    def remote_env(self):
        home = os.path.expanduser("~")
        return {
            "HOME": self.remote, "USER": os.environ.get("USER", ""), "LOGNAME": os.environ.get("USER", ""),
            "SHELL": "/bin/bash", "TERM": "xterm-256color", "LANG": "C.UTF-8",
            "PATH": f"{self.remote}/bin:{home}/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
            "RUSTUP_HOME": f"{home}/.rustup", "CARGO_HOME": os.path.join(self.remote, ".cargo"),
            "CARGO_BUILD_JOBS": "2", "TMUX_TMPDIR": os.path.join(self.remote, ".tmux"),
            "XDG_CONFIG_HOME": os.path.join(self.remote, ".config"),
            "KOHBENCH": self.marker + "-remote",
        }

    def local_env(self):
        env = {k: v for k, v in os.environ.items() if k not in SPOILERS and not k.startswith("FUX_")}
        rt = os.path.join(self.state, "rt")
        os.makedirs(rt, mode=0o700, exist_ok=True)
        os.chmod(rt, 0o700)
        env.update(
            XDG_RUNTIME_DIR=rt, FUX_SOCKET=os.path.join(rt, "fux.sock"),
            XDG_CONFIG_HOME=os.path.join(self.state, "config"), KOHBENCH=self.marker + "-local",
            TERM="xterm-256color", LANG="C.UTF-8", PYTHONDONTWRITEBYTECODE="1", SHELL="/bin/bash",
            PATH=":".join([os.path.join(self.state, "bin"), os.path.dirname(CLAUDE), os.path.dirname(CODEX),
                           "/usr/local/bin", "/usr/bin", "/bin"]),
        )
        return env

    # -- the remote machine
    def remote_box(self, server):
        """SERVER (an argv) as the remote machine: in a process namespace of its own, under
        remote_init.py as process 1, which also runs the checker there. The user's home is hidden
        but for what the remote needs (its own HOME, the toolchain, the binaries), /tmp is its own,
        and the server and everything it runs see neither the run's local side nor the tasks."""
        home = os.path.expanduser("~")
        rtmp = os.path.join(self.state, "rtmp")
        os.makedirs(rtmp, exist_ok=True)
        os.makedirs(os.path.join(self.remote, ".tmux"), mode=0o700, exist_ok=True)
        # No `tty` group: in the sandbox's user namespace it maps to nobody, and sshd, which gives
        # a terminal to that group if it exists, fails to; without it the terminal stays the user's.
        group = os.path.join(self.state, "group")
        with open("/etc/group") as f, open(group, "w") as out:
            out.writelines(line for line in f if not line.startswith("tty:"))
        outer = ["bwrap", "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-pid",
                 "--die-with-parent", "--tmpfs", home, "--bind", rtmp, "/tmp", "--ro-bind", group, "/etc/group",
                 "--ro-bind", os.path.join(home, ".rustup"), os.path.join(home, ".rustup"),
                 "--ro-bind", os.path.join(home, ".cargo"), os.path.join(home, ".cargo"),
                 "--ro-bind", BINS, BINS, "--ro-bind", HERE, HERE,
                 "--bind", self.root, self.root, "--bind", self.remote, self.remote, "--"]
        inner = ["bwrap", "--bind", "/", "/", "--dev", "/dev", "--die-with-parent",
                 "--tmpfs", self.local, "--tmpfs", HERE, "--"]
        init = ["python3", "-I", os.path.join(HERE, "remote_init.py"), self.state,
                os.path.join(self.task["dir"], "check.py"), self.local, self.remote, "--"]
        return outer + init + inner + server

    def remote_check(self, seconds=600):
        """The task's checker, run by the remote's process 1."""
        res = os.path.join(self.state, "check.res")
        if os.path.exists(res):
            os.remove(res)
        open(os.path.join(self.state, "check.req"), "w").close()
        wait_for(lambda: os.path.exists(res), seconds, "the checker")
        ok, why = json.load(open(res))
        return ok, why

    def start_koh(self):
        koh = CONFIGS[self.config]["bin"]
        lenv = self.local_env()
        cid = subprocess.run([koh, "id"], env=lenv, capture_output=True, text=True, check=True).stdout.strip()
        serve = [koh, "serve", "--local", "--port", str(self.port), "--allow", cid, "--shell", "bash"]
        p = subprocess.Popen(self.remote_box(serve), cwd=self.remote, env=self.remote_env(),
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, start_new_session=True)
        self.procs.append(p)
        log = os.path.join(self.state, "serve.log")
        read = lambda: os.path.exists(log) and re.search(r"[0-9a-f]{64}", open(log).read())
        sid = wait_for(read, 20, "koh serve's id").group(0)
        # Saved with its address where this koh can (`--direct` on `servers add`), as a user would.
        add = [koh, "servers", "add", "bench", sid]
        if subprocess.run(add + ["--direct", f"127.0.0.1:{self.port}"], env=lenv, capture_output=True).returncode:
            subprocess.run(add, env=lenv, capture_output=True, check=True)

    def start_sshd(self):
        s = self.state
        for key in ("host", "client"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", os.path.join(s, key)], check=True)
        shutil.copy(os.path.join(s, "client.pub"), os.path.join(s, "authorized_keys"))
        shell = os.path.join(s, "remote-shell")
        env = " ".join(f"{k}='{v}'" for k, v in self.remote_env().items())
        with open(shell, "w") as f:
            f.write("#!/bin/sh\n"
                    f"cd '{self.remote}' || exit 1\n"
                    "case \"$SSH_ORIGINAL_COMMAND\" in sftp|internal-sftp|*/sftp-server) "
                    f"exec env -i {env} /usr/lib/ssh/sftp-server;; esac\n"
                    f"if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then exec env -i {env} SSH_ORIGINAL_COMMAND=\"$SSH_ORIGINAL_COMMAND\" "
                    "/bin/bash -c \"$SSH_ORIGINAL_COMMAND\"; fi\n"
                    f"exec env -i {env} /bin/bash -i\n")
        os.chmod(shell, 0o755)
        with open(os.path.join(s, "sshd_config"), "w") as f:
            f.write(f"Port {self.port}\nListenAddress 127.0.0.1\nHostKey {s}/host\nAuthorizedKeysFile {s}/authorized_keys\n"
                    f"PidFile {s}/sshd.pid\nUsePAM no\nStrictModes no\nPasswordAuthentication no\n"
                    f"KbdInteractiveAuthentication no\nForceCommand {shell}\nSubsystem sftp internal-sftp\n"
                    f"SetEnv KOHBENCH={self.marker}-remote\n")
        with open(os.path.join(s, "ssh_config"), "w") as f:
            f.write(f"Host bench\n  HostName 127.0.0.1\n  Port {self.port}\n  User {os.environ.get('USER', '')}\n"
                    f"  IdentityFile {s}/client\n  IdentitiesOnly yes\n  StrictHostKeyChecking no\n"
                    f"  UserKnownHostsFile {s}/known_hosts\n  LogLevel ERROR\n")
        sshd = ["/usr/bin/sshd", "-D", "-f", os.path.join(s, "sshd_config"), "-E", os.path.join(s, "sshd.log")]
        p = subprocess.Popen(self.remote_box(sshd), cwd=self.remote, env=self.remote_env(),
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, start_new_session=True)
        self.procs.append(p)
        wait_for(lambda: os.path.exists(os.path.join(s, "sshd.pid")), 10, "sshd")

    # -- the local side
    def wrappers(self):
        bin_dir = os.path.join(self.state, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        log = os.path.join(self.state, "calls.log")
        real = {"fux": FUX, "sleep": shutil.which("sleep"), "ssh": "/usr/bin/ssh", "scp": "/usr/bin/scp",
                "sftp": "/usr/bin/sftp", "rsync": shutil.which("rsync")}
        if self.tool == "koh":
            real["koh"] = CONFIGS[self.config]["bin"]
        flags = {"ssh": f"-F {self.state}/ssh_config", "scp": f"-F {self.state}/ssh_config",
                 "sftp": f"-F {self.state}/ssh_config"}
        for name, target in real.items():
            if not target:
                continue
            extra = flags.get(name, "") if self.tool == "ssh" else ""
            with open(os.path.join(bin_dir, name), "w") as f:
                f.write(f'#!/bin/sh\nprintf "%s\\t%s\\t%s\\n" "$(date +%s.%N)" "{name}" "$*" >> "{log}"\n'
                        f'exec "{target}" {extra} "$@"\n')
            os.chmod(os.path.join(bin_dir, name), 0o755)

    def sandbox(self, argv):
        """ARGV in bubblewrap: the remote sides, the task sets and the results hidden."""
        hide = [REMOTES, RUNS, os.path.join(SCRATCH, "results"), REPO, os.path.expanduser("~/code/notes"),
                os.path.expanduser("~/.claude/projects/-home-gsc")]
        ltmp = os.path.join(self.state, "ltmp")
        os.makedirs(ltmp, exist_ok=True)
        # A shell the agent starts (in fux) reads this, not the user's: the run's wrappers first in
        # PATH (the user's own koh is hidden with ~/.cargo/bin), and no history written.
        rc = os.path.join(self.state, "bashrc")
        with open(rc, "w") as f:
            f.write(f"PATH={os.path.join(self.state, 'bin')}:{os.path.dirname(CLAUDE)}:{os.path.dirname(CODEX)}"
                    ":/usr/local/bin:/usr/bin:/bin\n"
                    "HISTFILE=/dev/null\nPS1='\\w\\$ '\n")
        home = os.path.expanduser("~")
        box = ["bwrap", "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-pid", "--die-with-parent",
               "--tmpfs", os.path.join(home, ".cargo", "bin")]
        for name in (".bashrc", ".bash_profile", ".profile"):
            if os.path.exists(os.path.join(home, name)):
                box += ["--ro-bind", rc, os.path.join(home, name)]
        for path in hide:
            if os.path.exists(path):
                box += ["--tmpfs", path]
        return box + ["--bind", self.root, self.root, "--bind", ltmp, "/tmp", "--chdir", self.local, "--"] + argv

    def start_fux(self, env):
        sock = env["FUX_SOCKET"]
        p = subprocess.Popen(self.sandbox([FUX, "__serve", sock]), env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=open(os.path.join(self.state, "fux.log"), "w"),
                             start_new_session=True)
        self.procs.append(p)
        wait_for(lambda: os.path.exists(sock), 10, "the agent's fux server")

    def drop_watch(self, stop):
        """Kills the tool's client processes once the task's drop file appears on the remote."""
        when = self.task.get("drop", {}).get("when")
        if not when:
            return
        path = os.path.join(self.remote, when)
        while not stop.is_set():
            if os.path.exists(path):
                time.sleep(float(self.task["drop"].get("after", 0.5)))
                bins = {os.path.basename(c["bin"]) for c in CONFIGS.values() if "bin" in c}
                names = {"koh"} | bins if self.tool == "koh" else {"ssh", "scp", "sftp"}
                # The local side's clients only: the server (`koh-master serve`) has the same name.
                self.dropped = kill_marked(self.marker + "-local", only=names)
                return
            time.sleep(0.2)

    def teardown(self):
        for p in self.procs:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        kill_marked(self.marker + "-local")
        kill_marked(self.marker + "-remote")
        for p in self.procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def go(self, model, timeout):
        self.dropped = None
        self.lay_out()
        self.wrappers()
        env = self.local_env()
        record = {"config": self.config, "task": self.task["id"], "cat": self.task.get("cat", ""),
                  "difficulty": self.task.get("difficulty", ""), "root": self.root}
        try:
            (self.start_koh if self.tool == "koh" else self.start_sshd)()
            self.start_fux(env)
            readme = os.path.join(DOCS, self.config, "README.md")
            learn = LEARN[self.tool].format(readme=readme, port=self.port)
            prompt = PROMPT.format(learn=learn, local=self.local, goal=self.task["goal"].strip())
            with open(os.path.join(self.state, "prompt.md"), "w") as f:
                f.write(prompt)
            stop = threading.Event()
            watcher = threading.Thread(target=self.drop_watch, args=(stop,), daemon=True)
            watcher.start()
            started = time.time()
            argv = agent_argv(model, prompt, self.local)
            record["agent"] = model
            stream_path = os.path.join(self.state, "stream.jsonl")
            with open(stream_path, "w") as out, open(os.path.join(self.state, "agent.err"), "w") as err:
                agent = subprocess.Popen(self.sandbox(argv), env=env, stdout=out, stderr=err,
                                         stdin=subprocess.DEVNULL, start_new_session=True)
                try:
                    agent.wait(timeout=self.task.get("timeout", timeout))
                    record["timed_out"] = False
                except subprocess.TimeoutExpired:
                    os.killpg(agent.pid, signal.SIGKILL)
                    agent.wait()
                    record["timed_out"] = True
            stop.set()
            record["seconds"] = round(time.time() - started, 1)
            record.update(read_stream(stream_path, self.tool), dropped=self.dropped)
            record.update(read_calls(os.path.join(self.state, "calls.log"), self.tool))
            ok, why = self.remote_check()
            record.update(ok=ok, why=why)
        except Exception as e:
            record.update(ok=False, why=f"harness error: {type(e).__name__}: {e}", harness_error=True)
        finally:
            self.teardown()
        return record


def read_stream(path, tool):
    commands, final, usage = [], "", {}
    for line in open(path, errors="replace"):
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        # codex exec --json: items, and the turn's usage.
        item = msg.get("item") or {}
        if msg.get("type") == "item.completed" and item.get("type") == "command_execution":
            commands.append(item.get("command") or "")
        if msg.get("type") == "item.completed" and item.get("type") == "agent_message":
            final = item.get("text") or ""
        if msg.get("type") == "turn.completed":
            u = msg.get("usage") or {}
            usage = {"tokens_in": u.get("input_tokens"), "tokens_out": u.get("output_tokens")}
        # claude -p --output-format stream-json.
        if msg.get("type") == "assistant":
            for part in msg.get("message", {}).get("content", []):
                if part.get("type") == "tool_use":
                    inp = part.get("input", {})
                    commands.append(inp.get("command") or json.dumps(inp)[:400])
        if msg.get("type") == "result":
            final = msg.get("result") or ""
            usage = {"cost_usd": msg.get("total_cost_usd"), "turns": msg.get("num_turns")}
    loops = sum(1 for c in commands if re.search(r"\b(while|until)\b.*\b(do)\b", c, re.S))
    return dict(bash_calls=len(commands), polling_loops=loops,
                base64=sum(1 for c in commands if "base64" in c),
                friction=final.split("FRICTION:")[-1].strip()[:800] if "FRICTION:" in final else "",
                final=final[-1500:], **usage)


def read_calls(path, tool):
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    calls = [l.split("\t") for l in lines]
    count = lambda names: sum(1 for c in calls if len(c) > 1 and c[1] in names)
    secs = 0.0
    for c in calls:
        if len(c) > 2 and c[1] == "sleep":
            try:
                secs += float(c[2].split()[0])
            except (ValueError, IndexError):
                pass
    remote = {"koh"} if tool == "koh" else {"ssh", "scp", "sftp", "rsync"}
    return dict(tool_calls=count(remote), fux_calls=count({"fux"}), sleeps=count({"sleep"}), sleep_s=round(secs, 1))


# ------------------------------------------------------------------ validation

def validate(task, slot):
    """Whether TASK is sound: its checker fails the untouched state, and its
    reference solution (`solve.sh`, run locally with `ssh bench` set up, the
    drop included) passes it. Returns (ok, why)."""
    if not os.path.exists(os.path.join(task["dir"], "solve.sh")):
        return False, "no solve.sh"
    problems = []
    for mode in ("noop", "solve"):
        run = Run("validate", "ssh", task, slot, 0)
        run.dropped = None
        run.lay_out()
        run.wrappers()
        env = run.local_env()
        try:
            run.start_sshd()
            if mode == "solve":
                stop = threading.Event()
                threading.Thread(target=run.drop_watch, args=(stop,), daemon=True).start()
                p = subprocess.run(["bash", os.path.join(task["dir"], "solve.sh")], cwd=run.local, env=env,
                                   capture_output=True, text=True, timeout=task.get("solve_timeout", 300))
                stop.set()
            ok, why = run.remote_check()
            if mode == "noop" and ok:
                problems.append(f"the untouched state passes ({why})")
            if mode == "solve" and not ok:
                problems.append(f"solve.sh fails: {why}; exit {p.returncode}; stderr {p.stderr[-300:]!r}")
            if mode == "solve" and task.get("drop") and not run.dropped:
                problems.append("the drop never fired")
        except Exception as e:
            problems.append(f"{mode}: {type(e).__name__}: {e}")
        finally:
            run.teardown()
    return not problems, "; ".join(problems) or "ok"


# ------------------------------------------------------------------ driver

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--set", required=True)
    r.add_argument("--configs", default="koh-master")
    r.add_argument("--tasks", default="all")
    r.add_argument("--repeats", type=int, default=1)
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--slot-base", type=int, default=0)
    r.add_argument("--model", default="haiku", help="haiku (claude -p), or codex-sol / codex-sol-fast (codex exec, gpt-6.1-sol, standard or fast tier)")
    r.add_argument("--timeout", type=int, default=1200)
    r.add_argument("--out", required=True)
    v = sub.add_parser("validate")
    v.add_argument("--set", required=True)
    v.add_argument("--tasks", default="all")
    v.add_argument("--workers", type=int, default=2)
    v.add_argument("--slot-base", type=int, default=40)
    args = ap.parse_args()
    if args.cmd == "validate":
        tasks = load_set(args.set)
        if args.tasks != "all":
            tasks = [t for t in tasks if t["id"] in set(args.tasks.split(","))]
        bad = 0
        import queue
        slots = queue.Queue()
        for n in range(args.slot_base, args.slot_base + min(args.workers, 4)):
            slots.put(n)

        def one(t):
            slot = slots.get()
            try:
                return validate(t, slot)
            finally:
                slots.put(slot)

        with concurrent.futures.ThreadPoolExecutor(min(args.workers, 4)) as pool:
            futs = {pool.submit(one, t): t for t in tasks}
            for fut in concurrent.futures.as_completed(futs):
                ok, why = fut.result()
                bad += not ok
                print(f"{'ok ' if ok else 'BAD'} {futs[fut]['id']:<8} {why}", flush=True)
        sys.exit(1 if bad else 0)
    assert args.workers <= 12, "at most 12 agents at once"
    for config in args.configs.split(","):
        c = CONFIGS[config]
        if "bin" in c:
            assert os.path.exists(c["bin"]), f"build {c['bin']} first"
            assert os.path.exists(os.path.join(DOCS, config, "README.md")), f"copy the README to {DOCS}/{config}/"
    tasks = load_set(args.set)
    if args.tasks != "all":
        want = set(args.tasks.split(","))
        tasks = [t for t in tasks if t["id"] in want]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    tag = os.path.splitext(os.path.basename(args.out))[0]
    jobs = [(c, t, n) for n in range(args.repeats) for t in tasks for c in args.configs.split(",")]
    results = json.load(open(args.out)) if os.path.exists(args.out) else []
    done = {(x["config"], x["task"], x.get("repeat", 0)) for x in results if not x.get("harness_error")}
    results = [x for x in results if not x.get("harness_error")]
    jobs = [j for j in jobs if (j[0], j[1]["id"], j[2]) not in done]
    print(f"{len(jobs)} runs to do", flush=True)
    lock = threading.Lock()
    free = list(range(args.slot_base, args.slot_base + args.workers))

    def work(job, slot):
        config, task, n = job
        rec = Run(tag, config, task, slot, n).go(args.model, args.timeout)
        rec["repeat"] = n
        return rec

    with concurrent.futures.ThreadPoolExecutor(args.workers) as pool:
        pending = {}
        while jobs or pending:
            while jobs and free:
                slot = free.pop()
                pending[pool.submit(work, jobs.pop(0), slot)] = slot
            finished, _ = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for fut in finished:
                free.append(pending.pop(fut))
                rec = fut.result()
                with lock:
                    results.append(rec)
                    tmp = args.out + ".tmp"
                    with open(tmp, "w") as f:
                        json.dump(results, f, indent=1)
                    os.replace(tmp, args.out)
                print(f"{'ok ' if rec['ok'] else 'FAIL'} {rec['config']:<10} {rec['task']:<8} {rec.get('seconds', 0):>6}s "
                      f"tool={rec.get('tool_calls', 0)} fux={rec.get('fux_calls', 0)} sleep={rec.get('sleep_s', 0)}s "
                      f"${rec.get('cost_usd') or 0:.3f} {'' if rec['ok'] else rec['why'][:90]}", flush=True)


if __name__ == "__main__":
    main()
