#!/usr/bin/env python3
"""What a session costs a person at a terminal, measured on the real binary beside a plain fux pane.

    cargo build --release && tools/timing.py target/release/koh [echo] [scroll] [full] [flood] [again]

Each step runs once through `koh connect` (a `koh serve` on loopback, a session, koh's viewer in a
200x60 pty this script owns) and once as a plain pane seen through `koh fux view` in such a pty: the
same holder and viewer without koh between them. It prints a table and leaves nothing behind. Linux
(it reads /proc for the processors' time); python3 and nothing else.

  echo    a key until its echo is on the terminal, typed slowly (100 ms apart) and fast (10 ms)
  scroll  the same while the program prints a line every 5, 20 and 50 ms; how many rounds a second
          the pane's holder wrote and how many reached the client's mirror; what the server and
          the client cost meanwhile
  full    the same after `seq 1 560000`: 3.8 MB in each history file, which the server proves
          each time a line is added to them
  flood   `seq 1 2000000`, until its end is on the terminal; then a client that comes anew
  again   a `koh mount` whose server is stopped and started: until its mirror is the pane again,
          after nothing changed and after the history was put aside meanwhile (`history.1`)
"""
import fcntl, os, pty, select, shutil, signal, socket, struct, subprocess, sys, tempfile, termios, time

KOH = os.path.abspath(sys.argv[1])
WHAT = sys.argv[2:] or ['echo', 'scroll', 'full', 'flood', 'again']
ROOT = tempfile.mkdtemp(prefix='koh-timing-')
STARTED = []  # every process this script started, to end them all
KEYS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#%^&*()_+=[]{};:,.<>?/~'
ECHO = "stty -icanon min 1; exec cat >/dev/null"


def env(**more):
    e = dict(os.environ, HOME=f'{ROOT}/home', KOH_CONFIG_DIR=f'{ROOT}/cli', XDG_RUNTIME_DIR=f'{ROOT}/run-c')
    e.update(more)
    return e


class Tty:
    """A program in a 200x60 pty: what it drew, and keys for it."""

    def __init__(self, argv, **more):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 60, 200, 0, 0))
        self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env(**more), start_new_session=True)
        os.close(slave)
        os.set_blocking(self.master, False)
        STARTED.append(self.proc)
        self.drawn = b''

    def read(self, wait):
        if select.select([self.master], [], [], wait)[0]:
            try:
                some = os.read(self.master, 1 << 16)
            except OSError:
                some = b''
            self.drawn += some
            return some
        return b''

    def until(self, text, most=60.0):
        began = time.monotonic()
        while text not in self.drawn:
            if time.monotonic() - began > most:
                raise SystemExit(f'not in {most} s: {text!r} on the terminal of {self.proc.args}')
            self.read(0.05)
        return time.monotonic() - began

    def key(self, key, most=3.0):
        """Types one key; the milliseconds until it is drawn."""
        while self.read(0):
            pass
        began = time.monotonic()
        os.write(self.master, key.encode())
        while time.monotonic() - began < most:
            if key.encode() in self.read(most):
                break
        return (time.monotonic() - began) * 1000

    def end(self):
        self.proc.kill()
        self.proc.wait()
        os.close(self.master)


def serve():
    port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port.bind(('127.0.0.1', 0))
    addr = '127.0.0.1:%d' % port.getsockname()[1]
    port.close()
    client = subprocess.run([KOH, 'id'], env=env(), capture_output=True, text=True).stdout.strip()
    def start():
        e = env(KOH_CONFIG_DIR=f'{ROOT}/srv', XDG_RUNTIME_DIR=f'{ROOT}/run-s')
        server = subprocess.Popen([KOH, 'serve', '--no-relay', '--shell', '/bin/sh', '--direct', addr, '--allow', client],
                                  env=e, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, start_new_session=True)
        STARTED.append(server)
        said = {}
        while 'sessions dir' not in said:
            label, _, rest = server.stderr.readline().partition(':')
            said[label.strip()] = rest.strip()
        return server, said['koh server id'], said['sessions dir']
    return start, addr


def stats(ms):
    ms = sorted(ms)
    at = lambda share: ms[min(len(ms) - 1, int(len(ms) * share))]
    return f'{at(0.5):7.2f} {at(0.99):7.2f} {ms[-1]:7.2f}'


def keys(tty, count, gap):
    out = []
    for n in range(count):
        out.append(tty.key(KEYS[n % len(KEYS)]))
        if n % 40 == 39:
            os.write(tty.master, b'\n')
        time.sleep(gap)
    return out


def ticks(pid):
    """The processor time a process has had, in seconds."""
    try:
        fields = open(f'/proc/{pid}/stat').read().rsplit(') ', 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')
    except OSError:
        return 0.0


def number(pane):
    try:
        return os.stat(f'{pane}/generation').st_ino
    except OSError:
        return 0


def holder(pane):
    return int(open(f'{pane}/status').readline().split()[1])


def plain(name, program):
    """A pane of a fux session of this script's own, and a viewer of it: no koh between them."""
    session = f'{ROOT}/plain'
    os.makedirs(f'{ROOT}/nokeys', exist_ok=True)
    e = env(XDG_RUNTIME_DIR=session, COLUMNS='200', LINES='60')
    pane = subprocess.run([KOH, 'fux', 'start', f'{session}/{name}/p', '--', 'sh', '-c', program], env=e, capture_output=True, text=True).stdout.strip()
    return Tty([KOH, 'fux', 'view', f'{session}/{name}', f'{ROOT}/nokeys'], XDG_RUNTIME_DIR=session), pane


def main():
    for folder in ['home', 'cli', 'srv', 'run-c', 'run-s']:
        os.makedirs(f'{ROOT}/{folder}')
    start, addr = serve()
    server, server_id, sessions = start()
    connect = lambda *asks: Tty([KOH, 'connect', server_id, '--direct', addr, *asks])
    mirror_of = lambda tty: next((f'{ROOT}/run-c/{d}/session/connect/remote' for d in os.listdir(f'{ROOT}/run-c') if d.startswith(f'koh-connect-{tty.proc.pid}-')), None)
    print(f'koh {subprocess.run([KOH, "--version"], capture_output=True, text=True).stdout.strip()}, load {os.getloadavg()[0]:.1f}; milliseconds: median, p99, most')

    if 'echo' in WHAT:
        runs = {'koh connect': [[], []], 'plain fux view': [[], []]}
        for turn in range(3):
            for name in runs:
                tty = connect('--new', '--', 'sh', '-c', ECHO) if name == 'koh connect' else plain(f'e{turn}', ECHO)[0]
                time.sleep(0.7)
                tty.key('~')
                runs[name][0] += keys(tty, 40, 0.1)
                runs[name][1] += keys(tty, 120, 0.01)
                tty.end()
        for name, (slow, fast) in runs.items():
            print(f'a key until its echo, typed slowly   {name:15} {stats(slow)}   ({len(slow)} keys)')
            print(f'a key until its echo, typed fast     {name:15} {stats(fast)}   ({len(fast)} keys)')

    for filled in [what for what in ['scroll', 'full'] if what in WHAT]:
        for every in ['0.005', '0.02', '0.05']:
            fill = 'seq 1 560000; ' if filled == 'full' else ''
            program = f'{fill}stty -icanon min 1; (n=0; while :; do n=$((n+1)); echo line $n; sleep {every}; done) & exec cat >/dev/null'
            for name in ['koh connect', 'plain fux view']:
                if name == 'koh connect':
                    before = set(os.listdir(sessions))
                    tty = connect('--new', '--', 'sh', '-c', program)
                    time.sleep(3.0 if fill else 1.0)
                    pane = f'{sessions}/{(set(os.listdir(sessions)) - before).pop()}'
                    watched = [pane, mirror_of(tty)]
                else:
                    tty, pane = plain(f's{filled}{every}', program)
                    time.sleep(3.0 if fill else 1.0)
                    watched = [pane]
                seen, rounds, cost = [number(w) for w in watched], [0] * len(watched), (ticks(server.pid), ticks(tty.proc.pid))
                began, echoes, next_key = time.monotonic(), [], time.monotonic() + 0.2
                while time.monotonic() - began < 6:
                    # (The folders' numbers are looked at each millisecond; a key every 150 ms.)
                    for at, folder in enumerate(watched):
                        now = number(folder)
                        if now != seen[at]:
                            seen[at], rounds[at] = now, rounds[at] + 1
                    if time.monotonic() >= next_key:
                        echoes.append(tty.key(KEYS[len(echoes) % len(KEYS)]))
                        next_key = time.monotonic() + 0.15
                    tty.read(0.001)
                took = time.monotonic() - began
                # (`generation` is replaced twice a round: odd, then even.)
                per = ' '.join(f'{r / 2 / took:5.1f}' for r in rounds)
                cpu = f'server {100 * (ticks(server.pid) - cost[0]) / took:4.1f}% client {100 * (ticks(tty.proc.pid) - cost[1]) / took:4.1f}%' if name == 'koh connect' else f'viewer {100 * (ticks(tty.proc.pid) - cost[1]) / took:4.1f}%'
                history = f', {os.path.getsize(pane + "/history") / 1e6:.1f} MB of history' if fill else ''
                print(f'a line every {float(every) * 1000:2.0f} ms{history}: a key\'s echo    {name:15} {stats(echoes)}   rounds a second (holder{", mirror" if len(rounds) > 1 else ""}): {per}   {cpu}')
                tty.end()

    if 'flood' in WHAT or 'again' in WHAT:
        # (Its last line is letters where the numbers were, so the viewer draws it whole; and it is
        # not in the command as it is typed.)
        flood = b"seq 1 2000000; echo THE-''END\n"
        took = {}
        for name in ['koh connect', 'plain fux view']:
            if name == 'koh connect':
                before = set(os.listdir(sessions))
                tty = connect('--new')
                tty.until(b'$')
                flooded = (set(os.listdir(sessions)) - before).pop()
            else:
                tty = plain('f', 'exec sh')[0]
                tty.until(b'$')
            os.write(tty.master, flood)
            took[name] = tty.until(b'THE-END', 120)
            tty.end()
        print(f'seq 1 2000000, until its end is on the terminal: koh connect {took["koh connect"]:.2f} s, plain fux view {took["plain fux view"]:.2f} s')
        pane = f'{sessions}/{flooded}'
        size = sum(os.path.getsize(f'{pane}/{f}') for f in os.listdir(pane) if os.path.isfile(f'{pane}/{f}'))
        began = time.monotonic()
        tty = connect('--session', flooded)
        tty.until(b'THE-END')
        print(f'a client that comes anew to that session ({size / 1e6:.1f} MB of files): its end on the terminal after {(time.monotonic() - began) * 1000:.0f} ms')
        tty.end()

    if 'again' in WHAT:
        mirror, said = f'{ROOT}/mounted', f'{ROOT}/mount.said'
        mount = subprocess.Popen([KOH, 'mount', server_id, '--direct', addr, '--session', flooded, mirror], env=env(), stdin=subprocess.DEVNULL, stderr=open(said, 'w'))
        STARTED.append(mount)
        size = lambda folder: sum(os.path.getsize(f'{folder}/{f}') for f in ['history', 'history.styled'])
        same = lambda: open(f'{mirror}/generation').read() == open(f'{pane}/generation').read() and size(mirror) == size(pane)
        backs = lambda: open(said).read().count('the link is back')
        while not (os.path.exists(f'{mirror}/generation') and same()):
            time.sleep(0.01)
        for what, typed in [('nothing changed', b''), ('a line printed', b'echo one-line\n'), ('the history put aside meanwhile', b'seq 1 700000\n')]:
            server.send_signal(signal.SIGINT)
            server.wait()
            aside = os.stat(f'{pane}/history.1').st_ino if os.path.exists(f'{pane}/history.1') else 0
            had, round_before, came = size(pane), number(mirror), backs()
            with open(f'{pane}/in', 'wb') as keys_in:
                keys_in.write(typed)
            time.sleep(4 if typed.startswith(b'seq') else 0.5)
            moved = os.path.exists(f'{pane}/history.1') and os.stat(f'{pane}/history.1').st_ino != aside
            server, _, _ = start()
            # From the server's answer to the attach (koh says the link is back) until the first
            # round has been applied: the mirror's list, the server's reading of it, the round.
            while backs() == came:
                time.sleep(0.0005)
            began = time.monotonic()
            while number(mirror) == round_before or not same():
                time.sleep(0.0005)
                assert time.monotonic() - began < 60, 'the mirror did not become the pane'
            grew = (size(pane) - had) / 1e6 if not moved else float('nan')
            print(f'a mount whose server came back, {what}{" (history.1 is another file)" if moved else ""}: from the answer to its attach until its mirror is the pane again {(time.monotonic() - began) * 1000:.0f} ms' + (f' ({grew:.2f} MB added)' if grew == grew else ''))
        mount.kill()

try:
    main()
finally:
    for pane in [d for root in [f'{ROOT}/run-s/koh/fux/koh-sessions', f'{ROOT}/plain'] if os.path.isdir(root) for d, _, files in os.walk(root) if 'status' in files]:
        try:
            os.kill(holder(pane), signal.SIGKILL)
        except (OSError, ValueError, IndexError):
            pass
    for proc in STARTED:
        if proc.poll() is None:
            proc.kill()
    shutil.rmtree(ROOT, ignore_errors=True)
