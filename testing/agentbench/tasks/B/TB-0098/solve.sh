python3 - <<'PY'
import fcntl, os, pty, re, select, struct, sys, termios, time


class P:
    """A program on a pseudo-terminal, driven like expect."""

    def __init__(self, argv, rows=24, cols=80):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            os.execvp(argv[0], argv)
        self.buf = b""

    def expect(self, pat, timeout=90):
        pat = pat.encode() if isinstance(pat, str) else pat
        end = time.time() + timeout
        while True:
            m = re.search(pat, self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            left = end - time.time()
            if left <= 0:
                sys.exit(f"timeout waiting for {pat!r}: {self.buf[-400:]!r}")
            r, _, _ = select.select([self.fd], [], [], left)
            if r:
                try:
                    d = os.read(self.fd, 65536)
                except OSError:
                    d = b""
                if not d:
                    sys.exit(f"eof waiting for {pat!r}: {self.buf[-400:]!r}")
                self.buf += d

    def send(self, data):
        os.write(self.fd, data.encode() if isinstance(data, str) else data)

    def wait(self):
        while True:
            try:
                d = os.read(self.fd, 65536)
            except OSError:
                break
            if not d:
                break
            self.buf += d
        return os.waitpid(self.pid, 0)[1]

p = P(["ssh", "-tt", "bench", "~/bin/setup-wizard"])
p.expect("press button")
p.send("\x15ladder-eu-3\t")
p.send("\x1b[C\x1b[C\t")
p.send("\x7f\x7f48\t")
p.send("\r")
p.expect("setup-wizard: saved")
p.wait()
PY
