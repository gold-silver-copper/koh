python3 -I - <<'PY'
import fcntl, os, pty, re, select, struct, sys, termios, time


class Term:
    """A program on a pseudo-terminal, driven like expect."""

    def __init__(self, *argv, rows=40, cols=120):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp(argv[0], list(argv))
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.buf = b""

    def read(self, timeout):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return None
        try:
            d = os.read(self.fd, 65536)
        except OSError:
            d = b""
        return d

    def expect(self, pat, timeout=120):
        rx = re.compile(pat.encode() if isinstance(pat, str) else pat)
        end = time.time() + timeout
        while True:
            m = rx.search(self.buf)
            if m:
                self.buf = self.buf[m.end():]
                return m
            d = self.read(max(0, end - time.time()))
            if d is None:
                sys.exit(f"timeout waiting for {pat!r}; last output {self.buf[-400:]!r}")
            if not d:
                sys.exit(f"eof waiting for {pat!r}; last output {self.buf[-400:]!r}")
            self.buf += d

    def send(self, s, pause=0.15):
        os.write(self.fd, s.encode() if isinstance(s, str) else s)
        time.sleep(pause)

    def close(self, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            d = self.read(1)
            if d == b"":
                break
            if d:
                self.buf += d
        _, status = os.waitpid(self.pid, 0)
        return os.waitstatus_to_exitcode(status)

t = Term("ssh", "-tt", "bench", "~/bin/board")
t.expect("loaded")
t.send("\x1bOB"); t.send("\x1bOB")
t.send(">")
t.send("\x1bOA"); t.send("\x1bOA")
t.send(">")
t.send("s")
t.expect("saved")
t.send("q")
t.close()
PY
