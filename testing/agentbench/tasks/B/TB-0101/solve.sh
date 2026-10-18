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

import re
p = P(["ssh", "-tt", "bench", "~/bin/vault"])
p.expect("vault> ")
p.send("auth\r")
ch = p.expect(rb"challenge: ([0-9a-f]+)").group(1).decode()
import subprocess
code = subprocess.run(["ssh", "bench", f"~/bin/otp {ch}"], capture_output=True, text=True).stdout.strip()
p.send(f"respond {code}\r")
p.expect("authenticated")
p.send("get release/signing-pass\r")
s = p.expect(rb"signing-pass\r\n([0-9a-f]+)\r\n").group(1).decode()
open("answer.txt", "w").write(s + "\n")
p.send("quit\r")
p.wait()
PY
