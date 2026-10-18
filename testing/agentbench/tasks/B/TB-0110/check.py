import os, socket


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def get(port, path):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(f"GET {path} HTTP/1.0\r\nHost: x\r\n\r\n".encode())
        data = b""
        while True:
            d = s.recv(4096)
            if not d:
                return data
            data += d


def check(local, remote):
    pf = os.path.join(remote, ".bench", "asset-server.pid")
    if not os.path.exists(pf):
        return False, "asset-server never started"
    pid = int(open(pf).read())
    port = int(open(os.path.join(remote, "asset-server.port")).read())
    path = os.path.join(local, "answer.txt")
    got = open(path).read().strip() if os.path.exists(path) else None
    if got != str(port):
        return False, f"answer {got!r}, but the server listens on {port}"
    for n in range(3):
        try:
            reply = get(port, "/health")
        except OSError as e:
            return False, f"the server does not answer on {port}: {e}"
        if b"ok asset-server" not in reply:
            return False, f"unexpected reply {reply[:100]!r}"
    if not alive(pid):
        return False, "asset-server died (after logging a request?)"
    return True, "asset-server is up and serving"
