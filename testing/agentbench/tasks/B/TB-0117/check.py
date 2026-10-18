import json, os, socket


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def check(local, remote):
    b = os.path.join(remote, ".bench")
    svcs = {}
    for n in ("metrics", "edge", "cache", "queue"):
        p = os.path.join(b, f"svc-{n}.json")
        if not os.path.exists(p):
            return False, "the stack was never started"
        svcs[n] = json.load(open(p))
    if alive(svcs["edge"]["pid"]):
        return False, "the stale process holding the API port still runs"
    dead = [n for n in ("metrics", "cache", "queue") if not alive(svcs[n]["pid"])]
    if dead:
        return False, f"other services were stopped: {dead}"
    p = os.path.join(b, "api-v2.json")
    if not os.path.exists(p):
        return False, "api-v2 never started"
    api = json.load(open(p))
    if api["port"] != svcs["edge"]["port"] or not alive(api["pid"]):
        return False, "api-v2 is not running on the API port"
    try:
        with socket.create_connection(("127.0.0.1", api["port"]), timeout=5) as s:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            reply = b""
            while True:
                d = s.recv(4096)
                if not d:
                    break
                reply += d
    except OSError as e:
        return False, f"nothing answers on the API port: {e}"
    if b"api v2" not in reply:
        return False, f"the API port answers {reply[:80]!r}, not api-v2"
    return True, "api-v2 serves on the API port; the rest of the stack runs"
