#!/usr/bin/env python3
"""Process 1 of a run's remote side, in a process namespace of its own (bench.py starts it in
bubblewrap): it starts the server, reaps orphans, and runs the task's checker on request, so the
checker sees the remote's processes as the remote does.

    remote_init.py STATE CHECK_PY LOCAL REMOTE -- SERVER ARGV...

The server's output goes to STATE/serve.log. A request is STATE/check.req appearing; the answer
is STATE/check.res, JSON [ok, why]. It ends when the server does, or when it is killed.
"""
import importlib.util
import json
import os
import subprocess
import sys
import time

sys.dont_write_bytecode = True


def check(path, local, remote):
    try:
        spec = importlib.util.spec_from_file_location("check", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        ok, why = module.check(local, remote)
        return [bool(ok), str(why)]
    except Exception as e:  # a checker that crashes fails the run, and says so
        return [False, f"checker raised {type(e).__name__}: {e}"]


def main():
    state, check_py, local, remote = sys.argv[1:5]
    server = sys.argv[sys.argv.index("--") + 1:]
    log = open(os.path.join(state, "serve.log"), "w")
    child = subprocess.Popen(server, cwd=remote, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    request = os.path.join(state, "check.req")
    while True:
        # Process 1 reaps whatever is orphaned in the namespace, so nothing lingers as a zombie.
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                pid = 0
            if pid == 0:
                break
            if pid == child.pid:
                child.returncode = 0
        if os.path.exists(request):
            os.remove(request)
            answer = check(check_py, local, remote)
            tmp = os.path.join(state, "check.res.tmp")
            with open(tmp, "w") as f:
                json.dump(answer, f)
            os.replace(tmp, os.path.join(state, "check.res"))
        time.sleep(0.1)


if __name__ == "__main__":
    main()
