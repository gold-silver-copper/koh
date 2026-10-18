import hashlib, io, os, stat, subprocess, tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "stampede-0.9.3-linux.tar.gz"
TOP = "stampede-0.9.3"


def check(local, remote):
    crate = os.path.join(HERE, "setup", "remote", "crates", "stampede")
    for side, root in (("local", os.path.join(local, "dist")), ("remote", os.path.join(remote, "dist"))):
        for f in (NAME, "SHA256SUMS"):
            if not os.path.exists(os.path.join(root, f)):
                return False, f"no {f} in the {side} dist/"
    data = open(os.path.join(local, "dist", NAME), "rb").read()
    if data != open(os.path.join(remote, "dist", NAME), "rb").read():
        return False, "the local archive differs from the remote one"
    sums = open(os.path.join(local, "dist", "SHA256SUMS")).read()
    if sums != open(os.path.join(remote, "dist", "SHA256SUMS")).read():
        return False, "the local SHA256SUMS differs from the remote one"
    if sums.strip() != f"{hashlib.sha256(data).hexdigest()}  {NAME}":
        return False, f"SHA256SUMS is {sums.strip()!r}, not the archive's hash in sha256sum format"
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
        members = tar.getmembers()
    except (tarfile.TarError, OSError, EOFError) as e:
        return False, f"the archive is not a gzipped tar: {e}"
    files = {}
    for m in members:
        name = m.name[2:] if m.name.startswith("./") else m.name
        name = name.rstrip("/")
        if name != TOP and not name.startswith(TOP + "/"):
            return False, f"entry {m.name!r} is not under {TOP}/"
        if m.isfile():
            files[name] = m
        elif not m.isdir():
            return False, f"entry {m.name!r} is not a plain file or directory"
    want = {f"{TOP}/bin/stampede", f"{TOP}/README.md", f"{TOP}/LICENSE"}
    if set(files) != want:
        return False, f"archive files {sorted(files)}, wanted {sorted(want)}"
    for f in ("README.md", "LICENSE"):
        if tar.extractfile(files[f"{TOP}/{f}"]).read() != open(os.path.join(crate, f), "rb").read():
            return False, f"{f} in the archive is not the crate's"
    b = files[f"{TOP}/bin/stampede"]
    if not b.mode & stat.S_IXUSR:
        return False, "bin/stampede is not executable in the archive"
    exe = os.path.join(remote, ".bench", "stampede-check")
    os.makedirs(os.path.dirname(exe), exist_ok=True)
    open(exe, "wb").write(tar.extractfile(b).read())
    os.chmod(exe, 0o755)
    try:
        ver = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10).stdout.strip()
        prof = subprocess.run([exe, "--build-info"], capture_output=True, text=True, timeout=10).stdout.strip()
    except OSError as e:
        return False, f"bin/stampede does not run: {e}"
    if ver != "stampede 0.9.3 (build 5f1c)":
        return False, f"bin/stampede --version says {ver!r}"
    if prof != "profile: release":
        return False, f"bin/stampede is not a release build ({prof!r})"
    return True, "release archive and checksum are right on both sides"
