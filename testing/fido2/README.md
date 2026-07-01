# koh FIDO2 / security-key end-to-end test

A self-contained, hardware-free test of koh's optional FIDO2 second factor (`koh serve --require-sk`).
It drives the **real** production path — the actual `koh` binary, a real `ssh-agent`, and real
`sk-ssh-ed25519@openssh.com` signatures — using OpenSSH's **software** FIDO2 authenticator
(`sk-dummy.so`) in place of a physical security key. No USB token, no phone, no purchase.

> Why a container? OpenSSH's `ed25519-sk` keys are signed through `libfido2` over USB/HID, and a
> phone passkey can't stand in (wrong transport). The reproducible way to get a *software*
> authenticator into that path is OpenSSH's own `sk-dummy` provider, which is trivial to build on
> Linux — so the whole thing is packaged as a Docker image that needs nothing from your host but
> Docker itself.

## Run it

```sh
testing/fido2/run.sh
```

The first run builds the image (compiles koh + OpenSSH from source — a few minutes); later runs are
cached and start in seconds. Options:

```sh
testing/fido2/run.sh --rebuild   # force a fresh image (e.g. after changing koh)
testing/fido2/run.sh --shell     # open a shell in the image to poke around
```

You'll watch each scenario run and get a pass/fail summary; the process exits non-zero if any test
fails (so it drops straight into CI).

## What it checks

Two koh servers are started on loopback — one with `--require-sk`, one without — and these scenarios
run against them, each asserting the admission decision from the server's structured `koh::auth` log:

| # | Scenario | Expected |
|---|----------|----------|
| 1 | allowlisted id **+ the correct security key** | **admitted** |
| 2 | allowlisted id + a security key **not** on `--allow-sk` | rejected |
| 3 | allowlisted id but **no** security-key proof | rejected |
| 4 | correct security key but an **un-allowlisted endpoint id** | rejected (before the SK gate) |
| 5 | **default** endpoint-id-only auth (server without `--require-sk`) | admitted |

## How it maps to koh

- `sk-dummy.so` signs in software but echoes the **user-presence (touch) flag** the agent requests, so
  koh's touch requirement (`flags & 0x01`) is satisfied — exactly as a real tap would.
- The client uses `koh connect --sk-key <pub>`, which asks the running `ssh-agent` to sign koh's
  challenge — the same `AgentSkSigner` path a real hardware key uses (the one piece the in-repo unit
  tests can't cover).
- Admission is read from the server's audit log (`event=authn`/`authz`, `outcome=accepted|rejected`),
  the authoritative record of every gate.

## The one caveat

This proves the protocol, the wire format, the ssh-agent integration, and the accept/reject logic end
to end. It does **not** prove *hardware backing* — `sk-dummy` is software, and koh (by design) can't
attest that a key lives in real hardware (see [`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md)).
For that last mile you need a physical FIDO2 key. Everything else is exercised here.

## Files

- `Dockerfile` — builds koh + from-source OpenSSH + `sk-dummy.so` into one image.
- `run.sh` — host entry point (build if needed, then run).
- `harness/run-tests.sh` — the orchestrator that runs inside the container.
