# koh

A Rust, peer-to-peer remote shell inspired by [mosh](https://mosh.org), built on [iroh](https://iroh.computer) / QUIC.

koh gives you a responsive remote shell that survives network changes, suspend/resume, and reconnects — without SSH, open ports, or server-side accounts.

## Install and usage

```sh
cargo install koh
```

koh authorizes by endpoint id. There are no passwords or accounts.

```sh
# On the client, print its id:
koh id

# On the server, allow that client and start a shell host:
koh serve --allow <client-id>

# On the client, connect to the server:
koh connect <server-id>
```

Useful commands:

```sh
koh id                    # print this machine's endpoint id
koh serve --allow <id>    # host a shell for an allowed client
koh connect <id>          # connect to a server id
koh key passwd            # change the identity-key passphrase
koh key info              # show identity-key information
```

Useful flags:

```sh
--clipboard               # opt in to OSC-52 clipboard writes
--key-file <path>         # use a custom identity-key path
--session-ttl-secs <n>    # keep detached sessions around longer/shorter
--max-connections <n>     # limit concurrent connections
--max-sessions <n>        # limit sessions
```

Keys live under `~/.config/koh/` by default.

## Security keys (FIDO2, optional second factor)

By default koh authorizes by endpoint id alone. For a machine you want locked down harder, you can
*additionally* require a FIDO2 hardware security key (an OpenSSH `ed25519-sk` credential) — the server
won't attach a session or spawn a shell until the client proves possession of an allowlisted key with
a physical touch. This is layered on top of `--allow`, not a replacement for it.

```sh
# One-time: create a security-key-backed SSH key (touch the key when prompted).
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk

# On the server, require the key in addition to the endpoint-id allowlist:
koh serve --allow <client-id> --require-sk --allow-sk ~/.ssh/id_ed25519_sk.pub

# On the client, load the key into your ssh-agent, then connect with it:
ssh-add ~/.ssh/id_ed25519_sk
koh connect <server-id> --sk-key ~/.ssh/id_ed25519_sk.pub
```

```sh
--require-sk              # (server) require a security-key proof before admission
--allow-sk <pub|file>     # (server) allowlist an sk-ssh-ed25519 public key (repeatable)
--sk-key <pubkey-file>    # (client) authenticate with this security key via ssh-agent
```

Each connection (including transparent reconnects) issues a fresh challenge bound to both endpoint
ids, so a captured proof cannot be replayed or relayed to another server, and you touch the key again
on reconnect. koh verifies the signature and the user-presence (touch) flag but does not verify FIDO
*attestation*, so enrol only keys you generated on real hardware. Only `ed25519-sk` is supported today
(`ecdsa-sk` is rejected with a clear message). ssh-agent (unix) is the supported signer. See
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full security model and limitations.

**Platforms:** Linux, macOS, and Android via [Termux](https://termux.dev). Windows is not supported; use WSL2.

## Android / Termux install

1. Install Termux from the [Termux GitHub releases](https://github.com/termux/termux-app/releases). Do not use the old Play Store build.
2. In Termux, install Rust and build tools:

   ```sh
   pkg update
   pkg install rust clang pkg-config
   ```

3. Install koh:

   ```sh
   cargo install koh
   ```

If DNS resolution is broken on your Android device, try setting an explicit resolver:

```sh
KOH_DNS=1.1.1.1 koh connect <server-id>
```

## Highlights

- Built in Rust on iroh peer-to-peer QUIC; connects by endpoint id instead of hostname/port.
- Mosh-style predictive local echo and screen-state sync for responsive shells on bad networks.
- Detachable sessions survive suspend/resume, IP changes, and reconnects without tmux.
- No SSH bootstrap, no listening port, and no port forwarding needed.
- Not wire-compatible with mosh or SSH; koh is its own protocol/tool.
- Intended for personal machines you control; not a full SSH replacement.
- Does not provide multi-user accounts, file transfer, scrollback sync, or Windows support.

## Status

koh is experimental and intended for personal use on machines you control.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model, [`SECURITY.md`](SECURITY.md) for vulnerability reporting, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for implementation details.

## License

GPL-3.0-or-later.
