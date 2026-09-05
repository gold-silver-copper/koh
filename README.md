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
--on-bell <cmd>           # run a shell command whenever the remote bell rings
--shell <program>         # host a program instead of the login shell (repeat to pass args)
--key-file <path>         # use a custom identity-key path
--session-ttl-secs <n>    # keep detached sessions around longer/shorter
--max-connections <n>     # limit concurrent connections
--max-sessions <n>        # limit sessions
```

Keys live under `~/.config/koh/` by default.

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

To get a phone notification when the remote shell rings the bell (a finished build, an agent
waiting for input), hook `termux-notification`:

```sh
koh connect <server-id> --on-bell 'termux-notification -t "koh bell"'
```

The hook runs detached from the terminal at most once per second; `KOH_BELL_COUNT` and
`KOH_TITLE` are set in its environment, and every other `KOH_*` variable is scrubbed. Bells that
rang before you attached do not fire it; bells during a reconnect do.

## As a library

koh's server and client are callable from another binary. Depend on it without the `cli` feature
(clap stays out of your tree) and pick exactly one `backend-*` terminal feature:

```toml
[dependencies]
koh = { version = "0.11", default-features = false, features = ["backend-termina"] }
```

The stable surface is the four config types and their entry points: `koh::server::{serve,
ServeConfig}`, `koh::client::{connect, ConnectConfig, run_id, IdConfig}` and
`koh::keycmd::{run, KeyConfig}`. `ServeConfig::command` is an argv, so any program can be hosted,
not only a shell:

```rust
use koh::server::{serve, ServeConfig};

serve(ServeConfig {
    allow: vec![client_id],
    command: vec!["zellij".into(), "attach".into(), "-c".into(), "main".into()],
    ..Default::default()
})
.await?;
```

The `koh` binary is the same code behind clap; `cargo install koh` is unaffected.

### Embedding a stateful application

Use `koh::identity::Identity` and `koh::embed::{Connection, Server}` for application embedding.
Applications do not need iroh types or networking internals. Implement `server::SessionHost` for
application state/input and `client::{ClientState, ClientTerminal}` for rendering. Choose a distinct
static protocol identifier for your state schema; koh's standalone shell uses its own protocol.

Load credentials before starting terminal readers:

```rust,no_run
# async fn example<S: koh::client::ClientState, T: koh::client::ClientTerminal<S>>(
# config: koh::client::ConnectConfig, term: T,
# input_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
# resize_rx: tokio::sync::mpsc::Receiver<()>,
# shutdown: tokio_util::sync::CancellationToken,
# ) -> anyhow::Result<()> {
let identity = koh::identity::load_client(config.key_file.as_deref())?;
let connection = koh::embed::Connection::connect(&config, b"example/app/1", &identity).await?;
// In a real application, create `term` and input producers only after the two steps above.
connection.run(term, input_rx, resize_rx, shutdown, None).await?;
# Ok(())
# }
```

Keep the identity for the invocation and reuse it for later connections; reconnects already retain
it internally. `IdentityStore` can cache path-based loads within an invocation. Encrypted key
loading, prompting, private-path checks, and reset leases belong to koh. `Identity::transfer` and
`receive` carry an unlocked identity across an application's private startup IPC; transferred
bytes are secret material and must never enter arguments, logs, or public sockets. Receivers wipe
the supplied buffer, including malformed input.

`Server::bind` accepts a server identity, an allowlist of endpoint ID strings, the protocol ID,
a `NetworkProfile`, a connection limit, and a factory for a shared `SessionHost`. koh authenticates
and admits peers, limits connections, owns accept/reconnect tasks, and calls the host's session
hooks. The application decides whether its workspace persists after a viewer disconnects.
Networking shutdown does not replace application process/PTY cleanup.

`Connection::connect` starts no terminal readers or signal handlers. Embedded input is byte-exact;
`run` does not interpret koh CLI escape keys. The standalone client explicitly opts into
`with_koh_escape_keys()`. Applications implement their own shortcuts and cancel the supplied token. The application owns those
resources and must stop/join its producers after the connection finishes. Cancelling the supplied
token ends `run`; normal completion waits at most two seconds for endpoint close. Dropping `run`
releases its terminal and connection handles without waiting for asynchronous network shutdown.
Call `Connection::close` to discard an admitted connection before running it. `Server::close`
stops admissions and connections and joins its worker with a bounded shutdown wait. Applications
should then complete their own workspace shutdown in their chosen lifecycle order.

The standalone `koh connect` and `koh serve` remain independently useful. fux is an embedding
consumer; koh does not depend on it or on zor.

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

MIT, from 0.10.0 onward. Releases before 0.10.0 remain available under GPL-3.0-or-later.
