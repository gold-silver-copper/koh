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

### Syncing a state of your own

Since 0.11 the server hosts any `SyncState` producer and the client renders any `ClientState`, so
a program can use koh's transport (SSP over iroh: loss-tolerant, reconnecting, detachable) for
something other than a terminal screen. The state type a connection carries is selected by its
ALPN, so old koh peers are never confused. A twenty-line sketch: a shared `String` that every
authorized peer appends to.

```rust
use koh::server::{serve_with, cli::Hosts, ClientId, SessionHost, SharedHost, ServeConfig};
use koh::ssp::SyncState;

#[derive(Clone, Default, PartialEq)]
struct Log(String);
impl SyncState for Log {
    type Diff = String; // the whole log; a real state diffs against `base`
    const RECV_DECODE_LIMIT: usize = 1 << 20;
    const RECEIVE_BUDGET_UNITS: usize = 1 << 24;
    fn resource_units(&self) -> usize { self.0.len() }
    fn diff_from(&self, _base: &Self) -> String { self.0.clone() }
    fn apply(&mut self, d: &String) { self.0 = d.clone(); }
}

struct LogHost(Log);
impl SessionHost for LogHost {
    type State = Log;
    fn snapshot(&mut self) -> Log { self.0.clone() }
    fn input(&mut self, b: &[u8]) { self.0 .0.push_str(&String::from_utf8_lossy(b)); }
    fn resize(&mut self, _: ClientId, _: u16, _: u16) {}
    fn stamp_echo_ack(_: &mut Log, _: u64) {} // a real state carries it for the predictor
    fn alive(&self) -> bool { true }
}

let hosts = Hosts::new().with(b"example/log/1", SharedHost::new(|| Ok(LogHost(Log::default()))));
serve_with(ServeConfig { allow, ..Default::default() }, hosts).await?;
```

On the client side, implement `koh::client::ClientState` for `Log` (title, exit code, echo-ack)
and a `ClientTerminal<Log>` that prints it, then `connect_with(config, b"example/log/1", || Ok(term),
input_rx, resize_rx)`. `tests/e2e_generic_host.rs` is the complete, runnable version of this over a
real loopback connection.

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
