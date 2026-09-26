//! The clap definitions for `koh`, and their conversions into `koh-core`'s config structs.
//!
//! clap's derives emit `#[allow(...)]` for lints that `koh-core` forbids, which is why the command
//! line lives in this crate, whose lints are `deny`. Keep it to plain field-moving conversions.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Arguments for `koh id` (the clap adapter over [`IdConfig`](koh_core::idcmd::IdConfig)).
#[derive(Args, Debug)]
pub struct IdArgs {
    /// Path to the client's persistent secret key.
    #[arg(long)]
    key_file: Option<PathBuf>,
}

impl From<IdArgs> for koh_core::idcmd::IdConfig {
    fn from(a: IdArgs) -> Self {
        Self {
            key_file: a.key_file,
        }
    }
}

/// Arguments for `koh key` (the clap adapter over [`KeyConfig`](koh_core::keycmd::KeyConfig)).
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
    /// Print the key file and its endpoint id (never the secret).
    Info,
    /// Delete an unused identity; the next use creates a new endpoint ID.
    Reset {
        /// Acknowledge permanent identity loss and required allowlist updates.
        #[arg(long)]
        yes: bool,
    },
}

impl From<KeyArgs> for koh_core::keycmd::KeyConfig {
    fn from(a: KeyArgs) -> Self {
        Self {
            op: match a.cmd {
                KeyCmd::Info => koh_core::keycmd::KeyOp::Info,
                KeyCmd::Reset { yes } => koh_core::keycmd::KeyOp::Reset { confirmed: yes },
            },
            key_file: a.key_file,
        }
    }
}

/// Arguments for `koh serve` (the clap adapter over [`ServeConfig`](koh_core::server::ServeConfig)).
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
    #[arg(long, default_value_t = koh_core::server::cli::DEFAULT_SCROLLBACK, value_parser = clap::value_parser!(u64).range(0..=koh_core::server::cli::MAX_SCROLLBACK))]
    scrollback: u64,

    /// Keep a detached session's shell alive this long (seconds) for the client to reconnect.
    /// Default 24h (mosh-style "close the laptop, reopen later").
    #[arg(long, default_value_t = koh_core::server::cli::DEFAULT_SESSION_TTL_SECS)]
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
    #[arg(long, default_value_t = koh_core::server::cli::DEFAULT_MAX_CONNECTIONS, value_parser = clap::value_parser!(u32).range(1..))]
    max_connections: u32,

    /// Maximum number of distinct live sessions (one per authorized peer). A new peer is refused
    /// once this many sessions exist; reconnecting to an existing session is always allowed. Bounds
    /// the number of real shells a flood of authorized keys can spawn.
    #[arg(long, default_value_t = koh_core::server::cli::DEFAULT_MAX_SESSIONS, value_parser = clap::value_parser!(u32).range(1..))]
    max_sessions: u32,
}

impl From<ServeArgs> for koh_core::server::ServeConfig {
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
            launcher: koh_core::pty::Launcher::this_binary(),
        }
    }
}

/// Arguments for `koh connect <server-id>` (the clap adapter over [`ConnectConfig`](koh_core::client::ConnectConfig)).
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

impl From<ConnectArgs> for koh_core::client::ConnectConfig {
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

#[cfg(test)]
mod tests {
    use clap::Parser;
    use koh_core::client::ConnectConfig;
    use koh_core::server::ServeConfig;

    use super::{ConnectArgs, ServeArgs};

    #[test]
    fn serve_args_map_shell_to_command_argv_and_keep_defaults() {
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            serve: ServeArgs,
        }
        let cli = Cli::parse_from([
            "koh", "--allow", "abc", "--shell", "zellij", "--shell", "attach",
        ]);
        let c: ServeConfig = cli.serve.into();
        assert_eq!(c.command, ["zellij", "attach"]);
        assert_eq!(c.allow, ["abc"]);
        // Everything not given on the command line must equal `ServeConfig::default()`.
        let d = ServeConfig::default();
        assert_eq!(c.scrollback, d.scrollback);
        assert_eq!(c.session_ttl_secs, d.session_ttl_secs);
        assert_eq!(c.max_connections, d.max_connections);
        assert_eq!(c.max_sessions, d.max_sessions);

        // A single `--shell` is just the program.
        let cli = Cli::parse_from(["koh", "--allow", "abc", "--shell", "/bin/zsh"]);
        assert_eq!(ServeConfig::from(cli.serve).command, ["/bin/zsh"]);
        // No `--shell` = login shell.
        let cli = Cli::parse_from(["koh", "--allow", "abc"]);
        assert_eq!(ServeConfig::from(cli.serve).command, Vec::<String>::new());
    }

    #[test]
    fn connect_args_map_on_bell_to_bell_command() {
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            connect: ConnectArgs,
        }
        let cli = Cli::parse_from(["koh", "abc", "--on-bell", "termux-notification"]);
        let c: ConnectConfig = cli.connect.into();
        assert_eq!(c.bell_command.as_deref(), Some("termux-notification"));
    }
}
