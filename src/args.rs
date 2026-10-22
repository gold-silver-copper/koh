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

use koh::client::{ConnectConfig, CopyJob, Remote, SyncTree};
use koh::keycmd::{KeyConfig, KeyOp};
use koh::names::{List, Op, Route, Scope};
use koh::request::{
    Argv, Command as Cmdline, CommandLine, JobName, On, Pick, RemotePath, Run, SessionNum, Signal,
    Sources, Until, Wait, WaitText,
};
use koh::server::cli::{
    DEFAULT_JOB_LOG_BYTES, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_SESSIONS, DEFAULT_SCROLLBACK_BYTES,
    DEFAULT_SESSION_TTL_SECS, MAX_JOB_LOG_BYTES, MAX_SCROLLBACK_BYTES,
};
use koh::server::ServeConfig;
use koh::sync::glob::{Excludes, Pattern};
use koh::sync::Opts;
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

/// koh's message for `error` if it is a `--sh` script whose quoting broke on the way: the shell
/// that ran koh split it, so words came after it that clap takes for arguments. The script is
/// one word, or goes on stdin; what came is shown cut, not echoed whole.
pub fn broken_sh(error: &clap::Error, argv: &[OsString]) -> Option<String> {
    use clap::error::{ContextKind, ContextValue};
    if error.kind() != ErrorKind::UnknownArgument {
        return None;
    }
    let sub = argv.get(1)?.to_str()?;
    let given = argv
        .iter()
        .skip(2)
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--sh" || arg.as_bytes().starts_with(b"--sh="));
    if !matches!(sub, "exec" | "run") || !given {
        return None;
    }
    let came = match error.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(came)) => came.as_str(),
        _ => "",
    };
    let mut cut: String = came
        .chars()
        .take(40)
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect();
    if came.chars().nth(40).is_some() {
        cut.push('…');
    }
    let fix = if sub == "exec" {
        "pipe the script in instead: koh exec SERVER -- sh -s < script.sh (or <<'EOF' ... EOF)"
    } else {
        "a job has no stdin: koh run SERVER --sh \"$(cat script.sh)\""
    };
    Some(format!(
        "--sh takes the script as one word, and more came after it ('{cut}'): its quoting broke; \
         {fix}"
    ))
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
    Sessions(RemoteArgs, bool),
    /// `koh output`.
    Output {
        remote: RemoteArgs,
        session: SessionNum,
        last: bool,
        json: bool,
    },
    /// `koh exec`.
    Exec {
        remote: RemoteArgs,
        run: Run,
        /// A tree to bring into line there first (`--sync`).
        sync: Option<SyncTree>,
        json: bool,
    },
    /// `koh run`.
    Start {
        remote: RemoteArgs,
        name: Option<JobName>,
        run: Run,
        sync: Option<SyncTree>,
        json: bool,
    },
    /// `koh jobs`.
    Jobs(RemoteArgs, Option<JobName>, bool),
    /// `koh logs`.
    Logs {
        remote: RemoteArgs,
        job: JobName,
        follow: bool,
        /// Its last lines kept to show; `None` for all.
        tail: Option<u32>,
    },
    /// `koh kill`.
    Kill {
        remote: RemoteArgs,
        job: JobName,
        signal: Signal,
        json: bool,
    },
    /// `koh wait`.
    Wait {
        remote: RemoteArgs,
        wait: Wait,
        /// A job's last lines to show once it ends.
        tail: u32,
        timeout: Option<std::time::Duration>,
        json: bool,
    },
    /// `koh cp`.
    Copy {
        remote: RemoteArgs,
        job: CopyJob,
        opts: Opts,
        /// The destination as the user wrote it, to say.
        shown: String,
        json: bool,
    },
    Key(KeyConfig),
    /// `koh servers` or `koh clients`.
    Names {
        list: List,
        op: Op,
        key_file: Option<PathBuf>,
    },
    /// `koh help-agents`.
    HelpAgents,
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
            named: match self.server {
                ServerRef::Id(id) => id.to_string(),
                ServerRef::Name(name) => name,
            },
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
    pub program: Option<Argv>,
    pub cwd: Option<RemotePath>,
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
            program: self.program,
            cwd: self.cwd,
            clipboard: self.clipboard,
            hyperlinks: self.hyperlinks,
            colours: self.colours,
            bell_command: self.bell_command,
        }
    }
}

/// What `koh help-agents` prints: everything an agent needs, short.
pub const HELP_AGENTS: &str = "\
koh for scripts and agents. SERVER is a name saved with `koh servers add NAME ID --direct IP:PORT`
or an endpoint id. Nothing here needs a terminal but `connect`.

Edit here, build there, in one call:
  koh exec SERVER --sync proj -- cargo test   proj here synced to SERVER:proj (only the files that
                                       changed, said in a line on stderr), then run in it
  koh exec SERVER --sync . -C proj -- cargo test   from within the tree: -C names it there
  koh run SERVER --sync proj --name b -- cargo build && koh wait SERVER b --timeout 600   a long
                                       build that outlives a dropped link (rerun the wait if it
                                       timed out: the job runs on)
  koh cp -r --exclude target SERVER:proj/. proj   back here: what a command changed there
                                       (rustfmt), only the files that differ

Run something:
  koh exec SERVER -- PROG ARG...       words passed as they are, no shell; ~/x is in the home
  koh exec SERVER --sh 'cd src && make'  a shell line, on purpose: one word, quoted whole
  koh exec SERVER -- sh -s < script.sh  a longer script, or one with quotes in it, on stdin
  koh exec SERVER -C proj -- PROG ...  start in DIR (relative: in the home). Not an unquoted
                                       -C ~/proj: your shell makes that this machine's home
  stdin goes to the command; stdout and stderr come back apart (sent to one file here, as
  2>&1 or a terminal does, in the order it wrote them); exits with its status (127 no such
  program, 126 could not start: no -C DIR there, 255 koh's own error). A killed koh hangs it up
  at once (SIGTERM, SIGHUP, SIGINT), within 10 s if SIGKILLed.
  koh connect SERVER -C proj -- gdb ./prog  one program on a terminal of its own (an editor, a
                                       debugger, a TUI), in a terminal, started in DIR (else
                                       the home); ends with its status

Jobs (survive koh exiting and the link dropping; output and status kept):
  koh run SERVER [--name build] [-C DIR] -- make -j4   prints the job's name; 127 no such
                                        program, 126 could not start (no -C DIR there)
  koh wait SERVER build                 until it ends: prints its last 200 lines (--tail N, 0 for
                                        none), exits with its status
  koh wait SERVER build --text listening  until its output has the text (1 if it ended first)
  koh wait SERVER build --timeout 60    gives up after 60s (exit 124), saying how the job
                                        stands (processes, CPU time) and its last lines
  koh wait SERVER --file out/done.txt   until the file exists
  koh logs SERVER build [--follow]      its last 200 lines (--tail N, --all), then on stderr
                                        `· running 34s: ...` or `· exited 101 after 34s`; with
                                        --follow on as it writes until it ends, then that line,
                                        and exits with its status
  koh jobs SERVER [build]               one line a job; with a name, its command whole; a
                                        running one's processes and CPU time (Linux servers)
  koh kill SERVER build [--signal KILL]

Copy (a sync: merges, makes parents, sends only files that changed, by hash):
  koh cp -r ./src SERVER:proj/          src lands as proj/src; `./src/.` lands its contents
  koh cp -r ./src SERVER:proj/src       updates proj/src, there already (as `./src/.` does; cp
                                        would nest it as proj/src/src: name that, or end in /)
  koh cp SERVER:proj/out.txt .          the other way
  --delete removes what the source lacks; --exclude PAT (repeat); -p keeps mtimes (default:
  arrival time, so builds see changes); --atomic lands nothing until all came; --dry-run
  changes nothing and sends no file, listing each change (`new`, `replaced`, `deleted`, `dir`,
  `link` and its path; a file's size, and the size of the one it replaces) before the summary.
  --diff is that dry run, each replaced text file (to 1 MiB) followed by its unified diff
  (a/ the destination's, b/ the source's): which files differ by content, and how.
  Without --delete, what the source lacks is kept and counted, but for directories (most
  often made there, as a build's target/). Prints one line,
  where it landed: `3 files sent, 41 KB → SERVER:proj/src (1 new, 2 replaced; 120 unchanged)`
  (`received` for a download). A cut copy resumes when rerun.
  To build there what you edit here, sync in the same call as the build, so it never sees stale
  code (an unchanged tree costs only hashes): `koh exec SERVER --sync proj -- make` (`--exclude
  target` keeps a local build's output here). There is no watch mode, whose sync a build can
  still overtake.

Shell sessions (`koh connect SERVER` in a terminal, or fux):
  koh sessions SERVER                   number, attached, state (reading/busy/...), last status
  koh wait SERVER --session N           until its running command ends; exits with its status
  koh wait SERVER --session N --reading until its program waits for input
  koh output SERVER --session N [--last]  its screen (no blank rows below what it shows), or
                                        the last command's output

--json on sessions, output, exec, run, jobs, kill, wait and cp: one JSON value on stdout, and on
failure {\"error\":{\"kind\":...,\"message\":...}}. --timeout SECS on wait (exit 124).
Exit codes: 0 ok, 1 failed, 2 usage, 3 server not reached, 4 refused (not allowed, or out of
the key's scope), 75 server busy (too many connections at once: nothing ran, so retry), 124 wait
timed out, 126 a command or session could not start (no -C DIR there), 127 no such program
(exec, run); exec, wait and logs --follow exit with the remote status (75 too when busy).
";

/// `koh`'s command line.
pub fn command() -> Command {
    Command::new("koh")
        .version(env!("CARGO_PKG_VERSION"))
        .about("koh: a peer-to-peer remote shell over iroh. Alone on a terminal it opens a menu of your keys, servers and clients. Agents: `koh help-agents`")
        .subcommand(serve())
        .subcommand(connect())
        .subcommand(sessions())
        .subcommand(output())
        .subcommand(exec())
        .subcommand(run())
        .subcommand(jobs())
        .subcommand(logs())
        .subcommand(kill())
        .subcommand(wait())
        .subcommand(cp())
        .subcommand(id())
        .subcommand(key())
        .subcommand(names(List::Servers))
        .subcommand(names(List::Clients))
        .subcommand(Command::new("help-agents").about("What scripts and agents need of koh, in one short page"))
        // `--help` ends with that page, so a script's first look has all it needs.
        .after_long_help(HELP_AGENTS)
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

/// `--json`.
fn json() -> Arg {
    flag("json", "json").help("Say it as one JSON value on stdout")
}

fn serve() -> Command {
    Command::new("serve")
        .about("Host shells, commands, jobs and copies for the allowed clients")
        .arg(path("key_file", "key-file", "KEY_FILE").help("The server's secret-key file (a stable endpoint id)"))
        .arg(
            Arg::new("allow")
                .long("allow")
                .value_name("ENDPOINT_ID")
                .value_parser(allow_id)
                .action(ArgAction::Append)
                .help("Allow a client endpoint id for this run (repeatable), beside those saved with `koh clients add`"),
        )
        .arg(
            Arg::new("shell")
                .long("shell")
                .value_name("PROGRAM_OR_ARG")
                .action(ArgAction::Append)
                .help("The program a session runs (default $SHELL); repeat to pass arguments; never split on whitespace"),
        )
        .arg(flag("no_shell_marks", "no-shell-marks").help("Start bash, zsh or fish without koh's marks (OSC 133) of where each command starts and ends"))
        .arg(
            Arg::new("scrollback_bytes")
                .long("scrollback-bytes")
                .value_name("BYTES")
                .default_value(DEFAULT_SCROLLBACK_BYTES.to_string())
                .value_parser(value_parser!(u64).range(0..=MAX_SCROLLBACK_BYTES))
                .help("History each session keeps (at most 1 GiB)"),
        )
        .arg(
            Arg::new("job_log_bytes")
                .long("job-log-bytes")
                .value_name("BYTES")
                .default_value(DEFAULT_JOB_LOG_BYTES.to_string())
                .value_parser(value_parser!(u64).range(0..=MAX_JOB_LOG_BYTES))
                .help("Output each job keeps, its newest (at most 64 MiB)"),
        )
        .arg(
            Arg::new("session_ttl_secs")
                .long("session-ttl-secs")
                .value_name("SECS")
                .default_value(DEFAULT_SESSION_TTL_SECS.to_string())
                .value_parser(value_parser!(u64))
                .help("How long a detached session, or an ended job, is kept"),
        )
        .arg(Arg::new("relay_url").long("relay-url").value_name("URL").value_parser(relay_url).help("Use this self-hosted relay instead of n0's"))
        .arg(flag("local", "local").conflicts_with("relay_url").help("No relay or discovery (LAN, loopback): clients dial --direct IP:PORT"))
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("PORT")
                .value_parser(value_parser!(u16).range(1..))
                .help("Bind this UDP port, so --direct clients find a restarted server"),
        )
        .arg(
            Arg::new("max_connections")
                .long("max-connections")
                .value_name("N")
                .default_value(DEFAULT_MAX_CONNECTIONS.to_string())
                .value_parser(value_parser!(NonZeroU32))
                .help("Most connections at once; as many more from allowed clients wait up to 10 s for room, then are told the server is busy"),
        )
        .arg(
            Arg::new("max_sessions")
                .long("max-sessions")
                .value_name("N")
                .default_value(DEFAULT_MAX_SESSIONS.to_string())
                .value_parser(value_parser!(NonZeroU32))
                .help("Most sessions, all clients' together"),
        )
}

/// `cmd` with how to dial the server: the client key, `--direct` and `--relay-url`.
fn dialing(cmd: Command) -> Command {
    cmd.arg(path("key_file", "key-file", "KEY_FILE").help("The client's secret-key file"))
        .arg(
            Arg::new("direct")
                .long("direct")
                .value_name("IP:PORT")
                .value_parser(value_parser!(SocketAddr))
                .conflicts_with("relay_url")
                .help("Dial this address (LAN, loopback; no relay or discovery)"),
        )
        .arg(
            Arg::new("relay_url")
                .long("relay-url")
                .value_name("URL")
                .value_parser(relay_url)
                .help("Dial via this self-hosted relay"),
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
                .help("A name saved with `koh servers add`, or an endpoint id"),
        ),
    )
}

/// `--session N`.
fn session(required: bool) -> Arg {
    Arg::new("session")
        .long("session")
        .value_name("N")
        .value_parser(value_parser!(u64))
        .required(required)
        .help("Your session numbered N (`koh sessions`)")
}

fn connect() -> Command {
    remote(Command::new("connect").about("Open a shell on a server, in this terminal: your session there attached last, else a new one; with `-- PROG ARG...`, a new session running that program on a terminal of its own (an editor, a debugger, a TUI) in place of the shell, ending when it does with its status. Ctrl-^ . detaches, Ctrl-^ Ctrl-Z suspends"))
        .arg(flag("new", "new").conflicts_with("session").help("A new session, beside your others"))
        .arg(session(false))
        .arg(cwd().conflicts_with("session").help("A new session, starting in DIR (relative: in the server user's home)"))
        .arg(
            Arg::new("program")
                .value_name("PROG")
                .value_parser(value_parser!(OsString))
                .num_args(1..)
                .last(true)
                .conflicts_with("session")
                .help("After `--`: a program and its arguments, passed as they are, run in a new session in place of the shell"),
        )
        .arg(flag("no_clipboard", "no-clipboard").help("Do not let the server set your clipboard (OSC 52)"))
        .arg(flag("no_hyperlinks", "no-hyperlinks").help("Do not pass the server's links (OSC 8) to your terminal"))
        .arg(flag("no_colours", "no-colours").help("Do not tell the server your terminal's colours (programs asking get no answer)"))
        .arg(Arg::new("on_bell").long("on-bell").value_name("CMD").help("Run this shell command when the remote bell rings (at most once a second; KOH_BELL_COUNT, KOH_TITLE set)"))
}

fn sessions() -> Command {
    remote(Command::new("sessions").about("List your sessions: number, attached or detached, age, size, what its program is doing (reading, busy, ...; running: while a command runs), the last command's status, title"))
        .arg(json())
}

fn output() -> Command {
    remote(Command::new("output").about(
        "Print a session's screen as text (no blank rows below the last that shows anything), or the output of the last command its shell finished",
    ))
    .arg(session(true))
    .arg(flag("last", "last").help("The last finished command's output, not the screen"))
    .arg(json())
}

/// `-C DIR`: where a command, or a new session, starts on the server.
fn cwd() -> Arg {
    Arg::new("cwd")
        .short('C')
        .long("cd")
        .value_name("DIR")
        .value_parser(value_parser!(OsString))
}

/// What `exec` and `run` take: the command and where it starts.
fn command_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("sh")
            .long("sh")
            .value_name("LINE")
            .conflicts_with("command")
            .required_unless_present("command")
            .help("Run LINE with the server user's shell ($SHELL -c)"),
    )
    .arg(cwd().help("Start in DIR (relative: in the server user's home)"))
    .arg(
        Arg::new("sync")
            .long("sync")
            .value_name("LOCAL")
            .value_parser(value_parser!(PathBuf))
            .help("First bring the directory there into line with LOCAL here, sending only the files that changed (as `koh cp -r LOCAL/. SERVER:DIR`), and say so in a line on stderr: DIR is -C's, else LOCAL's own path (relative: in the home), where the command then starts"),
    )
    .arg(
        Arg::new("exclude")
            .long("exclude")
            .value_name("PATTERN")
            .action(ArgAction::Append)
            .value_parser(value_parser!(OsString))
            .requires("sync")
            .help("With --sync: neither send nor remove entries matching it: `target`, `*.o` (repeatable)"),
    )
    .arg(
        Arg::new("command")
            .value_name("PROG")
            .value_parser(value_parser!(OsString))
            .num_args(1..)
            .last(true)
            .help("After `--`: the program and its arguments, passed as they are"),
    )
    .arg(json())
}

fn exec() -> Command {
    command_args(remote(Command::new("exec").about("Run a command on a server with no terminal and exit with its status: your stdin goes to it, its stdout and stderr come back apart. A killed or dropped koh hangs it up (at once on SIGTERM, SIGHUP or SIGINT; within 10 s on SIGKILL). 127: no such program; 126: it could not start (no -C DIR there, say); 75: the server was busy (nothing ran: retry); 255: koh's own error")))
}

fn run() -> Command {
    command_args(remote(Command::new("run").about("Start a job: a command that outlives this koh and the link, its stdout and stderr kept together (`koh logs`), its status too (`koh wait`, `koh jobs`). Prints its name")))
        .arg(Arg::new("name").long("name").value_name("NAME").value_parser(job_name).help("Its name (default: the next free number); one that ended is replaced"))
}

fn jobs() -> Command {
    remote(Command::new("jobs").about(
        "List your jobs, one line each: name, running or exited (status, how long it ran), output size, the command's first line; with JOB, that one, its command whole",
    ))
    .arg(job_arg(false))
    .arg(json())
}

/// A job's name, the argument.
fn job_arg(required: bool) -> Arg {
    Arg::new("job")
        .value_name("JOB")
        .value_parser(job_name)
        .required(required)
        .help("The job's name")
}

fn logs() -> Command {
    remote(Command::new("logs").about("Print a job's output, its last 200 lines unless asked for more (of the newest `--job-log-bytes` kept), then on stderr whether it runs on or how it ended; with --follow, until it ends, then exit with its status"))
        .arg(job_arg(true))
        .arg(flag("follow", "follow").short('f').help("Go on until the job ends"))
        .arg(tail(DEFAULT_TAIL).conflicts_with("all"))
        .arg(flag("all", "all").help("All of the output kept"))
}

/// The lines of a job's output `koh logs` and `koh wait` show unless told otherwise: the end of a
/// test run's or a build's, where its failures are.
const DEFAULT_TAIL: &str = "200";

/// `--tail N`, defaulting to `default`.
fn tail(default: &'static str) -> Arg {
    Arg::new("tail")
        .long("tail")
        .short('n')
        .value_name("N")
        .default_value(default)
        .value_parser(value_parser!(u32))
        .help("Its last N lines")
}

fn kill() -> Command {
    remote(Command::new("kill").about("Send a job's processes a signal (TERM by default)"))
        .arg(job_arg(true))
        .arg(
            Arg::new("signal")
                .long("signal")
                .short('s')
                .value_name("SIG")
                .default_value("TERM")
                .value_parser(signal)
                .help("TERM, KILL, INT or HUP"),
        )
        .arg(json())
}

fn wait() -> Command {
    remote(Command::new("wait").about("Wait on the server: for a job to end (print its last lines, as `koh logs` does, and exit with its status), or a text in its output, or a file; for a session's running command to end (at once if none runs), its program to read its terminal, or a text on its screen"))
        .arg(job_arg(false).conflicts_with("session"))
        .arg(session(false))
        .arg(Arg::new("text").long("text").value_name("TEXT").conflicts_with_all(["file", "reading"]).help("Until the text appears (exit 1 if the job ends first)"))
        .arg(Arg::new("file").long("file").value_name("PATH").value_parser(value_parser!(OsString)).conflicts_with("reading").help("Until the path exists (relative: in the home)"))
        .arg(flag("reading", "reading").requires("session").help("Until the session's program waits for input"))
        .arg(Arg::new("timeout").long("timeout").value_name("SECS").value_parser(value_parser!(f64)).help("Give up after SECS: exit 124"))
        .arg(tail(DEFAULT_TAIL).help("When a job ends, print its last N lines first (0: none)"))
        .arg(json())
}

fn cp() -> Command {
    dialing(Command::new("cp").about("Copy files and trees between here and a server, as a sync: `koh cp SRC... SERVER:DST` or `koh cp SERVER:SRC... DST`. Into DST if it is a directory (or ends in /, or there are several SRC: it is made), else as DST, its parents made. Directories merge; only files that changed are sent (by hash); a cut copy resumes when run again. A file written gets its arrival time unless -p. `dir/.` copies what is in dir. A tree copied to a directory of its own name that is there updates it, as `X/.` does (`koh cp -r X S:X` again), where cp would nest it: `S:X/` or `S:X/X` nests it. Prints what it did and where it landed"))
        .arg(
            Arg::new("paths")
                .value_name("PATH")
                .value_parser(value_parser!(OsString))
                .num_args(2..)
                .required(true)
                .help("The sources, then the destination; one side is SERVER:PATH (a path with a / before its : is local)"),
        )
        .arg(flag("recursive", "recursive").short('r').visible_short_alias('R').help("Accepted, as scp's: directories always copy whole"))
        .arg(flag("preserve", "preserve").short('p').help("Keep the source's modification times"))
        .arg(flag("delete", "delete").help("Remove from the destination's directories what the source does not have"))
        .arg(flag("atomic", "atomic").help("Rename nothing into place, and remove nothing, until all of the copy came"))
        .arg(flag("dry_run", "dry-run").help("Change nothing and send no file's bytes: list what would be sent (new or replaced), deleted, made or linked, then the summary"))
        .arg(flag("diff", "diff").help("A dry run that also shows how each replaced text file differs (a unified diff, a/ the destination's, b/ the source's; files up to 1 MiB): the source's file goes to the destination's end to be compared, nothing changed"))
        .arg(Arg::new("exclude").long("exclude").value_name("PATTERN").action(ArgAction::Append).value_parser(value_parser!(OsString)).help("Neither send nor remove entries matching it: `*.o`, `target`, `src/gen/*` (repeatable)"))
        .arg(json())
}

fn id() -> Command {
    Command::new("id")
        .about("Print this machine's koh id (add it to a server's --allow list)")
        .arg(path("key_file", "key-file", "KEY_FILE").help("The client's secret-key file"))
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
    add = match list {
        List::Servers => add
            .arg(
                Arg::new("direct")
                    .long("direct")
                    .value_name("IP:PORT")
                    .value_parser(value_parser!(SocketAddr))
                    .conflicts_with("relay_url")
                    .help("Dial it at this address unless a command says --direct or --relay-url itself"),
            )
            .arg(
                Arg::new("relay_url")
                    .long("relay-url")
                    .value_name("URL")
                    .value_parser(relay_url)
                    .help("Dial it via this self-hosted relay unless a command says otherwise"),
            ),
        List::Clients => add
            .arg(Arg::new("cp").long("cp").value_name("DIR").value_parser(scope_dir).help("Scope it: copies only, in DIR and below (no shell; with --exec, commands too)"))
            .arg(Arg::new("exec").long("exec").value_name("DIR").value_parser(scope_dir).help("Scope it: commands and jobs only, started in DIR (no shell; not a sandbox: a command can reach what the server user can)")),
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

/// A job's name.
fn job_name(value: &str) -> Result<JobName, BadValue> {
    JobName::new(value).map_err(|e| BadValue(e.to_owned()))
}

/// A signal's name.
fn signal(value: &str) -> Result<Signal, BadValue> {
    Signal::named(value).ok_or_else(|| BadValue(format!("{value:?} is not TERM, KILL, INT or HUP")))
}

/// A scope's directory.
fn scope_dir(value: &str) -> Result<PathBuf, BadValue> {
    Scope::dir(value).map_err(|e| BadValue(format!("{e:#}")))
}

/// The command `m` names (its words, or `--sh`) and where it starts.
fn run_of(m: &ArgMatches) -> Result<Run, clap::Error> {
    let command = if let Some(line) = m.get_one::<String>("sh") {
        Cmdline::Shell(
            CommandLine::new(line.clone().into_bytes())
                .map_err(|why| invalid(&format!("--sh: {why}")))?,
        )
    } else {
        {
            let words: Vec<Vec<u8>> = m
                .get_many::<OsString>("command")
                .into_iter()
                .flatten()
                .map(|word| word.as_bytes().to_vec())
                .collect();
            Cmdline::Argv(Argv::new(words).map_err(|why| invalid(&format!("the command: {why}")))?)
        }
    };
    Ok(Run {
        command,
        cwd: cwd_of(m)?,
    })
}

/// The command `m` names, and the tree `--sync` brings into line first, if asked: to `-C`'s
/// directory, else to the local one's own path there, which the command then starts in.
fn synced_run(m: &ArgMatches) -> Result<(Run, Option<SyncTree>), clap::Error> {
    let mut run = run_of(m)?;
    let Some(local) = m.get_one::<PathBuf>("sync") else {
        return Ok((run, None));
    };
    let excludes = excludes(m)?;
    let dest = if let Some(dir) = &run.cwd {
        dir.clone()
    } else {
        let dest = same_path(local).ok_or_else(|| {
            invalid(&format!(
                "--sync {}: it has no name of its own there; say where it goes with -C DIR \
                 (koh exec SERVER --sync {} -C proj -- ...)",
                local.display(),
                local.display()
            ))
        })?;
        let dest = RemotePath::new(dest).map_err(|why| invalid(&format!("--sync: {why}")))?;
        run.cwd = Some(dest.clone());
        dest
    };
    let sync = SyncTree {
        local: local.clone(),
        dest,
        excludes,
    };
    Ok((run, Some(sync)))
}

/// `local`'s path as the server takes it: the same, made of its names alone (`./src/` is `src`);
/// `None` for one that names no directory of its own (`.`, `..`, `../x`).
fn same_path(local: &std::path::Path) -> Option<Vec<u8>> {
    use std::path::Component;
    let mut names: Vec<&[u8]> = Vec::new();
    for part in local.components() {
        match part {
            Component::Normal(name) => names.push(name.as_bytes()),
            Component::CurDir => {}
            Component::RootDir => names.push(b""),
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    let path = names.join(&b'/');
    (names.iter().any(|name| !name.is_empty())).then_some(path)
}

/// The `--exclude` patterns `m` gives.
fn excludes(m: &ArgMatches) -> Result<Excludes, clap::Error> {
    m.get_many::<OsString>("exclude")
        .into_iter()
        .flatten()
        .map(|p| Pattern::new(p.as_bytes().to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .and_then(Excludes::new)
        .map_err(|why| invalid(&format!("--exclude: {why}")))
}

/// The directory `-C` names, if given.
fn cwd_of(m: &ArgMatches) -> Result<Option<RemotePath>, clap::Error> {
    m.get_one::<OsString>("cwd")
        .map(|dir| RemotePath::new(dir.as_bytes().to_vec()))
        .transpose()
        .map_err(|why| invalid(&format!("--cd: {why}")))
}

/// The config `matches` asks for. clap has already enforced the required subcommands and
/// arguments, the defaults and the ranges, so a missing value is an internal error.
pub fn parse(matches: &ArgMatches) -> Result<Cmd, clap::Error> {
    let json = |m: &ArgMatches| {
        m.try_get_one::<bool>("json")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(false)
    };
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
            job_log_bytes: value(m, "job_log_bytes")?,
        })),
        Some(("connect", m)) => Ok(Cmd::Connect(ConnectArgs {
            remote: remote_args(m)?,
            pick: match m.get_one::<u64>("session") {
                Some(&n) => Pick::Id(SessionNum(n)),
                None if m.get_flag("new") || m.contains_id("program") || m.contains_id("cwd") => {
                    Pick::New
                }
                None => Pick::Latest,
            },
            program: m
                .get_many::<OsString>("program")
                .map(|words| Argv::new(words.map(|word| word.as_bytes().to_vec()).collect()))
                .transpose()
                .map_err(|why| invalid(&format!("the program: {why}")))?,
            cwd: cwd_of(m)?,
            clipboard: !m.get_flag("no_clipboard"),
            hyperlinks: !m.get_flag("no_hyperlinks"),
            colours: !m.get_flag("no_colours"),
            bell_command: m.get_one::<String>("on_bell").cloned(),
        })),
        Some(("sessions", m)) => Ok(Cmd::Sessions(remote_args(m)?, json(m))),
        Some(("output", m)) => Ok(Cmd::Output {
            remote: remote_args(m)?,
            session: SessionNum(value(m, "session")?),
            last: m.get_flag("last"),
            json: json(m),
        }),
        Some(("exec", m)) => {
            let (run, sync) = synced_run(m)?;
            Ok(Cmd::Exec {
                remote: remote_args(m)?,
                run,
                sync,
                json: json(m),
            })
        }
        Some(("run", m)) => {
            let (run, sync) = synced_run(m)?;
            Ok(Cmd::Start {
                remote: remote_args(m)?,
                name: m.get_one::<JobName>("name").cloned(),
                run,
                sync,
                json: json(m),
            })
        }
        Some(("jobs", m)) => Ok(Cmd::Jobs(
            remote_args(m)?,
            m.get_one::<JobName>("job").cloned(),
            json(m),
        )),
        Some(("logs", m)) => Ok(Cmd::Logs {
            remote: remote_args(m)?,
            job: value(m, "job")?,
            follow: m.get_flag("follow"),
            tail: (!m.get_flag("all")).then(|| value(m, "tail")).transpose()?,
        }),
        Some(("kill", m)) => Ok(Cmd::Kill {
            remote: remote_args(m)?,
            job: value(m, "job")?,
            signal: value(m, "signal")?,
            json: json(m),
        }),
        Some(("wait", m)) => {
            let on = match (m.get_one::<JobName>("job"), m.get_one::<u64>("session")) {
                (Some(job), _) => Some(On::Job(job.clone())),
                (None, Some(&n)) => Some(On::Session(SessionNum(n))),
                (None, None) => None,
            };
            let until = if let Some(text) = m.get_one::<String>("text") {
                Until::Text(
                    WaitText::new(text.clone())
                        .map_err(|why| invalid(&format!("--text: {why}")))?,
                )
            } else if let Some(file) = m.get_one::<OsString>("file") {
                Until::File(
                    RemotePath::new(file.as_bytes().to_vec())
                        .map_err(|why| invalid(&format!("--file: {why}")))?,
                )
            } else if m.get_flag("reading") {
                Until::Reading
            } else {
                Until::End
            };
            let wait = Wait::new(on, until).map_err(|why| {
                invalid(&format!(
                    "wait for what: {why} (name a JOB, --session N or --file PATH)"
                ))
            })?;
            let timeout = m
                .get_one::<f64>("timeout")
                .map(|&secs| std::time::Duration::try_from_secs_f64(secs))
                .transpose()
                .map_err(|e| invalid(&format!("--timeout: {e}")))?;
            Ok(Cmd::Wait {
                remote: remote_args(m)?,
                wait,
                tail: value(m, "tail")?,
                timeout,
                json: json(m),
            })
        }
        Some(("cp", m)) => {
            let paths: Vec<&OsString> = m
                .get_many::<OsString>("paths")
                .into_iter()
                .flatten()
                .collect();
            let (server, job) = copy_job(&paths)?;
            let excludes = excludes(m)?;
            let opts = Opts {
                keep_times: m.get_flag("preserve"),
                delete: m.get_flag("delete"),
                atomic: m.get_flag("atomic"),
                dry_run: m.get_flag("dry_run") || m.get_flag("diff"),
                diff: m.get_flag("diff"),
                excludes,
            };
            let shown = paths
                .last()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok(Cmd::Copy {
                remote: RemoteArgs {
                    server,
                    key_file: m.get_one::<PathBuf>("key_file").cloned(),
                    direct: m.get_one::<SocketAddr>("direct").copied(),
                    relay_url: m.get_one::<RelayUrl>("relay_url").cloned(),
                },
                job,
                opts,
                shown,
                json: json(m),
            })
        }
        Some(("help-agents", _)) => Ok(Cmd::HelpAgents),
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
                        scope: Scope {
                            cp: sub.try_get_one::<PathBuf>("cp").ok().flatten().cloned(),
                            exec: sub.try_get_one::<PathBuf>("exec").ok().flatten().cloned(),
                        },
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

    /// A `--sh` script the shell split says so, short, and how to send it whole.
    #[test]
    fn a_split_sh_script_says_how_to_send_it_whole() {
        let script = format!("print('a b'){}", "x".repeat(1000));
        for (sub, fix) in [("exec", "-- sh -s"), ("run", "$(cat script.sh)")] {
            let argv: Vec<std::ffi::OsString> = ["koh", sub, ID, "--sh", "python3 -c ", &script]
                .iter()
                .map(Into::into)
                .collect();
            let error = command().try_get_matches_from(&argv).expect_err("split");
            let said = super::broken_sh(&error, &argv).expect("said");
            assert!(
                said.contains(fix) && said.contains("print('a b')xx"),
                "{said}"
            );
            assert!(said.len() < 300, "{said}");
        }
        // Another unexpected word, with no --sh, is clap's to say.
        let argv: Vec<std::ffi::OsString> = ["koh", "exec", ID, "ls", "-l"]
            .iter()
            .map(Into::into)
            .collect();
        let error = command().try_get_matches_from(&argv).expect_err("no --");
        assert_eq!(super::broken_sh(&error, &argv), None);
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
                scope: koh::names::Scope::default(),
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

    /// `--sync DIR` sends DIR's contents to the same path there, made of its names alone, and
    /// starts the command in it; with -C, to -C's directory. A path with no name of its own
    /// there needs -C, and `--exclude` needs `--sync`.
    #[test]
    fn sync_names_where_the_tree_goes_and_the_command_starts() {
        let synced = |argv: &[&str]| {
            let (Cmd::Exec { run, sync, .. } | Cmd::Start { run, sync, .. }) =
                parsed(&[&["koh"][..], argv].concat())
            else {
                panic!("exec or run");
            };
            let sync = sync.expect("a sync");
            let cwd = run.cwd.map(|dir| dir.as_bytes().to_vec());
            (sync.dest.as_bytes().to_vec(), cwd)
        };
        let proj = (b"proj".to_vec(), Some(b"proj".to_vec()));
        assert_eq!(
            synced(&["exec", ID, "--sync", "./proj/", "--", "make"]),
            proj
        );
        let deep = synced(&[
            "run",
            ID,
            "--sync",
            "a/./b",
            "--exclude",
            "target",
            "--",
            "make",
        ]);
        assert_eq!(deep.0, b"a/b");
        assert_eq!(
            synced(&["exec", ID, "--sync", "/w/p", "--", "make"]).0,
            b"/w/p"
        );
        let there = (b"~/p".to_vec(), Some(b"~/p".to_vec()));
        assert_eq!(
            synced(&["exec", ID, "--sync", ".", "-C", "~/p", "--", "make"]),
            there
        );
        for dir in [".", "..", "../x"] {
            let matches = command()
                .try_get_matches_from(["koh", "exec", ID, "--sync", dir, "--", "make"])
                .expect("valid command line");
            let said = parse(&matches).expect_err("no name there").to_string();
            assert!(said.contains("with -C DIR"), "{said}");
        }
        let alone = ["koh", "exec", ID, "--exclude", "target", "--", "make"];
        assert!(command().try_get_matches_from(alone).is_err());
    }

    /// `koh exec` takes its program and arguments after `--`, each word as it is (a line for the
    /// shell only with `--sh`); `koh cp` reads `SERVER:PATH` as scp does, one side the server's.
    #[test]
    fn exec_and_cp_read_their_arguments() {
        use koh::client::CopyJob;
        use koh::request::Command as Remote;
        use std::path::PathBuf;
        let Cmd::Exec {
            remote, run, json, ..
        } = parsed(&[
            "koh",
            "exec",
            "laptop",
            "--direct",
            "127.0.0.1:9",
            "-C",
            "src",
            "--",
            "ls",
            "-la",
            "a b",
        ])
        else {
            panic!("exec");
        };
        let Remote::Argv(argv) = &run.command else {
            panic!("argv");
        };
        assert_eq!(argv.words(), [&b"ls"[..], b"-la", b"a b"]);
        assert_eq!(
            run.cwd.as_ref().map(koh::request::RemotePath::as_bytes),
            Some(&b"src"[..])
        );
        assert!(remote.direct.is_some() && !json);
        let Cmd::Exec { run, json, .. } =
            parsed(&["koh", "exec", ID, "--json", "--sh", "make && make test"])
        else {
            panic!("exec --sh");
        };
        let Remote::Shell(line) = &run.command else {
            panic!("shell");
        };
        assert_eq!(line.as_bytes(), b"make && make test");
        assert!(json && run.cwd.is_none());
        // A command, and only one: words or a line.
        for argv in [
            &["koh", "exec", ID][..],
            &["koh", "exec", ID, "--sh", "ls", "--", "ls"],
        ] {
            assert!(command().try_get_matches_from(argv).is_err(), "{argv:?}");
        }
        let copy = |argv: &[&str]| {
            let Cmd::Copy {
                remote, job, opts, ..
            } = parsed(&[&["koh", "cp"][..], argv].concat())
            else {
                panic!("cp {argv:?}");
            };
            (remote.server, job, opts)
        };
        let (server, job, opts) = copy(&["-r", "-p", "--delete", "a", "./b:c", "laptop:~/x"]);
        assert!(opts.keep_times && opts.delete && !opts.atomic);
        assert_eq!(server, super::ServerRef::Name("laptop".to_owned()));
        let CopyJob::Put { sources, dest } = job else {
            panic!("put");
        };
        assert_eq!(sources, [PathBuf::from("a"), PathBuf::from("./b:c")]);
        assert_eq!(dest.as_bytes(), b"~/x");
        let (_, job, opts) = copy(&[&format!("{ID}:/etc/hosts"), &format!("{ID}:"), "."]);
        assert!(!opts.keep_times && !opts.delete);
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
        // Both sides here, both there, or two servers: refused. So is `-n`, which `cp` reads as
        // "no clobber", where a dry run is spelled out.
        for argv in [
            &["koh", "cp", "-n", "a", "laptop:b"][..],
            &["koh", "cp", "a", "b"],
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
