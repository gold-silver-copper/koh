//! koh CLI entrypoint: zero-macro parser, unified help, strict exit codes.
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use koh::client::{Client, ConnectOptions, DialOptions, parse_signal};
use koh::keys::{
    ClientEntry, Role, Route, ServerEntry, load_clients, load_or_create_key, load_servers,
    parse_endpoint_id, parse_relay_url, reset_key, save_clients, save_servers, validate_peer_name,
};
use koh::proto::SessionInfo;
use koh::server::{ServeOptions, cap, run_serve};
use koh::{Exit, KohError, Result};

const HELP: &str = include_str!("help.txt");
/// What `koh help-agents` says after the help: a session's files, and the three commands
/// that read them as a script for `koh exec`.
const RECIPES: &str = include_str!("help-agents.txt");

fn main() -> ExitCode {
    // fux's own command line, under two words: `koh fux …` is `fux …`, and `koh hold …` is how
    // `koh fux start` runs this file to hold a pane (a session is such a pane). Both are fux's
    // from their first word on, and handed over before anything else is done: a holder has no
    // thread but fux's own, and no runtime.
    let mut words = std::env::args_os().skip(1).peekable();
    match words.peek().and_then(|word| word.to_str()) {
        // A session's viewer, as `koh serve` runs it on a pty for a client's terminal: the pane,
        // and the keyboard's flags that terminal takes.
        Some("view-session") => {
            let words: Vec<_> = words.skip(1).collect();
            let [pane, keyboard] = words.as_slice() else {
                return ExitCode::from(Exit::USAGE.0);
            };
            let keyboard = keyboard.to_str().and_then(|flags| flags.parse().ok());
            let viewed = fux::view_pane(pane.into(), keyboard.unwrap_or(0));
            return viewed.map_or(ExitCode::FAILURE, |()| ExitCode::SUCCESS);
        }
        Some("fux") => return fux::command(words.skip(1)),
        Some("hold") => return fux::command(words),
        _ => {}
    }
    let Ok(args) = words
        .map(std::ffi::OsString::into_string)
        .collect::<std::result::Result<Vec<String>, _>>()
    else {
        let err = KohError::usage("arguments must be valid UTF-8");
        report_err(&err);
        return ExitCode::from(err.code.0);
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let err = KohError::internal(format!("tokio runtime: {e}"));
            report_err(&err);
            return ExitCode::from(err.code.0);
        }
    };
    let done = rt.block_on(run(args));
    // What `run` waited for is done; what it left (a blocking write to a terminal or pipe that
    // takes nothing, a blocked read of stdin) would hold koh's exit for good if waited for.
    rt.shutdown_background();
    match done {
        Ok(code) => ExitCode::from(code.0),
        Err(err) => {
            report_err(&err);
            ExitCode::from(err.code.0)
        }
    }
}

fn report_err(err: &KohError) {
    let _ = writeln!(std::io::stderr(), "koh: {}", err.message);
}

fn take_opt(args: &[String], i: &mut usize, flag: &str) -> Result<String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| KohError::usage(format!("{flag} requires a value")))
}

async fn run(args: Vec<String>) -> Result<Exit> {
    let Some(cmd) = args.first().map(String::as_str) else {
        let _ = std::io::stdout().write_all(HELP.as_bytes());
        return Ok(Exit::OK);
    };
    if matches!(cmd, "-h" | "--help" | "help" | "help-agents") {
        let recipes = if cmd == "help-agents" { RECIPES } else { "" };
        let _ = std::io::stdout().write_all([HELP, recipes].concat().as_bytes());
        return Ok(Exit::OK);
    }
    if matches!(cmd, "-V" | "--version" | "version") {
        let _ = writeln!(std::io::stdout(), "koh {}", env!("CARGO_PKG_VERSION"));
        return Ok(Exit::OK);
    }

    let rest = args.get(1..).unwrap_or_default();
    match cmd {
        "id" => cmd_id(rest),
        "key" => cmd_key(rest),
        "servers" => cmd_servers(rest),
        "clients" => cmd_clients(rest),
        "serve" => cmd_serve(rest).await,
        "exec" => cmd_exec(rest).await,
        "rsh" => cmd_rsh(rest).await,
        "run" => cmd_run(rest).await,
        "jobs" => cmd_jobs(rest).await,
        "logs" => cmd_logs(rest).await,
        "kill" => cmd_kill(rest).await,
        "wait" => cmd_wait(rest).await,
        "sessions" | "output" => cmd_sessions(rest, cmd == "output").await,
        "connect" => cmd_session(rest).await,
        other => Err(KohError::usage(format!(
            "unknown command {other:?} (try `koh --help`)"
        ))),
    }
}

fn parse_role(s: &str) -> Result<Role> {
    match s {
        "client" => Ok(Role::Client),
        "server" => Ok(Role::Server),
        _ => Err(KohError::usage(format!(
            "role must be `client` or `server`, got {s:?}"
        ))),
    }
}

fn cmd_id(args: &[String]) -> Result<Exit> {
    let (mut role, mut key_file) = (Role::Client, None::<PathBuf>);
    let mut i = 0;
    while let Some(a) = args.get(i).map(String::as_str) {
        match a {
            "--key-file" => key_file = Some(PathBuf::from(take_opt(args, &mut i, a)?)),
            "client" | "server" => role = parse_role(a)?,
            _ => return Err(KohError::usage(format!("unexpected argument {a:?}"))),
        }
        i += 1;
    }
    let key = load_or_create_key(role, key_file.as_deref())?;
    let _ = writeln!(std::io::stdout(), "{}", key.public());
    Ok(Exit::OK)
}

fn cmd_key(args: &[String]) -> Result<Exit> {
    if args.first().map(String::as_str) != Some("reset") {
        return Err(KohError::usage(
            "usage: koh key reset [client|server] --yes",
        ));
    }
    let (mut role, mut yes, mut key_file) = (Role::Client, false, None::<PathBuf>);
    let mut i = 1;
    while let Some(a) = args.get(i).map(String::as_str) {
        match a {
            "--yes" => yes = true,
            "--key-file" => key_file = Some(PathBuf::from(take_opt(args, &mut i, a)?)),
            "client" | "server" => role = parse_role(a)?,
            _ => return Err(KohError::usage(format!("unexpected argument {a:?}"))),
        }
        i += 1;
    }
    if !yes {
        return Err(KohError::usage("refusing to delete key without --yes"));
    }
    reset_key(role, key_file.as_deref())?;
    Ok(Exit::OK)
}

/// `--key-file PATH` wherever it is in `args`, and the words that are not it.
fn key_file_and_rest(args: &[String]) -> Result<(Option<PathBuf>, Vec<String>)> {
    let (mut key_file, mut rest) = (None, Vec::new());
    let mut i = 0;
    while let Some(a) = args.get(i).map(String::as_str) {
        match a {
            "--key-file" => key_file = Some(PathBuf::from(take_opt(args, &mut i, a)?)),
            _ => rest.push(a.to_string()),
        }
        i += 1;
    }
    Ok((key_file, rest))
}

/// The words after a subcommand: as many as its usage names, and no more.
fn words<'a, const N: usize>(clean: &'a [String], usage: &str) -> Result<&'a [String; N]> {
    let words = clean.get(1..).unwrap_or_default();
    words.try_into().map_err(|_| KohError::usage(usage))
}

fn cmd_servers(args: &[String]) -> Result<Exit> {
    let (key_file, clean) = key_file_and_rest(args)?;
    let mut list = load_servers(key_file.as_deref())?;
    match clean.first().map(String::as_str) {
        None => {
            for e in &list {
                let route = match &e.route {
                    Some(Route::Direct(a)) => format!(" direct={a}"),
                    Some(Route::Relay(u)) => format!(" relay={u}"),
                    None => String::new(),
                };
                let _ = writeln!(std::io::stdout(), "{} {}{route}", e.name, e.id);
            }
        }
        Some("add") => {
            const USAGE: &str =
                "usage: koh servers add NAME ID [--direct IP:PORT | --relay-url URL]";
            let name = clean.get(1).ok_or_else(|| KohError::usage(USAGE))?;
            let id_s = clean.get(2).ok_or_else(|| KohError::usage(USAGE))?;
            validate_peer_name(name)?;
            let id = parse_endpoint_id(id_s)?;
            let mut route = None;
            let mut j = 3;
            while let Some(a) = clean.get(j).map(String::as_str) {
                match a {
                    "--direct" => {
                        let v = take_opt(&clean, &mut j, a)?;
                        let addr: SocketAddr = v
                            .parse()
                            .map_err(|e| KohError::usage(format!("bad --direct: {e}")))?;
                        route = Some(Route::Direct(addr));
                    }
                    "--relay-url" => {
                        let v = take_opt(&clean, &mut j, a)?;
                        route = Some(Route::Relay(parse_relay_url(&v)?));
                    }
                    _ => return Err(KohError::usage(format!("unexpected argument {a:?}"))),
                }
                j += 1;
            }
            list.retain(|e| e.name != *name);
            list.push(ServerEntry {
                name: name.clone(),
                id,
                route,
            });
            save_servers(key_file.as_deref(), &list)?;
        }
        Some("rm") => {
            let [name] = words(&clean, "usage: koh servers rm NAME")?;
            let before = list.len();
            list.retain(|e| e.name != *name);
            if list.len() == before {
                return Err(KohError::failed(format!("no server named {name:?}")));
            }
            save_servers(key_file.as_deref(), &list)?;
        }
        Some("rename") => {
            let [old, new] = words(&clean, "usage: koh servers rename OLD NEW")?;
            validate_peer_name(new)?;
            let Some(entry) = list.iter_mut().find(|e| e.name == *old) else {
                return Err(KohError::failed(format!("no server named {old:?}")));
            };
            entry.name = new.clone();
            save_servers(key_file.as_deref(), &list)?;
        }
        Some(other) => {
            return Err(KohError::usage(format!(
                "unknown servers subcommand {other:?}"
            )));
        }
    }
    Ok(Exit::OK)
}

fn cmd_clients(args: &[String]) -> Result<Exit> {
    let (key_file, clean) = key_file_and_rest(args)?;
    let mut list = load_clients(key_file.as_deref(), |n, line| {
        let _ = writeln!(
            std::io::stderr(),
            "koh: clients:{n}: ignored, not NAME ID: {line:?}"
        );
    })?;
    match clean.first().map(String::as_str) {
        None => {
            for e in &list {
                let _ = writeln!(std::io::stdout(), "{} {}", e.name, e.id);
            }
        }
        Some("add") => {
            let [name, id_s] = words(&clean, "usage: koh clients add NAME ID")?;
            validate_peer_name(name)?;
            let id = parse_endpoint_id(id_s)?;
            list.retain(|e| e.name != *name);
            list.push(ClientEntry {
                name: name.clone(),
                id,
            });
            save_clients(key_file.as_deref(), &list)?;
        }
        Some("rm") => {
            let [name] = words(&clean, "usage: koh clients rm NAME")?;
            let before = list.len();
            list.retain(|e| e.name != *name);
            if list.len() == before {
                return Err(KohError::failed(format!("no client named {name:?}")));
            }
            save_clients(key_file.as_deref(), &list)?;
        }
        Some("rename") => {
            let [old, new] = words(&clean, "usage: koh clients rename OLD NEW")?;
            validate_peer_name(new)?;
            let Some(entry) = list.iter_mut().find(|e| e.name == *old) else {
                return Err(KohError::failed(format!("no client named {old:?}")));
            };
            entry.name = new.clone();
            save_clients(key_file.as_deref(), &list)?;
        }
        Some(other) => {
            return Err(KohError::usage(format!(
                "unknown clients subcommand {other:?}"
            )));
        }
    }
    Ok(Exit::OK)
}

async fn cmd_serve(args: &[String]) -> Result<Exit> {
    let mut opts = ServeOptions::default();
    let mut i = 0;
    while let Some(a) = args.get(i).map(String::as_str) {
        match a {
            "--key-file" => opts.key_file = Some(PathBuf::from(take_opt(args, &mut i, a)?)),
            "--direct" => {
                let v = take_opt(args, &mut i, a)?;
                opts.direct = Some(
                    v.parse()
                        .map_err(|e| KohError::usage(format!("bad --direct: {e}")))?,
                );
            }
            "--allow" => opts
                .allow
                .push(parse_endpoint_id(&take_opt(args, &mut i, a)?)?),
            "--shell" => opts.shell = Some(take_opt(args, &mut i, a)?),
            "--no-relay" => opts.disable_relay = true,
            "--max-connections" | "--max-sessions" => {
                // (A value that is no number is out of the range too, and is told the same.)
                let most = cap(a, take_opt(args, &mut i, a)?.parse().unwrap_or(0))?;
                if a == "--max-connections" {
                    opts.max_connections = most;
                } else {
                    opts.max_sessions = most;
                }
            }
            _ => return Err(KohError::usage(format!("unexpected serve flag {a:?}"))),
        }
        i += 1;
    }
    run_serve(opts).await?;
    Ok(Exit::OK)
}

fn parse_common_dial(args: &[String], i: &mut usize, opts: &mut DialOptions) -> Result<bool> {
    let Some(a) = args.get(*i).map(String::as_str) else {
        return Ok(false);
    };
    match a {
        "--key-file" => opts.key_file = Some(PathBuf::from(take_opt(args, i, a)?)),
        "--direct" => {
            let v = take_opt(args, i, a)?;
            opts.direct = Some(
                v.parse()
                    .map_err(|e| KohError::usage(format!("bad --direct: {e}")))?,
            );
        }
        "--relay-url" => opts.relay = Some(parse_relay_url(&take_opt(args, i, a)?)?),
        _ => return Ok(false),
    }
    Ok(true)
}

async fn cmd_exec(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions::default();
    let (mut server, mut cwd, mut sh_line) = (None::<String>, None::<String>, None::<String>);
    let mut argv = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        if a == "--" {
            argv.extend_from_slice(args.get(i + 1..).unwrap_or_default());
            break;
        }
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        match a {
            "-C" | "--cwd" => cwd = Some(take_opt(args, &mut i, a)?),
            "--sh" => sh_line = Some(take_opt(args, &mut i, a)?),
            _ if server.is_none() && !a.starts_with('-') => server = Some(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected exec argument {a:?}"))),
        }
        i += 1;
    }
    let server =
        server.ok_or_else(|| KohError::usage("usage: koh exec SERVER [-C DIR] -- PROG ARG..."))?;
    let argv = match sh_line {
        Some(line) => sh_argv(line),
        None if !argv.is_empty() => argv,
        None => {
            return Err(KohError::usage(
                "missing command (use `-- PROG ...` or `--sh 'LINE'`)",
            ));
        }
    };

    run_exec(&server, &opts, argv, cwd).await
}

fn sh_argv(line: String) -> Vec<String> {
    vec!["/bin/sh".into(), "-c".into(), "--".into(), line]
}

async fn run_exec(
    server: &str,
    opts: &DialOptions,
    argv: Vec<String>,
    cwd: Option<String>,
) -> Result<Exit> {
    let client = Client::connect(server, opts, false).await?;
    let done = client.exec(argv, cwd).await;
    client.close().await;
    let code = done?;
    Ok(Exit(u8::try_from(code).unwrap_or(1)))
}

async fn cmd_rsh(args: &[String]) -> Result<Exit> {
    const USAGE: &str =
        "usage: koh rsh [--key-file PATH] [--direct IP:PORT] [--relay-url URL] HOST WORD...";
    let mut opts = DialOptions::default();
    let mut i = 0;
    while let Some(a) = args.get(i).map(String::as_str) {
        if a == "--" || !a.starts_with('-') {
            break;
        }
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        return Err(KohError::usage(format!(
            "rsh does not support option {a:?} (only --key-file, --direct, --relay-url before HOST)"
        )));
    }
    if args.get(i).map(String::as_str) == Some("--") {
        i += 1;
    }
    let Some(host) = args.get(i) else {
        return Err(KohError::usage(USAGE));
    };
    let words = args.get(i + 1..).unwrap_or_default();
    if words.is_empty() {
        return Err(KohError::usage(USAGE));
    }
    run_exec(host, &opts, sh_argv(words.join(" ")), None).await
}

async fn cmd_run(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions::default();
    let (mut server, mut name, mut cwd, mut sh_line) = (
        None::<String>,
        None::<String>,
        None::<String>,
        None::<String>,
    );
    let mut argv = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        if a == "--" {
            argv.extend_from_slice(args.get(i + 1..).unwrap_or_default());
            break;
        }
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        match a {
            "--name" => name = Some(take_opt(args, &mut i, a)?),
            "-C" | "--cwd" => cwd = Some(take_opt(args, &mut i, a)?),
            "--sh" => sh_line = Some(take_opt(args, &mut i, a)?),
            _ if server.is_none() && !a.starts_with('-') => server = Some(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected run argument {a:?}"))),
        }
        i += 1;
    }
    let server =
        server.ok_or_else(|| KohError::usage("usage: koh run SERVER [--name N] -- PROG ARG..."))?;
    let argv = match sh_line {
        Some(line) => sh_argv(line),
        None if !argv.is_empty() => argv,
        None => return Err(KohError::usage("missing command")),
    };
    let client = Client::connect(&server, &opts, false).await?;
    let done = client.run_job(name, argv, cwd).await;
    client.close().await;
    let _ = writeln!(std::io::stdout(), "{}", done?.name);
    Ok(Exit::OK)
}

async fn cmd_jobs(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions::default();
    let (mut server, mut name) = (None::<String>, None::<String>);
    let mut i = 0;
    while i < args.len() {
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        if server.is_none() {
            server = Some(a.to_string());
        } else if name.is_none() {
            name = Some(a.to_string());
        } else {
            return Err(KohError::usage(format!("unexpected argument {a:?}")));
        }
        i += 1;
    }
    let server = server.ok_or_else(|| KohError::usage("usage: koh jobs SERVER [NAME]"))?;
    let client = Client::connect(&server, &opts, false).await?;
    let list = client.jobs(name).await;
    client.close().await;
    // (`fux::plain`: a control character in a peer's text is a `?`, so no field holds a tab.)
    for j in &list? {
        let [name, state, command] = [&j.name, &j.state, &j.command].map(|f| fux::plain(f));
        let _ = writeln!(
            std::io::stdout(),
            "{name}\t{state}\t{}s\t{command}",
            j.age_secs
        );
    }
    Ok(Exit::OK)
}

async fn cmd_logs(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions::default();
    let (mut server, mut name, mut tail, mut all, mut follow) =
        (None::<String>, None::<String>, None::<usize>, false, false);
    let mut i = 0;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        match a {
            "--tail" => {
                tail = Some(
                    take_opt(args, &mut i, a)?
                        .parse()
                        .map_err(|_| KohError::usage("bad --tail"))?,
                )
            }
            "--all" => all = true,
            "-f" | "--follow" => follow = true,
            _ if server.is_none() && !a.starts_with('-') => server = Some(a.to_string()),
            _ if name.is_none() && !a.starts_with('-') => name = Some(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected logs argument {a:?}"))),
        }
        i += 1;
    }
    let (Some(server), Some(name)) = (server, name) else {
        return Err(KohError::usage(
            "usage: koh logs SERVER JOB [--tail N | --all] [-f|--follow]",
        ));
    };
    let client = Client::connect(&server, &opts, follow).await?;
    let done = client
        .logs_to(name, tail, all, follow, std::io::stdout())
        .await;
    client.close().await;
    let Some((state, exit, age)) = done? else {
        return Ok(Exit(141));
    };
    let _ = writeln!(std::io::stderr(), "· {state} {age}s");
    Ok(if follow {
        Exit(u8::try_from(exit.unwrap_or(0)).unwrap_or(1))
    } else {
        Exit::OK
    })
}

async fn cmd_kill(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions::default();
    let (mut server, mut name, mut sig) = (None::<String>, None::<String>, 15i32);
    let mut i = 0;
    while i < args.len() {
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--signal" | "-s" => sig = parse_signal(&take_opt(args, &mut i, a)?)?,
            _ if server.is_none() && !a.starts_with('-') => server = Some(a.to_string()),
            _ if name.is_none() && !a.starts_with('-') => name = Some(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected kill argument {a:?}"))),
        }
        i += 1;
    }
    let (Some(server), Some(name)) = (server, name) else {
        return Err(KohError::usage("usage: koh kill SERVER JOB [--signal SIG]"));
    };
    let client = Client::connect(&server, &opts, false).await?;
    let info = client.kill_job(name, sig).await;
    client.close().await;
    let info = info?;
    if info.state != "running" {
        let _ = writeln!(
            std::io::stderr(),
            "koh: job {} is not running ({})",
            info.name,
            info.state
        );
    }
    Ok(Exit::OK)
}

async fn cmd_wait(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions::default();
    let (mut server, mut job, mut session, mut tail, mut timeout) = (
        None::<String>,
        None::<String>,
        None::<String>,
        None::<usize>,
        None::<u64>,
    );
    let mut i = 0;
    while i < args.len() {
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--session" => session = Some(take_opt(args, &mut i, a)?),
            "--tail" => {
                let lines = take_opt(args, &mut i, a)?.parse();
                tail = Some(lines.map_err(|_| KohError::usage("bad --tail"))?)
            }
            "--timeout" => {
                timeout = Some(
                    take_opt(args, &mut i, a)?
                        .parse()
                        .map_err(|_| KohError::usage("bad --timeout"))?,
                )
            }
            _ if server.is_none() && !a.starts_with('-') => server = Some(a.to_string()),
            _ if job.is_none() && !a.starts_with('-') => job = Some(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected wait argument {a:?}"))),
        }
        i += 1;
    }
    let usage = "usage: koh wait SERVER (JOB | --session NAME)";
    let server = server.ok_or_else(|| KohError::usage(usage))?;
    if session.is_none() && job.is_none() {
        return Err(KohError::usage(usage));
    }
    if session.is_some() && (job.is_some() || tail.is_some()) {
        let both = "a wait is for a job or for a session: JOB and --tail are a job's";
        return Err(KohError::usage(format!(
            "{both}, and are not said with --session"
        )));
    }
    let client = Client::connect(&server, &opts, true).await?;
    let res = match (session, job) {
        (Some(session), _) => client.wait_session(session, timeout).await,
        (None, Some(name)) => client.wait_job(name, tail.unwrap_or(200), timeout).await,
        (None, None) => Err(KohError::usage(usage)),
    };
    client.close().await;
    let res = res?;
    let _ = std::io::stdout().write_all(res.tail.as_bytes());
    let _ = writeln!(std::io::stderr(), "· {}", res.detail);
    Ok(Exit(u8::try_from(res.exit).unwrap_or(1)))
}

/// `koh sessions SERVER`, and as `output` `koh output SERVER --session NAME [--last]`: what a
/// session's folder on the server says.
async fn cmd_sessions(args: &[String], output: bool) -> Result<Exit> {
    let mut opts = DialOptions::default();
    let (mut server, mut session, mut last) = (None::<String>, None::<String>, false);
    let mut i = 0;
    while i < args.len() {
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        match a {
            "--session" if output => session = Some(take_opt(args, &mut i, a)?),
            "--last" if output => last = true,
            _ if server.is_none() && !a.starts_with('-') => server = Some(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected argument {a:?}"))),
        }
        i += 1;
    }
    let Some(server) = server.filter(|_| session.is_some() == output) else {
        return Err(KohError::usage(match output {
            true => "usage: koh output SERVER --session NAME [--last]",
            false => "usage: koh sessions SERVER",
        }));
    };
    let client = Client::connect(&server, &opts, false).await?;
    let said = match &session {
        Some(session) => client.output(session.clone(), last).await,
        None => client
            .sessions()
            .await
            .map(|list| list.iter().map(listed).collect()),
    };
    client.close().await;
    let _ = std::io::stdout().write_all(said?.as_bytes());
    Ok(Exit::OK)
}

/// A session as a line of `koh sessions` (its texts `fux::plain`, as a job's).
fn listed(s: &SessionInfo) -> String {
    let attached = if s.attached { "attached" } else { "detached" };
    let busy = if s.running_command { "busy" } else { "idle" };
    let last = s.last_exit.map_or("-".to_string(), |code| code.to_string());
    let [name, state, title] = [&s.name, &s.state, &s.title].map(|f| fux::plain(f));
    format!(
        "{name}\t{attached}\t{state}\t{busy}\texit={last}\t{}x{}\t{title}\n",
        s.cols, s.rows
    )
}

/// `koh connect`.
async fn cmd_session(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions::default();
    let mut server = None::<String>;
    let mut asks = ConnectOptions::default();
    let mut i = 0;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        if a == "--" {
            asks.argv
                .extend_from_slice(args.get(i + 1..).unwrap_or_default());
            break;
        }
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        match a {
            "--new" => asks.new = true,
            "--session" => asks.session = Some(take_opt(args, &mut i, a)?),
            "-C" | "--cwd" => asks.cwd = Some(take_opt(args, &mut i, a)?),
            _ if server.is_none() && !a.starts_with('-') => server = Some(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected argument {a:?}"))),
        }
        i += 1;
    }
    let server = server.ok_or_else(|| {
        KohError::usage("usage: koh connect SERVER [--session NAME | --new] [-C DIR] [-- PROG...]")
    })?;
    let client = Client::connect_view(&server, &opts).await?;
    let code = client.connect_interactive(asks).await?;
    Ok(Exit(u8::try_from(code).unwrap_or(1)))
}
