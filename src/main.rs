//! koh CLI entrypoint: zero-macro parser, unified help, strict exit codes, and `--json`.
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use koh::client::{Client, ConnectOptions, DialOptions, parse_signal, sync_before_command};
use koh::keys::{
    ClientEntry, Role, Route, Scope, ServerEntry, load_clients, load_or_create_key, load_servers,
    parse_endpoint_id, parse_relay_url, render_qr, reset_key, save_clients, save_servers,
    validate_peer_name,
};
use koh::server::{ServeOptions, cap, run_serve};
use koh::{Exit, KohError, Result};

const HELP: &str = include_str!("help.txt");

fn main() -> ExitCode {
    // fux's own command line, under two words: `koh fux …` is `fux …`, and `koh hold …` is how
    // `koh fux start` runs this file to hold a pane (a session is such a pane). Both are fux's
    // from their first word on, and handed over before anything else is done: a holder has no
    // thread but fux's own, and no runtime.
    let mut words = std::env::args_os().skip(1).peekable();
    match words.peek().and_then(|word| word.to_str()) {
        Some("fux") => return fux::command(words.skip(1)),
        Some("hold") => return fux::command(words),
        _ => {}
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let err = KohError::internal(format!("tokio runtime: {e}"));
            report_err(&err, json);
            return ExitCode::from(err.code.0);
        }
    };
    match rt.block_on(run(args)) {
        Ok(code) => ExitCode::from(code.0),
        Err(err) => {
            report_err(&err, json);
            ExitCode::from(err.code.0)
        }
    }
}

fn report_err(err: &KohError, json: bool) {
    if json {
        let _ = writeln!(std::io::stdout(), "{}", err.json_line());
    } else {
        let _ = writeln!(std::io::stderr(), "koh: {}", err.message);
    }
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
        let _ = std::io::stdout().write_all(HELP.as_bytes());
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
        "run" => cmd_run(rest).await,
        "jobs" => cmd_jobs(rest).await,
        "logs" => cmd_logs(rest).await,
        "kill" => cmd_kill(rest).await,
        "wait" => cmd_wait(rest).await,
        "cp" => cmd_cp(rest).await,
        // (Answered from a session's files on the server, by the build that follows this one.)
        "sessions" | "output" => Err(not_in_this_build(cmd)),
        "connect" => cmd_session(rest, false).await,
        "mount" => cmd_session(rest, true).await,
        other => Err(KohError::usage(format!(
            "unknown command {other:?} (try `koh --help`)"
        ))),
    }
}

fn not_in_this_build(what: &str) -> KohError {
    let now = "a session is a fux pane on the server: `koh exec` reads its files there";
    KohError::failed(format!("`koh {what}` is not in this build ({now})"))
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
    let (mut role, mut key_file, mut qr) = (Role::Client, None::<PathBuf>, false);
    let mut i = 0;
    while let Some(a) = args.get(i).map(String::as_str) {
        match a {
            "--key-file" => key_file = Some(PathBuf::from(take_opt(args, &mut i, a)?)),
            "--qr" => qr = true,
            "client" | "server" => role = parse_role(a)?,
            _ => return Err(KohError::usage(format!("unexpected argument {a:?}"))),
        }
        i += 1;
    }
    let key = load_or_create_key(role, key_file.as_deref())?;
    let id = key.public();
    let _ = writeln!(std::io::stdout(), "{id}");
    if qr {
        let _ = writeln!(std::io::stderr(), "{}", render_qr(&id));
    }
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

fn cmd_servers(args: &[String]) -> Result<Exit> {
    let mut key_file = None::<PathBuf>;
    let mut clean = Vec::new();
    let mut i = 0;
    while let Some(a) = args.get(i).map(String::as_str) {
        if a == "--key-file" {
            key_file = Some(PathBuf::from(take_opt(args, &mut i, a)?));
        } else {
            clean.push(a.to_string());
        }
        i += 1;
    }
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
            let name = clean.get(1).ok_or_else(|| {
                KohError::usage("usage: koh servers add NAME ID [--direct IP:PORT]")
            })?;
            let id_s = clean.get(2).ok_or_else(|| {
                KohError::usage("usage: koh servers add NAME ID [--direct IP:PORT]")
            })?;
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
            let name = clean
                .get(1)
                .ok_or_else(|| KohError::usage("usage: koh servers rm NAME"))?;
            let before = list.len();
            list.retain(|e| e.name != *name);
            if list.len() == before {
                return Err(KohError::failed(format!("no server named {name:?}")));
            }
            save_servers(key_file.as_deref(), &list)?;
        }
        Some("rename") => {
            let old = clean
                .get(1)
                .ok_or_else(|| KohError::usage("usage: koh servers rename OLD NEW"))?;
            let new = clean
                .get(2)
                .ok_or_else(|| KohError::usage("usage: koh servers rename OLD NEW"))?;
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
    let mut key_file = None::<PathBuf>;
    let mut clean = Vec::new();
    let mut i = 0;
    while let Some(a) = args.get(i).map(String::as_str) {
        if a == "--key-file" {
            key_file = Some(PathBuf::from(take_opt(args, &mut i, a)?));
        } else {
            clean.push(a.to_string());
        }
        i += 1;
    }
    let mut list = load_clients(key_file.as_deref())?;
    match clean.first().map(String::as_str) {
        None => {
            for e in &list {
                let scope = match &e.scope {
                    Scope::Full => String::new(),
                    Scope::Cp(d) => format!(" cp={}", d.display()),
                    Scope::Exec(d) => format!(" exec={}", d.display()),
                };
                let _ = writeln!(std::io::stdout(), "{} {}{scope}", e.name, e.id);
            }
        }
        Some("add") => {
            let name = clean.get(1).ok_or_else(|| {
                KohError::usage("usage: koh clients add NAME ID [--cp DIR | --exec DIR]")
            })?;
            let id_s = clean.get(2).ok_or_else(|| {
                KohError::usage("usage: koh clients add NAME ID [--cp DIR | --exec DIR]")
            })?;
            validate_peer_name(name)?;
            let id = parse_endpoint_id(id_s)?;
            let mut scope = Scope::Full;
            let mut j = 3;
            while let Some(a) = clean.get(j).map(String::as_str) {
                match a {
                    "--cp" => scope = Scope::Cp(PathBuf::from(take_opt(&clean, &mut j, a)?)),
                    "--exec" => scope = Scope::Exec(PathBuf::from(take_opt(&clean, &mut j, a)?)),
                    _ => return Err(KohError::usage(format!("unexpected argument {a:?}"))),
                }
                j += 1;
            }
            list.retain(|e| e.name != *name);
            list.push(ClientEntry {
                name: name.clone(),
                id,
                scope,
            });
            save_clients(key_file.as_deref(), &list)?;
        }
        Some("rm") => {
            let name = clean
                .get(1)
                .ok_or_else(|| KohError::usage("usage: koh clients rm NAME"))?;
            let before = list.len();
            list.retain(|e| e.name != *name);
            if list.len() == before {
                return Err(KohError::failed(format!("no client named {name:?}")));
            }
            save_clients(key_file.as_deref(), &list)?;
        }
        Some("rename") => {
            let old = clean
                .get(1)
                .ok_or_else(|| KohError::usage("usage: koh clients rename OLD NEW"))?;
            let new = clean
                .get(2)
                .ok_or_else(|| KohError::usage("usage: koh clients rename OLD NEW"))?;
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
        "--json" => opts.json = true,
        _ => return Ok(false),
    }
    Ok(true)
}

async fn cmd_exec(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions {
        key_file: None,
        direct: None,
        relay: None,
        json: false,
    };
    let (mut server, mut cwd, mut sync_dir, mut sh_line) = (
        None::<String>,
        None::<String>,
        None::<PathBuf>,
        None::<String>,
    );
    let mut excludes = Vec::new();
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
            "--sync" => sync_dir = Some(PathBuf::from(take_opt(args, &mut i, a)?)),
            "--exclude" => excludes.push(take_opt(args, &mut i, a)?),
            "--sh" => sh_line = Some(take_opt(args, &mut i, a)?),
            _ if server.is_none() && !a.starts_with('-') => server = Some(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected exec argument {a:?}"))),
        }
        i += 1;
    }
    let server = server.ok_or_else(|| {
        KohError::usage("usage: koh exec SERVER [-C DIR] [--sync DIR] -- PROG ARG...")
    })?;
    let (argv, shell) = match sh_line {
        Some(line) => (vec![line], true),
        None if !argv.is_empty() => (argv, false),
        None => {
            return Err(KohError::usage(
                "missing command (use `-- PROG ...` or `--sh 'LINE'`)",
            ));
        }
    };

    let client = Client::connect(&server, &opts, false).await?;
    let done = async {
        if let Some(dir) = sync_dir {
            let (remote_dir, _) =
                sync_before_command(&client, &dir, cwd.as_deref(), excludes, opts.json).await?;
            cwd = Some(remote_dir);
        }
        client.exec(argv, cwd, shell, None, opts.json).await
    }
    .await;
    client.close().await;
    let (code, out, err) = done?;
    if opts.json {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            serde_json::json!({
                "exit": code,
                "stdout": String::from_utf8_lossy(&out),
                "stderr": String::from_utf8_lossy(&err),
            })
        );
    }
    Ok(Exit(u8::try_from(code).unwrap_or(1)))
}

async fn cmd_run(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions {
        key_file: None,
        direct: None,
        relay: None,
        json: false,
    };
    let (mut server, mut name, mut cwd, mut sync_dir, mut sh_line) = (
        None::<String>,
        None::<String>,
        None::<String>,
        None::<PathBuf>,
        None::<String>,
    );
    let mut excludes = Vec::new();
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
            "--sync" => sync_dir = Some(PathBuf::from(take_opt(args, &mut i, a)?)),
            "--exclude" => excludes.push(take_opt(args, &mut i, a)?),
            "--sh" => sh_line = Some(take_opt(args, &mut i, a)?),
            _ if server.is_none() && !a.starts_with('-') => server = Some(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected run argument {a:?}"))),
        }
        i += 1;
    }
    let server =
        server.ok_or_else(|| KohError::usage("usage: koh run SERVER [--name N] -- PROG ARG..."))?;
    let (argv, shell) = match sh_line {
        Some(line) => (vec![line], true),
        None if !argv.is_empty() => (argv, false),
        None => return Err(KohError::usage("missing command")),
    };
    let client = Client::connect(&server, &opts, false).await?;
    let done = async {
        if let Some(dir) = sync_dir {
            let (remote_dir, _) =
                sync_before_command(&client, &dir, cwd.as_deref(), excludes, opts.json).await?;
            cwd = Some(remote_dir);
        }
        client.run_job(name, argv, cwd, shell).await
    }
    .await;
    client.close().await;
    let info = done?;
    if opts.json {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            serde_json::to_string(&info).unwrap_or_default()
        );
    } else {
        let _ = writeln!(std::io::stdout(), "{}", info.name);
    }
    Ok(Exit::OK)
}

async fn cmd_jobs(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions {
        key_file: None,
        direct: None,
        relay: None,
        json: false,
    };
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
    let list = list?;
    if opts.json {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            serde_json::to_string(&list).unwrap_or_default()
        );
    } else {
        for j in &list {
            let _ = writeln!(
                std::io::stdout(),
                "{}\t{}\t{}s\t{}",
                j.name,
                j.state,
                j.age_secs,
                j.command
            );
        }
    }
    Ok(Exit::OK)
}

async fn cmd_logs(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions {
        key_file: None,
        direct: None,
        relay: None,
        json: false,
    };
    let (mut server, mut name, mut tail, mut all, mut follow) =
        (None::<String>, None::<String>, None::<usize>, false, false);
    let mut i = 0;
    while i < args.len() {
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        let a = args.get(i).map(String::as_str).unwrap_or_default();
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
            "usage: koh logs SERVER JOB [--tail N | --all] [-f]",
        ));
    };
    let client = Client::connect(&server, &opts, follow).await?;
    let done = client.logs(name, tail, all, follow).await;
    client.close().await;
    let (bytes, state, exit, age) = done?;
    if !follow {
        let _ = std::io::stdout().write_all(&bytes);
    }
    let _ = writeln!(std::io::stderr(), "· {state} {age}s");
    Ok(if follow {
        Exit(u8::try_from(exit.unwrap_or(0)).unwrap_or(1))
    } else {
        Exit::OK
    })
}

async fn cmd_kill(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions {
        key_file: None,
        direct: None,
        relay: None,
        json: false,
    };
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
    if opts.json {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            serde_json::to_string(&info).unwrap_or_default()
        );
    }
    Ok(Exit::OK)
}

async fn cmd_wait(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions {
        key_file: None,
        direct: None,
        relay: None,
        json: false,
    };
    let (mut server, mut job, mut text, mut tail, mut timeout) = (
        None::<String>,
        None::<String>,
        None::<String>,
        200usize,
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
            "--text" => text = Some(take_opt(args, &mut i, a)?),
            "--session" => return Err(not_in_this_build("wait --session")),
            "--tail" => {
                tail = take_opt(args, &mut i, a)?
                    .parse()
                    .map_err(|_| KohError::usage("bad --tail"))?
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
    let (Some(server), Some(name)) = (server, job) else {
        return Err(KohError::usage("usage: koh wait SERVER JOB"));
    };
    let client = Client::connect(&server, &opts, true).await?;
    let res = client.wait_job(name, text, tail, timeout).await;
    client.close().await;
    let res = res?;

    if opts.json {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            serde_json::to_string(&res).unwrap_or_default()
        );
    } else {
        if !res.tail.is_empty() {
            let _ = std::io::stdout().write_all(res.tail.as_bytes());
        }
        let _ = writeln!(std::io::stderr(), "· {}", res.detail);
    }
    Ok(Exit(u8::try_from(res.exit).unwrap_or(1)))
}

async fn cmd_cp(args: &[String]) -> Result<Exit> {
    let mut opts = DialOptions {
        key_file: None,
        direct: None,
        relay: None,
        json: false,
    };
    let (mut delete, mut preserve, mut dry_run) = (false, false, false);
    let mut excludes = Vec::new();
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args.get(i).map(String::as_str).unwrap_or_default();
        if a == "--" {
            pos.extend_from_slice(args.get(i + 1..).unwrap_or_default());
            break;
        }
        if parse_common_dial(args, &mut i, &mut opts)? {
            i += 1;
            continue;
        }
        match a {
            "-r" | "-R" | "--recursive" => {}
            "--delete" => delete = true,
            "-p" | "--preserve" => preserve = true,
            "--dry-run" | "-n" => dry_run = true,
            "--exclude" => excludes.push(take_opt(args, &mut i, a)?),
            _ if !a.starts_with('-') => pos.push(a.to_string()),
            _ => return Err(KohError::usage(format!("unexpected cp flag {a:?}"))),
        }
        i += 1;
    }
    if pos.len() < 2 {
        return Err(KohError::usage(
            "usage: koh cp [-r] [--delete] [--exclude PAT] [-p] [--dry-run] SRC... DST",
        ));
    }
    let Some((dst, srcs)) = pos.split_last() else {
        return Err(KohError::usage(
            "usage: koh cp [-r] [--delete] [--exclude PAT] [-p] [--dry-run] SRC... DST",
        ));
    };
    if delete && srcs.len() > 1 {
        return Err(KohError::usage("--delete requires a single source"));
    }
    let summary = if let Some((server, rpath)) = split_remote(dst) {
        if srcs.iter().any(|s| split_remote(s).is_some()) {
            return Err(KohError::usage(
                "cannot mix remote sources with a remote destination",
            ));
        }
        let client = Client::connect(server, &opts, false).await?;
        let rdst = if rpath.is_empty() {
            ".".to_string()
        } else {
            rpath.to_string()
        };
        let local_srcs: Vec<PathBuf> = srcs.iter().map(PathBuf::from).collect();
        let s = client
            .cp_push_many(&local_srcs, &rdst, &excludes, delete, preserve, dry_run)
            .await;
        client.close().await;
        s?
    } else {
        let mut server_name: Option<&str> = None;
        let mut remote_srcs = Vec::with_capacity(srcs.len());
        for src in srcs {
            let Some((srv, rpath)) = split_remote(src) else {
                return Err(KohError::usage(
                    "all sources must be SERVER:PATH when destination is local",
                ));
            };
            match server_name {
                None => server_name = Some(srv),
                Some(prev) if prev != srv => {
                    return Err(KohError::usage(
                        "all remote sources in one `koh cp` must use the same server",
                    ));
                }
                Some(_) => {}
            }
            remote_srcs.push(if rpath.is_empty() {
                ".".to_string()
            } else {
                rpath.to_string()
            });
        }
        let server =
            server_name.ok_or_else(|| KohError::usage("one of SRC or DST must be SERVER:PATH"))?;
        let client = Client::connect(server, &opts, false).await?;
        let s = client
            .cp_pull_many(
                &remote_srcs,
                Path::new(dst),
                &excludes,
                delete,
                preserve,
                dry_run,
            )
            .await;
        client.close().await;
        s?
    };

    if opts.json {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            serde_json::to_string(&summary).unwrap_or_default()
        );
    } else {
        for p in &summary.added {
            let _ = writeln!(std::io::stdout(), "+ {p}");
        }
        for p in &summary.updated {
            let _ = writeln!(std::io::stdout(), "~ {p}");
        }
        for p in &summary.deleted {
            let _ = writeln!(std::io::stdout(), "- {p}");
        }
    }
    Ok(Exit::OK)
}

fn split_remote(s: &str) -> Option<(&str, &str)> {
    let (host, path) = s.split_once(':')?;
    if host.is_empty() || host.contains('/') {
        return None;
    }
    Some((host, path))
}

/// `koh connect` and `koh mount` name a session the same way; `mount` may name a directory too.
async fn cmd_session(args: &[String], mount: bool) -> Result<Exit> {
    let mut opts = DialOptions {
        key_file: None,
        direct: None,
        relay: None,
        json: false,
    };
    let (mut server, mut place) = (None::<String>, None::<PathBuf>);
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
            _ if mount && place.is_none() && !a.starts_with('-') => place = Some(a.into()),
            _ => return Err(KohError::usage(format!("unexpected argument {a:?}"))),
        }
        i += 1;
    }
    let server = server.ok_or_else(|| {
        let (what, place) = if mount {
            ("mount", " [DIR]")
        } else {
            ("connect", "")
        };
        KohError::usage(format!(
            "usage: koh {what} SERVER [--session NAME | --new] [-C DIR]{place} [-- PROG...]"
        ))
    })?;
    let client = Client::connect(&server, &opts, true).await?;
    let code = match mount {
        true => client.mount(asks, place, &server).await?,
        false => client.connect_interactive(asks).await?,
    };
    Ok(Exit(u8::try_from(code).unwrap_or(1)))
}
