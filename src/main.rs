//! The `koh` binary: `serve` / `connect` / `sessions` / `exec` / `cp` / `id` / `key` / `servers` /
//! `clients` dispatch, and the menu `koh` alone opens on a terminal.

mod args;

use std::io::IsTerminal as _;

use crate::args::{Cmd, ConnectArgs, RemoteArgs, ServerRef};
use koh::names::{List, Places};

// An explicit runtime instead of `#[tokio::main]`, whose expansion `allow`s `clippy::expect_used`.
fn main() -> std::process::ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cmd = match args::command()
        .try_get_matches_from(&argv)
        .and_then(|matches| args::parse(&matches))
    {
        Ok(cmd) => cmd,
        Err(e) => {
            if let Some(bad) = args::bad_value(&e) {
                koh::log::stderr(format_args!("koh: {bad}"));
                return std::process::ExitCode::FAILURE;
            }
            if let Some(broken) = args::broken_sh(&e, &argv) {
                koh::log::stderr(format_args!("koh: {broken}"));
                return std::process::ExitCode::from(2);
            }
            e.exit()
        }
    };
    if matches!(cmd, Cmd::Menu)
        && !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal())
    {
        // As clap does for a missing subcommand: help, and the usage error's status.
        let _ = args::command().print_help();
        return std::process::ExitCode::from(2);
    }
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => std::process::ExitCode::from(runtime.block_on(run(cmd))),
        Err(e) => {
            koh::log::stderr(format_args!("koh: {e:#}"));
            std::process::ExitCode::FAILURE
        }
    }
}

/// Whether `cmd` asked for `--json`: its errors are said so too.
const fn wants_json(cmd: &Cmd) -> bool {
    match cmd {
        Cmd::Sessions(_, json)
        | Cmd::Jobs(_, _, json)
        | Cmd::Output { json, .. }
        | Cmd::Exec { json, .. }
        | Cmd::Start { json, .. }
        | Cmd::Kill { json, .. }
        | Cmd::Wait { json, .. }
        | Cmd::Copy { json, .. } => *json,
        Cmd::Serve(_)
        | Cmd::Connect(_)
        | Cmd::Logs { .. }
        | Cmd::Key(_)
        | Cmd::Names { .. }
        | Cmd::HelpAgents
        | Cmd::Menu => false,
    }
}

/// Whether `cmd` exits with a remote status, its own errors then 255, as ssh's.
const fn passes_status(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::Exec { .. } | Cmd::Wait { .. } | Cmd::Logs { follow: true, .. }
    )
}

/// Run `cmd`; the status to exit with.
async fn run(cmd: Cmd) -> u8 {
    let (json, passes) = (wants_json(&cmd), passes_status(&cmd));
    match dispatch(cmd).await {
        Ok(Some(code)) => exit_status(code),
        Ok(None) => 0,
        Err(e) => {
            if json {
                use std::io::Write as _;
                let _ = writeln!(std::io::stdout(), "{}", koh::client::cli::json_error(&e));
            } else {
                koh::log::stderr(format_args!("koh: {e:#}"));
            }
            if passes {
                255
            } else {
                koh::client::cli::exit_code(&e)
            }
        }
    }
}

async fn dispatch(cmd: Cmd) -> anyhow::Result<Option<u32>> {
    use koh::client::cli::{self, Format};
    let mut out = std::io::stdout();
    let format = |json| Format { json };
    match cmd {
        Cmd::Serve(config) => serve(config).await,
        Cmd::Connect(args) => connect(args).await,
        Cmd::Sessions(remote, json) => cli::sessions(&resolve(remote)?, format(json), &mut out)
            .await
            .map(|()| None),
        Cmd::Output {
            remote,
            session,
            last,
            json,
        } => cli::output(&resolve(remote)?, (session, last), format(json), &mut out)
            .await
            .map(|()| None),
        Cmd::Exec { remote, run, json } => koh::client::exec(&resolve(remote)?, run, format(json))
            .await
            .map(Some),
        Cmd::Start {
            remote,
            name,
            run,
            json,
        } => cli::run(&resolve(remote)?, (name, run), format(json), &mut out)
            .await
            .map(|()| None),
        Cmd::Jobs(remote, job, json) => cli::jobs(&resolve(remote)?, job, format(json), &mut out)
            .await
            .map(|()| None),
        Cmd::Logs {
            remote,
            job,
            follow,
        } => {
            let status = cli::logs(&resolve(remote)?, job, follow).await?;
            Ok(status.filter(|_| follow))
        }
        Cmd::Kill {
            remote,
            job,
            signal,
            json,
        } => cli::kill(&resolve(remote)?, (job, signal), format(json), &mut out)
            .await
            .map(|()| None),
        Cmd::Wait {
            remote,
            wait,
            timeout,
            json,
        } => cli::wait(&resolve(remote)?, (wait, timeout), format(json), &mut out)
            .await
            .map(Some),
        Cmd::Copy {
            remote,
            job,
            opts,
            shown,
            json,
        } => {
            let remote = resolve(remote)?;
            koh::client::copy(&remote, (job, opts), &shown, format(json))
                .await
                .map(|()| None)
        }
        Cmd::HelpAgents => {
            use std::io::Write as _;
            out.write_all(args::HELP_AGENTS.as_bytes())?;
            Ok(None)
        }
        Cmd::Key(config) => koh::keycmd::run(&config).map(|()| None),
        Cmd::Names { list, op, key_file } => {
            let places = match list {
                List::Servers => Places::new(key_file, None)?,
                List::Clients => Places::new(None, key_file)?,
            };
            koh::names::run(&places, list, op, &mut out).map(|()| None)
        }
        Cmd::Menu => {
            let places = Places::new(None, None)?;
            let choice = koh::menu::run(
                &mut std::io::stdin().lock(),
                &mut std::io::stdout(),
                &places,
            )?;
            match choice {
                koh::menu::Choice::Quit => Ok(None),
                koh::menu::Choice::Connect(name) => connect(defaults_for_connect(&name)?).await,
                koh::menu::Choice::Serve => serve(defaults_for_serve()?).await,
            }
        }
    }
}

/// `koh serve`, allowing the clients saved beside the server key as well as any `--allow`.
async fn serve(mut config: koh::server::ServeConfig) -> anyhow::Result<Option<u32>> {
    config.saved_clients = Some(Places::new(None, config.key_file.clone())?);
    koh::server::serve(config).await.map(|()| None)
}

/// `koh connect`, with a saved name turned into its id and route.
async fn connect(args: ConnectArgs) -> anyhow::Result<Option<u32>> {
    let (server, route) = saved_server(&args.remote)?;
    koh::client::connect(args.into_config(server, route)).await
}

/// `remote`, with a saved name turned into its id and route.
fn resolve(remote: RemoteArgs) -> anyhow::Result<koh::client::Remote> {
    let (server, route) = saved_server(&remote)?;
    Ok(remote.into_remote(server, route))
}

/// The id of `remote`'s server and the route it was saved with: as given (with no route), or
/// saved under its name beside the client key.
fn saved_server(
    remote: &RemoteArgs,
) -> anyhow::Result<(iroh::EndpointId, Option<koh::names::Route>)> {
    match &remote.server {
        ServerRef::Id(id) => Ok((*id, None)),
        ServerRef::Name(name) => {
            let places = Places::new(remote.key_file.clone(), None)?;
            let saved = koh::names::load(&places, List::Servers)?;
            if let Some(entry) = saved.get(name) {
                Ok((entry.id, entry.route.clone()))
            } else {
                let known: Vec<&str> = saved.entries().map(|entry| entry.name.as_str()).collect();
                anyhow::bail!(
                    "{name:?} is neither an endpoint id nor a saved server name ({}); save it with \
                     `koh servers add {name} <id>`",
                    if known.is_empty() {
                        "none are saved".to_owned()
                    } else {
                        format!("saved: {}", known.join(", "))
                    }
                );
            }
        }
    }
}

/// `koh connect <name>` with every option at its default.
fn defaults_for_connect(name: &str) -> anyhow::Result<ConnectArgs> {
    if let Cmd::Connect(args) =
        args::parse(&args::command().try_get_matches_from(["koh", "connect", name])?)?
    {
        return Ok(args);
    }
    anyhow::bail!("internal error: `koh connect` parsed as another command")
}

/// `koh serve` with every option at its default.
fn defaults_for_serve() -> anyhow::Result<koh::server::ServeConfig> {
    if let Cmd::Serve(config) =
        args::parse(&args::command().try_get_matches_from(["koh", "serve"])?)?
    {
        return Ok(config);
    }
    anyhow::bail!("internal error: `koh serve` parsed as another command")
}

/// The exit status for the remote `code`: 255 if it does not fit 8 bits, where truncating could
/// turn a failure into 0.
fn exit_status(code: u32) -> u8 {
    u8::try_from(code).unwrap_or(u8::MAX)
}

#[cfg(test)]
mod tests {
    use super::exit_status;

    #[test]
    fn exit_status_passes_8_bit_codes_through() {
        for code in [0, 1, 42, 127, 128, 255] {
            assert_eq!(u32::from(exit_status(code)), code);
        }
    }

    #[test]
    fn exit_status_never_turns_an_out_of_range_code_into_success() {
        // `code as u8` made 256 and 512 exit 0 and 257 exit 1.
        for code in [256, 257, 512, 65_536, u32::MAX] {
            assert_eq!(exit_status(code), u8::MAX, "code {code}");
        }
    }
}
