//! The `koh` binary: `serve` / `connect` / `id` / `key` / `servers` / `clients` dispatch, and the
//! menu `koh` alone opens on a terminal.

mod args;

use std::io::IsTerminal as _;

use crate::args::{Cmd, ConnectArgs, ServerRef};
use koh::names::{List, Places};

// An explicit runtime instead of `#[tokio::main]`, whose expansion `allow`s `clippy::expect_used`.
fn main() -> std::process::ExitCode {
    // Sessions start through this binary (`koh __launch …`), before anything else runs.
    if let Some(argv) = koh::pty::launch_argv() {
        return std::process::ExitCode::from(koh::pty::launched(&argv));
    }
    let cmd = match args::command()
        .try_get_matches()
        .and_then(|matches| args::parse(&matches))
    {
        Ok(cmd) => cmd,
        Err(e) => match args::bad_value(&e) {
            Some(bad) => {
                eprintln!("koh: {bad}");
                return std::process::ExitCode::FAILURE;
            }
            None => e.exit(),
        },
    };
    if matches!(cmd, Cmd::Menu)
        && !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal())
    {
        // As clap does for a missing subcommand: help, and the usage error's status.
        let _ = args::command().print_help();
        return std::process::ExitCode::from(2);
    }
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(dispatch(cmd)));
    match result {
        Ok(Some(code)) => std::process::ExitCode::from(exit_status(code)),
        Ok(None) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("koh: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn dispatch(cmd: Cmd) -> anyhow::Result<Option<u32>> {
    match cmd {
        Cmd::Serve(config) => serve(config).await,
        Cmd::Connect(args) => connect(args).await,
        Cmd::Key(config) => koh::keycmd::run(&config).map(|()| None),
        Cmd::Names { list, op, key_file } => {
            let places = match list {
                List::Servers => Places::new(key_file, None)?,
                List::Clients => Places::new(None, key_file)?,
            };
            koh::names::run(&places, list, op, &mut std::io::stdout()).map(|()| None)
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
                koh::menu::Choice::Connect(id) => connect(defaults_for_connect(id)?).await,
                koh::menu::Choice::Serve => serve(defaults_for_serve()?).await,
            }
        }
    }
}

/// `koh serve`, allowing the clients saved beside the server key as well as any `--allow`.
async fn serve(mut config: koh::server::ServeConfig) -> anyhow::Result<Option<u32>> {
    let places = Places::new(None, config.key_file.clone())?;
    let saved = koh::names::load(&places, List::Clients)?;
    for (_, id) in saved.entries() {
        if !config.allow.contains(&id) {
            config.allow.push(id);
        }
    }
    koh::server::serve(config).await.map(|()| None)
}

/// `koh connect`, with a saved name turned into its id.
async fn connect(args: ConnectArgs) -> anyhow::Result<Option<u32>> {
    let server = match &args.server {
        ServerRef::Id(id) => *id,
        ServerRef::Name(name) => {
            let places = Places::new(args.key_file.clone(), None)?;
            let saved = koh::names::load(&places, List::Servers)?;
            if let Some(id) = saved.get(name) {
                id
            } else {
                let known: Vec<&str> = saved.entries().map(|(n, _)| n).collect();
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
    };
    koh::client::connect(args.into_config(server)).await
}

/// `koh connect <id>` with every option at its default.
fn defaults_for_connect(id: iroh::EndpointId) -> anyhow::Result<ConnectArgs> {
    let id = id.to_string();
    match args::parse(&args::command().try_get_matches_from(["koh", "connect", id.as_str()])?)? {
        Cmd::Connect(args) => Ok(args),
        Cmd::Serve(_) | Cmd::Key(_) | Cmd::Names { .. } | Cmd::Menu => {
            anyhow::bail!("internal error: `koh connect` parsed as another command")
        }
    }
}

/// `koh serve` with every option at its default.
fn defaults_for_serve() -> anyhow::Result<koh::server::ServeConfig> {
    match args::parse(&args::command().try_get_matches_from(["koh", "serve"])?)? {
        Cmd::Serve(config) => Ok(config),
        Cmd::Connect(_) | Cmd::Key(_) | Cmd::Names { .. } | Cmd::Menu => {
            anyhow::bail!("internal error: `koh serve` parsed as another command")
        }
    }
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
