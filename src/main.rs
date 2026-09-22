//! Koh CLI dispatch. The gateway and shell command sets follow their product features.
//! Identity display and key management do not require shell PTYs or rendering.

use clap::{Parser, Subcommand};
#[cfg(feature = "shell")]
use koh::client::ConnectArgs;
use koh::idcmd::IdArgs;
use koh::keycmd::KeyArgs;
#[cfg(feature = "shell")]
use koh::server::ServeArgs;

#[derive(Parser, Debug)]
#[command(
    name = "koh",
    version,
    about = "koh — a resilient peer-to-peer remote shell (mosh over iroh)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Host a PTY shell for authorized clients.
    #[cfg(feature = "shell")]
    Serve(ServeArgs),
    /// Authenticated access to an independently owned local Unix service.
    #[cfg(feature = "gateway")]
    Gateway(koh::gateway::cli::GatewayArgs),
    /// Connect to a koh server by its endpoint id.
    #[cfg(feature = "shell")]
    Connect(ConnectArgs),
    /// Print this machine's koh id (add it to a server's --allow list).
    Id(IdArgs),
    /// Change the identity key's encryption passphrase (like `ssh-keygen -p`; keys are always
    /// encrypted).
    Key(KeyArgs),
}

/// Declares panic-free items; see `panic_free!` in `src/lib.rs`. Applied per item because the clap
/// derives above emit `#[allow(clippy::restriction)]` and cannot compile under a crate-wide `forbid`.
macro_rules! panic_free {
    ($($item:item)*) => {$(
        #[cfg_attr(
            not(test),
            forbid(
                clippy::unwrap_used,
                clippy::expect_used,
                clippy::panic,
                clippy::unreachable,
                clippy::todo,
                clippy::unimplemented,
                clippy::get_unwrap,
                clippy::unwrap_in_result,
                clippy::panic_in_result_fn,
                clippy::exit,
                clippy::indexing_slicing,
                clippy::string_slice,
                clippy::expect_fun_call
            )
        )]
        $item
    )*};
}

panic_free! {
    // An explicit runtime instead of `#[tokio::main]`, whose expansion `allow`s
    // `clippy::expect_used` and so cannot compile under the `forbid`.
    fn main() -> std::process::ExitCode {
        let cli = Cli::parse();
        let result = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(anyhow::Error::from)
            .and_then(|runtime| runtime.block_on(dispatch(cli)));
        match result {
            // Exit with the remote shell's status (a POSIX wait status is 8-bit).
            Ok(Some(code)) => std::process::ExitCode::from(code as u8),
            Ok(None) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("koh: {e:#}");
                std::process::ExitCode::FAILURE
            }
        }
    }

    async fn dispatch(cli: Cli) -> anyhow::Result<Option<u32>> {
        match cli.cmd {
            #[cfg(feature = "gateway")]
            Cmd::Gateway(args) => koh::gateway::cli::run(args).await.map(|()| None),
            #[cfg(feature = "shell")]
            Cmd::Serve(args) => koh::server::serve(args).await.map(|()| None),
            #[cfg(feature = "shell")]
            Cmd::Connect(args) => koh::client::connect(args).await,
            Cmd::Id(args) => koh::idcmd::run_id(args).map(|()| None),
            Cmd::Key(args) => koh::keycmd::run(args).map(|()| None),
        }
    }
}
