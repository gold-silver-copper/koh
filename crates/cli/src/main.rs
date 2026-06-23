//! # koh
//!
//! A resilient peer-to-peer remote shell — mosh (the mobile shell), reimplemented in Rust over
//! [iroh](https://iroh.computer) p2p QUIC. One binary with three subcommands:
//!
//! - `koh serve`   — host a PTY shell for authorized clients (the server side).
//! - `koh connect` — connect to a server by its endpoint id and run the session (the client side).
//! - `koh id`      — print this machine's koh id (to add to a server's `--allow` list).
//!
//! Each subcommand delegates to a library entry point (`koh_server::serve`,
//! `koh_client::connect`, `koh_client::run_id`); this binary is just argument parsing + dispatch.

use clap::{Parser, Subcommand};
use koh_client::{ConnectArgs, IdArgs};
use koh_server::ServeArgs;

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
    Serve(ServeArgs),
    /// Connect to a koh server by its endpoint id.
    Connect(ConnectArgs),
    /// Print this machine's koh id (add it to a server's --allow list).
    Id(IdArgs),
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match dispatch(Cli::parse()).await {
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
        Cmd::Serve(args) => koh_server::serve(args).await.map(|()| None),
        Cmd::Connect(args) => koh_client::connect(args).await,
        Cmd::Id(args) => koh_client::run_id(args).map(|()| None),
    }
}
