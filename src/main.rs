//! # koh
//!
//! An SSH-authenticated peer-to-peer remote shell inspired by mosh, built in Rust over
//! [iroh](https://iroh.computer) p2p QUIC.
//!
//! The public command mirrors mosh: `koh [options] [--] user@<iroh-ssh-endpoint-id> [command...]`.
//! iroh-ssh carries SSH auth over iroh and launches a one-shot remote `koh serve`, then the
//! interactive shell attaches over koh's own iroh protocol. The lower-level `serve`, `connect`, and
//! `id` commands remain hidden implementation details for the bootstrap path.

use clap::{Parser, Subcommand};
use koh::client::{ConnectArgs, IdArgs};
use koh::keycmd::KeyArgs;
use koh::server::ServeArgs;
use koh::ssh::SshArgs;

#[derive(Parser, Debug)]
#[command(
    name = "koh",
    version,
    about = "koh — SSH auth over iroh, then a resilient peer-to-peer shell"
)]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    #[command(flatten)]
    ssh: SshArgs,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Host a PTY shell for authorized clients.
    #[command(hide = true)]
    Serve(ServeArgs),
    /// Connect to a koh server by its endpoint id.
    #[command(hide = true)]
    Connect(ConnectArgs),
    /// Print this machine's koh id (add it to a server's --allow list).
    #[command(hide = true)]
    Id(IdArgs),
    /// Launch a one-shot remote koh server over iroh-ssh, then connect over iroh.
    #[command(hide = true)]
    Ssh(SshArgs),
    /// Change the identity key's encryption passphrase (like `ssh-keygen -p`; keys are always
    /// encrypted).
    #[command(hide = true)]
    Key(KeyArgs),
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
        Some(Cmd::Serve(args)) => koh::server::serve(args).await.map(|()| None),
        Some(Cmd::Connect(args)) => koh::client::connect(args).await,
        Some(Cmd::Id(args)) => koh::client::run_id(args).map(|()| None),
        Some(Cmd::Ssh(args)) => koh::ssh::run(args).await,
        Some(Cmd::Key(args)) => koh::keycmd::run(args).map(|()| None),
        None => koh::ssh::run(cli.ssh).await,
    }
}
