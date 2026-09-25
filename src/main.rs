//! The `koh` binary: `serve` / `connect` / `id` / `key` dispatch.

mod args;

use clap::{Parser, Subcommand};

use crate::args::{ConnectArgs, IdArgs, KeyArgs, ServeArgs};

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
    /// Show or reset this machine's identity key.
    Key(KeyArgs),
}

// An explicit runtime instead of `#[tokio::main]`, whose expansion `allow`s `clippy::expect_used`.
fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(dispatch(cli)));
    match result {
        Ok(Some(code)) => std::process::ExitCode::from(exit_status(code)),
        Ok(None) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("koh: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn dispatch(cli: Cli) -> anyhow::Result<Option<u32>> {
    match cli.cmd {
        Cmd::Serve(args) => koh_core::server::serve(args).await.map(|()| None),
        Cmd::Connect(args) => koh_core::client::connect(args).await,
        Cmd::Id(args) => koh_core::idcmd::run_id(args).map(|()| None),
        Cmd::Key(args) => koh_core::keycmd::run(args).map(|()| None),
    }
}

/// The client's exit status for the remote shell's `code`. A POSIX exit status is 8-bit, but
/// the wire carries a `u32`. A code that does not fit (only a broken or hostile server sends
/// one) becomes 255: truncating it could give 0 and report a failed session as a success.
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
