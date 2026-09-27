//! The `koh` binary: `serve` / `connect` / `id` / `key` dispatch.

mod args;

use crate::args::Cmd;

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
        Cmd::Serve(config) => koh::server::serve(config).await.map(|()| None),
        Cmd::Connect(config) => koh::client::connect(config).await,
        Cmd::Key(config) => koh::keycmd::run(config).map(|()| None),
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
