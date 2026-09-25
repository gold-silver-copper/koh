//! The `koh` binary: `serve` / `connect` / `id` / `key` dispatch.

use clap::{Parser, Subcommand};
use koh::client::ConnectArgs;
use koh::idcmd::IdArgs;
use koh::keycmd::KeyArgs;
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
    Serve(ServeArgs),
    /// Authenticated access to an independently owned local Unix service.
    /// Connect to a koh server by its endpoint id.
    Connect(ConnectArgs),
    /// Print this machine's koh id (add it to a server's --allow list).
    Id(IdArgs),
    /// Show or reset this machine's identity key.
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
                clippy::expect_fun_call,
                // Not panics, but the same class of silent failure, and already at zero here:
                // results that must be used, runaway recursion and loops, oversized stack frames,
                // lock guards held across a match, and time/integer ops that panic or truncate.
                unused_must_use,
                unconditional_recursion,
                clippy::suspicious,
                clippy::infinite_loop,
                clippy::large_stack_frames,
                clippy::large_stack_arrays,
                clippy::read_zero_byte_vec,
                clippy::debug_assert_with_mut_call,
                clippy::significant_drop_in_scrutinee,
                clippy::cast_lossless,
                clippy::unchecked_time_subtraction,
                clippy::unused_result_ok,
                clippy::mem_forget,
                clippy::integer_division,
                clippy::allow_attributes_without_reason,
                // Every match names the variants it handles, so a new variant is a compile error
                // at each match instead of silently taking a wildcard arm.
                clippy::wildcard_enum_match_arm,
                // No silent truncation or sign change: convert with `From`/`TryFrom` and say what
                // happens when the value does not fit.
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_possible_wrap,
                // Every `+`, `-`, `*` states its overflow behaviour (`checked_*`, `saturating_*`
                // or a construction that cannot overflow): release builds keep overflow checks,
                // so an unchecked operator is a potential panic.
                clippy::arithmetic_side_effects
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
            Cmd::Serve(args) => koh::server::serve(args).await.map(|()| None),
            Cmd::Connect(args) => koh::client::connect(args).await,
            Cmd::Id(args) => koh::idcmd::run_id(args).map(|()| None),
            Cmd::Key(args) => koh::keycmd::run(args).map(|()| None),
        }
    }

    /// The client's exit status for the remote shell's `code`. A POSIX exit status is 8-bit, but
    /// the wire carries a `u32`. A code that does not fit (only a broken or hostile server sends
    /// one) becomes 255: truncating it could give 0 and report a failed session as a success.
    fn exit_status(code: u32) -> u8 {
        u8::try_from(code).unwrap_or(u8::MAX)
    }
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
