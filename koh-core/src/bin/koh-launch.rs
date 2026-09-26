//! The session launcher for koh-core's own tests: `koh-launch __launch PROGRAM [ARGS...]`, as
//! `koh __launch` is for `koh serve` (see `koh_core::pty::Launcher`). Tests find it through
//! `CARGO_BIN_EXE_koh-launch`; it is left out of the published crate.

fn main() -> std::process::ExitCode {
    if let Some(argv) = koh_core::pty::launch_argv() {
        return std::process::ExitCode::from(koh_core::pty::launched(&argv));
    }
    eprintln!("usage: koh-launch __launch PROGRAM [ARGS...]");
    std::process::ExitCode::from(2)
}
