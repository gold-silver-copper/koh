//! The one way the integration tests start a program, so what they may run is one list: koh itself
//! (the built binary, or a copy of it installed elsewhere) and harmless tools. Never a program that
//! authenticates, as `sudo` or `passwd` do: a test that typed a wrong password into one would be a
//! failed login on the machine running the tests. `Command::new` is banned everywhere else.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

/// The programs besides koh a test may start.
const HARMLESS: &[&str] = &["nvim"];

/// A command for `program`: the `koh` binary (by path, the file named `koh`) or a program of
/// [`HARMLESS`]. Anything else is refused.
pub fn command(program: impl AsRef<OsStr>) -> std::io::Result<Command> {
    let program = program.as_ref();
    let name = Path::new(program).file_name().and_then(OsStr::to_str);
    if name == Some("koh") || name.is_some_and(|name| HARMLESS.contains(&name)) {
        #[expect(
            clippy::disallowed_methods,
            reason = "the tests' one way to start a program"
        )]
        Ok(Command::new(program))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "tests may not run {}: only koh and {HARMLESS:?}",
                program.display()
            ),
        ))
    }
}
