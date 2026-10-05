//! PTYs: start the session's program on one through the launcher ([`LAUNCH`]), pump its output
//! and input on two threads of their own (so a slow program never blocks a tokio worker), resize
//! it, reap it.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use fuxix::poll::{Events, PollFd};
use fuxix::process::{Pid, Signal};
use fuxix::Errno;
use tokio::sync::mpsc;

/// Size of each output chunk read from the PTY master.
const READ_CHUNK: usize = 8192;
/// Bound on the output channel (chunks); a full one slows the reader.
const OUTPUT_CHANNEL_DEPTH: usize = 512;
/// Bound on the input channel (chunks). Full only when the program stopped reading its input,
/// which [`Pty::write_input`] reports instead of blocking.
const WRITE_CHANNEL_DEPTH: usize = 1024;

/// How the program ended: its exit code, which for a signal is 128 plus its number, as a shell
/// reports it, and the signal, if one ended it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exit {
    pub code: u32,
    pub signal: Option<i32>,
}

/// The argv for `command`, taken verbatim (no splitting, so a path with a space works); empty means
/// the shell `fallback` names.
fn build_command(command: &[String], fallback: impl FnOnce() -> String) -> Vec<OsString> {
    if command.is_empty() {
        vec![fallback().into()]
    } else {
        command.iter().map(OsString::from).collect()
    }
}

/// Remove every inherited `KOH_*` variable from `cmd`: they configure koh, not the hosted program,
/// and matching the prefix cannot miss one added later.
fn scrub_koh_env(cmd: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if is_koh_env_key(&key) {
            cmd.env_remove(&key);
        }
    }
}

/// Whether `key` is one of koh's own variables, scrubbed from every child koh spawns.
pub(crate) fn is_koh_env_key(key: &std::ffi::OsStr) -> bool {
    key.to_string_lossy().starts_with("KOH_")
}

/// The session shell when the caller didn't pass `--shell`: `shell_env` (`$SHELL`) if set, else
/// `/bin/sh`, which does **not** exist on Android, where it is `/system/bin/sh`.
fn resolve_shell(shell_env: Option<std::ffi::OsString>) -> String {
    if let Some(sh) = shell_env {
        if !sh.is_empty() {
            return sh.to_string_lossy().into_owned();
        }
    }
    if cfg!(target_os = "android") {
        "/system/bin/sh".to_string()
    } else {
        "/bin/sh".to_string()
    }
}

/// What failed in a PTY: allocation, the spawn, the pump threads, or a resize.
#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    /// Allocating the pseudo-terminal pair failed.
    #[error("opening pty: {0}")]
    OpenPty(#[source] io::Error),
    /// Starting the program on the slave side failed: the launcher, or the program itself.
    #[error("spawning shell: {0}")]
    Spawn(#[source] io::Error),
    /// Cloning the master or starting a pump thread failed.
    #[error("starting pty reader: {0}")]
    Reader(#[from] io::Error),
    /// Propagating a window-size change to the kernel (`TIOCSWINSZ`) failed.
    #[error("resizing pty: {0}")]
    Resize(#[source] io::Error),
}

/// The hidden subcommand that starts a session's program.
///
/// `<binary> __launch PROGRAM [ARGS...]`. Only koh runs it, so it is in no usage text. Its interface
/// is fixed: a running `koh serve` may launch through a newer binary installed over it.
pub const LAUNCH: &str = "__launch";

/// The binary [`Pty::spawn`] runs as the launcher.
///
/// The default is the running binary, which must hand a [`LAUNCH`] invocation to [`launched`], as
/// the `koh` binary does. Tests run a test harness, so they name the `koh` binary explicitly.
#[derive(Clone, Debug, Default)]
pub struct Launcher(Option<PathBuf>);

impl Launcher {
    /// The running binary.
    pub const fn this_binary() -> Self {
        Self(None)
    }

    /// The binary at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(Some(path.into()))
    }

    /// The file to run. On Linux and Android the running binary is its image, even once its file
    /// is replaced (an upgrade) or removed.
    fn program(&self) -> io::Result<PathBuf> {
        match &self.0 {
            Some(path) => Ok(path.clone()),
            None if cfg!(any(target_os = "linux", target_os = "android")) => {
                Ok(PathBuf::from("/proc/self/exe"))
            }
            None => std::env::current_exe(),
        }
    }
}

/// Runs `argv` through `launcher` as the leader of a new session with `slave` as its controlling
/// terminal and its stdin, stdout and stderr; `setup` sets the environment. Once this returns the
/// child is the program, with the pid the launcher had.
///
/// Starting a process in a new session needs code between `fork` and `exec`, which std allows only
/// through `unsafe`. The launcher runs that code as a program of its own instead, and reports a
/// failure, including its `exec` failing, on a pipe that `exec` closes: as std reports its own, so
/// this returns only once the program runs or cannot.
fn launch(
    launcher: &Launcher,
    argv: &[OsString],
    slave: &OwnedFd,
    setup: impl FnOnce(&mut Command),
) -> io::Result<std::process::Child> {
    let (mut failures, report) = io::pipe()?;
    let mut child = {
        let mut command = Command::new(launcher.program()?);
        command.arg(LAUNCH).args(argv);
        setup(&mut command);
        command
            .stdin(slave.try_clone()?)
            .stdout(report)
            .stderr(slave.try_clone()?);
        // Dropping `command` closes this side's end of the pipe.
        command.spawn()?
    };
    let mut failure = String::new();
    let read = failures.read_to_string(&mut failure);
    if read.is_ok() && failure.is_empty() {
        return Ok(child);
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(read.err().unwrap_or_else(|| io::Error::other(failure)))
}

/// The launcher's arguments, `PROGRAM [ARGS...]`, if this process was started as the launcher.
///
/// That is `<binary> __launch PROGRAM [ARGS...]`. A binary that launches sessions checks this first,
/// before it parses its command line or starts anything, and then calls [`launched`].
pub fn launch_argv() -> Option<Vec<OsString>> {
    let mut args = std::env::args_os().skip(1);
    if args.next()? == LAUNCH {
        Some(args.collect())
    } else {
        None
    }
}

/// The launcher: makes `PROGRAM [ARGS...]` a session leader on the PTY and becomes it.
///
/// [`Pty::spawn`] runs it as `<binary> __launch PROGRAM [ARGS...]`, with its stdin and stderr on a
/// PTY slave and its stdout on the pipe that reports a failure. It returns only if the program
/// could not start, with the exit status to use.
pub fn launched(argv: &[OsString]) -> u8 {
    // Whatever `koh serve` inherited without close-on-exec, or a thread of it opened while this
    // launcher was being spawned, reached here: marked, it goes no further, and the program gets
    // stdio and nothing else.
    let marked = fuxix::io::cloexec_from(3);
    // A close-on-exec copy, so a successful `exec` closes the pipe; the program's stdout is the PTY.
    let report = io::stdout().as_fd().try_clone_to_owned();
    let failure = match marked {
        Ok(()) => become_program(argv),
        Err(errno) => io::Error::other(format!(
            "marking inherited descriptors close-on-exec: {errno}"
        )),
    };
    if let Ok(report) = report {
        let _ = File::from(report).write_all(failure.to_string().as_bytes());
    }
    127
}

/// Makes this process the leader of a new session with its stdin as the controlling terminal, then
/// replaces it with `argv`. The error, if either fails. The spawn of the launcher cleared the
/// signal mask, and `exec` restores default dispositions (and the SIGPIPE Rust ignores), so the
/// program starts as it would from a shell.
fn become_program(argv: &[OsString]) -> io::Error {
    let Some((program, args)) = argv.split_first() else {
        return io::Error::other("no program to run");
    };
    if let Err(errno) = fuxix::process::setsid() {
        return io::Error::other(format!("setsid: {errno}"));
    }
    let terminal = io::stdin();
    if let Err(errno) = fuxix::terminal::make_controlling(&terminal) {
        return io::Error::other(format!("taking the PTY as controlling terminal: {errno}"));
    }
    let error = match terminal.as_fd().try_clone_to_owned() {
        Ok(stdout) => Command::new(program).args(args).stdout(stdout).exec(),
        Err(error) => error,
    };
    io::Error::other(format!("starting {}: {error}", program.to_string_lossy()))
}

/// How long the writer waits for the terminal to take more input before it looks at `stopping`
/// again. Only reached while a write cannot proceed, so it costs nothing in an interactive session.
const WRITE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Write all of `bytes` to `fd`, waiting for the terminal to take them, unless `stopping` is set or
/// the terminal is gone; whether all of it was written.
///
/// The master is non-blocking, so the wait is a `poll` the flag is checked around: a program that
/// stops reading its input cannot wedge this thread, as a blocking write to a full terminal input
/// queue does — the kernel does not wake that write even once the program is dead.
fn write_while_running(fd: &OwnedFd, bytes: &[u8], stopping: &AtomicBool) -> bool {
    let mut rest = bytes;
    while !rest.is_empty() {
        if stopping.load(Ordering::SeqCst) {
            return false;
        }
        let mut waiting = [PollFd::new(fd, Events::OUT)];
        match fuxix::poll::poll(&mut waiting, Some(WRITE_POLL_INTERVAL)) {
            Ok(_) => {}
            Err(errno) if errno == Errno::INTR => continue,
            Err(errno) => {
                tracing::debug!(error = %errno, "pty writer stopping");
                return false;
            }
        }
        let ready = waiting.first().map_or(Events::ERR, PollFd::revents);
        if ready.intersects(Events::ERR | Events::HUP | Events::NVAL) {
            return false; // the terminal is gone
        }
        if !ready.intersects(Events::OUT) {
            continue; // the timeout passed: look at `stopping` again
        }
        match fuxix::io::write(fd, rest) {
            Ok(0) => return false,
            Ok(n) => match rest.get(n..) {
                Some(remaining) => rest = remaining,
                None => return false,
            },
            Err(errno) if errno == Errno::AGAIN || errno == Errno::INTR => {}
            Err(errno) => {
                tracing::debug!(error = %errno, "pty writer stopping");
                return false;
            }
        }
    }
    true
}

/// A program running on a PTY. Dropping it ends the writer thread, which writes an EOT (Ctrl-D)
/// as it goes, and signals the program.
pub struct Pty {
    master: OwnedFd,
    /// To the writer thread. Keystrokes and query replies share it, so they stay in order.
    writer_tx: SyncSender<Vec<u8>>,
    child: std::process::Child,
    /// The child's pid; `None` only if the system reported one that is not a valid pid.
    pid: Option<Pid>,
    /// Set once the child is reaped. Its PID may then be recycled, so nothing signals it; an
    /// unreaped zombie still holds its PID, so signalling that is harmless.
    reaped: AtomicBool,
    /// The pump threads, for [`Pty::shutdown`] to join.
    reader_handle: Option<std::thread::JoinHandle<()>>,
    writer_handle: Option<std::thread::JoinHandle<()>>,
    /// Set while the session is being torn down: the writer thread gives up whatever the program
    /// left unread, so a join never waits on a write that can no longer complete.
    stopping: Arc<AtomicBool>,
}

impl Pty {
    /// Allocate a `rows`×`cols` PTY and start `command` (argv, verbatim; empty for the login shell)
    /// on it through `launcher`, with `TERM` set. Returns it and a receiver of its output, which
    /// ends when the program closes the PTY.
    pub fn spawn(
        rows: u16,
        cols: u16,
        command: &[String],
        term: &str,
        launcher: &Launcher,
    ) -> Result<(Self, mpsc::Receiver<Vec<u8>>), PtyError> {
        // fuxix serializes the allocation itself and works around macOS's PTY races.
        let (master, slave) =
            fuxix::pty::open(rows, cols).map_err(|e| PtyError::OpenPty(io::Error::other(e)))?;

        // Read the master before the child exists: macOS discards what a short-lived child wrote
        // if it exits before anything reads (about 3 spawns in 1000 under load).
        let reader = master.try_clone()?;
        let writer = master.try_clone()?;
        // Both pumps wait in `poll`, never in a read or write (the clones share this flag): a write
        // blocked on a full input queue is not woken even when the program dies.
        fuxix::io::set_nonblocking(&master, true)
            .map_err(|e| PtyError::OpenPty(io::Error::from(e)))?;
        let stopping = Arc::new(AtomicBool::new(false));

        let (tx, rx) = mpsc::channel::<Vec<u8>>(OUTPUT_CHANNEL_DEPTH);
        let reader_handle = std::thread::Builder::new()
            .name("koh-pty-reader".into())
            .spawn(move || {
                // Each read lands in the buffer that is sent on, so a chunk is never copied.
                let mut buf = vec![0u8; READ_CHUNK];
                loop {
                    let mut waiting = [PollFd::new(&reader, Events::IN)];
                    match fuxix::poll::poll(&mut waiting, None) {
                        Ok(_) => {}
                        Err(errno) if errno == Errno::INTR => continue,
                        Err(errno) => {
                            tracing::debug!(error = %errno, "pty reader stopping");
                            break;
                        }
                    }
                    match fuxix::io::read(&reader, &mut buf) {
                        Ok(0) => break, // EOF: the slave closed (macOS)
                        Ok(n) => {
                            let mut chunk = std::mem::replace(&mut buf, vec![0u8; READ_CHUNK]);
                            chunk.truncate(n);
                            if tx.blocking_send(chunk).is_err() {
                                break; // receiver dropped: session over
                            }
                        }
                        Err(errno) if errno == Errno::AGAIN || errno == Errno::INTR => {}
                        // Linux reports the slave closing as EIO.
                        Err(errno) => {
                            tracing::debug!(error = %errno, "pty reader stopping");
                            break;
                        }
                    }
                }
            })?;

        // `recv` yields every queued chunk before it sees the sender dropped, so pending input is
        // written before the EOT.
        let (writer_tx, writer_rx) = sync_channel::<Vec<u8>>(WRITE_CHANNEL_DEPTH);
        let writer_handle = {
            let stopping = Arc::clone(&stopping);
            std::thread::Builder::new()
                .name("koh-pty-writer".into())
                .spawn(move || {
                    while let Ok(chunk) = writer_rx.recv() {
                        if !write_while_running(&writer, &chunk, &stopping) {
                            break; // master closed, child gone, or teardown
                        }
                    }
                    // A newline then EOT: a terminal in canonical mode takes EOT as end of input
                    // only at the start of a line. Ctrl-D is VEOF unless the program changed it,
                    // and the child is signalled on drop regardless.
                    write_while_running(&writer, b"\n\x04", &stopping);
                })?
        };

        let argv = build_command(command, || resolve_shell(std::env::var_os("SHELL")));
        let child = launch(launcher, &argv, &slave, |cmd| {
            cmd.env("TERM", term);
            scrub_koh_env(cmd);
        })
        .map_err(PtyError::Spawn)?;
        // The child holds the slave now; drop ours so EOF propagates when it exits.
        drop(slave);
        let pid = Pid::of(&child);

        Ok((
            Self {
                master,
                writer_tx,
                child,
                pid,
                reaped: AtomicBool::new(false),
                reader_handle: Some(reader_handle),
                writer_handle: Some(writer_handle),
                stopping,
            },
            rx,
        ))
    }

    /// Tear the session down and join both pump threads. Dropping the `Pty` signals the child, so
    /// the reader sees EOF, and closes the writer's channel, so neither join can hang.
    pub fn shutdown(mut self) {
        let reader = self.reader_handle.take();
        let writer = self.writer_handle.take();
        drop(self);
        for handle in [writer, reader].into_iter().flatten() {
            let _ = handle.join();
        }
    }

    /// Queue `data` for the program, without blocking. [`io::ErrorKind::WouldBlock`] if the queue
    /// is full (the program stopped reading), [`io::ErrorKind::BrokenPipe`] if the writer is gone.
    pub fn write_input(&self, data: &[u8]) -> io::Result<()> {
        match self.writer_tx.try_send(data.to_vec()) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "pty writer queue full (child not draining its input)",
            )),
            Err(TrySendError::Disconnected(_)) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        }
    }

    /// How the PTY takes typed keys now, as the program set it: echo and line mode. `None` if the
    /// modes cannot be read.
    pub fn tty_modes(&self) -> Option<crate::terminal::TtyModes> {
        let modes = fuxix::terminal::attributes(&self.master).ok()?;
        Some(crate::terminal::TtyModes {
            echo: modes.echoes(),
            line: modes.line_mode(),
        })
    }

    /// Propagate a window-size change; the kernel raises `SIGWINCH` in the child.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError> {
        fuxix::terminal::set_window_size(&self.master, rows, cols)
            .map_err(|e| PtyError::Resize(e.into()))
    }

    /// How the child ended, if it has; it is then reaped, and never signalled again.
    pub fn try_wait(&mut self) -> std::io::Result<Option<Exit>> {
        if self.reaped.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let r = self.child.try_wait().map(|status| {
            status.map(|status| {
                let signal = status.signal();
                Exit {
                    code: signal.map_or_else(
                        || u32::try_from(status.code().unwrap_or_default()).unwrap_or(u32::MAX),
                        |signal| 128_u32.saturating_add(u32::try_from(signal).unwrap_or(u32::MAX)),
                    ),
                    signal,
                }
            })
        });
        if matches!(r, Ok(Some(_))) {
            self.reaped.store(true, Ordering::SeqCst);
        }
        r
    }

    /// Terminate the child with SIGHUP, as a terminal hanging up would. No-op once the child is
    /// reaped, so we never SIGHUP a recycled PID.
    pub fn kill(&self) -> io::Result<()> {
        self.signal(Signal::Hup)
    }

    /// Send `signal` to the child, unless it has been reaped (its PID may be recycled).
    fn signal(&self, signal: Signal) -> io::Result<()> {
        if self.reaped.load(Ordering::SeqCst) {
            return Ok(());
        }
        match self.pid {
            Some(pid) => fuxix::process::kill(pid, signal).map_err(io::Error::from),
            None => Ok(()),
        }
    }
}

impl Drop for Pty {
    /// Whether dropped after [`shutdown`](Pty::shutdown) or on an error path, the child must die
    /// so the reader thread cannot block forever on a slave it keeps open. The threads are not
    /// joined here: that could block a tokio worker; `shutdown` joins them.
    fn drop(&mut self) {
        // What the program has not read by now it never will: the writer stops at its next look.
        self.stopping.store(true, Ordering::SeqCst);
        // SIGHUP first, for a clean exit, then SIGKILL for a program that ignores it. Neither once
        // the child is reaped (see `signal`).
        let _ = self.signal(Signal::Hup);
        let _ = self.signal(Signal::Kill);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_command_passes_argv_verbatim_and_falls_back_when_empty() {
        // `command[0]` is the program, the tail its arguments — no splitting, no quoting.
        let argv: Vec<String> = ["zellij", "attach", "-c", "my session"]
            .into_iter()
            .map(String::from)
            .collect();
        // The fallback must not be consulted for a non-empty argv; a sentinel proves it wasn't.
        let got = build_command(&argv, || "FALLBACK-MUST-NOT-BE-USED".to_owned());
        assert_eq!(
            got,
            ["zellij", "attach", "-c", "my session"],
            "argv must reach the child exactly as given"
        );

        // Empty argv means "the session shell", resolved by the injected fallback.
        let got = build_command(&[], || "/custom/shell".to_owned());
        assert_eq!(got, ["/custom/shell"]);
    }

    #[test]
    fn resolve_shell_prefers_env_then_platform_default() {
        use std::ffi::OsString;
        // An explicit non-empty `$SHELL` wins.
        assert_eq!(
            resolve_shell(Some(OsString::from("/usr/bin/fish"))),
            "/usr/bin/fish"
        );
        // Empty `$SHELL` behaves like unset → a concrete absolute platform default.
        let empty = resolve_shell(Some(OsString::new()));
        let unset = resolve_shell(None);
        assert_eq!(empty, unset, "empty SHELL falls through like unset");
        assert!(
            unset.starts_with('/') && !unset.is_empty(),
            "an absolute fallback path"
        );
        // On Android the default must be the shell that actually exists (NOT /bin/sh).
        if cfg!(target_os = "android") {
            assert_eq!(unset, "/system/bin/sh");
        } else {
            assert_eq!(unset, "/bin/sh");
        }
    }

    #[test]
    fn scrub_removes_inherited_koh_vars() {
        // KOH_* vars set in the server's environment must not reach the spawned shell. A
        // `Command` inherits the parent env, so the scrub must remove an *inherited* var
        // explicitly: `get_envs` lists it as removed (`None`).
        std::env::set_var("KOH_SCRUB_TEST", "topsecret-unit");
        std::env::set_var("KOH_DNS", "1.1.1.1");
        let mut cmd = Command::new("/bin/sh");
        scrub_koh_env(&mut cmd);
        let removed: Vec<_> = cmd
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_owned())
            .collect();
        assert!(
            removed.iter().any(|key| key == "KOH_SCRUB_TEST"),
            "an inherited KOH_* var must be scrubbed from the child env"
        );
        assert!(
            removed.iter().any(|key| key == "KOH_DNS"),
            "operational KOH_* vars are scrubbed too"
        );
        std::env::remove_var("KOH_SCRUB_TEST");
        std::env::remove_var("KOH_DNS");
    }

    // The real-PTY / real-shell tests (spawn + stream + teardown) live in `tests/pty.rs` — a
    // dedicated integration-test binary — so they don't contend with the ~100 inline tests in
    // this crate's parallel test binary (which starved the PTY reader thread under load).
}
