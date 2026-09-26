//! # koh-pty — PTY allocation, shell spawn, resize, reaping
//!
//! The server side's plumbing to the real shell. Allocates a pseudo-terminal, starts the
//! user's login shell on it through the launcher ([`LAUNCH`]), pumps the child's output to an async
//! channel from a dedicated blocking thread, forwards input bytes to the child via a second
//! dedicated thread (so a slow child never blocks a tokio worker), and propagates window-size
//! changes (which `ioctl(TIOCSWINSZ)` turns into `SIGWINCH`).

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};

use fuxix::process::{Pid, Signal};
use tokio::sync::mpsc;

/// Size of each output chunk read from the PTY master.
const READ_CHUNK: usize = 8192;
/// Bound on the output channel (chunks). Backpressure here naturally slows the reader thread.
const OUTPUT_CHANNEL_DEPTH: usize = 512;
/// Bound on the input channel (chunks) feeding the writer thread. Generous, because under normal
/// interactive use the child drains its input promptly; a full queue means the child has stopped
/// reading (flow-controlled or hung), which [`Pty::write_input`] surfaces rather than blocking on.
const WRITE_CHANNEL_DEPTH: usize = 1024;

/// Exit information returned by owned process-group teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupExitStatus {
    code: u32,
    signal: Option<i32>,
}

impl GroupExitStatus {
    pub fn success(&self) -> bool {
        self.signal.is_none() && self.code == 0
    }

    pub fn exit_code(&self) -> u32 {
        self.code
    }

    /// The number of the signal that ended the child, if one did.
    pub fn signal(&self) -> Option<i32> {
        self.signal
    }
}

/// Resolve the session shell when the caller didn't pass `--shell`. Prefers `$SHELL`; otherwise a
/// platform default: `/bin/sh`, which does **not** exist on Android, where it is `/system/bin/sh`.
/// The logic lives in the pure [`resolve_shell`] so it is unit-testable without touching the
/// process env.
fn default_shell() -> String {
    resolve_shell(std::env::var_os("SHELL"))
}

/// The argv to run for `command`: `command[0]` is the program, the rest are arguments. An empty `command` means "the session shell", resolved by `fallback` (the login
/// shell in production; injected so this stays unit-testable without touching the process env).
///
/// Deliberately no whitespace splitting or quote parsing: hosting `zellij attach -c main` takes
/// four elements (`--shell` repeated four times), and a program whose path contains a space still
/// works. Splitting a single `--shell` string is a CLI-layer choice, not a PTY concern.
fn build_command(command: &[String], fallback: impl FnOnce() -> String) -> Vec<OsString> {
    if command.is_empty() {
        vec![fallback().into()]
    } else {
        command.iter().map(OsString::from).collect()
    }
}

/// Remove koh's own env vars (`KOH_*`, such as `KOH_LOG` and `KOH_DNS`) from a command's
/// environment before it spawns the session shell: they configure koh, not the
/// hosted program, and are not the remote user's to read. A `Command` inherits the full parent
/// environment, so we strip *every* inherited `KOH_*` key by prefix (rather than a hand-maintained
/// list that silently misses future vars). The launcher's environment is the program's. Pulled out
/// of [`Pty::spawn`] so it is unit-testable without allocating a real PTY.
fn scrub_koh_env(cmd: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if is_koh_env_key(&key) {
            cmd.env_remove(&key);
        }
    }
}

/// Whether `key` is one of koh's own environment variables (`KOH_*`) — the ones scrubbed from
/// every child koh spawns, here and in the client's bell hook.
pub(crate) fn is_koh_env_key(key: &std::ffi::OsStr) -> bool {
    key.to_string_lossy().starts_with("KOH_")
}

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

/// Typed errors from PTY allocation, shell spawn, and resize (mirrors the
/// `transport-iroh::SetupError` pattern so callers can match on the failure stage).
///
/// Every variant carries one `io::Error`; the reader and writer threads' `Builder::spawn` and the
/// master's clones are the `#[from]` source. Binaries keep `anyhow` internally — their
/// `?`/`.context()` absorb `PtyError` via anyhow's blanket `From<E: Error + Send + Sync>`.
#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    /// Allocating the pseudo-terminal pair failed.
    #[error("opening pty: {0}")]
    OpenPty(#[source] io::Error),
    /// Starting the program on the slave side failed: the launcher, or the program itself.
    #[error("spawning shell: {0}")]
    Spawn(#[source] io::Error),
    /// Wiring up the master read/write pumps failed: cloning the master, or starting a pump
    /// thread.
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
/// The default is the running binary, which must hand a [`LAUNCH`] invocation to [`launched`] (the
/// `koh` binary does); koh-core's own tests name their `koh-launch` binary instead.
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

/// A running shell behind a PTY.
///
/// Construct with [`Pty::spawn`], which also returns the receiver of the child's output.
/// Hold the `Pty` for the life of the session: dropping it drops `writer_tx`, which lets the
/// writer thread finish, and it writes an EOT (Ctrl-D) as it does, so the child sees EOF on its
/// stdin.
pub struct Pty {
    master: OwnedFd,
    /// Bounded sender to the dedicated writer thread (which owns a blocking handle on the master).
    /// Shared by both input producers (keystrokes + host query replies), so writes stay FIFO.
    writer_tx: SyncSender<Vec<u8>>,
    child: std::process::Child,
    /// The child's pid; `None` only if the system reported one that is not a valid pid.
    pid: Option<Pid>,
    /// Set once we have *reaped* the child (a `try_wait`/`wait` returned `Some`). After a reap the
    /// kernel may recycle the PID, so signaling the stored PID could hit an unrelated process —
    /// every kill path checks this and skips when set. An un-reaped exited child is still a
    /// zombie that reserves its PID, so signaling *that* is harmless; only a reaped PID is unsafe.
    reaped: AtomicBool,
    /// Join handles for the reader/writer pump threads, kept so a graceful [`Pty::shutdown`] can
    /// join them rather than leaking detached threads. `None` only after `shutdown` takes them.
    reader_handle: Option<std::thread::JoinHandle<()>>,
    writer_handle: Option<std::thread::JoinHandle<()>>,
}

impl Pty {
    /// Allocate a PTY of `rows`×`cols`, start `command` (or the user's default login shell when
    /// it is empty) on it through `launcher` with `TERM` set, and start streaming its output.
    ///
    /// `command[0]` is the program and the rest are its arguments, passed verbatim — no shell
    /// splitting or quoting happens here.
    ///
    /// Returns the [`Pty`] handle plus an async receiver of raw output chunks. The reader runs
    /// on a dedicated OS thread; when the child closes the PTY the channel ends.
    pub fn spawn(
        rows: u16,
        cols: u16,
        command: &[String],
        term: &str,
        launcher: &Launcher,
    ) -> Result<(Self, mpsc::Receiver<Vec<u8>>), PtyError> {
        // Concurrent allocations on macOS intermittently fail inside `posix_openpt` with a bogus
        // errno (-6 was seen under the short-lived-children test), although fuxix names the slave
        // without `ptsname`'s shared buffer. Allocation is quick; serialize it. A poisoned lock
        // only means another spawn panicked mid-allocation, which leaves nothing to protect, so it
        // is recovered rather than propagated.
        static OPEN_PTY: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let (master, slave) = {
            let _serialized = OPEN_PTY
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            fuxix::pty::open(rows, cols)
        }
        .map_err(|e| PtyError::OpenPty(io::Error::other(e)))?;

        // Start reading the master BEFORE the child exists. If a short-lived child writes and exits
        // (closing the last slave fd) while nothing is reading the master, macOS discards the
        // queued output and the next master read reports EOF: a quick command's entire output was
        // lost about 3 times in 1000 under load. With the reader already blocked in `read`, every
        // byte is consumed as it is written.
        let mut reader = File::from(master.try_clone()?);
        let mut writer = File::from(master.try_clone()?);

        let (tx, rx) = mpsc::channel::<Vec<u8>>(OUTPUT_CHANNEL_DEPTH);
        let reader_handle = std::thread::Builder::new()
            .name("koh-pty-reader".into())
            .spawn(move || {
                let mut buf = [0u8; READ_CHUNK];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break, // EOF: the slave closed (macOS)
                        // `Read::read` guarantees `n <= buf.len()`, so `get(..n)` is always
                        // `Some`; the `else` is a panic-free fallback that can't actually run.
                        Ok(n) => {
                            let Some(chunk) = buf.get(..n) else { break };
                            if tx.blocking_send(chunk.to_vec()).is_err() {
                                break; // receiver dropped: session over
                            }
                        }
                        // Linux reports the slave closing as EIO.
                        Err(e) => {
                            tracing::debug!(error = %e, "pty reader stopping");
                            break;
                        }
                    }
                }
            })?;

        // Dedicated writer thread: it owns a blocking handle on the master and drains the bounded
        // input channel, so `write_input` never blocks a tokio worker. `recv()` yields every
        // buffered chunk before it observes the senders being dropped, so pending writes flush
        // before the EOT that EOFs the child. The thread exits as soon as the last sender (held in
        // `Pty`) drops.
        let (writer_tx, writer_rx) = sync_channel::<Vec<u8>>(WRITE_CHANNEL_DEPTH);
        let writer_handle = std::thread::Builder::new()
            .name("koh-pty-writer".into())
            .spawn(move || {
                while let Ok(chunk) = writer_rx.recv() {
                    if writer
                        .write_all(&chunk)
                        .and_then(|()| writer.flush())
                        .is_err()
                    {
                        break; // master closed / child gone
                    }
                }
                // A newline then EOT: a terminal in canonical mode takes EOT as end of input only
                // at the start of a line. Ctrl-D is VEOF unless the program changed it, and the
                // child is signalled on drop regardless.
                let _ = writer.write_all(b"\n\x04");
            })?;

        let argv = build_command(command, default_shell);
        let child = launch(launcher, &argv, &slave, |cmd| {
            // A real terminal type so curses apps behave; the env is otherwise inherited.
            cmd.env("TERM", term);
            // Scrub koh's own env from the child: it configures koh, not the hosted program.
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
            },
            rx,
        ))
    }

    /// Gracefully tear down the session and join both I/O pump threads (rather than leaking them
    /// as detached threads). Consumes the `Pty`. It first kills the child — so the reader's
    /// blocking `read` returns EOF — then drops the writer sender — so the writer's `recv` returns
    /// — guaranteeing both threads unblock before we join them, so this never deadlocks.
    pub fn shutdown(mut self) {
        // A failed kill is logged, not ignored: if the child somehow survives it keeps the slave
        // fd open, the reader stays blocked on read(), and the join below would hang — so a warning
        // is the breadcrumb for that (otherwise impossible-looking) stall. Skip the kill entirely
        // once the child is reaped: it is already dead (reader saw EOF) and its PID may be recycled.
        // The `drop(self)` below still runs `Drop`, which is likewise reaped-gated.
        if !self.reaped.load(Ordering::SeqCst) {
            if let Err(e) = self.kill() {
                tracing::warn!(error = %e, "pty kill on shutdown failed; reader join may stall");
            }
        }
        let reader = self.reader_handle.take();
        let writer = self.writer_handle.take();
        // Dropping `self` drops `writer_tx`, which lets the writer thread observe the channel
        // close and exit; the child kill above lets the reader thread hit EOF and exit.
        drop(self);
        if let Some(h) = writer {
            let _ = h.join();
        }
        if let Some(h) = reader {
            let _ = h.join();
        }
    }

    /// Forward input bytes to the child (verbatim — keystrokes or host query replies).
    ///
    /// Takes `&self` and never blocks: it enqueues `data` onto the bounded channel feeding the
    /// writer thread. Both producers share one sender, and callers enqueue while holding the
    /// session lock, so bytes stay FIFO (a DSR reply can't overtake the keystroke that triggered
    /// it). Returns [`io::ErrorKind::BrokenPipe`] if the writer thread is gone, and
    /// [`io::ErrorKind::WouldBlock`] if the queue is full — the defined over-limit policy: surface
    /// backpressure rather than block a tokio worker or silently drop input (a full 1024-deep
    /// queue means the child has stopped reading, i.e. the session is effectively dead).
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

    /// Propagate a window-size change; the kernel raises `SIGWINCH` in the child.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError> {
        fuxix::terminal::set_window_size(&self.master, rows, cols)
            .map_err(|e| PtyError::Resize(e.into()))
    }

    /// Non-blocking check for child exit. On a `Some` result the child has been reaped, so the PID
    /// may be recycled — the kill paths must not signal it afterward.
    pub fn try_wait(&mut self) -> std::io::Result<Option<GroupExitStatus>> {
        if self.reaped.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let r = self.child.try_wait().map(|status| {
            status.map(|status| {
                let signal = status.signal();
                GroupExitStatus {
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
    pub fn kill(&mut self) -> io::Result<()> {
        self.signal(Signal::Hup)
    }

    /// Force-kill the child with SIGKILL (which cannot be trapped). [`kill`](Self::kill) only
    /// sends SIGHUP, so a child that ignores SIGHUP (e.g. `trap '' HUP`) would otherwise keep the
    /// PTY slave fd open and wedge the reader thread on a blocking `read()` forever — leaking a
    /// thread + fds per session.
    ///
    /// Skips signaling once the child has been **reaped**: the kernel may have recycled its PID,
    /// so SIGKILL could hit an unrelated same-uid process. A reaped child is already dead (its fds
    /// closed, so the reader already saw EOF), so there is nothing to kill; an un-reaped zombie
    /// still reserves its PID, so the SIGKILL below targets only a PID we still own.
    pub fn kill_hard(&self) {
        let _ = self.signal(Signal::Kill);
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
    fn drop(&mut self) {
        // A `Pty` dropped without an explicit [`Pty::shutdown`] (an error path, a panicking
        // session task) must still guarantee the child dies, so the
        // detached reader thread can't block forever on a still-open slave fd. SIGHUP
        // first (a well-behaved shell exits cleanly), then SIGKILL so a SIGHUP-immune child also
        // dies → the reader hits EOF and the pump threads exit. `writer_tx` drops with the struct,
        // EOFing the child's stdin. We deliberately do NOT join the threads here (that could block
        // the dropping thread, possibly a tokio worker); SIGKILL makes them exit promptly on their
        // own, and `shutdown` remains the path that joins.
        //
        // Skip signaling once the child is reaped: a reaped child is already dead and its
        // PID may have been recycled, so SIGHUP/SIGKILL here could hit an unrelated process.
        if self.reaped.load(Ordering::SeqCst) {
            return;
        }
        let _ = self.signal(Signal::Hup);
        self.kill_hard();
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

    #[test]
    #[expect(
        clippy::items_after_statements,
        reason = "`_assert_typed` is a deliberate compile-time signature assertion kept beside the runtime checks it documents"
    )]
    fn pty_error_variants_are_constructible_and_reachable() {
        let mk = || io::Error::other("boom");
        // Each stage variant is constructible and renders a non-empty message.
        for e in [
            PtyError::OpenPty(mk()),
            PtyError::Spawn(mk()),
            PtyError::Reader(mk()),
            PtyError::Resize(mk()),
        ] {
            assert!(!e.to_string().is_empty(), "variant must Display");
        }
        // The `#[from] io::Error` source (the reader-thread spawn path) yields `Reader`.
        let from_io: PtyError = mk().into();
        assert!(matches!(from_io, PtyError::Reader(_)));
        // A binary's `?`/`.context()` absorbs PtyError via anyhow's blanket `From` — the
        // typed error stays internal to the lib but composes with anyhow at the edges.
        let absorbed: anyhow::Error = PtyError::OpenPty(mk()).into();
        assert!(absorbed.to_string().contains("opening pty"));
        // The public spawn signature carries the typed error.
        fn _assert_typed(r: Result<(), PtyError>) -> Result<(), PtyError> {
            r
        }
    }

    // The real-PTY / real-shell tests (spawn + stream + teardown) live in `tests/pty.rs` — a
    // dedicated integration-test binary — so they don't contend with the ~100 inline tests in
    // this crate's parallel test binary (which starved the PTY reader thread under load).
}
