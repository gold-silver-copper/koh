//! PTYs: start the session's program on one through the launcher ([`LAUNCH`]), pump its output
//! and input on two threads of their own (so a slow program never blocks a tokio worker), resize
//! it, reap it.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
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
/// Input retained by the writer, including its in-flight write. Each chunk also costs at
/// least 64 bytes, bounding the queue's allocation overhead for many tiny writes. An empty queue
/// takes one chunk of any size: a whole paste goes in one write.
const WRITE_BUDGET: usize = 1024 * 1024;

/// How long a hung-up program has to exit, saving its history, before it is killed.
const HANGUP_GRACE: Duration = Duration::from_secs(1);

/// A write the PTY did not take; its allocation stays with the caller for a retry.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("the PTY's input queue is full")]
    Full(Vec<u8>),
    #[error("the PTY's input is closed")]
    Closed(Vec<u8>),
}

struct InputChunk {
    bytes: Vec<u8>,
    budget: Arc<AtomicUsize>,
    charge: usize,
}

impl Drop for InputChunk {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.charge, Ordering::AcqRel);
    }
}

fn reserve_input(budget: &AtomicUsize, len: usize) -> bool {
    let mut used = budget.load(Ordering::Acquire);
    loop {
        let Some(next) = used
            .checked_add(len.max(64))
            .filter(|&next| used == 0 || next <= WRITE_BUDGET)
        else {
            return false;
        };
        match budget.compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(current) => used = current,
        }
    }
}

/// How the program ended. Once it has, this always says how, so a session's last screen always
/// carries a status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exit {
    /// It exited with this code, which for a signal is 128 plus its number, as a shell reports it.
    Status(u32),
    /// It closed its terminal and ran on: it is hung up as its session ends, so it ends as by
    /// SIGHUP.
    HungUp,
}

impl Exit {
    /// The status a shell would report.
    pub const fn code(self) -> u32 {
        match self {
            Self::Status(code) => code,
            Self::HungUp => 129,
        }
    }
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

/// Remove each `KOH_*` variable of the `inherited` from `cmd`: they configure koh, not the hosted
/// program, and matching the prefix cannot miss one added later.
fn scrub_koh_env(cmd: &mut Command, inherited: impl Iterator<Item = OsString>) {
    for key in inherited.filter(|key| is_koh_env_key(key)) {
        cmd.env_remove(key);
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
pub const LAUNCH: &str = fuxix::pty::LAUNCH;

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
    fuxix::pty::launched(argv)
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

/// The program, until it is reaped: owning it is the right to signal its pid, which is no longer
/// its own once reaped.
struct Running {
    child: std::process::Child,
    pid: Pid,
}

impl Running {
    fn signal(&self, signal: Signal) -> io::Result<()> {
        fuxix::process::kill(self.pid, signal).map_err(io::Error::from)
    }

    /// How it ended, if it has; reaped then.
    fn try_wait(&mut self) -> io::Result<Option<Exit>> {
        let Some(status) = self.child.try_wait()? else {
            return Ok(None);
        };
        let code = status.signal().map_or_else(
            || u32::try_from(status.code().unwrap_or_default()).unwrap_or(u32::MAX),
            |signal| 128_u32.saturating_add(u32::try_from(signal).unwrap_or(u32::MAX)),
        );
        Ok(Some(Exit::Status(code)))
    }

    /// Hang up, as a terminal closing does, and leave it to `reaper`, which kills it if it
    /// outlives [`HANGUP_GRACE`].
    fn hang_up(self, reaper: &Reaper) {
        let _ = self.signal(Signal::Hup);
        let kill_at = std::time::Instant::now().checked_add(HANGUP_GRACE);
        if let Err(error) = reaper.0.send(Reap::Child(Stopping {
            running: self,
            kill_at,
        })) {
            tracing::error!(%error, "PTY child reaper stopped unexpectedly");
        }
    }
}

/// What the reaper is given: a hung-up program, or someone waiting until none is left.
enum Reap {
    Child(Stopping),
    Drain(Sender<()>),
}

/// A hung-up program, waited for until reaped, and killed at `kill_at`.
struct Stopping {
    running: Running,
    kill_at: Option<std::time::Instant>,
}

impl Stopping {
    /// Whether it is reaped, or cannot be waited for (no retry would change that); killed first if
    /// its grace is over.
    fn reaped(&mut self) -> bool {
        if self
            .kill_at
            .is_some_and(|at| std::time::Instant::now() >= at)
        {
            let _ = self.running.signal(Signal::Kill);
            self.kill_at = None;
        }
        match self.running.try_wait() {
            Ok(exit) => exit.is_some(),
            Err(error) => {
                tracing::warn!(%error, "could not reap PTY child");
                true
            }
        }
    }
}

/// The thread that reaps hung-up programs, polling them all, so one that does not exit delays none
/// of the others.
///
/// One per server, started before any child, so failing to start it orphans none and stops the
/// server at once. Every [`Pty`] is handed it; it runs until the last of them and of its handles
/// are gone and every program it was given is reaped.
#[derive(Clone, Debug)]
pub struct Reaper(Sender<Reap>);

impl Reaper {
    /// Start the thread.
    pub fn start() -> io::Result<Self> {
        let (tx, rx) = channel::<Reap>();
        std::thread::Builder::new()
            .name("koh-child-reaper".into())
            .spawn(move || {
                let mut children: Vec<Stopping> = Vec::new();
                let mut drains: Vec<Sender<()>> = Vec::new();
                let mut open = true;
                while open || !children.is_empty() {
                    let received = if !open {
                        std::thread::sleep(Duration::from_millis(20));
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    } else if children.is_empty() {
                        rx.recv()
                            .map_err(|_closed| std::sync::mpsc::RecvTimeoutError::Disconnected)
                    } else {
                        rx.recv_timeout(Duration::from_millis(20))
                    };
                    match received {
                        Ok(Reap::Child(child)) => children.push(child),
                        Ok(Reap::Drain(done)) => drains.push(done),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => open = false,
                    }
                    children.retain_mut(|child| !child.reaped());
                    if children.is_empty() {
                        for done in std::mem::take(&mut drains) {
                            let _ = done.send(());
                        }
                    }
                }
            })?;
        Ok(Self(tx))
    }

    /// Wait until every hung-up program is reaped, each killed once its grace is over: before the
    /// process exits, which would leave one that ignores SIGHUP running. Blocks for at most a
    /// little over [`HANGUP_GRACE`], so call it on a blocking worker.
    pub fn drain(&self) {
        let (done, drained) = channel();
        if self.0.send(Reap::Drain(done)).is_ok() {
            let _ = drained.recv_timeout(HANGUP_GRACE.saturating_mul(2));
        }
    }
}

/// The pump threads, stopped when this drops: also before the [`Pty`] exists, on a failed start.
#[derive(Default)]
struct Pumps {
    reader: Option<std::thread::JoinHandle<()>>,
    writer: Option<std::thread::JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
}

impl Drop for Pumps {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
    }
}

/// A program running on a PTY, ended by [`Pty::close`]. Rust cannot make a value be consumed, so
/// a `Pty` dropped unclosed (by a panic) still stops its pumps and hangs its program up.
pub struct Pty {
    master: fuxix::pty::Master,
    /// Keystrokes and query replies share this queue, so they stay in order.
    writer_tx: Sender<InputChunk>,
    write_budget: Arc<AtomicUsize>,
    /// The program, until reaped.
    running: Option<Running>,
    reaper: Reaper,
    pumps: Pumps,
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
        reaper: &Reaper,
    ) -> Result<(Self, mpsc::Receiver<Vec<u8>>), PtyError> {
        let size = pty_size(rows, cols).map_err(PtyError::OpenPty)?;
        // fuxix serializes the allocation itself and works around macOS's PTY races.
        let (master, slave) =
            fuxix::pty::open(size).map_err(|e| PtyError::OpenPty(io::Error::other(e)))?;

        // Read the master before the child exists: macOS discards what a short-lived child wrote
        // if it exits before anything reads (about 3 spawns in 1000 under load).
        let reader = master.as_fd().try_clone_to_owned()?;
        let writer = master.as_fd().try_clone_to_owned()?;
        // fuxix opens the master nonblocking; both pumps wait in `poll`.
        let mut pumps = Pumps::default();
        let stopping = Arc::clone(&pumps.stopping);

        let (tx, rx) = mpsc::channel::<Vec<u8>>(OUTPUT_CHANNEL_DEPTH);
        pumps.reader = Some(
            std::thread::Builder::new()
                .name("koh-pty-reader".into())
                .spawn(move || {
                    // Each read lands in the buffer that is sent on, so a chunk is never copied.
                    let mut buf = vec![0u8; READ_CHUNK];
                    while !stopping.load(Ordering::SeqCst) {
                        let mut waiting = [PollFd::new(&reader, Events::IN)];
                        match fuxix::poll::poll(&mut waiting, Some(WRITE_POLL_INTERVAL)) {
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
                                loop {
                                    if stopping.load(Ordering::SeqCst) {
                                        return;
                                    }
                                    match tx.try_send(chunk) {
                                        Ok(()) => break,
                                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                                        Err(mpsc::error::TrySendError::Full(pending)) => {
                                            chunk = pending;
                                            std::thread::sleep(Duration::from_millis(10));
                                        }
                                    }
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
                })?,
        );

        let (writer_tx, writer_rx) = channel::<InputChunk>();
        let write_budget = Arc::new(AtomicUsize::new(0));
        pumps.writer = Some({
            let stopping = Arc::clone(&pumps.stopping);
            std::thread::Builder::new()
                .name("koh-pty-writer".into())
                .spawn(move || {
                    while let Ok(chunk) = writer_rx.recv() {
                        if !write_while_running(&writer, &chunk.bytes, &stopping) {
                            break; // master closed, child gone, or teardown
                        }
                    }
                })?
        });

        let argv = build_command(command, || resolve_shell(std::env::var_os("SHELL")));
        let (child, pid) = slave
            .spawn(
                &launcher.program().map_err(PtyError::Spawn)?,
                &argv,
                |cmd| {
                    cmd.env("TERM", term);
                    scrub_koh_env(cmd, std::env::vars_os().map(|(key, _)| key));
                },
            )
            .map_err(|error| {
                let program = argv
                    .first()
                    .map(|arg| arg.to_string_lossy())
                    .unwrap_or_default();
                PtyError::Spawn(io::Error::new(
                    error.kind(),
                    format!("starting {program}: {error}"),
                ))
            })?;
        Ok((
            Self {
                master,
                writer_tx,
                write_budget,
                running: Some(Running { child, pid }),
                reaper: reaper.clone(),
                pumps,
            },
            rx,
        ))
    }

    /// End it: hang the program up, leaving it to the reaper, and join the pumps. Blocks while they
    /// notice, so call it on a blocking worker.
    pub fn close(mut self) {
        if let Some(running) = self.running.take() {
            running.hang_up(&self.reaper);
        }
        let pumps = [self.pumps.writer.take(), self.pumps.reader.take()];
        drop(self);
        for handle in pumps.into_iter().flatten() {
            let _ = handle.join();
        }
    }

    /// Queue `bytes` for the program, without blocking; on backpressure or closure, they come
    /// back unchanged.
    pub fn write(&self, bytes: Vec<u8>) -> Result<(), WriteError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if !reserve_input(&self.write_budget, bytes.len()) {
            return Err(WriteError::Full(bytes));
        }
        self.writer_tx
            .send(InputChunk {
                charge: bytes.len().max(64),
                bytes,
                budget: Arc::clone(&self.write_budget),
            })
            .map_err(|error| {
                let mut chunk = error.0;
                WriteError::Closed(std::mem::take(&mut chunk.bytes))
            })
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

    /// Propagate a window-size change to `rows`×`cols`; the kernel raises `SIGWINCH` in the child.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError> {
        let size = pty_size(rows, cols).map_err(PtyError::Resize)?;
        fuxix::terminal::set_window_size(&self.master, size).map_err(|e| PtyError::Resize(e.into()))
    }

    /// How the program ended, if it has; it is then reaped, and never signalled again.
    pub fn try_wait(&mut self) -> io::Result<Option<Exit>> {
        let Some(running) = &mut self.running else {
            return Ok(None);
        };
        let exit = running.try_wait()?;
        if exit.is_some() {
            self.running = None;
        }
        Ok(exit)
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        // The net under `close`; the pumps stop as `pumps` drops.
        if let Some(running) = self.running.take() {
            running.hang_up(&self.reaper);
        }
    }
}

/// `rows`×`cols`, which a PTY must have nonzero.
fn pty_size(rows: u16, cols: u16) -> io::Result<fuxix::terminal::Size> {
    fuxix::terminal::Size::new(rows, cols)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "PTY size must be nonzero"))
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
        // KOH_* vars in the server's environment must not reach the spawned shell. A `Command`
        // inherits the parent env, so the scrub removes each explicitly: `get_envs` lists it as
        // removed (`None`).
        let inherited = ["KOH_SCRUB_TEST", "KOH_DNS", "PATH"].map(OsString::from);
        let mut cmd = Command::new("/bin/sh");
        scrub_koh_env(&mut cmd, inherited.into_iter());
        let removed: Vec<_> = cmd
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_owned())
            .collect();
        assert_eq!(removed, ["KOH_DNS", "KOH_SCRUB_TEST"]);
    }

    // The real-PTY / real-shell tests (spawn + stream + teardown) live in `tests/pty.rs` — a
    // dedicated integration-test binary — so they don't contend with the ~100 inline tests in
    // this crate's parallel test binary (which starved the PTY reader thread under load).
}
