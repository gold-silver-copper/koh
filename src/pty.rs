//! PTYs: start the session's program on one, pump its output and input, resize it, reap it.
//!
//! The program leads a session of its own with the PTY as its controlling terminal (fuxix sets
//! that up between `fork` and `exec`). Its output and input go on two threads of their own, so a
//! slow program never blocks a tokio worker.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
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
fn build_command(command: &[String], fallback: impl FnOnce() -> String) -> Vec<String> {
    if command.is_empty() {
        vec![fallback()]
    } else {
        command.to_vec()
    }
}

/// The argv a session runs for `command`: it, or `$SHELL` (else the platform's shell) if empty.
pub fn session_argv(command: &[String]) -> Vec<String> {
    build_command(command, || resolve_shell(std::env::var_os("SHELL")))
}

/// Remove each `KOH_*` variable of the `inherited` from `cmd`: they configure koh, not the hosted
/// program, and matching the prefix cannot miss one added later.
pub(crate) fn scrub_koh_env(cmd: &mut Command, inherited: impl Iterator<Item = OsString>) {
    for key in inherited.filter(|key| is_koh_env_key(key)) {
        cmd.env_remove(key);
    }
}

/// Whether `key` is one of koh's own variables, scrubbed from every child koh spawns.
pub(crate) fn is_koh_env_key(key: &std::ffi::OsStr) -> bool {
    key.to_string_lossy().starts_with("KOH_")
}

/// The platform's shell: `/bin/sh`, which does **not** exist on Android, where it is
/// `/system/bin/sh`.
const PLATFORM_SHELL: &str = if cfg!(target_os = "android") {
    "/system/bin/sh"
} else {
    "/bin/sh"
};

/// The session shell when the caller didn't pass `--shell`: `shell_env` (`$SHELL`) if set, else
/// [`PLATFORM_SHELL`].
fn resolve_shell(shell_env: Option<std::ffi::OsString>) -> String {
    shell_env.filter(|sh| !sh.is_empty()).map_or_else(
        || PLATFORM_SHELL.to_owned(),
        |sh| sh.to_string_lossy().into_owned(),
    )
}

/// What failed in a PTY: allocation, the spawn, the pump threads, or a resize.
#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    /// Allocating the pseudo-terminal pair failed.
    #[error("opening pty: {0}")]
    OpenPty(#[source] io::Error),
    /// Starting the program on the slave side failed.
    #[error("spawning shell: {0}")]
    Spawn(#[source] io::Error),
    /// Cloning the master or starting a pump thread failed.
    #[error("starting pty reader: {0}")]
    Reader(#[from] io::Error),
    /// Propagating a window-size change to the kernel (`TIOCSWINSZ`) failed.
    #[error("resizing pty: {0}")]
    Resize(#[source] io::Error),
}

/// The home a session's program gets: the user's, or for tests one of their own
/// ([`isolated`](Self::isolated)), so a shell a test hosts never reads or writes the user's files.
#[derive(Clone, Debug, Default)]
pub struct Home(Option<PathBuf>);

impl Home {
    /// The user's: the program inherits the server's environment.
    pub const fn user() -> Self {
        Self(None)
    }

    /// `home`, with no history file, no `ENV` script, a plain prompt and the platform's shell.
    pub fn isolated(home: impl Into<PathBuf>) -> Self {
        Self(Some(home.into()))
    }

    /// The directory: an isolated one, else `$HOME`, if set.
    pub(crate) fn dir(&self) -> Option<PathBuf> {
        self.0.clone().or_else(|| {
            std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from)
        })
    }

    /// The shell a command `koh exec` asks for runs in: `$SHELL`, else the platform's; an isolated
    /// home's is the platform's, whatever the user's is.
    pub(crate) fn shell(&self) -> String {
        match self.0 {
            Some(_) => PLATFORM_SHELL.to_owned(),
            None => resolve_shell(std::env::var_os("SHELL")),
        }
    }

    /// Where a server run keeps the startup files that mark its shells' commands: an isolated
    /// home's own directory; else `$XDG_RUNTIME_DIR`, else the system's temporary directory.
    pub(crate) fn runtime_dir(&self) -> PathBuf {
        if let Some(home) = &self.0 {
            return home.clone();
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "a server's runtime files, in a private directory of its own, if there is no XDG_RUNTIME_DIR"
        )]
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
            .unwrap_or_else(std::env::temp_dir)
    }

    /// Give `cmd` this home, unless it is the user's.
    pub(crate) fn apply(&self, cmd: &mut Command) {
        if let Some(home) = &self.0 {
            cmd.env("HOME", home)
                .env("HISTFILE", "/dev/null")
                .env("ENV", "")
                .env("PS1", "$ ");
        }
    }
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

/// A program koh started, until it is reaped: owning it is the right to signal its pid, which is
/// no longer its own once reaped.
pub(crate) struct Running {
    child: std::process::Child,
    pid: Pid,
    whom: Whom,
}

/// Who a hang-up reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Whom {
    /// The program alone: a PTY's session leader, whose terminal closing hangs up the rest.
    Leader,
    /// Its whole process group: a program with no terminal (`koh exec`'s), which leads a session
    /// of its own, so its group is its pid.
    Group,
}

impl Running {
    /// `child`, which leads a session of its own (`fuxix::process::lead_session`) and has no
    /// terminal: a hang-up reaches its whole group. `None` if it has no pid to signal.
    pub(crate) fn group(child: std::process::Child) -> Option<Self> {
        let pid = Pid::of(&child)?;
        Some(Self {
            child,
            pid,
            whom: Whom::Group,
        })
    }

    fn signal(&self, signal: Signal) -> io::Result<()> {
        match self.whom {
            Whom::Leader => fuxix::process::kill(self.pid, signal),
            Whom::Group => fuxix::process::kill_group(self.pid, signal),
        }
        .map_err(io::Error::from)
    }

    /// Send `signal` to what it reaches: its group, for a command with no terminal.
    pub(crate) fn kill(&self, signal: Signal) {
        if let Err(error) = self.signal(signal) {
            tracing::debug!(%error, "signalling a command failed");
        }
    }

    /// How it ended, if it has; reaped then.
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<Exit>> {
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
    /// outlives [`HANGUP_GRACE`] (a group, whatever of it is left then).
    pub(crate) fn hang_up(self, reaper: &Reaper) {
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
        // A group's leader is reaped only once the group is killed: until then its pid, even a
        // zombie's, holds the group's id, so the kill cannot reach another group.
        if self.running.whom == Whom::Group && self.kill_at.is_some() {
            return false;
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
                use std::sync::mpsc::RecvTimeoutError::{Disconnected, Timeout};
                const POLL: Duration = Duration::from_millis(20);
                let mut children: Vec<Stopping> = Vec::new();
                let mut drains: Vec<Sender<()>> = Vec::new();
                loop {
                    let received = if children.is_empty() {
                        rx.recv().map_err(|_closed| Disconnected)
                    } else {
                        rx.recv_timeout(POLL)
                    };
                    match received {
                        Ok(Reap::Child(child)) => children.push(child),
                        Ok(Reap::Drain(done)) => drains.push(done),
                        Err(Timeout) => {}
                        Err(Disconnected) if children.is_empty() => return,
                        Err(Disconnected) => std::thread::sleep(POLL),
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
    /// process exits, which would leave one that ignores SIGHUP running. Blocks for at most twice
    /// [`HANGUP_GRACE`], so call it on a blocking worker.
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
    /// Allocate a `rows`×`cols` PTY and start `command` (argv, verbatim; empty for `$SHELL`)
    /// on it in `home` (in `cwd`, if given), with `TERM` and `env` set. Returns it and a receiver
    /// of its output, which ends when the program closes the PTY.
    pub fn spawn(
        rows: u16,
        cols: u16,
        command: &[String],
        env: &[(String, String)],
        (term, home, cwd): (&str, &Home, Option<&Path>),
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

        let argv = session_argv(command);
        let (child, pid) = slave
            .spawn(&argv, |cmd| {
                cmd.env("TERM", term);
                scrub_koh_env(cmd, std::env::vars_os().map(|(key, _)| key));
                home.apply(cmd);
                if let Some(cwd) = cwd {
                    cmd.current_dir(cwd);
                }
                cmd.envs(env.iter().map(|(key, value)| (key, value)));
            })
            .map_err(|error| {
                let program = argv.first().map_or("", String::as_str);
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
                running: Some(Running {
                    child,
                    pid,
                    whom: Whom::Leader,
                }),
                reaper: reaper.clone(),
                pumps,
            },
            rx,
        ))
    }

    /// End it: hang the program up, leaving it to the reaper (as dropping it does), and join the
    /// pumps. Blocks while they notice, so call it on a blocking worker.
    pub fn close(mut self) {
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
        let modes = fuxix::terminal::attributes(&self.master).ok()?.modes();
        Some(crate::terminal::TtyModes {
            echo: modes.echo,
            line: modes.canonical,
        })
    }

    /// What the program in the PTY's foreground is doing, as fux decides it: `since_key` since
    /// input was last written to it (`Duration::MAX` if never), `answered` if the screen changed
    /// after that input, and `prompt` if the shell's marks say it is back at its prompt.
    pub fn activity(
        &self,
        since_key: Duration,
        answered: bool,
        prompt: bool,
    ) -> crate::terminal::Activity {
        let Some(leader) = self.running.as_ref().map(|running| running.pid) else {
            return crate::terminal::Activity::Unknown;
        };
        // Keys it has yet to read (on a busy machine, a program blocked reading is not woken at
        // once), or output no one has read yet: what it does with its input is still to come, as
        // fux's own check has it.
        if self.keys_unread() || self.output_unread() {
            return crate::terminal::Activity::Busy;
        }
        fuxix::process::terminal_activity(&self.master, leader, since_key, answered, prompt).into()
    }

    /// Whether output the program wrote waits to be read from the master, as a poll that does
    /// not wait says (`FIONREAD` misses a write the kernel has yet to move on, on Linux).
    fn output_unread(&self) -> bool {
        let mut fds = [PollFd::new(&self.master, Events::IN)];
        let polled = fuxix::poll::poll(&mut fds, Some(Duration::ZERO));
        polled.is_ok_and(|n| n > 0) && fds.iter().any(|fd| fd.revents().intersects(Events::IN))
    }

    /// Whether keys wait in the terminal for the program to read. On Linux the slave is opened to
    /// ask (with no wait, and never as a controlling terminal); on macOS the master's `FIONREAD`
    /// counts them.
    fn keys_unread(&self) -> bool {
        #[cfg(target_os = "macos")]
        let unread = fuxix::io::unread(&self.master).ok();
        #[cfg(not(target_os = "macos"))]
        let unread = {
            use rustix::fs::{Mode, OFlags};
            let flags = OFlags::RDONLY | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC;
            rustix::fs::open(self.master.slave_path(), flags, Mode::empty())
                .ok()
                .and_then(|slave| fuxix::io::unread(slave).ok())
        };
        unread.is_some_and(|n| n > 0)
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
        // Closed or not; the pumps stop as `pumps` drops.
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
    fn the_command_is_argv_verbatim_or_else_the_shell() {
        let argv = ["zellij", "attach", "-c", "my session"].map(String::from);
        assert_eq!(build_command(&argv, || "unused".to_owned()), argv);
        assert_eq!(
            build_command(&[], || "/custom/shell".to_owned()),
            ["/custom/shell"]
        );
        // An empty `$SHELL` is as if unset: the platform's shell, which on Android is not /bin/sh.
        let fish = resolve_shell(Some(OsString::from("/usr/bin/fish")));
        assert_eq!(fish, "/usr/bin/fish");
        assert_eq!(resolve_shell(Some(OsString::new())), PLATFORM_SHELL);
        assert_eq!(resolve_shell(None), PLATFORM_SHELL);
    }

    #[test]
    fn scrub_removes_inherited_koh_vars() {
        // KOH_* vars in the server's environment must not reach the spawned shell. A `Command`
        // inherits the parent env, so the scrub removes each explicitly: `get_envs` lists it as
        // removed (`None`).
        let inherited = ["KOH_SCRUB_TEST", "KOH_DNS", "PATH"].map(OsString::from);
        #[expect(
            clippy::disallowed_methods,
            reason = "built to read its environment, never run"
        )]
        let mut cmd = Command::new("/bin/sh");
        scrub_koh_env(&mut cmd, inherited.into_iter());
        let removed: Vec<_> = cmd
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_owned())
            .collect();
        assert_eq!(removed, ["KOH_DNS", "KOH_SCRUB_TEST"]);
    }
}
