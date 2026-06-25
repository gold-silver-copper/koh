//! # koh-pty — PTY allocation, shell spawn, resize, reaping
//!
//! The server side's plumbing to the real shell. Allocates a pseudo-terminal, spawns the
//! user's login shell under it, pumps the child's output to an async channel from a dedicated
//! blocking thread (portable-pty's reader is blocking-only), forwards input bytes to the
//! child via a second dedicated thread (so a slow child never blocks a tokio worker), and
//! propagates window-size changes (which `ioctl(TIOCSWINSZ)` turns into `SIGWINCH`).

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};

use portable_pty::{
    native_pty_system, ChildKiller, CommandBuilder, ExitStatus, MasterPty, PtySize,
};
use tokio::sync::mpsc;

/// Size of each output chunk read from the PTY master.
const READ_CHUNK: usize = 8192;
/// Bound on the output channel (chunks). Backpressure here naturally slows the reader thread.
const OUTPUT_CHANNEL_DEPTH: usize = 512;
/// Bound on the input channel (chunks) feeding the writer thread. Generous, because under normal
/// interactive use the child drains its input promptly; a full queue means the child has stopped
/// reading (flow-controlled or hung), which [`Pty::write_input`] surfaces rather than blocking on.
const WRITE_CHANNEL_DEPTH: usize = 1024;

/// Resolve the session shell when the caller didn't pass `--shell`. Prefers `$SHELL`; otherwise a
/// platform default. portable-pty's `new_default_prog` falls back to `/bin/sh`, which does **not**
/// exist on Android (it's `/system/bin/sh`) — so a `koh serve` with no `--shell` would fail to spawn
/// a session there (and the Bevy Android app, which has no `$SHELL`, would hit the same). The logic
/// lives in the pure [`resolve_shell`] so it is unit-testable without touching the process env.
fn default_shell() -> String {
    resolve_shell(std::env::var_os("SHELL"))
}

/// Remove koh's operational env vars — notably the `$KOH_KEY_PASSPHRASE` identity-key secret — from
/// a command's environment before it spawns the session shell (L-4 / KOH-15). `CommandBuilder::new`
/// seeds the full parent environment, so we strip *every* inherited `KOH_*` key by prefix (rather
/// than a hand-maintained list that silently misses future vars). Pulled out of [`Pty::spawn`] so
/// it is unit-testable without allocating a real PTY.
fn scrub_koh_env(cmd: &mut CommandBuilder) {
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("KOH_") {
            cmd.env_remove(&key);
        }
    }
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
/// `portable-pty` surfaces its failures as `anyhow::Error`; we fold those into `io::Error`
/// (via [`io::Error::other`]) so every variant carries one concrete payload. Only the reader
/// thread's `Builder::spawn` is natively an `io::Error`, so it is the single `#[from]` source.
/// Binaries keep `anyhow` internally — their `?`/`.context()` absorb `PtyError` via anyhow's
/// blanket `From<E: Error + Send + Sync>`.
#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    /// Allocating the pseudo-terminal pair (`openpty`) failed.
    #[error("opening pty: {0}")]
    OpenPty(#[source] io::Error),
    /// Spawning the shell under the slave side (`spawn_command`) failed.
    #[error("spawning shell: {0}")]
    Spawn(#[source] io::Error),
    /// Wiring up the master read/write pumps failed: cloning the reader, taking the writer, or
    /// starting the blocking reader thread (`Builder::spawn`, the native `io::Error` source).
    #[error("starting pty reader: {0}")]
    Reader(#[from] io::Error),
    /// Propagating a window-size change to the kernel (`master.resize`) failed.
    #[error("resizing pty: {0}")]
    Resize(#[source] io::Error),
}

/// A running shell behind a PTY.
///
/// Construct with [`Pty::spawn`], which also returns the receiver of the child's output.
/// Hold the `Pty` for the life of the session: dropping it drops `writer_tx`, which lets the
/// writer thread finish and drop the PTY's write handle — and `portable-pty` writes an EOT
/// (Ctrl-D) on that drop, so the child sees EOF on its stdin.
pub struct Pty {
    master: Box<dyn MasterPty + Send>,
    /// Bounded sender to the dedicated writer thread (which owns the blocking `Box<dyn Write>`).
    /// Shared by both input producers (keystrokes + host query replies), so writes stay FIFO.
    writer_tx: SyncSender<Vec<u8>>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    /// Set once we have *reaped* the child (a `try_wait`/`wait` returned `Some`). After a reap the
    /// kernel may recycle the PID, so signaling the stored PID could hit an unrelated process —
    /// every kill path checks this and skips when set (KR-02). An un-reaped exited child is still a
    /// zombie that reserves its PID, so signaling *that* is harmless; only a reaped PID is unsafe.
    reaped: AtomicBool,
    /// Join handles for the reader/writer pump threads, kept so a graceful [`Pty::shutdown`] can
    /// join them rather than leaking detached threads. `None` only after `shutdown` takes them.
    reader_handle: Option<std::thread::JoinHandle<()>>,
    writer_handle: Option<std::thread::JoinHandle<()>>,
}

impl Pty {
    /// Allocate a PTY of `rows`×`cols`, spawn `shell` (or the user's default login shell when
    /// `None`) with `TERM` set, and start streaming its output.
    ///
    /// Returns the [`Pty`] handle plus an async receiver of raw output chunks. The reader runs
    /// on a dedicated OS thread; when the child closes the PTY the channel ends.
    pub fn spawn(
        rows: u16,
        cols: u16,
        shell: Option<&str>,
        term: &str,
    ) -> Result<(Self, mpsc::Receiver<Vec<u8>>), PtyError> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::OpenPty(io::Error::other(e)))?;

        let cmd_shell = shell.map_or_else(default_shell, str::to_owned);
        let mut cmd = CommandBuilder::new(cmd_shell);
        // A real terminal type so curses apps behave; the env is otherwise inherited.
        cmd.env("TERM", term);
        // Scrub koh's operational env from the child (L-4). Most important: `$KOH_KEY_PASSPHRASE` —
        // the identity-key secret — must NOT reach the spawned shell, or any authorized user could
        // `echo $KOH_KEY_PASSPHRASE` to recover it.
        scrub_koh_env(&mut cmd);

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| PtyError::Spawn(io::Error::other(e)))?;
        let killer = child.clone_killer();
        // The slave fd is now owned by the child; drop our handle so EOF propagates correctly.
        drop(pair.slave);

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| PtyError::Reader(io::Error::other(e)))?;
        let mut writer = pair
            .master
            .take_writer()
            .map_err(|e| PtyError::Reader(io::Error::other(e)))?;

        let (tx, rx) = mpsc::channel::<Vec<u8>>(OUTPUT_CHANNEL_DEPTH);
        let reader_handle = std::thread::Builder::new()
            .name("koh-pty-reader".into())
            .spawn(move || {
                let mut buf = [0u8; READ_CHUNK];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break, // EOF: slave closed (EIO is mapped to 0 on unix)
                        // `Read::read` guarantees `n <= buf.len()`, so `get(..n)` is always
                        // `Some`; the `else` is a panic-free fallback that can't actually run.
                        Ok(n) => {
                            let Some(chunk) = buf.get(..n) else { break };
                            if tx.blocking_send(chunk.to_vec()).is_err() {
                                break; // receiver dropped: session over
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "pty reader stopping");
                            break;
                        }
                    }
                }
            })?;

        // Dedicated writer thread: it owns the blocking `Box<dyn Write>` and drains the bounded
        // input channel, so `write_input` never blocks a tokio worker. `recv()` yields every
        // buffered chunk before it observes the senders being dropped, so pending writes flush
        // before the writer is dropped (and `portable-pty` then writes the EOT that EOFs the
        // child). The thread exits as soon as the last sender (held in `Pty`) drops.
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
                // `writer` drops here -> portable-pty sends EOT -> child sees EOF on stdin.
            })?;

        Ok((
            Self {
                master: pair.master,
                writer_tx,
                child,
                killer,
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
        // once the child is reaped: it is already dead (reader saw EOF) and its PID may be recycled
        // (KR-02). The `drop(self)` below still runs `Drop`, which is likewise reaped-gated.
        if !self.reaped.load(Ordering::SeqCst) {
            if let Err(e) = self.killer.kill() {
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
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::Resize(io::Error::other(e)))
    }

    /// Non-blocking check for child exit. On a `Some` result the child has been reaped, so the PID
    /// may now be recycled — the kill paths must not signal it afterward (KR-02).
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let r = self.child.try_wait();
        if matches!(r, Ok(Some(_))) {
            self.reaped.store(true, Ordering::SeqCst);
        }
        r
    }

    /// Terminate the child (SIGHUP via the portable-pty killer). No-op once the child is reaped, so
    /// we never SIGHUP a recycled PID (KR-02).
    pub fn kill(&mut self) -> std::io::Result<()> {
        if self.reaped.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.killer.kill()
    }

    /// Force-kill the child with SIGKILL (which cannot be trapped). portable-pty's cloned killer
    /// only sends SIGHUP, so a child that ignores SIGHUP (e.g. `trap '' HUP`) would otherwise keep
    /// the PTY slave fd open and wedge the reader thread on a blocking `read()` forever — leaking a
    /// thread + fds per session and defeating the reaper (KOH-10).
    ///
    /// Skips signaling once the child has been **reaped**: `process_id()` keeps returning the
    /// original PID after reaping, but the kernel may have recycled it, so SIGKILL could hit an
    /// unrelated same-uid process (KR-02). A reaped child is already dead (its fds closed, so the
    /// reader already saw EOF), so there is nothing to kill; an un-reaped zombie still reserves its
    /// PID, so the SIGKILL below targets only a PID we still own. Off-unix this is a no-op.
    pub fn kill_hard(&self) {
        if self.reaped.load(Ordering::SeqCst) {
            return;
        }
        #[cfg(unix)]
        if let Some(pid) = self.process_id() {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;
            if let Ok(pid) = i32::try_from(pid) {
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
        }
    }

    /// The child's process id, if known.
    fn process_id(&self) -> Option<u32> {
        self.child.process_id()
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        // A `Pty` dropped without an explicit [`Pty::shutdown`] (e.g. the Err path in
        // `session::teardown`, or any future caller) must still guarantee the child dies, so the
        // detached reader thread can't block forever on a still-open slave fd (KOH-10). SIGHUP
        // first (a well-behaved shell exits cleanly), then SIGKILL so a SIGHUP-immune child also
        // dies → the reader hits EOF and the pump threads exit. `writer_tx` drops with the struct,
        // EOFing the child's stdin. We deliberately do NOT join the threads here (that could block
        // the dropping thread, possibly a tokio worker); SIGKILL makes them exit promptly on their
        // own, and `shutdown` remains the path that joins.
        //
        // Skip signaling once the child is reaped (KR-02): a reaped child is already dead and its
        // PID may have been recycled, so SIGHUP/SIGKILL here could hit an unrelated process.
        if self.reaped.load(Ordering::SeqCst) {
            return;
        }
        let _ = self.killer.kill();
        self.kill_hard();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn scrub_removes_koh_key_passphrase_even_when_inherited() {
        // L-4: even when the parent process has $KOH_KEY_PASSPHRASE set, the spawned shell's env
        // must not — otherwise any authorized user could `echo $KOH_KEY_PASSPHRASE`. CommandBuilder
        // ::new seeds the full parent env, so this proves env_remove strips an *inherited* secret.
        std::env::set_var("KOH_KEY_PASSPHRASE", "topsecret-unit");
        std::env::set_var("KOH_DNS", "1.1.1.1");
        let mut cmd = CommandBuilder::new("/bin/sh");
        assert!(
            cmd.get_env("KOH_KEY_PASSPHRASE").is_some(),
            "the builder seeds the parent env, so the var is present before scrubbing"
        );
        scrub_koh_env(&mut cmd);
        assert!(
            cmd.get_env("KOH_KEY_PASSPHRASE").is_none(),
            "the identity-key passphrase must be scrubbed from the child env"
        );
        assert!(
            cmd.get_env("KOH_DNS").is_none(),
            "operational KOH_* vars are scrubbed too"
        );
        std::env::remove_var("KOH_KEY_PASSPHRASE");
        std::env::remove_var("KOH_DNS");
    }

    #[test]
    #[allow(
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
        // The public spawn signature now carries the typed error.
        fn _assert_typed(r: Result<(), PtyError>) -> Result<(), PtyError> {
            r
        }
    }

    // The real-PTY / real-shell tests (spawn + stream + teardown) live in `tests/pty.rs` — a
    // dedicated integration-test binary — so they don't contend with the ~100 inline tests in
    // this crate's parallel test binary (which starved the PTY reader thread under load).
}
