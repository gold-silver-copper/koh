//! # rmosh-pty — PTY allocation, shell spawn, resize, reaping
//!
//! The server side's plumbing to the real shell. Allocates a pseudo-terminal, spawns the
//! user's login shell under it, pumps the child's output to an async channel from a dedicated
//! blocking thread (portable-pty's reader is blocking-only), forwards input bytes to the
//! child, and propagates window-size changes (which `ioctl(TIOCSWINSZ)` turns into `SIGWINCH`).

use std::io::{self, Read, Write};

use portable_pty::{
    native_pty_system, ChildKiller, CommandBuilder, ExitStatus, MasterPty, PtySize,
};
use tokio::sync::mpsc;

/// Size of each output chunk read from the PTY master.
const READ_CHUNK: usize = 8192;
/// Bound on the output channel (chunks). Backpressure here naturally slows the reader thread.
const OUTPUT_CHANNEL_DEPTH: usize = 512;

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
/// Hold the `Pty` for the life of the session: dropping the writer signals EOF to the child.
pub struct Pty {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    killer: Box<dyn ChildKiller + Send + Sync>,
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

        let mut cmd = match shell {
            Some(prog) => CommandBuilder::new(prog),
            None => CommandBuilder::new_default_prog(),
        };
        // A real terminal type so curses apps behave; the env is otherwise inherited.
        cmd.env("TERM", term);

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
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| PtyError::Reader(io::Error::other(e)))?;

        let (tx, rx) = mpsc::channel::<Vec<u8>>(OUTPUT_CHANNEL_DEPTH);
        std::thread::Builder::new()
            .name("rmosh-pty-reader".into())
            .spawn(move || {
                let mut buf = [0u8; READ_CHUNK];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break, // EOF: slave closed (EIO is mapped to 0 on unix)
                        Ok(n) => {
                            if tx.blocking_send(buf[..n].to_vec()).is_err() {
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

        Ok((
            Pty {
                master: pair.master,
                writer,
                child,
                killer,
            },
            rx,
        ))
    }

    /// Forward input bytes to the child (verbatim — this is the raw keystroke stream).
    pub fn write_input(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(data)?;
        self.writer.flush()
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

    /// Non-blocking check for child exit.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Block until the child exits, returning its status.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }

    /// A standalone killer that can be moved to another thread/task to terminate the child.
    pub fn killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
        self.killer.clone_killer()
    }

    /// Terminate the child (SIGHUP, then a hard kill if it lingers).
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.killer.kill()
    }

    /// The child's process id, if known.
    pub fn process_id(&self) -> Option<u32> {
        self.child.process_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
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

    #[tokio::test]
    async fn spawns_and_streams_output() {
        // Run a one-shot command in the PTY and confirm we receive its output + reap it.
        let (mut pty, mut rx) =
            Pty::spawn(24, 80, Some("echo"), "xterm-256color").expect("spawn echo");
        // `CommandBuilder::new("echo")` then arg is awkward here (we only take a program),
        // so instead drive a tiny shell snippet via the default shell path below if needed.
        // `echo` with no args prints just a newline; assert we get *something* and EOF.
        let mut collected = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(chunk)) => collected.extend_from_slice(&chunk),
                Ok(None) => break, // channel closed: child exited and reader finished
                Err(_) => panic!("timed out waiting for pty output"),
            }
        }
        // `echo` prints a newline (CR/LF in a pty).
        assert!(
            collected.contains(&b'\n'),
            "expected a newline from echo, got {collected:?}"
        );
        // Child should be reapable.
        let status = pty.wait().expect("wait");
        assert!(status.success() || status.exit_code() == 0);
    }

    #[tokio::test]
    async fn interactive_shell_echoes_input() {
        // Spawn the default shell, send a command, and verify the echoed output comes back.
        let (mut pty, mut rx) = Pty::spawn(24, 80, None, "xterm-256color").expect("spawn shell");
        // Give the shell a moment to start, then type a command that prints a marker.
        tokio::time::sleep(Duration::from_millis(300)).await;
        pty.write_input(b"printf RMOSH_MARKER_OK\n").expect("write");

        let mut collected = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let found = loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(chunk)) => {
                    collected.extend_from_slice(&chunk);
                    if String::from_utf8_lossy(&collected).contains("RMOSH_MARKER_OK") {
                        break true;
                    }
                }
                Ok(None) => break false,
                Err(_) => break false,
            }
        };
        // Resize should not error while the shell is live.
        let _ = pty.resize(40, 120);
        let _ = pty.kill();
        assert!(
            found,
            "did not observe the marker in shell output: {}",
            String::from_utf8_lossy(&collected)
        );
    }
}
