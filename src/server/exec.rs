//! `koh exec` on the server: a command with no terminal, run by the server user's shell, as ssh
//! runs one.
//!
//! The command line is run as `$SHELL -c LINE` (else the platform's `sh`) in the user's home,
//! with the environment a session's program gets but `TERM`, as the leader of a session of its
//! own. The client's stream goes on as its stdin; its stdout and stderr go back on a stream each,
//! as they come, then its exit status on a third. Memory is bounded by a chunk each way: a slow
//! reader on either end holds the other back through the pipes and QUIC's flow control.
//!
//! The command ends when it has exited and its output has ended, or gone quiet for [`DRAINED`]
//! (a job it left in the background holds its pipes, which ssh would wait on for ever). A lost
//! connection, revocation or the server's shutdown hangs it up: SIGHUP to its process group, and
//! SIGKILL once the reaper's grace is over.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::pin::pin;
use std::process::Stdio;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;

use super::cli::Host;
use crate::proto::Close;
use crate::pty::{Home, Reaper, Running};
use crate::request::{CommandLine, ExecStream, ExitStatus, MAX_REPLY};
use crate::transport_iroh::close;

/// Most bytes moved at once, each way.
const CHUNK: usize = 64 * 1024;

/// How long output must be quiet, after the command exited, for its pipes to count as drained:
/// what it wrote is already in them, so it is read long before this.
const DRAINED: Duration = Duration::from_millis(100);

/// How often the command's exit is looked for while it writes, and once its output has ended.
const EXIT_POLL: Duration = Duration::from_millis(50);
const EXIT_POLL_ENDED: Duration = Duration::from_millis(5);

/// The command while it runs: hung up when dropped, unless it was reaped.
struct Command {
    running: Option<Running>,
    reaper: Reaper,
}

impl Command {
    /// Its exit status, if it has exited: reaped then.
    fn exit(&mut self) -> Option<u32> {
        let exit = self.running.as_mut()?.try_wait();
        match exit {
            Ok(Some(exit)) => {
                self.running = None;
                Some(exit.code())
            }
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(%error, "waiting for a command failed");
                None
            }
        }
    }
}

impl Drop for Command {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            running.hang_up(&self.reaper);
        }
    }
}

/// The command and its stdin, stdout and stderr.
type Spawned = (
    Command,
    tokio::process::ChildStdin,
    tokio::process::ChildStdout,
    tokio::process::ChildStderr,
);

/// Start `line` in `home`'s shell, left to `reaper` if it is hung up.
fn spawn(line: &CommandLine, home: &Home, reaper: &Reaper) -> std::io::Result<Spawned> {
    #[expect(
        clippy::disallowed_methods,
        reason = "the server user's shell, running what an allowed client asked, as its shell \
                  sessions do"
    )]
    let mut cmd = std::process::Command::new(home.shell());
    cmd.arg("-c")
        .arg(OsStr::from_bytes(line.as_bytes()))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("TERM");
    crate::pty::scrub_koh_env(&mut cmd, std::env::vars_os().map(|(key, _)| key));
    home.apply(&mut cmd);
    if let Some(dir) = home.dir() {
        cmd.current_dir(dir);
    }
    fuxix::process::lead_session(&mut cmd, false);
    let mut child = cmd.spawn()?;
    let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let command = Command {
        running: Running::group(child),
        reaper: reaper.clone(),
    };
    let (Some(stdin), Some(stdout), Some(stderr)) = pipes else {
        return Err(std::io::Error::other("the command's pipes are missing"));
    };
    Ok((
        command,
        tokio::process::ChildStdin::from_std(stdin)?,
        tokio::process::ChildStdout::from_std(stdout)?,
        tokio::process::ChildStderr::from_std(stderr)?,
    ))
}

/// Run `line` for the client on `conn`, `stdin` its stdin, until it ends and the client has its
/// status, or the connection is lost, which hangs it up.
pub(super) async fn serve(conn: &Connection, stdin: RecvStream, line: CommandLine, host: &Host) {
    let (mut command, child_in, child_out, child_err) = match spawn(&line, &host.home, &host.reaper)
    {
        Ok(spawned) => spawned,
        Err(error) => {
            tracing::warn!(%error, "could not start a command");
            close(conn, Close::CouldNotStart);
            return;
        }
    };
    let (Ok(out), Ok(err)) = (
        open(conn, ExecStream::Stdout).await,
        open(conn, ExecStream::Stderr).await,
    ) else {
        return;
    };
    let (exited_tx, exited) = watch::channel(false);
    let mut stdout = pin!(pump(child_out, out, exited.clone()));
    let mut stderr = pin!(pump(child_err, err, exited));
    let mut feeding = pin!(feed(stdin, child_in));
    let (mut out_done, mut err_done, mut fed) = (false, false, false);
    let mut status = None;
    let code = loop {
        if let Some(code) = status.filter(|_| out_done && err_done) {
            break code;
        }
        let poll = if out_done && err_done {
            EXIT_POLL_ENDED
        } else {
            EXIT_POLL
        };
        tokio::select! {
            () = &mut stdout, if !out_done => out_done = true,
            () = &mut stderr, if !err_done => err_done = true,
            () = &mut feeding, if !fed => fed = true,
            () = tokio::time::sleep(poll), if status.is_none() => {
                status = command.exit();
                if status.is_some() {
                    exited_tx.send_replace(true);
                }
            }
            // Dropped, the command is hung up.
            _ = conn.closed() => return,
            () = host.shutdown.cancelled() => return,
        }
    };
    let told = async {
        let mut send = open(conn, ExecStream::Status).await?;
        let status = crate::request::encode(&ExitStatus(code), MAX_REPLY)?;
        send.write_all(&status).await?;
        send.finish()?;
        anyhow::Ok(())
    };
    if told.await.is_ok() {
        super::linger(conn).await;
    }
}

/// A stream for the client, carrying `what`.
async fn open(conn: &Connection, what: ExecStream) -> anyhow::Result<SendStream> {
    let mut send = conn.open_uni().await?;
    send.write_all(&[what.tag()]).await?;
    Ok(send)
}

/// Send what the command writes on `from` to `to` until it ends, or, once `exited`, goes quiet for
/// [`DRAINED`]; then finish `to`.
async fn pump(
    mut from: impl AsyncRead + Unpin,
    mut to: SendStream,
    mut exited: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let read = if *exited.borrow_and_update() {
            match tokio::time::timeout(DRAINED, from.read(&mut buf)).await {
                Ok(read) => read,
                Err(_quiet) => break,
            }
        } else {
            tokio::select! {
                read = from.read(&mut buf) => read,
                _ = exited.changed() => continue,
            }
        };
        let n = match read {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if to
            .write_all(buf.get(..n).unwrap_or_default())
            .await
            .is_err()
        {
            return;
        }
    }
    let _ = to.finish();
}

/// Hand what the client sends on `from` to the command's stdin until either ends: the command
/// then reads its end, or the client's writes are stopped.
async fn feed(mut from: RecvStream, mut to: tokio::process::ChildStdin) {
    while let Ok(Some(chunk)) = from.read_chunk(CHUNK).await {
        if to.write_all(&chunk).await.is_err() {
            let _ = from.stop(0u32.into());
            return;
        }
    }
}
