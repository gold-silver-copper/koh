//! `koh exec` on the server: a command with no terminal, for as long as its connection lasts.
//!
//! Its words are run as they are, the first found on the server's `PATH` (`~/x` in the server
//! user's home), or a shell line is run by the user's shell (`$SHELL -c`, else the platform's
//! `sh`); it starts in their home, or the directory asked, with the environment a session's
//! program gets but `TERM`, as the leader of a session of its own. The client's stream goes on as
//! its stdin; its stdout and stderr go back on a stream each, as they come, then its exit status
//! on a third. Memory is bounded by a chunk each way: a slow reader on either end holds the other
//! back through the pipes and QUIC's flow control.
//!
//! The command ends when it has exited and its output has ended, or gone quiet for [`DRAINED`]
//! (a job it left in the background holds its pipes, which ssh would wait on for ever). A lost
//! connection (the client's own idle timeout is 10 s, so a killed client is found within it),
//! revocation or the server's shutdown hangs it up: SIGHUP to its process group, and SIGKILL once
//! the reaper's grace is over.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::pin::pin;
use std::process::Stdio;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;

use super::cli::Host;
use super::place::Place;
use crate::pty::{Reaper, Running};
use crate::request::{Command, ExecStream, ExitStatus, Problem, ProblemKind, Run, MAX_REPLY};

/// Most bytes moved at once, each way.
const CHUNK: usize = 64 * 1024;

/// How long output must be quiet, after the command exited, for its pipes to count as drained:
/// what it wrote is already in them, so it is read long before this.
const DRAINED: Duration = Duration::from_millis(100);

/// How often the command's exit is looked for while it writes, and once its output has ended.
const EXIT_POLL: Duration = Duration::from_millis(50);
const EXIT_POLL_ENDED: Duration = Duration::from_millis(5);

/// A command while it runs: hung up when dropped, unless it was reaped.
pub(super) struct Process {
    running: Option<Running>,
    reaper: Reaper,
}

impl Process {
    /// Its exit status, if it has exited: reaped then.
    pub(super) fn exit(&mut self) -> Option<u32> {
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

    /// The session it leads, unless it was reaped.
    pub(super) fn session(&self) -> Option<fuxix::process::Pid> {
        self.running.as_ref().map(Running::pid)
    }

    /// Send its process group `signal`, unless it was reaped.
    pub(super) fn signal(&self, signal: fuxix::process::Signal) {
        if let Some(running) = &self.running {
            running.kill(signal);
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(running) = self.running.take() {
            running.hang_up(&self.reaper);
        }
    }
}

/// The read end of a command's stdout or stderr.
pub(super) type Output = tokio::net::unix::pipe::Receiver;

/// A command started, and the pipes asked for: its stdin, its stdout, and its stderr unless it
/// writes that to its stdout's pipe.
pub(super) type Spawned = (
    Process,
    Option<tokio::process::ChildStdin>,
    Output,
    Option<Output>,
);

/// Start `run` at `place`, left to `reaper` if it is hung up, stdin piped if `stdin` (else
/// `/dev/null`), its stderr into its stdout's pipe if `together`, which keeps the order it wrote
/// them in; why not, said as the client shows it.
pub(super) fn spawn(
    run: &Run,
    host: &Host,
    place: &Place,
    (stdin, together): (bool, bool),
) -> Result<Spawned, Problem> {
    let home = &host.home;
    let cwd = place.cwd(run.cwd.as_ref())?;
    #[expect(
        clippy::disallowed_methods,
        reason = "what an allowed client asked the server user to run, as its shell sessions do"
    )]
    let mut cmd = match &run.command {
        Command::Shell(line) => {
            let mut cmd = std::process::Command::new(home.shell());
            cmd.arg("-c").arg(OsStr::from_bytes(line.as_bytes()));
            cmd
        }
        Command::Argv(argv) => {
            let none = Vec::new();
            let (program, args) = argv.words().split_first().unwrap_or((&none, &[]));
            // `~/x` is in the server user's home: no shell expands it here.
            let program = match (program.strip_prefix(b"~/"), home.dir()) {
                (Some(rest), Some(dir)) => dir.join(OsStr::from_bytes(rest)).into_os_string(),
                _ => OsStr::from_bytes(program).to_os_string(),
            };
            let mut cmd = std::process::Command::new(program);
            cmd.args(args.iter().map(|a| OsStr::from_bytes(a)));
            cmd
        }
    };
    let io = |e: std::io::Error| Problem::new(ProblemKind::CouldNotStart, e);
    let (out, out_end) = std::io::pipe().map_err(io)?;
    let err = if together {
        cmd.stderr(out_end.try_clone().map_err(io)?);
        None
    } else {
        let (err, err_end) = std::io::pipe().map_err(io)?;
        cmd.stderr(err_end);
        Some(err)
    };
    cmd.stdin(if stdin { Stdio::piped() } else { Stdio::null() })
        .stdout(out_end)
        .env_remove("TERM");
    crate::pty::scrub_koh_env(&mut cmd, std::env::vars_os().map(|(key, _)| key));
    home.apply(&mut cmd);
    if let Some(dir) = &cwd {
        cmd.current_dir(dir);
    }
    fuxix::process::lead_session(&mut cmd, false);
    let spawned = cmd.spawn();
    // The pipes' write ends are the command's alone now: its end is their end.
    drop(cmd);
    let mut child = spawned.map_err(|error| not_started(run, cwd.as_deref(), &error))?;
    let child_in = child.stdin.take();
    let process = Process {
        running: Running::group(child),
        reaper: host.reaper.clone(),
    };
    let output = |end: std::io::PipeReader| Output::from_owned_fd(end.into());
    let child_in = child_in
        .map(tokio::process::ChildStdin::from_std)
        .transpose()
        .map_err(io)?;
    Ok((
        process,
        child_in,
        output(out).map_err(io)?,
        err.map(output).transpose().map_err(io)?,
    ))
}

/// Why `run` did not start, from `error`.
fn not_started(run: &Run, cwd: Option<&Path>, error: &std::io::Error) -> Problem {
    let what = match &run.command {
        Command::Argv(argv) => argv
            .words()
            .first()
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .unwrap_or_default(),
        Command::Shell(_) => "the shell".to_owned(),
    };
    let place = cwd.map_or_else(String::new, |dir| format!(" (in {})", dir.display()));
    if error.kind() == std::io::ErrorKind::NotFound {
        // No such program: the directory to start in was there.
        return Problem::new(ProblemKind::NoSuchProgram, format!("{what}{place}"));
    }
    Problem::new(
        ProblemKind::CouldNotStart,
        format!("{what}{place}: {error}"),
    )
}

/// Run `run` for the client on `conn` at `place`, `stdin` its stdin, its stderr into its stdout if
/// `together`, until it ends and the client has its status, or the connection is lost, which
/// hangs it up.
pub(super) async fn serve(
    conn: &Connection,
    stdin: RecvStream,
    (run, together): (&Run, bool),
    host: &Host,
    place: &Place,
) {
    let (Ok(out), Ok(err)) = (
        open(conn, ExecStream::Stdout).await,
        open(conn, ExecStream::Stderr).await,
    ) else {
        return;
    };
    let status = match spawn(run, host, place, (true, together)) {
        Ok((mut process, child_in, child_out, child_err)) => {
            let Some(child_in) = child_in else { return };
            match pump_all(
                conn,
                (out, err),
                stdin,
                (&mut process, child_in, child_out, child_err),
                host,
            )
            .await
            {
                Some(code) => ExitStatus::Exited(code),
                None => return,
            }
        }
        Err(problem) => {
            tracing::info!(%problem, "a command could not start");
            let (mut out, mut err) = (out, err);
            let _ = (out.finish(), err.finish());
            ExitStatus::NotStarted(problem)
        }
    };
    let told = async {
        let mut send = open(conn, ExecStream::Status).await?;
        let status = crate::request::encode(&status, MAX_REPLY)?;
        send.write_all(&status).await?;
        send.finish()?;
        anyhow::Ok(())
    };
    if told.await.is_ok() {
        super::linger(conn).await;
    }
}

/// Move the command's stdin, stdout and stderr until it ended and its output did: its status;
/// `None` if the connection was lost or the server is stopping, which hangs it up.
async fn pump_all(
    conn: &Connection,
    (out, err): (SendStream, SendStream),
    stdin: RecvStream,
    (process, child_in, child_out, child_err): (
        &mut Process,
        tokio::process::ChildStdin,
        Output,
        Option<Output>,
    ),
    host: &Host,
) -> Option<u32> {
    let (exited_tx, exited) = watch::channel(false);
    let mut stdout = pin!(pump(Some(child_out), out, exited.clone()));
    let mut stderr = pin!(pump(child_err, err, exited));
    let mut feeding = pin!(feed(stdin, child_in));
    let (mut out_done, mut err_done, mut fed) = (false, false, false);
    let mut status = None;
    loop {
        if let Some(code) = status.filter(|_| out_done && err_done) {
            return Some(code);
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
                status = process.exit();
                if status.is_some() {
                    exited_tx.send_replace(true);
                }
            }
            // Returning drops the process, which hangs it up.
            _ = conn.closed() => return None,
            () = host.shutdown.cancelled() => return None,
        }
    }
}

/// A stream for the client, carrying `what`.
async fn open(conn: &Connection, what: ExecStream) -> anyhow::Result<SendStream> {
    let mut send = conn.open_uni().await?;
    send.write_all(&[what.tag()]).await?;
    Ok(send)
}

/// Send what the command writes on `from` to `to` until it ends, or, once `exited`, goes quiet for
/// [`DRAINED`]; then finish `to`. None, it finishes `to` at once.
async fn pump(
    from: Option<impl AsyncRead + Unpin>,
    mut to: SendStream,
    mut exited: watch::Receiver<bool>,
) {
    let Some(mut from) = from else {
        let _ = to.finish();
        return;
    };
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
