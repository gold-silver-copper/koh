//! `koh exec` on the server: a command with no terminal, for as long as its connection lasts; and
//! the starting and running of every command with no terminal, `koh run`'s jobs too.
//!
//! Its words are run as they are, the first found on the server's `PATH` (`~/x` in the server
//! user's home), or a shell line is run by the user's shell (`$SHELL -c`, else the platform's
//! `sh`); it starts in their home, or the directory asked, with the environment a session's
//! program gets but `TERM`, as the leader of a session of its own. The client's stream goes on as
//! its stdin; its stdout and stderr go back on a stream each, as they come, then its exit status
//! on a third. Memory is bounded by a chunk each way: a slow reader on either end holds the other
//! back through the pipes and QUIC's flow control.
//!
//! A command ends when it has exited and its output has ended, or gone quiet for [`DRAINED`] (a
//! job it left in the background holds its pipes, which ssh would wait on for ever). A lost
//! connection (the client's own idle timeout is 10 s, so a killed client is found within it),
//! revocation or the server's shutdown hangs it up: SIGHUP to its process group, and SIGKILL once
//! the reaper's grace is over.

use std::ffi::OsStr;
use std::future::Future;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::pin::pin;
use std::process::Stdio;
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::ChildStdin;
use tokio::sync::{mpsc, watch};
use tokio_util::task::task_tracker::TaskTrackerToken;

use super::cli::Host;
use super::place::Place;
use crate::pty::Program;
use crate::request::{
    Command, ExecStream, ExitStatus, Problem, ProblemKind, Run, Signal, MAX_REPLY,
};

/// Most bytes moved at once, each way.
const CHUNK: usize = 64 * 1024;

/// How long output must be quiet, after the command exited, for its pipes to count as drained:
/// what it wrote is already in them, so it is read long before this.
const DRAINED: Duration = Duration::from_millis(100);

/// The status of a command whose exit could not be read, as ssh says of a lost one.
const UNKNOWN: u32 = 255;

/// A command while it runs: hung up when dropped, unless it was reaped; until then one of those
/// the server's shutdown waits for ([`Host::running`]).
pub(super) struct Process {
    /// Before the count, so it is hung up before the shutdown stops waiting for it.
    program: Program,
    _counted: TaskTrackerToken,
}

impl Process {
    /// The session it leads, unless it was reaped.
    pub(super) fn session(&self) -> Option<fuxix::process::Pid> {
        self.program.pid()
    }

    /// Its exit status, reaping it: once [`Program::exited`] resolved.
    fn reap(&mut self) -> u32 {
        match self.program.try_wait() {
            Ok(Some(exit)) => exit.code(),
            Ok(None) => UNKNOWN,
            Err(error) => {
                tracing::warn!(%error, "waiting for a command failed");
                UNKNOWN
            }
        }
    }
}

/// The read end of a command's stdout or stderr.
pub(super) type Output = tokio::net::unix::pipe::Receiver;

/// A command started, and its pipes.
pub(super) struct Spawned {
    pub(super) process: Process,
    /// Its stdin, if asked for; else it reads `/dev/null`.
    pub(super) stdin: Option<ChildStdin>,
    pub(super) stdout: Output,
    /// Its stderr, unless it writes that into its stdout's pipe.
    pub(super) stderr: Option<Output>,
}

/// Start `run` at `place` for `host`, stdin piped if `stdin`, its stderr into its stdout's pipe if
/// `together`, which keeps the order it wrote them in; why not, said as the client shows it. The
/// fork and exec are on a blocking worker.
pub(super) async fn spawn(
    run: &Run,
    host: &Host,
    place: &Place,
    stdin: bool,
    together: bool,
) -> Result<Spawned, Problem> {
    // Counted first: once the shutdown began, it may already have stopped counting.
    let counted = host.running.token();
    if host.shutdown.is_cancelled() {
        return Err(Problem::new(
            ProblemKind::CouldNotStart,
            "the server is stopping",
        ));
    }
    let (run, place) = (run.clone(), place.clone());
    let (home, reaper) = (host.home.clone(), host.registry.reaper().clone());
    let started = tokio::task::spawn_blocking(move || {
        let io = |e: std::io::Error| Problem::new(ProblemKind::CouldNotStart, e);
        let cwd = place.cwd(run.cwd.as_ref())?;
        let mut cmd = command(&run.command, &home);
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
        let mut child = spawned.map_err(|error| not_started(&run, cwd.as_deref(), &error))?;
        let stdin = child.stdin.take();
        let program = Program::group(child, &reaper)
            .ok_or_else(|| Problem::new(ProblemKind::CouldNotStart, "no pid"))?;
        let output = |end: std::io::PipeReader| Output::from_owned_fd(end.into()).map_err(io);
        Ok(Spawned {
            process: Process {
                program,
                _counted: counted,
            },
            stdin: stdin.map(ChildStdin::from_std).transpose().map_err(io)?,
            stdout: output(out)?,
            stderr: err.map(output).transpose()?,
        })
    })
    .await;
    started.map_err(|e| Problem::new(ProblemKind::CouldNotStart, e))?
}

/// `command`, as the server user's shell runs it in `home`.
#[expect(
    clippy::disallowed_methods,
    reason = "what an allowed client asked the server user to run, as its shell sessions do"
)]
fn command(command: &Command, home: &crate::pty::Home) -> std::process::Command {
    match command {
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
    }
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

/// Wait for `process` to exit and for `output`, its pumps, to end: they are told on `exited` once
/// it exited, and drain for at most [`DRAINED`] more. `signals` are sent it meanwhile. Its status;
/// `None` if `stop` came first, which drops it, and so hangs it up.
pub(super) async fn finish(
    mut process: Process,
    output: impl Future<Output = ()>,
    exited: watch::Sender<bool>,
    signals: &mut mpsc::Receiver<Signal>,
    stop: impl Future<Output = ()>,
) -> Option<u32> {
    let (mut output, mut stop) = (pin!(output), pin!(stop));
    let mut waiting = pin!(process.program.exited());
    let (mut status, mut ended) = (None, false);
    loop {
        if let Some(code) = status.filter(|_| ended) {
            return Some(code);
        }
        tokio::select! {
            () = &mut output, if !ended => ended = true,
            () = &mut waiting, if status.is_none() => {
                status = Some(process.reap());
                exited.send_replace(true);
            }
            Some(signal) = signals.recv() => process.program.signal(match signal {
                Signal::Term => fuxix::process::Signal::Term,
                Signal::Kill => fuxix::process::Signal::Kill,
                Signal::Int => fuxix::process::Signal::Int,
                Signal::Hup => fuxix::process::Signal::Hup,
            }),
            () = &mut stop => return None,
        }
    }
}

/// What a command writes on a pipe, read until it ends, or, once the command `exited`, goes quiet
/// for [`DRAINED`].
pub(super) struct Drain {
    from: Output,
    exited: watch::Receiver<bool>,
    buf: Vec<u8>,
}

impl Drain {
    pub(super) fn new(from: Output, exited: watch::Receiver<bool>) -> Self {
        Self {
            from,
            exited,
            buf: vec![0u8; CHUNK],
        }
    }

    /// What it wrote next; `None` once that is all.
    pub(super) async fn next(&mut self) -> Option<&[u8]> {
        let read = loop {
            if *self.exited.borrow_and_update() {
                break tokio::time::timeout(DRAINED, self.from.read(&mut self.buf))
                    .await
                    .ok()?;
            }
            tokio::select! {
                read = self.from.read(&mut self.buf) => break read,
                _ = self.exited.changed() => {}
            }
        };
        match read {
            Ok(0) | Err(_) => None,
            Ok(n) => self.buf.get(..n),
        }
    }
}

/// Run `run` for the client on `conn` at `place`, `stdin` its stdin, its stderr into its stdout if
/// `together`, until it ends and the client has its status, or the connection is lost, which
/// hangs it up.
pub(super) async fn serve(
    conn: &Connection,
    stdin: RecvStream,
    run: &Run,
    together: bool,
    host: &Host,
    place: &Place,
) {
    let (Ok(out), Ok(err)) = (
        open(conn, ExecStream::Stdout).await,
        open(conn, ExecStream::Stderr).await,
    ) else {
        return;
    };
    let status = match spawn(run, host, place, true, together).await {
        Ok(Spawned {
            process,
            stdin: Some(child_in),
            stdout,
            stderr,
        }) => {
            let (exited, told) = watch::channel(false);
            let output = async {
                let feeding = async {
                    feed(stdin, child_in).await;
                    std::future::pending::<()>().await;
                };
                let stdout = pump(Some(stdout), out, told.clone());
                tokio::select! {
                    _ = async { tokio::join!(stdout, pump(stderr, err, told)) } => {}
                    () = feeding => {}
                }
            };
            let stop = async {
                tokio::select! {
                    _ = conn.closed() => {}
                    () = host.shutdown.cancelled() => {}
                }
            };
            let no_signals = &mut mpsc::channel(1).1;
            match finish(process, output, exited, no_signals, stop).await {
                Some(code) => ExitStatus::Exited(code),
                None => return,
            }
        }
        Ok(_) => return,
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

/// A stream for the client, carrying `what`.
async fn open(conn: &Connection, what: ExecStream) -> anyhow::Result<SendStream> {
    let mut send = conn.open_uni().await?;
    send.write_all(&[what.tag()]).await?;
    Ok(send)
}

/// Send what the command writes on `from`, if it has its own pipe, to `to` as [`Drain`] reads
/// it; then finish `to`.
async fn pump(from: Option<Output>, mut to: SendStream, exited: watch::Receiver<bool>) {
    if let Some(from) = from {
        let mut drain = Drain::new(from, exited);
        while let Some(bytes) = drain.next().await {
            if to.write_all(bytes).await.is_err() {
                return;
            }
        }
    }
    let _ = to.finish();
}

/// Hand what the client sends on `from` to the command's stdin until either ends: the command
/// then reads its end, or the client's writes are stopped.
async fn feed(mut from: RecvStream, mut to: ChildStdin) {
    while let Ok(Some(chunk)) = from.read_chunk(CHUNK).await {
        if to.write_all(&chunk).await.is_err() {
            let _ = from.stop(0u32.into());
            return;
        }
    }
}
