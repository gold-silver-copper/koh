//! `koh exec`: run one command on the server with no terminal, as ssh does, and exit with its
//! status.
//!
//! Local stdin goes to the command's stdin as it comes (the command starts at once, whatever stdin
//! does, and gets its end when stdin ends); its stdout and stderr come back apart, to the local
//! stdout and stderr, a chunk at a time, or, with `--json`, kept (at most [`MAX_KEPT`] each) and
//! said with the status as one JSON value. Stopped by a signal, or losing the link, the
//! connection closes, which hangs the command up; a client killed where it stands is noticed by
//! the server within 20 seconds. On a terminal it reports `busy` (`OSC 133 ; S`) while the
//! command runs, so a terminal that reads reports does not take it for one waiting for input.

use std::pin::pin;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use serde::Serialize;
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::cli::{Format, Opened, Remote};
use crate::request::{ExecStream, ExitStatus, ProblemKind, Request, Run, MAX_REPLY};

/// Most bytes moved at once from a stream.
const CHUNK: usize = 64 * 1024;

/// Most bytes of stdout, and of stderr, `--json` keeps; the rest is counted.
pub const MAX_KEPT: usize = 16 << 20;

/// The status when a local stdout or stderr was closed, as a shell reports a program SIGPIPE
/// ended.
const BROKEN_PIPE: u32 = 128 + 13;

/// `koh exec`: run `run` on `remote`; its exit status (128 plus the signal that killed it; 127 if
/// there is no such program, 126 if it could not start).
pub async fn exec(remote: &Remote, run: Run, format: Format) -> anyhow::Result<u32> {
    let interrupted = CancellationToken::new();
    crate::cancel_on_signals(&interrupted)?;
    let mut opened = Opened::dial(remote, &Request::Exec(run)).await?;
    super::cli::report_busy();
    let (stdin, reading) = super::io::spawn_stdin()?;
    let ran = drive(
        &opened.conn,
        &mut opened.control,
        stdin,
        &interrupted,
        format,
    )
    .await;
    reading.cancel();
    opened.close().await;
    ran
}

/// What stopped the command's output from reaching the user.
enum Stop {
    /// The local stdout or stderr is closed.
    Broken,
    Failed(anyhow::Error),
}

/// Where the command's output goes: the user's stdout and stderr, or kept for `--json`.
enum Sink {
    Through(Box<dyn AsyncWrite + Unpin + Send>),
    Kept(Vec<u8>, u64),
}

impl Sink {
    async fn take(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Through(to) => {
                to.write_all(chunk).await?;
                to.flush().await
            }
            Self::Kept(kept, dropped) => {
                let room = MAX_KEPT.saturating_sub(kept.len());
                let (taken, rest) = chunk.split_at(room.min(chunk.len()));
                kept.extend_from_slice(taken);
                *dropped = dropped.saturating_add(u64::try_from(rest.len()).unwrap_or(u64::MAX));
                Ok(())
            }
        }
    }
}

/// Feed `stdin` to the command on `conn`, through `control`, and its output to the user, until
/// its status comes.
async fn drive(
    conn: &Connection,
    control: &mut SendStream,
    stdin: mpsc::Receiver<Vec<u8>>,
    interrupted: &CancellationToken,
    format: Format,
) -> anyhow::Result<u32> {
    // Apart, so a command that does not read its stdin never holds up its output.
    let mut feeding = pin!(feed(stdin, control));
    let (mut out, mut err) = if format.json {
        (Sink::Kept(Vec::new(), 0), Sink::Kept(Vec::new(), 0))
    } else {
        #[expect(
            clippy::disallowed_methods,
            reason = "the command's own stderr, as it wrote it, as its stdout goes to stdout"
        )]
        let local_stderr = tokio::io::stderr();
        (
            Sink::Through(Box::new(tokio::io::stdout())),
            Sink::Through(Box::new(local_stderr)),
        )
    };
    let status = {
        let mut output = pin!(output(conn, &mut out, &mut err));
        let mut fed = false;
        loop {
            tokio::select! {
                () = &mut feeding, if !fed => fed = true,
                done = &mut output => break done,
                () = interrupted.cancelled() => {
                    anyhow::bail!("interrupted: the command was hung up");
                }
            }
        }
    };
    let code = match status {
        Ok(ExitStatus::Exited(code)) => Ok(code),
        Ok(ExitStatus::NotStarted(problem)) => {
            if !format.json {
                crate::log::stderr(format_args!("koh: {problem}"));
            }
            Err(problem)
        }
        Err(Stop::Broken) => Ok(BROKEN_PIPE),
        Err(Stop::Failed(error)) => return Err(super::refusal(conn, &error)),
    };
    let status = match &code {
        Ok(code) => *code,
        Err(problem) if problem.kind == ProblemKind::NotFound => 127,
        Err(_) => 126,
    };
    if let (Sink::Kept(stdout, out_dropped), Sink::Kept(stderr, err_dropped)) = (out, err) {
        #[derive(Serialize)]
        struct View<'a> {
            status: u32,
            stdout: String,
            stderr: String,
            stdout_dropped: u64,
            stderr_dropped: u64,
            error: Option<&'a str>,
        }
        let problem = code.as_ref().err().map(ToString::to_string);
        let view = View {
            status,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            stdout_dropped: out_dropped,
            stderr_dropped: err_dropped,
            error: problem.as_deref(),
        };
        let mut line = serde_json::to_vec(&view)?;
        line.push(b'\n');
        let mut stdout = tokio::io::stdout();
        stdout.write_all(&line).await?;
        stdout.flush().await?;
    }
    Ok(status)
}

/// Send what `stdin` reads on `control` until it ends, then end `control`: the command reads its
/// end. A command that took no more stops the stream, and the rest is not read.
async fn feed(mut stdin: mpsc::Receiver<Vec<u8>>, control: &mut SendStream) {
    while let Some(chunk) = stdin.recv().await {
        if control.write_all(&chunk).await.is_err() {
            return;
        }
    }
    let _ = control.finish();
}

/// Copy the command's stdout and stderr to `out` and `err`, as they come; then its status.
async fn output(conn: &Connection, out: &mut Sink, err: &mut Sink) -> Result<ExitStatus, Stop> {
    let failed = Stop::Failed;
    let stdout = accept(conn, ExecStream::Stdout).await.map_err(failed)?;
    let stderr = accept(conn, ExecStream::Stderr).await.map_err(failed)?;
    let status = async {
        let mut recv = accept(conn, ExecStream::Status).await.map_err(failed)?;
        let bytes = recv
            .read_to_end(MAX_REPLY.saturating_add(4))
            .await
            .map_err(|e| failed(e.into()))?;
        crate::request::decode_framed::<ExitStatus>(&bytes, MAX_REPLY).map_err(|e| failed(e.into()))
    };
    let (_, _, status) = tokio::try_join!(copy(stdout, out), copy(stderr, err), status)?;
    Ok(status)
}

/// The server's next stream, which must carry `what`.
async fn accept(conn: &Connection, what: ExecStream) -> anyhow::Result<RecvStream> {
    let mut recv = conn.accept_uni().await?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag).await?;
    let [tag] = tag;
    anyhow::ensure!(
        ExecStream::from_tag(tag) == Some(what),
        "the server sent the command's streams out of order"
    );
    Ok(recv)
}

/// Copy `recv` to `to` until it ends.
async fn copy(mut recv: RecvStream, to: &mut Sink) -> Result<(), Stop> {
    while let Some(chunk) = recv
        .read_chunk(CHUNK)
        .await
        .map_err(|e| Stop::Failed(e.into()))?
    {
        if let Err(error) = to.take(&chunk).await {
            return Err(if error.kind() == std::io::ErrorKind::BrokenPipe {
                Stop::Broken
            } else {
                Stop::Failed(error.into())
            });
        }
    }
    Ok(())
}
