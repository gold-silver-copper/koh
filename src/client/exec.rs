//! `koh exec`: run one command on the server with no terminal, as ssh does, and exit with its
//! status.
//!
//! Local stdin goes to the command's stdin as it comes (the command starts at once, whatever stdin
//! does, and gets its end when stdin ends); its stdout and stderr come back apart, to the local
//! stdout and stderr, a chunk at a time, or, with `--json`, kept (at most [`MAX_KEPT`] each) and
//! said with the status as one JSON value. Stopped by a signal, or losing the link, the
//! connection closes, which hangs the command up; a client killed where it stands is noticed by
//! the server within 10 seconds. On a terminal it reports `busy` (`OSC 133 ; S`) while the
//! command runs, so a terminal that reads reports does not take it for one waiting for input.

use std::pin::pin;
use std::time::{Duration, Instant};

use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream};
use serde::Serialize;
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::cli::{Format, Opened, Remote};
use super::copy::Synced;
use crate::request::{ExecStream, ExitStatus, RemotePath, Request, Run, MAX_REPLY};

/// Most bytes moved at once from a stream.
const CHUNK: usize = 64 * 1024;

/// Most bytes of stdout, and of stderr, `--json` keeps; the rest is counted.
pub const MAX_KEPT: usize = 16 << 20;

/// The status when a local stdout or stderr was closed, as a shell reports a program SIGPIPE
/// ended.
const BROKEN_PIPE: u32 = 128 + 13;

/// `koh exec`: run `run` on `remote`; its exit status.
///
/// That is 128 plus the signal that killed it; 127 if there is no such program, 126 if it could
/// not start. `synced` is the tree brought into line there first, if one was, which `--json`'s
/// value says.
pub async fn exec(
    remote: &Remote,
    (run, synced): (Run, Option<&Synced>),
    format: Format,
) -> anyhow::Result<u32> {
    let interrupted = CancellationToken::new();
    crate::cancel_on_signals(&interrupted)?;
    // Apart, its stdout and stderr could come back in another order than it wrote them: when they
    // go to one file here (`2>&1`, a terminal), they are one pipe there.
    let together = !format.json && one_file();
    let cwd = run.cwd.clone();
    let mut opened = Opened::dial(remote, &Request::Exec { run, together }).await?;
    super::cli::report_busy();
    let (stdin, reading) = super::io::spawn_stdin()?;
    let ran = drive(
        &opened.conn,
        &mut opened.control,
        stdin,
        (&interrupted, cwd.as_ref(), synced),
        format,
    )
    .await;
    reading.cancel();
    opened.close().await;
    ran
}

/// Whether this process's stdout and stderr are one file.
fn one_file() -> bool {
    #[expect(
        clippy::disallowed_methods,
        reason = "its file looked at, nothing written to it"
    )]
    let stderr = std::io::stderr();
    match (
        rustix::fs::fstat(std::io::stdout()),
        rustix::fs::fstat(stderr),
    ) {
        (Ok(out), Ok(err)) => (out.st_dev, out.st_ino) == (err.st_dev, err.st_ino),
        _ => false,
    }
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
/// its status comes; `cwd` is where it was to start.
async fn drive(
    conn: &Connection,
    control: &mut SendStream,
    stdin: mpsc::Receiver<Vec<u8>>,
    (interrupted, cwd, synced): (&CancellationToken, Option<&RemotePath>, Option<&Synced>),
    format: Format,
) -> anyhow::Result<u32> {
    let started = Instant::now();
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
                    anyhow::bail!("{}", stopped(crate::stopped_by(), started.elapsed()));
                }
            }
        }
    };
    let code = match status {
        Ok(ExitStatus::Exited(code)) => Ok(code),
        Ok(ExitStatus::NotStarted(problem)) => {
            let problem = super::cli::hint_problem(problem, cwd);
            if !format.json {
                crate::log::stderr(format_args!("koh: {problem}"));
            }
            Err(problem)
        }
        Err(Stop::Broken) => Ok(BROKEN_PIPE),
        Err(Stop::Failed(error)) => {
            return Err(cut_short(conn.close_reason().as_ref(), started.elapsed())
                .map_or_else(|| super::refusal(conn, &error), anyhow::Error::msg));
        }
    };
    let status = match &code {
        Ok(code) => *code,
        Err(problem) => problem.kind.not_started_status().map_or(126, u32::from),
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
            #[serde(skip_serializing_if = "Option::is_none")]
            synced: Option<&'a Synced>,
        }
        let problem = code.as_ref().err().map(ToString::to_string);
        let view = View {
            status,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            stdout_dropped: out_dropped,
            stderr_dropped: err_dropped,
            error: problem.as_deref(),
            synced,
        };
        let mut line = serde_json::to_vec(&view)?;
        line.push(b'\n');
        let mut stdout = tokio::io::stdout();
        stdout.write_all(&line).await?;
        stdout.flush().await?;
    }
    Ok(status)
}

/// What to do about a command that must outlive this connection.
const AS_A_JOB: &str =
    "a command that must outlive koh exec runs as a job: koh run SERVER -- ARGS, then koh wait \
     SERVER NAME";

/// Why a command that ran for `ran` was cut off when this koh was stopped by `signal`: what
/// became of it, and what to do.
fn stopped(signal: Option<&str>, ran: Duration) -> String {
    format!(
        "stopped by {} after {}: the command was hung up on the server (SIGHUP to its process \
         group, SIGKILL a second later); if a time limit stopped it, {AS_A_JOB}",
        signal.unwrap_or("a signal"),
        super::cli::span(ran.as_secs()),
    )
}

/// Why a command that ran for `ran` was cut off when its connection ended for `reason`, as a
/// person acts on it: nothing came for the idle timeout, or the server went away. `None` for a
/// close the server gave a reason for, which [`super::refusal`] says.
fn cut_short(reason: Option<&ConnectionError>, ran: Duration) -> Option<String> {
    let ran = super::cli::span(ran.as_secs());
    match reason? {
        ConnectionError::TimedOut => Some(format!(
            "cut off after {ran}: nothing came from the server for 10s (the network dropped, or \
             the server or this machine stalled or went away); a server still up hangs the \
             command up once it sees the link gone, within 10s; {AS_A_JOB}"
        )),
        ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 0 => {
            Some(format!(
                "cut off after {ran}: the server shut down, and hung the command up; run it again \
                 once the server is back"
            ))
        }
        ConnectionError::Reset => Some(format!(
            "cut off after {ran}: the server restarted, and the command was hung up with it; run \
             it again"
        )),
        ConnectionError::VersionMismatch
        | ConnectionError::TransportError(_)
        | ConnectionError::ConnectionClosed(_)
        | ConnectionError::ApplicationClosed(_)
        | ConnectionError::LocallyClosed
        | ConnectionError::CidsExhausted => None,
    }
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::endpoint::ConnectionError;

    #[test]
    fn a_cut_off_command_is_said_by_what_cut_it_off() {
        let ran = Duration::from_secs(120);
        let said = super::stopped(Some("SIGTERM"), ran);
        assert!(said.starts_with("stopped by SIGTERM after 2m00s: the command was hung up"));
        assert!(said.contains("koh run SERVER"), "{said}");
        let quiet = super::cut_short(Some(&ConnectionError::TimedOut), ran).unwrap_or_default();
        assert!(
            quiet.starts_with("cut off after 2m00s: nothing came from the server for 10s"),
            "{quiet}"
        );
        assert!(quiet.contains("koh run SERVER"), "{quiet}");
        let reset = super::cut_short(Some(&ConnectionError::Reset), ran).unwrap_or_default();
        assert!(reset.contains("restarted"), "{reset}");
        assert_eq!(super::cut_short(None, ran), None);
        assert_eq!(
            super::cut_short(Some(&ConnectionError::LocallyClosed), ran),
            None
        );
    }
}
