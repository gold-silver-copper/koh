//! `koh exec`: run one command on the server with no terminal, as ssh does, and exit with its
//! status.
//!
//! Local stdin goes to the command's stdin as it comes (the command starts at once, whatever stdin
//! does, and gets its end when stdin ends); its stdout and stderr come back apart, to the local
//! stdout and stderr, a chunk at a time. Nothing else is written there but a real error. Stopped
//! by a signal, or losing the link, the connection closes, which hangs the command up.

use std::pin::pin;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::cli::{Opened, Remote};
use crate::request::{CommandLine, ExecStream, ExitStatus, Request, MAX_REPLY};

/// Most bytes moved at once from a stream.
const CHUNK: usize = 64 * 1024;

/// The status when a local stdout or stderr was closed, as a shell reports a program SIGPIPE
/// ended.
const BROKEN_PIPE: u32 = 128 + 13;

/// `koh exec`: run `line` on `remote`; its exit status (128 plus the signal that killed it).
pub async fn exec(remote: &Remote, line: CommandLine) -> anyhow::Result<u32> {
    let interrupted = CancellationToken::new();
    crate::cancel_on_signals(&interrupted)?;
    let mut opened = Opened::dial(remote, &Request::Exec(line)).await?;
    let (stdin, reading) = super::io::spawn_stdin()?;
    let ran = run(&opened.conn, &mut opened.control, stdin, &interrupted).await;
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

/// Feed `stdin` to the command on `conn`, through `control`, and its output to the user, until
/// its status comes.
async fn run(
    conn: &Connection,
    control: &mut SendStream,
    stdin: mpsc::Receiver<Vec<u8>>,
    interrupted: &CancellationToken,
) -> anyhow::Result<u32> {
    // Apart, so a command that does not read its stdin never holds up its output.
    let mut feeding = pin!(feed(stdin, control));
    let mut output = pin!(output(conn));
    let mut fed = false;
    loop {
        tokio::select! {
            () = &mut feeding, if !fed => fed = true,
            done = &mut output => {
                return match done {
                    Ok(ExitStatus(code)) => Ok(code),
                    Err(Stop::Broken) => Ok(BROKEN_PIPE),
                    Err(Stop::Failed(error)) => Err(super::refusal(conn, &error)),
                };
            }
            () = interrupted.cancelled() => {
                anyhow::bail!("interrupted: the command was hung up");
            }
        }
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

/// Copy the command's stdout and stderr to the user's, as they come; then its status.
async fn output(conn: &Connection) -> Result<ExitStatus, Stop> {
    let failed = |error| Stop::Failed(error);
    let stdout = accept(conn, ExecStream::Stdout).await.map_err(failed)?;
    let stderr = accept(conn, ExecStream::Stderr).await.map_err(failed)?;
    #[expect(
        clippy::disallowed_methods,
        reason = "the command's own stderr, as it wrote it, as its stdout goes to stdout"
    )]
    let local_stderr = tokio::io::stderr();
    let status = async {
        let mut recv = accept(conn, ExecStream::Status).await.map_err(failed)?;
        let bytes = recv
            .read_to_end(MAX_REPLY.saturating_add(4))
            .await
            .map_err(|e| failed(e.into()))?;
        crate::request::decode_framed::<ExitStatus>(&bytes, MAX_REPLY).map_err(|e| failed(e.into()))
    };
    let (_, _, status) = tokio::try_join!(
        copy(stdout, tokio::io::stdout()),
        copy(stderr, local_stderr),
        status
    )?;
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

/// Copy `recv` to `to` until it ends, each chunk flushed as it comes.
async fn copy(mut recv: RecvStream, mut to: impl AsyncWrite + Unpin) -> Result<(), Stop> {
    while let Some(chunk) = recv
        .read_chunk(CHUNK)
        .await
        .map_err(|e| Stop::Failed(e.into()))?
    {
        let written = async {
            to.write_all(&chunk).await?;
            to.flush().await
        };
        if let Err(error) = written.await {
            return Err(if error.kind() == std::io::ErrorKind::BrokenPipe {
                Stop::Broken
            } else {
                Stop::Failed(error.into())
            });
        }
    }
    Ok(())
}
