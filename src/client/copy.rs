//! `koh cp`: copy files and trees between this machine and a server, done by [`crate::copy`] on a
//! blocking thread at this end and in process on the server, no remote shell, `tar` or `scp`
//! needed.

use std::path::PathBuf;
use std::pin::pin;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::cli::{Opened, Remote};
use crate::copy::{
    self, ChannelReader, ChannelWriter, FailKind, Failure, Skipped, Target, PIPE_DEPTH,
};
use crate::request::{Arity, Copy, RemotePath, Request, Sources, MAX_REPLY};

/// A copy, one side the server's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyJob {
    /// The server's `sources` to `dest` here.
    Get { sources: Sources, dest: PathBuf },
    /// `sources` here to `dest` on the server.
    Put {
        sources: Vec<PathBuf>,
        dest: RemotePath,
    },
}

/// `koh cp`: do `job` with `remote`. The entries skipped (fifos, sockets, devices) are said on
/// stderr. Stopped by a signal, it closes the connection and removes what it staged, as the
/// server then does.
pub async fn copy(remote: &Remote, job: CopyJob) -> anyhow::Result<()> {
    let interrupted = CancellationToken::new();
    crate::cancel_on_signals(&interrupted)?;
    let skipped = match job {
        CopyJob::Get { sources, dest } => get(remote, sources, dest, &interrupted).await?,
        CopyJob::Put { sources, dest } => put(remote, sources, dest, &interrupted).await?,
    };
    if skipped.count > 0 {
        let shown: Vec<String> = skipped
            .shown
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        crate::log::stderr(format_args!(
            "koh: skipped {} fifo(s), socket(s) or device(s), which cannot be copied: {}{}",
            skipped.count,
            shown.join(", "),
            if skipped.count > u64::try_from(shown.len()).unwrap_or(u64::MAX) {
                ", …"
            } else {
                ""
            }
        ));
    }
    Ok(())
}

/// Said when a signal stopped the copy.
const INTERRUPTED: &str = "interrupted: nothing of the copy that was under way was kept";

/// The server's `sources` to `dest`.
async fn get(
    remote: &Remote,
    sources: Sources,
    dest: PathBuf,
    interrupted: &CancellationToken,
) -> anyhow::Result<Skipped> {
    // Where they land is known before the server is asked anything.
    let arity = Arity::of(sources.paths().len());
    let target = Target::resolve(dest, arity)?;
    let mut opened = Opened::dial(remote, &Request::Copy(Copy::Get(sources))).await?;
    opened.control.finish()?;
    let (tx, rx) = mpsc::channel(PIPE_DEPTH);
    let mut landing = pin!(tokio::task::spawn_blocking(move || {
        copy::receive(ChannelReader::new(rx), &target)
    }));
    let conn = opened.conn.clone();
    let pumped = async move {
        let recv = conn.accept_uni().await?;
        copy::from_stream(recv, tx).await;
        anyhow::Ok(())
    };
    // Each way out drops the stream's end of the channel, and the receiver then finishes,
    // removing what it staged unless all of it came.
    let pumped = tokio::select! {
        landed = &mut landing => Some(Ok(landed)),
        pumped = pumped => pumped.err().map(Err),
        () = interrupted.cancelled() => None,
    };
    let landed = match pumped {
        Some(Ok(landed)) => landed,
        Some(Err(error)) => {
            let _ = landing.await;
            let refused = super::refusal(&opened.conn, &error);
            opened.close().await;
            return Err(refused);
        }
        None if interrupted.is_cancelled() => {
            let _ = landing.await;
            opened.close().await;
            anyhow::bail!(INTERRUPTED);
        }
        None => landing.await,
    };
    let landed = landed?.map_err(|failure| cut_short(&opened.conn, failure));
    opened.close().await;
    landed
}

/// `sources` to `dest` on the server.
async fn put(
    remote: &Remote,
    sources: Vec<PathBuf>,
    dest: RemotePath,
    interrupted: &CancellationToken,
) -> anyhow::Result<Skipped> {
    let arity = Arity::of(sources.len());
    let mut opened = Opened::dial(remote, &Request::Copy(Copy::Put { dest, arity })).await?;
    let (tx, rx) = mpsc::channel(PIPE_DEPTH);
    let sending = tokio::task::spawn_blocking(move || copy::send(&sources, ChannelWriter(tx)));
    let conn = opened.conn.clone();
    let answer = async move {
        let mut recv = conn.accept_uni().await?;
        let bytes = recv.read_to_end(MAX_REPLY.saturating_add(4)).await?;
        anyhow::Ok(crate::request::decode_framed::<Result<(), Failure>>(
            &bytes, MAX_REPLY,
        )?)
    };
    // The server may answer before all is sent (it failed): then the rest is not sent.
    let sent_all = async {
        let _ = copy::to_stream(rx, &mut opened.control).await;
        std::future::pending::<()>().await;
    };
    let outcome = tokio::select! {
        outcome = answer => Some(outcome),
        () = sent_all => None,
        () = interrupted.cancelled() => None,
    };
    let Some(outcome) = outcome else {
        // Closed, the server removes what it staged.
        opened.close().await;
        let _ = sending.await;
        anyhow::bail!(INTERRUPTED);
    };
    let sent = sending.await?;
    let outcome = outcome.map_err(|e| super::refusal(&opened.conn, &e));
    opened.close().await;
    // The server's word for how it went: a failure here was sent it, and it says so.
    match outcome? {
        Ok(()) => Ok(sent.ok().and_then(Result::ok).unwrap_or_default()),
        Err(failure) => Err(failure.into()),
    }
}

/// `failure`, unless it is the stream cut short by the server closing `conn` with a reason, which
/// says more.
fn cut_short(conn: &iroh::endpoint::Connection, failure: Failure) -> anyhow::Error {
    if failure.kind == FailKind::Truncated && crate::transport_iroh::closed_because(conn).is_some()
    {
        return super::refusal(conn, &failure.into());
    }
    failure.into()
}
