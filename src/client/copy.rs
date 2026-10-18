//! `koh cp`: bring files and trees into line between this machine and a server, done by
//! [`crate::sync`] on a blocking thread at this end and in process on the server, no remote
//! shell, `tar` or `scp` needed. On success it says what it did in one line, or as JSON.

use std::path::PathBuf;
use std::pin::pin;

use serde::Serialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::cli::{bytes, escaped, Format, Opened, Remote};
use crate::request::{RemotePath, Request, Sources};
use crate::sync::{
    self, ChannelReader, ChannelWriter, Copy, Dest, FailKind, Failure, Opts, Reply, Source,
    SourceCount, Summary, Target, PIPE_DEPTH, REPLY_DEPTH,
};

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

/// Said when a signal stopped the copy.
const INTERRUPTED: &str =
    "interrupted: the files that came are whole, the one under way kept for the next copy";

/// `koh cp`: do `job` with `remote` under `opts`, `shown` the destination as the user named it;
/// what it did is said on stdout.
pub async fn copy(
    remote: &Remote,
    (job, opts): (CopyJob, Opts),
    shown: &str,
    format: Format,
) -> anyhow::Result<()> {
    let interrupted = CancellationToken::new();
    crate::cancel_on_signals(&interrupted)?;
    let (summary, several) = match job {
        CopyJob::Get { sources, dest } => {
            let several = sources.paths().len() > 1;
            (
                get(remote, (sources, dest), opts, &interrupted).await?,
                several,
            )
        }
        CopyJob::Put { sources, dest } => {
            let several = sources.len() > 1;
            (
                put(remote, (sources, dest), opts, &interrupted).await?,
                several,
            )
        }
    };
    say(&summary, &landed(&summary, shown, several), format)
}

/// Where a copy to `shown` landed: inside it, as its one source's name, if the summary says so;
/// in it, if there were `several`; else as it.
fn landed(summary: &Summary, shown: &str, several: bool) -> String {
    let into = if shown.ends_with('/') || shown.ends_with(':') {
        shown.to_owned()
    } else {
        format!("{shown}/")
    };
    match &summary.inside {
        _ if several => into,
        Some(name) => format!("{into}{}", escaped(name)),
        None => shown.to_owned(),
    }
}

/// Say `summary` of a copy that landed at `landed`: one line, or one JSON value.
fn say(summary: &Summary, landed: &str, format: Format) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    if format.json {
        #[derive(Serialize)]
        struct View<'a> {
            landed: &'a str,
            #[serde(flatten)]
            summary: &'a Summary,
        }
        serde_json::to_writer(&mut out, &View { landed, summary })?;
        writeln!(out)?;
        return Ok(());
    }
    // What was sent, split into new and replaced, which add up to it; then the rest.
    let mut sent = Vec::new();
    if summary.new > 0 {
        sent.push(format!("{} new", summary.new));
    }
    if summary.replaced > 0 {
        sent.push(format!("{} replaced", summary.replaced));
    }
    let mut parts = Vec::new();
    if summary.unchanged > 0 {
        parts.push(format!("{} unchanged", summary.unchanged));
    }
    if summary.resumed > 0 {
        parts.push(format!("{} resumed", summary.resumed));
    }
    if summary.deleted > 0 {
        parts.push(format!("{} deleted", summary.deleted));
    }
    if summary.dirs > 0 {
        parts.push(format!("{} dirs made", summary.dirs));
    }
    if summary.links > 0 {
        parts.push(format!("{} links", summary.links));
    }
    let more = match (sent.is_empty(), parts.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!(" ({})", sent.join(", ")),
        (true, false) => format!(" ({})", parts.join(", ")),
        (false, false) => format!(" ({}; {})", sent.join(", "), parts.join(", ")),
    };
    let written = summary.written();
    writeln!(
        out,
        "{written} file{} sent, {} → {landed}{more}",
        if written == 1 { "" } else { "s" },
        bytes(summary.bytes),
    )?;
    if summary.skipped > 0 {
        crate::log::stderr(format_args!(
            "koh: skipped {} fifo(s), socket(s) or device(s), which cannot be copied: {}{}",
            summary.skipped,
            summary.skipped_shown.join(", "),
            if summary.skipped > u64::try_from(summary.skipped_shown.len()).unwrap_or(u64::MAX) {
                ", …"
            } else {
                ""
            }
        ));
    }
    Ok(())
}

/// The server's `sources` to `dest`.
async fn get(
    remote: &Remote,
    (sources, dest): (Sources, PathBuf),
    opts: Opts,
    interrupted: &CancellationToken,
) -> anyhow::Result<Summary> {
    // Where they land is known before the server is asked anything.
    let (target, made) = Target::resolve(&Dest::Path(dest), sources.paths().len())?;
    let request = Request::Copy(Copy::Get {
        sources,
        opts: opts.clone(),
    });
    let mut opened = Opened::dial(remote, &request).await?;
    let (tx, rx) = mpsc::channel(PIPE_DEPTH);
    let (reply_tx, reply_rx) = mpsc::channel(REPLY_DEPTH);
    let end_tx = reply_tx.clone();
    let mut landing = pin!(tokio::task::spawn_blocking(move || {
        let mut answer = |reply: Reply| reply_tx.try_send(reply).is_ok();
        sync::receive(ChannelReader::new(rx), &target, &opts, &mut answer)
    }));
    let conn = opened.conn.clone();
    let pumped = async move {
        let recv = conn.accept_uni().await?;
        sync::from_stream(recv, tx).await;
        anyhow::Ok(())
    };
    let replying = sync::replies_to(reply_rx, &mut opened.control);
    let landed = async {
        tokio::select! {
            landed = &mut landing => Some(Ok(landed)),
            pumped = pumped => match pumped {
                Ok(()) => Some(Ok(landing.await)),
                Err(error) => Some(Err(error)),
            },
            () = interrupted.cancelled() => None,
        }
    };
    let (landed, ()) = tokio::join!(
        async {
            let landed = landed.await;
            let _ = end_tx.send(Reply::End(Ok(Summary::default()))).await;
            drop(end_tx);
            landed
        },
        replying
    );
    let outcome = match landed {
        Some(Ok(landed)) => landed?.map_err(|failure| cut_short(&opened.conn, failure)),
        Some(Err(error)) => Err(super::refusal(&opened.conn, &error)),
        None => Err(anyhow::anyhow!(INTERRUPTED)),
    };
    opened.close().await;
    outcome.map(|mut summary| {
        summary.dirs = summary.dirs.saturating_add(made);
        summary
    })
}

/// `sources` to `dest` on the server.
async fn put(
    remote: &Remote,
    (sources, dest): (Vec<PathBuf>, RemotePath),
    opts: Opts,
    interrupted: &CancellationToken,
) -> anyhow::Result<Summary> {
    let count = SourceCount::new(sources.len())
        .ok_or_else(|| anyhow::anyhow!("no sources, or more than 1024"))?;
    let request = Request::Copy(Copy::Put {
        dest,
        sources: count,
        opts: opts.clone(),
    });
    let mut opened = Opened::dial(remote, &request).await?;
    let (tx, rx) = mpsc::channel(PIPE_DEPTH);
    let (reply_tx, mut reply_rx) = mpsc::channel(REPLY_DEPTH);
    let sources: Vec<Source> = sources.into_iter().map(Source::Path).collect();
    let sending = tokio::task::spawn_blocking(move || {
        let mut answers = |wait: bool| {
            if wait {
                reply_rx.blocking_recv()
            } else {
                reply_rx.try_recv().ok()
            }
        };
        sync::send(&sources, &opts, ChannelWriter(tx), &mut answers)
    });
    let conn = opened.conn.clone();
    let replies = async move {
        let recv = conn.accept_uni().await?;
        sync::replies_from(recv, reply_tx).await;
        anyhow::Ok(())
    };
    let sent = async {
        let _ = sync::to_stream(rx, &mut opened.control).await;
    };
    let both = async {
        let (_, replied) = tokio::join!(sent, replies);
        replied
    };
    let finished = tokio::select! {
        replied = both => Some(replied),
        () = interrupted.cancelled() => None,
    };
    let Some(replied) = finished else {
        opened.close().await;
        let _ = sending.await;
        anyhow::bail!(INTERRUPTED);
    };
    let outcome = sending.await?;
    let outcome = match (outcome, replied) {
        (Ok(Ok(summary)), _) => Ok(summary),
        (Ok(Err(failure)), _) => Err(cut_short(&opened.conn, failure)),
        (Err(error), replied) => Err(super::refusal(
            &opened.conn,
            &replied.err().unwrap_or_else(|| error.into()),
        )),
    };
    opened.close().await;
    outcome
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
