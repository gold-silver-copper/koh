//! `koh cp`: bring files and trees into line between this machine and a server, done by
//! [`crate::sync`] on a blocking thread at this end and in process on the server, no remote
//! shell, `tar` or `scp` needed. On success it says what it did in one line, or as JSON.

use std::future::Future;
use std::path::PathBuf;

use serde::Serialize;
use tokio_util::sync::CancellationToken;

use super::cli::{bytes, escaped, Format, Opened, Remote};
use crate::request::{RemotePath, Request, Sources};
use crate::sync::glob::Excludes;
use crate::sync::{self, Copy, Dest, FailKind, Failure, Opts, Source, SourceCount, Summary};

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
    let dry = opts.dry_run;
    // Said by direction: a download is received here, an upload sent from here.
    let (summary, verb) = match job {
        CopyJob::Get { sources, dest } => (
            get(remote, (sources, dest), opts, &interrupted).await?,
            "received",
        ),
        CopyJob::Put { sources, dest } => (
            put(remote, (sources, dest), opts, &interrupted).await?,
            "sent",
        ),
    };
    say(&summary, (shown, dry, verb), format)
}

/// Say `summary` of a copy to `landed` (or that would have been, if `dry`), its files `verb`
/// (sent, received): one line, after a dry run's changes one a line, or one JSON value.
fn say(
    summary: &Summary,
    (landed, dry, verb): (&str, bool, &str),
    format: Format,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    if format.json {
        #[derive(Serialize)]
        struct View<'a> {
            landed: &'a str,
            dry_run: bool,
            #[serde(flatten)]
            summary: &'a Summary,
        }
        let view = View {
            landed,
            dry_run: dry,
            summary,
        };
        serde_json::to_writer(&mut out, &view)?;
        writeln!(out)?;
        return Ok(());
    }
    for change in &summary.changes {
        let sizes = match (change.size, change.was) {
            (Some(size), Some(was)) => format!(" ({}, was {})", bytes(size), bytes(was)),
            (Some(size), None) => format!(" ({})", bytes(size)),
            (None, _) => String::new(),
        };
        writeln!(
            out,
            "{:<8} {}{sizes}",
            change.kind.name(),
            escaped(&change.path)
        )?;
    }
    if summary.changes_unshown > 0 {
        writeln!(out, "… {} more", summary.changes_unshown)?;
    }
    writeln!(out, "{}", line(summary, (landed, dry, verb)))?;
    if summary.skipped > 0 {
        crate::log::stderr(format_args!(
            "koh: skipped {} fifo(s), socket(s) or device(s), which cannot be copied",
            summary.skipped,
        ));
    }
    Ok(())
}

/// The line that says what a copy did: `3 files sent, 41 KB → SERVER:proj (1 new, 2 replaced; 120
/// unchanged)`, as a dry run if `dry`.
fn line(summary: &Summary, (landed, dry, verb): (&str, bool, &str)) -> String {
    let counted = |counts: &[(u64, &str)]| {
        let said: Vec<String> = counts
            .iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, what)| format!("{n} {what}"))
            .collect();
        said.join(", ")
    };
    // What came across, split into new and replaced, which add up to it; then the rest.
    let sent = counted(&[(summary.new, "new"), (summary.replaced, "replaced")]);
    let rest = counted(&[
        (summary.unchanged, "unchanged"),
        (summary.resumed, "resumed"),
        (summary.deleted, "deleted"),
        (summary.dirs, "dirs made"),
        (summary.links, "links"),
    ]);
    let more = match (sent.is_empty(), rest.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!(" ({sent})"),
        (true, false) => format!(" ({rest})"),
        (false, false) => format!(" ({sent}; {rest})"),
    };
    let written = summary.written();
    format!(
        "{}{written} file{} {}{verb}, {} → {landed}{more}{}",
        if dry { "dry run: " } else { "" },
        if written == 1 { "" } else { "s" },
        if dry { "would be " } else { "" },
        bytes(summary.bytes),
        if dry { "; nothing changed" } else { "" },
    )
}

/// A tree brought into line on the server before a command runs there (`--sync`).
///
/// What `local` holds goes to `dest`, as `koh cp -r LOCAL/. SERVER:DEST` sends it, only the files
/// that changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncTree {
    pub local: PathBuf,
    pub dest: RemotePath,
    pub excludes: Excludes,
}

/// What a sync did: where it landed, as the user would name it, and its summary.
#[derive(Debug, Serialize)]
pub struct Synced {
    pub landed: String,
    #[serde(flatten)]
    pub summary: Summary,
}

impl Synced {
    /// The line that says it, on stderr before the command's output: `koh: synced 2 files sent,
    /// 13 KB → SERVER:proj (2 replaced; 19 unchanged)`.
    pub fn line(&self) -> String {
        format!(
            "synced {}",
            line(&self.summary, (&self.landed, false, "sent"))
        )
    }
}

/// Bring `sync.dest` on `remote` into line with `sync.local` here.
pub async fn sync(remote: &Remote, sync: SyncTree) -> anyhow::Result<Synced> {
    let interrupted = CancellationToken::new();
    crate::cancel_on_signals(&interrupted)?;
    let landed = format!(
        "{}:{}",
        remote.named,
        escaped(&String::from_utf8_lossy(sync.dest.as_bytes()))
    );
    let opts = Opts {
        excludes: sync.excludes,
        ..Opts::default()
    };
    let sources = vec![sync.local.join(".")];
    let summary = put(remote, (sources, sync.dest), opts, &interrupted).await?;
    Ok(Synced { landed, summary })
}

/// The server's `sources` to `dest`.
async fn get(
    remote: &Remote,
    (sources, dest): (Sources, PathBuf),
    opts: Opts,
    interrupted: &CancellationToken,
) -> anyhow::Result<Summary> {
    let count = sources.paths().len();
    let request = Request::Copy(Copy::Get {
        sources,
        opts: opts.clone(),
    });
    let mut opened = Opened::dial(remote, &request).await?;
    let conn = opened.conn.clone();
    let items = async move { conn.accept_uni().await.ok() };
    let dest = (Ok(Dest::Path(dest)), count);
    let landing = sync::receive_on(dest, opts, items, &mut opened.control);
    let outcome = finished(&opened.conn, landing, interrupted).await;
    opened.close().await;
    outcome
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
    let sources = sources.into_iter().map(Source::Path).collect();
    let conn = opened.conn.clone();
    let replies = async move { conn.accept_uni().await.ok() };
    let sending = sync::send_on(Ok(sources), opts, &mut opened.control, replies);
    let outcome = finished(&opened.conn, sending, interrupted).await;
    opened.close().await;
    outcome
}

/// What `copying` on `conn` came to, unless a signal stopped it. A stream cut short by the
/// server closing the connection with a reason says that reason.
async fn finished(
    conn: &iroh::endpoint::Connection,
    copying: impl Future<Output = Result<Summary, Failure>>,
    interrupted: &CancellationToken,
) -> anyhow::Result<Summary> {
    tokio::select! {
        copied = copying => copied.map_err(|failure| {
            if failure.kind == FailKind::Truncated
                && crate::transport_iroh::closed_because(conn).is_some()
            {
                super::refusal(conn, &failure.into())
            } else {
                failure.into()
            }
        }),
        () = interrupted.cancelled() => Err(anyhow::anyhow!(INTERRUPTED)),
    }
}
