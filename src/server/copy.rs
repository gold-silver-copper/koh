//! `koh cp` on the server: send the paths a client asks for, or land what it sends, done in
//! process by [`crate::sync`] on a blocking thread, joined to the connection's streams by bounded
//! channels. Paths are taken as [`Place`] takes them.

use std::path::Path;
use std::pin::pin;

use iroh::endpoint::{Connection, RecvStream};
use tokio::sync::mpsc;

use super::place::{Place, Resolved};
use crate::request::RemotePath;
use crate::sync::{
    self, ChannelReader, ChannelWriter, Copy, Dest, FailKind, Failure, Reply, Source, Summary,
    Target, PIPE_DEPTH, REPLY_DEPTH,
};

/// Serve `copy` for the client on `conn` at `place`; `control` carries what the client sends
/// after its request: what it copies to the server, or its replies.
pub(super) async fn serve(conn: &Connection, control: RecvStream, copy: Copy, place: &Place) {
    match copy {
        Copy::Get { sources, opts } => {
            let resolved: Result<Vec<Source>, Failure> = sources
                .paths()
                .iter()
                .map(|path| source(place, path))
                .collect();
            get(conn, control, resolved, opts).await;
        }
        Copy::Put {
            dest,
            sources,
            opts,
        } => {
            let dest = dest_of(place, &dest);
            put(conn, control, dest, sources.get(), opts).await;
        }
    }
}

/// What `problem` is, as a copy's failure at `path`.
fn failure(path: &RemotePath, problem: &crate::request::Problem) -> Failure {
    let kind = match problem.kind {
        crate::request::ProblemKind::OutOfScope => FailKind::OutOfScope,
        crate::request::ProblemKind::NoHome => FailKind::NoHome,
        crate::request::ProblemKind::NoSuchJob
        | crate::request::ProblemKind::NoSuchSession
        | crate::request::ProblemKind::NameTaken
        | crate::request::ProblemKind::TooManyJobs
        | crate::request::ProblemKind::CouldNotStart
        | crate::request::ProblemKind::NotFound
        | crate::request::ProblemKind::Failed => FailKind::Other,
    };
    Failure::new(
        kind,
        Path::new(std::ffi::OsStr::new(&*String::from_utf8_lossy(
            path.as_bytes(),
        ))),
    )
}

fn source(place: &Place, path: &RemotePath) -> Result<Source, Failure> {
    match place.resolve(path).map_err(|p| failure(path, &p))? {
        Resolved::Path(path) => Ok(Source::Path(path)),
        Resolved::Beneath { root, path } => Ok(Source::Beneath { root, path }),
    }
}

fn dest_of(place: &Place, dest: &RemotePath) -> Result<Dest, Failure> {
    let dir = dest.as_bytes().ends_with(b"/");
    match place.resolve(dest).map_err(|p| failure(dest, &p))? {
        Resolved::Path(path) => {
            // A `/` at its end says it is a directory, which joining drops.
            let mut bytes = path.into_os_string();
            if dir && !bytes.as_encoded_bytes().ends_with(b"/") {
                bytes.push("/");
            }
            Ok(Dest::Path(bytes.into()))
        }
        Resolved::Beneath { root, path } => Ok(Dest::Beneath { root, path, dir }),
    }
}

/// Send `sources` to the client on a stream of its own, its replies coming on `replies`.
async fn get(
    conn: &Connection,
    replies: RecvStream,
    sources: Result<Vec<Source>, Failure>,
    opts: sync::Opts,
) {
    let Ok(mut send) = conn.open_uni().await else {
        return;
    };
    let (tx, rx) = mpsc::channel(PIPE_DEPTH);
    let (reply_tx, mut reply_rx) = mpsc::channel(REPLY_DEPTH);
    let sending = tokio::task::spawn_blocking(move || {
        let mut out = ChannelWriter(tx);
        match sources {
            Ok(sources) => {
                let mut answers = |wait: bool| {
                    if wait {
                        reply_rx.blocking_recv()
                    } else {
                        reply_rx.try_recv().ok()
                    }
                };
                sync::send(&sources, &opts, out, &mut answers).map(drop)
            }
            Err(failure) => {
                use std::io::Write as _;
                let item = crate::request::encode(&sync::Item::Failed(failure), sync::MAX_ITEM)
                    .map_err(std::io::Error::other)?;
                out.write_all(&item)
            }
        }
    });
    let pumping = sync::replies_from(replies, reply_tx);
    let (sent, ()) = tokio::join!(sync::to_stream(rx, &mut send), pumping);
    let _ = sending.await;
    if sent.is_ok() {
        super::linger(conn).await;
    }
}

/// Land what the client sends on `items` at `dest`, answering it, and tell it how that went.
async fn put(
    conn: &Connection,
    items: RecvStream,
    dest: Result<Dest, Failure>,
    count: usize,
    opts: sync::Opts,
) {
    let Ok(mut send) = conn.open_uni().await else {
        return;
    };
    let (tx, rx) = mpsc::channel(PIPE_DEPTH);
    let (reply_tx, reply_rx) = mpsc::channel(REPLY_DEPTH);
    let end_tx = reply_tx.clone();
    let mut landing = pin!(tokio::task::spawn_blocking(
        move || -> Result<Summary, Failure> {
            let (target, made): (Target, u64) = Target::resolve(&dest?, count)?;
            let mut answer = |reply: Reply| reply_tx.try_send(reply).is_ok();
            let mut summary = sync::receive(ChannelReader::new(rx), &target, &opts, &mut answer)?;
            summary.dirs = summary.dirs.saturating_add(made);
            Ok(summary)
        }
    ));
    let landed = async {
        // The receiver may be done before the stream is (it failed): the stream is then read no
        // further.
        let landed = tokio::select! {
            landed = &mut landing => landed,
            () = sync::from_stream(items, tx) => landing.await,
        };
        let outcome: Result<Summary, Failure> = landed.unwrap_or_else(|error| {
            tracing::error!(%error, "a copy's receiver failed");
            Err(Failure::new(FailKind::Other, Path::new("")))
        });
        if let Err(failure) = &outcome {
            tracing::info!(%failure, "a copy to the server failed");
        }
        let _ = end_tx.send(Reply::End(outcome)).await;
        // The last sender: the replies end with it.
        drop(end_tx);
    };
    // The answers go as they are made, while the receiver works.
    tokio::join!(landed, sync::replies_to(reply_rx, &mut send));
    super::linger(conn).await;
}
