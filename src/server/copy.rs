//! `koh cp` on the server: send the paths a client asks for, or land what it sends, done in
//! process by [`crate::sync`]. Paths are taken as [`Place`] takes them.

use std::path::Path;

use iroh::endpoint::{Connection, RecvStream};

use super::place::{Place, Resolved};
use crate::request::{ProblemKind, RemotePath};
use crate::sync::{self, Copy, Dest, FailKind, Failure, Source};

/// Serve `copy` for the client on `conn` at `place`; `control` carries what the client sends
/// after its request: what it copies to the server, or its replies.
pub(super) async fn serve(conn: &Connection, control: RecvStream, copy: Copy, place: &Place) {
    let Ok(mut send) = conn.open_uni().await else {
        return;
    };
    match copy {
        Copy::Get { sources, opts } => {
            let sources = sources.paths().iter().map(|path| source(place, path));
            let sources = sources.collect();
            let _ = sync::send_on(sources, opts, &mut send, async { Some(control) }).await;
        }
        Copy::Put {
            dest,
            sources,
            opts,
        } => {
            let dest = (dest_of(place, &dest), sources.get());
            let input = async { Some(control) };
            if let Err(failure) = sync::receive_on(dest, opts, input, &mut send).await {
                tracing::info!(%failure, "a copy to the server failed");
            }
        }
    }
    super::linger(conn).await;
}

/// Where `path` is, or why it is none of this copy's.
fn resolve(place: &Place, path: &RemotePath) -> Result<Resolved, Failure> {
    place.resolve(path).map_err(|problem| {
        let kind = match problem.kind {
            ProblemKind::OutOfScope => FailKind::OutOfScope,
            ProblemKind::NoHome => FailKind::NoHome,
            ProblemKind::NoSuchJob
            | ProblemKind::NoSuchSession
            | ProblemKind::NameTaken
            | ProblemKind::TooManyJobs
            | ProblemKind::CouldNotStart
            | ProblemKind::NotFound
            | ProblemKind::Failed
            | ProblemKind::NoSuchDir
            | ProblemKind::NoSuchProgram => FailKind::Other,
        };
        let shown = String::from_utf8_lossy(path.as_bytes());
        Failure::new(kind, Path::new(&*shown))
    })
}

fn source(place: &Place, path: &RemotePath) -> Result<Source, Failure> {
    Ok(match resolve(place, path)? {
        Resolved::Path(path) => Source::Path(path),
        Resolved::Beneath { root, path } => Source::Beneath { root, path },
    })
}

fn dest_of(place: &Place, dest: &RemotePath) -> Result<Dest, Failure> {
    let dir = dest.as_bytes().ends_with(b"/");
    Ok(match resolve(place, dest)? {
        Resolved::Path(path) => {
            // A `/` at its end says it is a directory, which joining drops.
            let mut bytes = path.into_os_string();
            if dir && !bytes.as_encoded_bytes().ends_with(b"/") {
                bytes.push("/");
            }
            Dest::Path(bytes.into())
        }
        Resolved::Beneath { root, path } => Dest::Beneath { root, path, dir },
    })
}
