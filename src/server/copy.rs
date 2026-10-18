//! `koh cp` on the server: send the paths a client asks for, or land the items it sends, done in
//! process by [`crate::copy`] on a blocking thread, joined to the connection's streams by a
//! bounded channel.
//!
//! Paths resolve as the server user's shell would take them: `~` and `~/…` in their home, and a
//! relative path relative to it.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::pin::pin;

use iroh::endpoint::{Connection, RecvStream};
use tokio::sync::mpsc;

use super::cli::Host;
use crate::copy::{self, ChannelReader, ChannelWriter, FailKind, Failure, Target, PIPE_DEPTH};
use crate::request::{Arity, Copy, RemotePath, Sources};

/// Serve `copy` for the client on `conn`; `control` carries the items of a copy to the server.
pub(super) async fn serve(conn: &Connection, control: RecvStream, copy: Copy, host: &Host) {
    let home = host.home.dir();
    match copy {
        Copy::Get(sources) => get(conn, &sources, home).await,
        Copy::Put { dest, arity } => put(conn, control, &dest, arity, home).await,
    }
}

/// Where `path` is, read as the server user's shell reads it, `home` theirs.
fn resolve(home: Option<&Path>, path: &RemotePath) -> Result<PathBuf, Failure> {
    let bytes = path.as_bytes();
    let os = |bytes| Path::new(OsStr::from_bytes(bytes));
    if bytes.starts_with(b"/") {
        return Ok(os(bytes).to_path_buf());
    }
    let in_home = match bytes {
        b"" | b"~" => b"",
        _ => bytes.strip_prefix(b"~/").unwrap_or(bytes),
    };
    let home = home.ok_or_else(|| Failure::new(FailKind::NoHome, os(bytes)))?;
    Ok(if in_home.is_empty() {
        home.to_path_buf()
    } else {
        home.join(os(in_home))
    })
}

/// Send `sources` to the client on a stream of its own.
async fn get(conn: &Connection, sources: &Sources, home: Option<PathBuf>) {
    let Ok(mut send) = conn.open_uni().await else {
        return;
    };
    let resolved: Result<Vec<PathBuf>, Failure> = sources
        .paths()
        .iter()
        .map(|path| resolve(home.as_deref(), path))
        .collect();
    let (tx, rx) = mpsc::channel(PIPE_DEPTH);
    let sending = tokio::task::spawn_blocking(move || match resolved {
        Ok(paths) => copy::send(&paths, ChannelWriter(tx)).map(drop),
        Err(failure) => copy::send_failure(&failure, ChannelWriter(tx)),
    });
    let sent = copy::to_stream(rx, &mut send).await;
    let _ = sending.await;
    if sent.is_ok() {
        super::linger(conn).await;
    }
}

/// Land what the client sends on `control` at `dest`, and tell it how that went.
async fn put(
    conn: &Connection,
    control: RecvStream,
    dest: &RemotePath,
    arity: Arity,
    home: Option<PathBuf>,
) {
    let dest = resolve(home.as_deref(), dest);
    let (tx, rx) = mpsc::channel(PIPE_DEPTH);
    let mut landing = pin!(tokio::task::spawn_blocking(move || {
        let target = Target::resolve(dest?, arity)?;
        copy::receive(ChannelReader::new(rx), &target).map(drop)
    }));
    // The receiver may be done before the stream is (it failed): the stream is then read no
    // further.
    let landed = tokio::select! {
        landed = &mut landing => landed,
        () = copy::from_stream(control, tx) => landing.await,
    };
    let outcome: Result<(), Failure> = landed.unwrap_or_else(|error| {
        tracing::error!(%error, "a copy's receiver failed");
        Err(Failure::new(FailKind::Other, Path::new("")))
    });
    if let Err(failure) = &outcome {
        tracing::info!(%failure, "a copy to the server failed");
    }
    if super::reply(conn, &outcome).await.is_ok() {
        super::linger(conn).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_resolves_as_the_users_shell_takes_it() {
        let home = Some(Path::new("/home/u"));
        let at = |path: &[u8]| resolve(home, &RemotePath::new(path.to_vec()).unwrap()).unwrap();
        assert_eq!(at(b""), Path::new("/home/u"));
        assert_eq!(at(b"~"), Path::new("/home/u"));
        assert_eq!(at(b"~/a b"), Path::new("/home/u/a b"));
        assert_eq!(at(b"x/y"), Path::new("/home/u/x/y"));
        assert_eq!(at(b"/etc/hosts"), Path::new("/etc/hosts"));
        // `~name` is no home of anyone's here: a name in the user's home.
        assert_eq!(at(b"~other"), Path::new("/home/u/~other"));
        let homeless = resolve(None, &RemotePath::new(b"~/x".to_vec()).unwrap());
        assert_eq!(homeless.unwrap_err().kind, FailKind::NoHome);
    }
}
