//! The koh server.
//!
//! A connection says what it is for in its opening request ([`crate::request`]), and [`cli`]
//! admits it and serves that. A session's PTY and emulator live in a [`session`] task that
//! outlives its connections; each connection to one runs [`attach`]. A command (`koh exec`) runs
//! in [`exec`] for its connection alone; a job (`koh run`) in [`jobs`], for as long as it runs; a
//! copy (`koh cp`) in [`copy`]; a wait in [`wait`].

mod attach;
pub mod cli;
mod copy;
mod exec;
mod jobs;
pub mod marks;
mod place;
pub mod session;
mod wait;

pub use cli::{serve, ServeConfig};
pub use session::{Registry, SessionSpec};

/// How long the server waits, once a request is answered, for the client to close the connection
/// having read the answer: a close of the server's own could throw away what it had not read.
const LINGER: std::time::Duration = std::time::Duration::from_secs(10);

/// Send `msg` whole to the client on `conn`, on a stream of its own, at most `max` bytes.
async fn reply_at_most<T: serde::Serialize + Sync>(
    conn: &iroh::endpoint::Connection,
    msg: &T,
    max: usize,
) -> anyhow::Result<()> {
    let bytes = crate::request::encode(msg, max)?;
    let mut send = conn.open_uni().await?;
    send.write_all(&bytes).await?;
    send.finish()?;
    Ok(())
}

/// Send `msg` whole to the client on `conn`, on a stream of its own.
async fn reply<T: serde::Serialize + Sync>(
    conn: &iroh::endpoint::Connection,
    msg: &T,
) -> anyhow::Result<()> {
    reply_at_most(conn, msg, crate::request::MAX_REPLY).await
}

/// Answer `msg` and wait for the client to close the connection.
async fn answer<T: serde::Serialize + Sync>(conn: &iroh::endpoint::Connection, msg: &T) {
    if reply(conn, msg).await.is_ok() {
        linger(conn).await;
    }
}

/// Wait, at most [`LINGER`], for the client to close `conn` once it has what it asked for; then
/// close it.
async fn linger(conn: &iroh::endpoint::Connection) {
    let _ = tokio::time::timeout(LINGER, conn.closed()).await;
    conn.close(0u32.into(), b"");
}
