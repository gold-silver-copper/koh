//! The library behind the `koh` remote shell: `koh serve` hosts a PTY for allowlisted peers and
//! `koh connect` renders it with predictive local echo, reconnecting transparently.
//!
//! [`transport_iroh`] sets up endpoints and admission; [`identity`] loads identities
//! and their reset leases; [`keycmd`] is `koh id` and `koh key`; [`names`] names the servers and clients
//! a machine knows. [`proto`] is the wire protocol, [`events`] the input it carries;
//! [`terminal`], [`predict`] and [`pty`] the screen, the prediction and the PTY; [`server`] hosts
//! sessions and [`client`] renders them. [`bounded`] holds every queue.
//!
//! Production code is panic-free by construction: `Cargo.toml` forbids the panic lints, lossy casts
//! and unchecked arithmetic, and a `forbid` cannot be lifted locally. Tests may panic.
//!
//! The library exists so the binary, tests and fuzz targets share code; all of it is internal.

pub mod bounded;
pub mod client;
pub mod events;
pub mod identity;
pub mod keycmd;
pub mod log;
pub mod menu;
pub mod names;
pub mod predict;
pub mod proto;
pub mod pty;
pub mod server;
pub mod terminal;
pub mod transport_iroh;

#[cfg(test)]
mod test_runtime;

/// Cancel `token` on the first SIGTERM, SIGINT or SIGHUP, so `koh serve` drains and `koh connect`
/// restores the terminal instead of the process dying where it stands; the token returned is
/// cancelled on the next, when waiting longer is not wanted. Fails only if a handler cannot be
/// installed.
pub(crate) fn cancel_on_signals(
    token: &tokio_util::sync::CancellationToken,
) -> std::io::Result<tokio_util::sync::CancellationToken> {
    use tokio::signal::unix::SignalKind;
    let again = tokio_util::sync::CancellationToken::new();
    for kind in [
        SignalKind::terminate(),
        SignalKind::interrupt(),
        SignalKind::hangup(),
    ] {
        let mut signal = tokio::signal::unix::signal(kind)?;
        let (token, again) = (token.clone(), again.clone());
        #[expect(clippy::disallowed_methods, reason = "one task a signal kind")]
        tokio::spawn(async move {
            while signal.recv().await.is_some() {
                if token.is_cancelled() {
                    again.cancel();
                }
                token.cancel();
            }
        });
    }
    Ok(again)
}
