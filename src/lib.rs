//! The library behind the `koh` remote shell: `koh serve` hosts a PTY for allowlisted peers and
//! `koh connect` renders it with predictive local echo, reconnecting transparently.
//!
//! [`transport_iroh`] sets up endpoints, the key file and admission; [`identity`] loads identities
//! and their reset leases; [`keycmd`] is `koh id` and `koh key`; [`names`] names the servers and clients
//! a machine knows. [`proto`] is the wire protocol, [`events`] the input it carries;
//! [`terminal`], [`predict`] and [`pty`] the screen, the prediction and the PTY; [`server`] hosts
//! sessions and [`client`] renders them.
//!
//! Production code is panic-free by construction: `Cargo.toml` forbids the panic lints, lossy casts
//! and unchecked arithmetic, and a `forbid` cannot be lifted locally. Tests may panic.
//!
//! The library exists so the binary, tests and fuzz targets share code; all of it is internal.

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

/// Cancel `token` on the first of `signals` that arrives, so `koh serve` drains and `koh connect`
/// restores the terminal instead of the process dying where it stands. Fails only if a handler
/// cannot be installed.
pub(crate) fn cancel_on_signals(
    token: &tokio_util::sync::CancellationToken,
    signals: &[tokio::signal::unix::SignalKind],
) -> std::io::Result<()> {
    for &kind in signals {
        let mut signal = tokio::signal::unix::signal(kind)?;
        let token = token.clone();
        tokio::spawn(async move {
            if signal.recv().await.is_some() {
                token.cancel();
            }
        });
    }
    Ok(())
}
