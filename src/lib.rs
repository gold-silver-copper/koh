//! The library behind the `koh` remote shell: `koh serve` hosts a PTY for allowlisted peers and
//! `koh connect` renders it with predictive local echo, reconnecting transparently.
//!
//! [`transport_iroh`] sets up endpoints; [`identity`] loads identities
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
pub mod copy;
pub mod events;
pub mod identity;
pub mod keycmd;
pub mod log;
pub mod menu;
pub mod names;
pub mod predict;
pub mod proto;
pub mod pty;
pub mod request;
pub mod server;
pub mod terminal;
pub mod transport_iroh;

#[cfg(test)]
mod test_runtime;

/// Cancel `token` on the first SIGTERM, SIGINT or SIGHUP, so `koh serve` drains and `koh connect`
/// restores the terminal instead of the process dying where it stands; the token returned is
/// cancelled on a later one ([`Shutdown`]), when waiting longer is not wanted. A SIGHUP ignored as
/// the process started (`nohup`) stays ignored. Fails only if a handler cannot be installed.
pub(crate) fn cancel_on_signals(
    token: &tokio_util::sync::CancellationToken,
) -> std::io::Result<tokio_util::sync::CancellationToken> {
    use tokio::signal::unix::{signal, SignalKind};
    // Read before the handler replaces it: the lowest bit of the `SigIgn` mask Linux and Android show
    // (elsewhere, never). The handler is installed even so: a program started later gets SIGHUP's
    // default at its `exec`, as a hosted shell must to hang up with its session.
    let nohup = std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        let mask = status.lines().find_map(|line| line.strip_prefix("SigIgn:"));
        mask.and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .is_some_and(|mask| mask & 1 == 1)
    });
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    let (draining, forced) = (token.clone(), tokio_util::sync::CancellationToken::new());
    let force = forced.clone();
    #[expect(clippy::disallowed_methods, reason = "the one signal task")]
    tokio::spawn(async move {
        let mut shutdown = Shutdown::default();
        loop {
            let name = tokio::select! {
                Some(()) = term.recv() => "SIGTERM",
                Some(()) = int.recv() => "SIGINT",
                Some(()) = hup.recv() => if nohup {
                    tracing::info!("SIGHUP ignored, as it was when koh started (nohup)");
                    continue;
                } else {
                    "SIGHUP"
                },
                else => return,
            };
            tracing::info!(signal = name, "shutting down");
            match shutdown.signal(std::time::Instant::now()) {
                Shutdown::Draining(_) => draining.cancel(),
                Shutdown::Forced => force.cancel(),
                Shutdown::Running => {}
            }
        }
    });
    Ok(forced)
}

/// Where a process is in shutting down, by the signals it got. Counted apart from what they
/// cancel: a drain the process began on its own (its endpoint closed) is not one a signal began.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Shutdown {
    #[default]
    Running,
    /// The first signal came, at this instant: drain.
    Draining(std::time::Instant),
    /// Another came, [`Shutdown::DEBOUNCE`] or more after the first: stop waiting.
    Forced,
}

impl Shutdown {
    /// Signals this close after the first are one event: a terminal closing sends its session a
    /// SIGHUP, and its shell sends another, and that must not skip the drain.
    const DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(1);

    /// A signal came at `now`: where that leaves the process.
    fn signal(&mut self, now: std::time::Instant) -> Self {
        *self = match *self {
            Self::Running => Self::Draining(now),
            Self::Draining(first) if now.saturating_duration_since(first) < Self::DEBOUNCE => {
                Self::Draining(first)
            }
            Self::Draining(_) | Self::Forced => Self::Forced,
        };
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::Shutdown;

    #[test]
    fn a_double_sighup_still_drains_and_a_later_signal_forces() {
        let t0 = std::time::Instant::now();
        let mut s = Shutdown::default();
        assert_eq!(s.signal(t0), Shutdown::Draining(t0));
        let echo = t0 + std::time::Duration::from_millis(5);
        assert_eq!(s.signal(echo), Shutdown::Draining(t0), "the same event");
        assert_eq!(s.signal(t0 + Shutdown::DEBOUNCE), Shutdown::Forced);
    }
}
