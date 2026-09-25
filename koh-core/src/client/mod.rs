//! The koh client: the session loop, abstracted over a [`ClientTerminal`].
//!
//! It runs either against the real terminal (the binary, via [`BackendTerminal`] over the
//! [`KohBackend`] tty) or against a scripted mock (integration tests) — no real TTY required for the
//! latter. The rendering path speaks only to [`KohBackend`] ([`backend`]).
//!
//! Terminal *input* (typed bytes) and *resize* ticks arrive as channels the caller wires up;
//! terminal *output* and *size* go through [`ClientTerminal`]. The binary's `main` connects a
//! [`KohBackend`] renderer + a raw-stdin reader + a `SIGWINCH` task; a test connects a capturing
//! mock + a scripted input channel.

pub mod backend;
pub mod cli;
mod io;
mod render;
mod session;

pub use crate::idcmd::{run_id, IdConfig};
pub use backend::{DefaultBackend, KohBackend};
pub use cli::{connect, BellHook, ConnectConfig};
pub(crate) use io::spawn_client_io;
pub use render::{InputModes, WindowState};
pub use session::{ClientSession, InputOutcome, TickResult};

use std::time::{Duration, Instant};

use crate::predict::{DisplayPreference, Overlay};
use crate::proto::{decode_frame, encode_client, Frame, MAX_FRAME, SESSION_ENDED};
use crate::terminal::TerminalScreen;
use crate::transport_iroh::{IrohChannel, ALPN};
use iroh::endpoint::{Connection, SendStream};
use iroh::{Endpoint, EndpointAddr};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// The window-title prefix mirrored onto the user's terminal so the OS title bar shows you're in a
/// koh session (mosh's `[mosh] `).
const KOH_TITLE_PREFIX: &str = "[koh] ";

/// The escape prefix (Ctrl-^); followed by '.' it disconnects the session.
pub(crate) const ESCAPE_PREFIX: u8 = 0x1e;
/// The escape suffix that suspends the client to the background (`Ctrl-^` then `Ctrl-Z`).
///
/// Mirrors mosh. In raw mode `Ctrl-Z` is a literal byte (no SIGTSTP from the tty), so the suspend
/// is driven through the escape machine instead.
pub(crate) const SUSPEND_KEY: u8 = 0x1a;

/// How long a single reconnect dial may run before it is abandoned and retried.
const RECONNECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Reconnect backoff: `BASE << min(attempt, 4)`, capped at `MAX`. [`backoff`] is only called for
/// `attempt > 0` (attempt 0 redials immediately), so the realized sequence is 1 → 2 → 4 → 8s.
const RECONNECT_BACKOFF_BASE: Duration = Duration::from_millis(500);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(8);
/// Minimum time a connection must stay up to count as "proven" and reset the reconnect backoff. A
/// connection that drops sooner than this — e.g. a malicious or compromised server that completes
/// the handshake then immediately closes — is treated like a failed dial: the attempt counter keeps
/// climbing and the next redial backs off, so such a server can't drive a tight reconnect/repaint
/// churn loop (K-03). A genuine mid-session drop after this dwell reconnects promptly.
const MIN_CONNECTION_DWELL: Duration = Duration::from_secs(5);

/// Wall-clock gap between two steady-loop iterations above which we assume the process was
/// **suspended** (Android deep-sleep / screen-off freezes the process) rather than merely busy.
///
/// The loop polls at least every ~50ms (`TickResult::wait_ms` is capped at 50), so a gap this large
/// can only mean the task was parked, unscheduled, for that whole span. On a phone that almost
/// always means the QUIC connection is now stale — the NAT mapping has likely expired and the
/// *server's* real-time idle timer has advanced — yet iroh's idle timer is driven by the **monotonic**
/// clock, which pauses across suspend, so iroh won't notice and can hold the dead connection for up
/// to its full ~5-minute idle timeout after wake. Detecting the freeze and reconnecting immediately
/// (reattaching to the retained server session) turns that ~5-minute hang into a ~1–2s redial.
///
/// 20s is ~400× the loop cadence, so normal scheduling jitter never trips it; a sub-20s glance rides
/// out on the existing connection (no visible reconnect). The cost of a false positive is only a
/// brief "reconnecting…" banner and a repaint back into the same session, so we bias low.
const STALE_AFTER_FREEZE: Duration = Duration::from_secs(20);

/// Whether a wall-clock gap between steady-loop iterations looks like a resume from a process
/// freeze (suspend), i.e. is at least [`STALE_AFTER_FREEZE`]. Pulled out so the threshold is
/// unit-testable without driving a whole session.
fn looks_like_resume_from_freeze(wall_gap: Duration) -> bool {
    wall_gap >= STALE_AFTER_FREEZE
}

/// Dials the server and awaits its admission ack, yielding a fresh [`IrohChannel`].
///
/// One instance is reused for the **initial** connection and for every **transparent reconnect**
/// after the link drops (e.g. a phone screen-off long enough that the QUIC connection idle-times
/// out). Re-dialing the same endpoint id reattaches to the detachable server session — the server
/// keeps the shell running and full-repaints the live screen onto the fresh connection — so the
/// user lands back exactly where they were instead of being dropped to a local shell.
pub struct IrohConnector {
    endpoint: Endpoint,
    target: EndpointAddr,
}

impl IrohConnector {
    /// A connector dialing `target` from `endpoint`.
    pub const fn new(endpoint: Endpoint, target: EndpointAddr) -> Self {
        Self { endpoint, target }
    }

    /// Connect to the server and await its admission ack. A server that rejects us (our node-id is
    /// not on its allowlist, or it's at capacity) closes the connection instead of admitting; that
    /// surfaces as an `Err` (the binary reports it before entering raw mode), so a rejected client
    /// fails fast rather than re-dialing forever.
    pub async fn connect(&self) -> anyhow::Result<IrohChannel> {
        let conn = match self.endpoint.connect(self.target.clone(), ALPN).await {
            Ok(conn) => conn,
            Err(e) if refused_our_alpn(&e) => {
                return Err(anyhow::Error::new(e).context(format!(
                    "the server does not speak this koh protocol ({}); upgrade koh on both ends",
                    String::from_utf8_lossy(ALPN)
                )));
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context("connecting to server (is your id on its allowlist?)"));
            }
        };
        if let Err(e) = crate::transport_iroh::admission::await_admission(&conn).await {
            // The server rejects with a specific application reason — "not authorized" / "server at
            // session capacity" — each pointing at a different operator fix. Surface that real reason
            // instead of a static guess. The reason is peer-controlled, so it is sanitized + capped.
            return Err(match server_close_reason(&conn) {
                Some(reason) => anyhow::Error::new(e)
                    .context(format!("server rejected the connection: {reason}")),
                None => anyhow::Error::new(e)
                    .context("server did not admit the connection (is your id on its allowlist?)"),
            });
        }
        Ok(IrohChannel::new(conn))
    }
}

/// Whether a dial failed because the server does not serve [`ALPN`]: the TLS handshake ended with
/// alert 120 (`no_application_protocol`), which QUIC reports as crypto error `0x178`. A server on
/// another koh protocol version refuses us this way, and pointing at the allowlist would mislead.
fn refused_our_alpn(error: &(dyn std::error::Error + 'static)) -> bool {
    use iroh::endpoint::{ConnectionError, TransportErrorCode};
    let no_alpn = TransportErrorCode::crypto(120);
    let mut next = Some(error);
    while let Some(e) = next {
        match e.downcast_ref::<ConnectionError>() {
            Some(ConnectionError::ConnectionClosed(close)) if close.error_code == no_alpn => {
                return true;
            }
            Some(ConnectionError::TransportError(t)) if t.code == no_alpn => return true,
            _ => {}
        }
        next = e.source();
    }
    false
}

/// The server's application close reason, if it rejected us with one. The reason is peer-controlled,
/// so it is control-char-stripped and length-capped before it can reach the user's terminal.
/// `close_reason()` is non-blocking (returns `None` if the peer didn't close with a reason), so this
/// can't hang the error path.
fn server_close_reason(conn: &iroh::endpoint::Connection) -> Option<String> {
    use iroh::endpoint::{ApplicationClose, ConnectionError};
    let ConnectionError::ApplicationClosed(ApplicationClose { reason, .. }) =
        conn.close_reason()?
    else {
        return None;
    };
    let cleaned: String = String::from_utf8_lossy(&reason)
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Reconnect backoff for a failed dial attempt (1-based `attempt`), in milliseconds.
fn backoff(attempt: u32) -> Duration {
    RECONNECT_BACKOFF_BASE
        .saturating_mul(1u32 << attempt.min(4))
        .min(RECONNECT_BACKOFF_MAX)
}

/// The reconnect attempt counter after a connection drops, given how long it stayed up (`dwell`).
///
/// A connection that lasted at least [`MIN_CONNECTION_DWELL`] proved itself, so the backoff resets
/// to 0 (a genuine mid-session drop reconnects promptly). A shorter-lived one — e.g. a server that
/// accepts then immediately closes — is treated like a failed dial: the counter increments
/// (saturating) so the next redial backs off, preventing a tight reconnect/repaint churn loop
/// (K-03). Pure so the branch logic is unit-testable without driving a real connection.
const fn next_attempt_after_drop(attempt: u32, dwell: Duration) -> u32 {
    if dwell.as_millis() >= MIN_CONNECTION_DWELL.as_millis() {
        0
    } else {
        attempt.saturating_add(1)
    }
}

/// Scan typed bytes for the disconnect escape (`Ctrl-^` then `.`) while reconnecting, mirroring
/// [`ClientSession`]'s prefix machine. `pending` carries the "saw a lone prefix" state across
/// calls; returns `true` once the user has typed the full quit sequence.
fn escape_quit(chunk: &[u8], pending: &mut bool) -> bool {
    for &b in chunk {
        if *pending {
            *pending = false;
            if b == b'.' {
                return true;
            }
        } else if b == ESCAPE_PREFIX {
            *pending = true;
        }
    }
    false
}

/// The out-of-band window state (title / icon / clipboard / bell) to mirror onto the real terminal.
fn window_state(screen: &TerminalScreen) -> WindowState<'_> {
    WindowState {
        title: screen.title(),
        icon: screen.icon(),
        clipboard: screen.clipboard(),
        bell_count: screen.bell_count(),
    }
}

/// Where the client paints frames and reads the window size.
///
/// The real binary draws to the terminal via a [`KohBackend`] ([`BackendTerminal`]); a test
/// captures cells/text as data.
pub trait ClientTerminal {
    /// Paint one frame. `state` is the authoritative synced screen (its window state and input
    /// modes are what the real terminal must mirror); `overlay` is the prediction overlay;
    /// `status` is the optional status line.
    fn render(
        &mut self,
        state: &TerminalScreen,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> std::io::Result<()>;

    /// The current window size as `(rows, cols)`.
    fn size(&self) -> std::io::Result<(u16, u16)>;

    /// Suspend the client to the background (the `Ctrl-^ Ctrl-Z` escape): restore the user's
    /// terminal to a usable cooked state, stop the process with `SIGTSTP`, and — once the user
    /// foregrounds it again (`SIGCONT`) — re-enter raw mode + the alternate screen so the caller can
    /// force a repaint. Blocks for the whole suspended duration (the entire process is stopped).
    ///
    /// Default: a no-op, so a scripted test terminal can never actually stop the test process; only
    /// the real [`BackendTerminal`] performs the suspend.
    fn suspend_resume(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The production [`ClientTerminal`], generic over a [`KohBackend`] (the binary's [`DefaultBackend`],
/// or a byte-capturing one in tests).
///
/// Puts the backend into raw mode + the alternate screen on [`enter`](Self::enter), restored on
/// drop. It owns the out-of-band ledger (`render::OutOfBand`) and paints the synced grid +
/// prediction overlay by driving the backend. The mode reset that restores the user's terminal on
/// drop and suspend lives in [`KohBackend::leave_alt_screen`].
pub struct BackendTerminal<B: KohBackend> {
    backend: B,
    /// Tracks the title / bell / input modes mirrored to the real terminal (see [`render::OutOfBand`]).
    oob: render::OutOfBand,
}

impl<B: KohBackend> BackendTerminal<B> {
    /// Take ownership of `backend`, enter raw mode + the alternate screen, and hide the cursor.
    /// `clipboard_enabled` gates honoring remote OSC-52 clipboard writes (default off; L-1).
    pub fn enter(mut backend: B, clipboard_enabled: bool) -> std::io::Result<Self> {
        backend.enter_raw_mode()?;
        // Build the struct, then enter the alternate screen via the backend — the enter/leave escape
        // sequences live only in `KohBackend` (`enter_alt_screen` / `leave_alt_screen`).
        // `enter_alt_screen` writes to the backend and never reads `oob`, so building first is inert.
        let mut this = Self {
            backend,
            oob: render::OutOfBand::with_title_prefix(KOH_TITLE_PREFIX.to_string())
                .with_clipboard(clipboard_enabled),
        };
        this.backend.enter_alt_screen()?;
        Ok(this)
    }
}

impl<B: KohBackend> ClientTerminal for BackendTerminal<B> {
    fn render(
        &mut self,
        state: &TerminalScreen,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> std::io::Result<()> {
        // Mirror the out-of-band terminal state (title/icon/clipboard/bell/modes) onto the real
        // terminal, then paint the cell grid.
        self.oob.emit(
            &mut self.backend,
            InputModes::from(state.screen()),
            window_state(state),
        )?;
        render::render(&mut self.backend, state.screen(), overlay, status)
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        self.backend.size()
    }

    fn suspend_resume(&mut self) -> std::io::Result<()> {
        // Restore the user's terminal (reset forwarded modes, show cursor, leave the alt screen)
        // and return to cooked mode, so the suspended job sits at a normal shell.
        self.backend.leave_alt_screen()?;
        self.backend.leave_raw_mode()?;
        let _ = self
            .backend
            .write_bytes("\n[koh suspended — run `fg` to resume]\n".as_bytes());
        let _ = self.backend.flush();
        // Stop ourselves. SIGTSTP halts the whole process; control returns here only once the user
        // foregrounds the job (SIGCONT). `nix::raise` keeps the crate `forbid(unsafe)`.
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGTSTP)
            .map_err(std::io::Error::other)?;
        // Foregrounded again: re-enter raw mode + the alternate screen and force the next frame to
        // re-assert the title / clipboard / input modes (the terminal was reset while we were away).
        self.backend.enter_raw_mode()?;
        self.backend.enter_alt_screen()?;
        self.oob.invalidate();
        Ok(())
    }
}

impl<B: KohBackend> Drop for BackendTerminal<B> {
    fn drop(&mut self) {
        // Reset forwarded modes, show the cursor, and leave the alternate screen so the user's
        // terminal isn't left with mouse reporting on (stray click bytes at the prompt), then return
        // to cooked mode. Both are best-effort on the teardown path.
        let _ = self.backend.leave_alt_screen();
        let _ = self.backend.leave_raw_mode();
    }
}

/// Run a client session, **transparently reconnecting** after the link drops.
///
/// Drives the session against `initial` (the already-established first connection); when that
/// connection dies — typically a phone screen-off long enough that QUIC idle-times-out — it
/// re-dials via `connector` and reattaches to the same detachable server session instead of
/// exiting. A fresh [`ClientSession`] is built per connection (the server uses a fresh transport
/// per attach and full-repaints the live screen), so the user resumes exactly where they were.
/// While reconnecting, the last screen is held under a "reconnecting…" banner and the quit escape
/// (`Ctrl-^ .`) still works.
///
/// This is the thin I/O shell around [`ClientSession`]: it owns the `tokio::select!`, channels,
/// sleeps, datagram send/recv/close, and `term.size()`/`render()`, delegating every protocol
/// decision to the session's step methods.
///
/// `input_rx` carries raw typed bytes (the caller must keep its sender alive for the session;
/// when it closes, the session ends). `resize_rx` carries resize *ticks* — each one prompts the
/// loop to re-read the current size from `term`; keep its sender alive even if you never resize,
/// so the loop doesn't spin on a closed channel. `initial_size` (`(rows, cols)`) seeds the size if
/// `term.size()` is unavailable.
/// Returns the remote shell's exit code (`Some`) when the session ended because the shell exited,
/// or `None` for a local quit (`Ctrl-^ .`, a closed input channel, or a cancelled `shutdown`) — so
/// the binary can exit with the remote status.
///
/// `shutdown` is a [`CancellationToken`] the caller cancels on a fatal signal (SIGTERM/SIGINT/
/// SIGHUP): the loop then returns as if the user quit, so `term` is dropped and the terminal is
/// restored — rather than the process dying at default signal disposition with the TTY left raw.
/// `bell`, if set, runs on every remote bell (KB-01).
#[expect(
    clippy::too_many_arguments,
    reason = "the I/O shell wires up the channel, connector, prediction policy, size, the two \
              input/resize channels, the terminal, the shutdown token and the bell hook — each a distinct \
              collaborator; bundling them into a struct would only move the list, not shorten it"
)]
pub async fn run_client<T: ClientTerminal>(
    initial: IrohChannel,
    connector: IrohConnector,
    pref: DisplayPreference,
    initial_size: (u16, u16),
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    mut resize_rx: mpsc::Receiver<()>,
    mut term: T,
    shutdown: CancellationToken,
    mut bell: Option<BellHook>,
) -> anyhow::Result<Option<u32>> {
    let mut channel = initial;
    // Persists ACROSS reconnect cycles (not reset per connection) so a server that keeps dropping us
    // fast can't escape the backoff by completing each handshake — only a connection that proves
    // itself (stays up past `MIN_CONNECTION_DWELL_MS`) resets it (K-03).
    let mut attempt: u32 = 0;
    loop {
        // A fresh session per (re)connection mirrors the server's fresh-transport-per-attach, which
        // full-repaints the live screen; re-seed the size from the terminal each time.
        let (rows, cols) = term.size().unwrap_or(initial_size);
        let mut session = ClientSession::new(pref, rows, cols);

        let conn_started = Instant::now();
        match drive_connection(
            &channel,
            &mut session,
            &mut term,
            &mut input_rx,
            &mut resize_rx,
            &shutdown,
            bell.as_mut(),
        )
        .await?
        {
            Disposition::Quit => {
                channel.close(0, b"client exit");
                return Ok(None);
            }
            Disposition::Ended(code) => {
                channel.close(0, b"client exit");
                return Ok(code);
            }
            Disposition::LinkLost => {
                channel.close(0, b"reconnecting");
                // Did this connection prove itself? A drop after a real session resets the backoff
                // (prompt reattach); a drop sooner than `MIN_CONNECTION_DWELL` is treated like a
                // failed dial — bump the attempt so `reconnect` backs off before redialing, so an
                // accept-then-instantly-close server can't spin us in a tight loop (K-03).
                let dwell = conn_started.elapsed();
                attempt = next_attempt_after_drop(attempt, dwell);
                match reconnect(
                    &connector,
                    &mut term,
                    &mut input_rx,
                    &session,
                    &shutdown,
                    &mut attempt,
                )
                .await
                {
                    ReconnectOutcome::Connected(c) => channel = c,
                    ReconnectOutcome::Quit => return Ok(None),
                }
            }
        }
    }
}

/// Why [`drive_connection`] returned: [`run_client`] decides whether to exit or reconnect.
enum Disposition {
    /// The user disconnected (`Ctrl-^ .`) or the input channel closed — exit, no reconnect.
    Quit,
    /// The server announced a clean shutdown; carry the remote shell's exit code out.
    Ended(Option<u32>),
    /// The connection dropped mid-session — the caller should reconnect and reattach.
    LinkLost,
}

/// Drive one connection: the steady send/render/select loop, returning a [`Disposition`] instead
/// of breaking — so the caller can reconnect on [`Disposition::LinkLost`] rather than exiting.
///
/// The client's stream is written by its own task behind a bounded queue, and frames are read by
/// their own tasks, so nothing here ever waits on the network: the keyboard, and with it the quit
/// escape, stays live even when the server stops reading.
async fn drive_connection<T: ClientTerminal>(
    channel: &IrohChannel,
    session: &mut ClientSession,
    term: &mut T,
    input_rx: &mut mpsc::Receiver<Vec<u8>>,
    resize_rx: &mut mpsc::Receiver<()>,
    shutdown: &CancellationToken,
    mut bell: Option<&mut BellHook>,
) -> anyhow::Result<Disposition> {
    let conn = channel.connection();
    let Ok(send) = conn.open_uni().await else {
        return Ok(Disposition::LinkLost);
    };
    let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE);
    let _writer = AbortOnDrop(tokio::spawn(write_client_stream(send, writer_rx)));
    let (frame_tx, mut frame_rx) = mpsc::channel::<Frame>(FRAME_QUEUE);
    let _reader = AbortOnDrop(tokio::spawn(read_frames(conn.clone(), frame_tx)));

    // Wall-clock checkpoint for freeze detection. `Instant` (and iroh's idle timer) are monotonic
    // and PAUSE across a system suspend, so they can't tell a long screen-off from a momentary
    // stall; `SystemTime` keeps real time across suspend. A large gap between two (≤50ms-cadence)
    // iterations therefore fingerprints a resume-from-freeze (see `STALE_AFTER_FREEZE`).
    let mut last_wall = std::time::SystemTime::now();
    // Last RTT we emitted a debug log for, so an operator with `RUST_LOG=koh=debug` can see whether a
    // sluggish session is the link (RTT climbing) or the server — without spamming a line per tick.
    // Only a meaningful change (>= 30 ms) is logged.
    let mut last_logged_rtt: Option<Duration> = None;
    loop {
        // If real time jumped far ahead of our ≤50ms polling cadence, the process was suspended
        // (phone screen-off). The connection is almost certainly dead, so proactively drop it and
        // reconnect — reattaching to the retained server session — instead of waiting out iroh's
        // clock-skewed ~5-minute idle timeout. (A backwards clock step, e.g. NTP, reads as no gap.)
        let wall_now = std::time::SystemTime::now();
        let wall_gap = wall_now.duration_since(last_wall).unwrap_or(Duration::ZERO);
        last_wall = wall_now;
        if looks_like_resume_from_freeze(wall_gap) {
            tracing::info!(
                frozen_secs = wall_gap.as_secs(),
                "detected resume from a process freeze (suspend/screen-off); forcing a reconnect"
            );
            return Ok(Disposition::LinkLost);
        }

        let now = Instant::now();
        let rtt = channel.rtt();
        if let Some(rtt) = rtt {
            if last_logged_rtt.is_none_or(|prev| prev.abs_diff(rtt) >= Duration::from_millis(30)) {
                tracing::debug!(rtt_ms = rtt.as_millis(), "link rtt");
                last_logged_rtt = Some(rtt);
            }
        }
        let tick = session.on_tick(now, rtt);

        // Repaint on new content, while a banner is up, or once more to clear a stale banner.
        let status_now = tick.status.is_some();
        if session.dirty || status_now || session.status_was_shown {
            term.render(session.state(), &session.overlay(), tick.status.as_deref())?;
            session.status_was_shown = status_now;
            session.dirty = false;
            // Run the bell hook when the remote bell count climbs (rate-limited inside). Only once
            // a server frame has arrived: the first paint is the blank default, and the first
            // synced frame primes the hook so bells from before this attach don't fire.
            if let Some(hook) = bell.as_deref_mut() {
                if session.synced() {
                    let win = session.window_state();
                    hook.prime(win.bell_count);
                    hook.observe_and_fire(win.bell_count, win.title, now);
                }
            }
        }

        if session.exited() {
            let code = session.state().exit_code();
            return Ok(end_session(term, session, shutdown, code).await);
        }

        tokio::select! {
            // Input-priority: a queued screen update must never starve local keystrokes. The
            // server loop is the mirror image and is deliberately NOT biased.
            biased;

            maybe = input_rx.recv() => {
                match maybe {
                    Some(chunk) => match session.on_input(Instant::now(), &chunk) {
                        InputOutcome::Quit => return Ok(Disposition::Quit),
                        InputOutcome::Suspend => {
                            // Ctrl-^ Ctrl-Z: hand the terminal back to the shell, stop, and on
                            // resume re-enter raw mode and force a full repaint. A no-op for the
                            // scripted test terminal.
                            term.suspend_resume()?;
                            session.dirty = true;
                            // The process was parked for the whole foreground-suspend (possibly
                            // minutes); reset the freeze checkpoint so that deliberate suspend isn't
                            // misread as a screen-off freeze and forced into a needless reconnect.
                            last_wall = std::time::SystemTime::now();
                        }
                        InputOutcome::Forwarded => {}
                    },
                    None => return Ok(Disposition::Quit), // input source closed
                }
            }
            // Graceful shutdown: a SIGTERM/SIGINT/SIGHUP (delivered via this token) returns Quit so
            // `run_client` unwinds and drops the terminal — restoring cooked mode + the main screen
            // — instead of the process dying at default disposition with the TTY left in raw mode.
            () = shutdown.cancelled() => return Ok(Disposition::Quit),
            permit = writer_tx.reserve(), if session.has_outgoing() => {
                let Ok(permit) = permit else {
                    // The writer ended: the stream, and so the connection, is gone.
                    return Ok(closed_disposition(conn, session));
                };
                if let Some(msg) = session.pop_outgoing() {
                    match encode_client(&msg) {
                        Ok(bytes) => permit.send(bytes),
                        Err(e) => tracing::warn!(error = %e, "dropping an unencodable message"),
                    }
                }
            }
            frame = frame_rx.recv() => {
                let Some(frame) = frame else {
                    // The frame reader ended because the connection closed.
                    let disposition = closed_disposition(conn, session);
                    if let Disposition::Ended(code) = disposition {
                        return Ok(end_session(term, session, shutdown, code).await);
                    }
                    tracing::info!(reason = ?conn.close_reason(), "link lost; will reconnect");
                    return Ok(disposition);
                };
                session.on_frame(Instant::now(), &frame);
            }
            maybe = resize_rx.recv() => {
                // A resize tick: read the fresh size from the terminal and propagate it. A closed
                // resize channel is fine; keep its sender alive to avoid spinning.
                if maybe.is_some() {
                    if let Ok((rows, cols)) = term.size() {
                        session.on_resize(rows, cols);
                    }
                }
            }
            () = tokio::time::sleep(tick.wait) => {}
        }
    }
}

/// How many encoded messages may wait for the client's stream writer.
const WRITER_QUEUE: usize = 64;
/// How many decoded frames may wait for the connection loop.
const FRAME_QUEUE: usize = 16;

/// Aborts a task when dropped, so a connection's helper tasks end with it.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Write queued messages to the client's stream until the queue or the stream closes.
async fn write_client_stream(mut send: SendStream, mut queue: mpsc::Receiver<Vec<u8>>) {
    while let Some(bytes) = queue.recv().await {
        if send.write_all(&bytes).await.is_err() {
            return;
        }
    }
    let _ = send.finish();
}

/// Accept the server's frame streams, each read on its own task so a stalled or reset stream never
/// holds up a newer frame. Ends when the connection closes.
async fn read_frames(conn: Connection, frames: mpsc::Sender<Frame>) {
    while let Ok(mut recv) = conn.accept_uni().await {
        let frames = frames.clone();
        tokio::spawn(async move {
            // A reset (superseded) or malformed frame is simply not delivered.
            let Ok(bytes) = recv.read_to_end(MAX_FRAME).await else {
                return;
            };
            match decode_frame(&bytes) {
                Ok(frame) => {
                    let _ = frames.send(frame).await;
                }
                Err(e) => tracing::debug!(error = %e, "dropping an undecodable frame"),
            }
        });
    }
}

/// What a closed connection means: the server ended the session (its shell exited), or the link was
/// lost and the client should reconnect.
fn closed_disposition(conn: &Connection, session: &ClientSession) -> Disposition {
    use iroh::endpoint::{ApplicationClose, ConnectionError};
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(ApplicationClose { error_code, reason }))
            if error_code.into_inner() == 0 && reason.as_ref() == SESSION_ENDED =>
        {
            Disposition::Ended(session.state().exit_code())
        }
        _ => Disposition::LinkLost,
    }
}

/// Paint the "session ended" banner, linger briefly so it is seen, and report the exit code.
async fn end_session<T: ClientTerminal>(
    term: &mut T,
    session: &ClientSession,
    shutdown: &CancellationToken,
    code: Option<u32>,
) -> Disposition {
    let _ = term.render(
        session.state(),
        &Overlay::empty(),
        Some("[koh] session ended"),
    );
    // Stay responsive to a SIGTERM/SIGINT/SIGHUP right after the shell exits, so an impatient
    // signal restores the TTY now instead of after the dwell.
    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(400)) => {}
        () = shutdown.cancelled() => {}
    }
    Disposition::Ended(code)
}

/// The result of a [`reconnect`] loop.
enum ReconnectOutcome {
    /// A fresh connection was established; resume the session on it.
    Connected(IrohChannel),
    /// The user disconnected (`Ctrl-^ .`) or input closed while reconnecting — exit.
    Quit,
}

/// Re-dial the server with capped exponential backoff after the link drops, painting a
/// "reconnecting…" banner over the last screen and staying responsive to the quit escape.
///
/// Retries indefinitely (an outage may outlast many attempts, mosh-style); the user can always
/// `Ctrl-^ .` to give up. A single dial is bounded by [`RECONNECT_CONNECT_TIMEOUT`] and is *not*
/// cancelled by banner repaints or non-quit keystrokes — it is pinned and polled in place — so a
/// slow dial still completes.
async fn reconnect<T: ClientTerminal>(
    connector: &IrohConnector,
    term: &mut T,
    input_rx: &mut mpsc::Receiver<Vec<u8>>,
    last: &ClientSession,
    shutdown: &CancellationToken,
    attempt: &mut u32,
) -> ReconnectOutcome {
    let started = Instant::now();
    let mut pending_escape = false;
    let quit_hint = " (Ctrl-^ . to quit)";
    'attempt: loop {
        // Back off BEFORE dialing whenever we've already failed a dial or the previous connection
        // dropped too fast (`*attempt > 0`). The caller seeds `*attempt` from the just-dropped
        // connection's dwell, so a server that completes the handshake then immediately closes is
        // backed off here rather than redialed instantly — closing the tight-loop hole (K-03). On a
        // proven-then-dropped connection `*attempt == 0`, so a normal reconnect dials at once. The
        // wait stays responsive to the quit escape / shutdown and keeps the banner clock ticking.
        if *attempt > 0 {
            let wait_until = Instant::now()
                .checked_add(backoff(*attempt))
                .unwrap_or_else(Instant::now);
            while Instant::now() < wait_until {
                let banner = format!(
                    "[koh] disconnected — reconnecting… {}s{quit_hint}",
                    started.elapsed().as_secs()
                );
                let _ = term.render(last.state(), &Overlay::empty(), Some(banner.as_str()));
                let remaining = wait_until.saturating_duration_since(Instant::now());
                tokio::select! {
                    biased;
                    maybe = input_rx.recv() => match maybe {
                        Some(chunk) => {
                            if escape_quit(&chunk, &mut pending_escape) {
                                return ReconnectOutcome::Quit;
                            }
                        }
                        None => return ReconnectOutcome::Quit,
                    },
                    _ = shutdown.cancelled() => return ReconnectOutcome::Quit,
                    _ = tokio::time::sleep(remaining.min(Duration::from_secs(1))) => {}
                }
            }
        }
        let dial = tokio::time::timeout(RECONNECT_CONNECT_TIMEOUT, connector.connect());
        tokio::pin!(dial);
        loop {
            let banner = format!(
                "[koh] disconnected — reconnecting… {}s{quit_hint}",
                started.elapsed().as_secs()
            );
            let _ = term.render(last.state(), &Overlay::empty(), Some(banner.as_str()));

            tokio::select! {
                biased;

                maybe = input_rx.recv() => {
                    match maybe {
                        Some(chunk) => {
                            if escape_quit(&chunk, &mut pending_escape) {
                                return ReconnectOutcome::Quit;
                            }
                        }
                        None => return ReconnectOutcome::Quit, // input source closed
                    }
                }

                res = &mut dial => {
                    match res {
                        Ok(Ok(channel)) => return ReconnectOutcome::Connected(channel),
                        Ok(Err(e)) => tracing::info!(reason = %e, attempt = *attempt, "reconnect dial failed"),
                        Err(_) => tracing::info!(attempt = *attempt, "reconnect dial timed out"),
                    }
                    // Bump the attempt; the top-of-loop backoff waits before the next dial.
                    *attempt = (*attempt).saturating_add(1);
                    continue 'attempt;
                }

                // Honor a SIGTERM/SIGINT/SIGHUP even mid-reconnect, so the terminal is restored.
                _ = shutdown.cancelled() => return ReconnectOutcome::Quit,

                _ = tokio::time::sleep(Duration::from_secs(1)) => { /* tick the banner clock */ }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_on_another_protocol_is_reported_as_such() {
        crate::test_runtime::current_thread().block_on(async {
            // A server that only speaks the previous protocol's ALPN refuses the TLS handshake. The
            // error must say so, not blame the allowlist.
            use crate::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr};
            let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(generate_secret_key())
                .alpns(vec![b"koh/iroh/2".to_vec()])
                .bind()
                .await
                .expect("bind old-protocol server");
            let addr = loopback_addr(&server);
            let accept = tokio::spawn(async move {
                if let Some(incoming) = server.accept().await {
                    let _ = incoming.await;
                }
                server
            });
            let client = bind_endpoint_local(generate_secret_key(), false)
                .await
                .expect("bind client");
            let error = match IrohConnector::new(client, addr).connect().await {
                Ok(_) => panic!("an old-protocol server must refuse the handshake"),
                Err(e) => format!("{e:#}"),
            };
            assert!(
                error.contains("does not speak this koh protocol (koh/3)"),
                "{error}"
            );
            assert!(!error.contains("allowlist"), "{error}");
            let _ = accept.await;
        });
    }

    #[test]
    fn escape_quit_matches_the_session_machine_across_chunks() {
        // The reconnect-path escape detector must agree with `ClientSession`'s prefix machine.
        let mut p = false;
        assert!(!escape_quit(b"hello", &mut p), "plain bytes never quit");
        assert!(!p);
        // Prefix + '.' in one chunk quits.
        assert!(escape_quit(&[ESCAPE_PREFIX, b'.'], &mut p));
        // Prefix split across chunks: state carries over, then '.' quits.
        p = false;
        assert!(!escape_quit(&[ESCAPE_PREFIX], &mut p));
        assert!(p, "a lone prefix leaves us pending");
        assert!(escape_quit(b".", &mut p));
        // Prefix then a non-'.' byte does NOT quit and clears the pending state.
        p = false;
        assert!(!escape_quit(&[ESCAPE_PREFIX, b'x'], &mut p));
        assert!(!p, "prefix + non-dot resets pending");
        assert!(!escape_quit(b".", &mut p), "a later lone '.' must not quit");
    }

    #[test]
    fn reconnect_backoff_grows_then_caps() {
        // 1-based attempts: 1s, 2s, 4s, 8s, then capped at 8s — never below base, never above max.
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(3), Duration::from_secs(4));
        assert_eq!(backoff(4), RECONNECT_BACKOFF_MAX);
        assert_eq!(backoff(5), RECONNECT_BACKOFF_MAX);
        assert_eq!(
            backoff(99),
            RECONNECT_BACKOFF_MAX,
            "shift is clamped, no overflow"
        );
    }

    #[test]
    fn dwell_gate_resets_on_proven_connection_and_climbs_on_flap() {
        // K-03: a connection that lasted >= the dwell threshold proved itself -> backoff resets to 0
        // (prompt reattach), regardless of the prior attempt count.
        assert_eq!(next_attempt_after_drop(0, MIN_CONNECTION_DWELL), 0);
        assert_eq!(next_attempt_after_drop(5, MIN_CONNECTION_DWELL), 0);
        assert_eq!(
            next_attempt_after_drop(5, MIN_CONNECTION_DWELL + Duration::from_secs(10)),
            0
        );
        // A connection that dropped before the threshold (accept-then-close server) is a flap:
        // the counter climbs so the next redial backs off.
        assert_eq!(next_attempt_after_drop(0, Duration::ZERO), 1);
        assert_eq!(
            next_attempt_after_drop(
                3,
                MIN_CONNECTION_DWELL
                    .checked_sub(Duration::from_millis(1))
                    .unwrap(),
            ),
            4
        );
        // Saturates rather than overflowing under a sustained flapping server.
        assert_eq!(next_attempt_after_drop(u32::MAX, Duration::ZERO), u32::MAX);
    }

    #[test]
    fn freeze_detection_fires_only_on_a_real_suspend_gap() {
        // A normal loop cadence (the steady loop polls at least every ~50ms) must never look like a
        // freeze, so an active session is never needlessly torn down...
        assert!(!looks_like_resume_from_freeze(Duration::from_millis(0)));
        assert!(!looks_like_resume_from_freeze(Duration::from_millis(50)));
        assert!(!looks_like_resume_from_freeze(Duration::from_secs(5)));
        // ...a sub-threshold glance still rides out on the existing connection...
        assert_eq!(STALE_AFTER_FREEZE, Duration::from_secs(20));
        assert!(!looks_like_resume_from_freeze(Duration::from_secs(19)));
        // ...but a multi-second-to-minutes suspend (phone screen-off) forces a proactive reconnect.
        assert!(looks_like_resume_from_freeze(STALE_AFTER_FREEZE));
        assert!(looks_like_resume_from_freeze(Duration::from_secs(300)));
    }

    #[test]
    fn backend_terminal_render_through_the_trait_matches_render_directly() {
        // `ClientTerminal` for `BackendTerminal` is a pure delegation —
        // the bytes are identical to calling the out-of-band ledger and `render::render` by hand.
        use crate::client::backend::CaptureBackend;
        let screen = TerminalScreen::from_bytes(
            24,
            80,
            b"\x1b]2;the title\x1b\\\x1b[?2004hhello \x1b[31mred\x1b[m\x07",
        );
        // Through the trait.
        let mut via_trait = BackendTerminal {
            backend: CaptureBackend::default(),
            oob: render::OutOfBand::with_title_prefix(KOH_TITLE_PREFIX.to_string()),
        };
        via_trait
            .render(&screen, &Overlay::empty(), Some("status"))
            .unwrap();
        // By hand.
        let mut direct = CaptureBackend::default();
        let mut oob = render::OutOfBand::with_title_prefix(KOH_TITLE_PREFIX.to_string());
        oob.emit(
            &mut direct,
            InputModes::from(screen.screen()),
            window_state(&screen),
        )
        .unwrap();
        render::render(
            &mut direct,
            screen.screen(),
            &Overlay::empty(),
            Some("status"),
        )
        .unwrap();
        assert_eq!(via_trait.backend.bytes, direct.bytes);
        assert_ne!(via_trait.backend.bytes, b"");
    }
}
