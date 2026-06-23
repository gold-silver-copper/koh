//! Library surface of `koh-client`: the session loop, abstracted over a [`ClientTerminal`]
//! so it can run either against the real terminal (the binary, via [`TerminaTerminal`]) or
//! against a scripted mock (integration tests) — no real TTY required for the latter.
//!
//! Terminal *input* (typed bytes) and *resize* ticks arrive as channels the caller wires up;
//! terminal *output* and *size* go through [`ClientTerminal`]. The binary's `main` connects the
//! termina renderer + a raw-stdin reader + a `SIGWINCH` task; a test connects a capturing mock
//! + a scripted input channel.

pub mod cli;
mod render;

pub use cli::{connect, run_id, ConnectArgs, IdArgs};

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use iroh::{Endpoint, EndpointAddr};
use koh_input::UserInput;
use koh_predict::{DisplayPreference, Overlay, PredictionEngine};
use koh_ssp::{RecvOutcome, Transport, SHUTDOWN_SENTINEL};
use koh_terminal::TerminalScreen;
use koh_transport_iroh::{IrohChannel, MonoClock, ALPN};
use secrecy::{ExposeSecret, SecretString};
use termina::escape::csi::{Csi, DecPrivateMode, DecPrivateModeCode, Mode};
use termina::{PlatformTerminal, Terminal as _};
use tokio::sync::mpsc;

pub use render::render;

/// The escape prefix (Ctrl-^); followed by '.' it disconnects the session.
pub const ESCAPE_PREFIX: u8 = 0x1e;

/// How long a single reconnect dial may run before it is abandoned and retried.
const RECONNECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Reconnect backoff: `BASE << min(attempt, 4)`, capped at `MAX` (0.5s → 1 → 2 → 4 → 8s).
const RECONNECT_BACKOFF_BASE_MS: u64 = 500;
const RECONNECT_BACKOFF_MAX_MS: u64 = 8_000;

/// Dials the server and replays the passphrase handshake, yielding a fresh [`IrohChannel`].
///
/// One instance is reused for the **initial** connection and for every **transparent reconnect**
/// after the link drops (e.g. a phone screen-off long enough that the QUIC connection idle-times
/// out). Re-dialing the same endpoint id reattaches to the detachable server session — the server
/// keeps the shell running and full-repaints the live screen onto the fresh connection — so the
/// user lands back exactly where they were instead of being dropped to a local shell.
pub struct IrohConnector {
    endpoint: Endpoint,
    target: EndpointAddr,
    /// The optional passphrase second factor, shared (so it survives across reconnect dials) and
    /// held as a `SecretString` (zeroized on drop, never logged); exposed only at the KDF call.
    passphrase: Arc<Option<SecretString>>,
}

impl IrohConnector {
    pub fn new(
        endpoint: Endpoint,
        target: EndpointAddr,
        passphrase: Arc<Option<SecretString>>,
    ) -> Self {
        Self {
            endpoint,
            target,
            passphrase,
        }
    }

    /// Connect to the server and complete the passphrase handshake. Surfaces a bad-allowlist or
    /// wrong-passphrase failure as an `Err` (the binary reports it before entering raw mode).
    pub async fn connect(&self) -> anyhow::Result<IrohChannel> {
        let conn = self
            .endpoint
            .connect(self.target.clone(), ALPN)
            .await
            .context("connecting to server (is your id on its allowlist?)")?;
        let pass = self
            .passphrase
            .as_ref()
            .as_ref()
            .map(SecretString::expose_secret);
        koh_transport_iroh::auth::handshake_client(&conn, pass)
            .await
            .context("passphrase handshake (wrong or missing --passphrase?)")?;
        Ok(IrohChannel::new(conn))
    }
}

/// Reconnect backoff for a failed dial attempt (1-based `attempt`), in milliseconds.
fn backoff_ms(attempt: u32) -> u64 {
    (RECONNECT_BACKOFF_BASE_MS << attempt.min(4)).min(RECONNECT_BACKOFF_MAX_MS)
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

/// Where the client paints frames and reads the window size. The real binary draws to the
/// terminal via termina ([`TerminaTerminal`]); a test captures cells/text as data.
pub trait ClientTerminal {
    fn render(
        &mut self,
        screen: &vt100::Screen,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> std::io::Result<()>;

    /// The current window size as `(rows, cols)`.
    fn size(&self) -> std::io::Result<(u16, u16)>;
}

/// The production terminal: a termina `PlatformTerminal` put into raw mode + the alternate
/// screen on construction, restored on drop. It paints the synced grid + prediction overlay.
pub struct TerminaTerminal {
    term: PlatformTerminal,
}

impl TerminaTerminal {
    /// Acquire the terminal, enter raw mode + the alternate screen, and hide the cursor.
    pub fn enter() -> std::io::Result<Self> {
        let mut term = PlatformTerminal::new()?;
        term.enter_raw_mode()?;
        write!(
            term,
            "{}{}",
            Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(
                DecPrivateModeCode::ClearAndEnableAlternateScreen
            ))),
            Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(
                DecPrivateModeCode::ShowCursor
            ))),
        )?;
        term.flush()?;
        Ok(Self { term })
    }
}

impl ClientTerminal for TerminaTerminal {
    fn render(
        &mut self,
        screen: &vt100::Screen,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> std::io::Result<()> {
        render::render(&mut self.term, screen, overlay, status)
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        let d = self.term.get_dimensions()?;
        Ok((d.rows, d.cols))
    }
}

impl Drop for TerminaTerminal {
    fn drop(&mut self) {
        // Show the cursor and leave the alternate screen; the PlatformTerminal's own Drop
        // restores cooked mode afterward.
        let _ = write!(
            self.term,
            "{}{}",
            Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(
                DecPrivateModeCode::ShowCursor
            ))),
            Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(
                DecPrivateModeCode::ClearAndEnableAlternateScreen
            ))),
        );
        let _ = self.term.flush();
    }
}

/// What [`ClientSession::on_input`] decided about a chunk of typed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOutcome {
    /// The user typed the escape prefix followed by `.` — disconnect.
    Quit,
    /// The bytes were consumed (forwarded to the server and/or seeded into the predictor).
    Forwarded,
}

/// What one [`ClientSession::on_tick`] produced for the I/O loop to act on.
#[derive(Debug, Default)]
pub struct TickResult {
    /// Datagrams to ship to the server this tick (the caller sends them; the session does no I/O).
    pub outgoing: Vec<Vec<u8>>,
    /// How long the caller should wait before the next tick if nothing else wakes it (ms).
    pub wait_ms: u64,
    /// The "link down — resuming…" banner text, if the peer has gone quiet (else `None`).
    pub status: Option<String>,
    /// `Some(exit_code)` once the server has announced a clean shutdown (the inner `Option` is
    /// the remote shell's exit code, which may be unknown). The caller renders a final frame and
    /// returns this code.
    pub ended: Option<Option<u32>>,
}

/// The terminal-agnostic, **synchronous, I/O-free** core of the client session loop.
///
/// It owns the SSP [`Transport`], the [`PredictionEngine`], and the small render/escape state, and
/// exposes pure step methods (`on_input`/`on_datagram`/`on_resize`/`on_tick`) that take the
/// current time and return what to do — never touching tokio, iroh, or a real terminal. That makes
/// the whole client protocol deterministically unit-testable (see this module's tests), and lets a
/// future front-end (e.g. the planned Bevy app) drive it without `run_client`'s I/O scaffolding.
///
/// The screen is **derived** from the transport, never stored: [`screen`](Self::screen) and
/// [`overlay`](Self::overlay) borrow it, so `run_client` renders through those borrows with no
/// extra clone.
pub struct ClientSession {
    transport: Transport<UserInput, TerminalScreen>,
    predictor: PredictionEngine,
    /// True after we've seen the lone escape prefix and are waiting for the next byte.
    pending_escape: bool,
    /// Set whenever the rendered output may have changed; cleared once the caller repaints.
    dirty: bool,
    /// Whether the "link down" banner was painted last frame, so we force one more repaint to
    /// clear it the moment the peer reappears (recovery may arrive as a Duplicate, not NewState).
    status_was_shown: bool,
}

impl ClientSession {
    /// Create a session at time `now` (ms) with datagram budget `mtu`, seeding the first resize
    /// the server should see. Marked connected and dirty (so the first frame paints).
    pub fn new(
        now: u64,
        mtu: usize,
        pref: DisplayPreference,
        initial_rows: u16,
        initial_cols: u16,
    ) -> Self {
        let mut transport = Transport::<UserInput, TerminalScreen>::new(now, mtu);
        transport.set_connected(true);
        transport
            .current_mut()
            .push_resize(initial_rows, initial_cols);
        Self {
            transport,
            predictor: PredictionEngine::new(pref),
            pending_escape: false,
            dirty: true,
            status_was_shown: false,
        }
    }

    /// Feed a chunk of locally-typed bytes. Runs the escape-prefix machine (`0x1e` then `.` quits;
    /// `0x1e` then anything else forwards both bytes literally), seeds the predictor against the
    /// current remote screen, and appends the surviving bytes to the outgoing input stream.
    pub fn on_input(&mut self, now: u64, bytes: &[u8]) -> InputOutcome {
        let mut quit = false;
        let mut fwd: Vec<u8> = Vec::with_capacity(bytes.len());
        for &b in bytes {
            if self.pending_escape {
                self.pending_escape = false;
                if b == b'.' {
                    quit = true;
                    break;
                }
                fwd.push(ESCAPE_PREFIX);
                fwd.push(b);
            } else if b == ESCAPE_PREFIX {
                self.pending_escape = true;
            } else {
                fwd.push(b);
            }
        }
        if quit {
            return InputOutcome::Quit;
        }
        if !fwd.is_empty() {
            self.predictor
                .set_local_frame_sent(self.transport.newest_sent_num());
            self.predictor.set_srtt(self.transport.srtt_ms());
            // Seed predictions against the current remote screen. The screen borrows `transport`
            // immutably while `predictor` is borrowed mutably — disjoint fields, so no clone is
            // needed; the borrow ends before `current_mut()` below.
            let screen = self.transport.remote_state().screen();
            for &b in &fwd {
                self.predictor.new_user_byte(now, b, screen);
            }
            self.transport.current_mut().push_bytes(&fwd);
            self.dirty = true;
        }
        InputOutcome::Forwarded
    }

    /// Feed one inbound datagram. On a newest-in-order state it reconciles the predictor against
    /// the fresh authoritative screen (culling confirmed/incorrect predictions) and marks dirty.
    pub fn on_datagram(&mut self, now: u64, bytes: &[u8]) {
        if self.transport.recv(now, bytes) == RecvOutcome::NewState {
            let echo_ack = self.transport.remote_state().echo_ack();
            self.predictor.set_local_frame_late_acked(echo_ack);
            self.predictor.set_srtt(self.transport.srtt_ms());
            let screen = self.transport.remote_state().screen();
            self.predictor.cull(now, screen);
            self.dirty = true;
        }
    }

    /// Note a new window size: propagate it to the server and reset the predictor (a resize
    /// invalidates in-flight predictions).
    pub fn on_resize(&mut self, rows: u16, cols: u16) {
        self.transport.current_mut().push_resize(rows, cols);
        self.predictor.reset();
        self.dirty = true;
    }

    /// Advance the steady-state at time `now` with the latest `mtu`/`rtt_ms`, returning the
    /// datagrams to send, the next idle wait, the link-down banner, and — once the server has
    /// announced shutdown — the remote exit code. Does no I/O: it returns datagrams instead of
    /// sending them.
    pub fn on_tick(&mut self, now: u64, mtu: usize, rtt_ms: Option<f64>) -> TickResult {
        self.transport.set_mtu(mtu);
        if let Some(rtt) = rtt_ms {
            self.transport.observe_rtt(rtt);
        }
        let outgoing = self.transport.tick(now);

        // Link-down is driven by transport liveness, which refreshes on ANY decoded inbound
        // (including duplicate keepalives) — so a quiet-but-alive session never falsely trips the
        // banner. No banner before first contact (last_heard == 0 -> still connecting).
        let status = if self.transport.last_heard() > 0 && !self.transport.link_up_within(now, 3000)
        {
            let since = now.saturating_sub(self.transport.last_heard());
            Some(format!("[koh] link down — resuming… {}s", since / 1000))
        } else {
            None
        };

        let ended = (self.transport.remote_num() == SHUTDOWN_SENTINEL)
            .then(|| self.transport.remote_state().exit_code());

        let wait_ms = self.transport.wait_time(now).min(50);
        TickResult {
            outgoing,
            wait_ms,
            status,
            ended,
        }
    }

    /// The authoritative remote screen, borrowed (derived from the transport, never stored).
    pub fn screen(&self) -> &vt100::Screen {
        self.transport.remote_state().screen()
    }

    /// The current prediction overlay to draw over [`screen`](Self::screen).
    pub fn overlay(&self) -> Overlay {
        self.predictor
            .overlay(self.transport.remote_state().screen())
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
/// or `None` for a local quit (`Ctrl-^ .` or a closed input channel) — so the binary can exit with
/// the remote status.
pub async fn run_client<T: ClientTerminal>(
    initial: IrohChannel,
    connector: IrohConnector,
    pref: DisplayPreference,
    initial_size: (u16, u16),
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    mut resize_rx: mpsc::Receiver<()>,
    mut term: T,
) -> anyhow::Result<Option<u32>> {
    let clock = MonoClock::new();
    let mut channel = initial;
    loop {
        // A fresh session per (re)connection mirrors the server's fresh-transport-per-attach, which
        // full-repaints the live screen; re-seed the size from the terminal each time.
        let (rows, cols) = term.size().unwrap_or(initial_size);
        let mut session = ClientSession::new(
            clock.now_ms(),
            channel.max_datagram_size(),
            pref,
            rows,
            cols,
        );

        match drive_connection(
            &channel,
            &mut session,
            &mut term,
            &mut input_rx,
            &mut resize_rx,
            &clock,
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
                match reconnect(&connector, &mut term, &mut input_rx, &session, &clock).await {
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
async fn drive_connection<T: ClientTerminal>(
    channel: &IrohChannel,
    session: &mut ClientSession,
    term: &mut T,
    input_rx: &mut mpsc::Receiver<Vec<u8>>,
    resize_rx: &mut mpsc::Receiver<()>,
    clock: &MonoClock,
) -> anyhow::Result<Disposition> {
    loop {
        let now = clock.now_ms();
        let tick = session.on_tick(now, channel.max_datagram_size(), channel.rtt_ms());
        for datagram in &tick.outgoing {
            channel.send(datagram);
        }

        // Repaint on new content, while the banner is up, or once more to clear a stale banner.
        let status_now = tick.status.is_some();
        if session.dirty || status_now || session.status_was_shown {
            term.render(session.screen(), &session.overlay(), tick.status.as_deref())?;
            session.status_was_shown = status_now;
            session.dirty = false;
        }

        if let Some(code) = tick.ended {
            let _ = term.render(
                session.screen(),
                &Overlay::empty(),
                Some("[koh] session ended"),
            );
            tokio::time::sleep(Duration::from_millis(400)).await;
            return Ok(Disposition::Ended(code));
        }

        tokio::select! {
            // Input-priority: a queued screen update must never starve local keystrokes (mosh
            // keeps typing responsive even when the screen is busy). The server loop is the mirror
            // image and is deliberately NOT biased (see `koh_server::run_attached`).
            biased;

            maybe = input_rx.recv() => {
                match maybe {
                    Some(chunk) => {
                        if session.on_input(clock.now_ms(), &chunk) == InputOutcome::Quit {
                            return Ok(Disposition::Quit);
                        }
                    }
                    None => return Ok(Disposition::Quit), // input source closed
                }
            }

            // Cancel-safety: if a higher-priority arm fires first, this in-flight `read_datagram`
            // future is dropped. That is only sound because the pinned `iroh = "1.0.0"`'s
            // `read_datagram` is cancel-safe (a dropped future loses no buffered datagram); any
            // iroh version bump must re-verify this before relying on the drop here.
            dg = channel.recv() => {
                match dg {
                    Ok(bytes) => session.on_datagram(clock.now_ms(), &bytes),
                    Err(e) => {
                        tracing::info!(reason = %e, "link lost; will reconnect");
                        return Ok(Disposition::LinkLost);
                    }
                }
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

            _ = tokio::time::sleep(Duration::from_millis(tick.wait_ms)) => {}
        }
    }
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
    clock: &MonoClock,
) -> ReconnectOutcome {
    let started = clock.now_ms();
    let mut pending_escape = false;
    let mut attempt: u32 = 0;
    'attempt: loop {
        let dial = tokio::time::timeout(RECONNECT_CONNECT_TIMEOUT, connector.connect());
        tokio::pin!(dial);
        loop {
            let secs = clock.now_ms().saturating_sub(started) / 1000;
            let banner = format!("[koh] disconnected — reconnecting… {secs}s (Ctrl-^ . to quit)");
            let _ = term.render(last.screen(), &Overlay::empty(), Some(banner.as_str()));

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
                        Ok(Err(e)) => tracing::info!(reason = %e, attempt, "reconnect dial failed"),
                        Err(_) => tracing::info!(attempt, "reconnect dial timed out"),
                    }
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(Duration::from_millis(backoff_ms(attempt))).await;
                    continue 'attempt;
                }

                _ = tokio::time::sleep(Duration::from_secs(1)) => { /* tick the banner clock */ }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koh_input::InputEvent;
    use koh_terminal::ServerTerminal;

    /// Drive a server-side transport until it emits at least one datagram, returning them. Used to
    /// synthesize *real* server frames for the client session to consume — no iroh, no tokio.
    fn drive_until_nonempty(t: &mut Transport<TerminalScreen, UserInput>) -> Vec<Vec<u8>> {
        let mut now = 0u64;
        loop {
            now += 25;
            let out = t.tick(now);
            if !out.is_empty() || now > 5_000 {
                return out;
            }
        }
    }

    fn new_session() -> ClientSession {
        ClientSession::new(0, 1200, DisplayPreference::Always, 24, 80)
    }

    #[test]
    fn escape_prefix_dot_quits_and_plain_bytes_forward() {
        let mut s = new_session();
        // Plain bytes are forwarded and appended to the outgoing UserInput stream.
        assert_eq!(s.on_input(0, b"ls\r"), InputOutcome::Forwarded);
        let typed: Vec<u8> = s
            .transport
            .current()
            .events()
            .iter()
            .filter_map(|e| match e {
                InputEvent::Byte(b) => Some(*b),
                InputEvent::Resize { .. } => None,
            })
            .collect();
        assert_eq!(
            typed, b"ls\r",
            "forwarded bytes land in transport.current()"
        );
        // The escape prefix (0x1e) followed by '.' disconnects.
        assert_eq!(s.on_input(0, &[ESCAPE_PREFIX, b'.']), InputOutcome::Quit);
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
        assert_eq!(backoff_ms(1), 1_000);
        assert_eq!(backoff_ms(2), 2_000);
        assert_eq!(backoff_ms(3), 4_000);
        assert_eq!(backoff_ms(4), RECONNECT_BACKOFF_MAX_MS);
        assert_eq!(backoff_ms(5), RECONNECT_BACKOFF_MAX_MS);
        assert_eq!(
            backoff_ms(99),
            RECONNECT_BACKOFF_MAX_MS,
            "shift is clamped, no overflow"
        );
    }

    #[test]
    fn lone_escape_prefix_then_other_byte_forwards_both() {
        let mut s = new_session();
        // 0x1e then a non-'.' byte forwards the prefix AND the byte literally (escape pass-through).
        assert_eq!(s.on_input(0, &[ESCAPE_PREFIX]), InputOutcome::Forwarded);
        assert_eq!(s.on_input(0, b"x"), InputOutcome::Forwarded);
        let typed: Vec<u8> = s
            .transport
            .current()
            .events()
            .iter()
            .filter_map(|e| match e {
                InputEvent::Byte(b) => Some(*b),
                InputEvent::Resize { .. } => None,
            })
            .collect();
        assert_eq!(
            typed,
            [ESCAPE_PREFIX, b'x'],
            "escaped non-dot byte passes through literally"
        );
    }

    #[test]
    fn on_datagram_new_state_marks_dirty_and_culls_predictor() {
        let mut s = new_session();
        // Type 'x': a prediction is seeded but hidden (epoch-gated) until the server confirms echo.
        s.on_input(0, b"x");
        s.dirty = false; // clear so we can observe on_datagram re-dirtying
        assert!(
            s.overlay().is_empty(),
            "the first keystroke stays hidden until confirmed"
        );
        assert_eq!(
            s.predictor.confirmed_epoch(),
            0,
            "nothing is confirmed before the server frame arrives"
        );

        // A real server frame that echoes 'x' and acks input frame 1 (past the echo debounce).
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.process(b"x");
        emu.register_input_frame(1, 0);
        emu.set_echo_ack(100);
        let mut server = Transport::<TerminalScreen, UserInput>::new(0, 1200);
        server.set_connected(true);
        server.observe_rtt(20.0);
        *server.current_mut() = emu.snapshot();
        for dg in drive_until_nonempty(&mut server) {
            s.on_datagram(100, &dg);
        }
        assert!(
            s.dirty,
            "a new remote state must mark the client dirty (needs repaint)"
        );
        assert!(
            s.screen().contents().contains('x'),
            "the new state is applied to the screen"
        );
        // Pin the cull effect to on_datagram ITSELF: the epoch must advance here, before any
        // further keystroke (an `on_input` would also call cull, which is why asserting only on a
        // later keystroke's visibility wouldn't isolate this call).
        assert_eq!(
            s.predictor.confirmed_epoch(),
            1,
            "on_datagram's cull must grade the echoed 'x' Correct and advance the confirmed epoch"
        );

        // And the downstream consequence holds: a subsequent keystroke is now VISIBLE.
        s.on_input(110, b"y");
        assert_eq!(
            s.overlay().cell(0, 1).map(|c| c.glyph.as_str()),
            Some("y"),
            "typing after the confirmed echo is visible (the prior prediction was culled)"
        );
    }

    #[test]
    fn on_tick_emits_outgoing_and_reports_shutdown_exit_code() {
        let mut s = new_session();
        // First tick: the initial resize is pending, so a datagram goes out and there's no end yet.
        let first = s.on_tick(0, 1200, Some(20.0));
        assert!(
            !first.outgoing.is_empty(),
            "the pending initial resize must be sent"
        );
        assert!(first.ended.is_none(), "no shutdown announced yet");
        assert!(first.wait_ms <= 50, "wait is capped at 50ms");

        // Craft a real server shutdown frame carrying exit code 7 and deliver it.
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.set_exit_code(7);
        let mut server = Transport::<TerminalScreen, UserInput>::new(0, 1200);
        server.set_connected(true);
        server.observe_rtt(20.0);
        *server.current_mut() = emu.snapshot();
        server.start_shutdown(0);
        for dg in drive_until_nonempty(&mut server) {
            s.on_datagram(10, &dg);
        }
        let tick = s.on_tick(10, 1200, Some(20.0));
        assert_eq!(
            tick.ended,
            Some(Some(7)),
            "a SHUTDOWN_SENTINEL remote state reports the remote shell's exit code"
        );
    }

    #[test]
    fn on_resize_resets_predictor_and_propagates() {
        let mut s = new_session();
        s.on_resize(40, 120);
        // The resize is appended to the outgoing input stream.
        let last_resize = s
            .transport
            .current()
            .events()
            .iter()
            .rev()
            .find_map(|e| match e {
                InputEvent::Resize { rows, cols } => Some((*rows, *cols)),
                InputEvent::Byte(_) => None,
            });
        assert_eq!(
            last_resize,
            Some((40, 120)),
            "resize propagates to the server"
        );
        assert!(s.dirty, "a resize requires a repaint");
    }
}
