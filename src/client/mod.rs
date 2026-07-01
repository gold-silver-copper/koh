//! The koh client: the session loop, abstracted over a [`ClientTerminal`].
//!
//! It runs either against the real terminal (the binary, via [`TerminaTerminal`]) or against a
//! scripted mock (integration tests) — no real TTY required for the latter.
//!
//! Terminal *input* (typed bytes) and *resize* ticks arrive as channels the caller wires up;
//! terminal *output* and *size* go through [`ClientTerminal`]. The binary's `main` connects the
//! termina renderer + a raw-stdin reader + a `SIGWINCH` task; a test connects a capturing mock
//! + a scripted input channel.

pub mod cli;
mod render;

pub use cli::{connect, run_id, ConnectArgs, IdArgs};

use std::io::Write;
use std::time::Duration;

use crate::input::UserInput;
use crate::predict::{DisplayPreference, Overlay, PredictionEngine};
use crate::ssp::{RecvOutcome, Transport, SHUTDOWN_SENTINEL};
use crate::terminal::TerminalScreen;
use crate::transport_iroh::{IrohChannel, MonoClock, ALPN};
use anyhow::Context;
use iroh::{Endpoint, EndpointAddr};
use termina::escape::csi::{Csi, DecPrivateMode, DecPrivateModeCode, Mode};
use termina::{PlatformTerminal, Terminal as _};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub use render::WindowState;

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

/// The DEC private modes we may have forwarded to the user's terminal (X10 `?9` + all mouse modes
/// and encodings, bracketed paste `?2004`, application cursor keys `?1`) plus normal keypad
/// (`ESC >`). Reset together whenever we leave the alternate screen — on drop *or* on suspend — so
/// the user's shell isn't left with mouse reporting on, injecting stray bytes at the prompt.
const RESET_FORWARDED_MODES: &[u8] =
    b"\x1b[?9l\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1l\x1b>";

/// How long a single reconnect dial may run before it is abandoned and retried.
const RECONNECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// The dial budget when a security key is configured. A `--require-sk` dial includes a human hardware
/// touch, which the server grants up to [`sk_auth::SK_TOUCH_GRACE`](crate::transport_iroh::sk_auth::SK_TOUCH_GRACE);
/// the client must therefore wait a bit LONGER than the server (touch grace + handshake headroom) so a
/// slow-but-legitimate touch isn't aborted client-side — and so the server's decision (admit or a
/// clear reject) wins the race instead of the client timing out with a generic "unreachable" error.
const RECONNECT_CONNECT_TIMEOUT_SK: Duration = Duration::from_secs(45);
/// Reconnect backoff: `BASE << min(attempt, 4)`, capped at `MAX`. `backoff_ms` is only called for
/// `attempt > 0` (attempt 0 redials immediately), so the realized sequence is 1 → 2 → 4 → 8s.
const RECONNECT_BACKOFF_BASE_MS: u64 = 500;
const RECONNECT_BACKOFF_MAX_MS: u64 = 8_000;
/// Minimum time a connection must stay up to count as "proven" and reset the reconnect backoff. A
/// connection that drops sooner than this — e.g. a malicious or compromised server that completes
/// the handshake then immediately closes — is treated like a failed dial: the attempt counter keeps
/// climbing and the next redial backs off, so such a server can't drive a tight reconnect/repaint
/// churn loop (K-03). A genuine mid-session drop after this dwell reconnects promptly.
const MIN_CONNECTION_DWELL_MS: u64 = 5_000;

/// How long the link must be silent before the in-session "link down — resuming…" banner appears.
///
/// An idle, still-connected peer sends a keepalive every `crate::ssp::ACK_INTERVAL` (3 s), and
/// the transport's `last_heard` refreshes on every decoded inbound (including duplicate keepalives)
/// — so on a healthy link the gap between contacts never exceeds one interval. The trouble
/// is on a *lossy* link: a single dropped or jittered keepalive pushes the gap just past one
/// interval, so a threshold near `ACK_INTERVAL` flashes the banner on routine packet loss (the gap
/// recovers the instant the next keepalive lands). Gate the banner at several keepalive intervals so
/// a couple of missed keepalives are absorbed silently and the banner only surfaces on a genuine
/// stall — at the cost of a few extra seconds before a real outage is announced (the user can always
/// `Ctrl-^ .` to quit immediately).
const LINK_DOWN_GRACE_MS: u64 = crate::ssp::ACK_INTERVAL * 3;

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
    /// Optional FIDO2 second factor: when set, every dial (initial and each transparent reconnect)
    /// re-proves possession of the security key against the server's fresh per-connection challenge.
    sk: Option<std::sync::Arc<crate::transport_iroh::sk_auth::ClientSkCtx>>,
}

impl IrohConnector {
    pub fn new(endpoint: Endpoint, target: EndpointAddr) -> Self {
        Self {
            endpoint,
            target,
            sk: None,
        }
    }

    /// Attach a security-key signing context so this connector satisfies a server's `--require-sk`
    /// challenge on every dial (see [`crate::transport_iroh::sk_auth`]).
    #[must_use]
    pub fn with_sk(mut self, ctx: crate::transport_iroh::sk_auth::ClientSkCtx) -> Self {
        self.sk = Some(std::sync::Arc::new(ctx));
        self
    }

    /// How long a single dial by this connector may run. When a security key is configured the dial
    /// includes a hardware touch, so it gets the wider [`RECONNECT_CONNECT_TIMEOUT_SK`] budget; the
    /// plain path keeps the tight [`RECONNECT_CONNECT_TIMEOUT`]. Used for the initial dial and every
    /// transparent reconnect so they stay consistent.
    pub fn dial_timeout(&self) -> Duration {
        if self.sk.is_some() {
            RECONNECT_CONNECT_TIMEOUT_SK
        } else {
            RECONNECT_CONNECT_TIMEOUT
        }
    }

    /// Connect to the server and await its admission ack. A server that rejects us (our node-id is
    /// not on its allowlist, it's at capacity, or a required security-key proof failed) closes the
    /// connection instead of admitting; that surfaces as an `Err` (the binary reports it before
    /// entering raw mode), so a rejected client fails fast rather than re-dialing forever.
    pub async fn connect(&self) -> anyhow::Result<IrohChannel> {
        let conn = self
            .endpoint
            .connect(self.target.clone(), ALPN)
            .await
            .context("connecting to server (is your id on its allowlist?)")?;
        // With a security key configured, run the SK-aware admission (which answers a challenge if the
        // server issues one); otherwise the plain one-byte admission. Both handle the no-SK server.
        let admission = match &self.sk {
            Some(ctx) => {
                crate::transport_iroh::admission::await_admission_with_sk(&conn, ctx).await
            }
            None => crate::transport_iroh::admission::await_admission(&conn).await,
        };
        if let Err(e) = admission {
            // A client-LOCAL security-key failure (no agent, wrong/unplugged key, declined/slow touch)
            // leaves the connection open, so `server_close_reason` is None and the generic
            // allowlist message below would misdirect the operator. Caption those with the real
            // (self-descriptive) SkAuth cause instead.
            if let crate::transport_iroh::admission::AdmissionError::SkAuth(_) = &e {
                return Err(anyhow::Error::new(e).context(
                    "security-key authentication failed (check your key is plugged in and loaded, \
                     e.g. `ssh-add ~/.ssh/id_ed25519_sk`, and touch it when prompted)",
                ));
            }
            // Otherwise the server rejected with a specific application reason — "not authorized" /
            // "server at session capacity" / "security-key auth failed" — each pointing at a
            // different operator fix. Surface that real reason instead of a static guess. The reason
            // is peer-controlled, so it is sanitized + capped.
            return Err(match server_close_reason(&conn) {
                Some(reason) => anyhow::Error::new(e)
                    .context(format!("server rejected the connection: {reason}")),
                None => anyhow::Error::new(e).context(
                    "server did not admit the connection (check your id is on its --allow list; if it \
                     requires a security key, pass --sk-key)",
                ),
            });
        }
        Ok(IrohChannel::new(conn))
    }
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
fn backoff_ms(attempt: u32) -> u64 {
    (RECONNECT_BACKOFF_BASE_MS << attempt.min(4)).min(RECONNECT_BACKOFF_MAX_MS)
}

/// The reconnect attempt counter after a connection drops, given how long it stayed up (`dwell_ms`).
///
/// A connection that lasted at least [`MIN_CONNECTION_DWELL_MS`] proved itself, so the backoff
/// resets to 0 (a genuine mid-session drop reconnects promptly). A shorter-lived one — e.g. a
/// server that accepts then immediately closes — is treated like a failed dial: the counter
/// increments (saturating) so the next redial backs off, preventing a tight reconnect/repaint churn
/// loop (K-03). Pure so the branch logic is unit-testable without driving a real connection.
const fn next_attempt_after_drop(attempt: u32, dwell_ms: u64) -> u32 {
    if dwell_ms >= MIN_CONNECTION_DWELL_MS {
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

/// Where the client paints frames and reads the window size. The real binary draws to the
/// terminal via termina ([`TerminaTerminal`]); a test captures cells/text as data.
pub trait ClientTerminal {
    /// Paint one frame. `screen` is the authoritative grid (and carries the input modes —
    /// bracketed-paste / mouse / cursor-key — which the real terminal must mirror); `overlay` is
    /// the prediction overlay; `status` is the optional status line; `win` is the out-of-band
    /// window state (title / icon / clipboard / bell) to mirror onto the real terminal.
    fn render(
        &mut self,
        screen: &vt100::Screen,
        overlay: &Overlay,
        status: Option<&str>,
        win: render::WindowState<'_>,
    ) -> std::io::Result<()>;

    /// The current window size as `(rows, cols)`.
    fn size(&self) -> std::io::Result<(u16, u16)>;

    /// Suspend the client to the background (the `Ctrl-^ Ctrl-Z` escape): restore the user's
    /// terminal to a usable cooked state, stop the process with `SIGTSTP`, and — once the user
    /// foregrounds it again (`SIGCONT`) — re-enter raw mode + the alternate screen so the caller can
    /// force a repaint. Blocks for the whole suspended duration (the entire process is stopped).
    ///
    /// Default: a no-op, so a scripted test terminal can never actually stop the test process; only
    /// the real [`TerminaTerminal`] performs the suspend.
    fn suspend_resume(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The production terminal: a termina `PlatformTerminal` put into raw mode + the alternate
/// screen on construction, restored on drop. It paints the synced grid + prediction overlay.
pub struct TerminaTerminal {
    term: PlatformTerminal,
    /// Tracks the title / bell / input modes mirrored to the real terminal (see [`render::OutOfBand`]).
    oob: render::OutOfBand,
}

impl TerminaTerminal {
    /// Acquire the terminal, enter raw mode + the alternate screen, and hide the cursor.
    /// `clipboard_enabled` gates honoring remote OSC-52 clipboard writes (default off; L-1).
    pub fn enter(clipboard_enabled: bool) -> std::io::Result<Self> {
        let mut term = PlatformTerminal::new()?;
        term.enter_raw_mode()?;
        // Build the struct, then enter the alternate screen via the SAME helper the resume path
        // uses, so the enter/leave escape sequences only ever live in one place (enter_screen /
        // leave_screen). `enter_screen` writes to `self.term` and never reads `oob`, so building
        // first is inert.
        let mut this = Self {
            term,
            oob: render::OutOfBand::with_title_prefix(KOH_TITLE_PREFIX.to_string())
                .with_clipboard(clipboard_enabled),
        };
        this.enter_screen()?;
        Ok(this)
    }

    /// Re-enter the alternate screen and hide the cursor (the raw-mode/alt-screen setup shared by
    /// [`enter`](Self::enter) and the resume half of [`suspend_resume`](Self::suspend_resume)).
    fn enter_screen(&mut self) -> std::io::Result<()> {
        write!(
            self.term,
            "{}{}",
            Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(
                DecPrivateModeCode::ClearAndEnableAlternateScreen
            ))),
            Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(
                DecPrivateModeCode::ShowCursor
            ))),
        )?;
        self.term.flush()
    }

    /// Reset forwarded modes, show the cursor, and leave the alternate screen (the teardown shared
    /// by [`Drop`] and the suspend half of [`suspend_resume`](Self::suspend_resume)).
    fn leave_screen(&mut self) -> std::io::Result<()> {
        self.term.write_all(RESET_FORWARDED_MODES)?;
        write!(
            self.term,
            "{}{}",
            Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(
                DecPrivateModeCode::ShowCursor
            ))),
            Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(
                DecPrivateModeCode::ClearAndEnableAlternateScreen
            ))),
        )?;
        self.term.flush()
    }
}

impl ClientTerminal for TerminaTerminal {
    fn render(
        &mut self,
        screen: &vt100::Screen,
        overlay: &Overlay,
        status: Option<&str>,
        win: render::WindowState<'_>,
    ) -> std::io::Result<()> {
        // Mirror the out-of-band terminal state (title/icon/clipboard/bell/modes) onto the real
        // terminal, then paint the cell grid.
        self.oob.emit(&mut self.term, screen, win)?;
        render::render(&mut self.term, screen, overlay, status)
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        let d = self.term.get_dimensions()?;
        Ok((d.rows, d.cols))
    }

    fn suspend_resume(&mut self) -> std::io::Result<()> {
        // Restore the user's terminal (reset forwarded modes, show cursor, leave the alt screen)
        // and return to cooked mode, so the suspended job sits at a normal shell.
        self.leave_screen()?;
        self.term.enter_cooked_mode()?;
        let _ = writeln!(self.term, "\n[koh suspended — run `fg` to resume]");
        let _ = self.term.flush();
        // Stop ourselves. SIGTSTP halts the whole process; control returns here only once the user
        // foregrounds the job (SIGCONT). `nix::raise` keeps the crate `forbid(unsafe)`.
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGTSTP)
            .map_err(std::io::Error::other)?;
        // Foregrounded again: re-enter raw mode + the alternate screen and force the next frame to
        // re-assert the title / clipboard / input modes (the terminal was reset while we were away).
        self.term.enter_raw_mode()?;
        self.enter_screen()?;
        self.oob.invalidate();
        Ok(())
    }
}

impl Drop for TerminaTerminal {
    fn drop(&mut self) {
        // Reset forwarded modes, show the cursor, and leave the alternate screen so the user's
        // terminal isn't left with mouse reporting on (stray click bytes at the prompt). The
        // PlatformTerminal's own Drop restores cooked mode afterward.
        let _ = self.leave_screen();
    }
}

/// What [`ClientSession::on_input`] decided about a chunk of typed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOutcome {
    /// The user typed the escape prefix followed by `.` — disconnect.
    Quit,
    /// The user typed the escape prefix followed by `Ctrl-Z` — suspend to the background. Any bytes
    /// before the escape in the same chunk were already forwarded; the caller drives the suspend.
    Suspend,
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
        let predictor = PredictionEngine::new(pref);
        Self {
            transport,
            predictor,
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
        let mut suspend = false;
        let mut fwd: Vec<u8> = Vec::with_capacity(bytes.len());
        for &b in bytes {
            if self.pending_escape {
                self.pending_escape = false;
                if b == b'.' {
                    quit = true;
                    break;
                }
                if b == SUSPEND_KEY {
                    suspend = true;
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
        // Forward any bytes that preceded the escape before suspending, so nothing typed ahead of
        // `Ctrl-^ Ctrl-Z` is dropped.
        if !fwd.is_empty() {
            self.predictor
                .set_local_frame_sent(self.transport.newest_sent_num());
            self.predictor
                .set_srtt(self.transport.send_interval() as f64);
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
        if suspend {
            return InputOutcome::Suspend;
        }
        InputOutcome::Forwarded
    }

    /// Feed one inbound datagram. On a newest-in-order state it reconciles the predictor against
    /// the fresh authoritative screen (culling confirmed/incorrect predictions) and marks dirty.
    pub fn on_datagram(&mut self, now: u64, bytes: &[u8]) {
        if self.transport.recv(now, bytes) == RecvOutcome::NewState {
            let echo_ack = self.transport.remote_state().echo_ack();
            self.predictor.set_local_frame_late_acked(echo_ack);
            self.predictor
                .set_srtt(self.transport.send_interval() as f64);
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
        // Escalate a long-pending prediction to the glitch underline on time, even on a silent
        // link (no datagram/keystroke to drive cull). Repaint if the flagging changed.
        if self
            .predictor
            .tick(now, self.transport.remote_state().screen())
        {
            self.dirty = true;
        }
        let outgoing = self.transport.tick(now);

        // Link-down is driven by transport liveness, which refreshes on ANY decoded inbound
        // (including duplicate keepalives) — so a quiet-but-alive session never falsely trips the
        // banner. The grace is several keepalive intervals (LINK_DOWN_GRACE_MS), so a dropped/jittered
        // keepalive on a lossy link doesn't flash the banner the moment one packet is late. No banner
        // before first contact (last_heard == 0 -> still connecting).
        let status = if self.transport.last_heard() > 0
            && !self.transport.link_up_within(now, LINK_DOWN_GRACE_MS)
        {
            let since = now.saturating_sub(self.transport.last_heard());
            Some(format!("[koh] link down — resuming… {}s", since / 1000))
        } else {
            None
        };

        // K-04 (trust boundary, documented by design): both `remote_num()` and the carried
        // `exit_code` are peer-controlled, so a malicious/typo'd server can announce a shutdown with
        // any exit code, which becomes koh's process exit status (`code as u8`). This is the same
        // contract as ssh/mosh — the remote shell's exit code is *meant* to propagate — so we keep
        // it rather than masking a useful signal. A wrapper that must distinguish "the remote shell
        // exited N" from "the transport failed" should key off koh's own failure paths (a dropped
        // connection returns via `LinkLost`/reconnect, never this clean-shutdown arm), not trust the
        // peer-announced code as authoritative. The connection is already QUIC-authenticated to the
        // dialed node id; an attacker who can send this frame can already disrupt the session.
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

    /// The out-of-band window state (title / icon / clipboard / bell) for the client to mirror
    /// onto the real terminal alongside the cell grid.
    pub fn window_state(&self) -> render::WindowState<'_> {
        let ts = self.transport.remote_state();
        render::WindowState {
            title: ts.title(),
            icon: ts.icon(),
            clipboard: ts.clipboard(),
            bell_count: ts.bell_count(),
        }
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
#[expect(
    clippy::too_many_arguments,
    reason = "the I/O shell wires up the channel, connector, prediction policy, size, the two \
              input/resize channels, the terminal, and the shutdown token — each a distinct \
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
) -> anyhow::Result<Option<u32>> {
    let clock = MonoClock::new();
    let mut channel = initial;
    // Persists ACROSS reconnect cycles (not reset per connection) so a server that keeps dropping us
    // fast can't escape the backoff by completing each handshake — only a connection that proves
    // itself (stays up past `MIN_CONNECTION_DWELL_MS`) resets it (K-03).
    let mut attempt: u32 = 0;
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

        let conn_started = clock.now_ms();
        match drive_connection(
            &channel,
            &mut session,
            &mut term,
            &mut input_rx,
            &mut resize_rx,
            &clock,
            &shutdown,
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
                // (prompt reattach); a drop sooner than `MIN_CONNECTION_DWELL_MS` is treated like a
                // failed dial — bump the attempt so `reconnect` backs off before redialing, so an
                // accept-then-instantly-close server can't spin us in a tight loop (K-03).
                let dwell = clock.now_ms().saturating_sub(conn_started);
                attempt = next_attempt_after_drop(attempt, dwell);
                match reconnect(
                    &connector,
                    &mut term,
                    &mut input_rx,
                    &session,
                    &clock,
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
async fn drive_connection<T: ClientTerminal>(
    channel: &IrohChannel,
    session: &mut ClientSession,
    term: &mut T,
    input_rx: &mut mpsc::Receiver<Vec<u8>>,
    resize_rx: &mut mpsc::Receiver<()>,
    clock: &MonoClock,
    shutdown: &CancellationToken,
) -> anyhow::Result<Disposition> {
    // Wall-clock checkpoint for freeze detection. `MonoClock` (and iroh's idle timer) are monotonic
    // and PAUSE across a system suspend, so they can't tell a long screen-off from a momentary
    // stall; `SystemTime` keeps real time across suspend. A large gap between two (≤50ms-cadence)
    // iterations therefore fingerprints a resume-from-freeze (see `STALE_AFTER_FREEZE`).
    let mut last_wall = std::time::SystemTime::now();
    // Last RTT we emitted a debug log for, so an operator with `RUST_LOG=koh=debug` can see whether a
    // sluggish session is the link (RTT climbing) or the server — without spamming a line per tick
    // (O-07). Only a meaningful change (>= 30 ms) is logged.
    let mut last_logged_rtt: Option<f64> = None;
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

        let now = clock.now_ms();
        let rtt = channel.rtt_ms();
        if let Some(ms) = rtt {
            if last_logged_rtt.is_none_or(|prev| (prev - ms).abs() >= 30.0) {
                tracing::debug!(rtt_ms = ms, "link rtt");
                last_logged_rtt = Some(ms);
            }
        }
        let tick = session.on_tick(now, channel.max_datagram_size(), rtt);
        for datagram in &tick.outgoing {
            channel.send(datagram);
        }

        // Repaint on new content, while the banner is up, or once more to clear a stale banner.
        let status_now = tick.status.is_some();
        if session.dirty || status_now || session.status_was_shown {
            term.render(
                session.screen(),
                &session.overlay(),
                tick.status.as_deref(),
                session.window_state(),
            )?;
            session.status_was_shown = status_now;
            session.dirty = false;
        }

        if let Some(code) = tick.ended {
            let _ = term.render(
                session.screen(),
                &Overlay::empty(),
                Some("[koh] session ended"),
                session.window_state(),
            );
            // Brief dwell so the "session ended" banner is seen — but stay responsive to a
            // SIGTERM/SIGINT/SIGHUP (this was the one await not inside the select!), so an impatient
            // signal right after the shell exits restores the TTY now instead of after 400ms.
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(400)) => {}
                () = shutdown.cancelled() => {}
            }
            return Ok(Disposition::Ended(code));
        }

        tokio::select! {
            // Input-priority: a queued screen update must never starve local keystrokes (mosh
            // keeps typing responsive even when the screen is busy). The server loop is the mirror
            // image and is deliberately NOT biased (see `crate::server::run_attached`).
            biased;

            maybe = input_rx.recv() => {
                match maybe {
                    Some(chunk) => match session.on_input(clock.now_ms(), &chunk) {
                        InputOutcome::Quit => return Ok(Disposition::Quit),
                        InputOutcome::Suspend => {
                            // Ctrl-^ Ctrl-Z: hand the terminal back to the shell, stop, and on
                            // resume re-enter raw mode and force a full repaint. A no-op for the
                            // scripted test terminal.
                            term.suspend_resume()?;
                            session.dirty = true;
                            // The process was parked for the whole foreground-suspend (possibly
                            // minutes); reset the freeze checkpoint so that deliberate suspend isn't
                            // misread as a screen-off freeze and forced into a needless reconnect
                            // (KR-05). Real screen-off/deep-sleep doesn't go through this arm.
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
            _ = shutdown.cancelled() => return Ok(Disposition::Quit),

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
    shutdown: &CancellationToken,
    attempt: &mut u32,
) -> ReconnectOutcome {
    let started = clock.now_ms();
    let mut pending_escape = false;
    'attempt: loop {
        // Back off BEFORE dialing whenever we've already failed a dial or the previous connection
        // dropped too fast (`*attempt > 0`). The caller seeds `*attempt` from the just-dropped
        // connection's dwell, so a server that completes the handshake then immediately closes is
        // backed off here rather than redialed instantly — closing the tight-loop hole (K-03). On a
        // proven-then-dropped connection `*attempt == 0`, so a normal reconnect dials at once. The
        // wait stays responsive to the quit escape / shutdown and keeps the banner clock ticking.
        if *attempt > 0 {
            let wait_until = clock.now_ms().saturating_add(backoff_ms(*attempt));
            while clock.now_ms() < wait_until {
                let secs = clock.now_ms().saturating_sub(started) / 1000;
                let banner =
                    format!("[koh] disconnected — reconnecting… {secs}s (Ctrl-^ . to quit)");
                let _ = term.render(
                    last.screen(),
                    &Overlay::empty(),
                    Some(banner.as_str()),
                    last.window_state(),
                );
                let remaining = wait_until.saturating_sub(clock.now_ms());
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
                    _ = tokio::time::sleep(Duration::from_millis(remaining.min(1000))) => {}
                }
            }
        }
        let dial = tokio::time::timeout(connector.dial_timeout(), connector.connect());
        tokio::pin!(dial);
        loop {
            let secs = clock.now_ms().saturating_sub(started) / 1000;
            let banner = format!("[koh] disconnected — reconnecting… {secs}s (Ctrl-^ . to quit)");
            let _ = term.render(
                last.screen(),
                &Overlay::empty(),
                Some(banner.as_str()),
                last.window_state(),
            );

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
    use crate::input::InputEvent;
    use crate::terminal::ServerTerminal;

    /// Regression guard for the SK dial-timeout mismatch: a `--require-sk` dial includes a hardware
    /// touch that the server (and ssh-agent) grant up to `SK_TOUCH_GRACE`, so the client's SK dial
    /// budget MUST exceed that grace — otherwise a slow-but-legitimate touch is aborted client-side
    /// before the server would have admitted it, making the feature flaky.
    #[test]
    fn sk_dial_timeout_exceeds_the_server_touch_grace() {
        let grace = crate::transport_iroh::sk_auth::SK_TOUCH_GRACE;
        assert!(
            RECONNECT_CONNECT_TIMEOUT_SK > grace,
            "client SK dial budget ({RECONNECT_CONNECT_TIMEOUT_SK:?}) must exceed the server/agent \
             touch grace ({grace:?}) so a slow touch isn't aborted client-side"
        );
        // The plain (no-SK) path keeps its tight budget.
        assert!(RECONNECT_CONNECT_TIMEOUT < RECONNECT_CONNECT_TIMEOUT_SK);
    }

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
    fn escape_prefix_ctrl_z_suspends() {
        let mut s = new_session();
        // 0x1e then Ctrl-Z (0x1a) requests a background suspend.
        assert_eq!(
            s.on_input(0, &[ESCAPE_PREFIX, SUSPEND_KEY]),
            InputOutcome::Suspend
        );
        // The suffix also works split across chunks (the pending-escape state carries over).
        assert_eq!(s.on_input(0, &[ESCAPE_PREFIX]), InputOutcome::Forwarded);
        assert_eq!(s.on_input(0, &[SUSPEND_KEY]), InputOutcome::Suspend);
    }

    #[test]
    fn bytes_before_suspend_escape_are_forwarded_first() {
        let mut s = new_session();
        // Typing "hi" then Ctrl-^ Ctrl-Z in one chunk: "hi" must reach the server before we suspend.
        assert_eq!(
            s.on_input(0, &[b'h', b'i', ESCAPE_PREFIX, SUSPEND_KEY]),
            InputOutcome::Suspend
        );
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
            typed, b"hi",
            "pre-escape bytes are forwarded before suspending"
        );
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
    fn dwell_gate_resets_on_proven_connection_and_climbs_on_flap() {
        // K-03: a connection that lasted >= the dwell threshold proved itself -> backoff resets to 0
        // (prompt reattach), regardless of the prior attempt count.
        assert_eq!(next_attempt_after_drop(0, MIN_CONNECTION_DWELL_MS), 0);
        assert_eq!(next_attempt_after_drop(5, MIN_CONNECTION_DWELL_MS), 0);
        assert_eq!(
            next_attempt_after_drop(5, MIN_CONNECTION_DWELL_MS + 10_000),
            0
        );
        // A connection that dropped before the threshold (accept-then-close server) is a flap:
        // the counter climbs so the next redial backs off.
        assert_eq!(next_attempt_after_drop(0, 0), 1);
        assert_eq!(next_attempt_after_drop(3, MIN_CONNECTION_DWELL_MS - 1), 4);
        // Saturates rather than overflowing under a sustained flapping server.
        assert_eq!(next_attempt_after_drop(u32::MAX, 0), u32::MAX);
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
    fn link_down_banner_absorbs_a_missed_keepalive_but_shows_on_a_real_stall() {
        // Regression: the "link down — resuming…" banner used a 3 s grace — exactly the keepalive
        // interval (ssp::ACK_INTERVAL) — so a single dropped/jittered keepalive on a lossy link
        // pushed the silence gap just past the grace and flashed the banner, then cleared the moment
        // the next keepalive landed. The grace is now several keepalive intervals, so transient loss
        // is absorbed while a genuine stall still surfaces.
        let mut s = new_session();
        // Stamp last_heard with a real decoded server frame at t = 1000.
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.process(b"ready prompt $ ");
        let mut server = Transport::<TerminalScreen, UserInput>::new(0, 1200);
        server.set_connected(true);
        server.observe_rtt(20.0);
        *server.current_mut() = emu.snapshot();
        for dg in drive_until_nonempty(&mut server) {
            s.on_datagram(1000, &dg);
        }

        // One missed keepalive ≈ two intervals of silence — still inside the grace, so no banner.
        let absorbed = s.on_tick(1000 + 2 * crate::ssp::ACK_INTERVAL, 1200, Some(20.0));
        assert!(
            absorbed.status.is_none(),
            "a single missed keepalive must not flash the link-down banner"
        );
        // Right at the grace boundary: still no banner (the gate is strictly past the grace).
        let boundary = s.on_tick(1000 + LINK_DOWN_GRACE_MS, 1200, Some(20.0));
        assert!(
            boundary.status.is_none(),
            "the banner must not show until the silence exceeds the grace"
        );
        // A sustained silence well past the grace is a real stall — the banner shows.
        let stalled = s.on_tick(1000 + LINK_DOWN_GRACE_MS + 2_000, 1200, Some(20.0));
        assert!(
            stalled.status.is_some(),
            "a silence past the grace shows the link-down banner"
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
