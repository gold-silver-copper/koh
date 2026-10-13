//! The koh client: the session loop, abstracted over a [`ClientTerminal`].
//!
//! Typed bytes and resize ticks arrive on channels; output and the window size go through
//! [`ClientTerminal`]: the real tty ([`BackendTerminal`] over [`KohBackend`]) in the binary, a
//! capturing mock in tests.

pub mod backend;
pub mod cli;
mod io;
mod link;
mod probe;
mod render;
mod scrollback;
mod session;

pub use backend::{DefaultBackend, KohBackend};
pub use cli::{connect, BellHook, ConnectConfig};
pub(crate) use io::spawn_client_io;
pub use render::WindowState;
pub use session::{ClientSession, Found, InputOutcome, TickResult};

use std::time::{Duration, Instant, SystemTime};

use crate::log::Peer;
use crate::predict::Overlay;
use crate::proto::{decode_server, encode_client, ClientMsg, Close, ServerMsg, Stream, MAX_FRAME};
use crate::terminal::{Size, TerminalScreen};
use crate::transport_iroh::{closed_because, ALPN, PROTOCOL};
use iroh::endpoint::{Connection, RecvStream};
use iroh::{Endpoint, EndpointAddr};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

/// Prefixed to the mirrored window title, as mosh prefixes `[mosh] `.
const KOH_TITLE_PREFIX: &str = "[koh] ";

/// The escape prefix (Ctrl-^); followed by '.' it disconnects the session.
pub(crate) const ESCAPE_PREFIX: u8 = 0x1e;
/// After the escape prefix, suspends the client (as mosh does): in raw mode `Ctrl-Z` is a plain
/// byte, not SIGTSTP.
pub(crate) const SUSPEND_KEY: u8 = 0x1a;

/// After [`ESCAPE_PREFIX`], opens the scrollback view.
pub(crate) const SCROLLBACK_KEY: u8 = b'[';

/// How long a single reconnect dial may run before it is abandoned and retried.
const RECONNECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Reconnect backoff: `BASE << min(attempt, 4)`, capped at `MAX`; attempts from 1 wait 1, 2, 4, 8 s.
const RECONNECT_BACKOFF_BASE: Duration = Duration::from_millis(500);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(8);
/// How long a connection must last to reset the reconnect backoff. One that drops sooner counts as
/// a failed dial, so a server that accepts and at once closes cannot drive a tight redial loop.
const MIN_CONNECTION_DWELL: Duration = Duration::from_secs(5);

/// A wall-clock gap between two loop iterations (which run at least every 50 ms) this long means
/// the process was frozen, as Android does at screen-off. The connection is then almost surely
/// dead, but iroh's idle timer runs on the monotonic clock, which pauses too, so it would hold it
/// for up to five minutes; reconnecting at once reattaches in a second or two. A false positive
/// costs only a brief banner, so the threshold is low.
const STALE_AFTER_FREEZE: Duration = Duration::from_secs(20);

/// Dials the server and awaits its first frame, which admits the client: the first connection and every reconnect, which
/// reattaches to the same server session.
pub struct IrohConnector {
    endpoint: Endpoint,
    target: EndpointAddr,
}

impl IrohConnector {
    /// A connector dialing `target` from `endpoint`.
    pub const fn new(endpoint: Endpoint, target: EndpointAddr) -> Self {
        Self { endpoint, target }
    }

    /// Connect and await the stream of the first frame, which the server sends once the client has a
    /// session.
    /// A server that will not have us for good closes the connection instead, a [`Refused`]
    /// error, so the client fails fast rather than redialing forever; one that cannot have us now
    /// (at capacity, say) closes it saying so, an error that is its [`Close`].
    pub async fn connect(&self) -> anyhow::Result<Admitted> {
        let conn = match self.endpoint.connect(self.target.clone(), ALPN).await {
            Ok(conn) => conn,
            Err(e) if refused_our_alpn(&e) => return Err(Refused::OtherProtocol.into()),
            Err(e) => anyhow::bail!("connecting to server: {}", Peer(e)),
        };
        match conn.accept_uni().await {
            Ok(first) => Ok(Admitted(conn, first)),
            Err(e) => Err(match closed_because(&conn) {
                Some(Close::NotAuthorized) => Refused::NotAuthorized.into(),
                Some(why) => why.into(),
                None => anyhow::anyhow!("server did not admit the connection: {}", Peer(e)),
            }),
        }
    }
}

/// A connection the server admitted, and the stream of its first frame, which said so.
pub struct Admitted(pub Connection, RecvStream);

/// The server refused us for good: redialing cannot help, so the client exits saying why.
#[derive(Debug, thiserror::Error)]
pub enum Refused {
    #[error("server rejected the connection: {}", Close::NotAuthorized)]
    NotAuthorized,
    #[error("the server does not speak this koh protocol ({PROTOCOL}); upgrade koh on both ends")]
    OtherProtocol,
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

/// The wait before redialing after `attempt` (from 1) failures.
fn backoff(attempt: u32) -> Duration {
    RECONNECT_BACKOFF_BASE
        .saturating_mul(1u32 << attempt.min(4))
        .min(RECONNECT_BACKOFF_MAX)
}

/// The attempt counter after a connection that lasted `dwell` dropped: reset if it lasted
/// [`MIN_CONNECTION_DWELL`], else counted as a failed dial.
const fn next_attempt_after_drop(attempt: u32, dwell: Duration) -> u32 {
    if dwell.as_millis() >= MIN_CONNECTION_DWELL.as_millis() {
        0
    } else {
        attempt.saturating_add(1)
    }
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

/// Where the client paints frames and reads the window size: the tty, or a test's capture.
pub trait ClientTerminal {
    /// Paint `state`, the synced screen, with the predictions `overlay` and an optional status
    /// line.
    fn render(
        &mut self,
        state: &TerminalScreen,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> std::io::Result<()>;

    /// The current window size.
    fn size(&self) -> std::io::Result<Size>;

    /// The window was resized: whatever it showed may be gone, so the next [`render`](Self::render)
    /// paints everything. Default: a no-op, for a terminal that paints everything every time.
    fn window_resized(&mut self) {}

    /// Suspend the client (`Ctrl-^ Ctrl-Z`): restore the user's terminal and stop the process with
    /// SIGTSTP; whether it did, so the caller waits for SIGCONT before [`resume`](Self::resume).
    /// Default: nothing, so a test terminal never stops the test process.
    fn suspend(&mut self) -> std::io::Result<bool> {
        Ok(false)
    }

    /// Take the terminal back after a [`suspend`](Self::suspend): it was reset meanwhile.
    fn resume(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Ask the user's terminal `questions` (the session's: what it does at start-up, its colours
    /// again after it reported a new scheme). Default: a no-op, for a terminal that answers
    /// nothing.
    fn ask(&mut self, _questions: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    /// The user's terminal said what it does: paint and listen by it. Default: a no-op.
    fn found(&mut self, _found: Found) -> std::io::Result<()> {
        Ok(())
    }

    /// The run's first frame arrived, showing `win`: the clipboard and bells in it are from before
    /// the client came. Default: a no-op, for a terminal that mirrors neither.
    fn prime(&mut self, _win: WindowState<'_>) {}
}

/// This process's pid, as the signal calls take it.
fn own_pid() -> std::io::Result<fuxix::process::Pid> {
    i32::try_from(std::process::id())
        .ok()
        .and_then(fuxix::process::Pid::from_raw)
        .ok_or_else(|| std::io::Error::other("this process's pid is not a valid pid"))
}

/// The production [`ClientTerminal`] over a [`KohBackend`]: raw mode and the alternate screen from
/// [`enter`](Self::enter) until drop, the mirrored window state, and the painted grid.
pub struct BackendTerminal<B: KohBackend> {
    backend: B,
    /// The title, clipboard, bell and input modes mirrored to the terminal.
    oob: render::OutOfBand,
    /// What the terminal was last painted with, so a frame paints only what changed.
    painter: render::Painter,
    /// What the client turned on in the user's terminal beside the input modes, which it turns
    /// off again on leaving and on suspend: kitty's disambiguate and alternate keys, pushed, and
    /// scheme reports (mode 2031).
    extras: Extras,
    /// What was on when the client suspended, to turn on at the resume.
    suspended: Extras,
}

/// What the client turns on in a terminal that speaks it, beside the input modes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Extras {
    kitty: bool,
    scheme_reports: bool,
}

impl Extras {
    /// The bytes turning on what `self` has and `was` has not.
    fn on(self, was: Self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.kitty && !was.kitty {
            out.extend_from_slice(b"\x1b[>5u");
        }
        if self.scheme_reports && !was.scheme_reports {
            out.extend_from_slice(b"\x1b[?2031h");
        }
        out
    }

    /// The bytes turning them off: the push popped.
    fn off(self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.kitty {
            out.extend_from_slice(b"\x1b[<u");
        }
        if self.scheme_reports {
            out.extend_from_slice(b"\x1b[?2031l");
        }
        out
    }
}

impl<B: KohBackend> BackendTerminal<B> {
    /// Enter raw mode and the alternate screen on `backend`. `clipboard_enabled` lets the server
    /// set the clipboard (OSC 52).
    pub fn enter(mut backend: B, clipboard_enabled: bool) -> std::io::Result<Self> {
        backend.enter_raw_mode()?;
        let mut this = Self {
            backend,
            oob: render::OutOfBand::with_title_prefix(KOH_TITLE_PREFIX.to_string())
                .with_clipboard(clipboard_enabled),
            painter: render::Painter::default(),
            extras: Extras::default(),
            suspended: Extras::default(),
        };
        this.backend.enter_alt_screen()?;
        Ok(this)
    }

    /// Turn on, until the client leaves, what `want` has and is not on yet.
    fn turn_on(&mut self, want: Extras) -> std::io::Result<()> {
        let on = want.on(self.extras);
        self.extras = want;
        self.ask(&on)
    }

    /// Paint underline styles (`4:n`) if the terminal draws them (`on`), else plain underlines,
    /// the default; what the terminal shows is painted again.
    pub fn set_underline_styles(&mut self, on: bool) {
        self.painter.set_underline_styles(on);
    }

    /// Paint hyperlinks (OSC 8) if `on`, the default; else their text alone. What the terminal
    /// shows is painted again.
    pub fn set_hyperlinks(&mut self, on: bool) {
        self.painter.set_hyperlinks(on);
    }

    /// Turn off what [`turn_on`](Self::turn_on) turned on.
    fn turn_off(&mut self) -> std::io::Result<()> {
        let off = std::mem::take(&mut self.extras).off();
        self.ask(&off)
    }
}

impl<B: KohBackend> ClientTerminal for BackendTerminal<B> {
    fn render(
        &mut self,
        state: &TerminalScreen,
        overlay: &Overlay,
        status: Option<&str>,
    ) -> std::io::Result<()> {
        self.oob.emit(
            &mut self.backend,
            state.screen().modes().mouse_mode,
            window_state(state),
        )?;
        self.painter
            .render(&mut self.backend, state.screen(), overlay, status)
    }

    fn size(&self) -> std::io::Result<Size> {
        self.backend.size()
    }

    fn window_resized(&mut self) {
        self.painter.invalidate();
    }

    fn ask(&mut self, questions: &[u8]) -> std::io::Result<()> {
        if questions.is_empty() {
            return Ok(());
        }
        self.backend.write_bytes(questions)?;
        self.backend.flush()
    }

    fn found(&mut self, found: Found) -> std::io::Result<()> {
        self.painter.set_underline_styles(found.underline_styles);
        self.turn_on(Extras {
            kitty: found.kitty,
            scheme_reports: found.scheme_reports,
        })
    }

    fn prime(&mut self, win: WindowState<'_>) {
        self.oob.prime(win);
    }

    fn suspend(&mut self) -> std::io::Result<bool> {
        // Off until turned on again at the resume, so a failure meanwhile does not turn them off
        // twice.
        self.suspended = self.extras;
        self.turn_off()?;
        self.backend.leave_alt_screen()?;
        self.backend.leave_raw_mode()?;
        let _ = self
            .backend
            .write_bytes("\n[koh suspended — run `fg` to resume]\n".as_bytes());
        let _ = self.backend.flush();
        fuxix::process::kill(own_pid()?, fuxix::process::Signal::Tstp)?;
        Ok(true)
    }

    fn resume(&mut self) -> std::io::Result<()> {
        // The terminal was reset meanwhile: everything is asserted again on the next frame.
        self.backend.enter_raw_mode()?;
        self.backend.enter_alt_screen()?;
        let extras = std::mem::take(&mut self.suspended);
        self.turn_on(extras)?;
        self.oob.invalidate();
        self.painter.invalidate();
        Ok(())
    }
}

impl<B: KohBackend> Drop for BackendTerminal<B> {
    fn drop(&mut self) {
        // Best-effort: a mode left on (mouse reporting, say) would garble the user's shell.
        let _ = self.turn_off();
        let _ = self.backend.leave_alt_screen();
        let _ = self.backend.leave_raw_mode();
    }
}

/// Run a client session on `initial`, redialing through `connector` and reattaching to the same
/// server session whenever the link drops; meanwhile the last screen stays up under a banner.
///
/// The I/O shell around [`ClientSession`], which makes every protocol decision. One session lives
/// for the whole run, its first phase asking the user's terminal what it does (its colours too if
/// `colours`), so stdin has one decoder from start to end and what is typed while the link is down
/// is read by the same escape machine. `input_rx` carries typed bytes (its closing ends the
/// session); `resize_rx` carries resize ticks, on which the size is read from `term`
/// (`initial_size` if that fails). Cancelling `shutdown` (on a fatal signal) quits like the user,
/// so the terminal is restored. `bell` runs on every remote bell.
///
/// The client's stream is opened and written by its own task behind a bounded queue, and frames
/// are read by their own tasks, so nothing here waits on the network outside the one `select!`:
/// the keyboard, the quit escape and signals stay live even when the server grants no stream or
/// stops reading.
///
/// Returns the remote shell's exit code if it exited, `None` on a local quit.
#[expect(
    clippy::too_many_arguments,
    reason = "the I/O shell wires up the connection, connector, size, whether colours are told, \
              the two input/resize channels, the terminal, the shutdown token and the bell hook — \
              each a distinct collaborator; bundling them into a struct would only move the list, \
              not shorten it"
)]
pub async fn run_client<T: ClientTerminal>(
    initial: Admitted,
    dialed_at: SystemTime,
    connector: IrohConnector,
    initial_size: Size,
    colours: bool,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    resize_rx: mpsc::Receiver<()>,
    mut term: T,
    shutdown: CancellationToken,
    mut bell: Option<BellHook>,
) -> anyhow::Result<Option<u32>> {
    let mut session = ClientSession::new(term.size().unwrap_or(initial_size));
    session.ask_terminal(Instant::now(), colours);
    // `None` once the resize ticks end, so a closed channel is not polled again.
    let mut resize_rx = Some(resize_rx);
    // Kept across connections: only one that lasts resets it (see `MIN_CONNECTION_DWELL`).
    let mut attempt: u32 = 0;
    let mut net = Net::Up(Wire::open(initial));
    // Wall-clock time, which keeps running while the process is frozen (see `STALE_AFTER_FREEZE`),
    // from when the connection was made: a freeze before the first iteration counts.
    let mut last_wall = dialed_at;
    // Logged on a change of 30 ms or more, to tell a slow link from a slow server in debug logs.
    let mut last_logged_rtt: Option<Duration> = None;
    // The status line as last painted: painted again only when it changes.
    let mut shown_status: Option<String> = None;
    loop {
        // A clock stepped backwards reads as no gap.
        let wall_now = SystemTime::now();
        let wall_gap = wall_now.duration_since(last_wall).unwrap_or(Duration::ZERO);
        last_wall = wall_now;
        let rtt = if let Net::Up(wire) = &net {
            if wall_gap >= STALE_AFTER_FREEZE {
                tracing::info!(
                    frozen_secs = wall_gap.as_secs(),
                    "detected resume from a process freeze (suspend/screen-off); forcing a reconnect"
                );
                net = redial(wire, &mut attempt, &mut session, &connector);
                continue;
            }
            crate::transport_iroh::rtt(&wire.conn)
        } else {
            None
        };
        if let Some(rtt) = rtt {
            if last_logged_rtt.is_none_or(|prev| prev.abs_diff(rtt) >= Duration::from_millis(30)) {
                tracing::debug!(rtt_ms = rtt.as_millis(), "link rtt");
                last_logged_rtt = Some(rtt);
            }
        }
        let now = Instant::now();
        let tick = session.on_tick(now, rtt);

        // Repaint on new content, or when the status line says something else.
        if session.dirty || tick.status != shown_status {
            match session.view() {
                Some(view) => term.render(&view, &Overlay::default(), tick.status.as_deref())?,
                None => term.render(session.state(), &session.overlay(), tick.status.as_deref())?,
            }
            shown_status = tick.status;
            session.dirty = false;
            // Only once synced: the first synced frame primes the hook and the mirroring, so bells
            // and a clipboard from before this attach reach neither.
            if session.synced() {
                let win = session.window_state();
                term.prime(win);
                if let Some(hook) = bell.as_mut() {
                    hook.prime(win.bell_count);
                    if hook.observe(win.bell_count, now) {
                        hook.fire(win.bell_count, win.title);
                    }
                }
            }
        }

        if session.exited() {
            end_session(&mut term, &session, &shutdown).await;
            return Ok(session.state().exit_code());
        }

        // What the user's terminal said it does, and the questions the session has for it.
        if let Some(found) = session.take_found() {
            term.found(found)?;
        }
        let questions = session.take_questions();
        if let Err(e) = term.ask(&questions) {
            tracing::debug!(error = %e, "could not ask the terminal");
        }

        let (writers, frames, dialing) = match &mut net {
            Net::Up(wire) => (
                Some((&wire.input_tx, &wire.control_tx)),
                Some(&mut wire.frame_rx),
                None,
            ),
            Net::Down(dial) => (None, None, Some(dial)),
        };
        let change = tokio::select! {
            // Not biased: a flood of keystrokes must not starve frames, nor frames keystrokes.
            maybe = input_rx.recv() => match maybe {
                Some(chunk) => session.on_input(Instant::now(), &chunk).into(),
                None => Some(Change::Quit), // input source closed
            },
            // A lone Escape, or a sequence cut short, is taken as typed once nothing follows.
            () = when(session.deadline().map(|at| tokio::time::sleep_until(at.into()))) => {
                session.on_timeout(Instant::now()).into()
            }
            () = shutdown.cancelled() => Some(Change::Quit),
            permit = when(writers.map(|(input, _)| input.reserve())), if session.has_outgoing_on(Stream::Input) => {
                send(permit.ok(), session.pop_outgoing_on(Stream::Input))
            }
            permit = when(writers.map(|(_, control)| control.reserve())), if session.has_outgoing_on(Stream::Control) => {
                send(permit.ok(), session.pop_outgoing_on(Stream::Control))
            }
            maybe = when(resize_rx.as_mut().map(mpsc::Receiver::recv)) => {
                match maybe {
                    Some(()) => {
                        term.window_resized();
                        if let Ok(size) = term.size() {
                            session.on_resize(size);
                        }
                    }
                    None => resize_rx = None,
                }
                None
            }
            frame = when(frames.map(mpsc::Receiver::recv)) => match frame.map(|received| received.msg) {
                // The frame reader ended because the connection closed.
                None => Some(Change::Closed),
                Some(msg) => {
                    session.on_server(Instant::now(), msg);
                    None
                }
            },
            dialed = when(dialing) => Some(Change::Dialed(dialed)),
            () = tokio::time::sleep(tick.wait) => None,
        };
        match change {
            None => {}
            Some(Change::Quit) => return Ok(None),
            Some(Change::Suspend) => {
                let Some(typed) = suspend(&mut term, &shutdown, &mut input_rx).await? else {
                    return Ok(None);
                };
                // A suspend escape typed meanwhile is not taken again.
                if session.on_input(Instant::now(), &typed) == InputOutcome::Quit {
                    return Ok(None);
                }
                // A window resized while the client was stopped sent it no SIGWINCH.
                term.window_resized();
                if let Ok(size) = term.size() {
                    session.on_resize(size);
                }
                session.dirty = true;
                shown_status = None;
                // A deliberate suspend is not a freeze to reconnect after.
                last_wall = SystemTime::now();
            }
            Some(Change::Closed) => {
                let Net::Up(wire) = &mut net else {
                    continue;
                };
                // The server ended the session (its shell exited); else the link was lost.
                if closed_because(&wire.conn) == Some(Close::SessionEnded) {
                    // What the reader still has was sent before the close: the last frame says
                    // how the program exited, whichever end noticed the close first.
                    let drained = async {
                        while let Some(received) = wire.frame_rx.recv().await {
                            session.on_server(Instant::now(), received.msg);
                        }
                    };
                    let _ = tokio::time::timeout(Duration::from_secs(1), drained).await;
                    end_session(&mut term, &session, &shutdown).await;
                    return Ok(session.state().exit_code());
                }
                tracing::info!(reason = ?wire.conn.close_reason(), "link lost; will reconnect");
                net = redial(wire, &mut attempt, &mut session, &connector);
            }
            Some(Change::Dialed(Ok(Ok(conn)))) => {
                session.attach(term.size().unwrap_or(initial_size));
                net = Net::Up(Wire::open(conn));
            }
            Some(Change::Dialed(failed)) => {
                if let Ok(Err(e)) = failed {
                    if e.is::<Refused>() {
                        return Err(e);
                    }
                    // Refused for now (at capacity, say): redialing may do, and the banner says why.
                    if let Some(why) = e.downcast_ref::<Close>() {
                        session.refused(why.text());
                    }
                    tracing::info!(reason = %e, attempt, "reconnect dial failed");
                } else {
                    tracing::info!(attempt, "reconnect dial timed out");
                }
                attempt = attempt.saturating_add(1);
                net = Net::Down(dial(&connector, attempt));
            }
        }
    }
}

/// Suspend the client on `term`, and once the process is continued take the terminal back; what
/// was typed meanwhile, to go on with, or `None` to quit. The stop may never come (the kernel
/// drops it in a process group without job control): then a key typed, which a stopped process
/// could not read, ends the wait too, as does a fatal signal or the input's end, which quit.
async fn suspend<T: ClientTerminal>(
    term: &mut T,
    shutdown: &CancellationToken,
    input: &mut mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<Option<Vec<u8>>> {
    use tokio::signal::unix::{signal, SignalKind};
    // Listening before the stop, so the SIGCONT that ends it is not missed.
    let mut continued = signal(SignalKind::from_raw(fuxix::process::Signal::Cont.raw()))?;
    let mut typed = Vec::new();
    if term.suspend()? {
        tokio::select! {
            _ = continued.recv() => {}
            maybe = input.recv() => match maybe {
                Some(bytes) => typed = bytes,
                None => return Ok(None),
            },
            () = shutdown.cancelled() => return Ok(None),
        }
    }
    term.resume()?;
    Ok(Some(typed))
}

/// The client's link to the server: a live connection, or a redial under way.
enum Net<'c> {
    Up(Wire),
    Down(Dial<'c>),
}

/// A redial: the backoff, then one dial, abandoned after [`RECONNECT_CONNECT_TIMEOUT`]. Pinned,
/// so banner repaints and keystrokes do not restart a slow one.
type Dial<'c> = std::pin::Pin<Box<dyn std::future::Future<Output = Dialed> + Send + 'c>>;

/// A redial's result: connected, refused, or timed out.
type Dialed = Result<anyhow::Result<Admitted>, tokio::time::error::Elapsed>;

/// What one turn of [`run_client`]'s loop left for it to act on.
enum Change {
    /// The user quit, the input channel closed, or a fatal signal came.
    Quit,
    /// The user typed the suspend escape.
    Suspend,
    /// The connection closed: the session ended, or the link was lost.
    Closed,
    /// A redial finished.
    Dialed(Dialed),
}

impl From<InputOutcome> for Option<Change> {
    fn from(outcome: InputOutcome) -> Self {
        match outcome {
            InputOutcome::Quit => Some(Change::Quit),
            InputOutcome::Suspend => Some(Change::Suspend),
            InputOutcome::Forwarded => None,
        }
    }
}

/// A live connection: its stream writer and frame reader, which end with it, and it with them.
struct Wire {
    conn: Connection,
    /// The writers of the client's input and control streams.
    input_tx: mpsc::Sender<Vec<u8>>,
    control_tx: mpsc::Sender<Vec<u8>>,
    frame_rx: mpsc::Receiver<Received>,
    _writers: [AbortOnDropHandle<()>; 2],
    _reader: AbortOnDropHandle<()>,
    /// When the loop took the connection, for its dwell.
    started: Instant,
}

impl Wire {
    /// Start the tasks opening and writing the client's input and control streams and reading
    /// frames on `conn`. Each stream is opened by its writer, so a server that grants none holds
    /// up nothing else; one that fails to open ends its writer, which loses the link.
    fn open(Admitted(conn, first): Admitted) -> Self {
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE);
        let (control_tx, control_rx) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE);
        let (frame_tx, frame_rx) = mpsc::channel::<Received>(FRAME_QUEUE);
        #[expect(
            clippy::disallowed_methods,
            reason = "two writers and a reader a connection"
        )]
        let (writers, reader) = (
            [input_rx, control_rx].map(|rx| {
                AbortOnDropHandle::new(tokio::spawn(write_client_stream(conn.clone(), rx)))
            }),
            AbortOnDropHandle::new(tokio::spawn(read_frames(conn.clone(), first, frame_tx))),
        );
        Self {
            conn,
            input_tx,
            control_tx,
            frame_rx,
            _writers: writers,
            _reader: reader,
            started: Instant::now(),
        }
    }
}

impl Drop for Wire {
    /// The run, or this connection, is over: the server is told at once, not at the idle timeout.
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"client exit");
    }
}

/// The link on `wire` was lost: close it, detach the session, and redial.
fn redial<'c>(
    wire: &Wire,
    attempt: &mut u32,
    session: &mut ClientSession,
    connector: &'c IrohConnector,
) -> Net<'c> {
    wire.conn.close(0u32.into(), b"reconnecting");
    *attempt = next_attempt_after_drop(*attempt, wire.started.elapsed());
    session.detach(Instant::now());
    Net::Down(dial(connector, *attempt))
}

/// Dial again: at once after a proven connection's drop (`attempt` 0), else after a backoff, so a
/// server that completes the handshake and at once closes is not redialed in a tight loop.
fn dial(connector: &IrohConnector, attempt: u32) -> Dial<'_> {
    let wait = if attempt > 0 {
        backoff(attempt)
    } else {
        Duration::ZERO
    };
    Box::pin(async move {
        tokio::time::sleep(wait).await;
        tokio::time::timeout(RECONNECT_CONNECT_TIMEOUT, connector.connect()).await
    })
}

/// What `future` gives, or never without one: a select arm for a state that may not be.
async fn when<F: std::future::Future>(future: Option<F>) -> F::Output {
    match future {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

/// How many encoded messages may wait for the client's stream writer.
const WRITER_QUEUE: usize = 64;
/// How many decoded frames may wait for the connection loop.
const FRAME_QUEUE: usize = 16;

/// Send `msg` with `permit`, a writer's room; a writer that ended (`None`) lost the connection.
fn send(permit: Option<mpsc::Permit<'_, Vec<u8>>>, msg: Option<ClientMsg>) -> Option<Change> {
    let Some(permit) = permit else {
        return Some(Change::Closed);
    };
    match msg.map(|msg| encode_client(&msg)) {
        Some(Ok(bytes)) => permit.send(bytes),
        Some(Err(e)) => tracing::warn!(error = %e, "dropping an unencodable message"),
        None => {}
    }
    None
}

/// Open the client's stream on `conn` and write queued messages to it, until the queue or the
/// stream closes.
async fn write_client_stream(conn: Connection, mut queue: mpsc::Receiver<Vec<u8>>) {
    let Ok(mut send) = conn.open_uni().await else {
        return;
    };
    while let Some(bytes) = queue.recv().await {
        if send.write_all(&bytes).await.is_err() {
            return;
        }
    }
    let _ = send.finish();
}

/// A server stream read past this is a large one, which needs one of [`LARGE_STREAMS`] to go on.
const SMALL_STREAM: usize = 256 * 1024;

/// Most large server streams read, or waiting for the loop, at once.
///
/// With the small ones, the client holds at most about `LARGE_STREAMS` of [`MAX_FRAME`] and
/// [`FRAME_QUEUE`] of twice [`SMALL_STREAM`] of the server's streams, as they came: some 40 MiB,
/// not 16 of the largest. The loop inflates them one at a time (a frame to at most [`MAX_FRAME`],
/// history rows to at most [`MAX_HISTORY_REPLY`](crate::terminal::MAX_HISTORY_REPLY)). A large stream waits for its turn holding at most two chunks, and one that has its
/// turn waits on nothing but its own bytes, so the turns cannot deadlock.
const LARGE_STREAMS: usize = 2;

/// A message from the server, holding its turn as a large stream, if it was one, until the loop
/// takes it.
struct Received {
    msg: ServerMsg,
    _large: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// Accept the server's streams (frames, and history rows), after `first`, each read on its own task so a stalled or
/// reset stream never holds up a newer frame. Ends when the connection closes.
///
/// At most [`FRAME_QUEUE`] streams are read or wait to be applied at once, together: a reader
/// takes its slot in `frames` before it reads. Past them, no stream is accepted, so QUIC's stream
/// limit stops the server opening more; and of them, at most [`LARGE_STREAMS`] are large.
async fn read_frames(conn: Connection, first: RecvStream, frames: mpsc::Sender<Received>) {
    let large = std::sync::Arc::new(tokio::sync::Semaphore::new(LARGE_STREAMS));
    let mut first = Some(first);
    loop {
        let Ok(slot) = frames.clone().reserve_owned().await else {
            return;
        };
        let mut recv = match first.take() {
            Some(recv) => recv,
            None => match conn.accept_uni().await {
                Ok(recv) => recv,
                Err(_) => return,
            },
        };
        let large = std::sync::Arc::clone(&large);
        #[expect(
            clippy::disallowed_methods,
            reason = "each holds one of the frames' slots"
        )]
        tokio::spawn(async move {
            let (mut bytes, mut turn) = (Vec::new(), None);
            // A reset (superseded), oversized or malformed stream is simply not delivered.
            while let Some(chunk) = recv.read_chunk(SMALL_STREAM).await.ok()? {
                bytes.extend_from_slice(&chunk);
                if bytes.len() > SMALL_STREAM && turn.is_none() {
                    turn = Some(std::sync::Arc::clone(&large).acquire_owned().await.ok()?);
                }
                if bytes.len() > MAX_FRAME {
                    return None;
                }
            }
            match decode_server(&bytes) {
                Ok(msg) => drop(slot.send(Received { msg, _large: turn })),
                Err(e) => tracing::debug!(error = %e, "dropping an undecodable frame"),
            }
            Some(())
        });
    }
}

/// Paint the "session ended" banner and linger briefly so it is seen.
async fn end_session<T: ClientTerminal>(
    term: &mut T,
    session: &ClientSession,
    shutdown: &CancellationToken,
) {
    let _ = term.render(
        session.state(),
        &Overlay::default(),
        Some("[koh] session ended"),
    );
    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(400)) => {}
        () = shutdown.cancelled() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a server sends to admit the client: a first stream, here an empty one.
    async fn admit(conn: &Connection) -> anyhow::Result<()> {
        conn.open_uni().await?.finish()?;
        Ok(())
    }

    /// A server that will not have the client for good (another protocol, or not authorized) is
    /// a [`Refused`]; one that cannot have it now closes saying why, and is redialed.
    #[test]
    fn a_refusal_is_for_good_only_when_not_authorized() {
        use crate::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr};
        let key = || generate_secret_key().expect("OS randomness");
        crate::test_runtime::current_thread().block_on(async {
            let client = bind_endpoint_local(key(), false).await.unwrap();
            // A server that only speaks the previous protocol's ALPN refuses the TLS handshake. The
            // error must say so, not blame the allowlist.
            let old = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(key())
                .alpns(vec![b"koh/iroh/2".to_vec()])
                .bind()
                .await
                .unwrap();
            let addr = loopback_addr(&old);
            let accept = koh_testkit::spawn(async move {
                if let Some(incoming) = old.accept().await {
                    let _ = incoming.await;
                }
                old
            });
            let Err(error) = IrohConnector::new(client.clone(), addr).connect().await else {
                panic!("an old-protocol server must refuse the handshake");
            };
            assert!(
                matches!(error.downcast_ref(), Some(Refused::OtherProtocol)),
                "{error:#}"
            );
            assert!(format!("{error:#}").contains(PROTOCOL), "{error:#}");
            let _ = accept.await;
            // A server that closes the connection instead of admitting it, saying why.
            let server = bind_endpoint_local(key(), true).await.unwrap();
            let connector = IrohConnector::new(client, loopback_addr(&server));
            for why in [
                Close::AtCapacity,
                Close::CouldNotStart,
                Close::NotAuthorized,
            ] {
                let (refusing, dialed) = tokio::join!(
                    async {
                        let conn = server.accept().await.unwrap().await.unwrap();
                        crate::transport_iroh::close(&conn, why);
                        conn.closed().await
                    },
                    connector.connect()
                );
                drop(refusing);
                let Err(error) = dialed else {
                    panic!("{why:?}: admitted");
                };
                if why == Close::NotAuthorized {
                    assert!(error.is::<Refused>(), "{why:?}: {error:#}");
                } else {
                    // Transient: redialed, and the banner says why.
                    assert!(!error.is::<Refused>(), "{why:?}: {error:#}");
                    assert_eq!(error.downcast_ref::<Close>(), Some(&why));
                }
            }
        });
    }

    #[test]
    fn reconnect_backoff_grows_then_caps() {
        // 1-based attempts: 1s, 2s, 4s, 8s, then capped at 8s; the shift is clamped, no overflow.
        for (attempt, secs) in [(1, 1), (2, 2), (3, 4), (4, 8), (5, 8), (99, 8)] {
            assert_eq!(backoff(attempt), Duration::from_secs(secs), "{attempt}");
        }
    }

    #[test]
    fn dwell_gate_resets_on_proven_connection_and_climbs_on_flap() {
        // A connection that lasted >= the dwell threshold proved itself -> backoff resets to 0
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

    /// What the client turns on in the user's terminal it turns off again, popping its push: on
    /// leaving (the terminal's drop) and on suspend (both call `turn_off`).
    #[test]
    fn the_kitty_push_and_scheme_reports_are_undone() {
        let mut term = BackendTerminal {
            backend: crate::client::backend::CaptureBackend::default(),
            oob: render::OutOfBand::with_title_prefix(String::new()),
            painter: render::Painter::default(),
            extras: Extras::default(),
            suspended: Extras::default(),
        };
        let both = Found {
            underline_styles: false,
            kitty: true,
            scheme_reports: true,
        };
        term.found(Found {
            scheme_reports: false,
            ..both
        })
        .unwrap();
        // Told again, with more: only what is new is turned on, so one push is popped.
        term.found(both).unwrap();
        assert_eq!(term.backend.bytes, b"\x1b[>5u\x1b[?2031h");
        term.backend.bytes.clear();
        term.turn_off().unwrap();
        assert_eq!(term.backend.bytes, b"\x1b[<u\x1b[?2031l");
        // A terminal that speaks neither is sent neither.
        term.backend.bytes.clear();
        term.found(Found::default()).unwrap();
        term.turn_off().unwrap();
        assert_eq!(term.backend.bytes, b"");
    }

    /// A terminal that shows nothing, of a fixed size.
    struct Blind;

    impl ClientTerminal for Blind {
        fn render(
            &mut self,
            _: &TerminalScreen,
            _: &Overlay,
            _: Option<&str>,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn size(&self) -> std::io::Result<Size> {
            Ok(Size::new(24, 80))
        }
    }

    /// A server that admits the client and grants it no stream to write on: the keyboard stays
    /// the client's, and the quit escape ends it at once.
    #[test]
    fn a_server_granting_no_streams_cannot_block_quit() {
        use crate::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr};
        use iroh::endpoint::{QuicTransportConfig, VarInt};
        let key = || generate_secret_key().expect("OS randomness");
        crate::test_runtime::current_thread().block_on(async {
            let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(key())
                .alpns(vec![ALPN.to_vec()])
                .transport_config(
                    QuicTransportConfig::builder()
                        .max_concurrent_uni_streams(VarInt::from_u32(0))
                        .build(),
                )
                .bind()
                .await
                .expect("bind the server");
            let addr = loopback_addr(&server);
            let accept = koh_testkit::spawn(async move {
                if let Some(incoming) = server.accept().await {
                    if let Ok(conn) = incoming.await {
                        if admit(&conn).await.is_ok() {
                            conn.closed().await;
                        }
                    }
                }
                server
            });
            let client = bind_endpoint_local(key(), false)
                .await
                .expect("bind the client");
            let connector = IrohConnector::new(client, addr);
            let conn = connector.connect().await.expect("admitted");
            let (input, input_rx) = mpsc::channel(8);
            let (_resize, resize_rx) = mpsc::channel(1);
            let run = koh_testkit::spawn(run_client(
                conn,
                SystemTime::now(),
                connector,
                Size::new(24, 80),
                false,
                input_rx,
                resize_rx,
                Blind,
                CancellationToken::new(),
                None,
            ));
            // Keys that need the stream, then the quit escape.
            for keys in [&b"ls\r"[..], &[ESCAPE_PREFIX, b'.']] {
                input.send(keys.to_vec()).await.expect("typed");
            }
            let quit = tokio::time::timeout(Duration::from_secs(5), run).await;
            assert!(
                matches!(quit, Ok(Ok(Ok(None)))),
                "the client did not quit: {quit:?}"
            );
            let _ = tokio::time::timeout(Duration::from_secs(5), accept).await;
        });
    }

    /// A real server, admitting the one client, that runs `serve` on the connection.
    async fn loopback<F, Fut>(serve: F) -> (Admitted, IrohConnector)
    where
        F: FnOnce(Connection) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        use crate::transport_iroh::{bind_endpoint_local, generate_secret_key};
        let key = || generate_secret_key().expect("OS randomness");
        let server = bind_endpoint_local(key(), true)
            .await
            .expect("bind the server");
        let addr = crate::transport_iroh::loopback_addr(&server);
        koh_testkit::spawn(async move {
            if let Some(incoming) = server.accept().await {
                if let Ok(conn) = incoming.await {
                    if admit(&conn).await.is_ok() {
                        serve(conn.clone()).await;
                        conn.closed().await;
                    }
                }
            }
            drop(server);
        });
        let client = bind_endpoint_local(key(), false)
            .await
            .expect("bind the client");
        let connector = IrohConnector::new(client, addr);
        (connector.connect().await.expect("admitted"), connector)
    }

    #[test]
    fn large_server_streams_take_turns_and_give_them_back() {
        // More large streams than the client has slots, each dropped as garbage: a turn kept by
        // a dropped stream would leave readers holding every slot, and the reply after them would
        // never come.
        crate::test_runtime::current_thread().block_on(async {
            let (Admitted(conn, first), _connector) = loopback(|conn| async move {
                for _ in 0..20 {
                    let mut send = conn.open_uni().await.expect("a stream");
                    send.write_all(&vec![0xff; 1 << 20]).await.expect("written");
                    send.finish().expect("finished");
                }
                let reply = crate::terminal::HistoryReply {
                    id: 7,
                    rows: Vec::new(),
                };
                let bytes = crate::proto::FrameEncoder::default()
                    .encode_history(&reply)
                    .expect("encoded");
                let mut send = conn.open_uni().await.expect("a stream");
                send.write_all(&bytes).await.expect("written");
                send.finish().expect("finished");
            })
            .await;
            let (tx, mut rx) = mpsc::channel(FRAME_QUEUE);
            koh_testkit::spawn(read_frames(conn, first, tx));
            let got = tokio::time::timeout(Duration::from_secs(20), rx.recv())
                .await
                .expect("the reply after the large streams never came")
                .expect("the reader ended");
            assert!(matches!(got.msg, ServerMsg::History(ref body) if crate::proto::decode_history(body).is_ok_and(|reply| reply.id == 7)));
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_closed_resize_channel_does_not_spin_the_loop() {
        /// This thread's CPU time so far, in clock ticks: the loop runs on it (one-thread runtime).
        fn cpu_ticks() -> u64 {
            let stat = std::fs::read_to_string("/proc/thread-self/stat").expect("stat");
            let fields: Vec<&str> = stat.rsplit(") ").next().unwrap().split(' ').collect();
            fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
        }
        crate::test_runtime::current_thread().block_on(async {
            let (conn, connector) = loopback(|_| async {}).await;
            let (input, input_rx) = mpsc::channel(8);
            let (resize, resize_rx) = mpsc::channel(1);
            drop(resize);
            let run = koh_testkit::spawn(run_client(
                conn,
                SystemTime::now(),
                connector,
                Size::new(24, 80),
                false,
                input_rx,
                resize_rx,
                Blind,
                CancellationToken::new(),
                None,
            ));
            let before = cpu_ticks();
            tokio::time::sleep(Duration::from_secs(1)).await;
            let used = cpu_ticks() - before;
            input.send(vec![ESCAPE_PREFIX, b'.']).await.expect("typed");
            let quit = tokio::time::timeout(Duration::from_secs(5), run).await;
            assert!(matches!(quit, Ok(Ok(Ok(None)))), "{quit:?}");
            // A spinning loop takes the whole second (100 ticks); an idle one a few.
            assert!(used < 30, "the loop spun: {used} ticks of CPU in a second");
        });
    }
}
