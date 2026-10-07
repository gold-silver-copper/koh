//! The koh client: the session loop, abstracted over a [`ClientTerminal`].
//!
//! Typed bytes and resize ticks arrive on channels; output and the window size go through
//! [`ClientTerminal`]: the real tty ([`BackendTerminal`] over [`KohBackend`]) in the binary, a
//! capturing mock in tests.

pub mod backend;
pub mod cli;
mod io;
pub mod probe;
mod render;
mod scrollback;
mod session;

pub use backend::{DefaultBackend, KohBackend};
pub use cli::{connect, BellHook, ConnectConfig};
pub(crate) use io::spawn_client_io;
pub use render::{InputModes, WindowState};
pub use session::{ClientSession, InputOutcome, TickResult};

use std::time::{Duration, Instant, SystemTime};

use crate::predict::{DisplayPreference, Overlay};
use crate::proto::{decode_server, encode_client, ServerMsg, MAX_FRAME};
use crate::terminal::{Size, TerminalScreen};
use crate::transport_iroh::admission::{self, Close, Disconnect, Link};
use iroh::endpoint::SendStream;
use iroh::{Endpoint, EndpointAddr};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Prefixed to the mirrored window title, as mosh prefixes `[mosh] `.
const KOH_TITLE_PREFIX: &str = "[koh] ";

/// The escape prefix (Ctrl-^); followed by '.' it disconnects the session.
pub(crate) const ESCAPE_PREFIX: u8 = 0x1e;
/// After the escape prefix, suspends the client (as mosh does): in raw mode `Ctrl-Z` is a plain
/// byte, not SIGTSTP.
pub(crate) const SUSPEND_KEY: u8 = 0x1a;

/// After [`ESCAPE_PREFIX`], opens the scrollback view.
pub(crate) const SCROLLBACK_KEY: u8 = b'[';

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

/// Whether a wall-clock gap between loop iterations means the process was frozen.
fn looks_like_resume_from_freeze(wall_gap: Duration) -> bool {
    wall_gap >= STALE_AFTER_FREEZE
}

/// Dials the server and awaits its admission ack: the first connection and every reconnect, which
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

    /// Connect and await the admission ack. A server that refuses us closes the connection
    /// instead, which is a [`Disconnect::Fatal`], so a refused client fails fast rather than
    /// redialing forever.
    pub async fn connect(&self) -> Result<Link, Disconnect> {
        admission::dial(&self.endpoint, self.target.clone()).await
    }
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
        overlay: &Overlay<'_>,
        status: Option<&str>,
    ) -> std::io::Result<()>;

    /// The current window size.
    fn size(&self) -> std::io::Result<Size>;

    /// The window was resized: whatever it showed may be gone, so the next [`render`](Self::render)
    /// paints everything. Default: a no-op, for a terminal that paints everything every time.
    fn window_resized(&mut self) {}

    /// Suspend the client (`Ctrl-^ Ctrl-Z`): restore the user's terminal, stop the process with
    /// SIGTSTP, and once it is foregrounded take the terminal back. Blocks while stopped. Default:
    /// a no-op, so a test terminal never stops the test process.
    fn suspend_resume(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Ask the user's terminal `questions` (the session's: its colours again, after it reported a
    /// new scheme). Default: a no-op, for a terminal that answers nothing.
    fn ask(&mut self, _questions: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
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
}

/// What the client turns on in a terminal that speaks it, beside the input modes.
#[derive(Debug, Clone, Copy, Default)]
struct Extras {
    kitty: bool,
    scheme_reports: bool,
}

impl Extras {
    /// The bytes turning them on.
    fn on(self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.kitty {
            out.extend_from_slice(b"\x1b[>5u");
        }
        if self.scheme_reports {
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
        };
        this.backend.enter_alt_screen()?;
        Ok(this)
    }

    /// The terminal speaks the kitty keyboard protocol (`kitty`) and reports its scheme
    /// (`scheme_reports`), as the probe found: turn each on now, until the client leaves.
    pub(crate) fn turn_on(&mut self, kitty: bool, scheme_reports: bool) -> std::io::Result<()> {
        self.extras = Extras {
            kitty,
            scheme_reports,
        };
        self.ask(&self.extras.on())
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

    /// Ask the user's terminal `queries` (written and flushed now).
    pub(crate) fn ask(&mut self, queries: &[u8]) -> std::io::Result<()> {
        self.backend.write_bytes(queries)?;
        self.backend.flush()
    }

    /// Turn off what [`turn_on`](Self::turn_on) turned on.
    fn turn_off(&mut self) -> std::io::Result<()> {
        let off = self.extras.off();
        if off.is_empty() {
            return Ok(());
        }
        self.ask(&off)
    }
}

impl<B: KohBackend> ClientTerminal for BackendTerminal<B> {
    fn render(
        &mut self,
        state: &TerminalScreen,
        overlay: &Overlay<'_>,
        status: Option<&str>,
    ) -> std::io::Result<()> {
        self.oob.emit(
            &mut self.backend,
            InputModes::from(state.screen()),
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
        Self::ask(self, questions)
    }

    fn suspend_resume(&mut self) -> std::io::Result<()> {
        self.turn_off()?;
        self.backend.leave_alt_screen()?;
        self.backend.leave_raw_mode()?;
        let _ = self
            .backend
            .write_bytes("\n[koh suspended — run `fg` to resume]\n".as_bytes());
        let _ = self.backend.flush();
        // Returns once the user foregrounds the job again.
        fuxix::process::kill(own_pid()?, fuxix::process::Signal::Tstp)?;
        // The terminal was reset meanwhile: re-assert everything on the next frame.
        self.backend.enter_raw_mode()?;
        self.backend.enter_alt_screen()?;
        let on = self.extras.on();
        if !on.is_empty() {
            self.ask(&on)?;
        }
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
/// for the whole run, so what is typed while the link is down is kept for the next connection and
/// read by the same escape machine. `input_rx` carries typed bytes (its closing ends the session);
/// `resize_rx` carries resize ticks, on which the size is read from `term` (`initial_size` if that
/// fails). Cancelling `shutdown` (on a fatal signal) quits like the user, so the terminal is
/// restored. `bell` runs on every remote bell.
///
/// The client's stream is written by its own task behind a bounded queue, and frames are read by
/// their own tasks, so nothing here waits on the network: the keyboard, and the quit escape, stay
/// live even when the server stops reading.
///
/// Returns the remote shell's exit code if it exited, `None` on a local quit.
#[expect(
    clippy::too_many_arguments,
    reason = "the I/O shell wires up the connection, connector, prediction policy, size, the \
              terminal's colours, the two input/resize channels, the terminal, the shutdown token and the bell hook — each a distinct \
              collaborator; bundling them into a struct would only move the list, not shorten it"
)]
pub async fn run_client<T: ClientTerminal>(
    initial: Link,
    dialed_at: SystemTime,
    connector: IrohConnector,
    pref: DisplayPreference,
    initial_size: Size,
    colours: Option<crate::events::WireColours>,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    mut resize_rx: mpsc::Receiver<()>,
    mut term: T,
    shutdown: CancellationToken,
    mut bell: Option<BellHook>,
) -> anyhow::Result<Option<u32>> {
    let mut session = ClientSession::new(pref, term.size().unwrap_or(initial_size));
    session.set_colours(colours);
    // Kept across connections: only one that lasts resets it (see `MIN_CONNECTION_DWELL`).
    let mut attempt: u32 = 0;
    let mut net = Net::Up(Wire::open(initial).await);
    // Wall-clock time, which keeps running while the process is frozen (see `STALE_AFTER_FREEZE`),
    // from when the connection was made: a freeze before the first iteration counts.
    let mut last_wall = dialed_at;
    // Logged on a change of 30 ms or more, to tell a slow link from a slow server in debug logs.
    let mut last_logged_rtt: Option<Duration> = None;
    loop {
        // A clock stepped backwards reads as no gap.
        let wall_now = SystemTime::now();
        let wall_gap = wall_now.duration_since(last_wall).unwrap_or(Duration::ZERO);
        last_wall = wall_now;
        let rtt = if let Net::Up(wire) = &net {
            if looks_like_resume_from_freeze(wall_gap) {
                tracing::info!(
                    frozen_secs = wall_gap.as_secs(),
                    "detected resume from a process freeze (suspend/screen-off); forcing a reconnect"
                );
                net = redial(wire, &mut attempt, &mut session, &connector);
                continue;
            }
            wire.link.rtt()
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

        // Repaint on new content, while a banner is up, or once more to clear a stale banner.
        let status_now = tick.status.is_some();
        if session.dirty || status_now || session.status_was_shown {
            match session.view() {
                Some(view) => term.render(&view, &Overlay::empty(), tick.status.as_deref())?,
                None => term.render(session.state(), &session.overlay(), tick.status.as_deref())?,
            }
            session.status_was_shown = status_now;
            session.dirty = false;
            // Only once synced: the first synced frame primes the hook, so bells from before this
            // attach don't fire it.
            if let Some(hook) = bell.as_mut() {
                if session.synced() {
                    let win = session.window_state();
                    hook.prime(win.bell_count);
                    hook.observe_and_fire(win.bell_count, win.title, now);
                }
            }
        }

        if session.exited() {
            end_session(&mut term, &session, &shutdown).await;
            return Ok(net.close(session.state().exit_code()));
        }

        // The colours again, after the terminal reported a new scheme.
        let questions = session.take_questions();
        if !questions.is_empty() {
            if let Err(e) = term.ask(&questions) {
                tracing::debug!(error = %e, "could not ask the terminal its colours");
            }
        }

        let (writer, frames, dialing) = match &mut net {
            Net::Up(wire) => (Some(&wire.writer_tx), Some(&mut wire.frame_rx), None),
            Net::Down(dial) => (None, None, Some(dial)),
        };
        let change = tokio::select! {
            // Keystrokes first: queued screen updates must never starve them.
            biased;

            maybe = input_rx.recv() => match maybe {
                Some(chunk) => {
                    let outcome = session.on_input(Instant::now(), &chunk);
                    after_input(outcome, &mut term, &mut session, &mut last_wall)?
                }
                None => Some(Change::Quit), // input source closed
            },
            // A lone Escape, or a sequence cut short, is taken as typed once nothing follows.
            () = until(session.deadline()) => {
                let outcome = session.on_timeout(Instant::now());
                after_input(outcome, &mut term, &mut session, &mut last_wall)?
            }
            () = shutdown.cancelled() => Some(Change::Quit),
            permit = when(writer.map(mpsc::Sender::reserve)), if session.has_outgoing() => match permit.ok() {
                // The writer ended: the stream, and so the connection, is gone.
                None => Some(Change::Closed { banner: false }),
                Some(permit) => {
                    if let Some(msg) = session.pop_outgoing() {
                        match encode_client(&msg) {
                            Ok(bytes) => permit.send(bytes),
                            Err(e) => tracing::warn!(error = %e, "dropping an unencodable message"),
                        }
                    }
                    None
                }
            },
            frame = when(frames.map(mpsc::Receiver::recv)) => match frame {
                // The frame reader ended because the connection closed.
                None => Some(Change::Closed { banner: true }),
                Some(ServerMsg::Frame { base, rows, body }) => {
                    session.on_frame_stream(Instant::now(), base, &rows, &body);
                    None
                }
                Some(ServerMsg::History(reply)) => {
                    session.on_history(&reply);
                    None
                }
            },
            dialed = when(dialing) => Some(Change::Dialed(dialed)),
            maybe = resize_rx.recv() => {
                if maybe.is_some() {
                    term.window_resized();
                    if let Ok(size) = term.size() {
                        session.on_resize(size);
                    }
                }
                None
            }
            () = tokio::time::sleep(tick.wait) => None,
        };
        match change {
            None => {}
            Some(Change::Quit) => return Ok(net.close(None)),
            Some(Change::Closed { banner }) => {
                let Net::Up(wire) = &net else {
                    continue;
                };
                match wire.link.ended() {
                    Disconnect::Ended => {
                        if banner {
                            end_session(&mut term, &session, &shutdown).await;
                        }
                        return Ok(net.close(session.state().exit_code()));
                    }
                    Disconnect::Fatal(e) => return Err(e),
                    Disconnect::Transient(e) => {
                        tracing::info!(reason = %format!("{e:#}"), "link lost; will reconnect");
                        net = redial(wire, &mut attempt, &mut session, &connector);
                    }
                }
            }
            Some(Change::Dialed(Ok(link))) => {
                session.attach(Instant::now(), term.size().unwrap_or(initial_size));
                net = Net::Up(Wire::open(link).await);
            }
            Some(Change::Dialed(Err(failed))) => match failed {
                Disconnect::Ended => return Ok(session.state().exit_code()),
                Disconnect::Fatal(e) => return Err(e),
                Disconnect::Transient(e) => {
                    tracing::info!(reason = %format!("{e:#}"), attempt, "reconnect dial failed");
                    attempt = attempt.saturating_add(1);
                    net = Net::Down(dial(&connector, attempt));
                }
            },
        }
    }
}

/// The client's link to the server: a live connection, or a redial under way.
enum Net<'c> {
    Up(Wire),
    Down(Dial<'c>),
}

impl Net<'_> {
    /// The run is over: close the connection, if one is up, and return `code`.
    fn close(&self, code: Option<u32>) -> Option<u32> {
        if let Self::Up(wire) = self {
            wire.link.close(Close::ClientExit);
        }
        code
    }
}

/// A redial: the backoff, then one dial. Pinned, so banner repaints and keystrokes do not restart a
/// slow one.
type Dial<'c> = std::pin::Pin<Box<dyn std::future::Future<Output = Dialed> + Send + 'c>>;

/// A redial's result.
type Dialed = Result<Link, Disconnect>;

/// What one turn of [`run_client`]'s loop left for it to act on.
enum Change {
    /// The user quit, the input channel closed, or a fatal signal came.
    Quit,
    /// The connection closed: the session ended (with its banner if `banner`), or the link was lost.
    Closed { banner: bool },
    /// A redial finished.
    Dialed(Dialed),
}

/// A live connection: its stream writer and frame reader, which end with it.
struct Wire {
    link: Link,
    writer_tx: mpsc::Sender<Vec<u8>>,
    frame_rx: mpsc::Receiver<ServerMsg>,
    _writer: AbortOnDrop<()>,
    _reader: AbortOnDrop<()>,
    /// When the loop took the connection, for its dwell.
    started: Instant,
}

impl Wire {
    /// Start the tasks writing the client's stream and reading frames on `link`. A stream that
    /// does not open ends the writer, which loses the link.
    async fn open(link: Link) -> Self {
        let send = link.open_uni().await.ok();
        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE);
        let writer = AbortOnDrop(tokio::spawn(write_client_stream(send, writer_rx)));
        let (frame_tx, frame_rx) = mpsc::channel::<ServerMsg>(FRAME_QUEUE);
        let reader = AbortOnDrop(tokio::spawn(read_frames(link.clone(), frame_tx)));
        Self {
            link,
            writer_tx,
            frame_rx,
            _writer: writer,
            _reader: reader,
            started: Instant::now(),
        }
    }
}

/// The link on `wire` was lost: close it, detach the session, and redial.
fn redial<'c>(
    wire: &Wire,
    attempt: &mut u32,
    session: &mut ClientSession,
    connector: &'c IrohConnector,
) -> Net<'c> {
    wire.link.close(Close::Reconnecting);
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
        connector.connect().await
    })
}

/// What `future` gives, or never without one: a select arm for one state of [`Net`].
async fn when<F: std::future::Future>(future: Option<F>) -> F::Output {
    match future {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

/// Act on what typed input decided: suspend now, or say the user quit.
fn after_input<T: ClientTerminal>(
    outcome: InputOutcome,
    term: &mut T,
    session: &mut ClientSession,
    last_wall: &mut SystemTime,
) -> std::io::Result<Option<Change>> {
    match outcome {
        InputOutcome::Quit => return Ok(Some(Change::Quit)),
        InputOutcome::Suspend => {
            term.suspend_resume()?;
            session.dirty = true;
            // A deliberate suspend is not a freeze to reconnect after.
            *last_wall = SystemTime::now();
        }
        InputOutcome::Forwarded => {}
    }
    Ok(None)
}

/// Sleep until `deadline`, or forever with none.
async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,
        None => std::future::pending().await,
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

/// Write queued messages to the client's stream, if it opened, until the queue or the stream
/// closes.
async fn write_client_stream(send: Option<SendStream>, mut queue: mpsc::Receiver<Vec<u8>>) {
    let Some(mut send) = send else {
        return;
    };
    while let Some(bytes) = queue.recv().await {
        if send.write_all(&bytes).await.is_err() {
            return;
        }
    }
    let _ = send.finish();
}

/// Accept the server's streams (frames, and history rows), each read on its own task so a stalled or
/// reset stream never holds up a newer frame. Ends when the connection closes.
async fn read_frames(link: Link, frames: mpsc::Sender<ServerMsg>) {
    while let Ok(mut recv) = link.accept_uni().await {
        let frames = frames.clone();
        tokio::spawn(async move {
            // A reset (superseded) or malformed frame is simply not delivered.
            let Ok(bytes) = recv.read_to_end(MAX_FRAME).await else {
                return;
            };
            match decode_server(&bytes) {
                Ok(msg) => {
                    let _ = frames.send(msg).await;
                }
                Err(e) => tracing::debug!(error = %e, "dropping an undecodable frame"),
            }
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
        &Overlay::empty(),
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

    #[test]
    fn a_server_on_another_protocol_is_reported_as_such() {
        crate::test_runtime::current_thread().block_on(async {
            // A server that only speaks the previous protocol's ALPN refuses the TLS handshake. The
            // error must say so, not blame the allowlist.
            use crate::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr};
            let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .secret_key(generate_secret_key().expect("OS randomness"))
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
            let client = bind_endpoint_local(generate_secret_key().expect("OS randomness"), false)
                .await
                .expect("bind client");
            let error = match IrohConnector::new(client, addr).connect().await {
                Err(Disconnect::Fatal(e)) => format!("{e:#}"),
                Ok(_) => panic!("an old-protocol server must refuse the handshake"),
                Err(e) => panic!("an old-protocol server is a verdict, not {e:?}"),
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
            painter: render::Painter::default(),
            extras: Extras::default(),
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
        render::Painter::default()
            .render(
                &mut direct,
                screen.screen(),
                &Overlay::empty(),
                Some("status"),
            )
            .unwrap();
        assert_eq!(via_trait.backend.bytes, direct.bytes);
        assert_ne!(via_trait.backend.bytes, b"");
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
        };
        term.turn_on(true, true).unwrap();
        assert_eq!(term.backend.bytes, b"\x1b[>5u\x1b[?2031h");
        term.backend.bytes.clear();
        term.turn_off().unwrap();
        assert_eq!(term.backend.bytes, b"\x1b[<u\x1b[?2031l");
        // A terminal that speaks neither is sent neither.
        term.backend.bytes.clear();
        term.turn_on(false, false).unwrap();
        term.turn_off().unwrap();
        assert_eq!(term.backend.bytes, b"");
    }
}
