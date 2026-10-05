//! The koh client: the session loop, abstracted over a [`ClientTerminal`].
//!
//! Typed bytes and resize ticks arrive on channels; output and the window size go through
//! [`ClientTerminal`]: the real tty ([`BackendTerminal`] over [`KohBackend`]) in the binary, a
//! capturing mock in tests.

pub mod backend;
pub mod cli;
mod io;
mod probe;
mod render;
mod scrollback;
mod session;

pub use backend::{DefaultBackend, KohBackend};
pub use cli::{connect, BellHook, ConnectConfig};
pub(crate) use io::spawn_client_io;
pub use render::{InputModes, WindowState};
pub use session::{ClientSession, InputOutcome, TickResult};

use std::time::{Duration, Instant};

use crate::predict::{DisplayPreference, Overlay};
use crate::proto::{decode_server, encode_client, ServerMsg, MAX_FRAME, SESSION_ENDED};
use crate::terminal::{Size, TerminalScreen};
use crate::transport_iroh::ALPN;
use iroh::endpoint::{Connection, SendStream};
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

    /// Connect and await the admission ack. A server that rejects us closes the connection instead,
    /// which is an error, so a rejected client fails fast rather than redialing forever.
    pub async fn connect(&self) -> anyhow::Result<Connection> {
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
            // Surface the server's own reason ("not authorized", "at session capacity"): each
            // points at a different fix.
            return Err(match server_close_reason(&conn) {
                Some(reason) => anyhow::Error::new(e)
                    .context(format!("server rejected the connection: {reason}")),
                None => anyhow::Error::new(e)
                    .context("server did not admit the connection (is your id on its allowlist?)"),
            });
        }
        Ok(conn)
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

/// The server's application close reason, if any: peer-controlled, so stripped of control
/// characters and capped before it can reach the user's terminal.
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

/// Whether `chunk` completes the quit escape (`Ctrl-^ .`) while reconnecting, as
/// [`ClientSession`]'s escape machine would; `pending` carries a lone prefix across chunks.
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
        };
        this.backend.enter_alt_screen()?;
        Ok(this)
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

    fn suspend_resume(&mut self) -> std::io::Result<()> {
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
        self.oob.invalidate();
        self.painter.invalidate();
        Ok(())
    }
}

impl<B: KohBackend> Drop for BackendTerminal<B> {
    fn drop(&mut self) {
        // Best-effort: a mode left on (mouse reporting, say) would garble the user's shell.
        let _ = self.backend.leave_alt_screen();
        let _ = self.backend.leave_raw_mode();
    }
}

/// Run a client session on `initial`, redialing through `connector` and reattaching to the same
/// server session whenever the link drops; meanwhile the last screen stays up under a banner.
///
/// The I/O shell around [`ClientSession`], which makes every protocol decision. `input_rx` carries
/// typed bytes (its closing ends the session); `resize_rx` carries resize ticks, on which the size
/// is read from `term` (`initial_size` if that fails). Cancelling `shutdown` (on a fatal signal)
/// quits like the user, so the terminal is restored. `bell` runs on every remote bell.
///
/// Returns the remote shell's exit code if it exited, `None` on a local quit.
#[expect(
    clippy::too_many_arguments,
    reason = "the I/O shell wires up the connection, connector, prediction policy, size, the two \
              input/resize channels, the terminal, the shutdown token and the bell hook — each a distinct \
              collaborator; bundling them into a struct would only move the list, not shorten it"
)]
pub async fn run_client<T: ClientTerminal>(
    initial: Connection,
    connector: IrohConnector,
    pref: DisplayPreference,
    initial_size: Size,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    mut resize_rx: mpsc::Receiver<()>,
    mut term: T,
    shutdown: CancellationToken,
    mut bell: Option<BellHook>,
) -> anyhow::Result<Option<u32>> {
    let mut conn = initial;
    // Kept across connections: only one that lasts resets it (see `MIN_CONNECTION_DWELL`).
    let mut attempt: u32 = 0;
    loop {
        // A fresh session per connection: the server repaints the live screen on each attach.
        let size = term.size().unwrap_or(initial_size);
        let mut session = ClientSession::new(pref, size);

        let conn_started = Instant::now();
        match drive_connection(
            &conn,
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
                conn.close(0u32.into(), b"client exit");
                return Ok(None);
            }
            Disposition::Ended(code) => {
                conn.close(0u32.into(), b"client exit");
                return Ok(code);
            }
            Disposition::LinkLost => {
                conn.close(0u32.into(), b"reconnecting");
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
                    ReconnectOutcome::Connected(c) => conn = c,
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

/// Drive one connection until it ends, and say how.
///
/// The client's stream is written by its own task behind a bounded queue, and frames are read by
/// their own tasks, so nothing here waits on the network: the keyboard, and the quit escape, stay
/// live even when the server stops reading.
async fn drive_connection<T: ClientTerminal>(
    conn: &Connection,
    session: &mut ClientSession,
    term: &mut T,
    input_rx: &mut mpsc::Receiver<Vec<u8>>,
    resize_rx: &mut mpsc::Receiver<()>,
    shutdown: &CancellationToken,
    mut bell: Option<&mut BellHook>,
) -> anyhow::Result<Disposition> {
    let Ok(send) = conn.open_uni().await else {
        return Ok(Disposition::LinkLost);
    };
    let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE);
    let _writer = AbortOnDrop(tokio::spawn(write_client_stream(send, writer_rx)));
    let (frame_tx, mut frame_rx) = mpsc::channel::<ServerMsg>(FRAME_QUEUE);
    let _reader = AbortOnDrop(tokio::spawn(read_frames(conn.clone(), frame_tx)));

    // Wall-clock time, which keeps running while the process is frozen (see `STALE_AFTER_FREEZE`).
    let mut last_wall = std::time::SystemTime::now();
    // Logged on a change of 30 ms or more, to tell a slow link from a slow server in debug logs.
    let mut last_logged_rtt: Option<Duration> = None;
    loop {
        // A clock stepped backwards reads as no gap.
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
        let rtt = crate::transport_iroh::rtt(conn);
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
            match session.view() {
                Some(view) => term.render(&view, &Overlay::empty(), tick.status.as_deref())?,
                None => term.render(session.state(), &session.overlay(), tick.status.as_deref())?,
            }
            session.status_was_shown = status_now;
            session.dirty = false;
            // Only once synced: the first synced frame primes the hook, so bells from before this
            // attach don't fire it.
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
            // Keystrokes first: queued screen updates must never starve them.
            biased;

            maybe = input_rx.recv() => {
                match maybe {
                    Some(chunk) => match session.on_input(Instant::now(), &chunk) {
                        InputOutcome::Quit => return Ok(Disposition::Quit),
                        InputOutcome::Suspend => {
                            term.suspend_resume()?;
                            session.dirty = true;
                            // A deliberate suspend is not a freeze to reconnect after.
                            last_wall = std::time::SystemTime::now();
                        }
                        InputOutcome::Forwarded => {}
                    },
                    None => return Ok(Disposition::Quit), // input source closed
                }
            }
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
                match frame {
                    ServerMsg::Frame { base, body } => {
                        session.on_frame_stream(Instant::now(), base, &body);
                    }
                    ServerMsg::History(reply) => session.on_history(&reply),
                }
            }
            maybe = resize_rx.recv() => {
                if maybe.is_some() {
                    term.window_resized();
                    if let Ok(size) = term.size() {
                        session.on_resize(size);
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

/// Accept the server's streams (frames, and history rows), each read on its own task so a stalled or
/// reset stream never holds up a newer frame. Ends when the connection closes.
async fn read_frames(conn: Connection, frames: mpsc::Sender<ServerMsg>) {
    while let Ok(mut recv) = conn.accept_uni().await {
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
    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(400)) => {}
        () = shutdown.cancelled() => {}
    }
    Disposition::Ended(code)
}

/// The result of a [`reconnect`] loop.
enum ReconnectOutcome {
    /// A fresh connection was established; resume the session on it.
    Connected(Connection),
    /// The user disconnected (`Ctrl-^ .`) or input closed while reconnecting — exit.
    Quit,
}

/// Redial with capped exponential backoff until connected or the user quits, painting a
/// "reconnecting…" banner over the last screen. The dial is pinned, so banner repaints and
/// keystrokes do not restart a slow one.
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
    'attempt: loop {
        // Back off before dialing once a dial failed or the last connection dropped too fast
        // (`*attempt > 0`, which the caller seeds from the connection's dwell), so a server that
        // completes the handshake and at once closes is not redialed in a tight loop. A proven
        // connection's drop dials at once.
        let wait = if *attempt > 0 {
            backoff(*attempt)
        } else {
            Duration::ZERO
        };
        let dial = async {
            tokio::time::sleep(wait).await;
            tokio::time::timeout(RECONNECT_CONNECT_TIMEOUT, connector.connect()).await
        };
        tokio::pin!(dial);
        loop {
            let banner = format!(
                "[koh] disconnected — reconnecting… {}s (Ctrl-^ . to quit)",
                started.elapsed().as_secs()
            );
            let _ = term.render(last.state(), &Overlay::empty(), Some(banner.as_str()));
            tokio::select! {
                biased;
                maybe = input_rx.recv() => match maybe {
                    Some(chunk) => {
                        if escape_quit(&chunk, &mut pending_escape) {
                            return ReconnectOutcome::Quit;
                        }
                    }
                    None => return ReconnectOutcome::Quit, // input source closed
                },
                // Honor a SIGTERM/SIGINT/SIGHUP even mid-reconnect, so the terminal is restored.
                () = shutdown.cancelled() => return ReconnectOutcome::Quit,
                res = &mut dial => {
                    match res {
                        Ok(Ok(conn)) => return ReconnectOutcome::Connected(conn),
                        Ok(Err(e)) => tracing::info!(reason = %e, attempt = *attempt, "reconnect dial failed"),
                        Err(_) => tracing::info!(attempt = *attempt, "reconnect dial timed out"),
                    }
                    *attempt = (*attempt).saturating_add(1);
                    continue 'attempt;
                }
                () = tokio::time::sleep(Duration::from_secs(1)) => {} // tick the banner clock
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
}
