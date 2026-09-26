//! The koh server: the per-connection session loop.
//!
//! Reused by the binary and by integration tests (so the full PTY⇄emulator⇄transport path can be
//! exercised over a real iroh connection without the CLI/accept scaffolding).
//!
//! Sessions are **detachable**: the long-lived PTY + emulator lives in a [`session`] task and
//! survives client disconnects; a per-connection [`run_attached`] loop drives a *fresh* protocol
//! core against it, so a reconnecting client re-syncs to the current screen.

mod audit;
pub mod cli;
pub mod session;

pub use cli::{serve, ServeConfig};
pub use session::{PtyHost, Registry, SessionSpec};

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::proto::{
    encode_frame, frame_interval, retry_after, ClientDecoder, ClientMsg, Frame, FrameNum, InputSeq,
    ProtoError, FRAME_WINDOW, HEARTBEAT, SESSION_ENDED,
};
use crate::terminal::TerminalScreen;
use crate::transport_iroh::IrohChannel;
use iroh::endpoint::RecvStream;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Why an attached connection loop returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExit {
    /// The client connection dropped; the session stays alive for reattach.
    Detached,
    /// The shell exited and the shutdown handshake completed; the session should be reaped.
    ShellExited,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Ss3State {
    #[default]
    Ground,
    Esc,
    Ss3,
}

/// Rewrites the client's arrow keys to match the remote app's DECCKM mode before they reach the PTY.
///
/// SS3-form cursor keys (`ESC O A..D`) become CSI-form (`ESC [ A..D`) when the app is NOT in
/// application-cursor mode, so arrows behave regardless of the local terminal's mode (a faithful
/// port of mosh's `UserInput::input`). The `ESC` is emitted eagerly and the SS3 state carries
/// across input chunks.
#[derive(Default)]
struct CursorKeyNormalizer {
    state: Ss3State,
}

impl CursorKeyNormalizer {
    /// Normalize `input` for an app whose application-cursor-keys mode is `app_cursor`, returning
    /// the bytes to feed the PTY.
    fn normalize(&mut self, input: &[u8], app_cursor: bool) -> Vec<u8> {
        // A capacity hint: one spare byte for a held escape; saturating cannot matter.
        let mut out = Vec::with_capacity(input.len().saturating_add(1));
        for &b in input {
            match self.state {
                Ss3State::Ground => {
                    if b == 0x1b {
                        self.state = Ss3State::Esc;
                    }
                    out.push(b); // ESC is emitted eagerly (mosh)
                }
                Ss3State::Esc => {
                    if b == b'O' {
                        self.state = Ss3State::Ss3; // hold the 'O' pending its final byte
                    } else {
                        self.state = Ss3State::Ground;
                        out.push(b);
                    }
                }
                Ss3State::Ss3 => {
                    self.state = Ss3State::Ground;
                    // ESC was already emitted; complete the sequence, rewriting SS3 -> CSI when the
                    // app isn't in application-cursor mode.
                    out.push(if !app_cursor && (b'A'..=b'D').contains(&b) {
                        b'['
                    } else {
                        b'O'
                    });
                    out.push(b);
                }
            }
        }
        out
    }
}

/// Server-side debounce before received input is considered "echoed": how long the hosted
/// program gets to reflect a keystroke on screen before the client's prediction is confirmed.
pub(crate) const ECHO_TIMEOUT: Duration = Duration::from_millis(50);

/// How long the server waits for the client to acknowledge the final frame before closing.
const FINAL_ACK_WAIT: Duration = Duration::from_secs(1);

/// Which of one client's inputs the hosted program has had time to reflect.
///
/// Input sequence numbers are per connection, so each connection has its own tracker; two
/// connections on one session never see each other's numbers.
#[derive(Debug)]
pub(crate) struct EchoAck {
    /// The newest input considered reflected on screen.
    acked: InputSeq,
    /// Inputs not yet promoted, with when they arrived, oldest first.
    pending: VecDeque<(InputSeq, Instant)>,
    timeout: Duration,
}

impl Default for EchoAck {
    fn default() -> Self {
        Self::with_timeout(ECHO_TIMEOUT)
    }
}

impl EchoAck {
    /// A tracker with a custom debounce; tests use a small one.
    pub(crate) const fn with_timeout(timeout: Duration) -> Self {
        Self {
            acked: InputSeq(0),
            pending: VecDeque::new(),
            timeout,
        }
    }

    /// Input `seq` arrived at `now`. Sequence numbers only advance; a stale one is ignored.
    pub(crate) fn register(&mut self, seq: InputSeq, now: Instant) {
        let newest = self.pending.back().map_or(self.acked, |(s, _)| *s);
        if seq > newest {
            self.pending.push_back((seq, now));
        }
    }

    /// Promote every input that arrived at least the debounce before `now`. Returns whether the
    /// echo-ack advanced.
    pub(crate) fn promote(&mut self, now: Instant) -> bool {
        let before = self.acked;
        while let Some(&(seq, arrived)) = self.pending.front() {
            if now.saturating_duration_since(arrived) < self.timeout {
                break;
            }
            self.acked = seq;
            self.pending.pop_front();
        }
        self.acked != before
    }

    /// When [`promote`](Self::promote) could next advance, or `None` if nothing is pending.
    pub(crate) fn next_promotion(&self) -> Option<Instant> {
        let (_, arrived) = self.pending.front()?;
        arrived.checked_add(self.timeout)
    }

    /// The current echo-ack.
    pub(crate) const fn echo_ack(&self) -> InputSeq {
        self.acked
    }
}

/// The client input one read made ready for the PTY.
#[derive(Debug, Default, PartialEq, Eq)]
struct Drained {
    /// Keystrokes, DECCKM-normalized, in order.
    keys: Vec<u8>,
    /// The last resize among the messages, clamped to `[MIN_DIM, MAX_DIM]`. Earlier ones in the same
    /// read have no observable effect, so they are dropped rather than each costing a
    /// `TIOCSWINSZ`, a `SIGWINCH` and an emulator reallocation.
    resize: Option<(u16, u16)>,
}

/// The server side of one connection: the I/O-free protocol core.
///
/// It decodes the client's stream, tracks the echo-ack, and decides when to send which frame
/// against which base. The connection loop in [`run_attached`] does the I/O and holds the session
/// lock only to take snapshots and apply input.
pub(crate) struct ServerConn {
    decoder: ClientDecoder,
    cursor_keys: CursorKeyNormalizer,
    echo: EchoAck,
    /// The newest snapshot of the session's screen.
    screen: TerminalScreen,
    /// `screen` differs from what was last sent, or the base must be rebuilt.
    unsent_change: bool,
    /// `screen` was taken after the hosted program exited.
    final_snapshot: bool,
    /// The newest frame the client acknowledged, and its screen. Starts as the blank frame 0.
    acked: (FrameNum, TerminalScreen),
    /// Frames sent since, oldest first, at most `FRAME_WINDOW`.
    sent: VecDeque<(FrameNum, TerminalScreen)>,
    last_num: FrameNum,
    last_sent_at: Option<Instant>,
    last_sent_echo: InputSeq,
    /// The first frame sent after the program exited, and when.
    final_frame: Option<(FrameNum, Instant)>,
}

impl Default for ServerConn {
    fn default() -> Self {
        Self::with_echo(EchoAck::default())
    }
}

impl ServerConn {
    fn with_echo(echo: EchoAck) -> Self {
        Self {
            decoder: ClientDecoder::default(),
            cursor_keys: CursorKeyNormalizer::default(),
            echo,
            screen: TerminalScreen::default(),
            unsent_change: true,
            final_snapshot: false,
            acked: (FrameNum::BLANK, TerminalScreen::default()),
            sent: VecDeque::new(),
            last_num: FrameNum::BLANK,
            last_sent_at: None,
            last_sent_echo: InputSeq(0),
            final_frame: None,
        }
    }

    /// Install the session's latest screen (taken while the program was `alive`).
    fn install_snapshot(&mut self, screen: TerminalScreen, alive: bool) {
        let last_sent = self.sent.back().map_or(&self.acked.1, |(_, s)| s);
        if screen != *last_sent {
            self.unsent_change = true;
        }
        self.screen = screen;
        if !alive {
            self.final_snapshot = true;
        }
    }

    /// Append bytes read from the client's stream.
    fn push_client_bytes(&mut self, bytes: &[u8]) {
        self.decoder.push(bytes);
    }

    /// Decode every complete message read so far at `now`: acks and resyncs update the frame
    /// state, inputs register with the echo-ack and come back normalized for the PTY.
    fn drain_client(&mut self, now: Instant, app_cursor: bool) -> Result<Drained, ProtoError> {
        let mut drained = Drained::default();
        while let Some(msg) = self.decoder.next_msg()? {
            match msg {
                ClientMsg::Input { seq, bytes } => {
                    self.echo.register(seq, now);
                    drained
                        .keys
                        .extend(self.cursor_keys.normalize(&bytes, app_cursor));
                }
                ClientMsg::Resize { rows, cols } => {
                    drained.resize = Some(crate::terminal::clamp_dims(rows, cols));
                }
                ClientMsg::Ack { frame } => self.ack(frame),
                ClientMsg::Resync => self.resync(),
            }
        }
        Ok(drained)
    }

    /// The client's stream ended: fine between messages, a protocol error inside one.
    fn finish_client(&self) -> Result<(), ProtoError> {
        self.decoder.finish()
    }

    /// The client applied `num`. Frames sent before it are no longer needed as bases. An ack for a
    /// frame this connection no longer holds (or never sent) is ignored.
    fn ack(&mut self, num: FrameNum) {
        if num <= self.acked.0 {
            return;
        }
        let Some(pos) = self.sent.iter().position(|(n, _)| *n == num) else {
            return;
        };
        let mut rest = self.sent.split_off(pos);
        if let Some(acked) = rest.pop_front() {
            self.acked = acked;
        }
        self.sent = rest;
    }

    /// The client does not hold the base of what it was sent; diff against the blank screen, which
    /// it always holds, until it acknowledges a newer frame.
    fn resync(&mut self) {
        self.acked = (FrameNum::BLANK, TerminalScreen::default());
        self.unsent_change = true;
    }

    /// Promote the echo-ack at `now`.
    fn promote_echo(&mut self, now: Instant) {
        self.echo.promote(now);
    }

    /// The frame to send at `now` on a path with round-trip time `rtt`, if one is due: the screen
    /// or the echo-ack changed and a frame interval has passed, the newest frame went unacknowledged
    /// for a retry interval (it is resent as a new frame, which supersedes the old one), or nothing
    /// was sent for a heartbeat.
    fn poll_frame(&mut self, now: Instant, rtt: Option<Duration>) -> Option<Frame> {
        let changed = self.unsent_change || self.echo.echo_ack() != self.last_sent_echo;
        let since = self
            .last_sent_at
            .map(|at| now.saturating_duration_since(at));
        let interval_passed = since.is_none_or(|since| since >= frame_interval(rtt));
        let unacked = self.last_num > self.acked.0;
        let retry_due = unacked && since.is_some_and(|since| since >= retry_after(rtt));
        let heartbeat_due = since.is_none_or(|since| since >= HEARTBEAT);
        let due = (changed && interval_passed) || retry_due || heartbeat_due;
        if !due {
            return None;
        }
        let num = self.last_num.next();
        let frame = Frame {
            num,
            base: self.acked.0,
            echo_ack: self.echo.echo_ack(),
            diff: self.screen.diff_from(&self.acked.1),
        };
        self.sent.push_back((num, self.screen.clone()));
        while self.sent.len() > FRAME_WINDOW {
            self.sent.pop_front();
        }
        self.last_num = num;
        self.last_sent_at = Some(now);
        self.last_sent_echo = frame.echo_ack;
        self.unsent_change = false;
        if self.final_snapshot && self.final_frame.is_none() {
            self.final_frame = Some((num, now));
        }
        Some(frame)
    }

    /// The newest frame the client has acknowledged.
    const fn acked(&self) -> FrameNum {
        self.acked.0
    }

    /// Whether the latest snapshot has application-cursor-keys mode on, for the arrow normalizer.
    fn app_cursor(&self) -> bool {
        self.screen.application_cursor()
    }

    /// Whether the connection is done: the program exited and the client acknowledged the final
    /// frame, or did not within [`FINAL_ACK_WAIT`].
    fn finished(&self, now: Instant) -> bool {
        self.final_frame.is_some_and(|(num, at)| {
            self.acked.0 >= num || now.saturating_duration_since(at) >= FINAL_ACK_WAIT
        })
    }

    /// When the loop must wake at the latest, with nothing else happening.
    fn next_wake(&self, now: Instant, rtt: Option<Duration>) -> Instant {
        let mut wake = self
            .last_sent_at
            .map_or(now, |at| at.checked_add(HEARTBEAT).unwrap_or(now));
        let changed = self.unsent_change || self.echo.echo_ack() != self.last_sent_echo;
        if changed {
            let interval = self
                .last_sent_at
                .map_or(now, |at| at.checked_add(frame_interval(rtt)).unwrap_or(now));
            wake = wake.min(interval);
        }
        if self.last_num > self.acked.0 {
            let retry = self
                .last_sent_at
                .map_or(now, |at| at.checked_add(retry_after(rtt)).unwrap_or(now));
            wake = wake.min(retry);
        }
        if let Some(promotion) = self.echo.next_promotion() {
            wake = wake.min(promotion);
        }
        if let Some((_, at)) = self.final_frame {
            wake = wake.min(at.checked_add(FINAL_ACK_WAIT).unwrap_or(now));
        }
        wake.max(now)
    }
}

/// Drive one client connection against its session, through a [`session::SessionClient`].
///
/// The async shell around the `ServerConn` core: it watches the session's screen, forwards the
/// client's input, sends each frame on its own stream, and resets the stream of a frame a newer one
/// supersedes. A fresh core per attach repaints the live screen onto a (re)connecting client.
/// Dropping the `SessionClient` (on return or panic) detaches; the session keeps running.
pub async fn run_attached(
    conn: iroh::endpoint::Connection,
    mut session: session::SessionClient,
) -> anyhow::Result<SessionExit> {
    let channel = IrohChannel::new(conn.clone());
    let mut core = ServerConn::default();
    // Seed the core with the live screen so the first frame repaints it onto this connection.
    core.install_snapshot((*session.screen()).clone(), true);
    let mut client: Option<RecvStream> = None;
    // The client gets exactly one stream for the connection, even after it finishes that one.
    let mut had_client_stream = false;
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut in_flight: VecDeque<(FrameNum, CancellationToken)> = VecDeque::new();
    let result = loop {
        let now = Instant::now();
        core.promote_echo(now);
        let rtt = channel.rtt();
        if let Some(frame) = core.poll_frame(now, rtt) {
            // Every older frame the client has not acknowledged is superseded.
            let acked = core.acked();
            for (num, cancel) in std::mem::take(&mut in_flight) {
                if num > acked {
                    cancel.cancel();
                }
            }
            match encode_frame(&frame) {
                Ok(bytes) => {
                    let cancel = CancellationToken::new();
                    tokio::spawn(send_frame(conn.clone(), bytes, cancel.clone()));
                    in_flight.push_back((frame.num, cancel));
                }
                Err(e) => tracing::error!(error = %e, "encoding a frame failed"),
            }
        }
        if core.finished(now) {
            conn.close(0u32.into(), SESSION_ENDED);
            break Ok(SessionExit::ShellExited);
        }
        let wake = tokio::time::Instant::from_std(core.next_wake(now, rtt));
        let reading = client.is_some();
        tokio::select! {
            // NOT biased: a screen change may already be pending, which under `biased` would starve
            // client input.
            screen = session.next_screen() => match screen {
                Some(screen) => {
                    let alive = screen.exit_code().is_none();
                    core.install_snapshot((*screen).clone(), alive);
                }
                // The session task ended without a final screen (server shutting down): detach.
                None => break Ok(SessionExit::Detached),
            },
            stream = conn.accept_uni() => match stream {
                Ok(stream) if !had_client_stream => {
                    had_client_stream = true;
                    client = Some(stream);
                }
                Ok(_) => {
                    conn.close(PROTOCOL_ERROR.into(), b"a second client stream");
                    break Ok(SessionExit::Detached);
                }
                Err(e) => {
                    info!(reason = %e, "connection closed by peer (detaching)");
                    break Ok(SessionExit::Detached);
                }
            },
            read = read_client(client.as_mut(), &mut read_buf), if reading => match read {
                Ok(Some(n)) => {
                    core.push_client_bytes(read_buf.get(..n).unwrap_or_default());
                    let app_cursor = core.app_cursor();
                    match core.drain_client(Instant::now(), app_cursor) {
                        Ok(drained) => {
                            // Await the session's bounded input queue: a full queue (a program not
                            // reading its input) stops this read branch, so QUIC flow control
                            // pushes the pressure back to the client.
                            if !drained.keys.is_empty() {
                                session.send_keys(drained.keys).await;
                            }
                            if let Some((rows, cols)) = drained.resize {
                                session.send_resize(rows, cols).await;
                            }
                            if !session.can_send() {
                                break Ok(SessionExit::Detached); // the session ended
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "client broke the protocol; closing");
                            conn.close(PROTOCOL_ERROR.into(), b"protocol error");
                            break Ok(SessionExit::Detached);
                        }
                    }
                }
                Ok(None) => {
                    // The client finished its stream; a clean end only between messages.
                    if core.finish_client().is_err() {
                        conn.close(PROTOCOL_ERROR.into(), b"protocol error");
                        break Ok(SessionExit::Detached);
                    }
                    client = None;
                }
                Err(e) => {
                    info!(reason = %e, "client stream failed (detaching)");
                    break Ok(SessionExit::Detached);
                }
            },
            () = tokio::time::sleep_until(wake) => {}
        }
    };
    for (_, cancel) in in_flight {
        cancel.cancel();
    }
    result
}

/// The close code for a client that broke the protocol.
const PROTOCOL_ERROR: u32 = 2;

/// Read from the client's stream; `None` when there is no stream is never polled (the caller
/// guards the branch).
async fn read_client(
    stream: Option<&mut RecvStream>,
    buf: &mut [u8],
) -> Result<Option<usize>, iroh::endpoint::ReadError> {
    match stream {
        Some(stream) => stream.read(buf).await,
        None => std::future::pending().await,
    }
}

/// Send one frame on its own stream. Cancelling resets the stream, so QUIC stops retransmitting a
/// frame a newer one has superseded.
async fn send_frame(conn: iroh::endpoint::Connection, bytes: Vec<u8>, cancel: CancellationToken) {
    let mut send = tokio::select! {
        stream = conn.open_uni() => match stream {
            Ok(stream) => stream,
            Err(_) => return,
        },
        () = cancel.cancelled() => return,
    };
    let cancelled = tokio::select! {
        written = async {
            send.write_all(&bytes).await.ok()?;
            send.finish().ok()
        } => {
            if written.is_none() {
                return;
            }
            false
        }
        () = cancel.cancelled() => true,
    };
    // Written: wait until the client has it all, or until it is superseded.
    let cancelled = cancelled
        || tokio::select! {
            _ = send.stopped() => false,
            () = cancel.cancelled() => true,
        };
    if cancelled {
        let _ = send.reset(0u32.into());
    }
}

/// Convenience: run a one-session, one-connection server for `conn`.
///
/// Spawns a registry that hosts a single session, started through `launcher`, attaches this
/// connection, serves it, and tears the session down afterwards. Used by tests and callers that
/// don't need the full accept loop.
pub async fn run_session(
    conn: iroh::endpoint::Connection,
    command: &[String],
    scrollback: usize,
    launcher: crate::pty::Launcher,
) -> anyhow::Result<()> {
    let registry = Registry::spawn(SessionSpec {
        command: command.to_vec().into(),
        scrollback,
        max_sessions: 1,
        ttl: Duration::from_secs(1),
        launcher,
    });
    let peer = conn.remote_id();
    if let Some((client, _)) = registry.attach(peer).await {
        let _ = run_attached(conn, client).await?;
    }
    registry.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{CursorKeyNormalizer, Drained, EchoAck, ServerConn, FINAL_ACK_WAIT};
    use crate::proto::{
        encode_client, retry_after, ClientMsg, Frame, FrameNum, InputSeq, FRAME_WINDOW, HEARTBEAT,
    };
    use crate::terminal::TerminalScreen;

    /// Feed `chunks` through one normalizer at the given app-cursor mode, return the PTY bytes.
    fn norm(chunks: &[&[u8]], app_cursor: bool) -> Vec<u8> {
        let mut n = CursorKeyNormalizer::default();
        let mut out = Vec::new();
        for c in chunks {
            out.extend(n.normalize(c, app_cursor));
        }
        out
    }

    #[test]
    fn ss3_arrows_rewrite_to_csi_when_not_in_application_cursor_mode() {
        // ESC O A..D  ->  ESC [ A..D  (the app expects ANSI cursor keys).
        assert_eq!(norm(&[b"\x1bOA"], false), b"\x1b[A");
        assert_eq!(norm(&[b"\x1bOD"], false), b"\x1b[D");
    }

    #[test]
    fn ss3_arrows_preserved_in_application_cursor_mode() {
        assert_eq!(norm(&[b"\x1bOA"], true), b"\x1bOA");
    }

    #[test]
    fn csi_arrows_and_plain_bytes_pass_through() {
        assert_eq!(norm(&[b"\x1b[A"], false), b"\x1b[A");
        assert_eq!(norm(&[b"ls\r"], false), b"ls\r");
        // A bare ESC then a normal byte (e.g. vim's Escape) is untouched.
        assert_eq!(norm(&[b"\x1bi"], false), b"\x1bi");
    }

    #[test]
    fn ss3_sequence_split_across_chunks_normalizes() {
        // The SS3 state carries across input chunks.
        assert_eq!(norm(&[b"\x1b", b"O", b"A"], false), b"\x1b[A");
        assert_eq!(norm(&[b"\x1b", b"[", b"A"], false), b"\x1b[A");
    }

    fn stream(msgs: &[ClientMsg]) -> Vec<u8> {
        msgs.iter()
            .flat_map(|m| encode_client(m).unwrap())
            .collect()
    }

    #[test]
    fn a_read_keeps_only_the_last_resize_and_concatenates_keys() {
        // Several resizes in one read collapse to the last (clamped); keys stay in order.
        let mut conn = ServerConn::default();
        conn.push_client_bytes(&stream(&[
            ClientMsg::Input {
                seq: InputSeq(1),
                bytes: b"ab".to_vec(),
            },
            ClientMsg::Resize { rows: 10, cols: 20 },
            ClientMsg::Input {
                seq: InputSeq(2),
                bytes: b"\x1bOA".to_vec(),
            },
            ClientMsg::Resize { rows: 30, cols: 40 },
            ClientMsg::Resize {
                rows: 65000,
                cols: 1,
            },
            ClientMsg::Input {
                seq: InputSeq(3),
                bytes: b"ef".to_vec(),
            },
        ]));
        let drained = conn.drain_client(Instant::now(), false).unwrap();
        assert_eq!(
            drained,
            Drained {
                keys: b"ab\x1b[Aef".to_vec(),
                resize: Some(crate::terminal::clamp_dims(65000, 1)),
            }
        );
        conn.push_client_bytes(&stream(&[ClientMsg::Input {
            seq: InputSeq(4),
            bytes: b"x".to_vec(),
        }]));
        assert_eq!(
            conn.drain_client(Instant::now(), false).unwrap().resize,
            None
        );
    }

    #[test]
    fn a_partial_message_waits_and_a_truncated_stream_is_an_error() {
        let mut conn = ServerConn::default();
        let bytes = stream(&[ClientMsg::Input {
            seq: InputSeq(1),
            bytes: b"hello".to_vec(),
        }]);
        let (first, rest) = bytes.split_at(3);
        conn.push_client_bytes(first);
        assert!(conn
            .drain_client(Instant::now(), false)
            .unwrap()
            .keys
            .is_empty());
        assert!(
            conn.finish_client().is_err(),
            "the stream ended inside a message"
        );
        conn.push_client_bytes(rest);
        assert_eq!(
            conn.drain_client(Instant::now(), false).unwrap().keys,
            b"hello"
        );
        assert!(conn.finish_client().is_ok());
    }

    // --- EchoAck: the per-connection echo-ack debounce.

    #[test]
    fn echo_ack_debounces() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut t = EchoAck::default();
        t.register(InputSeq(5), t0);
        assert!(!t.promote(ms(10)), "too soon");
        assert_eq!(t.echo_ack(), InputSeq(0));
        assert!(
            t.promote(ms(50)),
            "after the 50 ms debounce the input counts as echoed"
        );
        assert_eq!(t.echo_ack(), InputSeq(5));
    }

    #[test]
    fn echo_ack_honors_an_injected_timeout() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut t = EchoAck::with_timeout(Duration::from_millis(10));
        t.register(InputSeq(5), t0);
        assert!(!t.promote(ms(5)));
        assert!(t.promote(ms(11)));
        let mut d = EchoAck::default();
        d.register(InputSeq(5), t0);
        assert!(!d.promote(ms(11)), "the 50 ms default has not elapsed");
    }

    #[test]
    fn echo_ack_is_monotonic_takes_the_newest_and_says_when_it_next_moves() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut t = EchoAck::default();
        assert_eq!(t.next_promotion(), None, "nothing pending");
        t.register(InputSeq(3), t0);
        t.register(InputSeq(7), ms(20));
        t.register(InputSeq(6), ms(25)); // stale: ignored
        assert_eq!(t.next_promotion(), Some(ms(50)));
        t.promote(ms(55));
        assert_eq!(t.echo_ack(), InputSeq(3));
        assert_eq!(t.next_promotion(), Some(ms(70)));
        t.promote(ms(100));
        assert_eq!(t.echo_ack(), InputSeq(7));
        assert_eq!(t.next_promotion(), None);
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

        /// Two connections' trackers fed interleaved inputs never influence each other: each ack
        /// is bounded by the inputs *that* connection registered.
        #[test]
        fn echo_ack_trackers_are_independent_per_connection(
            ops in proptest::collection::vec((proptest::prelude::any::<bool>(), 1u64..1000, 0u64..10_000), 1..64),
        ) {
            let t0 = Instant::now();
            let at = |n: u64| t0.checked_add(Duration::from_millis(n)).expect("time within range");
            let mut a = EchoAck::with_timeout(Duration::from_millis(10));
            let mut b = EchoAck::with_timeout(Duration::from_millis(10));
            let (mut max_a, mut max_b) = (0u64, 0u64);
            for (to_a, seq, now) in ops {
                if to_a {
                    a.register(InputSeq(seq), at(now));
                    max_a = max_a.max(seq);
                } else {
                    b.register(InputSeq(seq), at(now));
                    max_b = max_b.max(seq);
                }
                a.promote(at(now.saturating_add(100)));
                b.promote(at(now.saturating_add(100)));
                proptest::prop_assert!(a.echo_ack().0 <= max_a, "A acked input it never saw");
                proptest::prop_assert!(b.echo_ack().0 <= max_b, "B acked input it never saw");
            }
        }
    }

    // --- ServerConn: frame pacing, bases, acknowledgements and shutdown, with no I/O.

    fn screen(bytes: &[u8]) -> TerminalScreen {
        TerminalScreen::from_bytes(24, 80, bytes)
    }

    /// Apply `frame` to `base`, as a client holding that base would.
    fn applied(base: &TerminalScreen, frame: &Frame) -> TerminalScreen {
        let mut s = base.clone();
        s.apply(&frame.diff);
        s
    }

    #[test]
    fn a_changed_snapshot_marks_an_unsent_change_and_the_exit_screen_is_final() {
        let t0 = Instant::now();
        let mut c = ServerConn::default();
        c.install_snapshot(screen(b"a"), true);
        assert!(
            c.poll_frame(t0, None).is_some(),
            "the changed screen is sent"
        );
        // Re-installing the same screen is not a change, so nothing new is due.
        c.install_snapshot(screen(b"a"), true);
        assert!(c.poll_frame(t0, None).is_none());
        // The exit screen marks the connection final.
        c.install_snapshot(screen(b"a"), false);
        let last = c.poll_frame(t0 + Duration::from_secs(1), None);
        assert!(last.is_some() || c.finished(t0 + Duration::from_secs(1) + FINAL_ACK_WAIT));
    }

    #[test]
    fn the_first_frame_goes_out_at_once_and_later_ones_are_paced() {
        let t0 = Instant::now();
        let rtt = Some(Duration::from_millis(100)); // a 50 ms frame interval
        let mut c = ServerConn::default();
        c.install_snapshot(screen(b"hello"), true);
        let first = c
            .poll_frame(t0, rtt)
            .expect("the first frame is due at once");
        assert_eq!((first.num, first.base), (FrameNum(1), FrameNum::BLANK));
        assert!(applied(&TerminalScreen::default(), &first)
            .screen()
            .contents()
            .contains("hello"));
        assert!(c.poll_frame(t0, rtt).is_none(), "nothing changed");
        c.install_snapshot(screen(b"hello world"), true);
        assert!(
            c.poll_frame(t0 + Duration::from_millis(10), rtt).is_none(),
            "inside the interval"
        );
        assert_eq!(
            c.next_wake(t0 + Duration::from_millis(10), rtt),
            t0 + Duration::from_millis(50)
        );
        let second = c
            .poll_frame(t0 + Duration::from_millis(50), rtt)
            .expect("interval passed");
        assert_eq!(second.num, FrameNum(2));
        assert_eq!(second.base, FrameNum::BLANK, "nothing was acknowledged yet");
    }

    #[test]
    fn a_quiet_connection_still_gets_a_heartbeat() {
        let t0 = Instant::now();
        let mut c = ServerConn::default();
        c.install_snapshot(screen(b"idle"), true);
        c.poll_frame(t0, None).expect("first frame");
        // Acknowledged, so no retry is due; only the heartbeat is.
        c.ack(FrameNum(1));
        let just_before = (t0 + HEARTBEAT)
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        assert!(c.poll_frame(just_before, None).is_none());
        assert_eq!(c.next_wake(t0, None), t0 + HEARTBEAT);
        let beat = c.poll_frame(t0 + HEARTBEAT, None).expect("heartbeat");
        assert_eq!(beat.num, FrameNum(2));
    }

    #[test]
    fn an_unacknowledged_frame_is_resent_as_a_new_one_after_a_retry_interval() {
        let t0 = Instant::now();
        let rtt = Some(Duration::from_millis(200));
        let retry = retry_after(rtt);
        let mut c = ServerConn::default();
        c.install_snapshot(screen(b"lost?"), true);
        let first = c.poll_frame(t0, rtt).unwrap();
        let just_before = (t0 + retry).checked_sub(Duration::from_millis(1)).unwrap();
        assert!(c.poll_frame(just_before, rtt).is_none());
        assert_eq!(c.next_wake(t0, rtt), t0 + retry);
        let again = c.poll_frame(t0 + retry, rtt).expect("resent");
        assert_eq!((again.num, again.base), (FrameNum(2), FrameNum::BLANK));
        assert_eq!(
            again.diff, first.diff,
            "the same screen, as a frame that supersedes"
        );
        // Once acknowledged, nothing more is resent until something changes.
        c.ack(FrameNum(2));
        assert!(c.poll_frame(t0 + retry * 3, rtt).is_none());
    }

    #[test]
    fn frames_diff_against_the_newest_acknowledged_frame() {
        let t0 = Instant::now();
        let later = |n| t0 + Duration::from_secs(n);
        let mut c = ServerConn::default();
        c.install_snapshot(screen(b"one"), true);
        let one = c.poll_frame(t0, None).unwrap();
        c.install_snapshot(screen(b"one two"), true);
        let two = c.poll_frame(later(1), None).unwrap();
        c.ack(FrameNum(1));
        c.install_snapshot(screen(b"one two three"), true);
        let three = c.poll_frame(later(2), None).unwrap();
        assert_eq!(three.base, FrameNum(1));
        let client_one = applied(&TerminalScreen::default(), &one);
        assert_eq!(applied(&client_one, &three), screen(b"one two three"));
        // An ack for a frame older than the acknowledged one changes nothing.
        c.ack(FrameNum(2));
        c.ack(FrameNum(1));
        c.install_snapshot(screen(b"four"), true);
        assert_eq!(c.poll_frame(later(3), None).unwrap().base, FrameNum(2));
        let _ = two;
    }

    #[test]
    fn a_resync_diffs_against_the_blank_screen_until_a_newer_ack() {
        let t0 = Instant::now();
        let later = |n| t0 + Duration::from_secs(n);
        let mut c = ServerConn::default();
        c.install_snapshot(screen(b"a"), true);
        c.poll_frame(t0, None).unwrap();
        c.ack(FrameNum(1));
        c.push_client_bytes(&stream(&[ClientMsg::Resync]));
        c.drain_client(later(1), false).unwrap();
        let rebuilt = c
            .poll_frame(later(1), None)
            .expect("a resync forces a frame");
        assert_eq!(rebuilt.base, FrameNum::BLANK);
        assert_eq!(applied(&TerminalScreen::default(), &rebuilt), screen(b"a"));
    }

    #[test]
    fn only_the_last_frames_are_kept_so_an_ack_for_an_older_one_is_ignored() {
        let t0 = Instant::now();
        let mut c = ServerConn::default();
        for n in 0..=u64::try_from(FRAME_WINDOW).unwrap() {
            c.install_snapshot(screen(format!("frame {n}").as_bytes()), true);
            c.poll_frame(t0 + Duration::from_secs(n), None).unwrap();
        }
        assert_eq!(c.sent.len(), FRAME_WINDOW);
        c.ack(FrameNum(1)); // dropped from the window
        assert_eq!(c.acked(), FrameNum::BLANK);
        c.ack(FrameNum(3));
        assert_eq!(c.acked(), FrameNum(3));
    }

    #[test]
    fn the_connection_finishes_once_the_final_frame_is_acked_or_after_a_second() {
        let t0 = Instant::now();
        let sent = t0 + Duration::from_secs(1);
        // A connection that has just sent the final frame (with the exit code) at `sent`.
        let exited = || {
            let mut c = ServerConn::default();
            c.install_snapshot(screen(b"$ "), true);
            c.poll_frame(t0, None).unwrap();
            assert!(!c.finished(t0));
            let mut emu = crate::terminal::ServerTerminal::new(24, 80, 0).unwrap();
            emu.set_exit_code(3);
            c.install_snapshot(emu.snapshot(), false);
            let last = c.poll_frame(sent, None).expect("the final frame");
            assert!(!c.finished(sent));
            (c, last)
        };
        let (mut acked, last) = exited();
        acked.ack(last.num);
        assert!(acked.finished(sent), "acked: done at once");
        let (unacked, _) = exited();
        let just_before = (sent + FINAL_ACK_WAIT)
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        assert!(!unacked.finished(just_before));
        assert!(
            unacked.finished(sent + FINAL_ACK_WAIT),
            "unacked: done after the wait"
        );
    }
}
