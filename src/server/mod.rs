//! The koh server: the per-connection session loop.
//!
//! Reused by the binary and by integration tests (so the full PTY⇄emulator⇄transport path can be
//! exercised over a real iroh connection without the CLI/accept scaffolding).
//!
//! Sessions are **detachable**: the long-lived PTY + emulator lives in [`session::Session`] and
//! survives client disconnects; a per-connection [`run_attached`] loop drives a *fresh* `Transport`
//! against it, so a reconnecting client re-syncs to the current screen.

mod audit;
pub mod cli;
pub mod session;

#[cfg(feature = "cli")]
pub use cli::ServeArgs;
pub use cli::{serve, ServeConfig};
pub use session::{ChangeSignal, PtyHost, SharedSession};

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::proto::{
    encode_frame, frame_interval, retry_after, ClientDecoder, ClientMsg, Frame, FrameNum, InputSeq,
    ProtoError, FRAME_WINDOW, HEARTBEAT, SESSION_ENDED,
};
use crate::ssp::SyncState as _;
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

/// How often a connection retries PTY input the writer queue could not take.
const INPUT_RETRY: Duration = Duration::from_millis(10);

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
    /// The screen may have changed since `screen` was taken.
    dirty: bool,
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
    /// Keystrokes the PTY writer queue could not take yet. While this is non-empty the loop stops
    /// reading the client's stream, so QUIC flow control pushes back on the client.
    pending_keys: Vec<u8>,
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
            dirty: true,
            unsent_change: true,
            final_snapshot: false,
            acked: (FrameNum::BLANK, TerminalScreen::default()),
            sent: VecDeque::new(),
            last_num: FrameNum::BLANK,
            last_sent_at: None,
            last_sent_echo: InputSeq(0),
            final_frame: None,
            pending_keys: Vec::new(),
        }
    }

    /// Whether a new snapshot is needed: the screen may have changed, or the program exited and
    /// the final screen (with its exit code) has not been taken yet.
    const fn needs_snapshot(&self, alive: bool) -> bool {
        self.dirty || (!alive && !self.final_snapshot)
    }

    /// Install a snapshot taken while the program was `alive`.
    fn install_snapshot(&mut self, screen: TerminalScreen, alive: bool) {
        let last_sent = self.sent.back().map_or(&self.acked.1, |(_, s)| s);
        if screen != *last_sent {
            self.unsent_change = true;
        }
        self.screen = screen;
        self.dirty = false;
        if !alive {
            self.final_snapshot = true;
        }
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
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
        if !self.pending_keys.is_empty() {
            wake = wake.min(now.checked_add(INPUT_RETRY).unwrap_or(now));
        }
        wake.max(now)
    }
}

/// Drive a client connection against an existing (shared, detachable) [`session::Session`].
///
/// The async shell around the `ServerConn` core: it snapshots the session when it changes, applies the
/// client's input to the PTY, sends each frame on its own stream, and resets the stream of a frame
/// a newer one supersedes. A fresh core per attach starts from the blank screen, so the first frame
/// repaints the live screen onto a (re)connecting client. It does **not** kill the host on
/// disconnect: it returns [`SessionExit::Detached`] and leaves it running for the next reattach.
pub async fn run_attached(
    conn: iroh::endpoint::Connection,
    handle: SharedSession,
) -> anyhow::Result<SessionExit> {
    let channel = IrohChannel::new(conn.clone());
    let mut core = ServerConn::default();
    let mut changed = handle.changed.subscribe();
    let mut client: Option<RecvStream> = None;
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut in_flight: VecDeque<(FrameNum, CancellationToken)> = VecDeque::new();
    let result = loop {
        let now = Instant::now();
        core.promote_echo(now);
        // Snapshot under the session lock, only when something may have changed. Mark the change
        // signal seen BEFORE snapshotting: a pulse after this point re-fires `changed()` below and
        // costs at most one redundant snapshot, while marking it after could swallow a pulse for a
        // change the snapshot missed.
        {
            let s = handle.session.lock().await;
            let alive = s.host.alive();
            if core.needs_snapshot(alive) {
                let _ = changed.borrow_and_update();
                let snapshot = s.host.snapshot();
                drop(s);
                core.install_snapshot(snapshot, alive);
            }
        }
        // Keystrokes the PTY queue could not take last time.
        if !core.pending_keys.is_empty() {
            let mut s = handle.session.lock().await;
            if s.host.input(&core.pending_keys) {
                core.pending_keys.clear();
            }
        }
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
        let reading = client.is_some() && core.pending_keys.is_empty();
        tokio::select! {
            // NOT biased: `changed` may already be pending, which under `biased` would starve
            // client input. `watch` remembers the last version each receiver saw, so a pulse that
            // landed between the snapshot above and this wait resolves immediately.
            _ = changed.changed() => core.mark_dirty(),
            stream = conn.accept_uni() => match stream {
                Ok(stream) if client.is_none() => client = Some(stream),
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
                    let mut s = handle.session.lock().await;
                    match core.drain_client(Instant::now(), s.host.application_cursor()) {
                        Ok(drained) => {
                            if !drained.keys.is_empty() && !s.host.input(&drained.keys) {
                                core.pending_keys = drained.keys;
                            }
                            if let Some((rows, cols)) = drained.resize {
                                s.host.resize(rows, cols);
                                // A resize changes the emulator grid directly, with no pulse.
                                core.mark_dirty();
                            }
                        }
                        Err(e) => {
                            drop(s);
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

/// Convenience: run a **standalone** (non-detachable) PTY session for one connection.
///
/// Spawns a shell, serves it, and kills it when the connection ends. Used by integration tests and
/// any caller that doesn't need reattach. The binary uses the [`session`] store + [`run_attached`].
pub async fn run_session(
    conn: iroh::endpoint::Connection,
    command: &[String],
    scrollback: usize,
) -> anyhow::Result<()> {
    let handle = session::spawn_session(command, scrollback)?;
    let _ = run_attached(conn, handle.clone()).await?;
    handle.session.lock().await.host.kill();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{CursorKeyNormalizer, Drained, EchoAck, ServerConn, FINAL_ACK_WAIT};
    use crate::proto::{
        decode_frame, encode_client, retry_after, ClientMsg, Frame, FrameNum, InputSeq,
        FRAME_WINDOW, HEARTBEAT, MAX_FRAME,
    };
    use crate::ssp::SyncState as _;
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
        msgs.iter().flat_map(|m| encode_client(m).unwrap()).collect()
    }

    #[test]
    fn a_read_keeps_only_the_last_resize_and_concatenates_keys() {
        // Several resizes in one read collapse to the last (clamped); keys stay in order.
        let mut conn = ServerConn::default();
        conn.push_client_bytes(&stream(&[
            ClientMsg::Input { seq: InputSeq(1), bytes: b"ab".to_vec() },
            ClientMsg::Resize { rows: 10, cols: 20 },
            ClientMsg::Input { seq: InputSeq(2), bytes: b"\x1bOA".to_vec() },
            ClientMsg::Resize { rows: 30, cols: 40 },
            ClientMsg::Resize { rows: 65000, cols: 1 },
            ClientMsg::Input { seq: InputSeq(3), bytes: b"ef".to_vec() },
        ]));
        let drained = conn.drain_client(Instant::now(), false).unwrap();
        assert_eq!(
            drained,
            Drained {
                keys: b"ab\x1b[Aef".to_vec(),
                resize: Some(crate::terminal::clamp_dims(65000, 1)),
            }
        );
        conn.push_client_bytes(&stream(&[ClientMsg::Input { seq: InputSeq(4), bytes: b"x".to_vec() }]));
        assert_eq!(conn.drain_client(Instant::now(), false).unwrap().resize, None);
    }

    #[test]
    fn a_partial_message_waits_and_a_truncated_stream_is_an_error() {
        let mut conn = ServerConn::default();
        let bytes = stream(&[ClientMsg::Input { seq: InputSeq(1), bytes: b"hello".to_vec() }]);
        let (first, rest) = bytes.split_at(3);
        conn.push_client_bytes(first);
        assert!(conn.drain_client(Instant::now(), false).unwrap().keys.is_empty());
        assert!(conn.finish_client().is_err(), "the stream ended inside a message");
        conn.push_client_bytes(rest);
        assert_eq!(conn.drain_client(Instant::now(), false).unwrap().keys, b"hello");
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
        assert!(t.promote(ms(50)), "after the 50 ms debounce the input counts as echoed");
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
            let at = |n: u64| t0 + Duration::from_millis(n);
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
                a.promote(at(now + 100));
                b.promote(at(now + 100));
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
    fn snapshots_are_taken_when_dirty_and_once_after_exit() {
        let mut c = ServerConn::default();
        assert!(c.needs_snapshot(true), "the first pass snapshots");
        c.install_snapshot(screen(b"a"), true);
        assert!(!c.needs_snapshot(true), "a clean live host skips it");
        assert!(c.needs_snapshot(false), "the exit screen is always taken");
        c.install_snapshot(screen(b"a"), false);
        assert!(!c.needs_snapshot(false), "but only once");
        c.mark_dirty();
        assert!(c.needs_snapshot(false));
    }

    #[test]
    fn the_first_frame_goes_out_at_once_and_later_ones_are_paced() {
        let t0 = Instant::now();
        let rtt = Some(Duration::from_millis(100)); // a 50 ms frame interval
        let mut c = ServerConn::default();
        c.install_snapshot(screen(b"hello"), true);
        let first = c.poll_frame(t0, rtt).expect("the first frame is due at once");
        assert_eq!((first.num, first.base), (FrameNum(1), FrameNum::BLANK));
        assert!(applied(&TerminalScreen::default(), &first).screen().contents().contains("hello"));
        assert!(c.poll_frame(t0, rtt).is_none(), "nothing changed");
        c.install_snapshot(screen(b"hello world"), true);
        assert!(c.poll_frame(t0 + Duration::from_millis(10), rtt).is_none(), "inside the interval");
        assert_eq!(c.next_wake(t0 + Duration::from_millis(10), rtt), t0 + Duration::from_millis(50));
        let second = c.poll_frame(t0 + Duration::from_millis(50), rtt).expect("interval passed");
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
        let just_before = (t0 + HEARTBEAT).checked_sub(Duration::from_millis(1)).unwrap();
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
        assert_eq!(again.diff, first.diff, "the same screen, as a frame that supersedes");
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
        let rebuilt = c.poll_frame(later(1), None).expect("a resync forces a frame");
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
        let just_before = (sent + FINAL_ACK_WAIT).checked_sub(Duration::from_millis(1)).unwrap();
        assert!(!unacked.finished(just_before));
        assert!(unacked.finished(sent + FINAL_ACK_WAIT), "unacked: done after the wait");
    }

    // --- run_session / run_attached over real iroh, with a minimal koh/3 client.

    /// A bare koh/3 client: writes messages, applies frames whose base it holds, and acks them.
    struct RawClient {
        conn: iroh::endpoint::Connection,
        send: iroh::endpoint::SendStream,
        frames: tokio::sync::mpsc::Receiver<Frame>,
        screens: std::collections::HashMap<FrameNum, TerminalScreen>,
        newest: FrameNum,
        echo_ack: InputSeq,
        last_seq: InputSeq,
        _endpoint: iroh::Endpoint,
    }

    impl RawClient {
        async fn connect(addr: iroh::EndpointAddr) -> Self {
            use crate::transport_iroh::{bind_endpoint_local, generate_secret_key, ALPN};
            let endpoint = bind_endpoint_local(generate_secret_key(), false)
                .await
                .expect("bind client");
            let conn = endpoint.connect(addr, ALPN).await.expect("connect");
            let send = conn.open_uni().await.expect("open the client stream");
            let (tx, frames) = tokio::sync::mpsc::channel(64);
            let reader = conn.clone();
            tokio::spawn(async move {
                while let Ok(mut recv) = reader.accept_uni().await {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Ok(bytes) = recv.read_to_end(MAX_FRAME).await {
                            if let Ok(frame) = decode_frame(&bytes) {
                                let _ = tx.send(frame).await;
                            }
                        }
                    });
                }
            });
            Self {
                conn,
                send,
                frames,
                screens: std::collections::HashMap::from([(FrameNum::BLANK, TerminalScreen::default())]),
                newest: FrameNum::BLANK,
                echo_ack: InputSeq(0),
                last_seq: InputSeq(0),
                _endpoint: endpoint,
            }
        }

        async fn write(&mut self, msg: &ClientMsg) {
            self.send
                .write_all(&encode_client(msg).unwrap())
                .await
                .expect("write the client stream");
        }

        async fn type_bytes(&mut self, bytes: &[u8]) {
            self.last_seq = self.last_seq.next();
            let msg = ClientMsg::Input { seq: self.last_seq, bytes: bytes.to_vec() };
            self.write(&msg).await;
        }

        /// Apply and ack frames for `ms`.
        async fn pump(&mut self, ms: u64) {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
            while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, self.frames.recv()).await {
                if frame.num <= self.newest {
                    continue;
                }
                let Some(base) = self.screens.get(&frame.base) else { continue };
                let mut next = base.clone();
                next.apply(&frame.diff);
                self.screens.insert(frame.num, next);
                self.newest = frame.num;
                self.echo_ack = self.echo_ack.max(frame.echo_ack);
                self.write(&ClientMsg::Ack { frame: frame.num }).await;
            }
        }

        fn screen(&self) -> &TerminalScreen {
            &self.screens[&self.newest]
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_session_delivers_keys_and_clamped_resizes_then_kills_the_shell() {
        use crate::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr};
        let server_ep = bind_endpoint_local(generate_secret_key(), true)
            .await
            .expect("bind");
        let addr = loopback_addr(&server_ep);
        let accept = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("incoming");
            let conn = incoming.await.expect("handshake");
            super::run_session(conn, &["cat".to_owned()], 0).await
        });
        let mut client = RawClient::connect(addr).await;
        client.write(&ClientMsg::Resize { rows: 65000, cols: 1 }).await;
        client.type_bytes(b"xy").await;
        let clamped = crate::terminal::clamp_dims(65000, 1);
        for _ in 0..100 {
            client.pump(100).await;
            let s = client.screen();
            if s.screen().contents().contains("xy") && s.size() == clamped && client.echo_ack >= InputSeq(1) {
                break;
            }
        }
        assert!(client.screen().screen().contents().contains("xy"), "input reached the program");
        assert_eq!(client.screen().size(), clamped, "the resize arrives clamped");
        assert_eq!(client.echo_ack, InputSeq(1), "the input is acknowledged as echoed");
        client.conn.close(0u32.into(), b"done");
        tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .expect("run_session returns after the connection ends")
            .expect("accept task")
            .expect("run_session");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn echo_ack_is_tracked_per_connection_so_a_second_connection_sees_only_its_own_input() {
        // Two connections on ONE session (a peer's reconnect racing its old connection). A types
        // many times, B once. Each must only ever be acked for input it sent.
        use crate::server::session::spawn_session;
        use crate::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr};
        let server_ep = bind_endpoint_local(generate_secret_key(), true)
            .await
            .expect("bind");
        let addr = loopback_addr(&server_ep);
        let handle = spawn_session(&["cat".to_owned()], 0).expect("spawn");
        let h2 = handle.clone();
        let accept = tokio::spawn(async move {
            while let Some(incoming) = server_ep.accept().await {
                let h = h2.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        let _ = super::run_attached(conn, h).await;
                    }
                });
            }
        });
        let mut a = RawClient::connect(addr.clone()).await;
        let mut b = RawClient::connect(addr).await;
        for _ in 0..30 {
            a.type_bytes(b"a").await;
            a.pump(20).await;
            b.pump(20).await;
            assert!(a.echo_ack <= a.last_seq, "A was acked for input it never sent");
            assert_eq!(b.echo_ack, InputSeq(0), "B was handed A's echo-ack");
        }
        b.type_bytes(b"b").await;
        for _ in 0..50 {
            a.pump(20).await;
            b.pump(20).await;
            if b.echo_ack == InputSeq(1) && a.echo_ack == a.last_seq {
                break;
            }
        }
        assert_eq!(b.echo_ack, InputSeq(1), "B is acked for its own one input");
        assert_eq!(a.echo_ack, a.last_seq, "A is acked up to its own last input");
        accept.abort();
    }
}
