//! The koh server.
//!
//! A session's PTY and emulator live in a [`session`] task that outlives its
//! connections; each connection runs [`run_attached`] with a fresh protocol core, so a client that
//! reconnects gets the current screen.

mod audit;
pub mod cli;
pub mod session;

pub use cli::{serve, ServeConfig};
pub use session::{PtyHost, Registry, SessionSpec};

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::events::{InputEvent, WireColours};
use crate::proto::{
    encode_history, retry_after, ClientDecoder, ClientMsg, Frame, FrameEncoder, FrameNum,
    FrameScreen, InputSeq, ProtoError, FRAME_FLOOR, FRAME_WINDOW, HEARTBEAT, MAX_PENDING_HISTORY,
    WINDOW_CELLS,
};
use crate::terminal::{HistoryRequest, Size, TerminalScreen};
use crate::transport_iroh::admission::{self, Close, Link};
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

/// Rewrites SS3 arrow keys (`ESC O A..D`) as CSI (`ESC [ A..D`) for a program not in application
/// cursor mode, so arrows work whatever mode the local terminal is in (mosh's `UserInput::input`).
/// The state carries across chunks.
#[derive(Default)]
struct CursorKeyNormalizer {
    state: Ss3State,
}

impl CursorKeyNormalizer {
    /// Append `input`, normalized for a program whose application cursor mode is `app_cursor`, to
    /// `out`.
    fn normalize_into(&mut self, input: &[u8], app_cursor: bool, out: &mut Vec<u8>) {
        // One spare byte for a held escape.
        out.reserve(input.len().saturating_add(1));
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
                    // ESC went out already.
                    out.push(if !app_cursor && (b'A'..=b'D').contains(&b) {
                        b'['
                    } else {
                        b'O'
                    });
                    out.push(b);
                }
            }
        }
    }
}

/// How long the program gets to show a keystroke before it counts as echoed.
pub(crate) const ECHO_TIMEOUT: Duration = Duration::from_millis(50);

/// How long the server waits for the client to acknowledge the final frame before closing.
const FINAL_ACK_WAIT: Duration = Duration::from_secs(1);

/// Which of one connection's inputs the program has had time to show. Per connection, as input
/// sequence numbers are.
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

    /// Promote the inputs that arrived at least the debounce before `now`; whether the echo-ack moved.
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

    /// Whether input arrived within the debounce and is not yet promoted.
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// The current echo-ack.
    pub(crate) const fn echo_ack(&self) -> InputSeq {
        self.acked
    }
}

/// Input for the session, in the order the client sent it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ToSession {
    /// Raw bytes ([`ClientMsg::Input`]), DECCKM-normalized.
    Bytes(Vec<u8>),
    /// Decoded input ([`ClientMsg::Keys`]), which the session encodes as its program asked.
    Events(Vec<InputEvent>),
    /// What the user's terminal said of its colours.
    Colours(WireColours),
}

/// The client input one read made ready for the PTY.
#[derive(Debug, Default, PartialEq, Eq)]
struct Drained {
    /// The input, in order; neighbours of one kind merged.
    input: Vec<ToSession>,
    /// The last resize, clamped. Earlier ones in a read would have no visible effect, only costs.
    resize: Option<Size>,
}

/// The server side of one connection, without I/O: it decodes the client's stream, tracks the
/// echo-ack, and decides when to send which frame against which base.
pub(crate) struct ServerConn {
    decoder: ClientDecoder,
    cursor_keys: CursorKeyNormalizer,
    echo: EchoAck,
    /// The session's newest screen, shared with every frame that shows it.
    screen: Arc<TerminalScreen>,
    /// `screen` differs from what was last sent, or the base must be rebuilt.
    unsent_change: bool,
    /// `screen` was taken after the hosted program exited.
    final_snapshot: bool,
    /// The newest frame the client acknowledged, and its screen. Starts as the blank frame 0.
    acked: FrameScreen,
    /// Frames sent since, oldest first: at most `FRAME_WINDOW`, holding at most [`WINDOW_CELLS`]
    /// cells together unless the newest alone is more, so a client that never acknowledges cannot
    /// make the server hold sixteen of the largest screens. The newest is always kept.
    sent: VecDeque<FrameScreen>,
    last_num: FrameNum,
    last_sent_at: Option<Instant>,
    last_sent_echo: InputSeq,
    /// The first frame sent after the program exited, and when.
    final_frame: Option<(FrameNum, Instant)>,
    /// History requests not yet answered, oldest first, at most [`MAX_PENDING_HISTORY`].
    history: VecDeque<HistoryRequest>,
    /// An answer is on its way to the client; the next waits for it to be delivered.
    history_busy: bool,
    /// Encodes frames, primed for the base they are diffed against.
    encoder: FrameEncoder,
    /// Frames sent and not yet delivered, oldest first: each one's number, size and when it went.
    in_flight: VecDeque<(FrameNum, usize, Instant)>,
    /// How long recent frames took to be delivered, for the link's rate.
    deliveries: Deliveries,
}

/// How many recent deliveries the link's rate is judged by.
const DELIVERY_SAMPLES: usize = 16;

/// The bytes the server may have in flight before the link's rate is known: about ten packets,
/// QUIC's initial window.
const INITIAL_BUDGET: usize = 12_000;

/// Most frames in flight: half the window of frames the server keeps (and the client keeps as
/// bases), so that every frame in flight is still in the window when its delivery is heard of, and
/// a fast program on a slow round trip cannot outrun the acknowledgements.
const MAX_IN_FLIGHT: usize = FRAME_WINDOW.div_euclid(2);

/// Most frames in flight with which an echo still goes at once: past them it waits like any frame.
const MAX_IN_FLIGHT_ECHO: usize = FRAME_WINDOW - 2;

/// Most rows a frame may change and still go at once as the program's echo of the user's input.
const ECHO_ROWS: usize = 4;

/// The least gap between frames that carry the echo of the user's input.
const ECHO_FLOOR: Duration = Duration::from_millis(1);

/// How long recent frames took from being sent to being delivered, and their sizes: what the link
/// carries in a round trip.
#[derive(Debug, Default)]
struct Deliveries {
    /// Each recent frame's size, and how long it took, newest last.
    samples: VecDeque<(usize, Duration)>,
}

impl Deliveries {
    fn record(&mut self, bytes: usize, took: Duration) {
        self.samples.push_back((bytes, took));
        if self.samples.len() > DELIVERY_SAMPLES {
            self.samples.pop_front();
        }
    }

    /// The bytes the link carries in a round trip of `rtt`, about: its rate times the round trip,
    /// the rate judged by the quickest recent delivery per byte. A frame took a round trip and the
    /// time its bytes took to go; the quickest delivery of all is near the round trip alone, so
    /// what a frame took beyond it is its bytes' time. `None` before any delivery.
    fn budget(&self, rtt: Duration) -> Option<usize> {
        let quickest = self.samples.iter().map(|(_, took)| *took).min()?;
        let budget = self
            .samples
            .iter()
            .map(|(bytes, took)| {
                // At least a millisecond: a frame faster than that says the link is fast, not
                // how fast.
                let sending = took.saturating_sub(quickest).max(Duration::from_millis(1));
                let per_rtt = u128::from(u64::try_from(*bytes).unwrap_or(u64::MAX))
                    .saturating_mul(rtt.as_nanos())
                    .checked_div(sending.as_nanos())
                    .unwrap_or(0);
                usize::try_from(per_rtt).unwrap_or(usize::MAX)
            })
            .max()?;
        Some(budget)
    }
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
            screen: Arc::default(),
            unsent_change: true,
            final_snapshot: false,
            acked: FrameScreen::default(),
            sent: VecDeque::new(),
            last_num: FrameNum::BLANK,
            last_sent_at: None,
            last_sent_echo: InputSeq(0),
            final_frame: None,
            history: VecDeque::new(),
            history_busy: false,
            encoder: FrameEncoder::default(),
            in_flight: VecDeque::new(),
            deliveries: Deliveries::default(),
        }
    }

    /// Install the session's latest screen (taken while the program was `alive`).
    fn install_snapshot(&mut self, screen: Arc<TerminalScreen>, alive: bool) {
        let last_sent = &self.sent.back().unwrap_or(&self.acked).screen;
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

    /// Decode the complete messages read so far, at `now`: the input and resize for the PTY.
    fn drain_client(&mut self, now: Instant, app_cursor: bool) -> Result<Drained, ProtoError> {
        let mut drained = Drained::default();
        while let Some(msg) = self.decoder.next_msg()? {
            match msg {
                ClientMsg::Input { seq, bytes } => {
                    self.echo.register(seq, now);
                    if !matches!(drained.input.last(), Some(ToSession::Bytes(_))) {
                        drained.input.push(ToSession::Bytes(Vec::new()));
                    }
                    if let Some(ToSession::Bytes(keys)) = drained.input.last_mut() {
                        self.cursor_keys.normalize_into(&bytes, app_cursor, keys);
                    }
                }
                ClientMsg::Keys { seq, events } => {
                    self.echo.register(seq, now);
                    match drained.input.last_mut() {
                        Some(ToSession::Events(queued)) => queued.extend(events),
                        _ => drained.input.push(ToSession::Events(events)),
                    }
                }
                ClientMsg::Colours(colours) => drained.input.push(ToSession::Colours(colours)),
                ClientMsg::Resize(size) => {
                    drained.resize = Some(crate::terminal::clamp_dims(size));
                }
                ClientMsg::Ack { frame } => self.ack(frame, now),
                ClientMsg::Resync => self.resync(),
                ClientMsg::History(request) => {
                    if self.history.len() >= MAX_PENDING_HISTORY {
                        return Err(ProtoError::TooManyRequests);
                    }
                    self.history.push_back(request);
                }
            }
        }
        Ok(drained)
    }

    /// The next history request to answer, if no answer is on its way; the caller calls
    /// [`history_delivered`](Self::history_delivered) once its answer is delivered.
    fn next_history(&mut self) -> Option<HistoryRequest> {
        if self.history_busy {
            return None;
        }
        let request = self.history.pop_front()?;
        self.history_busy = true;
        Some(request)
    }

    /// The last history answer was delivered (or given up on): the next may go.
    fn history_delivered(&mut self) {
        self.history_busy = false;
    }

    /// The client's stream ended: fine between messages, a protocol error inside one.
    fn finish_client(&self) -> Result<(), ProtoError> {
        self.decoder.finish()
    }

    /// The client applied `num`, so older frames are no bases any more. An ack for a frame no longer
    /// held is ignored.
    fn ack(&mut self, num: FrameNum, now: Instant) {
        self.delivered(num, now);
        if num <= self.acked.num {
            return;
        }
        let Some(pos) = self.sent.iter().position(|sent| sent.num == num) else {
            return;
        };
        let mut rest = self.sent.split_off(pos);
        if let Some(acked) = rest.pop_front() {
            self.acked = acked;
        }
        self.sent = rest;
    }

    /// Frame `num` was delivered at `now`: it is no longer in flight, nor are the frames before it,
    /// which it superseded, and how long it took says how fast the link is.
    fn delivered(&mut self, num: FrameNum, now: Instant) {
        if let Some(&(_, bytes, sent)) = self.in_flight.iter().find(|(n, _, _)| *n == num) {
            self.deliveries
                .record(bytes, now.saturating_duration_since(sent));
        }
        self.in_flight.retain(|(n, _, _)| *n > num);
    }

    /// Frame `num`, of `bytes` on its stream, went at `now`.
    fn frame_sent(&mut self, num: FrameNum, bytes: usize, now: Instant) {
        self.in_flight.push_back((num, bytes, now));
    }

    /// The frame bytes in flight at `now`: sent, not delivered, and not given up on (a frame not
    /// delivered within a retry interval is lost, or reset, and its newest screen is resent).
    fn in_flight_bytes(&self, now: Instant, rtt: Option<Duration>) -> usize {
        self.live_in_flight(now, rtt)
            .map(|(_, bytes, _)| *bytes)
            .fold(0, usize::saturating_add)
    }

    /// The frames in flight at `now` (as [`in_flight_bytes`](Self::in_flight_bytes) counts them).
    fn in_flight_frames(&self, now: Instant, rtt: Option<Duration>) -> usize {
        self.live_in_flight(now, rtt).count()
    }

    fn live_in_flight(
        &self,
        now: Instant,
        rtt: Option<Duration>,
    ) -> impl Iterator<Item = &(FrameNum, usize, Instant)> {
        let given_up = retry_after(rtt);
        self.in_flight
            .iter()
            .filter(move |(_, _, sent)| now.saturating_duration_since(*sent) < given_up)
    }

    /// Whether the link has room for a frame at `now`: the bytes in flight under the budget (or
    /// none), and fewer frames in flight than `most`.
    fn room(&self, now: Instant, rtt: Option<Duration>, most: usize) -> bool {
        let bytes = self.in_flight_bytes(now, rtt);
        (bytes == 0 || bytes < self.budget(rtt)) && self.in_flight_frames(now, rtt) < most
    }

    /// The frame bytes the link may have in flight: about a round trip's worth.
    fn budget(&self, rtt: Option<Duration>) -> usize {
        rtt.and_then(|rtt| self.deliveries.budget(rtt))
            .unwrap_or(INITIAL_BUDGET)
    }

    /// Whether the screen's change is small and the user typed in the last echo debounce: a frame
    /// that likely carries the program's echo, which goes at once.
    fn carries_echo(&self) -> bool {
        self.echo.has_pending()
            && self
                .screen
                .rows_differing(&self.acked.screen)
                .is_some_and(|rows| rows <= ECHO_ROWS)
    }

    /// The client lacks a frame's base: diff against the blank screen until it acknowledges one.
    fn resync(&mut self) {
        self.acked = FrameScreen::default();
        self.unsent_change = true;
    }

    /// Promote the echo-ack at `now`.
    fn promote_echo(&mut self, now: Instant) {
        self.echo.promote(now);
    }

    /// The frame due at `now`, if any.
    ///
    /// A changed screen or echo-ack goes once the frame floor has passed and the link has room:
    /// the frame bytes in flight are under about a round trip's worth (or none are), so frames
    /// never queue behind each other, and while they would, the screen they would carry is skipped
    /// for the newest. A small change while the user's input awaits its echo goes at once, room or
    /// not. Besides, the newest frame is resent as a new one once unacknowledged for a retry
    /// interval, and a heartbeat goes when the link has been quiet.
    fn poll_frame(&mut self, now: Instant, rtt: Option<Duration>) -> Option<Frame> {
        let changed = self.unsent_change || self.echo.echo_ack() != self.last_sent_echo;
        let since = self
            .last_sent_at
            .map(|at| now.saturating_duration_since(at));
        let passed = |floor: Duration| since.is_none_or(|since| since >= floor);
        let room = self.room(now, rtt, MAX_IN_FLIGHT);
        let unacked = self.last_num > self.acked.num;
        let retry_due = unacked && since.is_some_and(|since| since >= retry_after(rtt));
        let heartbeat_due = since.is_none_or(|since| since >= HEARTBEAT);
        let echo = self.unsent_change
            && passed(ECHO_FLOOR)
            && self.carries_echo()
            && self.in_flight_frames(now, rtt) < MAX_IN_FLIGHT_ECHO;
        let due = (changed && passed(FRAME_FLOOR) && room) || echo || retry_due || heartbeat_due;
        if !due {
            return None;
        }
        let num = self.last_num.next();
        let frame = Frame {
            num,
            base: self.acked.num,
            echo_ack: self.echo.echo_ack(),
            diff: self.screen.diff_from(&self.acked.screen),
        };
        self.sent.push_back(FrameScreen {
            num,
            screen: Arc::clone(&self.screen),
        });
        while self.sent.len() > FRAME_WINDOW
            || (self.sent.len() > 1 && distinct_cells(&self.sent) > WINDOW_CELLS)
        {
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

    /// `frame`, just polled, encoded for its stream against its base, the acknowledged screen.
    fn encode(&mut self, frame: &Frame) -> Result<Vec<u8>, ProtoError> {
        let base = if frame.base == self.acked.num {
            Arc::clone(&self.acked.screen)
        } else {
            // Polled frames are always on the acknowledged one; a blank base otherwise.
            Arc::default()
        };
        self.encoder.encode(frame, &base)
    }

    /// The newest frame the client has acknowledged.
    const fn acked(&self) -> FrameNum {
        self.acked.num
    }

    /// Whether the program has application cursor keys on.
    fn app_cursor(&self) -> bool {
        self.screen.application_cursor()
    }

    /// Whether the connection is done: the program exited and the client acknowledged the final
    /// frame, or did not within [`FINAL_ACK_WAIT`].
    fn finished(&self, now: Instant) -> bool {
        self.final_frame.is_some_and(|(num, at)| {
            self.acked.num >= num || now.saturating_duration_since(at) >= FINAL_ACK_WAIT
        })
    }

    /// When the loop must wake at the latest, with nothing else happening (a delivery wakes it
    /// too).
    fn next_wake(&self, now: Instant, rtt: Option<Duration>) -> Instant {
        let mut wake = self
            .last_sent_at
            .map_or(now, |at| at.checked_add(HEARTBEAT).unwrap_or(now));
        let changed = self.unsent_change || self.echo.echo_ack() != self.last_sent_echo;
        if changed {
            // As `poll_frame` decides: an echo goes after its floor, anything else once the floor
            // passed with room in flight, else when a delivery makes room or a frame is given up.
            let floor = if self.unsent_change
                && self.carries_echo()
                && self.in_flight_frames(now, rtt) < MAX_IN_FLIGHT_ECHO
            {
                Some(ECHO_FLOOR)
            } else if self.room(now, rtt, MAX_IN_FLIGHT) {
                Some(FRAME_FLOOR)
            } else {
                None
            };
            match floor {
                Some(floor) => {
                    let after = self
                        .last_sent_at
                        .map_or(now, |at| at.checked_add(floor).unwrap_or(now));
                    wake = wake.min(after);
                }
                None => {
                    if let Some(given_up) = self
                        .in_flight
                        .iter()
                        .map(|(_, _, sent)| sent.checked_add(retry_after(rtt)).unwrap_or(now))
                        .find(|&at| at > now)
                    {
                        wake = wake.min(given_up);
                    }
                }
            }
        }
        if self.last_num > self.acked.num {
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

/// The cells the screens of `frames` hold in memory, a row several of them share counted once.
fn distinct_cells(frames: &VecDeque<FrameScreen>) -> usize {
    TerminalScreen::distinct_cells(frames.iter().map(|frame| &*frame.screen))
}

/// Drive one connection against its session: the I/O around a `ServerConn`.
///
/// It forwards the
/// client's input, sends each frame on its own stream and resets the streams of superseded ones.
/// Returning (or panicking) detaches.
pub async fn run_attached(
    conn: Link,
    mut session: session::SessionClient,
) -> anyhow::Result<SessionExit> {
    let mut core = ServerConn::default();
    core.install_snapshot(session.screen(), true);
    let mut client: Option<RecvStream> = None;
    // The client gets exactly one stream for the connection, even after it finishes that one.
    let mut had_client_stream = false;
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut in_flight: VecDeque<(FrameNum, CancellationToken)> = VecDeque::new();
    // Each frame's task says here when the client has all of it: its acknowledgement. Unbounded,
    // but at most one message a frame sent.
    let (delivered_tx, mut delivered_rx) = tokio::sync::mpsc::unbounded_channel::<FrameNum>();
    // History answers go one at a time; each one's task says here when it is delivered.
    let (history_tx, mut history_rx) = tokio::sync::mpsc::channel::<()>(1);
    let history_cancel = CancellationToken::new();
    let _history_guard = history_cancel.clone().drop_guard();
    let result = loop {
        if let Some(request) = core.next_history() {
            tokio::spawn(send_history(
                conn.clone(),
                session.history(request),
                history_tx.clone(),
                history_cancel.clone(),
            ));
        }
        let now = Instant::now();
        core.promote_echo(now);
        let rtt = conn.rtt();
        if let Some(frame) = core.poll_frame(now, rtt) {
            // Every older frame the client has not acknowledged is superseded.
            let acked = core.acked();
            for (num, cancel) in std::mem::take(&mut in_flight) {
                if num > acked {
                    cancel.cancel();
                }
            }
            match core.encode(&frame) {
                Ok(bytes) => {
                    core.frame_sent(frame.num, bytes.len(), now);
                    let cancel = CancellationToken::new();
                    tokio::spawn(send_frame(
                        conn.clone(),
                        frame.num,
                        bytes,
                        cancel.clone(),
                        delivered_tx.clone(),
                        rtt.unwrap_or(Duration::ZERO)
                            .saturating_add(crate::proto::ACK_DELAY),
                    ));
                    in_flight.push_back((frame.num, cancel));
                }
                Err(e) => tracing::error!(error = %e, "encoding a frame failed"),
            }
        }
        if core.finished(now) {
            conn.close(Close::SessionEnded);
            break Ok(SessionExit::ShellExited);
        }
        let wake = tokio::time::Instant::from_std(core.next_wake(now, rtt));
        let reading = client.is_some();
        tokio::select! {
            // Not biased: a pending screen change would starve client input.
            screen = session.next_screen() => match screen {
                Some(screen) => {
                    let alive = screen.exit_code().is_none();
                    core.install_snapshot(screen, alive);
                }
                // The server is shutting down.
                None => break Ok(SessionExit::Detached),
            },
            stream = conn.accept_uni() => match stream {
                Ok(stream) if !had_client_stream => {
                    had_client_stream = true;
                    client = Some(stream);
                }
                Ok(_) => {
                    conn.close(Close::SecondStream);
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
                            // A full input queue stops reading, so QUIC pushes back on the client.
                            for input in drained.input {
                                session.send_input(input).await;
                            }
                            if let Some(size) = drained.resize {
                                session.send_resize(size).await;
                            }
                            if !session.can_send() {
                                break Ok(SessionExit::Detached); // the session ended
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "client broke the protocol; closing");
                            conn.close(Close::ProtocolError);
                            break Ok(SessionExit::Detached);
                        }
                    }
                }
                Ok(None) => {
                    // The client finished its stream; a clean end only between messages.
                    if core.finish_client().is_err() {
                        conn.close(Close::ProtocolError);
                        break Ok(SessionExit::Detached);
                    }
                    client = None;
                }
                Err(e) => {
                    info!(reason = %e, "client stream failed (detaching)");
                    break Ok(SessionExit::Detached);
                }
            },
            Some(()) = history_rx.recv() => core.history_delivered(),
            Some(num) = delivered_rx.recv() => core.ack(num, Instant::now()),
            () = tokio::time::sleep_until(wake) => {}
        }
    };
    for (_, cancel) in in_flight {
        cancel.cancel();
    }
    result
}

/// Read from the client's stream, if there is one.
async fn read_client(
    stream: Option<&mut RecvStream>,
    buf: &mut [u8],
) -> Result<Option<usize>, iroh::endpoint::ReadError> {
    match stream {
        Some(stream) => stream.read(buf).await,
        None => std::future::pending().await,
    }
}

/// Send frame `num` on its own stream, and say on `delivered` once the client has all of it.
/// Cancelling (a newer frame superseded it) resets the stream, so QUIC stops retransmitting it: at
/// once if it is still being written, else after `grace`.
async fn send_frame(
    conn: Link,
    num: FrameNum,
    bytes: Vec<u8>,
    cancel: CancellationToken,
    delivered: tokio::sync::mpsc::UnboundedSender<FrameNum>,
    grace: Duration,
) {
    // A frame superseded before it starts is never opened.
    let mut send = tokio::select! {
        biased;
        () = cancel.cancelled() => return,
        stream = conn.open_uni() => match stream {
            Ok(stream) => stream,
            Err(_) => return,
        },
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
    // Written: wait until the client has it all. All of it delivered (`stopped` with no code) is
    // the client's acknowledgement: it applies every frame it gets on a base it holds, and keeps a
    // late one as a base. Superseded once written, it still has `grace` (a round trip and the
    // acknowledgement's delay) to be delivered, so that through a flood of frames each superseding
    // the last the server still learns which the client has; then it is reset, so QUIC stops
    // retransmitting it. Superseded while still being written, it is reset at once.
    if !cancelled {
        tokio::select! {
            stopped = send.stopped() => {
                if matches!(stopped, Ok(None)) {
                    let _ = delivered.send(num);
                }
                return;
            }
            () = cancel.cancelled() => {}
        }
        tokio::select! {
            stopped = send.stopped() => {
                if matches!(stopped, Ok(None)) {
                    let _ = delivered.send(num);
                }
                return;
            }
            () = tokio::time::sleep(grace) => {}
        }
    }
    let _ = send.reset(0u32.into());
}

/// Answer one history request: fetch the rows from the session, and send them on a stream of their
/// own, below frames in priority, so they never delay one. Says on `delivered` once the client has
/// them all, or they could not go.
async fn send_history(
    conn: Link,
    reply: impl std::future::Future<Output = Option<crate::terminal::HistoryReply>>,
    delivered: tokio::sync::mpsc::Sender<()>,
    cancel: CancellationToken,
) {
    let send = async {
        let reply = reply.await?;
        let bytes = encode_history(&reply)
            .map_err(|e| tracing::error!(error = %e, "encoding history rows failed"))
            .ok()?;
        let mut send = conn.open_uni().await.ok()?;
        let _ = send.set_priority(HISTORY_PRIORITY);
        send.write_all(&bytes).await.ok()?;
        send.finish().ok()?;
        let _ = send.stopped().await;
        Some(())
    };
    tokio::select! {
        _ = send => {}
        () = cancel.cancelled() => return,
    }
    let _ = delivered.send(()).await;
}

/// The priority of history streams: below frames' (0), so QUIC sends a frame's bytes first.
const HISTORY_PRIORITY: i32 = -1;

/// Admit `conn` and serve it one session of `command`, then tear it down: the server without its
/// accept loop, for tests.
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
        let _ = run_attached(admission::admit(conn).await?, client).await?;
    }
    registry.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::{
        distinct_cells, CursorKeyNormalizer, Drained, EchoAck, ServerConn, ToSession,
        FINAL_ACK_WAIT,
    };
    use crate::proto::{
        encode_client, retry_after, ClientMsg, Frame, FrameNum, InputSeq, FRAME_FLOOR,
        FRAME_WINDOW, HEARTBEAT, WINDOW_CELLS,
    };
    use crate::terminal::{Size, TerminalScreen};

    /// Feed `chunks` through one normalizer at the given app-cursor mode, return the PTY bytes.
    fn norm(chunks: &[&[u8]], app_cursor: bool) -> Vec<u8> {
        let mut n = CursorKeyNormalizer::default();
        let mut out = Vec::new();
        for c in chunks {
            n.normalize_into(c, app_cursor, &mut out);
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
            ClientMsg::Resize(Size::new(10, 20)),
            ClientMsg::Input {
                seq: InputSeq(2),
                bytes: b"\x1bOA".to_vec(),
            },
            ClientMsg::Resize(Size::new(30, 40)),
            ClientMsg::Resize(Size::new(65000, 1)),
            ClientMsg::Input {
                seq: InputSeq(3),
                bytes: b"ef".to_vec(),
            },
        ]));
        let drained = conn.drain_client(Instant::now(), false).unwrap();
        assert_eq!(
            drained,
            Drained {
                input: vec![ToSession::Bytes(b"ab\x1b[Aef".to_vec())],
                resize: Some(crate::terminal::clamp_dims(Size::new(65000, 1))),
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

    /// A server and a client connection on loopback, and the client's endpoint, kept alive.
    async fn loopback() -> (
        crate::transport_iroh::admission::Link,
        iroh::endpoint::Connection,
        iroh::Endpoint,
        iroh::Endpoint,
    ) {
        use crate::transport_iroh::{
            bind_endpoint_local, generate_secret_key, loopback_addr, ALPN,
        };
        let server = bind_endpoint_local(generate_secret_key().unwrap(), true)
            .await
            .unwrap();
        let client = bind_endpoint_local(generate_secret_key().unwrap(), false)
            .await
            .unwrap();
        let addr = loopback_addr(&server);
        let (accepted, connected) = tokio::join!(
            async { server.accept().await.unwrap().await.unwrap() },
            client.connect(addr, ALPN)
        );
        let admitted = crate::transport_iroh::admission::admit(accepted)
            .await
            .unwrap();
        (admitted, connected.unwrap(), server, client)
    }

    #[test]
    fn a_delivered_frame_is_acknowledged_and_one_superseded_unwritten_is_not() {
        use super::send_frame;
        use tokio_util::sync::CancellationToken;
        crate::test_runtime::current_thread().block_on(async {
            let (server, client, _s, _c) = loopback().await;
            let reader = tokio::spawn(async move {
                let mut recv = client.accept_uni().await.unwrap();
                recv.read_to_end(MAX_FRAME_TEST).await.unwrap();
                client
            });
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let grace = Duration::from_secs(5);
            let current = CancellationToken::new();
            tokio::spawn(send_frame(
                server.clone(),
                FrameNum(1),
                vec![1; 100],
                current,
                tx.clone(),
                grace,
            ));
            let wait = Duration::from_secs(10);
            assert_eq!(
                tokio::time::timeout(wait, rx.recv()).await.ok().flatten(),
                Some(FrameNum(1))
            );
            // Superseded before it was written: never sent, so never acknowledged.
            let superseded = CancellationToken::new();
            superseded.cancel();
            send_frame(
                server.clone(),
                FrameNum(2),
                vec![2; 100],
                superseded,
                tx,
                grace,
            )
            .await;
            assert_eq!(rx.recv().await, None);
            let _client = reader.await.unwrap();
        });
    }

    const MAX_FRAME_TEST: usize = 1024;

    #[test]
    fn history_requests_are_answered_one_at_a_time_and_too_many_waiting_is_an_error() {
        use crate::proto::{ProtoError, MAX_PENDING_HISTORY};
        use crate::terminal::HistoryRequest;
        let ask = |newest| ClientMsg::History(HistoryRequest { newest, count: 1 });
        let mut conn = ServerConn::default();
        conn.push_client_bytes(&stream(&[ask(1), ask(2)]));
        conn.drain_client(Instant::now(), false).unwrap();
        assert_eq!(conn.next_history().map(|r| r.newest), Some(1));
        assert_eq!(
            conn.next_history(),
            None,
            "the next waits for the last's delivery"
        );
        conn.history_delivered();
        assert_eq!(conn.next_history().map(|r| r.newest), Some(2));
        conn.history_delivered();
        assert_eq!(conn.next_history(), None);
        let flood: Vec<ClientMsg> = (0..=u64::try_from(MAX_PENDING_HISTORY).unwrap())
            .map(ask)
            .collect();
        conn.push_client_bytes(&stream(&flood));
        assert!(matches!(
            conn.drain_client(Instant::now(), false),
            Err(ProtoError::TooManyRequests)
        ));
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
        assert_eq!(
            conn.drain_client(Instant::now(), false).unwrap().input,
            vec![]
        );
        assert!(
            conn.finish_client().is_err(),
            "the stream ended inside a message"
        );
        conn.push_client_bytes(rest);
        assert_eq!(
            conn.drain_client(Instant::now(), false).unwrap().input,
            vec![ToSession::Bytes(b"hello".to_vec())]
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
        c.install_snapshot(Arc::new(screen(b"a")), true);
        assert!(
            c.poll_frame(t0, None).is_some(),
            "the changed screen is sent"
        );
        // Re-installing the same screen is not a change, so nothing new is due.
        c.install_snapshot(Arc::new(screen(b"a")), true);
        assert!(c.poll_frame(t0, None).is_none());
        // The exit screen marks the connection final.
        c.install_snapshot(Arc::new(screen(b"a")), false);
        let last = c.poll_frame(t0 + Duration::from_secs(1), None);
        assert!(last.is_some() || c.finished(t0 + Duration::from_secs(1) + FINAL_ACK_WAIT));
    }

    #[test]
    fn the_first_frame_goes_out_at_once_and_a_burst_waits_for_the_floor() {
        let t0 = Instant::now();
        let rtt = Some(Duration::from_millis(100));
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::new(screen(b"hello")), true);
        let first = c
            .poll_frame(t0, rtt)
            .expect("the first frame is due at once");
        assert_eq!((first.num, first.base), (FrameNum(1), FrameNum::BLANK));
        assert!(applied(&TerminalScreen::default(), &first)
            .screen()
            .contents()
            .contains("hello"));
        c.frame_sent(first.num, 100, t0);
        assert!(c.poll_frame(t0, rtt).is_none(), "nothing changed");
        c.install_snapshot(Arc::new(screen(b"hello world")), true);
        let inside = t0 + Duration::from_millis(1);
        assert!(c.poll_frame(inside, rtt).is_none(), "inside the floor");
        assert_eq!(c.next_wake(inside, rtt), t0 + FRAME_FLOOR);
        let second = c
            .poll_frame(t0 + FRAME_FLOOR, rtt)
            .expect("the floor passed, and the link has room");
        assert_eq!(second.num, FrameNum(2));
        assert_eq!(second.base, FrameNum::BLANK, "nothing was acknowledged yet");
    }

    /// A connection that has learnt the link: a round trip of 50 ms, and 10 kB taking 40 ms
    /// beyond it, a budget of 12.5 kB in flight. Frames go at `t[0]` and `t[1]` (50 ms on), and
    /// are delivered at `t[1]` and `t[2]` (140 ms on).
    fn on_a_slow_link(t: [Instant; 3]) -> Option<(ServerConn, Option<Duration>)> {
        let rtt = Some(Duration::from_millis(50));
        let mut c = ServerConn::default();
        let [start, second, done] = t;
        c.install_snapshot(Arc::new(screen(b"start")), true);
        let one = c.poll_frame(start, rtt)?;
        c.frame_sent(one.num, 100, start);
        c.ack(one.num, second);
        c.install_snapshot(Arc::new(screen(b"start, then more")), true);
        let two = c.poll_frame(second, rtt)?;
        c.frame_sent(two.num, 10_000, second);
        c.ack(two.num, done);
        (c.budget(rtt) == 12_500).then_some((c, rtt))
    }

    #[test]
    fn frames_in_flight_never_exceed_about_a_round_trip_of_the_link() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let (mut c, rtt) = on_a_slow_link([t0, t0 + ms(50), t0 + ms(140)]).unwrap();
        let t = t0 + Duration::from_millis(200);
        c.install_snapshot(Arc::new(screen(b"a big repaint")), true);
        let big = c.poll_frame(t, rtt).expect("room for it");
        c.frame_sent(big.num, 20_000, t);
        c.install_snapshot(Arc::new(screen(b"a big repaint, changed")), true);
        let later = t + Duration::from_millis(30);
        assert!(
            c.poll_frame(later, rtt).is_none(),
            "20 kB in flight, past the budget"
        );
        assert_eq!(
            c.next_wake(later, rtt),
            t + retry_after(rtt),
            "a delivery wakes the loop, or the frame is given up on"
        );
        c.ack(big.num, t + Duration::from_millis(100));
        assert!(c.poll_frame(t + Duration::from_millis(100), rtt).is_some());
    }

    #[test]
    fn with_nothing_it_may_send_the_connection_does_not_wake_at_once() {
        // Typed input awaits its echo, the echo-ack changed but not the screen, and the link is
        // full: nothing can go until a delivery, so the loop must not spin.
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let (mut c, rtt) = on_a_slow_link([t0, t0 + ms(50), t0 + ms(140)]).unwrap();
        let t = t0 + ms(200);
        c.install_snapshot(Arc::new(screen(b"$ ")), true);
        let full = c.poll_frame(t, rtt).unwrap();
        c.frame_sent(full.num, 20_000, t);
        c.push_client_bytes(&stream(&[ClientMsg::Input {
            seq: InputSeq(1),
            bytes: b"x".to_vec(),
        }]));
        c.drain_client(t, false).unwrap();
        // A second key, still awaiting its echo once the first is promoted.
        c.push_client_bytes(&stream(&[ClientMsg::Input {
            seq: InputSeq(2),
            bytes: b"y".to_vec(),
        }]));
        c.drain_client(t + ms(30), false).unwrap();
        let later = t + ms(60);
        c.promote_echo(later);
        assert!(
            c.poll_frame(later, rtt).is_none(),
            "no room, and no new screen to echo"
        );
        assert!(
            c.next_wake(later, rtt) > later,
            "the loop sleeps until something can go"
        );
    }

    #[test]
    fn frames_in_flight_never_outrun_the_window_of_frames_kept() {
        // Tiny frames, far under the byte budget, from a program changing the screen nonstop: past
        // half the window in flight, the next waits, so every delivery heard of is still a frame
        // the server holds.
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let (mut c, rtt) = on_a_slow_link([t0, t0 + ms(50), t0 + ms(140)]).unwrap();
        let mut at = t0 + ms(200);
        for n in 0..super::MAX_IN_FLIGHT {
            c.install_snapshot(Arc::new(screen(format!("count {n}").as_bytes())), true);
            let frame = c.poll_frame(at, rtt).expect("room for it");
            c.frame_sent(frame.num, 40, at);
            at += FRAME_FLOOR;
        }
        c.install_snapshot(Arc::new(screen(b"count more")), true);
        assert!(c.poll_frame(at, rtt).is_none(), "half the window in flight");
        assert!(
            c.next_wake(at, rtt) > at,
            "and the loop sleeps until a delivery"
        );
    }

    #[test]
    fn a_slow_link_skips_to_the_newest_screen() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let (mut c, rtt) = on_a_slow_link([t0, t0 + ms(50), t0 + ms(140)]).unwrap();
        let t = t0 + Duration::from_millis(200);
        c.install_snapshot(Arc::new(screen(b"frame 0")), true);
        let big = c.poll_frame(t, rtt).unwrap();
        c.frame_sent(big.num, 20_000, t);
        let mut at = t;
        for n in 1..=5 {
            at += Duration::from_millis(10);
            c.install_snapshot(Arc::new(screen(format!("frame {n}").as_bytes())), true);
            assert!(c.poll_frame(at, rtt).is_none(), "screen {n} waits");
        }
        c.ack(big.num, at);
        let next = c.poll_frame(at, rtt).expect("room again");
        assert_eq!(
            next.num,
            big.num.next(),
            "the screens between were never sent"
        );
        let shown = applied(&screen(b"frame 0"), &next);
        assert!(shown.screen().contents().contains("frame 5"));
    }

    #[test]
    fn the_echo_of_typing_goes_at_once_even_with_the_link_full() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let (mut c, rtt) = on_a_slow_link([t0, t0 + ms(50), t0 + ms(140)]).unwrap();
        let t = t0 + Duration::from_millis(200);
        c.install_snapshot(Arc::new(screen(b"$ ")), true);
        let full = c.poll_frame(t, rtt).unwrap();
        c.frame_sent(full.num, 20_000, t);
        // The user types; the program's echo changes one row.
        c.push_client_bytes(&stream(&[ClientMsg::Input {
            seq: InputSeq(1),
            bytes: b"l".to_vec(),
        }]));
        c.drain_client(t, false).unwrap();
        c.install_snapshot(Arc::new(screen(b"$ l")), true);
        let typed = t + Duration::from_millis(1);
        let echo = c.poll_frame(typed, rtt).expect("the echo goes at once");
        assert!(applied(&screen(b"$ "), &echo)
            .screen()
            .contents()
            .contains("$ l"));
        // A large change is not an echo, typed or not: it waits for room.
        c.frame_sent(echo.num, 100, typed);
        let lines: Vec<u8> = (0..20)
            .flat_map(|n| format!("line {n}\r\n").into_bytes())
            .collect();
        c.install_snapshot(Arc::new(screen(&lines)), true);
        assert!(c
            .poll_frame(typed + Duration::from_millis(2), rtt)
            .is_none());
    }

    #[test]
    fn a_quiet_connection_still_gets_a_heartbeat() {
        let t0 = Instant::now();
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::new(screen(b"idle")), true);
        c.poll_frame(t0, None).expect("first frame");
        // Acknowledged, so no retry is due; only the heartbeat is.
        c.ack(FrameNum(1), Instant::now());
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
        c.install_snapshot(Arc::new(screen(b"lost?")), true);
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
        c.ack(FrameNum(2), Instant::now());
        assert!(c.poll_frame(t0 + retry * 3, rtt).is_none());
    }

    #[test]
    fn frames_diff_against_the_newest_acknowledged_frame() {
        let t0 = Instant::now();
        let later = |n| t0 + Duration::from_secs(n);
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::new(screen(b"one")), true);
        let one = c.poll_frame(t0, None).unwrap();
        c.install_snapshot(Arc::new(screen(b"one two")), true);
        let two = c.poll_frame(later(1), None).unwrap();
        c.ack(FrameNum(1), Instant::now());
        c.install_snapshot(Arc::new(screen(b"one two three")), true);
        let three = c.poll_frame(later(2), None).unwrap();
        assert_eq!(three.base, FrameNum(1));
        let client_one = applied(&TerminalScreen::default(), &one);
        assert_eq!(applied(&client_one, &three), screen(b"one two three"));
        // An ack for a frame older than the acknowledged one changes nothing.
        c.ack(FrameNum(2), Instant::now());
        c.ack(FrameNum(1), Instant::now());
        c.install_snapshot(Arc::new(screen(b"four")), true);
        assert_eq!(c.poll_frame(later(3), None).unwrap().base, FrameNum(2));
        let _ = two;
    }

    #[test]
    fn a_resync_diffs_against_the_blank_screen_until_a_newer_ack() {
        let t0 = Instant::now();
        let later = |n| t0 + Duration::from_secs(n);
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::new(screen(b"a")), true);
        c.poll_frame(t0, None).unwrap();
        c.ack(FrameNum(1), Instant::now());
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
            c.install_snapshot(Arc::new(screen(format!("frame {n}").as_bytes())), true);
            c.poll_frame(t0 + Duration::from_secs(n), None).unwrap();
        }
        assert_eq!(c.sent.len(), FRAME_WINDOW);
        c.ack(FrameNum(1), Instant::now()); // dropped from the window
        assert_eq!(c.acked(), FrameNum::BLANK);
        c.ack(FrameNum(3), Instant::now());
        assert_eq!(c.acked(), FrameNum(3));
    }

    #[test]
    fn the_connection_finishes_once_the_final_frame_is_acked_or_after_a_second() {
        let t0 = Instant::now();
        let sent = t0 + Duration::from_secs(1);
        // A connection that has just sent the final frame (with the exit code) at `sent`.
        let exited = || {
            let mut c = ServerConn::default();
            c.install_snapshot(Arc::new(screen(b"$ ")), true);
            c.poll_frame(t0, None).unwrap();
            assert!(!c.finished(t0));
            let mut emu = crate::terminal::ServerTerminal::new(24, 80, 0).unwrap();
            emu.set_exit_code(3);
            c.install_snapshot(Arc::new(emu.snapshot()), false);
            let last = c.poll_frame(sent, None).expect("the final frame");
            assert!(!c.finished(sent));
            (c, last)
        };
        let (mut acked, last) = exited();
        acked.ack(last.num, Instant::now());
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

    /// A screen of the largest size a client may ask for, showing `text`.
    fn largest(text: &str) -> Arc<TerminalScreen> {
        let max = crate::terminal::MAX_DIM;
        Arc::new(TerminalScreen::from_bytes(max, max, text.as_bytes()))
    }

    #[test]
    fn frames_resent_to_a_client_that_never_acknowledges_share_their_screen() {
        // A client that acknowledges nothing is resent the unchanged screen at every heartbeat.
        // Each resend held its own copy: sixteen of a 1000x1000 screen were over 500 MB.
        let mut c = ServerConn::default();
        let big = largest("unchanged");
        c.install_snapshot(Arc::clone(&big), true);
        let t0 = Instant::now();
        for n in 0..=u64::try_from(FRAME_WINDOW).unwrap() {
            c.poll_frame(t0 + HEARTBEAT * u32::try_from(n).unwrap(), None)
                .expect("a heartbeat is due");
        }
        assert_eq!(
            c.sent.len(),
            FRAME_WINDOW,
            "the window still holds every resend"
        );
        assert!(c.sent.iter().all(|sent| Arc::ptr_eq(&sent.screen, &big)));
        assert_eq!(distinct_cells(&c.sent), WINDOW_CELLS);
    }

    #[test]
    fn frames_that_differ_by_a_row_share_the_rest() {
        // Each snapshot shares the rows the program left alone with the one before, so a window of
        // frames that each changed one row holds one screen and those rows, not sixteen screens.
        let mut c = ServerConn::default();
        let mut emu = crate::terminal::ServerTerminal::new(24, 80, 0).unwrap();
        let t0 = Instant::now();
        for n in 0..20_u32 {
            emu.process(format!("line {n}\r\n").as_bytes());
            c.install_snapshot(Arc::new(emu.snapshot()), true);
            c.poll_frame(t0 + HEARTBEAT * n, None)
                .expect("a frame is due");
        }
        assert_eq!(c.sent.len(), FRAME_WINDOW);
        let changed_rows = FRAME_WINDOW - 1;
        assert_eq!(distinct_cells(&c.sent), (24 + changed_rows) * 80);
    }

    #[test]
    fn frames_awaiting_acknowledgement_hold_at_most_one_largest_screen() {
        // Alternating screens (a client flipping between two sizes, say) are all distinct: without a
        // bound on cells, sixteen of the largest are held for a client that never acknowledges.
        let mut c = ServerConn::default();
        let t0 = Instant::now();
        for n in 0..20_u32 {
            c.install_snapshot(largest(&format!("screen {n}")), true);
            c.poll_frame(t0 + HEARTBEAT * n, None)
                .expect("a frame is due");
            assert!(distinct_cells(&c.sent) <= WINDOW_CELLS, "after frame {n}");
        }
        // Only the newest is left, and it still diffs against the base the client holds.
        assert_eq!(c.sent.len(), 1);
        assert_eq!(c.acked(), FrameNum::BLANK);
        let frame = c
            .poll_frame(t0 + HEARTBEAT * 20, None)
            .expect("a heartbeat is due");
        assert_eq!(frame.base, FrameNum::BLANK);
        // An acknowledgement of a dropped frame is ignored, as one past the window is.
        c.ack(FrameNum(3), Instant::now());
        assert_eq!(c.acked(), FrameNum::BLANK);
    }
}
