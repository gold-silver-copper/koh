//! The koh server.
//!
//! A session's PTY and emulator live in a [`session`] task that outlives its
//! connections; each connection runs [`run_attached`] with a fresh protocol core, so a client that
//! reconnects gets the current screen.

mod audit;
pub mod cli;
mod held;
pub mod session;

pub use cli::{serve, ServeConfig};
pub use session::{Registry, SessionSpec};

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::bounded::Bounded;
use crate::events::{InputEvent, WireColours};
use crate::log::Peer;
use crate::proto::{
    retry_after, ClientDecoder, ClientMsg, Close, Frame, FrameEncoder, FrameNum, FrameScreen,
    InputSeq, ProtoError, FRAME_FLOOR, FRAME_WINDOW, HEARTBEAT, MAX_PENDING_HISTORY,
};
use crate::terminal::{HistoryReply, HistoryRequest, Size, TerminalScreen};
use crate::transport_iroh::close;
use held::ClientHolds;
use iroh::endpoint::RecvStream;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// How long the program gets to show a keystroke before it counts as echoed.
const ECHO_TIMEOUT: Duration = Duration::from_millis(50);

/// Most inputs awaiting their echo: one message each, within [`ECHO_TIMEOUT`].
const ECHO_PENDING: usize = 256;

/// Most messages for the session waiting for room in its queue.
const TO_SESSION: usize = 64;

/// Most bytes of input waiting for room in the session's queue before the client's stream is left
/// unread: a message's worth, so a paste the program is slow to take holds up neither the control
/// messages behind it (acknowledgements, history requests) nor more than itself.
const HELD_INPUT: usize = crate::proto::MAX_CLIENT_MESSAGE;

/// How long the server waits for the client to acknowledge the final frame, at least.
const FINAL_ACK_WAIT: Duration = Duration::from_secs(1);

/// How long the client has to acknowledge the final frame: [`FINAL_ACK_WAIT`], or two retries on
/// a link slower than that, so a slow link is not taken for a lost one.
fn final_wait(rtt: Option<Duration>) -> Duration {
    FINAL_ACK_WAIT.max(retry_after(rtt).saturating_mul(2))
}

/// Which of one connection's inputs the program has had time to show. Per connection, as input
/// sequence numbers are.
#[derive(Debug, Default)]
pub(crate) struct EchoAck {
    /// The newest input considered reflected on screen.
    acked: InputSeq,
    /// Inputs not yet promoted, with when they arrived, oldest first.
    pending: Bounded<(InputSeq, Instant), ECHO_PENDING>,
}

impl EchoAck {
    /// Input `seq` arrived at `now`. Sequence numbers only advance; a stale one is ignored. Past
    /// [`ECHO_PENDING`] waiting, the newest waits in place of the one before it.
    pub(crate) fn register(&mut self, seq: InputSeq, now: Instant) {
        let newest = self.pending.back().map_or(self.acked, |(s, _)| *s);
        if seq <= newest {
            return;
        }
        if let Err(input) = self.pending.push_back((seq, now)) {
            if let Some(last) = self.pending.back_mut() {
                last.0 = input.0;
            }
        }
    }

    /// Promote the inputs that arrived at least the debounce before `now`; whether the echo-ack moved.
    pub(crate) fn promote(&mut self, now: Instant) -> bool {
        let before = self.acked;
        while let Some(&(seq, arrived)) = self.pending.front() {
            if now.saturating_duration_since(arrived) < ECHO_TIMEOUT {
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
        arrived.checked_add(ECHO_TIMEOUT)
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

/// What a connection hands its session, in the order the client sent it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ToSession {
    /// Decoded input ([`ClientMsg::Keys`]), which the session encodes as its program asked.
    Events(Vec<InputEvent>),
    /// What the user's terminal said of its colours.
    Colours(WireColours),
    /// The client's window, clamped.
    Resize(Size),
}

impl ToSession {
    /// The bytes of input it holds.
    fn bytes(&self) -> usize {
        match self {
            Self::Events(events) => events.iter().map(InputEvent::encoded_len).sum(),
            Self::Colours(_) | Self::Resize(_) => 0,
        }
    }
}

/// The server side of one connection, without I/O: it decodes the client's stream, tracks the
/// echo-ack, and decides when to send which frame against which base.
#[derive(Default)]
pub(crate) struct ServerConn {
    decoder: ClientDecoder,
    /// The client finished its stream: what it left must decode whole.
    client_ended: bool,
    echo: EchoAck,
    /// What the client sent for the session, oldest first, until the session has room. Nothing
    /// more is decoded once it is full, nor read while it holds [`HELD_INPUT`].
    to_session: Bounded<ToSession, TO_SESSION>,
    /// The bytes of input in `to_session`.
    held_input: usize,
    /// The session's newest screen, shared with every frame that shows it.
    screen: Arc<TerminalScreen>,
    /// `screen` is what was last sent, and the base needs no rebuilding.
    screen_sent: bool,
    /// The frames the client is taken to hold, by their delivery.
    held: ClientHolds,
    last_num: FrameNum,
    last_sent_at: Option<Instant>,
    last_sent_echo: InputSeq,
    /// The first frame sent after the program exited, and when.
    final_frame: Option<(FrameNum, Instant)>,
    /// History requests not yet answered, oldest first.
    history: Bounded<HistoryRequest, MAX_PENDING_HISTORY>,
    /// An answer is on its way to the client; the next waits for it to be delivered.
    history_busy: bool,
    /// Encodes frames, primed for the base they are diffed against.
    encoder: FrameEncoder,
    /// Frames sent and not yet delivered nor given up on, oldest first: each one's number, size and
    /// when it went.
    in_flight: Bounded<(FrameNum, usize, Instant), FRAME_WINDOW>,
    /// What recent deliveries prove of the link's rate, newest last.
    rates: Bounded<Rate, DELIVERY_SAMPLES>,
    /// When the client last acknowledged any of the connection's packets.
    heard: Option<Instant>,
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

/// A rate the link is proven to carry, in bytes a second: only a delivery makes one, and a frame
/// of `b` bytes delivered `t` after it was sent took at least `b / rate` to cross the link, so
/// `b / t` is never more than the link carries, whatever the round trip, the queue or the delay
/// of the acknowledgement added to `t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Rate(u64);

impl Rate {
    /// What delivering `bytes` in `took` proves; `None` for an empty frame or no time.
    fn proven(bytes: usize, took: Duration) -> Option<Self> {
        let per_sec = u128::try_from(bytes)
            .ok()?
            .saturating_mul(1_000_000_000)
            .checked_div(took.as_nanos())?;
        u64::try_from(per_sec).ok().filter(|&r| r > 0).map(Self)
    }

    /// The bytes it carries in `span`.
    fn carried(self, span: Duration) -> usize {
        let bytes = u128::from(self.0)
            .saturating_mul(span.as_nanos())
            .checked_div(1_000_000_000)
            .unwrap_or(0);
        usize::try_from(bytes).unwrap_or(usize::MAX)
    }
}

impl ServerConn {
    /// Install the session's latest screen. One that carries the program's exit code is final.
    fn install_snapshot(&mut self, screen: Arc<TerminalScreen>) {
        if screen != self.held.newest().screen {
            self.screen_sent = false;
        }
        self.screen = screen;
    }

    /// The hosted program exited: the installed screen carries its exit code, and the frame that
    /// sends it is final. Every finality check reads this.
    fn exited(&self) -> bool {
        self.screen.exit_code().is_some()
    }

    /// Bytes read from the client's stream, at `now`: what they complete is decoded.
    fn push_client_bytes(&mut self, bytes: &[u8], now: Instant) -> Result<(), ProtoError> {
        self.decoder.push(bytes);
        self.decode(now)
    }

    /// The client finished its stream: fine between messages, a protocol error inside one, once
    /// the messages before it are decoded.
    fn client_ended(&mut self, now: Instant) -> Result<(), ProtoError> {
        self.client_ended = true;
        self.decode(now)
    }

    /// The oldest input for the session, which has room for it, decoding on behind it.
    fn poll_input(&mut self, now: Instant) -> Result<Option<ToSession>, ProtoError> {
        let input = self.to_session.pop_front();
        self.held_input = self
            .held_input
            .saturating_sub(input.as_ref().map_or(0, ToSession::bytes));
        self.decode(now)?;
        Ok(input)
    }

    /// Whether to read more of the client's stream: while the input waiting for the session is
    /// under [`HELD_INPUT`] and its queue has room.
    fn wants_bytes(&self) -> bool {
        self.held_input < HELD_INPUT && !self.to_session.is_full()
    }

    /// Decode the complete messages read, at `now`, while the session's queue has room: control
    /// messages handled at once, input queued for the session (none once the program exited).
    fn decode(&mut self, now: Instant) -> Result<(), ProtoError> {
        while !self.to_session.is_full() {
            let Some(msg) = self.decoder.next_msg()? else {
                return if self.client_ended {
                    self.decoder.finish()
                } else {
                    Ok(())
                };
            };
            let input = match msg {
                ClientMsg::Keys { seq, events } => {
                    self.echo.register(seq, now);
                    ToSession::Events(events)
                }
                ClientMsg::Colours(colours) => ToSession::Colours(colours),
                ClientMsg::Resize(size) => ToSession::Resize(crate::terminal::clamp_dims(size)),
                ClientMsg::Ack { frame } => {
                    self.ack(frame, now);
                    continue;
                }
                ClientMsg::Resync => {
                    self.resync();
                    continue;
                }
                ClientMsg::History(request) => {
                    self.history
                        .push_back(request)
                        .map_err(|_full| ProtoError::TooManyRequests)?;
                    continue;
                }
            };
            if !self.exited() {
                self.for_session(input);
            }
        }
        Ok(())
    }

    /// Queue `input` for the session, merged into the last if both are events, or resizes, of
    /// which only the last matters. The caller made room.
    fn for_session(&mut self, input: ToSession) {
        self.held_input = self.held_input.saturating_add(input.bytes());
        match (self.to_session.back_mut(), input) {
            (Some(ToSession::Events(queued)), ToSession::Events(events)) => queued.extend(events),
            (Some(ToSession::Resize(queued)), ToSession::Resize(size)) => *queued = size,
            (_, input) => {
                let _ = self.to_session.push_back(input);
            }
        }
    }

    /// The next history request to answer, if no answer is on its way; the caller calls
    /// clears `history_busy` once its answer is delivered.
    fn next_history(&mut self) -> Option<HistoryRequest> {
        if self.history_busy {
            return None;
        }
        let request = self.history.pop_front()?;
        self.history_busy = true;
        Some(request)
    }

    /// `reply` encoded for its stream, by the frames' compressor; if it cannot be, the answer
    /// with no rows to `request`, so the client is answered whatever happens.
    fn encode_history(&mut self, request: HistoryRequest, reply: &HistoryReply) -> Option<Vec<u8>> {
        self.encoder
            .encode_history(reply)
            .or_else(|e| {
                tracing::error!(error = %e, "encoding history rows failed");
                self.encoder.encode_history(&request.none())
            })
            .ok()
    }

    /// The client has frame `num`, so older frames are no bases any more. An ack for a frame no
    /// longer held is ignored.
    fn ack(&mut self, num: FrameNum, now: Instant) {
        // No longer in flight, nor are the frames before it, which it superseded, and how long it
        // took proves a rate of the link.
        if let Some(&(_, bytes, sent)) = self.in_flight.iter().find(|(n, _, _)| *n == num) {
            if let Some(rate) = Rate::proven(bytes, now.saturating_duration_since(sent)) {
                self.rates.push_evicting(rate);
            }
        }
        self.in_flight.retain(|(n, _, _)| *n > num);
        self.held.delivered(num);
    }

    /// Frame `num`, of `bytes` on its stream, went at `now`. Frames given up on, which a client
    /// that never takes them leaves undelivered for good, are forgotten, as are those past the
    /// window of frames kept.
    fn frame_sent(&mut self, num: FrameNum, bytes: usize, now: Instant, rtt: Option<Duration>) {
        let heard = self.heard;
        self.in_flight
            .retain(|&(_, _, sent)| given_up(sent, heard, rtt) > now);
        self.in_flight.push_evicting((num, bytes, now));
    }

    /// The frames, and their bytes, in flight at `now`: sent, not delivered, and not given up on.
    fn in_flight(&self, now: Instant, rtt: Option<Duration>) -> (usize, usize) {
        self.in_flight
            .iter()
            .filter(|&&(_, _, sent)| given_up(sent, self.heard, rtt) > now)
            .fold((0, 0), |(frames, total), &(_, bytes, _)| {
                (frames.saturating_add(1), total.saturating_add(bytes))
            })
    }

    /// Whether the link has room for a frame at `now`: the bytes in flight under the budget (or
    /// none), and fewer frames in flight than `most`.
    fn room(&self, now: Instant, rtt: Option<Duration>, most: usize) -> bool {
        let (frames, bytes) = self.in_flight(now, rtt);
        (bytes == 0 || bytes < self.budget(rtt)) && frames < most
    }

    /// The link's rate, the most a recent delivery proves.
    fn rate(&self) -> Option<Rate> {
        self.rates.iter().max().copied()
    }

    /// The frame bytes the link may have in flight: about a round trip's worth.
    fn budget(&self, rtt: Option<Duration>) -> usize {
        rtt.zip(self.rate())
            .map_or(INITIAL_BUDGET, |(rtt, rate)| rate.carried(rtt))
    }

    /// Whether an unsent change likely carries the echo of the user's input, with few enough
    /// frames in flight that it goes at once.
    fn echo_due(&self, now: Instant, rtt: Option<Duration>) -> bool {
        !self.screen_sent && self.carries_echo() && self.in_flight(now, rtt).0 < MAX_IN_FLIGHT_ECHO
    }

    /// Whether the screen's change is small and the user typed in the last echo debounce: a frame
    /// that likely carries the program's echo, which goes at once.
    fn carries_echo(&self) -> bool {
        self.echo.has_pending()
            && self
                .screen
                .rows_differing(&self.held.base().screen)
                .is_some_and(|rows| rows <= ECHO_ROWS)
    }

    /// The client lacks a frame's base: it is taken to hold nothing, and the next frame is on the
    /// blank screen.
    fn resync(&mut self) {
        self.held.forget();
        self.screen_sent = false;
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
        let changed = self.changed();
        let since = self
            .last_sent_at
            .map(|at| now.saturating_duration_since(at));
        let passed = |floor: Duration| since.is_none_or(|since| since >= floor);
        let room = self.room(now, rtt, MAX_IN_FLIGHT);
        let retry_due = self.retry_at(rtt).is_some_and(|at| now >= at);
        let echo = passed(ECHO_FLOOR) && self.echo_due(now, rtt);
        let due =
            (changed && passed(FRAME_FLOOR) && room) || echo || retry_due || passed(HEARTBEAT);
        if !due {
            return None;
        }
        let num = self.last_num.next();
        let base = self.held.base();
        let (diff, sent) = self.screen.diff_and_sent(&base.screen);
        let frame = Frame {
            num,
            base: base.num,
            echo_ack: self.echo.echo_ack(),
            diff,
        };
        // What the client will hold, which later frames diff against: the screen, unless the
        // frame left some of its links for a later one.
        let sent = sent.map_or_else(|| Arc::clone(&self.screen), Arc::new);
        self.screen_sent = sent == self.screen;
        self.held.sent(FrameScreen { num, screen: sent });
        self.last_num = num;
        self.last_sent_at = Some(now);
        self.last_sent_echo = frame.echo_ack;
        if self.exited() && self.final_frame.is_none() {
            self.final_frame = Some((num, now));
        }
        Some(frame)
    }

    /// The frame due at `now`, if any, encoded for its stream against its base, and taken as sent.
    /// [`Self::poll_frame`] diffs it against the acknowledged screen and changes only the frames
    /// sent since, so that is still its base here.
    fn next_frame(
        &mut self,
        now: Instant,
        rtt: Option<Duration>,
    ) -> Option<(FrameNum, Result<Vec<u8>, ProtoError>)> {
        let frame = self.poll_frame(now, rtt)?;
        let bytes = self.encoder.encode(&frame, &self.held.base().screen);
        if let Ok(bytes) = &bytes {
            self.frame_sent(frame.num, bytes.len(), now, rtt);
        }
        Some((frame.num, bytes))
    }

    /// Whether the screen or the echo-ack changed since the last frame, or the base must be
    /// rebuilt.
    fn changed(&self) -> bool {
        !self.screen_sent || self.echo.echo_ack() != self.last_sent_echo
    }

    /// When the newest frame, unacknowledged, is resent as a new one: once it is given up on.
    fn retry_at(&self, rtt: Option<Duration>) -> Option<Instant> {
        let sent = self
            .last_sent_at
            .filter(|_| self.last_num > self.held.base().num)?;
        Some(given_up(sent, self.heard, rtt))
    }

    /// Whether the connection is done: the program exited and the client acknowledged the final
    /// frame, or did not within [`final_wait`].
    fn finished(&self, now: Instant, rtt: Option<Duration>) -> bool {
        self.final_acked()
            || self
                .final_frame
                .is_some_and(|(_, at)| now.saturating_duration_since(at) >= final_wait(rtt))
    }

    /// Whether the client acknowledged the final frame: it has the program's end, so its session
    /// may end too.
    fn final_acked(&self) -> bool {
        self.final_frame
            .is_some_and(|(num, _)| self.held.base().num >= num)
    }

    /// When the loop must wake at the latest, with nothing else happening (a delivery wakes it
    /// too).
    fn next_wake(&self, now: Instant, rtt: Option<Duration>) -> Instant {
        let after = |gap| {
            self.last_sent_at
                .map_or(now, |at| at.checked_add(gap).unwrap_or(now))
        };
        // As `poll_frame` decides: an echo goes after its floor, anything else once the floor
        // passed with room in flight, else when a delivery makes room or a frame is given up.
        let frame = if !self.changed() {
            None
        } else if self.echo_due(now, rtt) {
            Some(after(ECHO_FLOOR))
        } else if self.room(now, rtt, MAX_IN_FLIGHT) {
            Some(after(FRAME_FLOOR))
        } else {
            (self.in_flight.iter())
                .map(|&(_, _, sent)| given_up(sent, self.heard, rtt))
                .find(|&at| at > now)
        };
        let ends = self
            .final_frame
            .map(|(_, at)| at.checked_add(final_wait(rtt)).unwrap_or(now));
        [frame, self.retry_at(rtt), self.echo.next_promotion(), ends]
            .into_iter()
            .flatten()
            .fold(after(HEARTBEAT), Instant::min)
            .max(now)
    }
}

/// When a frame sent at `sent` is given up on (lost, or reset), its newest screen then resent: once
/// the client has acknowledged nothing for a retry interval since, `heard` being when it last did.
/// A frame that takes the link longer than that to send is acknowledged packet by packet as it
/// lands, so it is not taken for a lost one; a link gone quiet has lost the tail, which QUIC would
/// only probe for after its backed-off timeout.
fn given_up(sent: Instant, heard: Option<Instant>, rtt: Option<Duration>) -> Instant {
    let since = heard.map_or(sent, |heard| heard.max(sent));
    since.checked_add(retry_after(rtt)).unwrap_or(since)
}

/// Drive one connection against its session: the I/O around a `ServerConn`, which nothing here
/// waits on but in its `select!`.
///
/// It forwards the client's input as the session takes it, sends each frame on its own stream and
/// resets the streams of superseded ones, and answers history requests. Returning (or panicking)
/// detaches.
pub async fn run_attached(authorized: cli::Authorized, mut session: session::SessionClient) {
    let conn = authorized.conn();
    let mut core = ServerConn::default();
    core.install_snapshot(session.screen());
    let input = session.input.clone();
    let mut client: Option<RecvStream> = None;
    // The client gets exactly one stream for the connection, even after it finishes that one.
    let mut had_client_stream = false;
    // Whether the session still publishes screens: `next_screen` ends with it.
    let mut session_open = true;
    let mut read_buf = vec![0u8; 16 * 1024];
    // Cancels the newest frame, which the next supersedes.
    let mut newest = CancellationToken::new();
    // The client's acknowledgements counted so far: a new one is the link making progress.
    let mut last_acks = 0;
    // Each frame's task says here when the client has all of it: its acknowledgement. Bounded by
    // the frames in flight, each of which says so once.
    let (delivered_tx, mut delivered_rx) = tokio::sync::mpsc::channel::<FrameNum>(FRAME_WINDOW);
    // History answers go one at a time: the request the session is answering, then the answer's
    // task, which says here when it is delivered.
    let mut answering: Option<(HistoryRequest, tokio::sync::oneshot::Receiver<HistoryReply>)> =
        None;
    let (history_tx, mut history_rx) = tokio::sync::mpsc::channel::<()>(1);
    let history_cancel = CancellationToken::new();
    let _history_guard = history_cancel.clone().drop_guard();
    let how = loop {
        if answering.is_none() {
            answering = core
                .next_history()
                .map(|request| (request, session.history(request)));
        }
        let now = Instant::now();
        core.echo.promote(now);
        let rtt = crate::transport_iroh::rtt(conn);
        let acks = {
            let rx = conn.stats().frame_rx;
            rx.acks.saturating_add(rx.path_acks)
        };
        if acks != last_acks {
            last_acks = acks;
            core.heard = Some(now);
        }
        if let Some((num, bytes)) = core.next_frame(now, rtt) {
            // The frame before is superseded (a delivered one is past cancelling).
            newest.cancel();
            newest = CancellationToken::new();
            match bytes {
                Ok(bytes) => {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "a frame's task ends once it is delivered, or superseded and \
                                  reset after a round trip"
                    )]
                    tokio::spawn(send_frame(
                        conn.clone(),
                        num,
                        bytes,
                        newest.clone(),
                        delivered_tx.clone(),
                        rtt.unwrap_or(Duration::ZERO)
                            .saturating_add(crate::proto::ACK_DELAY),
                    ));
                }
                Err(e) => tracing::error!(error = %e, "encoding a frame failed"),
            }
        }
        if core.finished(now, rtt) {
            if !core.final_acked() {
                // The client may not have the end: the session keeps it, and this close, as a lost
                // link, has the client redial for it.
                conn.close(0u32.into(), b"");
                break "the final frame went unacknowledged (session kept)";
            }
            // The client has the program's end: the session need keep it no longer.
            session.ended().await;
            // Delivered is not yet read: a client closes once it has read the final frame, and a
            // close of ours before then would throw away what it had not read.
            let _ = tokio::time::timeout(FINAL_ACK_WAIT, conn.closed()).await;
            close(conn, Close::SessionEnded);
            break "shell exited";
        }
        let wake = tokio::time::Instant::from_std(core.next_wake(now, rtt));
        let reading = client.is_some() && core.wants_bytes();
        let broke = tokio::select! {
            // Not biased: a pending screen change would starve client input.
            screen = session.next_screen(), if session_open => match screen {
                Some(screen) => {
                    core.install_snapshot(screen);
                    Ok(())
                }
                // A session that ends after its exit screen does not cut off the final frame.
                None if core.exited() => {
                    session_open = false;
                    Ok(())
                }
                // The session was ended: revoked, or the server is shutting down.
                None => break "the session was ended (revoked, or the server is stopping)",
            },
            permit = input.reserve(), if !core.to_session.is_empty() => match permit {
                Ok(permit) => core.poll_input(Instant::now()).map(|taken| {
                    if let Some(taken) = taken {
                        permit.send(session::Input {
                            attach: session.attach,
                            input: taken,
                        });
                    }
                }),
                Err(_) => break "the session was ended (revoked, or the server is stopping)",
            },
            stream = conn.accept_uni() => match stream {
                Ok(stream) if !had_client_stream => {
                    had_client_stream = true;
                    client = Some(stream);
                    Ok(())
                }
                Ok(_) => Err(ProtoError::UnknownStream),
                Err(e) => {
                    info!(reason = %Peer(e), "connection closed by peer (detaching)");
                    break "client detached (session retained)";
                }
            },
            read = read_client(client.as_mut(), &mut read_buf), if reading => match read {
                Ok(Some(n)) => core.push_client_bytes(read_buf.get(..n).unwrap_or_default(), Instant::now()),
                Ok(None) => {
                    client = None;
                    core.client_ended(Instant::now())
                }
                Err(e) => {
                    info!(reason = %Peer(e), "client stream failed (detaching)");
                    break "client detached (session retained)";
                }
            },
            answer = async {
                match answering.as_mut() {
                    Some((_, rx)) => rx.await,
                    None => std::future::pending().await,
                }
            }, if answering.is_some() => {
                if let Some((request, _)) = answering.take() {
                    // The session's answer, or none: the client is answered whatever happens.
                    let reply = answer.unwrap_or_else(|_gone| request.none());
                    match core.encode_history(request, &reply) {
                        Some(bytes) => {
                            #[expect(clippy::disallowed_methods, reason = "one history answer at a time")]
                            tokio::spawn(send_history(conn.clone(), bytes, history_tx.clone(), history_cancel.clone()));
                        }
                        None => core.history_busy = false,
                    }
                }
                Ok(())
            },
            Some(()) = history_rx.recv() => {
                core.history_busy = false;
                Ok(())
            }
            Some(num) = delivered_rx.recv() => {
                core.ack(num, Instant::now());
                Ok(())
            }
            () = tokio::time::sleep_until(wake) => Ok(()),
        };
        if let Err(e) = broke {
            tracing::warn!(error = %e, "client broke the protocol; closing");
            close(conn, Close::ProtocolError);
            break "client detached (session retained)";
        }
    };
    newest.cancel();
    info!(peer = %conn.remote_id(), "{how}");
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
    conn: iroh::endpoint::Connection,
    num: FrameNum,
    bytes: Vec<u8>,
    cancel: CancellationToken,
    delivered: tokio::sync::mpsc::Sender<FrameNum>,
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
        let superseded = async {
            cancel.cancelled().await;
            tokio::time::sleep(grace).await;
        };
        tokio::select! {
            stopped = send.stopped() => {
                if matches!(stopped, Ok(None)) {
                    let _ = delivered.send(num).await;
                }
                return;
            }
            () = superseded => {}
        }
    }
    let _ = send.reset(0u32.into());
}

/// Send one history answer, `bytes`, on a stream of its own, below frames in priority, so it never
/// delays one. Says on `delivered` once the client has it all, or it could not go.
async fn send_history(
    conn: iroh::endpoint::Connection,
    bytes: Vec<u8>,
    delivered: tokio::sync::mpsc::Sender<()>,
    cancel: CancellationToken,
) {
    let send = async {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::{held::distinct_cells, EchoAck, ServerConn, ToSession, FINAL_ACK_WAIT};
    use crate::events::InputEvent;
    use crate::proto::{
        encode_client, retry_after, ClientMsg, Frame, FrameNum, InputSeq, FRAME_FLOOR,
        FRAME_WINDOW, HEARTBEAT, WINDOW_CELLS,
    };
    use crate::terminal::{Size, TerminalScreen};

    /// The client typed `text`, as input `seq`.
    fn typed(seq: u64, text: &str) -> ClientMsg {
        ClientMsg::Keys {
            seq: InputSeq(seq),
            events: text.chars().map(key).collect(),
        }
    }

    fn key(c: char) -> InputEvent {
        InputEvent::Key(
            fux_vt::keys::Keystroke::from(fux_vt::keys::KeyPress::plain(fux_vt::keys::Key::Char(
                c,
            )))
            .into(),
        )
    }

    fn stream(msgs: &[ClientMsg]) -> Vec<u8> {
        msgs.iter()
            .flat_map(|m| encode_client(m).unwrap())
            .collect()
    }

    #[test]
    fn a_read_queues_the_session_input_in_order_merging_neighbours() {
        // Neighbouring keys go as one batch, and of neighbouring resizes only the last, clamped.
        let now = Instant::now();
        let mut conn = ServerConn::default();
        let read = stream(&[
            typed(1, "ab"),
            ClientMsg::Resize(Size::new(10, 20)),
            typed(2, "c"),
            typed(3, "d"),
            ClientMsg::Resize(Size::new(30, 40)),
            ClientMsg::Resize(Size::new(65000, 1)),
        ]);
        conn.push_client_bytes(&read, now).unwrap();
        let queued: Vec<ToSession> = std::iter::from_fn(|| conn.poll_input(now).unwrap()).collect();
        assert_eq!(
            queued,
            [
                ToSession::Events(vec![key('a'), key('b')]),
                ToSession::Resize(Size::new(10, 20)),
                ToSession::Events(vec![key('c'), key('d')]),
                ToSession::Resize(crate::terminal::clamp_dims(Size::new(65000, 1))),
            ]
        );
        assert!(conn.to_session.is_empty());
    }

    #[test]
    fn a_paste_the_session_has_not_taken_holds_up_no_control_message_behind_it() {
        // The program is slow to take a paste: the client's stream is still read, and the history
        // request behind the paste answered, until a message's worth of input waits.
        let now = Instant::now();
        let mut conn = ServerConn::default();
        let paste = ClientMsg::Keys {
            seq: InputSeq(1),
            events: vec![InputEvent::Paste("p".repeat(crate::events::MAX_PASTE))],
        };
        conn.push_client_bytes(&stream(std::slice::from_ref(&paste)), now)
            .unwrap();
        assert!(conn.wants_bytes());
        let ask = crate::terminal::HistoryRequest {
            id: 1,
            newest: 1,
            count: 1,
        };
        conn.push_client_bytes(&stream(&[ClientMsg::History(ask)]), now)
            .unwrap();
        assert_eq!(conn.next_history(), Some(ask));
        conn.push_client_bytes(&stream(&[paste]), now).unwrap();
        assert!(!conn.wants_bytes(), "two pastes wait: read no more");
        conn.poll_input(now).unwrap();
        assert!(conn.wants_bytes(), "taken: read on");
    }

    #[test]
    fn input_left_undecoded_is_decoded_as_the_session_takes_it_even_after_the_stream_ends() {
        // More than the session's queue holds: the rest waits undecoded, so a client cannot grow
        // it, and goes on as the session takes input, with no bytes more from the client. A clean
        // end with messages left is no error.
        let now = Instant::now();
        let mut conn = ServerConn::default();
        let colours = ClientMsg::Colours(crate::events::WireColours::default());
        conn.push_client_bytes(&stream(&vec![colours; super::TO_SESSION + 1]), now)
            .unwrap();
        assert!(!conn.to_session.is_empty());
        conn.client_ended(now).unwrap();
        let taken = std::iter::from_fn(|| conn.poll_input(now).unwrap()).count();
        assert_eq!(taken, super::TO_SESSION + 1);
    }

    /// A server and a client connection on loopback, and the client's endpoint, kept alive.
    async fn loopback() -> (
        iroh::endpoint::Connection,
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
        (accepted, connected.unwrap(), server, client)
    }

    #[test]
    fn a_delivered_frame_is_acknowledged_and_one_superseded_unwritten_is_not() {
        use super::send_frame;
        use tokio_util::sync::CancellationToken;
        crate::test_runtime::current_thread().block_on(async {
            let (server, client, _s, _c) = loopback().await;
            let reader = koh_testkit::spawn(async move {
                let mut recv = client.accept_uni().await.unwrap();
                recv.read_to_end(MAX_FRAME_TEST).await.unwrap();
                client
            });
            let (tx, mut rx) = tokio::sync::mpsc::channel(4);
            let grace = Duration::from_secs(5);
            let current = CancellationToken::new();
            koh_testkit::spawn(send_frame(
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
        let ask = |newest| {
            ClientMsg::History(HistoryRequest {
                id: newest,
                newest,
                count: 1,
            })
        };
        let mut conn = ServerConn::default();
        conn.push_client_bytes(&stream(&[ask(1), ask(2)]), Instant::now())
            .unwrap();
        assert_eq!(conn.next_history().map(|r| r.newest), Some(1));
        assert_eq!(
            conn.next_history(),
            None,
            "the next waits for the last's delivery"
        );
        conn.history_busy = false;
        assert_eq!(conn.next_history().map(|r| r.newest), Some(2));
        conn.history_busy = false;
        assert_eq!(conn.next_history(), None);
        let flood: Vec<ClientMsg> = (0..=u64::try_from(MAX_PENDING_HISTORY).unwrap())
            .map(ask)
            .collect();
        assert!(matches!(
            conn.push_client_bytes(&stream(&flood), Instant::now()),
            Err(ProtoError::TooManyRequests)
        ));
    }

    #[test]
    fn a_partial_message_waits_and_a_truncated_stream_is_an_error() {
        let now = Instant::now();
        let bytes = stream(&[typed(1, "hello")]);
        let (first, rest) = bytes.split_at(3);
        let mut truncated = ServerConn::default();
        truncated.push_client_bytes(first, now).unwrap();
        assert!(truncated.to_session.is_empty());
        assert!(
            truncated.client_ended(now).is_err(),
            "the stream ended inside a message"
        );
        let mut whole = ServerConn::default();
        whole.push_client_bytes(first, now).unwrap();
        whole.push_client_bytes(rest, now).unwrap();
        whole.client_ended(now).unwrap();
        assert_eq!(
            whole.poll_input(now).unwrap(),
            Some(ToSession::Events("hello".chars().map(key).collect()))
        );
    }

    // --- EchoAck: the per-connection echo-ack debounce.

    #[test]
    fn echo_ack_debounces_is_monotonic_takes_the_newest_and_says_when_it_next_moves() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut t = EchoAck::default();
        assert_eq!(t.next_promotion(), None, "nothing pending");
        t.register(InputSeq(3), t0);
        t.register(InputSeq(7), ms(20));
        t.register(InputSeq(6), ms(25)); // stale: ignored
        assert_eq!(t.next_promotion(), Some(ms(50)));
        assert!(!t.promote(ms(49)), "inside the 50 ms debounce");
        assert_eq!(t.echo_ack(), InputSeq(0));
        assert!(t.promote(ms(55)));
        assert_eq!(t.echo_ack(), InputSeq(3));
        assert_eq!(t.next_promotion(), Some(ms(70)));
        t.promote(ms(100));
        assert_eq!(t.echo_ack(), InputSeq(7));
        assert_eq!(t.next_promotion(), None);
    }

    // --- ServerConn: frame pacing, bases, acknowledgements and shutdown, with no I/O.

    fn screen(bytes: &[u8]) -> TerminalScreen {
        TerminalScreen::from_bytes(24, 80, bytes)
    }

    /// Apply `frame` to `base`, as a client holding that base would.
    fn applied(base: &TerminalScreen, frame: &Frame) -> TerminalScreen {
        let mut s = base.clone();
        s.apply(&frame.diff).unwrap();
        s
    }

    /// A blank screen carrying the program's exit `code`.
    fn exit_screen(code: u32) -> Arc<TerminalScreen> {
        let mut emu = crate::terminal::ServerTerminal::new(24, 80, 0).unwrap();
        emu.set_exit_code(code);
        Arc::new(emu.snapshot())
    }

    #[test]
    fn a_connection_whose_first_screen_is_the_exit_screen_finishes_on_its_ack() {
        let t0 = Instant::now();
        let mut c = ServerConn::default();
        c.install_snapshot(exit_screen(0));
        let first = c.poll_frame(t0, None).expect("the exit screen is sent");
        assert!(!c.finished(t0, None));
        c.ack(first.num, t0);
        assert!(c.finished(t0, None), "the first frame was the final one");
    }

    #[test]
    fn the_first_frame_goes_out_at_once_and_a_burst_waits_for_the_floor() {
        let t0 = Instant::now();
        let rtt = Some(Duration::from_millis(100));
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::new(screen(b"hello")));
        let first = c
            .poll_frame(t0, rtt)
            .expect("the first frame is due at once");
        assert_eq!((first.num, first.base), (FrameNum(1), FrameNum::BLANK));
        assert!(applied(&TerminalScreen::default(), &first)
            .screen()
            .contents()
            .contains("hello"));
        c.frame_sent(first.num, 100, t0, rtt);
        c.install_snapshot(Arc::new(screen(b"hello")));
        assert!(
            c.poll_frame(t0, rtt).is_none(),
            "the same screen again is no change"
        );
        c.install_snapshot(Arc::new(screen(b"hello world")));
        let inside = t0 + Duration::from_millis(1);
        assert!(c.poll_frame(inside, rtt).is_none(), "inside the floor");
        assert_eq!(c.next_wake(inside, rtt), t0 + FRAME_FLOOR);
        let second = c
            .poll_frame(t0 + FRAME_FLOOR, rtt)
            .expect("the floor passed, and the link has room");
        assert_eq!(second.num, FrameNum(2));
        assert_eq!(second.base, FrameNum::BLANK, "nothing was acknowledged yet");
    }

    /// A connection that has learnt the link: a round trip of 50 ms, and 10 kB delivered in 90 ms,
    /// which proves some 111 kB/s, a budget of 5.5 kB in flight. Frames go at 0 and 50 ms, and
    /// are delivered at 50 and 140 ms; returned with the round trip and the time 200 ms on.
    fn on_a_slow_link() -> (ServerConn, Option<Duration>, Instant) {
        let t0 = Instant::now();
        let ms = |n| t0.checked_add(Duration::from_millis(n)).unwrap();
        let rtt = Some(Duration::from_millis(50));
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::new(screen(b"start")));
        let one = c.poll_frame(t0, rtt).unwrap();
        c.frame_sent(one.num, 100, t0, rtt);
        c.ack(one.num, ms(50));
        c.install_snapshot(Arc::new(screen(b"start, then more")));
        let two = c.poll_frame(ms(50), rtt).unwrap();
        c.frame_sent(two.num, 10_000, ms(50), rtt);
        c.ack(two.num, ms(140));
        assert_eq!(c.budget(rtt), 5_555);
        (c, rtt, ms(200))
    }

    /// [`on_a_slow_link`], then the link filled at its time by a 20 kB frame showing `text`.
    fn on_a_full_link(text: &[u8]) -> (ServerConn, Option<Duration>, Instant, FrameNum) {
        let (mut c, rtt, t) = on_a_slow_link();
        c.install_snapshot(Arc::new(screen(text)));
        let full = c.poll_frame(t, rtt).expect("room for it");
        c.frame_sent(full.num, 20_000, t, rtt);
        (c, rtt, t, full.num)
    }

    #[test]
    fn frames_in_flight_never_exceed_about_a_round_trip_of_the_link() {
        let (mut c, rtt, t, big) = on_a_full_link(b"a big repaint");
        c.install_snapshot(Arc::new(screen(b"a big repaint, changed")));
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
        c.ack(big, t + Duration::from_millis(100));
        assert!(c.poll_frame(t + Duration::from_millis(100), rtt).is_some());
    }

    #[test]
    fn with_nothing_it_may_send_the_connection_does_not_wake_at_once() {
        // Typed input awaits its echo, the echo-ack changed but not the screen, and the link is
        // full: nothing can go until a delivery, so the loop must not spin.
        let ms = Duration::from_millis;
        let (mut c, rtt, t, _) = on_a_full_link(b"$ ");
        c.push_client_bytes(&stream(&[typed(1, "x")]), t).unwrap();
        // A second key, still awaiting its echo once the first is promoted.
        c.push_client_bytes(&stream(&[typed(2, "y")]), t + ms(30))
            .unwrap();
        let later = t + ms(60);
        c.echo.promote(later);
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
        let (mut c, rtt, mut at) = on_a_slow_link();
        for n in 0..super::MAX_IN_FLIGHT {
            c.install_snapshot(Arc::new(screen(format!("count {n}").as_bytes())));
            let frame = c.poll_frame(at, rtt).expect("room for it");
            c.frame_sent(frame.num, 40, at, rtt);
            at += FRAME_FLOOR;
        }
        c.install_snapshot(Arc::new(screen(b"count more")));
        assert!(c.poll_frame(at, rtt).is_none(), "half the window in flight");
        assert!(
            c.next_wake(at, rtt) > at,
            "and the loop sleeps until a delivery"
        );
    }

    #[test]
    fn a_slow_link_skips_to_the_newest_screen() {
        let (mut c, rtt, mut at, big) = on_a_full_link(b"frame 0");
        for n in 1..=5 {
            at += Duration::from_millis(10);
            c.install_snapshot(Arc::new(screen(format!("frame {n}").as_bytes())));
            assert!(c.poll_frame(at, rtt).is_none(), "screen {n} waits");
        }
        c.ack(big, at);
        let next = c.poll_frame(at, rtt).expect("room again");
        assert_eq!(next.num, big.next(), "the screens between were never sent");
        let shown = applied(&screen(b"frame 0"), &next);
        assert!(shown.screen().contents().contains("frame 5"));
    }

    #[test]
    fn the_echo_of_typing_goes_at_once_even_with_the_link_full() {
        let (mut c, rtt, t, _) = on_a_full_link(b"$ ");
        // The user types; the program's echo changes one row.
        c.push_client_bytes(&stream(&[typed(1, "l")]), t).unwrap();
        c.install_snapshot(Arc::new(screen(b"$ l")));
        let typed = t + Duration::from_millis(1);
        let echo = c.poll_frame(typed, rtt).expect("the echo goes at once");
        assert!(applied(&screen(b"$ "), &echo)
            .screen()
            .contents()
            .contains("$ l"));
        // A large change is not an echo, typed or not: it waits for room.
        c.frame_sent(echo.num, 100, typed, rtt);
        let lines: Vec<u8> = (0..20)
            .flat_map(|n| format!("line {n}\r\n").into_bytes())
            .collect();
        c.install_snapshot(Arc::new(screen(&lines)));
        assert!(c
            .poll_frame(typed + Duration::from_millis(2), rtt)
            .is_none());
    }

    #[test]
    fn a_quiet_connection_still_gets_a_heartbeat() {
        let t0 = Instant::now();
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::new(screen(b"idle")));
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
        c.install_snapshot(Arc::new(screen(b"lost?")));
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
        // While the client acknowledges packets, the frame is still landing: it is resent only
        // once the link has gone a retry interval without one.
        let heard = t0 + retry + retry / 2;
        c.heard = Some(heard);
        assert!(c.poll_frame(t0 + retry * 2, rtt).is_none(), "still landing");
        assert_eq!(c.next_wake(t0 + retry * 2, rtt), heard + retry);
        assert_eq!(c.poll_frame(heard + retry, rtt).unwrap().num, FrameNum(3));
        // Once acknowledged, nothing more is resent until something changes.
        c.ack(FrameNum(3), Instant::now());
        assert!(c.poll_frame(t0 + retry * 9, rtt).is_none());
    }

    proptest::proptest! {
        #[test]
        fn a_delivery_never_proves_more_than_the_link_carries(
            bytes in 1_usize..100_000_000,
            per_sec in 1_u64..1 << 40,
            extra in 0_u64..10_000_000,
        ) {
            // On a link of `per_sec`, `bytes` take at least `bytes / per_sec` to deliver, and the
            // round trip, the queue and the acknowledgement's delay only add to it.
            let sending = u128::try_from(bytes).unwrap().saturating_mul(1_000_000_000).div_ceil(u128::from(per_sec));
            let took = Duration::from_nanos(u64::try_from(sending).unwrap().saturating_add(extra));
            let proven = super::Rate::proven(bytes, took);
            proptest::prop_assert!(proven.is_none_or(|rate| rate <= super::Rate(per_sec)));
        }
    }

    #[test]
    fn frames_diff_against_the_newest_acknowledged_frame() {
        let t0 = Instant::now();
        let later = |n| t0 + Duration::from_secs(n);
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::new(screen(b"one")));
        let one = c.poll_frame(t0, None).unwrap();
        c.install_snapshot(Arc::new(screen(b"one two")));
        c.poll_frame(later(1), None).unwrap();
        c.ack(FrameNum(1), Instant::now());
        c.install_snapshot(Arc::new(screen(b"one two three")));
        let three = c.poll_frame(later(2), None).unwrap();
        assert_eq!(three.base, FrameNum(1));
        let client_one = applied(&TerminalScreen::default(), &one);
        assert_eq!(applied(&client_one, &three), screen(b"one two three"));
        // An ack for a frame older than the acknowledged one changes nothing.
        c.ack(FrameNum(2), Instant::now());
        c.ack(FrameNum(1), Instant::now());
        c.install_snapshot(Arc::new(screen(b"four")));
        assert_eq!(c.poll_frame(later(3), None).unwrap().base, FrameNum(2));
    }

    #[test]
    fn a_delivery_of_a_frame_sent_before_a_resync_does_not_undo_it() {
        // The client refused frame 2 (it lacked base 1) and asked for a Resync; QUIC then reports
        // frame 2 delivered, after the Resync was read. The client never held frame 2, so the next
        // frame must still be on the blank screen.
        let t0 = Instant::now();
        let later = |n| t0 + Duration::from_secs(n);
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::new(screen(b"a")));
        c.poll_frame(t0, None).unwrap();
        c.ack(FrameNum(1), later(1));
        c.install_snapshot(Arc::new(screen(b"a b")));
        let two = c.poll_frame(later(2), None).unwrap();
        assert_eq!(two.base, FrameNum(1));
        c.push_client_bytes(&stream(&[ClientMsg::Resync]), later(3))
            .unwrap();
        c.ack(FrameNum(2), later(3));
        c.install_snapshot(Arc::new(screen(b"a b c")));
        let next = c
            .poll_frame(later(4), None)
            .expect("a resync forces a frame");
        assert_eq!(
            next.base,
            FrameNum::BLANK,
            "a frame on a base the client threw away"
        );
        assert_eq!(applied(&TerminalScreen::default(), &next), screen(b"a b c"));
    }

    #[test]
    fn only_the_last_frames_are_kept_so_an_ack_for_an_older_one_is_ignored() {
        let t0 = Instant::now();
        let mut c = ServerConn::default();
        for n in 0..=u64::try_from(FRAME_WINDOW).unwrap() {
            c.install_snapshot(Arc::new(screen(format!("frame {n}").as_bytes())));
            c.poll_frame(t0 + Duration::from_secs(n), None).unwrap();
        }
        assert_eq!(c.held.window().len(), FRAME_WINDOW);
        c.ack(FrameNum(1), Instant::now()); // dropped from the window
        assert_eq!(c.held.base().num, FrameNum::BLANK);
        c.ack(FrameNum(3), Instant::now());
        assert_eq!(c.held.base().num, FrameNum(3));
    }

    #[test]
    fn the_connection_finishes_once_the_final_frame_is_acked_or_after_a_second() {
        let t0 = Instant::now();
        let sent = t0 + Duration::from_secs(1);
        // A connection that has just sent the final frame (with the exit code) at `sent`.
        let exited = || {
            let mut c = ServerConn::default();
            c.install_snapshot(Arc::new(screen(b"$ ")));
            c.poll_frame(t0, None).unwrap();
            assert!(!c.finished(t0, None));
            c.install_snapshot(exit_screen(3));
            let last = c.poll_frame(sent, None).expect("the final frame");
            assert!(!c.finished(sent, None));
            (c, last)
        };
        let (mut acked, last) = exited();
        acked.ack(last.num, Instant::now());
        assert!(acked.finished(sent, None), "acked: done at once");
        let (unacked, _) = exited();
        let just_before = (sent + FINAL_ACK_WAIT)
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        assert!(!unacked.finished(just_before, None));
        assert!(
            unacked.finished(sent + FINAL_ACK_WAIT, None),
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
        c.install_snapshot(Arc::clone(&big));
        let t0 = Instant::now();
        for n in 0..=u64::try_from(FRAME_WINDOW).unwrap() {
            c.poll_frame(t0 + HEARTBEAT * u32::try_from(n).unwrap(), None)
                .expect("a heartbeat is due");
        }
        assert_eq!(
            c.held.window().len(),
            FRAME_WINDOW,
            "the window still holds every resend"
        );
        assert!(c
            .held
            .window()
            .iter()
            .all(|sent| Arc::ptr_eq(&sent.screen, &big)));
        assert_eq!(distinct_cells(c.held.window()), WINDOW_CELLS);
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
            c.install_snapshot(Arc::new(emu.snapshot()));
            c.poll_frame(t0 + HEARTBEAT * n, None)
                .expect("a frame is due");
        }
        assert_eq!(c.held.window().len(), FRAME_WINDOW);
        let changed_rows = FRAME_WINDOW - 1;
        assert_eq!(distinct_cells(c.held.window()), (24 + changed_rows) * 80);
    }

    #[test]
    fn frames_awaiting_acknowledgement_hold_at_most_one_largest_screen() {
        // Alternating screens (a client flipping between two sizes, say) are all distinct: without a
        // bound on cells, sixteen of the largest are held for a client that never acknowledges.
        let mut c = ServerConn::default();
        let t0 = Instant::now();
        for n in 0..20_u32 {
            c.install_snapshot(largest(&format!("screen {n}")));
            c.poll_frame(t0 + HEARTBEAT * n, None)
                .expect("a frame is due");
            assert!(
                distinct_cells(c.held.window()) <= WINDOW_CELLS,
                "after frame {n}"
            );
        }
        // Only the newest is left, and it still diffs against the base the client holds.
        assert_eq!(c.held.window().len(), 1);
        assert_eq!(c.held.base().num, FrameNum::BLANK);
        let frame = c
            .poll_frame(t0 + HEARTBEAT * 20, None)
            .expect("a heartbeat is due");
        assert_eq!(frame.base, FrameNum::BLANK);
        // An acknowledgement of a dropped frame is ignored, as one past the window is.
        c.ack(FrameNum(3), Instant::now());
        assert_eq!(c.held.base().num, FrameNum::BLANK);
    }

    #[test]
    fn frames_a_client_never_takes_are_forgotten() {
        // A client that never accepts a frame's stream leaves every frame undelivered; the
        // server forgets them past the window, or it would hold one more each retry, for good.
        let mut c = ServerConn::default();
        let t0 = Instant::now();
        let rtt = Some(Duration::from_millis(50));
        for n in 0..1000_u32 {
            c.install_snapshot(Arc::new(screen(format!("frame {n}").as_bytes())));
            let at = t0 + Duration::from_millis(u64::from(n));
            if let Some(frame) = c.poll_frame(at, rtt) {
                c.frame_sent(frame.num, 100, at, rtt);
            }
        }
        assert!(c.in_flight.len() <= FRAME_WINDOW, "{}", c.in_flight.len());
    }

    #[test]
    fn links_left_off_a_frame_go_in_a_later_one() {
        // More links than a diff carries: the frame leaves some off, the server holds the screen
        // as the client has it, and the next frames carry the rest, until the client has all.
        let mut out = Vec::new();
        for row in 0..12 {
            for col in 0..64 {
                out.extend_from_slice(
                    format!(
                        "\x1b]8;;https://koh.example/{row}/{col}/{}\x1b\\x\x1b]8;;\x1b\\",
                        "a".repeat(2000)
                    )
                    .as_bytes(),
                );
            }
            out.extend_from_slice(b"\r\n");
        }
        let server = Arc::new(TerminalScreen::from_bytes(24, 80, &out));
        let mut c = ServerConn::default();
        c.install_snapshot(Arc::clone(&server));
        let mut client = TerminalScreen::default();
        let t0 = Instant::now();
        for n in 0..10_u32 {
            let at = t0 + HEARTBEAT * n;
            let Some(frame) = c.poll_frame(at, None) else {
                continue;
            };
            client = applied(&client, &frame);
            c.ack(frame.num, at);
            if client == *server {
                assert!(n > 0, "the first frame could not carry every link");
                return;
            }
        }
        panic!("the client never got every link");
    }
}
