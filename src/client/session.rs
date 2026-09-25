//! The client's I/O-free core: frames in, messages out.
//!
//! [`ClientSession`] holds the screens of its last applied frames, turns typed bytes and resizes
//! into [`ClientMsg`]s, applies [`Frame`]s whose base it holds, and runs the predictor. It never
//! touches tokio, iroh or a terminal; the connection loop in [`super`] moves the bytes, and tests
//! drive it directly.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::predict::{DisplayPreference, Overlay, PredictionEngine};
use crate::proto::{
    retry_after, ClientMsg, Frame, FrameNum, InputSeq, FRAME_WINDOW, HEARTBEAT, MAX_INPUT_BYTES,
};
use crate::terminal::{Grid, TerminalScreen};

use super::render::WindowState;
use super::{window_state, ESCAPE_PREFIX, SUSPEND_KEY};

/// How long the server may go unheard before the "link down" banner appears: three missed
/// heartbeats, so one late or lost frame on a lossy link does not flash it.
pub const LINK_DOWN_GRACE: Duration = HEARTBEAT.saturating_mul(3);

/// The most typed bytes the client holds while the server is not taking input. Past this, typing is
/// dropped and the status line says so.
const MAX_QUEUED_INPUT: usize = 1024 * 1024;

/// What [`ClientSession::on_input`] decided about a chunk of typed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOutcome {
    /// The user typed the escape prefix followed by `.` — disconnect.
    Quit,
    /// The user typed the escape prefix followed by `Ctrl-Z` — suspend to the background. Any bytes
    /// before the escape in the same chunk were already queued; the caller drives the suspend.
    Suspend,
    /// The bytes were consumed (queued for the server and seeded into the predictor).
    Forwarded,
}

/// What one [`ClientSession::on_tick`] produced for the connection loop.
#[derive(Debug, Default)]
pub struct TickResult {
    /// How long to wait before the next tick if nothing else wakes the loop.
    pub wait: Duration,
    /// The status banner to draw, if any: the link is down, or input is paused.
    pub status: Option<String>,
}

/// The client side of one connection.
pub struct ClientSession {
    /// The newest applied frame and its screen.
    current: (FrameNum, TerminalScreen),
    /// The frames applied before it, oldest first, at most `FRAME_WINDOW - 1`.
    older: VecDeque<(FrameNum, TerminalScreen)>,
    /// A `Resync` was sent and no frame has applied since.
    resync_sent: bool,
    /// The newest input the server has reported reflected on screen.
    echo_ack: InputSeq,
    /// The last input sequence number used.
    last_seq: InputSeq,
    /// Messages for the server, oldest first.
    outgoing: VecDeque<ClientMsg>,
    /// Typed bytes in `outgoing`.
    queued_input: usize,
    /// Typing was dropped because `outgoing` was full; cleared once it drains.
    input_paused: bool,
    /// When the server was last heard from; `None` until the first frame.
    last_heard: Option<Instant>,
    /// When input was last queued, or the last probe sent, while some input is not yet confirmed
    /// by the echo-ack.
    last_nudge: Option<Instant>,
    predictor: PredictionEngine,
    /// True after the lone escape prefix, while waiting for the next byte.
    pending_escape: bool,
    /// Set whenever the rendered output may have changed; cleared once the caller repaints.
    pub(crate) dirty: bool,
    /// Whether a status banner was painted last frame, so its removal repaints once more.
    pub(crate) status_was_shown: bool,
}

impl ClientSession {
    /// A session for a new connection, telling the server the window is `rows × cols`.
    pub fn new(pref: DisplayPreference, rows: u16, cols: u16) -> Self {
        Self {
            current: (FrameNum::BLANK, TerminalScreen::default()),
            older: VecDeque::new(),
            resync_sent: false,
            echo_ack: InputSeq::default(),
            last_seq: InputSeq::default(),
            outgoing: VecDeque::from([ClientMsg::Resize { rows, cols }]),
            queued_input: 0,
            input_paused: false,
            last_heard: None,
            last_nudge: None,
            predictor: PredictionEngine::new(pref),
            pending_escape: false,
            dirty: true,
            status_was_shown: false,
        }
    }

    /// Feed a chunk of typed bytes. Runs the escape machine (`0x1e` then `.` quits, then `Ctrl-Z`
    /// suspends, then anything else forwards both bytes), seeds the predictor, and queues the rest.
    pub fn on_input(&mut self, now: Instant, bytes: &[u8]) -> InputOutcome {
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
        // Bytes typed before `Ctrl-^ Ctrl-Z` in the same chunk still go out.
        if !fwd.is_empty() {
            self.queue_input(now, &fwd);
        }
        if suspend {
            return InputOutcome::Suspend;
        }
        InputOutcome::Forwarded
    }

    fn queue_input(&mut self, now: Instant, bytes: &[u8]) {
        if self.queued_input.saturating_add(bytes.len()) > MAX_QUEUED_INPUT {
            // The server is not taking input; queueing more would grow without bound.
            if !self.input_paused {
                self.input_paused = true;
                self.dirty = true;
            }
            return;
        }
        // Predictions made now expire with the first input message that carries these bytes.
        let seq = match self.outgoing.back() {
            Some(ClientMsg::Input { seq, bytes: queued })
                if queued.len().saturating_add(bytes.len()) <= MAX_INPUT_BYTES =>
            {
                *seq
            }
            _ => self.last_seq.next(),
        };
        self.predictor
            .set_local_frame_sent(seq.0.saturating_sub(1));
        for &b in bytes {
            self.predictor.new_user_byte(b, self.current.1.screen());
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            let appended = match self.outgoing.back_mut() {
                Some(ClientMsg::Input { bytes: queued, .. }) => {
                    let room = MAX_INPUT_BYTES.saturating_sub(queued.len());
                    let (now_part, later) = rest.split_at(room.min(rest.len()));
                    queued.extend_from_slice(now_part);
                    rest = later;
                    !now_part.is_empty()
                }
                _ => false,
            };
            if !appended {
                let (now_part, later) = rest.split_at(MAX_INPUT_BYTES.min(rest.len()));
                self.last_seq = self.last_seq.next();
                self.outgoing.push_back(ClientMsg::Input {
                    seq: self.last_seq,
                    bytes: now_part.to_vec(),
                });
                rest = later;
            }
        }
        self.queued_input = self.queued_input.saturating_add(bytes.len());
        self.last_nudge = Some(now);
        self.dirty = true;
    }

    /// Note a new window size: queue it for the server and reset the predictor, whose
    /// predictions a resize invalidates.
    pub fn on_resize(&mut self, rows: u16, cols: u16) {
        // Only the last of several unsent resizes matters.
        if let Some(ClientMsg::Resize {
            rows: queued_rows,
            cols: queued_cols,
        }) = self.outgoing.back_mut()
        {
            *queued_rows = rows;
            *queued_cols = cols;
        } else {
            self.outgoing.push_back(ClientMsg::Resize { rows, cols });
        }
        self.predictor.reset();
        self.dirty = true;
    }

    /// A frame arrived at `now`. It is applied if it is newer than the current screen and its base
    /// is one this session holds; otherwise it only proves the link is alive.
    pub fn on_frame(&mut self, now: Instant, frame: &Frame) {
        self.last_heard = Some(now);
        if frame.num <= self.current.0 {
            return;
        }
        let base = if frame.base == FrameNum::BLANK {
            Some(TerminalScreen::default())
        } else if frame.base == self.current.0 {
            Some(self.current.1.clone())
        } else {
            self.older
                .iter()
                .find(|(num, _)| *num == frame.base)
                .map(|(_, screen)| screen.clone())
        };
        let Some(mut screen) = base else {
            if !self.resync_sent {
                self.resync_sent = true;
                self.outgoing.push_back(ClientMsg::Resync);
            }
            return;
        };
        screen.apply(&frame.diff);
        let previous = std::mem::replace(&mut self.current, (frame.num, screen));
        self.older.push_back(previous);
        while self.older.len() >= FRAME_WINDOW {
            self.older.pop_front();
        }
        self.resync_sent = false;
        self.acknowledge(frame.num);
        self.echo_ack = self.echo_ack.max(frame.echo_ack);
        self.predictor.set_local_frame_late_acked(self.echo_ack.0);
        self.predictor.cull(self.current.1.screen());
        self.dirty = true;
    }

    fn acknowledge(&mut self, num: FrameNum) {
        // A newer ack supersedes an unsent one.
        if let Some(pos) = self
            .outgoing
            .iter()
            .position(|m| matches!(m, ClientMsg::Ack { .. }))
        {
            self.outgoing.remove(pos);
        }
        self.outgoing.push_back(ClientMsg::Ack { frame: num });
    }

    /// Advance to `now` with the connection's current `rtt`: expire stale predictions, probe for
    /// input the server has not confirmed, and report the status banner.
    pub fn on_tick(&mut self, now: Instant, rtt: Option<Duration>) -> TickResult {
        // Input the echo-ack has not confirmed for a retry interval may be stuck behind a lost
        // packet. Any later packet lets QUIC detect the loss and retransmit at once, where
        // otherwise it waits out its probe timeout; a repeated acknowledgement is that packet, and
        // the server ignores it.
        if self.echo_ack < self.last_seq
            && self
                .last_nudge
                .is_some_and(|at| now.saturating_duration_since(at) >= retry_after(rtt))
        {
            self.last_nudge = Some(now);
            if !self.outgoing.iter().any(|m| matches!(m, ClientMsg::Ack { .. })) {
                self.outgoing.push_back(ClientMsg::Ack {
                    frame: self.current.0,
                });
            }
        }
        // The predictor engages adaptively on the link's round-trip time.
        self.predictor
            .set_rtt_ms(rtt.map_or(0.0, |rtt| rtt.as_secs_f64() * 1000.0));
        let silent = self
            .last_heard
            .map(|heard| now.saturating_duration_since(heard));
        let status = match silent {
            Some(silent) if silent > LINK_DOWN_GRACE => Some(format!(
                "[koh] link down — resuming… {}s",
                silent.as_secs()
            )),
            _ if self.input_paused => {
                Some("[koh] input paused — the server is not taking input".to_owned())
            }
            _ => None,
        };
        TickResult {
            wait: Duration::from_millis(50),
            status,
        }
    }

    /// Whether messages are waiting for the server.
    pub fn has_outgoing(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Take the next message for the server.
    pub fn pop_outgoing(&mut self) -> Option<ClientMsg> {
        let msg = self.outgoing.pop_front()?;
        if let ClientMsg::Input { bytes, .. } = &msg {
            self.queued_input = self.queued_input.saturating_sub(bytes.len());
            if self.input_paused && self.queued_input == 0 {
                self.input_paused = false;
                self.dirty = true;
            }
        }
        Some(msg)
    }

    /// Whether a frame reported that the shell exited (its code is on [`state`](Self::state)).
    pub const fn exited(&self) -> bool {
        self.current.1.exit_code().is_some()
    }

    /// The newest applied screen.
    pub const fn state(&self) -> &TerminalScreen {
        &self.current.1
    }

    /// Whether a server frame has been applied, i.e. [`state`](Self::state) is the server's and
    /// not the blank screen a session starts from.
    pub fn synced(&self) -> bool {
        self.current.0 > FrameNum::BLANK
    }

    /// The prediction overlay to draw over [`state`](Self::state).
    pub fn overlay(&self) -> Overlay {
        self.predictor.overlay()
    }

    /// The window state (title, icon, clipboard, bell) to mirror onto the real terminal.
    pub fn window_state(&self) -> WindowState<'_> {
        window_state(&self.current.1)
    }

    /// The newest applied screen's grid.
    pub const fn screen(&self) -> &Grid {
        self.current.1.screen()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::ServerTerminal;

    fn start() -> (Instant, ClientSession) {
        let now = Instant::now();
        (now, ClientSession::new(DisplayPreference::Always, 24, 80))
    }

    fn screen(bytes: &[u8]) -> TerminalScreen {
        TerminalScreen::from_bytes(24, 80, bytes)
    }

    fn frame(num: u64, base: u64, echo_ack: u64, from: &TerminalScreen, to: &TerminalScreen) -> Frame {
        Frame {
            num: FrameNum(num),
            base: FrameNum(base),
            echo_ack: InputSeq(echo_ack),
            diff: to.diff_from(from),
        }
    }

    fn drain(s: &mut ClientSession) -> Vec<ClientMsg> {
        std::iter::from_fn(|| s.pop_outgoing()).collect()
    }

    fn typed(msgs: &[ClientMsg]) -> Vec<u8> {
        msgs.iter()
            .filter_map(|m| match m {
                ClientMsg::Input { bytes, .. } => Some(bytes.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    #[test]
    fn a_session_first_tells_the_server_its_window_size() {
        let (_, mut s) = start();
        assert_eq!(drain(&mut s), [ClientMsg::Resize { rows: 24, cols: 80 }]);
    }

    #[test]
    fn escape_prefix_dot_quits_and_plain_bytes_forward() {
        let (now, mut s) = start();
        assert_eq!(s.on_input(now, b"ls\r"), InputOutcome::Forwarded);
        assert_eq!(typed(&drain(&mut s)), b"ls\r");
        assert_eq!(s.on_input(now, &[ESCAPE_PREFIX, b'.']), InputOutcome::Quit);
    }

    #[test]
    fn escape_prefix_ctrl_z_suspends_even_split_across_chunks() {
        let (now, mut s) = start();
        assert_eq!(
            s.on_input(now, &[ESCAPE_PREFIX, SUSPEND_KEY]),
            InputOutcome::Suspend
        );
        assert_eq!(s.on_input(now, &[ESCAPE_PREFIX]), InputOutcome::Forwarded);
        assert_eq!(s.on_input(now, &[SUSPEND_KEY]), InputOutcome::Suspend);
        assert!(typed(&drain(&mut s)).is_empty());
    }

    #[test]
    fn bytes_before_suspend_escape_are_forwarded_first() {
        let (now, mut s) = start();
        assert_eq!(
            s.on_input(now, &[b'h', b'i', ESCAPE_PREFIX, SUSPEND_KEY]),
            InputOutcome::Suspend
        );
        assert_eq!(typed(&drain(&mut s)), b"hi");
    }

    #[test]
    fn lone_escape_prefix_then_other_byte_forwards_both() {
        let (now, mut s) = start();
        assert_eq!(s.on_input(now, &[ESCAPE_PREFIX]), InputOutcome::Forwarded);
        assert_eq!(s.on_input(now, b"x"), InputOutcome::Forwarded);
        assert_eq!(typed(&drain(&mut s)), [ESCAPE_PREFIX, b'x']);
    }

    #[test]
    fn input_is_numbered_in_order_and_a_paste_is_split() {
        let now = Instant::now();
        let mut s = ClientSession::new(DisplayPreference::Never, 24, 80);
        let paste: Vec<u8> = (0..200_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        s.on_input(now, b"first");
        s.on_input(now, &paste);
        let msgs = drain(&mut s);
        let inputs: Vec<(InputSeq, usize)> = msgs
            .iter()
            .filter_map(|m| match m {
                ClientMsg::Input { seq, bytes } => Some((*seq, bytes.len())),
                _ => None,
            })
            .collect();
        assert!(inputs.iter().all(|&(_, len)| len <= MAX_INPUT_BYTES));
        let seqs: Vec<u64> = inputs.iter().map(|(seq, _)| seq.0).collect();
        assert_eq!(seqs, (1..=u64::try_from(seqs.len()).unwrap()).collect::<Vec<_>>());
        assert_eq!(typed(&msgs), [b"first".as_slice(), &paste].concat());
    }

    #[test]
    fn typing_past_the_queue_limit_is_dropped_and_reported_until_it_drains() {
        // Queueing, not prediction, is under test; skip predicting a megabyte byte by byte.
        let now = Instant::now();
        let mut s = ClientSession::new(DisplayPreference::Never, 24, 80);
        let chunk = vec![b'z'; MAX_INPUT_BYTES];
        for _ in 0..MAX_QUEUED_INPUT.div_euclid(MAX_INPUT_BYTES) {
            s.on_input(now, &chunk);
        }
        assert!(s.on_tick(now, None).status.is_none(), "the queue is full, not over");
        s.on_input(now, b"dropped");
        let status = s.on_tick(now, None).status.expect("input paused banner");
        assert!(status.contains("input paused"), "{status}");
        let queued = typed(&drain(&mut s));
        assert_eq!(queued.len(), MAX_QUEUED_INPUT, "the dropped bytes were not queued");
        assert!(s.on_tick(now, None).status.is_none(), "draining clears the banner");
    }

    #[test]
    fn frames_apply_against_a_held_base_and_are_acknowledged() {
        let (now, mut s) = start();
        drain(&mut s);
        let blank = TerminalScreen::default();
        let one = screen(b"one");
        let two = screen(b"one two");
        s.dirty = false;
        s.on_frame(now, &frame(1, 0, 0, &blank, &one));
        assert!(s.dirty && s.synced());
        assert!(s.screen().contents().contains("one"));
        s.on_frame(now, &frame(2, 1, 0, &one, &two));
        assert!(s.screen().contents().contains("one two"));
        // Only the newest acknowledgement is worth sending.
        assert_eq!(drain(&mut s), [ClientMsg::Ack { frame: FrameNum(2) }]);
    }

    #[test]
    fn an_older_or_repeated_frame_is_ignored() {
        let (now, mut s) = start();
        let blank = TerminalScreen::default();
        let one = screen(b"one");
        let two = screen(b"two");
        s.on_frame(now, &frame(2, 0, 0, &blank, &two));
        s.on_frame(now, &frame(1, 0, 0, &blank, &one));
        s.on_frame(now, &frame(2, 0, 0, &blank, &one));
        assert!(s.screen().contents().contains("two"));
    }

    #[test]
    fn an_unknown_base_sends_one_resync_until_a_frame_applies() {
        let (now, mut s) = start();
        drain(&mut s);
        let blank = TerminalScreen::default();
        let one = screen(b"one");
        s.on_frame(now, &frame(5, 4, 0, &one, &one));
        s.on_frame(now, &frame(6, 4, 0, &one, &one));
        assert_eq!(drain(&mut s), [ClientMsg::Resync], "one resync, not one per frame");
        s.on_frame(now, &frame(7, 0, 0, &blank, &one));
        assert!(s.screen().contents().contains("one"));
        s.on_frame(now, &frame(8, 3, 0, &one, &one));
        assert_eq!(
            drain(&mut s),
            [ClientMsg::Ack { frame: FrameNum(7) }, ClientMsg::Resync]
        );
    }

    #[test]
    fn only_the_last_frames_are_kept_as_bases() {
        let (now, mut s) = start();
        let mut prev = TerminalScreen::default();
        for n in 1..=20u64 {
            let next = screen(format!("frame {n}").as_bytes());
            s.on_frame(now, &frame(n, n - 1, 0, &prev, &next));
            prev = next;
        }
        drain(&mut s);
        let oldest_kept = 20 - u64::try_from(FRAME_WINDOW).unwrap() + 1;
        let target = screen(b"target");
        let base = screen(format!("frame {}", oldest_kept - 1).as_bytes());
        s.on_frame(now, &frame(21, oldest_kept - 1, 0, &base, &target));
        assert_eq!(drain(&mut s), [ClientMsg::Resync], "a dropped base is gone");
        let base = screen(format!("frame {oldest_kept}").as_bytes());
        s.on_frame(now, &frame(22, oldest_kept, 0, &base, &target));
        assert!(s.screen().contents().contains("target"), "a kept base applies");
    }

    #[test]
    fn a_frame_confirms_echoed_predictions() {
        let (now, mut s) = start();
        s.on_input(now, b"x");
        assert!(s.overlay().is_empty(), "the first keystroke stays hidden until confirmed");
        assert_eq!(s.predictor.confirmed_epoch(), 0);
        let echoed = screen(b"x");
        let later = now + Duration::from_millis(100);
        s.on_frame(later, &frame(1, 0, 1, &TerminalScreen::default(), &echoed));
        assert_eq!(
            s.predictor.confirmed_epoch(),
            1,
            "the echoed keystroke is graded correct and its epoch confirmed"
        );
        s.on_input(later, b"y");
        assert_eq!(
            s.overlay().cell(0, 1).map(|c| c.glyph.as_str()),
            Some("y"),
            "typing after a confirmed echo is shown"
        );
    }

    #[test]
    fn the_shell_exit_and_window_state_come_from_the_frames() {
        let (now, mut s) = start();
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
        emu.process(b"cell three\x07\x07");
        let live = emu.snapshot();
        s.on_frame(now, &frame(1, 0, 0, &TerminalScreen::default(), &live));
        assert!(!s.exited());
        assert_eq!(s.window_state().bell_count, 2);
        emu.set_exit_code(7);
        let exited = emu.snapshot();
        s.on_frame(now, &frame(2, 1, 0, &live, &exited));
        assert!(s.exited());
        assert_eq!(s.state().exit_code(), Some(7));
    }

    #[test]
    fn link_down_banner_absorbs_a_missed_heartbeat_but_shows_on_a_real_stall() {
        let (now, mut s) = start();
        assert!(
            s.on_tick(now + LINK_DOWN_GRACE * 2, None).status.is_none(),
            "no banner before the first frame (still connecting)"
        );
        s.on_frame(now, &frame(1, 0, 0, &TerminalScreen::default(), &screen(b"$ ")));
        assert!(s.on_tick(now + HEARTBEAT * 2, None).status.is_none());
        assert!(s.on_tick(now + LINK_DOWN_GRACE, None).status.is_none());
        let stalled = s.on_tick(now + LINK_DOWN_GRACE + Duration::from_secs(2), None);
        assert!(stalled.status.is_some_and(|b| b.contains("link down")));
    }

    #[test]
    fn unconfirmed_input_is_probed_after_a_retry_interval() {
        let (now, mut s) = start();
        let rtt = Some(Duration::from_millis(200));
        let retry = retry_after(rtt);
        s.on_input(now, b"a");
        drain(&mut s);
        let just_before = (now + retry).checked_sub(Duration::from_millis(1)).unwrap();
        s.on_tick(just_before, rtt);
        assert!(drain(&mut s).is_empty(), "too early to probe");
        s.on_tick(now + retry, rtt);
        assert_eq!(drain(&mut s), [ClientMsg::Ack { frame: FrameNum::BLANK }]);
        s.on_tick(now + retry + Duration::from_millis(1), rtt);
        assert!(drain(&mut s).is_empty(), "one probe per retry interval");
        // The echo-ack confirms the input: no more probes.
        let echoed = screen(b"a");
        s.on_frame(now + retry, &frame(1, 0, 1, &TerminalScreen::default(), &echoed));
        drain(&mut s);
        s.on_tick(now + retry * 4, rtt);
        assert!(drain(&mut s).is_empty(), "confirmed input is not probed");
    }

    #[test]
    fn resizes_coalesce_and_reset_the_predictor() {
        let (now, mut s) = start();
        s.on_resize(30, 100);
        s.on_resize(40, 120);
        s.on_input(now, b"a");
        s.on_resize(50, 132);
        assert_eq!(
            drain(&mut s),
            [
                ClientMsg::Resize { rows: 40, cols: 120 },
                ClientMsg::Input {
                    seq: InputSeq(1),
                    bytes: b"a".to_vec()
                },
                ClientMsg::Resize { rows: 50, cols: 132 },
            ]
        );
        assert!(s.overlay().is_empty(), "a resize drops predictions");
        assert!(s.dirty);
    }
}
