//! The client's core, without I/O: [`ClientSession`] turns typed bytes and resizes into
//! [`ClientMsg`]s, applies [`Frame`]s whose base it holds, and runs the predictor.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fux_vt::keys::colour::Scheme;
use fux_vt::keys::decode::{Decoder, Input, Reply};
use fux_vt::keys::encode::{key_bytes, paste, KeyMode, PASTE_END, PASTE_START};
use fux_vt::keys::{KeyPress, Keystroke};

use crate::events::{
    narrow, InputEvent, WireColours, WireScheme, MAX_EVENTS, MAX_PASTE_PIECE, PALETTE,
};
use crate::predict::{DisplayPreference, Overlay, PredictionEngine};
use crate::proto::{
    decode_frame_body, dictionary_for, retry_after, ClientMsg, Frame, FrameNum, FrameScreen,
    InputSeq, FRAME_WINDOW, HEARTBEAT, MAX_INPUT_BYTES, WINDOW_CELLS,
};
use crate::terminal::{Grid, HistoryReply, RowEncodings, Size, TerminalScreen};

use super::probe::COLOUR_QUERIES;
use super::render::WindowState;
use super::scrollback::Scrollback;
use super::{window_state, ESCAPE_PREFIX, SCROLLBACK_KEY, SUSPEND_KEY};

/// How long the server may go unheard before the "link down" banner: three heartbeats, so one late
/// frame does not flash it.
pub const LINK_DOWN_GRACE: Duration = HEARTBEAT.saturating_mul(3);

/// The most typed bytes held while the server takes no input; past it, typing is dropped and the
/// status line says so. A paste is kept up to this long too.
const MAX_QUEUED_INPUT: usize = 1024 * 1024;

/// What the status line says of a paste past [`MAX_QUEUED_INPUT`], which is dropped whole.
const PASTE_TOO_LONG: &str = "[koh] paste over 1 MiB — not sent";

/// How long a notice stays on the status line.
const NOTICE_FOR: Duration = Duration::from_secs(3);

/// What [`ClientSession::on_input`] decided about a chunk of typed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOutcome {
    /// The user typed the escape prefix followed by `.` — disconnect.
    Quit,
    /// The user typed the escape prefix and `Ctrl-Z`: suspend. Bytes before it were queued.
    Suspend,
    /// The bytes were queued and predicted.
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
    current: FrameScreen,
    /// The frames applied before it, oldest first: at most `FRAME_WINDOW - 1`, holding at most
    /// [`WINDOW_CELLS`] cells beyond `current`'s.
    older: VecDeque<FrameScreen>,
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
    /// When input was last queued or probed for, while some is unconfirmed.
    last_nudge: Option<Instant>,
    predictor: PredictionEngine,
    /// What the user's terminal sends, decoded.
    decoder: Decoder,
    /// The escape prefix as typed, while waiting for the key after it.
    pending_escape: Option<Keystroke>,
    /// The user's terminal's colours, while the server is told them (not with `--no-colours`).
    colours: Option<WireColours>,
    /// The colours were asked again (after a new scheme) and not all are in.
    colours_asked: bool,
    /// Questions for the user's terminal, for the caller to write.
    ask: Vec<u8>,
    /// A notice for the status line, and when it was given.
    notice: Option<(String, Instant)>,
    /// A key's legacy bytes, as last matched against the escape prefix.
    scratch: Vec<u8>,
    /// The history held, and the scrollback view.
    scrollback: Scrollback,
    /// When the user last typed or a frame last applied: history is fetched ahead only after a
    /// quiet spell.
    last_activity: Option<Instant>,
    /// The window's height, for the view's pages.
    rows: u16,
    /// Rows' encodings, kept from one frame's dictionary to the next.
    encodings: RowEncodings,
    /// Set whenever the rendered output may have changed; cleared once the caller repaints.
    pub(crate) dirty: bool,
    /// Whether a status banner was painted last frame, so its removal repaints once more.
    pub(crate) status_was_shown: bool,
}

impl ClientSession {
    /// A session for a new connection, telling the server the window's `size`.
    pub fn new(pref: DisplayPreference, size: Size) -> Self {
        Self {
            current: FrameScreen::default(),
            older: VecDeque::new(),
            resync_sent: false,
            echo_ack: InputSeq::default(),
            last_seq: InputSeq::default(),
            outgoing: VecDeque::from([ClientMsg::Resize(size)]),
            queued_input: 0,
            input_paused: false,
            last_heard: None,
            last_nudge: None,
            predictor: PredictionEngine::new(pref),
            decoder: Decoder::with_paste_limit(MAX_QUEUED_INPUT),
            pending_escape: None,
            colours: None,
            colours_asked: false,
            ask: Vec::new(),
            notice: None,
            scratch: Vec::with_capacity(16),
            scrollback: Scrollback::default(),
            last_activity: None,
            rows: size.rows,
            encodings: RowEncodings::default(),
            dirty: true,
            status_was_shown: false,
        }
    }

    /// Take typed bytes, as the user's terminal sent them: decoded, then handled as
    /// [`on_inputs`](Self::on_inputs) says. An incomplete sequence waits for more, or for
    /// [`deadline`](Self::deadline).
    pub fn on_input(&mut self, now: Instant, bytes: &[u8]) -> InputOutcome {
        let mut inputs = Vec::new();
        self.decoder.bytes(bytes, &mut inputs);
        self.decoder.mark(now);
        self.on_inputs(now, inputs)
    }

    /// When an incomplete sequence typed is to be taken as it is (a lone Escape is a key once
    /// nothing follows it for a moment): call [`on_timeout`](Self::on_timeout) then.
    pub fn deadline(&self) -> Option<Instant> {
        self.decoder.deadline()
    }

    /// The [`deadline`](Self::deadline) passed: what was waiting is taken as it is.
    pub fn on_timeout(&mut self, now: Instant) -> InputOutcome {
        if self.decoder.deadline().is_none_or(|d| d > now) {
            return InputOutcome::Forwarded;
        }
        let mut inputs = Vec::new();
        self.decoder.timeout(&mut inputs);
        self.on_inputs(now, inputs)
    }

    /// Take decoded input: the escape prefix (a key whose legacy byte is `Ctrl-^`, from any
    /// terminal) then `.` quits, then `Ctrl-Z` suspends, then `[` opens the scrollback view, then
    /// anything else forwards both; the rest is predicted and queued. The terminal's answers to
    /// the client's own questions are taken here and go no further.
    pub fn on_inputs(&mut self, now: Instant, inputs: Vec<Input>) -> InputOutcome {
        let mut quit = false;
        let mut suspend = false;
        let mut fwd: Vec<InputEvent> = Vec::new();
        // Input for the scrollback view, which goes nowhere else.
        let mut viewed: Vec<Input> = Vec::new();
        for input in inputs {
            match input {
                Input::Reply(reply) => {
                    self.on_reply(now, reply);
                    continue;
                }
                Input::PasteTooLong => {
                    self.notice = Some((PASTE_TOO_LONG.to_owned(), now));
                    self.dirty = true;
                    continue;
                }
                Input::Key(_)
                | Input::Paste(_)
                | Input::FocusIn
                | Input::FocusOut
                | Input::Mouse(_) => {}
            }
            let key = match &input {
                // The prefix is a control: a key without Ctrl can only matter after one.
                Input::Key(stroke) if stroke.press.mods.ctrl || self.pending_escape.is_some() => {
                    self.scratch.clear();
                    key_bytes(
                        stroke.press.into(),
                        KeyMode::legacy(false),
                        &mut self.scratch,
                    );
                    Some(self.scratch.as_slice())
                }
                Input::Key(_)
                | Input::Paste(_)
                | Input::PasteTooLong
                | Input::FocusIn
                | Input::FocusOut
                | Input::Mouse(_)
                | Input::Reply(_) => None,
            };
            if let Some(prefix) = self.pending_escape.take() {
                match key {
                    Some(b".") => {
                        quit = true;
                        break;
                    }
                    Some([SUSPEND_KEY]) => {
                        suspend = true;
                        break;
                    }
                    Some([SCROLLBACK_KEY]) => {
                        if !self.scrollback.viewing() {
                            self.scrollback.open();
                            self.dirty = true;
                        }
                        continue;
                    }
                    _ => {}
                }
                if self.scrollback.viewing() {
                    viewed.extend([Input::Key(prefix), input]);
                } else {
                    fwd.push(InputEvent::Key(prefix.into()));
                    events_of(input, &mut fwd);
                }
            } else if key == Some(&[ESCAPE_PREFIX]) {
                if let Input::Key(stroke) = input {
                    self.pending_escape = Some(stroke);
                }
            } else if self.scrollback.viewing() {
                viewed.push(input);
            } else if !self.input_paused {
                // While paused, what is typed is dropped: only the escape is looked for.
                events_of(input, &mut fwd);
            }
        }
        if !viewed.is_empty() {
            self.scrollback.on_events(&viewed, self.rows);
            self.dirty = true;
        }
        if quit {
            return InputOutcome::Quit;
        }
        // Input before `Ctrl-^ Ctrl-Z` in the same read still goes out.
        if !fwd.is_empty() {
            self.queue_events(now, fwd);
        }
        if suspend {
            return InputOutcome::Suspend;
        }
        InputOutcome::Forwarded
    }

    /// An answer or report from the user's terminal. A new scheme (mode 2031) asks the colours
    /// again; once the round's last answer (DA1) is in, the server is told them.
    fn on_reply(&mut self, now: Instant, reply: Reply) {
        let Some(colours) = self.colours.as_mut() else {
            return;
        };
        match reply {
            Reply::Scheme(scheme) => {
                colours.scheme = Some(match scheme {
                    Scheme::Dark => WireScheme::Dark,
                    Scheme::Light => WireScheme::Light,
                });
                if !self.colours_asked {
                    self.colours_asked = true;
                    self.ask.extend_from_slice(COLOUR_QUERIES);
                    self.decoder.expect(now);
                }
            }
            Reply::Colour { number: 10, rgb } => colours.foreground = Some(narrow(rgb)),
            Reply::Colour { number: 11, rgb } => colours.background = Some(narrow(rgb)),
            Reply::Palette { index, rgb } => {
                if let Some(slot) = colours.palette.get_mut(usize::from(index)) {
                    *slot = Some(narrow(rgb));
                }
            }
            Reply::Attributes if self.colours_asked => {
                self.colours_asked = false;
                self.outgoing.push_back(ClientMsg::Colours(colours.clone()));
            }
            Reply::Colour { .. }
            | Reply::Attributes
            | Reply::Mode { .. }
            | Reply::KittyFlags(_)
            | Reply::UnderlineStyles => {}
        }
    }

    fn queue_events(&mut self, now: Instant, events: Vec<InputEvent>) {
        let size: usize = events.iter().map(InputEvent::wire_len).sum();
        if self.queued_input.saturating_add(size) > MAX_QUEUED_INPUT {
            // The server is not taking input; queueing more would grow without bound.
            if !self.input_paused {
                self.input_paused = true;
                self.dirty = true;
            }
            return;
        }
        // Predictions made now expire with the first input message that carries these events.
        let first = events.first().map_or(0, InputEvent::wire_len);
        let seq = match self.outgoing.back() {
            Some(ClientMsg::Keys {
                seq,
                events: queued,
            }) if fits(queued, first) => *seq,
            _ => self.last_seq.next(),
        };
        self.predictor.set_local_frame_sent(seq.0.saturating_sub(1));
        for event in &events {
            let screen = self.current.screen.screen();
            match event {
                InputEvent::Key(key) => self.predictor.new_user_key(key.stroke().press, screen),
                InputEvent::Mouse(_) | InputEvent::Focus(_) | InputEvent::Paste { .. } => {
                    self.predictor.new_user_other(screen);
                }
            }
        }
        for event in events {
            match self.outgoing.back_mut() {
                Some(ClientMsg::Keys { events: queued, .. }) if fits(queued, event.wire_len()) => {
                    queued.push(event);
                }
                _ => {
                    self.last_seq = self.last_seq.next();
                    self.outgoing.push_back(ClientMsg::Keys {
                        seq: self.last_seq,
                        events: vec![event],
                    });
                }
            }
        }
        self.queued_input = self.queued_input.saturating_add(size);
        self.last_nudge = Some(now);
        self.last_activity = Some(now);
        self.dirty = true;
    }

    /// Questions for the user's terminal the session has (the colours again, after the terminal
    /// reported a new scheme), for the caller to write.
    pub fn take_questions(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.ask)
    }

    /// What the user's terminal said of its colours, to tell the server now and to keep across
    /// reconnects; `None` if the user turned telling off (`--no-colours`) or the terminal said
    /// nothing. Known colours are told at once.
    pub fn set_colours(&mut self, colours: Option<WireColours>) {
        if let Some(colours) = colours.as_ref().filter(|c| c.known()) {
            self.outgoing.push_back(ClientMsg::Colours(colours.clone()));
        }
        self.colours = colours.map(|mut c| {
            c.palette.resize(PALETTE, None);
            c
        });
    }

    /// The colours as last learned, for the next connection.
    pub fn colours(&self) -> Option<WireColours> {
        self.colours.clone()
    }

    /// Queue a new window size; it voids the predictions.
    pub fn on_resize(&mut self, size: Size) {
        // Only the last of several unsent resizes matters.
        if let Some(ClientMsg::Resize(queued)) = self.outgoing.back_mut() {
            *queued = size;
        } else {
            self.outgoing.push_back(ClientMsg::Resize(size));
        }
        self.rows = size.rows;
        self.predictor.reset();
        self.dirty = true;
    }

    /// A frame's stream arrived: its body inflated against its base's dictionary, then applied as
    /// [`on_frame`](Self::on_frame) does. A frame on a base not held asks for a resync; one that
    /// does not inflate or decode is dropped, as a lost one would be.
    pub fn on_frame_stream(&mut self, now: Instant, base: FrameNum, rows: &[u16], body: &[u8]) {
        self.last_heard = Some(now);
        let screen = if base == FrameNum::BLANK {
            Some(Arc::default())
        } else if base == self.current.num {
            Some(Arc::clone(&self.current.screen))
        } else {
            self.older
                .iter()
                .find(|older| older.num == base)
                .map(|older| Arc::clone(&older.screen))
        };
        let Some(screen) = screen else {
            if !self.resync_sent {
                self.resync_sent = true;
                self.outgoing.push_back(ClientMsg::Resync);
            }
            return;
        };
        let dictionary = dictionary_for(base, &screen, rows, &mut self.encodings);
        match decode_frame_body(base, body, &dictionary) {
            Ok(frame) => self.on_frame(now, &frame),
            Err(e) => tracing::debug!(error = %e, "dropping an undecodable frame"),
        }
    }

    /// A frame arrived: applied if newer and on a base held, else only proof the link lives.
    ///
    /// The client sends no acknowledgement: the server takes a frame's delivery as one. So a frame
    /// that arrives after a newer one, on a base held, is kept among the older screens, as the
    /// server may diff against it.
    pub fn on_frame(&mut self, now: Instant, frame: &Frame) {
        self.last_heard = Some(now);
        if frame.num <= self.current.num {
            self.keep_late(frame);
            return;
        }
        // The copy shares every row with the base; the frame replaces only its own.
        let base = if frame.base == FrameNum::BLANK {
            Some(TerminalScreen::default())
        } else if frame.base == self.current.num {
            Some(TerminalScreen::clone(&self.current.screen))
        } else {
            self.older
                .iter()
                .find(|older| older.num == frame.base)
                .map(|older| TerminalScreen::clone(&older.screen))
        };
        let Some(mut screen) = base else {
            if !self.resync_sent {
                self.resync_sent = true;
                self.outgoing.push_back(ClientMsg::Resync);
            }
            return;
        };
        screen.apply(&frame.diff);
        let previous = std::mem::replace(
            &mut self.current,
            FrameScreen {
                num: frame.num,
                screen: Arc::new(screen),
            },
        );
        self.older.push_back(previous);
        while self.older.len() >= FRAME_WINDOW || self.older_cells() > WINDOW_CELLS {
            self.older.pop_front();
        }
        self.resync_sent = false;
        self.echo_ack = self.echo_ack.max(frame.echo_ack);
        self.predictor.set_local_frame_late_acked(self.echo_ack.0);
        self.predictor.set_tty(self.current.screen.tty());
        self.predictor.cull(self.current.screen.screen());
        self.scrollback.on_mark(self.current.screen.history());
        self.last_activity = Some(now);
        self.dirty = true;
    }

    /// History rows arrived.
    pub fn on_history(&mut self, reply: &HistoryReply) {
        self.scrollback.on_reply(reply);
        if self.scrollback.viewing() {
            self.dirty = true;
        }
    }

    /// Keep `frame`, older than the current one, as a base, if its base is held and it is not.
    fn keep_late(&mut self, frame: &Frame) {
        let held = |num: FrameNum| {
            num == self.current.num || self.older.iter().any(|older| older.num == num)
        };
        if held(frame.num) {
            return;
        }
        let base = if frame.base == FrameNum::BLANK {
            Some(TerminalScreen::default())
        } else {
            self.older
                .iter()
                .chain(std::iter::once(&self.current))
                .find(|older| older.num == frame.base)
                .map(|older| TerminalScreen::clone(&older.screen))
        };
        let Some(mut screen) = base else {
            return;
        };
        screen.apply(&frame.diff);
        self.older.push_back(FrameScreen {
            num: frame.num,
            screen: Arc::new(screen),
        });
        while self.older.len() >= FRAME_WINDOW || self.older_cells() > WINDOW_CELLS {
            self.older.pop_front();
        }
    }

    /// The cells the older frames hold beyond the current one.
    fn older_cells(&self) -> usize {
        TerminalScreen::cells_beyond(
            &self.current.screen,
            self.older.iter().map(|older| &*older.screen),
        )
    }

    /// Advance to `now`: probe for unconfirmed input, and report the status banner.
    pub fn on_tick(&mut self, now: Instant, rtt: Option<Duration>) -> TickResult {
        // Unconfirmed input may be behind a lost packet: any later one (a repeated ack, which the
        // server ignores) lets QUIC retransmit at once instead of after its probe timeout.
        if self.echo_ack < self.last_seq
            && self
                .last_nudge
                .is_some_and(|at| now.saturating_duration_since(at) >= retry_after(rtt))
        {
            self.last_nudge = Some(now);
            if !self
                .outgoing
                .iter()
                .any(|m| matches!(m, ClientMsg::Ack { .. }))
            {
                self.outgoing.push_back(ClientMsg::Ack {
                    frame: self.current.num,
                });
            }
        }
        // The history the view shows, or the newest screenful once the client is idle.
        let idle = Scrollback::idle(now, self.last_activity) && self.synced();
        while let Some(request) = self.scrollback.next_request(self.rows, idle) {
            self.outgoing.push_back(ClientMsg::History(request));
        }
        let silent = self
            .last_heard
            .map(|heard| now.saturating_duration_since(heard));
        let status = match silent {
            Some(silent) if silent > LINK_DOWN_GRACE => {
                Some(format!("[koh] link down — resuming… {}s", silent.as_secs()))
            }
            _ if self.input_paused => {
                Some("[koh] input paused — the server is not taking input".to_owned())
            }
            _ if self
                .notice
                .as_ref()
                .is_some_and(|(_, at)| now.saturating_duration_since(*at) < NOTICE_FOR) =>
            {
                self.notice.as_ref().map(|(notice, _)| notice.clone())
            }
            _ => self.scrollback.status(),
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
        let sent = match &msg {
            ClientMsg::Input { bytes, .. } => Some(bytes.len()),
            ClientMsg::Keys { events, .. } => Some(events.iter().map(InputEvent::wire_len).sum()),
            ClientMsg::Resize(_)
            | ClientMsg::Ack { .. }
            | ClientMsg::Resync
            | ClientMsg::History(_)
            | ClientMsg::Colours(_) => None,
        };
        if let Some(sent) = sent {
            self.queued_input = self.queued_input.saturating_sub(sent);
            if self.input_paused && self.queued_input == 0 {
                self.input_paused = false;
                self.dirty = true;
            }
        }
        Some(msg)
    }

    /// Whether a frame reported that the shell exited (its code is on [`state`](Self::state)).
    pub fn exited(&self) -> bool {
        self.current.screen.exit_code().is_some()
    }

    /// The newest applied screen.
    pub fn state(&self) -> &TerminalScreen {
        &self.current.screen
    }

    /// The newest frame applied.
    pub const fn applied(&self) -> FrameNum {
        self.current.num
    }

    /// Whether a frame has been applied, so [`state`](Self::state) is the server's.
    pub fn synced(&self) -> bool {
        self.current.num > FrameNum::BLANK
    }

    /// Whether typing was being shown as it was predicted: the trust a reconnect to the same session
    /// carries ([`carry_trust`](Self::carry_trust)).
    pub fn trusted(&self) -> bool {
        self.synced() && self.predictor.trusted()
    }

    /// Trust typing as the last connection to the same session did, once the first frame shows no
    /// password prompt.
    pub fn carry_trust(&mut self) {
        self.predictor.carry_trust();
    }

    /// The prediction overlay to draw over [`state`](Self::state).
    pub fn overlay(&self) -> Overlay<'_> {
        self.predictor.overlay()
    }

    /// The screen to show in place of [`state`](Self::state), without the overlay: the scrollback
    /// view, while it is open.
    pub fn view(&self) -> Option<TerminalScreen> {
        self.scrollback.shown(&self.current.screen)
    }

    /// The history held and the view of it.
    pub const fn scrollback(&self) -> &Scrollback {
        &self.scrollback
    }

    /// The window state (title, icon, clipboard, bell) to mirror onto the real terminal.
    pub fn window_state(&self) -> WindowState<'_> {
        window_state(&self.current.screen)
    }

    /// The newest applied screen's grid.
    pub fn screen(&self) -> &Grid {
        self.current.screen.screen()
    }
}

/// Whether an event of `len` bytes fits in a queued `Keys` message holding `queued`.
fn fits(queued: &[InputEvent], len: usize) -> bool {
    queued.len() < MAX_EVENTS
        && queued
            .iter()
            .map(InputEvent::wire_len)
            .sum::<usize>()
            .saturating_add(len)
            <= MAX_INPUT_BYTES
}

/// What the server gets for one decoded input. A paste goes with every end marker in it removed,
/// as often as removing one makes another (so no piece, nor the pieces together, can end the
/// program's bracket), in pieces of at most [`MAX_PASTE_PIECE`] bytes split between characters.
fn events_of(input: Input, out: &mut Vec<InputEvent>) {
    match input {
        Input::Key(stroke) => out.push(InputEvent::Key(stroke.into())),
        Input::Mouse(event) => out.push(InputEvent::Mouse(event.into())),
        Input::FocusIn => out.push(InputEvent::Focus(true)),
        Input::FocusOut => out.push(InputEvent::Focus(false)),
        Input::Paste(text) => {
            let mut framed = Vec::with_capacity(text.len().saturating_add(12));
            paste(&text, true, &mut framed);
            let inner = framed
                .get(PASTE_START.len()..framed.len().saturating_sub(PASTE_END.len()))
                .unwrap_or_default();
            let text = String::from_utf8_lossy(inner);
            let mut rest: &str = &text;
            let mut first = true;
            loop {
                let mut cut = rest.len().min(MAX_PASTE_PIECE);
                while !rest.is_char_boundary(cut) {
                    cut = cut.saturating_sub(1);
                }
                let (piece, after) = rest.split_at(cut);
                out.push(InputEvent::Paste {
                    text: piece.to_owned(),
                    first,
                    last: after.is_empty(),
                });
                first = false;
                rest = after;
                if rest.is_empty() {
                    break;
                }
            }
        }
        Input::PasteTooLong | Input::Reply(_) => {}
    }
}

/// A key's legacy bytes, in normal cursor mode: its one form, which the escape prefix and its keys
/// are matched against whatever the user's terminal sent.
pub fn legacy_bytes(press: KeyPress) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8);
    key_bytes(press.into(), KeyMode::legacy(false), &mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{WireKey, WireKeyCode, WireMouse};
    use crate::terminal::ServerTerminal;

    fn start() -> (Instant, ClientSession) {
        let now = Instant::now();
        (
            now,
            ClientSession::new(DisplayPreference::Always, Size::new(24, 80)),
        )
    }

    fn screen(bytes: &[u8]) -> TerminalScreen {
        TerminalScreen::from_bytes(24, 80, bytes)
    }

    fn frame(
        num: u64,
        base: u64,
        echo_ack: u64,
        from: &TerminalScreen,
        to: &TerminalScreen,
    ) -> Frame {
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

    /// What a legacy program with nothing set gets for the input sent: keys as their legacy
    /// bytes, pastes as their text.
    fn typed(msgs: &[ClientMsg]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in msgs {
            match m {
                ClientMsg::Input { bytes, .. } => out.extend_from_slice(bytes),
                ClientMsg::Keys { events, .. } => {
                    for event in events {
                        match event {
                            InputEvent::Key(key) => {
                                out.extend_from_slice(&legacy_bytes(key.stroke().press));
                            }
                            InputEvent::Paste { text, .. } => {
                                out.extend_from_slice(text.as_bytes());
                            }
                            InputEvent::Mouse(_) | InputEvent::Focus(_) => {}
                        }
                    }
                }
                ClientMsg::Resize(_)
                | ClientMsg::Ack { .. }
                | ClientMsg::Resync
                | ClientMsg::History(_)
                | ClientMsg::Colours(_) => {}
            }
        }
        out
    }

    #[test]
    fn a_session_first_tells_the_server_its_window_size() {
        let (_, mut s) = start();
        assert_eq!(drain(&mut s), [ClientMsg::Resize(Size::new(24, 80))]);
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
        assert_eq!(typed(&drain(&mut s)), b"");
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
        let mut s = ClientSession::new(DisplayPreference::Never, Size::new(24, 80));
        let paste: Vec<u8> = (0..200_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        s.on_input(now, b"first");
        // A paste, bracketed by the terminal, goes in pieces; keys typed unbracketed, as events.
        s.on_input(now, &[&b"\x1b[200~"[..], &paste, b"\x1b[201~"].concat());
        s.on_input(now, &paste[..5000]);
        let msgs = drain(&mut s);
        let inputs: Vec<(InputSeq, usize)> = msgs
            .iter()
            .filter_map(|m| match m {
                ClientMsg::Keys { seq, events } => Some((*seq, events.len())),
                ClientMsg::Input { .. }
                | ClientMsg::Resize(_)
                | ClientMsg::Ack { .. }
                | ClientMsg::Resync
                | ClientMsg::History(_)
                | ClientMsg::Colours(_) => None,
            })
            .collect();
        assert!(inputs.iter().all(|&(_, len)| len <= MAX_EVENTS));
        let seqs: Vec<u64> = inputs.iter().map(|(seq, _)| seq.0).collect();
        assert_eq!(
            seqs,
            (1..=u64::try_from(seqs.len()).unwrap()).collect::<Vec<_>>()
        );
        assert_eq!(
            typed(&msgs),
            [b"first".as_slice(), &paste, &paste[..5000]].concat()
        );
        let pieces: Vec<(usize, bool, bool)> = msgs
            .iter()
            .filter_map(|m| match m {
                ClientMsg::Keys { events, .. } => Some(events),
                ClientMsg::Input { .. }
                | ClientMsg::Resize(_)
                | ClientMsg::Ack { .. }
                | ClientMsg::Resync
                | ClientMsg::History(_)
                | ClientMsg::Colours(_) => None,
            })
            .flatten()
            .filter_map(|e| match e {
                InputEvent::Paste { text, first, last } => Some((text.len(), *first, *last)),
                InputEvent::Key(_) | InputEvent::Mouse(_) | InputEvent::Focus(_) => None,
            })
            .collect();
        assert_eq!(
            pieces,
            [
                (MAX_PASTE_PIECE, true, false),
                (MAX_PASTE_PIECE, false, false),
                (MAX_PASTE_PIECE, false, false),
                (200_000 - 3 * MAX_PASTE_PIECE, false, true)
            ]
        );
    }

    #[test]
    fn typing_past_the_queue_limit_is_dropped_and_reported_until_it_drains() {
        // Queueing, not prediction, is under test; skip predicting a megabyte byte by byte.
        let now = Instant::now();
        let mut s = ClientSession::new(DisplayPreference::Never, Size::new(24, 80));
        // Pastes, as a terminal in bracketed paste sends them.
        let chunk = [
            &b"\x1b[200~"[..],
            &vec![b'z'; MAX_INPUT_BYTES],
            b"\x1b[201~",
        ]
        .concat();
        for _ in 0..MAX_QUEUED_INPUT.div_euclid(MAX_INPUT_BYTES) {
            s.on_input(now, &chunk);
        }
        assert!(
            s.on_tick(now, None).status.is_none(),
            "the queue is full, not over"
        );
        s.on_input(now, b"dropped");
        let status = s.on_tick(now, None).status.expect("input paused banner");
        assert!(status.contains("input paused"), "{status}");
        let queued = typed(&drain(&mut s));
        assert_eq!(
            queued.len(),
            MAX_QUEUED_INPUT,
            "the dropped bytes were not queued"
        );
        assert!(
            s.on_tick(now, None).status.is_none(),
            "draining clears the banner"
        );
    }

    #[test]
    fn frames_apply_against_a_held_base_and_send_no_acknowledgement() {
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
        // The server takes a frame's delivery as its acknowledgement.
        assert_eq!(drain(&mut s), []);
        assert_eq!(s.applied(), FrameNum(2));
    }

    #[test]
    fn a_frame_that_arrives_after_a_newer_one_is_kept_as_a_base() {
        let (now, mut s) = start();
        drain(&mut s);
        let blank = TerminalScreen::default();
        let one = screen(b"one");
        let two = screen(b"two");
        let three = screen(b"three");
        s.on_frame(now, &frame(2, 0, 0, &blank, &two));
        // Frame 1 is delivered late; the server, told of its delivery, may diff against it.
        s.on_frame(now, &frame(1, 0, 0, &blank, &one));
        assert!(
            s.screen().contents().contains("two"),
            "the newer stays shown"
        );
        s.on_frame(now, &frame(3, 1, 0, &one, &three));
        assert!(s.screen().contents().contains("three"));
        assert_eq!(drain(&mut s), [], "no resync: frame 1 was kept");
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
        assert_eq!(
            drain(&mut s),
            [ClientMsg::Resync],
            "one resync, not one per frame"
        );
        s.on_frame(now, &frame(7, 0, 0, &blank, &one));
        assert!(s.screen().contents().contains("one"));
        s.on_frame(now, &frame(8, 3, 0, &one, &one));
        assert_eq!(drain(&mut s), [ClientMsg::Resync]);
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
        assert!(
            s.screen().contents().contains("target"),
            "a kept base applies"
        );
    }

    /// A screen of the largest size a server may send, with text on every row.
    fn largest_full() -> TerminalScreen {
        let max = crate::terminal::MAX_DIM;
        let mut emu = ServerTerminal::new(max, max, 0).expect("emulator");
        let rows: Vec<String> = (0..max).map(|row| format!("row {row}")).collect();
        emu.process(rows.join("\r\n").as_bytes());
        emu.snapshot()
    }

    #[test]
    fn older_frames_hold_at_most_one_largest_screen_beyond_the_current_one() {
        // A server that sends only full repaints of the largest screen, each from the blank base
        // so no row is shared: fifteen older copies of it were about 480 MB.
        let (now, mut s) = start();
        let big = largest_full();
        let repaint = big.diff_from(&TerminalScreen::default());
        for n in 1..=20 {
            s.on_frame(
                now,
                &Frame {
                    num: FrameNum(n),
                    base: FrameNum::BLANK,
                    echo_ack: InputSeq(0),
                    diff: repaint.clone(),
                },
            );
            assert!(s.older_cells() <= WINDOW_CELLS, "after frame {n}");
        }
        assert_eq!(
            s.older.len(),
            1,
            "one largest screen besides the current one"
        );
        assert_eq!(s.older_cells(), WINDOW_CELLS);
        assert_eq!(s.state(), &big);
        drain(&mut s);
        // A frame on a dropped base still asks for a resync; one on the kept base applies.
        s.on_frame(now, &frame(21, 5, 0, &big, &big));
        assert_eq!(drain(&mut s), [ClientMsg::Resync]);
        s.on_frame(now, &frame(22, 19, 0, &big, &big));
        assert_eq!(drain(&mut s), []);
        assert_eq!(s.applied(), FrameNum(22));
    }

    #[test]
    fn older_frames_share_the_rows_they_have_in_common() {
        // Frames that each change a row keep the whole window: the rows the current screen still
        // shows are shared with it, so the older frames cost nothing beyond it.
        let (now, mut s) = start();
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
        let mut prev = TerminalScreen::default();
        for n in 1..=20 {
            emu.process(format!("line {n}\r\n").as_bytes());
            let next = emu.snapshot();
            s.on_frame(now, &frame(n, n - 1, 0, &prev, &next));
            prev = next;
        }
        assert_eq!(s.older.len(), FRAME_WINDOW - 1);
        assert_eq!(s.older_cells(), 0);
        assert_eq!(s.state(), &prev);
    }

    #[test]
    fn a_window_of_scrolled_frames_costs_one_screen_and_the_new_rows() {
        // Output scrolling a line a frame on a screen a quarter of the budget: the rows that only
        // moved stay shared, so the whole window is kept where copies would allow four frames.
        let (now, mut s) = start();
        let (rows, cols) = (500, 500);
        let mut emu = ServerTerminal::new(rows, cols, 0).expect("emulator");
        let lines: Vec<String> = (0..rows).map(|row| format!("line {row}")).collect();
        emu.process(lines.join("\r\n").as_bytes());
        let mut prev = emu.snapshot();
        s.on_frame(now, &frame(1, 0, 0, &TerminalScreen::default(), &prev));
        for n in 2..=20 {
            emu.process(format!("\r\nline {n}").as_bytes());
            let next = emu.snapshot();
            let frame = frame(n, n - 1, 0, &prev, &next);
            assert_eq!(frame.diff.shifts.iter().count(), 1, "frame {n}");
            s.on_frame(now, &frame);
            assert_eq!(s.state(), &next);
            prev = next;
        }
        assert_eq!(s.older.len(), FRAME_WINDOW - 1);
        // Per frame, the row that scrolled off and the one written.
        let screens = std::iter::once(&*s.current.screen).chain(s.older.iter().map(|f| &*f.screen));
        let distinct = TerminalScreen::distinct_cells(screens);
        assert!(
            distinct <= (usize::from(rows) + 2 * FRAME_WINDOW) * usize::from(cols),
            "{distinct} cells"
        );
        assert!(4 * usize::from(rows) * usize::from(cols) <= WINDOW_CELLS);
    }

    #[test]
    fn a_frame_confirms_echoed_predictions() {
        let (now, mut s) = start();
        s.on_input(now, b"x");
        assert!(
            s.overlay().is_empty(),
            "the first keystroke stays hidden until confirmed"
        );
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
            s.overlay().cell(0, 1).map(|c| c.glyph),
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
        s.on_frame(
            now,
            &frame(1, 0, 0, &TerminalScreen::default(), &screen(b"$ ")),
        );
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
        assert_eq!(
            drain(&mut s),
            [ClientMsg::Ack {
                frame: FrameNum::BLANK
            }]
        );
        s.on_tick(now + retry + Duration::from_millis(1), rtt);
        assert!(drain(&mut s).is_empty(), "one probe per retry interval");
        // The echo-ack confirms the input: no more probes.
        let echoed = screen(b"a");
        s.on_frame(
            now + retry,
            &frame(1, 0, 1, &TerminalScreen::default(), &echoed),
        );
        drain(&mut s);
        s.on_tick(now + retry * 4, rtt);
        assert!(drain(&mut s).is_empty(), "confirmed input is not probed");
    }

    #[test]
    fn resizes_coalesce_and_reset_the_predictor() {
        let (now, mut s) = start();
        s.on_resize(Size::new(30, 100));
        s.on_resize(Size::new(40, 120));
        s.on_input(now, b"a");
        s.on_resize(Size::new(50, 132));
        assert_eq!(
            drain(&mut s),
            [
                ClientMsg::Resize(Size::new(40, 120)),
                ClientMsg::Keys {
                    seq: InputSeq(1),
                    events: vec![InputEvent::Key(WireKey {
                        key: WireKeyCode::Char('a'),
                        mods: 0,
                        kitty: None,
                    })],
                },
                ClientMsg::Resize(Size::new(50, 132)),
            ]
        );
        assert!(s.overlay().is_empty(), "a resize drops predictions");
        assert!(s.dirty);
    }

    /// The events sent, in order.
    fn events(msgs: &[ClientMsg]) -> Vec<InputEvent> {
        msgs.iter()
            .filter_map(|m| match m {
                ClientMsg::Keys { events, .. } => Some(events.clone()),
                ClientMsg::Input { .. }
                | ClientMsg::Resize(_)
                | ClientMsg::Ack { .. }
                | ClientMsg::Resync
                | ClientMsg::History(_)
                | ClientMsg::Colours(_) => None,
            })
            .flatten()
            .collect()
    }

    fn key(press: &str) -> InputEvent {
        InputEvent::Key(WireKey::from(Keystroke::from(
            press.parse::<KeyPress>().expect("a key name"),
        )))
    }

    #[test]
    fn a_kitty_terminals_keys_go_as_it_told_them() {
        let (now, mut s) = start();
        drain(&mut s);
        // Ctrl-I and Tab, which legacy bytes cannot tell apart, and Shift-Enter.
        s.on_input(now, b"\x1b[105;5u\t\x1b[13;2u");
        let sent = events(&drain(&mut s));
        assert_eq!(sent.len(), 3);
        let InputEvent::Key(ctrl_i) = sent[0] else {
            panic!("{sent:?}")
        };
        assert_eq!(ctrl_i.key, WireKeyCode::Char('i'));
        assert_eq!(ctrl_i.mods, 4);
        assert_eq!(sent[1], key("Tab"));
        let InputEvent::Key(shift_enter) = sent[2] else {
            panic!("{sent:?}")
        };
        assert_eq!((shift_enter.key, shift_enter.mods), (WireKeyCode::Enter, 1));
    }

    #[test]
    fn the_escape_prefix_works_from_a_kitty_terminal() {
        let (now, mut s) = start();
        // Ctrl-6 is the prefix from a kitty terminal, `.` quits.
        assert_eq!(s.on_input(now, b"\x1b[54;5u."), InputOutcome::Quit);
        let (now, mut s) = start();
        assert_eq!(
            s.on_input(now, b"\x1b[54;5u\x1b[122;5u"),
            InputOutcome::Suspend
        );
        // The prefix and another key: both go on, the prefix as it was typed.
        let (now, mut s) = start();
        drain(&mut s);
        s.on_input(now, b"\x1b[54;5ux");
        let sent = events(&drain(&mut s));
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1], key("x"));
    }

    #[test]
    fn mouse_and_focus_go_as_events_and_a_lone_escape_after_its_wait() {
        let (now, mut s) = start();
        drain(&mut s);
        s.on_input(now, b"\x1b[<0;10;5M\x1b[I\x1b[O");
        let sent = events(&drain(&mut s));
        assert!(
            matches!(
                sent.as_slice(),
                [
                    InputEvent::Mouse(WireMouse { row: 4, col: 9, .. }),
                    InputEvent::Focus(true),
                    InputEvent::Focus(false)
                ]
            ),
            "{sent:?}"
        );
        // A lone Escape may begin a sequence: it waits for its deadline, then goes.
        s.on_input(now, b"\x1b");
        assert_eq!(events(&drain(&mut s)), []);
        let deadline = s.deadline().expect("waiting on the Escape");
        assert_eq!(s.on_timeout(now), InputOutcome::Forwarded);
        assert!(events(&drain(&mut s)).is_empty(), "not before the deadline");
        s.on_timeout(deadline);
        assert_eq!(events(&drain(&mut s)), [key("Escape")]);
        assert_eq!(s.deadline(), None);
    }

    #[test]
    fn the_scrollback_view_takes_decoded_keys_and_the_wheel() {
        let (now, mut s) = start();
        s.scrollback.on_mark(crate::terminal::HistoryMark {
            newest: 1000,
            len: 100,
        });
        s.on_input(now, &[ESCAPE_PREFIX, SCROLLBACK_KEY]);
        assert!(s.view().is_some());
        drain(&mut s);
        // From a kitty terminal: Page Up as `CSI 5 ~`, the wheel, `q` to leave.
        s.on_input(now, b"\x1b[5~\x1b[<64;1;1M");
        assert_eq!(s.scrollback.offset(), Some(26));
        s.on_input(now, b"q");
        assert!(s.view().is_none());
        assert!(
            events(&drain(&mut s)).is_empty(),
            "the view's keys go nowhere else"
        );
    }

    #[test]
    fn colours_are_told_on_connecting_and_again_on_a_new_scheme() {
        let (now, mut s) = start();
        let colours = WireColours {
            background: Some([0x1e, 0x1e, 0x20]),
            scheme: Some(WireScheme::Dark),
            ..WireColours::default()
        };
        s.set_colours(Some(colours.clone()));
        let sent = drain(&mut s);
        assert_eq!(sent.get(1), Some(&ClientMsg::Colours(colours)));
        // The terminal reports a light scheme: its colours are asked again, and told once DA1,
        // the round's last answer, is in.
        s.on_input(now, b"\x1b[?997;2n");
        assert_eq!(s.take_questions(), COLOUR_QUERIES);
        assert_eq!(drain(&mut s), []);
        s.on_input(
            now,
            b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\\x1b]4;1;rgb:cd/00/00\x07\x1b[?62c",
        );
        let told = drain(&mut s);
        let [ClientMsg::Colours(told)] = told.as_slice() else {
            panic!("{told:?}")
        };
        assert_eq!(told.background, Some([0xff, 0xff, 0xff]));
        assert_eq!(told.scheme, Some(WireScheme::Light));
        assert_eq!(told.palette.get(1), Some(&Some([0xcd, 0, 0])));
        assert_eq!(s.colours().as_ref(), Some(told));
        // Not told, nothing is asked or sent.
        let (now, mut s) = start();
        s.set_colours(None);
        s.on_input(now, b"\x1b[?997;2n");
        assert_eq!(s.take_questions(), b"");
        assert_eq!(drain(&mut s), [ClientMsg::Resize(Size::new(24, 80))]);
    }

    #[test]
    fn a_paste_too_long_is_dropped_and_said() {
        let (now, mut s) = start();
        drain(&mut s);
        let long = [
            &b"\x1b[200~"[..],
            &vec![b'x'; MAX_QUEUED_INPUT + 1],
            b"\x1b[201~k",
        ]
        .concat();
        s.on_input(now, &long);
        assert_eq!(events(&drain(&mut s)), [key("k")]);
        let status = s.on_tick(now, None).status.expect("a notice");
        assert!(status.contains("paste over 1 MiB"), "{status}");
        assert!(s
            .on_tick(now + NOTICE_FOR, None)
            .status
            .is_none_or(|s| !s.contains("paste")));
    }

    /// fux-vt's decoder ends a paste at `ESC [ 201 ~`; the C1 form of it, U+009B `201~`, can be in
    /// a paste's text, and the client removes it (as often as removing one makes another) before
    /// the paste leaves.
    #[test]
    fn a_pastes_end_markers_are_removed_before_it_is_sent() {
        let (now, mut s) = start();
        drain(&mut s);
        s.on_input(
            now,
            "\x1b[200~a\u{9b}201~b\u{9b}20\u{9b}201~1~c\x1b[201~".as_bytes(),
        );
        assert_eq!(
            events(&drain(&mut s)),
            [InputEvent::Paste {
                text: "abc".to_owned(),
                first: true,
                last: true
            }]
        );
    }
}
