//! What one connection holds: the frames it applied, which are the bases the server may diff
//! against, what its server echoed, and when it was heard.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use crate::proto::{ClientMsg, Frame, FrameNum, FrameScreen, InputSeq, FRAME_WINDOW, WINDOW_CELLS};
use crate::terminal::{RowEncodings, TerminalScreen};

/// One connection's frames and echo. Only [`ClientSession::new`](super::session::ClientSession::new)
/// and [`ClientSession::attach`](super::session::ClientSession::attach) make one.
pub(super) struct Link {
    /// The newest applied frame and its screen.
    current: FrameScreen,
    /// The frames applied before it, oldest first: at most `FRAME_WINDOW - 1`, holding at most
    /// [`WINDOW_CELLS`] cells beyond `current`'s.
    older: VecDeque<FrameScreen>,
    /// The newest base a frame came on that was not held. A frame on it, or on an older one, was
    /// sent before the server read the `Resync` that refusal owed, which forgets them all. This
    /// holds because a `Link` is one connection's, to one server session, whose frame numbers only
    /// rise: [`ClientSession::attach`](super::session::ClientSession::attach) makes a new one for
    /// each connection, so numbers from another never meet it.
    refused: FrameNum,
    /// A `Resync` is owed to this connection's server and not yet taken to be sent. It lives here,
    /// beside `refused`, so the two go together: one is never dropped while the other stays.
    resync_owed: bool,
    /// The newest input the server has reported reflected on screen.
    pub(super) echo_ack: InputSeq,
    /// When the server was last heard from; `None` until the first frame.
    pub(super) last_heard: Option<Instant>,
    /// When input was last queued or probed for, while some is unconfirmed.
    pub(super) last_nudge: Option<Instant>,
    /// When the newest frame moved the cursor to another row: a fresh prompt, whose program may
    /// still turn echo off. Keys typed within `PROMPT_HOLD` of it are shown only once echoed.
    pub(super) new_row_at: Option<Instant>,
    /// Rows' encodings, kept from one frame's dictionary to the next.
    pub(super) encodings: RowEncodings,
}

impl Link {
    /// A link on which nothing has arrived, showing `screen` until its first frame (which, on
    /// the blank base, builds from nothing), with input up to `echo_ack` taken as handled.
    pub(super) fn fresh(screen: Arc<TerminalScreen>, echo_ack: InputSeq) -> Self {
        Self {
            current: FrameScreen {
                num: FrameNum::BLANK,
                screen,
            },
            older: VecDeque::new(),
            refused: FrameNum::BLANK,
            resync_owed: false,
            echo_ack,
            last_heard: None,
            last_nudge: None,
            new_row_at: None,
            encodings: RowEncodings::default(),
        }
    }

    /// The newest applied frame and its screen.
    pub(super) const fn current(&self) -> &FrameScreen {
        &self.current
    }

    /// The screen of frame `num`, if it is held as a base: the blank one, the current one or an
    /// older one.
    pub(super) fn base(&self, num: FrameNum) -> Option<Arc<TerminalScreen>> {
        if num == FrameNum::BLANK {
            return Some(Arc::default());
        }
        self.older
            .iter()
            .chain(std::iter::once(&self.current))
            .find(|held| held.num == num)
            .map(|held| Arc::clone(&held.screen))
    }

    /// `frame` applied to its base, if that is held.
    pub(super) fn applied(&self, frame: &Frame) -> Option<FrameScreen> {
        // The copy shares every row with the base; the frame replaces only its own.
        let mut screen = Arc::unwrap_or_clone(self.base(frame.base)?);
        screen.apply(&frame.diff);
        Some(FrameScreen {
            num: frame.num,
            screen: Arc::new(screen),
        })
    }

    /// `frame`, newer than the current one, applied: it is current, and the current one older.
    pub(super) fn advance(&mut self, frame: FrameScreen) {
        let previous = std::mem::replace(&mut self.current, frame);
        self.keep(previous);
    }

    /// Keep `frame`, older than the current one, as a base, if its base is held and it is not:
    /// the server, told of its delivery, may diff against it.
    pub(super) fn keep_late(&mut self, frame: &Frame) {
        if frame.num == self.current.num || self.older.iter().any(|old| old.num == frame.num) {
            return;
        }
        if let Some(late) = self.applied(frame) {
            self.keep(late);
        }
    }

    /// Keep `frame` among the older ones, the oldest dropped past the window.
    fn keep(&mut self, frame: FrameScreen) {
        self.older.push_back(frame);
        while self.older.len() >= FRAME_WINDOW || self.older_cells() > WINDOW_CELLS {
            self.older.pop_front();
        }
    }

    /// A frame came on `base`, which is not held: a `Resync` is owed, unless one was for this
    /// base or a newer one. The server forgets every frame at a `Resync`, and numbers every later
    /// one above all it sent before, so a base at or below one refused was sent before it read
    /// the `Resync` and is covered by it; a newer one asks again. At most one is owed at a time,
    /// whatever the server sends.
    pub(super) fn refuse(&mut self, base: FrameNum) {
        if base > self.refused {
            self.refused = base;
            self.resync_owed = true;
        }
    }

    /// The connection is gone: the `Resync` owed to it, and the refusal that owed it, go with it.
    pub(super) const fn drop_resync(&mut self) {
        self.refused = FrameNum::BLANK;
        self.resync_owed = false;
    }

    /// Whether a `Resync` is owed and not yet taken.
    pub(super) const fn owes_resync(&self) -> bool {
        self.resync_owed
    }

    /// The owed `Resync`, taken to be sent.
    pub(super) fn take_resync(&mut self) -> Option<ClientMsg> {
        std::mem::take(&mut self.resync_owed).then_some(ClientMsg::Resync)
    }

    /// The cells the older frames hold beyond the current one.
    pub(super) fn older_cells(&self) -> usize {
        TerminalScreen::cells_beyond(
            &self.current.screen,
            self.older.iter().map(|older| &*older.screen),
        )
    }

    /// The frames applied before the current one.
    #[cfg(test)]
    pub(super) const fn older(&self) -> &VecDeque<FrameScreen> {
        &self.older
    }
}
