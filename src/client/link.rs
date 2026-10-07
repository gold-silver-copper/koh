//! What one connection holds: the frames it applied, which are the bases the server may diff
//! against, what its server echoed, and when it was heard.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use crate::proto::{ClientMsg, FrameNum, FrameScreen, InputSeq, FRAME_WINDOW, WINDOW_CELLS};
use crate::terminal::{RowEncodings, TerminalScreen};

/// One connection's frames and echo. Only [`ClientSession::new`](super::session::ClientSession::new)
/// and [`ClientSession::attach`](super::session::ClientSession::attach) make one.
pub(super) struct Link {
    /// The newest applied frame and its screen.
    current: FrameScreen,
    /// The frames applied before it, oldest first: at most `FRAME_WINDOW - 1`, holding at most
    /// [`WINDOW_CELLS`] cells beyond `current`'s.
    older: VecDeque<FrameScreen>,
    /// The last base a frame came on that was not held, for which a `Resync` was sent.
    refused: Option<FrameNum>,
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
            refused: None,
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

    /// Whether frame `num` is the current one or an older one.
    pub(super) fn holds(&self, num: FrameNum) -> bool {
        num == self.current.num || self.older.iter().any(|older| older.num == num)
    }

    /// `frame`, newer than the current one, applied: it is current, and the current one older.
    pub(super) fn advance(&mut self, frame: FrameScreen) {
        let previous = std::mem::replace(&mut self.current, frame);
        self.keep(previous);
    }

    /// Keep `frame` among the older ones, the oldest dropped past the window.
    pub(super) fn keep(&mut self, frame: FrameScreen) {
        self.older.push_back(frame);
        while self.older.len() >= FRAME_WINDOW || self.older_cells() > WINDOW_CELLS {
            self.older.pop_front();
        }
    }

    /// A frame came on `base`, which is not held: the `Resync` to send, unless one was sent for
    /// it. The server forgets every base at a `Resync`, so a base refused once never comes back,
    /// and every other one asks again.
    pub(super) fn refuse(&mut self, base: FrameNum) -> Option<ClientMsg> {
        (self.refused.replace(base) != Some(base)).then_some(ClientMsg::Resync)
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
