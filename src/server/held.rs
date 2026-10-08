//! What the server takes the client to hold: the newest frame delivered to it, which every frame is
//! diffed against, and the frames sent since. Delivery stands for the client's acknowledgement, so
//! a `Resync` (the client lacked a frame's base) forgets all of it at once: a delivery heard after
//! the forget is of a frame sent before it, which is no longer found.

use std::collections::VecDeque;

use crate::proto::{FrameNum, FrameScreen, FRAME_WINDOW, WINDOW_CELLS};
use crate::terminal::TerminalScreen;

/// The frames the client is taken to hold. Starts, and starts again at a `Resync`, as the blank
/// frame 0.
#[derive(Default)]
pub(super) struct ClientHolds {
    /// The newest frame delivered, and its screen: the base of every frame sent.
    acked: FrameScreen,
    /// Frames sent since, oldest first: at most `FRAME_WINDOW`, holding at most [`WINDOW_CELLS`]
    /// cells together unless the newest alone is more, so a client that never acknowledges cannot
    /// make the server hold sixteen of the largest screens. The newest is always kept.
    sent: VecDeque<FrameScreen>,
}

impl ClientHolds {
    /// The frame the next one is diffed against.
    pub(super) const fn base(&self) -> &FrameScreen {
        &self.acked
    }

    /// The newest frame sent, or the base if none was since.
    pub(super) fn newest(&self) -> &FrameScreen {
        self.sent.back().unwrap_or(&self.acked)
    }

    /// `frame` was sent.
    pub(super) fn sent(&mut self, frame: FrameScreen) {
        self.sent.push_back(frame);
        while self.sent.len() > FRAME_WINDOW
            || (self.sent.len() > 1 && distinct_cells(&self.sent) > WINDOW_CELLS)
        {
            self.sent.pop_front();
        }
    }

    /// Frame `num` was delivered, so it is the base and older frames are no bases any more. A
    /// frame no longer held, or sent before the last [`forget`](Self::forget), is ignored.
    pub(super) fn delivered(&mut self, num: FrameNum) {
        let Some(pos) = self.sent.iter().position(|sent| sent.num == num) else {
            return;
        };
        let mut rest = self.sent.split_off(pos);
        if let Some(acked) = rest.pop_front() {
            self.acked = acked;
        }
        self.sent = rest;
    }

    /// The client holds nothing: diff against the blank screen until a frame sent from now on is
    /// delivered.
    pub(super) fn forget(&mut self) {
        *self = Self::default();
    }

    /// The frames sent and not yet delivered.
    #[cfg(test)]
    pub(super) const fn window(&self) -> &VecDeque<FrameScreen> {
        &self.sent
    }
}

/// The cells the screens of `frames` hold in memory, a row several of them share counted once.
pub(super) fn distinct_cells(frames: &VecDeque<FrameScreen>) -> usize {
    TerminalScreen::distinct_cells(frames.iter().map(|frame| &*frame.screen))
}
