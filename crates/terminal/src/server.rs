//! The server-side live terminal emulator: a long-lived `vt100::Parser` fed by the PTY,
//! plus the echo-ack debounce that tells the client which of its keystrokes are now visible.

use rmosh_ssp::NEVER;

use crate::{TerminalScreen, ECHO_TIMEOUT_MS};

/// Captures window title / icon / bell from `vt100`'s callback stream (none are stored on
/// `Screen` itself).
#[derive(Default)]
struct Callbacks {
    title: String,
    icon: String,
    bell_count: u64,
}

impl vt100::Callbacks for Callbacks {
    fn set_window_title(&mut self, _: &mut vt100::Screen, t: &[u8]) {
        self.title = String::from_utf8_lossy(t).into_owned();
    }
    fn set_window_icon_name(&mut self, _: &mut vt100::Screen, n: &[u8]) {
        self.icon = String::from_utf8_lossy(n).into_owned();
    }
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        self.bell_count += 1;
    }
}

/// The server's authoritative terminal. Owns the live parser (which is not `Clone`) and
/// produces a [`TerminalScreen`] snapshot for the SSP transport each tick.
pub struct ServerTerminal {
    parser: vt100::Parser<Callbacks>,
    scrollback: usize,
    /// The newest input frame number whose effects are considered on-screen.
    echo_ack: u64,
    /// Pending `(input_frame_num, arrival_timestamp_ms)`, oldest first.
    input_history: Vec<(u64, u64)>,
}

impl ServerTerminal {
    pub fn new(rows: u16, cols: u16, scrollback: usize) -> Self {
        ServerTerminal {
            parser: vt100::Parser::new_with_callbacks(rows, cols, scrollback, Callbacks::default()),
            scrollback,
            echo_ack: 0,
            input_history: Vec::new(),
        }
    }

    /// Feed a chunk of the child shell's output into the screen model.
    pub fn process(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    /// Resize the emulated screen (after applying a client resize to the PTY).
    pub fn resize(&mut self, rows: u16, cols: u16) {
        self.parser.screen_mut().set_size(rows, cols);
    }

    /// `(rows, cols)`.
    pub fn size(&self) -> (u16, u16) {
        self.parser.screen().size()
    }

    /// Record that user-input frame `n` arrived at `now` (ms). The screen has had no time to
    /// reflect it yet; [`set_echo_ack`](Self::set_echo_ack) promotes it after the debounce.
    pub fn register_input_frame(&mut self, n: u64, now: u64) {
        // Frame numbers only advance; ignore stale/duplicate registrations.
        if self.input_history.last().map(|(f, _)| n > *f).unwrap_or(true) {
            self.input_history.push((n, now));
        }
    }

    /// Promote `echo_ack` to the newest input frame that arrived at least `ECHO_TIMEOUT_MS`
    /// ago (so the shell has had time to echo it). Returns whether it changed. Mosh
    /// `Complete::set_echo_ack`.
    pub fn set_echo_ack(&mut self, now: u64) -> bool {
        let cutoff = now.saturating_sub(ECHO_TIMEOUT_MS);
        let mut newest = self.echo_ack;
        for &(frame, ts) in &self.input_history {
            if ts <= cutoff {
                newest = newest.max(frame);
            }
        }
        // Drop history entries strictly older than the new echo_ack (keep it and newer).
        self.input_history.retain(|&(frame, _)| frame >= newest);
        let changed = self.echo_ack != newest;
        self.echo_ack = newest;
        changed
    }

    /// Milliseconds until [`set_echo_ack`] could next advance, or [`NEVER`] if nothing pends.
    /// Mosh `Complete::wait_time`.
    pub fn echo_ack_wait_time(&self, now: u64) -> u64 {
        if self.input_history.len() < 2 {
            return NEVER;
        }
        let fire_at = self.input_history[1].1 + ECHO_TIMEOUT_MS;
        fire_at.saturating_sub(now)
    }

    /// The current echo-ack value.
    pub fn echo_ack(&self) -> u64 {
        self.echo_ack
    }

    /// Window title set by the shell (OSC 2), if any.
    pub fn title(&self) -> &str {
        &self.parser.callbacks().title
    }

    /// Window icon name set by the shell (OSC 1), if any.
    pub fn icon_name(&self) -> &str {
        &self.parser.callbacks().icon
    }

    /// Number of audible bells seen so far.
    pub fn bell_count(&self) -> u64 {
        self.parser.callbacks().bell_count
    }

    /// Scrollback length this emulator was built with.
    pub fn scrollback(&self) -> usize {
        self.scrollback
    }

    /// Produce the SSP snapshot the transport will diff and ship.
    pub fn snapshot(&self) -> TerminalScreen {
        TerminalScreen {
            screen: self.parser.screen().clone(),
            echo_ack: self.echo_ack,
            title: self.parser.callbacks().title.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_ack_debounces() {
        let mut t = ServerTerminal::new(24, 80, 0);
        t.register_input_frame(5, 1000);
        // Too soon: nothing within the debounce window.
        assert!(!t.set_echo_ack(1010));
        assert_eq!(t.echo_ack(), 0);
        // After 50ms the frame is considered echoed.
        assert!(t.set_echo_ack(1050));
        assert_eq!(t.echo_ack(), 5);
    }

    #[test]
    fn echo_ack_is_monotonic_and_takes_newest() {
        let mut t = ServerTerminal::new(24, 80, 0);
        t.register_input_frame(3, 1000);
        t.register_input_frame(7, 1005);
        t.set_echo_ack(1100); // both older than 50ms -> newest = 7
        assert_eq!(t.echo_ack(), 7);
    }

    #[test]
    fn title_and_bell_captured() {
        let mut t = ServerTerminal::new(24, 80, 0);
        t.process(b"\x1b]2;my-title\x07\x07");
        assert_eq!(t.title(), "my-title");
        assert_eq!(t.bell_count(), 1);
        assert_eq!(t.snapshot().title(), "my-title");
    }
}
