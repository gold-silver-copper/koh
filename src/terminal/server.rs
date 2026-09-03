//! The server-side live terminal emulator: a long-lived `vt100::Parser` fed by the PTY,
//! plus the terminal queries it answers on the host's behalf. The echo-ack debounce that tells the
//! client which of its keystrokes are now visible lives per connection in `server` (KS-02).

use crate::terminal::{clamp_dims, TerminalScreen, MAXIMUM_CLIPBOARD_SIZE, MAX_TITLE_LEN};

/// A ConEmu / Windows Terminal progress report from the hosted app (KO-01).
///
/// `OSC 9;4;<state>;<percent> ST`: `state` is 0 = clear, 1 = normal, 2 = error, 3 = indeterminate,
/// 4 = warning; `percent` is 0..=100. Host-side only — it never rides the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub state: u8,
    pub percent: u8,
}

/// How many unhandled OSC payloads [`ServerTerminal::take_unhandled_oscs`] retains between drains,
/// and the byte cap on each (dropped, never grown, so a hostile app can't pin memory here).
pub const UNHANDLED_OSC_RING: usize = 16;
pub const UNHANDLED_OSC_MAX_LEN: usize = 256;

/// Parse the parameters of an `OSC 9;4;…` progress report. `params` is vt100's split payload
/// (`["9", "4", state, percent]`); anything malformed or out of range is `None`.
fn parse_progress(params: &[&[u8]]) -> Option<Progress> {
    if params.len() < 3 || params.first().copied() != Some(b"9".as_slice()) {
        return None;
    }
    if params.get(1).copied() != Some(b"4".as_slice()) {
        return None;
    }
    let num = |i: usize| -> Option<u8> {
        let p = params.get(i).copied()?;
        let s = std::str::from_utf8(p).ok()?;
        s.parse::<u8>().ok()
    };
    let state = num(2)?;
    if state > 4 {
        return None;
    }
    let percent = if state == 0 { 0 } else { num(3)? };
    if percent > 100 {
        return None;
    }
    Some(Progress { state, percent })
}

/// Decode an OSC title/icon payload (lossy UTF-8) and clamp it to [`MAX_TITLE_LEN`] characters.
fn title_from(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(MAX_TITLE_LEN)
        .collect()
}

/// Captures window title / icon / bell from `vt100`'s callback stream (none are stored on
/// `Screen` itself), and synthesizes the host-bound replies to terminal queries (DSR / device
/// attributes / DECRQM) that `vt100` does not answer on its own.
#[derive(Default)]
struct Callbacks {
    title: String,
    icon: String,
    /// The remote-set clipboard payload (OSC 52, base64), capped at [`MAXIMUM_CLIPBOARD_SIZE`].
    clipboard: String,
    bell_count: u64,
    /// Bytes the emulator must send back to the application (query answers). Drained into the
    /// PTY input by the caller — never echoed onto the synced screen.
    host_replies: Vec<u8>,
    /// The latest OSC 9;4 progress report; `None` once cleared (state 0) or never set (KO-01).
    progress: Option<Progress>,
    /// The last [`UNHANDLED_OSC_RING`] OSC payloads vt100 did not handle, each truncated to
    /// [`UNHANDLED_OSC_MAX_LEN`] bytes, oldest first (KO-01).
    unhandled_oscs: std::collections::VecDeque<Vec<u8>>,
}

impl vt100::Callbacks for Callbacks {
    fn set_window_title(&mut self, _: &mut vt100::Screen, t: &[u8]) {
        self.title = title_from(t);
    }
    fn set_window_icon_name(&mut self, _: &mut vt100::Screen, n: &[u8]) {
        self.icon = title_from(n);
    }
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        self.bell_count += 1;
    }
    /// OSC 52: the app set the system clipboard. `data` is already base64 (vt100). Forward the `c`
    /// (clipboard) selection, capped; oversized sets are ignored.
    fn copy_to_clipboard(&mut self, _: &mut vt100::Screen, _ty: &[u8], data: &[u8]) {
        if data.len() <= MAXIMUM_CLIPBOARD_SIZE {
            self.clipboard = String::from_utf8_lossy(data).into_owned();
        }
    }

    /// OSC sequences vt100 has no handler for: parse progress (OSC 9;4) and keep a bounded ring of
    /// raw payloads for an embedding host's own detection (KO-01).
    fn unhandled_osc(&mut self, _: &mut vt100::Screen, params: &[&[u8]]) {
        match parse_progress(params) {
            Some(p) if p.state == 0 => self.progress = None,
            Some(p) => self.progress = Some(p),
            None => {}
        }
        let mut raw = params.join(&b';');
        raw.truncate(UNHANDLED_OSC_MAX_LEN);
        if self.unhandled_oscs.len() >= UNHANDLED_OSC_RING {
            self.unhandled_oscs.pop_front();
        }
        self.unhandled_oscs.push_back(raw);
    }

    /// Answer the terminal queries interactive apps (vim/htop/fzf/…) block on. vt100 routes
    /// these unrecognized CSIs here; we generate the reply the real terminal would send.
    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        i1: Option<u8>,
        i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        // First parameter (empty/`ESC[c` => 0; explicit `ESC[0c` => 0; `ESC[6n` => 6).
        let p0 = params.first().and_then(|p| p.first()).copied().unwrap_or(0);
        match (i1, i2, c) {
            // Device Status Report. cursor_position() is 0-indexed; the report is 1-indexed.
            (None, _, 'n') => match p0 {
                6 => {
                    let (row, col) = screen.cursor_position();
                    self.host_replies
                        .extend_from_slice(format!("\x1b[{};{}R", row + 1, col + 1).as_bytes());
                }
                5 => self.host_replies.extend_from_slice(b"\x1b[0n"), // "terminal OK"
                _ => {}
            },
            // DECDSR (cursor position bracketed by `?`), used by some apps.
            (Some(b'?'), _, 'n') if p0 == 6 => {
                let (row, col) = screen.cursor_position();
                self.host_replies
                    .extend_from_slice(format!("\x1b[?{};{}R", row + 1, col + 1).as_bytes());
            }
            // Primary Device Attributes (`ESC[c` / `ESC[0c`): answer as a VT220 (matches mosh).
            (None, _, 'c') => self.host_replies.extend_from_slice(b"\x1b[?62;1;6c"),
            // Secondary Device Attributes (`ESC[>c`).
            (Some(b'>'), _, 'c') => self.host_replies.extend_from_slice(b"\x1b[>1;10;0c"),
            // DECRQM mode request (`ESC[?<n>$p`): report bracketed-paste accurately, others as
            // "not recognized" (0) — an honest answer is safer than lying about a mode.
            (Some(b'?'), Some(b'$'), 'p') => {
                let status = match p0 {
                    2004 => {
                        if screen.bracketed_paste() {
                            1
                        } else {
                            2
                        }
                    }
                    _ => 0u16,
                };
                self.host_replies
                    .extend_from_slice(format!("\x1b[?{p0};{status}$y").as_bytes());
            }
            _ => {}
        }
    }
}

/// The server's authoritative terminal. Owns the live parser (which is not `Clone`) and
/// produces a [`TerminalScreen`] snapshot for the SSP transport each tick.
///
/// The echo-ack is **not** tracked here (KS-02): SSP frame numbers are per connection, so the
/// per-connection `ServerSession` owns the input history and stamps its own ack onto each snapshot
/// it takes. Snapshots leave `echo_ack` at 0 for that reason.
pub struct ServerTerminal {
    parser: vt100::Parser<Callbacks>,
    /// The shell's exit code once it has exited (propagated to the client on shutdown).
    exit_code: Option<u32>,
}

impl ServerTerminal {
    pub fn new(rows: u16, cols: u16, scrollback: usize) -> Self {
        Self {
            parser: vt100::Parser::new_with_callbacks(rows, cols, scrollback, Callbacks::default()),
            exit_code: None,
        }
    }

    /// Record the shell's exit code; the next snapshot carries it to the client.
    pub fn set_exit_code(&mut self, code: u32) {
        self.exit_code = Some(code);
    }

    /// Feed a chunk of the child shell's output into the screen model.
    ///
    /// Routed through [`process_contained`](crate::terminal::process_contained): a `vt100` panic on
    /// shell output (an emulator bug, not wire-controlled — but `vt100` is outside koh's no-panic
    /// coverage) is CONTAINED so it can't unwind out of the drain task and poison the session mutex.
    /// On a contained panic the chunk is dropped and the parser keeps its prior state; subsequent
    /// output repaints. The default hook still logs the backtrace to `$KOH_LOG` for an upstream report.
    pub fn process(&mut self, bytes: &[u8]) {
        if !crate::terminal::process_contained(&mut self.parser, bytes) {
            tracing::error!(
                "vt100 panicked on shell output; dropped the chunk (backtrace in logs)"
            );
        }
    }

    /// Take and clear any host-bound replies (DSR/DA/DECRQM answers) produced while processing
    /// PTY output. The caller MUST write these back to the PTY input so the querying app sees
    /// them; they are never part of the synced screen.
    pub fn take_host_replies(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.parser.callbacks_mut().host_replies)
    }

    /// The hosted app's latest OSC 9;4 progress report, if one is active (KO-01). Host-side
    /// information for an embedding server; not part of the synced screen.
    pub fn progress(&self) -> Option<Progress> {
        self.parser.callbacks().progress
    }

    /// Drain the ring of OSC payloads vt100 did not handle (at most [`UNHANDLED_OSC_RING`], each
    /// at most [`UNHANDLED_OSC_MAX_LEN`] bytes), oldest first (KO-01).
    pub fn take_unhandled_oscs(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.parser.callbacks_mut().unhandled_oscs).into()
    }

    /// Resize the emulated screen (after applying a client resize to the PTY). The dimensions are
    /// peer-controlled, so they are clamped to `[MIN_DIM, MAX_DIM]` here — vt100 allocates the grid
    /// eagerly, so an unbounded resize OOM-aborts the (cross-tenant) server and a zero dimension
    /// panics it (H-1 / M-2). Defense in depth: the call site clamps too, this is the chokepoint.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        let (rows, cols) = clamp_dims(rows, cols);
        self.parser.screen_mut().set_size(rows, cols);
    }

    /// `(rows, cols)`. Test-only: production reads geometry from the snapshot, not the live emulator.
    #[cfg(test)]
    pub fn size(&self) -> (u16, u16) {
        self.parser.screen().size()
    }

    /// Window title set by the shell (OSC 2), if any. Test-only — production reads it via
    /// [`snapshot`](Self::snapshot)'s [`TerminalScreen`].
    #[cfg(test)]
    pub fn title(&self) -> &str {
        &self.parser.callbacks().title
    }

    /// Window icon name set by the shell (OSC 1), if any. Test-only (see [`title`](Self::title)).
    #[cfg(test)]
    pub fn icon_name(&self) -> &str {
        &self.parser.callbacks().icon
    }

    /// Number of audible bells seen so far. Test-only (see [`title`](Self::title)).
    #[cfg(test)]
    pub fn bell_count(&self) -> u64 {
        self.parser.callbacks().bell_count
    }

    /// Whether the emulated app has DECCKM (application cursor keys) on — used to normalize the
    /// client's arrow-key bytes (SS3 vs CSI) before they reach the PTY.
    pub fn application_cursor(&self) -> bool {
        self.parser.screen().application_cursor()
    }

    /// Produce the SSP snapshot the transport will diff and ship. `echo_ack` is 0: the connection
    /// loop stamps its own (see [`SessionHost::stamp_echo_ack`](crate::server::SessionHost::stamp_echo_ack)).
    pub fn snapshot(&self) -> TerminalScreen {
        TerminalScreen {
            screen: self.parser.screen().clone(),
            echo_ack: 0,
            title: self.parser.callbacks().title.clone(),
            icon: self.parser.callbacks().icon.clone(),
            clipboard: self.parser.callbacks().clipboard.clone(),
            bell_count: self.parser.callbacks().bell_count,
            exit_code: self.exit_code,
            parser: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_cursor_position_report() {
        let mut t = ServerTerminal::new(24, 80, 0);
        t.process(b"\x1b[5;3H"); // move cursor to row 5, col 3 (1-indexed input)
        t.process(b"\x1b[6n"); // DSR: report cursor position
        assert_eq!(t.take_host_replies(), b"\x1b[5;3R"); // 1-indexed report
                                                         // Drained: a second take is empty.
        assert!(t.take_host_replies().is_empty());
    }

    #[test]
    fn answers_device_attributes() {
        let mut t = ServerTerminal::new(24, 80, 0);
        t.process(b"\x1b[c"); // primary DA
        assert_eq!(t.take_host_replies(), b"\x1b[?62;1;6c");
        t.process(b"\x1b[>c"); // secondary DA
        assert_eq!(t.take_host_replies(), b"\x1b[>1;10;0c");
    }

    #[test]
    fn title_icon_bell_clipboard_captured() {
        let mut t = ServerTerminal::new(24, 80, 0);
        t.process(b"\x1b]2;my-title\x07\x07\x1b]1;my-icon\x07\x1b]52;c;aGVsbG8=\x07");
        assert_eq!(t.title(), "my-title");
        assert_eq!(t.icon_name(), "my-icon");
        assert_eq!(t.bell_count(), 1);
        let snap = t.snapshot();
        assert_eq!(snap.title(), "my-title");
        assert_eq!(snap.icon(), "my-icon", "snapshot carries the icon name");
        assert_eq!(
            snap.clipboard(),
            "aGVsbG8=",
            "snapshot carries the OSC-52 clipboard"
        );
        assert_eq!(snap.bell_count(), 1, "snapshot carries the bell count");
    }

    #[test]
    fn server_resize_clamps_oom_and_zero() {
        use crate::terminal::{MAX_DIM, MIN_DIM};
        // The server emulator must clamp a peer-controlled resize before vt100 allocates the grid:
        // a giant resize would OOM-abort the (cross-tenant) server, a zero dimension would panic it.
        let mut t = ServerTerminal::new(24, 80, 0);
        t.resize(65000, 65000); // must not OOM
        assert_eq!(
            t.size(),
            (MAX_DIM, MAX_DIM),
            "giant resize clamped to MAX_DIM"
        );
        t.resize(0, 0); // must not panic
        assert_eq!(
            t.size(),
            (MIN_DIM, MIN_DIM),
            "zero resize clamped to MIN_DIM"
        );
        // Critically: feeding wrappy/wide shell output into the clamped grid must NOT panic vt100
        // (a 1×1 grid underflows its wrap math — MIN_DIM=2 is the smallest size it tolerates). This
        // is the in-process guard for the M-2 regression the emulator surfaced.
        t.process("AAAA日本🦀\r\nBBBB\r\n".repeat(8).as_bytes());
        let _ = t.snapshot();
        // A normal resize is untouched, and a snapshot after a clamped resize is still coherent.
        t.resize(40, 120);
        assert_eq!(t.size(), (40, 120));
        let _ = t.snapshot();
    }

    #[test]
    fn oversized_clipboard_is_dropped() {
        // A clipboard set above the cap must not be synced (anti-amplification).
        let mut t = ServerTerminal::new(24, 80, 0);
        let big = "A".repeat(MAXIMUM_CLIPBOARD_SIZE + 1);
        t.process(format!("\x1b]52;c;{big}\x07").as_bytes());
        assert_eq!(t.snapshot().clipboard(), "", "oversized clipboard dropped");
    }

    #[test]
    fn oversized_title_is_clamped() {
        // A runaway/hostile OSC title is clamped to MAX_TITLE_LEN chars (mosh's parse-time cap),
        // not stored unbounded.
        let mut t = ServerTerminal::new(24, 80, 0);
        let huge = "x".repeat(MAX_TITLE_LEN + 500);
        t.process(format!("\x1b]2;{huge}\x07").as_bytes());
        assert_eq!(
            t.title().chars().count(),
            MAX_TITLE_LEN,
            "title clamped to the cap"
        );
        // A title within the cap is untouched.
        t.process(b"\x1b]2;short\x07");
        assert_eq!(t.title(), "short");
    }

    // --- KO-01: OSC 9;4 progress and the unhandled-OSC ring ---

    #[test]
    fn osc_9_4_progress_is_parsed_and_cleared() {
        let mut t = ServerTerminal::new(24, 80, 0);
        t.process(b"\x1b]9;4;1;50\x1b\\");
        assert_eq!(
            t.progress(),
            Some(Progress {
                state: 1,
                percent: 50
            })
        );
        t.process(b"\x1b]9;4;3;0\x07"); // BEL-terminated, indeterminate
        assert_eq!(
            t.progress(),
            Some(Progress {
                state: 3,
                percent: 0
            })
        );
        t.process(b"\x1b]9;4;0\x1b\\"); // state 0 clears, no percent needed
        assert_eq!(t.progress(), None);
    }

    #[test]
    fn malformed_osc_9_4_yields_none_and_never_panics() {
        for bad in [
            &b"\x1b]9;4;1;150\x1b\\"[..], // percent out of range
            b"\x1b]9;4;x\x1b\\",          // non-numeric state
            b"\x1b]9;4\x1b\\",            // missing state
            b"\x1b]9;4;7;10\x1b\\",       // unknown state
            b"\x1b]\x1b\\",               // empty param list
        ] {
            let mut t = ServerTerminal::new(24, 80, 0);
            t.process(bad);
            assert_eq!(t.progress(), None, "{bad:?}");
        }
        // A 4 KiB payload is truncated into the ring, not stored whole.
        let mut t = ServerTerminal::new(24, 80, 0);
        let mut big = b"\x1b]9;4;1;".to_vec();
        big.extend(std::iter::repeat_n(b'9', 4096));
        big.extend_from_slice(b"\x1b\\");
        t.process(&big);
        assert_eq!(t.progress(), None);
        let ring = t.take_unhandled_oscs();
        assert_eq!(ring.len(), 1);
        assert!(ring[0].len() <= UNHANDLED_OSC_MAX_LEN);
    }

    #[test]
    fn unhandled_osc_ring_keeps_the_last_sixteen_and_drains() {
        let mut t = ServerTerminal::new(24, 80, 0);
        for i in 0..20u8 {
            t.process(format!("\x1b]777;item{i}\x1b\\").as_bytes());
        }
        let ring = t.take_unhandled_oscs();
        assert_eq!(ring.len(), UNHANDLED_OSC_RING);
        assert_eq!(ring[0], b"777;item4".to_vec(), "oldest retained is the 5th");
        assert_eq!(ring[15], b"777;item19".to_vec());
        assert!(t.take_unhandled_oscs().is_empty(), "take drains");
        // Handled OSCs (title) do not land in the ring.
        t.process(b"\x1b]2;a title\x1b\\");
        assert!(t.take_unhandled_oscs().is_empty());
        assert_eq!(t.title(), "a title");
    }
}
