//! # koh-terminal — the `TerminalScreen` SSP state
//!
//! The server→client half of the synchronized world: the terminal *screen*, not a byte
//! stream. The server parses the shell's escape-sequence output into a 2-D cell grid; the
//! protocol's job is to bring the client to the server's *current* screen, collapsing any
//! intermediate frames. A port of mosh's `Terminal::Complete`, backed by the `vt100` crate.
//!
//! ## Why a snapshot, not a live parser
//!
//! `vt100::Parser` is **not** `Clone`, but the SSP transport stores cloned state snapshots.
//! So [`TerminalScreen`] holds an owned `vt100::Screen` (which *is* `Clone`). The server's
//! live, long-lived emulator lives in [`ServerTerminal`]; it produces a [`TerminalScreen`]
//! snapshot each tick. The client's [`TerminalScreen::apply`] reconstructs a throwaway parser
//! to replay the diff onto its baseline.
//!
//! ## The diff carries more than the grid
//!
//! `vt100::Screen::contents_diff` does not express resize or the echo-ack. So [`ScreenDiff`]
//! bundles three things, mirroring mosh's `HostMessage`: the optional `resize`, the
//! `echo_ack` (which the client's predictor consumes as the authoritative "your input up to
//! frame N is now on screen"), the optional window `title`, and the `vt` escape-sequence
//! patch (`state_diff`, or a full `state_formatted` repaint after a resize).

use crate::ssp::SyncState;
use serde::{Deserialize, Serialize};

mod server;

pub use server::ServerTerminal;

/// Default screen geometry, used for the initial (num 0) state both ends agree on.
pub const DEFAULT_ROWS: u16 = 24;
pub const DEFAULT_COLS: u16 = 80;
/// Server-side debounce before a received input frame is considered "echoed" (mosh `ECHO_TIMEOUT`).
pub const ECHO_TIMEOUT_MS: u64 = 50;

/// Bounds on a peer-controlled terminal geometry.
///
/// `vt100::Parser` allocates `rows × cols` cells **eagerly**, so an unclamped resize from a hostile
/// peer is an out-of-memory bomb — `(65000, 65000)` is ≈135 GB. And vt100 **panics on a degenerate
/// grid**: whenever *either* dimension is below 2 its wrap/scroll math underflows (`Option::unwrap`
/// on a `None` row in `grid::col_wrap`), so a `(0, 0)` — or even `(1, 80)` — resize crashes the
/// session. Hence `MIN_DIM = 2`, the smallest geometry vt100 handles safely (verified empirically
/// against vt100 0.16). Every peer-influenced `(rows, cols)` MUST pass through [`clamp_dims`] before
/// it reaches vt100, on both the server (a client's `Resize`) and the client (a server's
/// `ScreenDiff.resize`). `MAX_DIM` is generous versus any real terminal (1000×1000 already dwarfs
/// any display).
pub const MIN_DIM: u16 = 2;
pub const MAX_DIM: u16 = 1000;

/// Upper bound on a synced window title / icon name, in characters.
///
/// mosh truncates OSC 0/1/2 at parse; no real app sends a multi-KiB title, so this just bounds a
/// hostile/runaway one. Enforced on the trusted server emulator *and* re-applied on the client,
/// which must never trust the wire.
pub const MAX_TITLE_LEN: usize = 256;

/// Upper bound on a forwarded clipboard payload (mosh's `MAXIMUM_CLIPBOARD_SIZE`).
///
/// A larger OSC-52 set is dropped/truncated rather than synced, so a remote app can't make either
/// end ship megabytes. Enforced server-side at capture *and* client-side at apply.
pub const MAXIMUM_CLIPBOARD_SIZE: usize = 16 * 1024;

/// Clamp a peer-supplied `(rows, cols)` into `[MIN_DIM, MAX_DIM]`.
///
/// The single chokepoint both the server and the client funnel a resize through before constructing
/// a `vt100` grid, so the two paths can never disagree. Closes the resize OOM (H-1) and the
/// zero-dimension panic (M-2).
#[must_use]
pub fn clamp_dims(rows: u16, cols: u16) -> (u16, u16) {
    (rows.clamp(MIN_DIM, MAX_DIM), cols.clamp(MIN_DIM, MAX_DIM))
}

/// Feed `bytes` to a `vt100` parser, CONTAINING any panic the parser raises on adversarial input.
///
/// `vt100` is a third-party dependency outside koh's `forbid(unsafe)` + denied-panic-lint coverage.
/// It is known to panic on degenerate input (sub-2 dimensions — guarded upstream of here by
/// [`clamp_dims`]) and its full escape-parser surface (OSC/DCS/SGR/grapheme edges) is not exhaustively
/// fuzzed. On the client this runs on **server-controlled** bytes, so an un-caught panic would unwind
/// into the client's async task and crash the session. [`std::panic::catch_unwind`] turns that "remote
/// client crash" into "drop one frame": returns `true` on success, `false` if a panic was caught (the
/// caller then discards the frame and keeps the last-good screen). The default panic hook still logs
/// the backtrace (to `$KOH_LOG`), so a genuine vt100 panic stays diagnosable + reportable upstream.
/// `catch_unwind` is no-`unsafe`; `AssertUnwindSafe` is required only because `&mut Parser` is not
/// `UnwindSafe`, and a poisoned parser is discarded by the caller.
fn process_contained(parser: &mut vt100::Parser, bytes: &[u8]) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parser.process(bytes))).is_ok()
}

/// Build a blank `vt100::Screen` of the given size (the only way to get an owned `Screen`,
/// since `Screen::new` is `pub(crate)`).
fn blank_screen(rows: u16, cols: u16) -> vt100::Screen {
    vt100::Parser::new(rows, cols, 0).screen().clone()
}

/// Truncate `s` to at most `max` characters (not bytes), preserving whole grapheme scalars.
fn capped_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// Truncate `s` to at most `max` bytes, never splitting a multi-byte UTF-8 scalar (so the result is
/// always valid UTF-8). Used for the clipboard cap, which is a byte budget.
fn capped_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    // Walk back to the nearest char boundary at or below `max`.
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or("").to_string()
}

/// The synchronized screen state.
///
/// Holds an owned `vt100::Screen` snapshot (what `diff_from`/`PartialEq`/render read, and what
/// survives `Clone` — `vt100::Parser` is not `Clone`), plus a live parser kept across `apply`
/// calls so incremental diffs are `O(diff)`, not a full re-parse of the whole grid per frame.
pub struct TerminalScreen {
    screen: vt100::Screen,
    /// Newest user-input frame number the server has echoed (drives the client predictor).
    echo_ack: u64,
    /// Window title (OSC 2), propagated so the client can mirror it.
    title: String,
    /// Window icon name (OSC 1), propagated alongside the title (mosh emits `]1;`/`]2;` when the
    /// two differ, else a combined `]0;`).
    icon: String,
    /// The terminal's clipboard selection set by the remote app via OSC 52 (base64 payload, capped
    /// server-side), forwarded so a remote yank reaches the local clipboard. Empty if unset.
    clipboard: String,
    /// Monotonic count of audible bells (BEL) the server has seen. The client rings its terminal
    /// once when this increases (mosh treats the bell count as part of frame identity).
    bell_count: u64,
    /// Set once the remote shell has exited, carrying its exit code so the client can exit with
    /// the same status (mosh parity). `None` while the shell is alive.
    exit_code: Option<u32>,
    /// Long-lived parser, in sync with `screen` whenever `Some`. Not part of identity; dropped
    /// on `Clone` (Parser is not Clone) and lazily rebuilt from `screen` on the next `apply`.
    parser: Option<Box<vt100::Parser>>,
}

impl Clone for TerminalScreen {
    fn clone(&self) -> Self {
        // Drop the live parser on clone; the snapshot carries the state and the next apply
        // rebuilds the parser from it. Clone is the rare path (transport state snapshots), so a
        // later one-time rebuild is fine — the per-frame apply stays cheap.
        Self {
            screen: self.screen.clone(),
            echo_ack: self.echo_ack,
            title: self.title.clone(),
            icon: self.icon.clone(),
            clipboard: self.clipboard.clone(),
            bell_count: self.bell_count,
            exit_code: self.exit_code,
            parser: None,
        }
    }
}

impl std::fmt::Debug for TerminalScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `parser` is deliberately omitted: it is a non-identity cache (dropped on clone,
        // lazily rebuilt) and `vt100::Parser` is not `Debug`. Mark the struct non-exhaustive.
        f.debug_struct("TerminalScreen")
            .field("size", &self.screen.size())
            .field("echo_ack", &self.echo_ack)
            .field("title", &self.title)
            .field("icon", &self.icon)
            .field("clipboard", &self.clipboard)
            .field("bell_count", &self.bell_count)
            .field("exit_code", &self.exit_code)
            .finish_non_exhaustive()
    }
}

impl Default for TerminalScreen {
    fn default() -> Self {
        Self {
            screen: blank_screen(DEFAULT_ROWS, DEFAULT_COLS),
            echo_ack: 0,
            title: String::new(),
            icon: String::new(),
            clipboard: String::new(),
            bell_count: 0,
            exit_code: None,
            parser: None,
        }
    }
}

impl TerminalScreen {
    /// Construct a screen by feeding `bytes` of terminal output into a fresh emulator of the
    /// given size (useful for tests and for the client's initial baseline).
    pub fn from_bytes(rows: u16, cols: u16, bytes: &[u8]) -> Self {
        let mut p = vt100::Parser::new(rows, cols, 0);
        p.process(bytes);
        Self {
            screen: p.screen().clone(),
            echo_ack: 0,
            title: String::new(),
            icon: String::new(),
            clipboard: String::new(),
            bell_count: 0,
            exit_code: None,
            parser: None,
        }
    }

    /// Borrow the underlying `vt100::Screen` (for rendering and predictor reconciliation).
    pub fn screen(&self) -> &vt100::Screen {
        &self.screen
    }

    /// The remote shell's exit code, once it has exited (`None` while alive).
    pub fn exit_code(&self) -> Option<u32> {
        self.exit_code
    }

    /// `(rows, cols)`.
    pub fn size(&self) -> (u16, u16) {
        self.screen.size()
    }

    /// The server's echo-ack: the newest input frame number reflected on this screen.
    pub fn echo_ack(&self) -> u64 {
        self.echo_ack
    }

    /// The window title, if the server has set one.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The window icon name (OSC 1), if the server has set one.
    pub fn icon(&self) -> &str {
        &self.icon
    }

    /// The remote-set clipboard payload (OSC 52, base64), or empty if none.
    pub fn clipboard(&self) -> &str {
        &self.clipboard
    }

    /// Monotonic count of audible bells the server has seen (the client rings on an increase).
    pub fn bell_count(&self) -> u64 {
        self.bell_count
    }
}

/// The wire delta between two [`TerminalScreen`]s (mosh `HostMessage`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScreenDiff {
    /// New `(rows, cols)` if the screen was resized; when set, `vt` is a full repaint.
    pub resize: Option<(u16, u16)>,
    /// The server's echo-ack at the target state.
    pub echo_ack: u64,
    /// New window title if it changed.
    pub title: Option<String>,
    /// New window icon name if it changed.
    pub icon: Option<String>,
    /// New clipboard payload if it changed (OSC 52; the client re-emits it to the local terminal).
    pub clipboard: Option<String>,
    /// The server's audible-bell count at the target state (absolute; the client rings when it
    /// increases past what it last saw). Always carried so a bell-only change isn't lost.
    pub bell_count: u64,
    /// The remote shell's exit code, set on the final (shutdown) frame.
    pub exit_code: Option<u32>,
    /// The `vt100` escape-sequence patch: `state_diff(base)` normally, or `state_formatted`
    /// (a self-contained repaint) when `resize` is set.
    pub vt: Vec<u8>,
}

impl SyncState for TerminalScreen {
    type Diff = ScreenDiff;

    // A repaint can be a few MiB, so the screen direction keeps the 16 MiB inflate ceiling (a tighter
    // cap risks dropping a legitimate large repaint) — set explicitly now the trait member is required.
    const RECV_DECODE_LIMIT: usize = crate::wire::MAX_DECOMPRESSED;

    // Each retained snapshot costs `rows × cols` cells (≤ MAX_DIM², dimension-bounded by `clamp_dims`);
    // the budget caps total retained screens at ~8 full-size ones, so a hostile server that prevents
    // collapse can't pin tens of GB on the client (KOH-01).
    const RECEIVE_BUDGET_UNITS: usize = 8 * (MAX_DIM as usize) * (MAX_DIM as usize);

    fn resource_units(&self) -> usize {
        let (rows, cols) = self.screen.size();
        // Each retained snapshot also owns title/icon/clipboard byte buffers (capped upstream at
        // MAX_TITLE_LEN / MAXIMUM_CLIPBOARD_SIZE, but a hostile server can still ship a distinct
        // max-size clipboard per state). The grid-cell count alone ignored them (K-05), letting a
        // flood of tiny-grid states pin tens of MiB of clipboard the budget never saw — so fold
        // their lengths into the unit count so RECEIVE_BUDGET_UNITS bounds total retained memory.
        ((rows as usize) * (cols as usize))
            .saturating_add(self.title.len())
            .saturating_add(self.icon.len())
            .saturating_add(self.clipboard.len())
    }

    fn diff_from(&self, base: &Self) -> Self::Diff {
        let resized = self.size() != base.size();
        let vt = if resized {
            // After a resize, vt100 does not reflow; ship a self-contained repaint.
            self.screen.state_formatted()
        } else {
            self.screen.state_diff(&base.screen)
        };
        ScreenDiff {
            resize: resized.then(|| self.size()),
            echo_ack: self.echo_ack,
            title: (self.title != base.title).then(|| self.title.clone()),
            icon: (self.icon != base.icon).then(|| self.icon.clone()),
            clipboard: (self.clipboard != base.clipboard).then(|| self.clipboard.clone()),
            bell_count: self.bell_count,
            exit_code: self.exit_code,
            vt,
        }
    }

    fn apply(&mut self, diff: &Self::Diff) {
        if let Some((rows, cols)) = diff.resize {
            // Resize: vt100 doesn't reflow, so `vt` is a self-contained repaint at the new size.
            // Rebuild the parser at the new geometry (rare path) and replay the repaint. CLAMP the
            // peer-supplied dimensions first — the server is trusted to clamp before it ships a
            // resize, but the client must never construct an unbounded/zero grid on the wire's say-so
            // (defense in depth: closes the client-side resize OOM / zero-dim panic, H-1 / M-2).
            //
            // K-13 — LOAD-BEARING: `apply()` runs in the SSP receive path BEFORE the per-direction
            // `RECEIVE_BUDGET_UNITS` check (the budget bounds *accumulation* across retained states,
            // not the cost of building one state), so this `clamp_dims` is the SOLE bound on a single
            // resize's grid allocation. Do not remove it or move it after the parser build — an
            // unclamped `(65000, 65000)` would allocate ~135 GB / panic here. MIN_DIM=2 also dodges
            // vt100 0.16's sub-2-dim panic. Mirror clamp on the server lives in `terminal/server.rs`.
            let (rows, cols) = clamp_dims(rows, cols);
            let mut p = Box::new(vt100::Parser::new(rows, cols, 0));
            if !process_contained(&mut p, &diff.vt) {
                // A peer-controlled repaint panicked vt100; CONTAIN it (see `process_contained`):
                // drop this frame and keep the prior screen rather than crashing the client task.
                return;
            }
            self.screen = p.screen().clone();
            self.parser = Some(p);
        } else {
            // Lazily (re)build the parser from the snapshot on the first apply / after a clone,
            // then feed only the incremental diff bytes. Steady-state cost is O(diff.vt), not a
            // full re-parse of the whole grid every frame.
            let parser = self.parser.get_or_insert_with(|| {
                let (rows, cols) = self.screen.size();
                let mut p = Box::new(vt100::Parser::new(rows, cols, 0));
                p.process(&self.screen.state_formatted());
                p
            });
            if !diff.vt.is_empty() && !process_contained(parser, &diff.vt) {
                // Contained vt100 panic mid-stream: the parser's state is now unknown, so drop it
                // (the next apply rebuilds from the last-good `screen`) and discard this frame.
                self.parser = None;
                return;
            }
            // Keep the snapshot in sync for PartialEq / diff_from / render.
            self.screen = parser.screen().clone();
        }
        self.echo_ack = self.echo_ack.max(diff.echo_ack);
        // Monotonic: never regress on a reordered/older diff (the SSP guarantees no state
        // regression, but `max` is the defensive, obviously-correct choice).
        self.bell_count = self.bell_count.max(diff.bell_count);
        // Title / icon / clipboard arrive from the wire. The server emulator caps them, but the
        // client must NOT trust that — a malicious server (or one speaking a future/looser protocol)
        // could ship an oversized payload to bloat the client or stuff its terminal. Re-apply the
        // same caps here before storing/emitting (L-2).
        if let Some(title) = &diff.title {
            self.title = capped_chars(title, MAX_TITLE_LEN);
        }
        if let Some(icon) = &diff.icon {
            self.icon = capped_chars(icon, MAX_TITLE_LEN);
        }
        if let Some(clipboard) = &diff.clipboard {
            self.clipboard = capped_bytes(clipboard, MAXIMUM_CLIPBOARD_SIZE);
        }
        if diff.exit_code.is_some() {
            self.exit_code = diff.exit_code;
        }
    }

    // subtract_prefix: screen state is absolute, so the default no-op is correct (mosh's
    // `Complete::subtract` is likewise a no-op).
}

impl PartialEq for TerminalScreen {
    fn eq(&self, other: &Self) -> bool {
        self.echo_ack == other.echo_ack
            && self.title == other.title
            // Include icon + clipboard so an OSC 1 / OSC 52 change with an otherwise-identical
            // screen still reaches the client (mosh likewise treats them as frame identity).
            && self.icon == other.icon
            && self.clipboard == other.clipboard
            // Include bell_count so a bell-only change (screen otherwise identical) isn't collapsed
            // away as unchanged — the bell must reach the client.
            && self.bell_count == other.bell_count
            // Include exit_code so the final "shell exited" state isn't collapsed as unchanged.
            && self.exit_code == other.exit_code
            && self.screen.size() == other.screen.size()
            // Two screens are equal for collapse purposes iff they render identically
            // (contents + cursor + input modes), i.e. their state_diff is empty.
            && self.screen.state_diff(&other.screen).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssp::testkit::{LinkParams, SimHarness};

    fn screen_from(rows: u16, cols: u16, bytes: &[u8]) -> TerminalScreen {
        TerminalScreen::from_bytes(rows, cols, bytes)
    }

    #[test]
    fn diff_apply_roundtrip_simple() {
        let base = TerminalScreen::default();
        let target = screen_from(24, 80, b"hello \x1b[31mworld\x1b[m");
        let diff = target.diff_from(&base);
        let mut c = base;
        c.apply(&diff);
        assert_eq!(c, target);
    }

    #[test]
    fn diff_apply_roundtrip_incremental() {
        let a = screen_from(24, 80, b"line one\r\nline two");
        let b = screen_from(24, 80, b"line one\r\nline two\r\nline three\x1b[1;1Hedited");
        let diff = b.diff_from(&a);
        assert!(!diff.vt.is_empty());
        assert!(diff.resize.is_none());
        let mut c = a;
        c.apply(&diff);
        assert_eq!(c, b);
    }

    #[test]
    fn resize_roundtrip_full_repaint() {
        let a = screen_from(24, 80, b"small screen content here");
        let b = screen_from(
            40,
            120,
            b"now a much wider and taller screen\r\nwith two lines",
        );
        let diff = b.diff_from(&a);
        assert_eq!(diff.resize, Some((40, 120)));
        let mut c = a;
        c.apply(&diff);
        assert_eq!(c, b);
        assert_eq!(c.size(), (40, 120));
    }

    #[test]
    fn clamp_dims_bounds_both_extremes() {
        assert_eq!(
            clamp_dims(65000, 65000),
            (MAX_DIM, MAX_DIM),
            "huge -> MAX_DIM"
        );
        assert_eq!(clamp_dims(0, 0), (MIN_DIM, MIN_DIM), "zero -> MIN_DIM");
        assert_eq!(clamp_dims(24, 80), (24, 80), "in-range passes through");
        assert_eq!(
            clamp_dims(0, 5000),
            (MIN_DIM, MAX_DIM),
            "mixed clamps each axis"
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// The untrusted server->client `apply` path must NEVER panic on an arbitrary `ScreenDiff`
        /// (any `vt` escape bytes, any peer dimensions/strings) and must always leave the screen
        /// within the dimension clamp and the title/clipboard caps — the invariant prior audits lean
        /// on (KOH-02/07, K-13, H-1/M-2). Every existing apply test feeds hand-crafted VALID bytes;
        /// this fuzzes the degenerate-input space where vt100 historically panicked. `vt` is bounded
        /// to a datagram-ish size so a failure is a logic panic, not an allocator OOM.
        #[test]
        fn apply_is_panic_free_and_holds_invariants(
            vt in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096),
            resize in proptest::option::of((proptest::prelude::any::<u16>(), proptest::prelude::any::<u16>())),
            title in proptest::option::of(".{0,512}"),
            icon in proptest::option::of(".{0,512}"),
            clipboard in proptest::option::of(".{0,40000}"),
            echo_ack in proptest::prelude::any::<u64>(),
            bell_count in proptest::prelude::any::<u64>(),
            exit_code in proptest::option::of(proptest::prelude::any::<u32>()),
        ) {
            let diff = ScreenDiff { resize, echo_ack, title, icon, clipboard, bell_count, exit_code, vt };
            let mut screen = TerminalScreen::default();
            screen.apply(&diff); // must not panic on adversarial input
            let (rows, cols) = screen.size();
            proptest::prop_assert!((MIN_DIM..=MAX_DIM).contains(&rows), "rows {rows} escaped the clamp");
            proptest::prop_assert!((MIN_DIM..=MAX_DIM).contains(&cols), "cols {cols} escaped the clamp");
            proptest::prop_assert!(screen.title.chars().count() <= MAX_TITLE_LEN);
            proptest::prop_assert!(screen.icon.chars().count() <= MAX_TITLE_LEN);
            proptest::prop_assert!(screen.clipboard.len() <= MAXIMUM_CLIPBOARD_SIZE);
        }
    }

    #[test]
    fn client_apply_clamps_oom_resize() {
        // A malicious server ships a (65000, 65000) resize. The client must NOT build a 135 GB
        // vt100 grid: apply clamps to MAX_DIM and reconstructs a bounded screen without OOM/panic.
        let mut c = TerminalScreen::default();
        let diff = ScreenDiff {
            resize: Some((65000, 65000)),
            echo_ack: 0,
            title: None,
            icon: None,
            clipboard: None,
            bell_count: 0,
            exit_code: None,
            vt: b"hello".to_vec(),
        };
        c.apply(&diff); // must not OOM/panic
        assert_eq!(c.size(), (MAX_DIM, MAX_DIM), "client clamps a giant resize");
    }

    #[test]
    fn client_apply_clamps_zero_resize() {
        // A (0, 0) resize would crash vt100 (its wrap/scroll math underflows on a sub-2 grid). The
        // client clamps to MIN_DIM and then safely replays a repaint of wrappy/wide content — which
        // would panic at 1×1 — proving MIN_DIM is large enough for vt100, not merely non-zero.
        let mut c = TerminalScreen::default();
        let diff = ScreenDiff {
            resize: Some((0, 0)),
            echo_ack: 0,
            title: None,
            icon: None,
            clipboard: None,
            bell_count: 0,
            exit_code: None,
            vt: "AAAA日本🦀\r\nBBBB\r\n".repeat(8).into_bytes(),
        };
        c.apply(&diff); // must not panic
        assert_eq!(
            c.size(),
            (MIN_DIM, MIN_DIM),
            "client clamps a zero-dimension resize"
        );
    }

    #[test]
    fn client_apply_caps_oversized_title_and_clipboard() {
        // A malicious server ships an oversized title + clipboard. The client re-applies the caps
        // (it must not trust the wire even though the honest server emulator already caps them).
        let mut c = TerminalScreen::default();
        let big_title = "T".repeat(MAX_TITLE_LEN + 1000);
        let big_clip = "C".repeat(MAXIMUM_CLIPBOARD_SIZE + 1000);
        let diff = ScreenDiff {
            resize: None,
            echo_ack: 0,
            title: Some(big_title),
            icon: Some("I".repeat(MAX_TITLE_LEN + 5)),
            clipboard: Some(big_clip),
            bell_count: 0,
            exit_code: None,
            vt: Vec::new(),
        };
        c.apply(&diff);
        assert_eq!(
            c.title().chars().count(),
            MAX_TITLE_LEN,
            "title capped client-side"
        );
        assert_eq!(
            c.icon().chars().count(),
            MAX_TITLE_LEN,
            "icon capped client-side"
        );
        assert!(
            c.clipboard().len() <= MAXIMUM_CLIPBOARD_SIZE,
            "clipboard capped client-side"
        );
    }

    #[test]
    fn capped_bytes_never_splits_utf8() {
        // A multi-byte scalar straddling the byte budget must be dropped whole, leaving valid UTF-8.
        let s = "a".repeat(MAXIMUM_CLIPBOARD_SIZE - 1) + "é"; // 'é' is 2 bytes, crosses the cap
        let out = capped_bytes(&s, MAXIMUM_CLIPBOARD_SIZE);
        assert!(out.len() <= MAXIMUM_CLIPBOARD_SIZE);
        assert_eq!(
            out.len(),
            MAXIMUM_CLIPBOARD_SIZE - 1,
            "the straddling scalar is dropped whole"
        );
    }

    #[test]
    fn equal_screens_compare_equal() {
        let a = screen_from(24, 80, b"identical");
        let b = screen_from(24, 80, b"identical");
        assert_eq!(a, b);
        assert!(a.diff_from(&b).vt.is_empty());
    }

    #[test]
    fn icon_and_clipboard_roundtrip_and_resist_collapse() {
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.process(b"\x1b]1;myicon\x07\x1b]2;mytitle\x07\x1b]52;c;aGk=\x07");
        let target = emu.snapshot();
        assert_eq!(target.icon(), "myicon");
        assert_eq!(target.clipboard(), "aGk=");

        let base = TerminalScreen::default();
        let diff = target.diff_from(&base);
        assert_eq!(diff.icon.as_deref(), Some("myicon"));
        assert_eq!(diff.clipboard.as_deref(), Some("aGk="));
        let mut c = base.clone();
        c.apply(&diff);
        assert_eq!(c, target, "icon + clipboard reconstruct via diff/apply");
        // A state carrying an icon/clipboard must NOT collapse equal to one without them.
        assert_ne!(base, c);
    }

    #[test]
    fn wide_chars_and_emoji_roundtrip() {
        // CJK (wide) + emoji + combining marks must survive diff/apply.
        let base = TerminalScreen::default();
        let target = screen_from(24, 80, "日本語 café 🦀 e\u{0301}".as_bytes());
        let diff = target.diff_from(&base);
        let mut c = base;
        c.apply(&diff);
        assert_eq!(c, target);
    }

    #[test]
    fn converges_over_lossy_link() {
        // Server (A) evolves its screen; client (B) must converge to the latest frame.
        let mut h =
            SimHarness::<TerminalScreen, TerminalScreen>::new(LinkParams::lossy(), 77, 1200);
        let mut emu = ServerTerminal::new(24, 80, 0);
        for i in 0..30u32 {
            emu.process(format!("\r\nframe {i} of output").as_bytes());
            *h.a_mut() = emu.snapshot();
            h.run_steps(5);
        }
        let final_snap = emu.snapshot();
        h.run_until(20_000, move |h| *h.b_view_of_a() == final_snap);
    }

    #[test]
    fn many_incremental_applies_without_reclone_track_server() {
        // The client holds ONE TerminalScreen and applies a long run of incremental diffs,
        // exercising the persistent-parser path (the parser is built once on the first apply and
        // reused — never rebuilt per frame). It must track the server's snapshot exactly.
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.process(b"line 0\r\n");
        let mut client = emu.snapshot();
        let mut base = client.clone();

        for i in 1..=20 {
            emu.process(format!("line {i}\r\n").as_bytes());
            let target = emu.snapshot();
            let diff = target.diff_from(&base);
            assert!(
                diff.resize.is_none(),
                "no resize -> incremental (persistent) path"
            );
            client.apply(&diff); // same object, repeated apply (no clone between frames)
            base = target.clone();
            assert_eq!(
                client, base,
                "client must track server after incremental diff {i}"
            );
        }
    }

    #[test]
    fn exit_code_propagates_through_diff_apply() {
        // When the shell exits, the server stamps the code; it must survive diff -> apply, and a
        // state carrying an exit code must NOT compare equal to one without (so it isn't collapsed).
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.process(b"bye");
        emu.set_exit_code(42);
        let target = emu.snapshot();
        assert_eq!(target.exit_code(), Some(42));

        let base = TerminalScreen::default();
        let diff = target.diff_from(&base);
        assert_eq!(diff.exit_code, Some(42));

        let mut c = base.clone();
        c.apply(&diff);
        assert_eq!(c.exit_code(), Some(42));
        assert_ne!(
            base, c,
            "a state carrying an exit code differs from one without"
        );
    }

    // --- Ported mosh terminal-emulation / unicode regression tests, recast as SSP round-trip
    // tests: feed the byte sequence from the corresponding mosh test to the server emulator, ship
    // the snapshot through diff/apply onto a fresh client, and assert the client reconstructs the
    // screen EXACTLY (koh's verification guarantee) plus the semantic outcome mosh checked.
    // mosh source: src/tests/emulation-*.test, unicode-*.test. ---

    /// Process `bytes`, ship server→client via diff/apply, assert exact reconstruction, and
    /// return the reconstructed client screen for semantic assertions.
    fn roundtrip(rows: u16, cols: u16, bytes: &[u8]) -> TerminalScreen {
        let mut emu = ServerTerminal::new(rows, cols, 0);
        emu.process(bytes);
        let target = emu.snapshot();
        let base = TerminalScreen::default();
        let diff = target.diff_from(&base);
        let mut client = base;
        client.apply(&diff);
        assert_eq!(
            client, target,
            "client must reconstruct the server screen exactly"
        );
        client
    }

    /// Trimmed text of one screen row (blank cells as spaces), for line-level assertions.
    fn row_text(s: &vt100::Screen, row: u16) -> String {
        let (_, cols) = s.size();
        (0..cols)
            .map(|c| match s.cell(row, c).map(vt100::Cell::contents) {
                Some(g) if !g.is_empty() => g.to_string(),
                _ => " ".to_string(),
            })
            .collect::<String>()
            .trim_end()
            .to_string()
    }

    #[test]
    fn attributes_survive_roundtrip() {
        // mosh emulation-attributes{,-16color,-256color8,-256color248,-truecolor}: SGR
        // attributes and colors must reconstruct on the client.
        let bytes = b"\x1b[1mB\x1b[m\x1b[4mU\x1b[m\x1b[7mR\x1b[m\x1b[3mI\x1b[m\
                      \x1b[31mC\x1b[m\x1b[38;5;208mP\x1b[m\x1b[38;2;10;20;30mT\x1b[m";
        let c = roundtrip(24, 80, bytes);
        let s = c.screen();
        assert!(s.cell(0, 0).unwrap().bold(), "bold");
        assert!(s.cell(0, 1).unwrap().underline(), "underline");
        assert!(s.cell(0, 2).unwrap().inverse(), "inverse");
        assert!(s.cell(0, 3).unwrap().italic(), "italic");
        assert_eq!(
            s.cell(0, 4).unwrap().fgcolor(),
            vt100::Color::Idx(1),
            "16-color red"
        );
        assert_eq!(
            s.cell(0, 5).unwrap().fgcolor(),
            vt100::Color::Idx(208),
            "256-color"
        );
        assert_eq!(
            s.cell(0, 6).unwrap().fgcolor(),
            vt100::Color::Rgb(10, 20, 30),
            "truecolor"
        );
    }

    #[test]
    fn cursor_motion_roundtrip() {
        // mosh emulation-cursor-motion: absolute positioning (CSI row;colH) places glyphs, which
        // must reconstruct on the client.
        let bytes = b"\x1b[H\x1b[J\x1b[1;1HA\x1b[1;10HB\x1b[4;1HC\x1b[24;1Hdone";
        let c = roundtrip(24, 80, bytes);
        let s = c.screen();
        assert_eq!(s.cell(0, 0).unwrap().contents(), "A");
        assert_eq!(s.cell(0, 9).unwrap().contents(), "B");
        assert_eq!(s.cell(3, 0).unwrap().contents(), "C");
        assert_eq!(row_text(s, 23), "done");
    }

    #[test]
    fn scroll_up_down_roundtrip() {
        // mosh emulation-scroll: SU (CSI N S) then SD (CSI N T) shift the screen; the result
        // must survive the round-trip. 24 numbered rows, scroll up 4, then down 2.
        let mut bytes = Vec::from(&b"\x1b[H\x1b[J"[..]);
        for i in 1..=24 {
            bytes.extend_from_slice(format!("\x1b[{i};1Hline{i}").as_bytes());
        }
        bytes.extend_from_slice(b"\x1b[4S\x1b[2T");
        let c = roundtrip(24, 80, &bytes);
        let s = c.screen();
        assert_eq!(
            row_text(s, 0),
            "",
            "two blank rows pushed in at the top after SD 2"
        );
        assert_eq!(
            row_text(s, 2),
            "line5",
            "line5 reached the top after SU 4, then down 2"
        );
        assert_eq!(row_text(s, 21), "line24", "last line still present");
    }

    #[test]
    fn insert_delete_lines_roundtrip_no_panic() {
        // mosh emulation-multiline-scroll: IL (CSI N L) / DL (CSI N M) with in- and out-of-range
        // counts must not panic and must round-trip exactly.
        let mut bytes = Vec::from(&b"\x1b[H\x1b[J"[..]);
        for i in 1..=24 {
            bytes.extend_from_slice(format!("\x1b[{i};1Hrow{i}").as_bytes());
        }
        for n in [0u32, 1, 2, 22, 26] {
            bytes.extend_from_slice(format!("\x1b[3;1H\x1b[{n}L").as_bytes());
            bytes.extend_from_slice(format!("\x1b[3;1H\x1b[{n}M").as_bytes());
        }
        let _ = roundtrip(24, 80, &bytes); // assertion: no panic + exact reconstruction
    }

    #[test]
    fn back_and_forward_tab_unsupported_but_roundtrip_clean() {
        // mosh emulation-back-tab: in mosh's hand-written emulator, CBT (CSI Z) / CHT (CSI I)
        // move between tab stops. The `vt100` crate koh delegates to does NOT implement
        // them, so they are no-ops (a known, minor divergence from mosh). What we DO guarantee is
        // that the unhandled sequences round-trip identically server↔client and corrupt nothing.
        // If vt100 ever gains CBT/CHT, this test flips and should become the real mosh assertion
        // ("hello, world" / a forward-tabbed "ab      tab").
        let c = roundtrip(24, 80, b"hello, wurld\x1b[Zo");
        assert_eq!(
            row_text(c.screen(), 0),
            "hello, wurldo",
            "CBT currently a no-op in vt100"
        );
        let c2 = roundtrip(24, 80, b"ab\x1b[Itab");
        assert_eq!(
            row_text(c2.screen(), 0),
            "abtab",
            "CHT currently a no-op in vt100"
        );
    }

    #[test]
    fn column_80_no_premature_wrap_roundtrip() {
        // mosh emulation-80th-column: filling exactly to the last column leaves the cursor in the
        // deferred-wrap state; a following CRLF must not spill an extra blank wrapped line.
        let mut bytes = Vec::from(&b"\x1b[H\x1b[J"[..]);
        bytes.resize(bytes.len() + 80, b'E'); // 80 'E's, filling the row exactly
        bytes.extend_from_slice(b"\r\nM");
        let c = roundtrip(24, 80, &bytes);
        let s = c.screen();
        assert_eq!(row_text(s, 0), "E".repeat(80), "80 chars fill row 0");
        assert_eq!(
            s.cell(1, 0).unwrap().contents(),
            "M",
            "M lands on row 1, no spurious wrap row"
        );
    }

    #[test]
    fn wrap_across_incremental_frames() {
        // mosh emulation-wrap-across-frames: text filled to column 80 on frame N, then wrapped on
        // frame N+1, broke mosh's round-trip verification (the wrap flag lived on the Cell). It
        // must reconstruct across an INCREMENTAL diff (the persistent-parser path), not a repaint.
        let mut emu = ServerTerminal::new(24, 80, 0);
        emu.process(b"\x1b[H\x1b[J");
        emu.process(&[b'a'; 80]); // frame N: fill to col 80 -> deferred-wrap state
        let frame_n = emu.snapshot();
        let mut client = TerminalScreen::default();
        client.apply(&frame_n.diff_from(&TerminalScreen::default()));
        assert_eq!(client, frame_n);

        emu.process(b"b"); // frame N+1: one more char forces the wrap to row 1
        let frame_n1 = emu.snapshot();
        let diff = frame_n1.diff_from(&frame_n);
        assert!(
            diff.resize.is_none(),
            "incremental path, not a full repaint"
        );
        client.apply(&diff);
        assert_eq!(
            client, frame_n1,
            "wrap across frames must reconstruct incrementally"
        );
        assert_eq!(
            client.screen().cell(1, 0).unwrap().contents(),
            "b",
            "wrapped char on row 1"
        );
    }

    #[test]
    fn combining_mark_after_erase_does_not_panic() {
        // mosh unicode-combine-fallback-assert: a combining mark applied right after erasing the
        // cell it would attach to must not panic (mosh hit an internal assertion here).
        let _ = roundtrip(24, 80, b"0\x1b[1J\xcc\xb4");
    }

    #[test]
    fn combining_mark_on_blank_line_roundtrip() {
        // mosh unicode-later-combining: a combining mark printed on an otherwise-empty line gets
        // a base glyph and round-trips without dropping surrounding text.
        let c = roundtrip(24, 80, b"abc\n\xcc\x82\ndef\n");
        let contents = c.screen().contents();
        assert!(contents.contains("abc") && contents.contains("def"));
    }

    #[test]
    fn latin1_supplement_roundtrip() {
        // mosh emulation-ascii-iso-8859: ISO-8859-1 supplement characters render and round-trip.
        let c = roundtrip(24, 80, "àáâãäåæçèéêëìíîïñòóôõöøùúûüýþÿ".as_bytes());
        assert!(c.screen().contents().contains("àáâãä"));
    }
}
