//! # koh-terminal — the screen the server sends
//!
//! The terminal *screen*, not a byte stream. The server parses the shell's output with `fux-vt`
//! ([`ServerTerminal`]) into a 2-D cell grid; frames bring the client to the server's *current*
//! screen, skipping any intermediate ones.
//!
//! ## A structured diff, no parser on the client
//!
//! [`TerminalScreen`] holds a plain [`Grid`] of `fux_vt::Cell`s plus the out-of-band channels: the
//! window `title`/`icon`, the `clipboard` and `bell` events and the shell's `exit_code`. A
//! [`ScreenDiff`] carries the changed rows as run-length-encoded cells, the cursor and the modes.
//! The client validates and copies cells; it never runs a terminal parser on server-controlled
//! bytes.

use std::num::NonZeroU16;
use std::sync::Arc;

use fux_vt::{Attributes, Cell, Color, MouseProtocolEncoding, MouseProtocolMode};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

mod grid;
mod server;

pub use grid::{Grid, Modes};
pub use server::ServerTerminal;

/// Default screen geometry, used for the blank screen both ends start from.
pub const DEFAULT_ROWS: u16 = 24;
pub const DEFAULT_COLS: u16 = 80;
/// Bounds on a peer-controlled terminal geometry.
///
/// A grid is allocated eagerly (`rows × cols` cells on the server's emulator and on the client),
/// so an unclamped resize from a hostile peer is an out-of-memory bomb: `(65000, 65000)` is
/// billions of cells. Every peer-influenced `(rows, cols)` MUST pass through [`clamp_dims`]
/// before a grid is built, on both the server (a client's `Resize`) and the client (a server's
/// `ScreenDiff.resize`). `MAX_DIM` is generous versus any real terminal (1000×1000 already dwarfs
/// any display); `MIN_DIM` keeps a degenerate 1-wide terminal out of the shell's way.
pub const MIN_DIM: u16 = 2;
pub const MAX_DIM: u16 = 1000;

/// Upper bound on a synced window title / icon name, in characters.
///
/// mosh truncates OSC 0/1/2 at parse; no real app sends a multi-KiB title, so this just bounds a
/// hostile/runaway one. Enforced on the trusted server emulator *and* re-applied on the client,
/// which must never trust the wire.
pub(crate) const MAX_TITLE_LEN: usize = 256;

/// Upper bound on a forwarded clipboard payload (mosh's `MAXIMUM_CLIPBOARD_SIZE`).
///
/// A larger OSC-52 set is dropped rather than synced, so a remote app can't make either end ship
/// megabytes. Enforced server-side at capture *and* client-side at apply.
pub const MAXIMUM_CLIPBOARD_SIZE: usize = 16 * 1024;

/// Clamp a peer-supplied `(rows, cols)` into `[MIN_DIM, MAX_DIM]`.
///
/// The single chokepoint both the server and the client funnel a resize through before building a
/// grid, so the two paths can never disagree and no resize can allocate an unbounded grid.
#[must_use]
pub fn clamp_dims(rows: u16, cols: u16) -> (u16, u16) {
    (rows.clamp(MIN_DIM, MAX_DIM), cols.clamp(MIN_DIM, MAX_DIM))
}

/// Truncate `s` to at most `max` characters (not bytes), preserving whole scalars.
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
    // The nearest char boundary at or below `max`.
    s.get(..s.floor_char_boundary(max))
        .unwrap_or("")
        .to_string()
}

/// The screen: the cell grid plus the out-of-band channels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalScreen {
    grid: Grid,
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
}

impl Default for TerminalScreen {
    fn default() -> Self {
        Self::with_grid(Grid::blank(DEFAULT_ROWS, DEFAULT_COLS))
    }
}

impl TerminalScreen {
    const fn with_grid(grid: Grid) -> Self {
        Self {
            grid,
            title: String::new(),
            icon: String::new(),
            clipboard: String::new(),
            bell_count: 0,
            exit_code: None,
        }
    }

    /// Construct a screen by feeding `bytes` of terminal output into a fresh emulator of the
    /// given (clamped) size. For tests.
    pub fn from_bytes(rows: u16, cols: u16, bytes: &[u8]) -> Self {
        ServerTerminal::new(rows, cols, 0).map_or_else(
            |_| Self::default(),
            |mut emu| {
                emu.process(bytes);
                emu.snapshot()
            },
        )
    }

    /// Borrow the grid (for rendering and predictor reconciliation).
    pub const fn screen(&self) -> &Grid {
        &self.grid
    }

    /// The remote shell's exit code, once it has exited (`None` while alive).
    pub const fn exit_code(&self) -> Option<u32> {
        self.exit_code
    }

    /// `(rows, cols)`.
    pub const fn size(&self) -> (u16, u16) {
        self.grid.size()
    }

    /// Whether the app has application-cursor-keys (DECCKM) on, for the arrow-key normalizer.
    pub fn application_cursor(&self) -> bool {
        self.grid.modes().application_cursor
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
    pub const fn bell_count(&self) -> u64 {
        self.bell_count
    }

    /// The cells `screens` hold in memory together: a row several of them share counts once.
    pub fn distinct_cells<'a>(screens: impl IntoIterator<Item = &'a Self>) -> usize {
        Grid::distinct_cells(screens.into_iter().map(|screen| &screen.grid))
    }
}

/// A colour on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireColor {
    Default,
    Idx(u8),
    Rgb(u8, u8, u8),
}

impl From<Color> for WireColor {
    fn from(c: Color) -> Self {
        match c {
            Color::Default => Self::Default,
            Color::Idx(i) => Self::Idx(i),
            Color::Rgb(r, g, b) => Self::Rgb(r, g, b),
        }
    }
}

impl From<WireColor> for Color {
    fn from(c: WireColor) -> Self {
        match c {
            WireColor::Default => Self::Default,
            WireColor::Idx(i) => Self::Idx(i),
            WireColor::Rgb(r, g, b) => Self::Rgb(r, g, b),
        }
    }
}

/// A cell's kind on the wire. The variant's index is its byte, so an unknown kind fails to decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellKind {
    Narrow,
    Wide,
    /// The right half of a wide glyph.
    Continuation,
}

/// A cell's style on the wire: one bit per attribute. Decoding rejects any bit outside the five
/// defined, so every value holds only known bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireStyle(u8);

impl WireStyle {
    pub const BOLD: u8 = 1;
    pub const DIM: u8 = 2;
    pub const ITALIC: u8 = 4;
    pub const UNDERLINE: u8 = 8;
    pub const INVERSE: u8 = 16;
    const ALL: u8 = 31;

    /// The style with exactly `bits`, or `None` if any is not a defined bit.
    pub const fn new(bits: u8) -> Option<Self> {
        if bits & !Self::ALL == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}

impl Serialize for WireStyle {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for WireStyle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u8::deserialize(deserializer)?;
        Self::new(bits).ok_or_else(|| {
            de::Error::invalid_value(
                de::Unexpected::Unsigned(u64::from(bits)),
                &"style bits within 0b11111",
            )
        })
    }
}

/// One cell on the wire. `text` is at most `fux_vt::Cell::CONTENTS_CAPACITY` bytes; a
/// continuation (the right half of a wide glyph) is empty with default colours and no style.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCell {
    pub text: String,
    pub kind: CellKind,
    pub fg: WireColor,
    pub bg: WireColor,
    pub style: WireStyle,
}

impl WireCell {
    fn of(cell: &Cell) -> Self {
        let a = cell.attributes();
        let bit = |on: bool, b: u8| if on { b } else { 0 };
        let style = bit(a.bold(), WireStyle::BOLD)
            | bit(a.dim(), WireStyle::DIM)
            | bit(a.italic(), WireStyle::ITALIC)
            | bit(a.underline(), WireStyle::UNDERLINE)
            | bit(a.inverse(), WireStyle::INVERSE);
        Self {
            text: cell.contents().to_owned(),
            kind: if cell.is_wide_continuation() {
                CellKind::Continuation
            } else if cell.is_wide() {
                CellKind::Wide
            } else {
                CellKind::Narrow
            },
            fg: a.foreground.into(),
            bg: a.background.into(),
            // Only defined bits were set above.
            style: WireStyle(style),
        }
    }

    /// The cell this encodes, or `None` if the encoding is malformed (oversized text, or a
    /// continuation carrying content).
    fn cell(&self) -> Option<Cell> {
        match self.kind {
            CellKind::Continuation => (self.text.is_empty()
                && self.fg == WireColor::Default
                && self.bg == WireColor::Default
                && self.style == WireStyle::default())
            .then(Cell::wide_continuation),
            CellKind::Narrow | CellKind::Wide => {
                let attributes = Attributes::new(self.fg.into(), self.bg.into())
                    .with_bold(self.style.has(WireStyle::BOLD))
                    .with_dim(self.style.has(WireStyle::DIM))
                    .with_italic(self.style.has(WireStyle::ITALIC))
                    .with_underline(self.style.has(WireStyle::UNDERLINE))
                    .with_inverse(self.style.has(WireStyle::INVERSE));
                Cell::new(&self.text, self.kind == CellKind::Wide, attributes)
            }
        }
    }
}

/// `count` consecutive identical cells. A run is never empty: a zero count fails to decode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub count: NonZeroU16,
    pub cell: WireCell,
}

impl Run {
    /// Add one more cell. `false` if the run already holds `u16::MAX` cells, the most `count`
    /// can say; the caller then starts a new run.
    fn extend(&mut self) -> bool {
        match self.count.checked_add(1) {
            Some(count) => {
                self.count = count;
                true
            }
            None => false,
        }
    }
}

/// One whole row: its runs cover exactly the screen width.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowDiff {
    pub row: u16,
    pub wrapped: bool,
    pub runs: Vec<Run>,
}

impl RowDiff {
    fn of(row: u16, cells: &[Cell], wrapped: bool) -> Self {
        let mut runs: Vec<Run> = Vec::new();
        let mut previous: Option<&Cell> = None;
        for cell in cells {
            let extended = previous == Some(cell) && runs.last_mut().is_some_and(Run::extend);
            if !extended {
                runs.push(Run {
                    count: NonZeroU16::MIN,
                    cell: WireCell::of(cell),
                });
            }
            previous = Some(cell);
        }
        Self { row, wrapped, runs }
    }

    /// Append exactly `cols` decoded cells to `out`, or return `None` if the runs are malformed or
    /// don't cover the row exactly (`out` then holds a partial row, which the caller discards).
    /// Work is bounded by `cols`: every run is non-empty.
    fn decode_into(&self, cols: u16, out: &mut Vec<Cell>) -> Option<()> {
        let mut len = 0_usize;
        for run in &self.runs {
            let count = usize::from(run.count.get());
            len = len
                .checked_add(count)
                .filter(|&len| len <= usize::from(cols))?;
            let cell = run.cell.cell()?;
            out.extend(std::iter::repeat_n(cell, count));
        }
        (len == usize::from(cols)).then_some(())
    }
}

/// The mouse reporting mode on the wire. The variant's index is its byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMouseMode {
    None,
    Press,
    PressRelease,
    ButtonMotion,
    AnyMotion,
}

impl From<MouseProtocolMode> for WireMouseMode {
    fn from(mode: MouseProtocolMode) -> Self {
        match mode {
            MouseProtocolMode::None => Self::None,
            MouseProtocolMode::Press => Self::Press,
            MouseProtocolMode::PressRelease => Self::PressRelease,
            MouseProtocolMode::ButtonMotion => Self::ButtonMotion,
            MouseProtocolMode::AnyMotion => Self::AnyMotion,
        }
    }
}

impl From<WireMouseMode> for MouseProtocolMode {
    fn from(mode: WireMouseMode) -> Self {
        match mode {
            WireMouseMode::None => Self::None,
            WireMouseMode::Press => Self::Press,
            WireMouseMode::PressRelease => Self::PressRelease,
            WireMouseMode::ButtonMotion => Self::ButtonMotion,
            WireMouseMode::AnyMotion => Self::AnyMotion,
        }
    }
}

/// The mouse report encoding on the wire. The variant's index is its byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMouseEncoding {
    Default,
    Utf8,
    Sgr,
}

impl From<MouseProtocolEncoding> for WireMouseEncoding {
    fn from(encoding: MouseProtocolEncoding) -> Self {
        match encoding {
            MouseProtocolEncoding::Default => Self::Default,
            MouseProtocolEncoding::Utf8 => Self::Utf8,
            MouseProtocolEncoding::Sgr => Self::Sgr,
        }
    }
}

impl From<WireMouseEncoding> for MouseProtocolEncoding {
    fn from(encoding: WireMouseEncoding) -> Self {
        match encoding {
            WireMouseEncoding::Default => Self::Default,
            WireMouseEncoding::Utf8 => Self::Utf8,
            WireMouseEncoding::Sgr => Self::Sgr,
        }
    }
}

/// The modes on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireModes {
    pub hide_cursor: bool,
    pub application_cursor: bool,
    pub application_keypad: bool,
    pub bracketed_paste: bool,
    pub mouse_mode: WireMouseMode,
    pub mouse_encoding: WireMouseEncoding,
}

impl From<Modes> for WireModes {
    fn from(m: Modes) -> Self {
        Self {
            hide_cursor: m.hide_cursor,
            application_cursor: m.application_cursor,
            application_keypad: m.application_keypad,
            bracketed_paste: m.bracketed_paste,
            mouse_mode: m.mouse_mode.into(),
            mouse_encoding: m.mouse_encoding.into(),
        }
    }
}

impl From<WireModes> for Modes {
    fn from(m: WireModes) -> Self {
        Self {
            hide_cursor: m.hide_cursor,
            application_cursor: m.application_cursor,
            application_keypad: m.application_keypad,
            bracketed_paste: m.bracketed_paste,
            mouse_mode: m.mouse_mode.into(),
            mouse_encoding: m.mouse_encoding.into(),
        }
    }
}

/// The wire delta between two [`TerminalScreen`]s (mosh `HostMessage`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenDiff {
    /// New `(rows, cols)` if the screen was resized; the client starts from a blank grid of that
    /// size, and `rows` then carries every row that isn't blank.
    pub resize: Option<(u16, u16)>,
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
    /// The cursor at the target state.
    pub cursor: (u16, u16),
    /// The modes at the target state.
    pub modes: WireModes,
    /// Every row that differs from the base (or from blank after a resize), whole.
    pub rows: Vec<RowDiff>,
}

impl TerminalScreen {
    /// The diff that turns `base` into `self`.
    pub fn diff_from(&self, base: &Self) -> ScreenDiff {
        let resized = self.size() != base.size();
        let (rows, _) = self.size();
        let changed = (0..rows).filter_map(|r| {
            let cells = self.grid.row(r)?;
            let wrapped = self.grid.row_wrapped(r);
            // A row shared with the base is the same without comparing its cells.
            let same = if resized {
                !wrapped && cells.iter().all(|cell| *cell == Cell::default())
            } else {
                self.grid.row_eq(&base.grid, r)
            };
            (!same).then(|| RowDiff::of(r, cells, wrapped))
        });
        ScreenDiff {
            resize: resized.then(|| self.size()),
            title: (self.title != base.title).then(|| self.title.clone()),
            icon: (self.icon != base.icon).then(|| self.icon.clone()),
            clipboard: (self.clipboard != base.clipboard).then(|| self.clipboard.clone()),
            bell_count: self.bell_count,
            exit_code: self.exit_code,
            cursor: self.grid.cursor_position(),
            modes: self.grid.modes().into(),
            rows: changed.collect(),
        }
    }

    /// Apply `diff`, a diff against this screen. A malformed diff changes nothing.
    pub fn apply(&mut self, diff: &ScreenDiff) {
        // Everything below is server-controlled. Validate the whole grid part first and commit
        // only if all of it is well-formed: a malformed frame is dropped and the prior screen
        // kept, never half-applied.
        //
        // LOAD-BEARING: this `clamp_dims` is the only bound on a single resize's grid
        // allocation. The mirror clamp on the server lives in `terminal/server.rs`.
        let (rows, cols) = diff
            .resize
            .map_or_else(|| self.size(), |(r, c)| clamp_dims(r, c));
        if diff.rows.len() > usize::from(rows) {
            return;
        }
        // Every row decodes into one staging buffer, `cols` cells each, in the diff's order. At
        // most `rows × cols` cells, which the clamp bounds.
        let width = usize::from(cols);
        let mut staged = Vec::with_capacity(diff.rows.len().saturating_mul(width));
        for row in &diff.rows {
            if row.row >= rows || row.decode_into(cols, &mut staged).is_none() {
                return;
            }
        }
        if diff.resize.is_some() {
            self.grid = Grid::blank(rows, cols);
        }
        // Only the rows the diff carries are replaced; the rest stay shared with the base.
        for (row, cells) in diff.rows.iter().zip(staged.chunks(width.max(1))) {
            self.grid.set_row(row.row, Arc::from(cells), row.wrapped);
        }
        let (crow, ccol) = diff.cursor;
        self.grid
            .set_cursor((crow.min(rows.saturating_sub(1)), ccol.min(cols)));
        self.grid.set_modes(diff.modes.into());

        // Monotonic: never regress on a reordered/older diff (the client applies only newer
        // frames, but `max` is the defensive, obviously-correct choice).
        self.bell_count = self.bell_count.max(diff.bell_count);
        // Title / icon / clipboard arrive from the wire. The server emulator caps them, but the
        // client must NOT trust that — a malicious server could ship an oversized payload to bloat
        // the client or stuff its terminal. Re-apply the same caps here before storing.
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_ne!(diff.rows, Vec::<RowDiff>::new());
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

    /// A diff that changes nothing but `resize`, for the clamp tests.
    fn resize_only(resize: (u16, u16)) -> ScreenDiff {
        ScreenDiff {
            resize: Some(resize),
            title: None,
            icon: None,
            clipboard: None,
            bell_count: 0,
            exit_code: None,
            cursor: (0, 0),
            modes: Modes::default().into(),
            rows: Vec::new(),
        }
    }

    fn wire_cell() -> impl proptest::strategy::Strategy<Value = WireCell> {
        use proptest::prelude::*;
        // `Union` rather than `prop_oneof!`, whose expansion `allow`s a lint this crate forbids.
        let color = proptest::strategy::Union::new([
            Just(WireColor::Default).boxed(),
            any::<u8>().prop_map(WireColor::Idx).boxed(),
            any::<(u8, u8, u8)>()
                .prop_map(|(r, g, b)| WireColor::Rgb(r, g, b))
                .boxed(),
        ]);
        let kind = proptest::sample::select(vec![
            CellKind::Narrow,
            CellKind::Wide,
            CellKind::Continuation,
        ]);
        (".{0,30}", kind, color.clone(), color, 0u8..=31).prop_map(|(text, kind, fg, bg, style)| {
            WireCell {
                text,
                kind,
                fg,
                bg,
                style: WireStyle::new(style).unwrap(),
            }
        })
    }

    fn row_diff() -> impl proptest::strategy::Strategy<Value = RowDiff> {
        use proptest::prelude::*;
        (
            0u16..40,
            any::<bool>(),
            proptest::collection::vec(
                (1u16..120, wire_cell()).prop_map(|(count, cell)| Run {
                    count: NonZeroU16::new(count).unwrap(),
                    cell,
                }),
                0..8,
            ),
        )
            .prop_map(|(row, wrapped, runs)| RowDiff { row, wrapped, runs })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// The untrusted server->client `apply` path must NEVER panic on an arbitrary structured
        /// `ScreenDiff` (any rows, runs, cells, cursor, modes, dimensions, strings) and must always
        /// leave the screen within the dimension clamp, a consistent grid, a cursor in range, and
        /// the title/clipboard caps.
        #[test]
        fn apply_is_panic_free_and_holds_invariants(
            rows in proptest::collection::vec(row_diff(), 0..6),
            resize in proptest::option::of((proptest::prelude::any::<u16>(), proptest::prelude::any::<u16>())),
            cursor in proptest::prelude::any::<(u16, u16)>(),
            modes in proptest::prelude::any::<(bool, bool, bool, bool)>(),
            mouse_mode in proptest::sample::select(vec![
                WireMouseMode::None,
                WireMouseMode::Press,
                WireMouseMode::PressRelease,
                WireMouseMode::ButtonMotion,
                WireMouseMode::AnyMotion,
            ]),
            mouse_encoding in proptest::sample::select(vec![
                WireMouseEncoding::Default,
                WireMouseEncoding::Utf8,
                WireMouseEncoding::Sgr,
            ]),
            title in proptest::option::of(".{0,512}"),
            icon in proptest::option::of(".{0,512}"),
            clipboard in proptest::option::of(".{0,40000}"),
            bell_count in proptest::prelude::any::<u64>(),
            exit_code in proptest::option::of(proptest::prelude::any::<u32>()),
        ) {
            let modes = WireModes {
                hide_cursor: modes.0,
                application_cursor: modes.1,
                application_keypad: modes.2,
                bracketed_paste: modes.3,
                mouse_mode,
                mouse_encoding,
            };
            let diff = ScreenDiff {
                resize, title, icon, clipboard, bell_count, exit_code, cursor, modes, rows,
            };
            let mut screen = TerminalScreen::default();
            screen.apply(&diff); // must not panic on adversarial input
            let (rows, cols) = screen.size();
            proptest::prop_assert!((MIN_DIM..=MAX_DIM).contains(&rows), "rows {rows} escaped the clamp");
            proptest::prop_assert!((MIN_DIM..=MAX_DIM).contains(&cols), "cols {cols} escaped the clamp");
            for r in 0..rows {
                proptest::prop_assert_eq!(screen.screen().row(r).map(<[Cell]>::len), Some(usize::from(cols)));
            }
            let (crow, ccol) = screen.screen().cursor_position();
            proptest::prop_assert!(crow < rows && ccol <= cols);
            proptest::prop_assert!(screen.title.chars().count() <= MAX_TITLE_LEN);
            proptest::prop_assert!(screen.icon.chars().count() <= MAX_TITLE_LEN);
            proptest::prop_assert!(screen.clipboard.len() <= MAXIMUM_CLIPBOARD_SIZE);
        }

        /// Arbitrary wire bytes that happen to decode as a `ScreenDiff` must apply without panic.
        #[test]
        fn decoded_wire_bytes_apply_without_panic(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048),
        ) {
            if let Ok(diff) = postcard::from_bytes::<ScreenDiff>(&bytes) {
                let mut screen = TerminalScreen::default();
                screen.apply(&diff);
                let (rows, cols) = screen.size();
                proptest::prop_assert!((MIN_DIM..=MAX_DIM).contains(&rows) && (MIN_DIM..=MAX_DIM).contains(&cols));
            }
        }

        /// The round-trip law over real emulator output: for any two screens produced by the server
        /// emulator (any bytes, any sizes), applying `target.diff_from(base)` to `base` yields
        /// exactly `target`, including after a resize.
        #[test]
        fn diff_apply_roundtrips_real_screens(
            first in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..600),
            second in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..600),
            resize in proptest::option::of((2u16..40, 2u16..100)),
        ) {
            let mut emu = ServerTerminal::new(12, 40, 0).expect("emulator");
            emu.process(&first);
            let base = emu.snapshot();
            if let Some((rows, cols)) = resize {
                emu.resize(rows, cols);
            }
            emu.process(&second);
            let target = emu.snapshot();
            let mut client = base.clone();
            client.apply(&target.diff_from(&base));
            proptest::prop_assert_eq!(client, target);
        }
    }

    #[test]
    fn client_apply_clamps_oom_resize() {
        // A malicious server ships a (65000, 65000) resize. The client must NOT build a giant
        // grid: apply clamps to MAX_DIM and reconstructs a bounded screen without OOM/panic.
        let mut c = TerminalScreen::default();
        c.apply(&resize_only((65000, 65000))); // must not OOM/panic
        assert_eq!(c.size(), (MAX_DIM, MAX_DIM), "client clamps a giant resize");
    }

    #[test]
    fn client_apply_clamps_zero_resize() {
        let mut c = TerminalScreen::default();
        c.apply(&resize_only((0, 0))); // must not panic
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
        let mut diff = TerminalScreen::default().diff_from(&TerminalScreen::default());
        diff.title = Some("T".repeat(MAX_TITLE_LEN + 1000));
        diff.icon = Some("I".repeat(MAX_TITLE_LEN + 5));
        diff.clipboard = Some("C".repeat(MAXIMUM_CLIPBOARD_SIZE + 1000));
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
    fn malformed_rows_drop_the_whole_frame() {
        // Every malformed grid part leaves the prior screen untouched, never half-applied.
        let base = screen_from(24, 80, b"keep me");
        let target = screen_from(24, 80, b"changed\r\nmore");
        let good = target.diff_from(&base);
        let mutations: [fn(&mut ScreenDiff); 5] = [
            |d| d.rows[0].row = 24, // row out of range
            |d| {
                let run = &mut d.rows[0].runs[0];
                run.count = run.count.checked_add(1).unwrap(); // overruns the width
            },
            |d| {
                if let Some(run) = d.rows[0].runs.last_mut() {
                    run.count = NonZeroU16::new(run.count.get() - 1).unwrap(); // falls short
                }
            },
            |d| d.rows[0].runs[0].cell.text = "x".repeat(Cell::CONTENTS_CAPACITY + 1),
            |d| d.rows[0].runs[0].cell.kind = CellKind::Continuation, // continuation with text
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut diff = good.clone();
            mutate(&mut diff);
            let mut c = base.clone();
            c.apply(&diff);
            assert_eq!(c, base, "mutation {i} must drop the frame");
        }
        // The unmutated diff applies.
        let mut c = base;
        c.apply(&good);
        assert_eq!(c, target);
    }

    #[test]
    fn a_malformed_last_row_drops_the_rows_before_it_too() {
        // Every row is validated before any is committed: rows that decoded fine before the
        // malformed one are not applied either.
        let base = screen_from(24, 80, b"keep\r\nkeep\r\nkeep");
        let target = screen_from(24, 80, b"one\r\ntwo\r\nthree");
        let good = target.diff_from(&base);
        assert_eq!(good.rows.len(), 3);
        let mutations: [fn(&mut ScreenDiff); 3] = [
            |d| d.rows[2].row = 24,
            |d| {
                let run = &mut d.rows[2].runs[0];
                run.count = run.count.checked_add(1).unwrap();
            },
            |d| d.rows[2].runs[0].cell.kind = CellKind::Continuation,
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut diff = good.clone();
            mutate(&mut diff);
            let mut c = base.clone();
            c.apply(&diff);
            assert_eq!(c, base, "mutation {i} must drop the whole frame");
        }
    }

    /// A [`ScreenDiff`] in the same wire shape with plain fields, to encode values the typed one
    /// cannot hold.
    #[derive(Clone, Serialize)]
    struct RawDiff {
        resize: Option<(u16, u16)>,
        title: Option<String>,
        icon: Option<String>,
        clipboard: Option<String>,
        bell_count: u64,
        exit_code: Option<u32>,
        cursor: (u16, u16),
        modes: RawModes,
        rows: Vec<RawRow>,
    }

    #[derive(Clone, Serialize)]
    struct RawModes {
        hide_cursor: bool,
        application_cursor: bool,
        application_keypad: bool,
        bracketed_paste: bool,
        mouse_mode: u8,
        mouse_encoding: u8,
    }

    #[derive(Clone, Serialize)]
    struct RawRow {
        row: u16,
        wrapped: bool,
        runs: Vec<RawRun>,
    }

    #[derive(Clone, Serialize)]
    struct RawRun {
        count: u16,
        cell: RawCell,
    }

    #[derive(Clone, Serialize)]
    struct RawCell {
        text: String,
        kind: u8,
        fg: WireColor,
        bg: WireColor,
        style: u8,
    }

    /// A resize to 2×2 whose first row reads `xx`.
    fn raw_two_by_two() -> RawDiff {
        RawDiff {
            resize: Some((2, 2)),
            title: None,
            icon: None,
            clipboard: None,
            bell_count: 0,
            exit_code: None,
            cursor: (0, 0),
            modes: RawModes {
                hide_cursor: false,
                application_cursor: false,
                application_keypad: false,
                bracketed_paste: false,
                mouse_mode: 4,
                mouse_encoding: 2,
            },
            rows: vec![RawRow {
                row: 0,
                wrapped: false,
                runs: vec![RawRun {
                    count: 2,
                    cell: RawCell {
                        text: "x".to_owned(),
                        kind: 0,
                        fg: WireColor::Default,
                        bg: WireColor::Default,
                        style: 31,
                    },
                }],
            }],
        }
    }

    fn decode_raw(raw: &RawDiff) -> postcard::Result<ScreenDiff> {
        postcard::from_bytes(&postcard::to_allocvec(raw)?)
    }

    #[test]
    fn malformed_cells_and_modes_fail_to_decode() {
        // What the types cannot hold fails at decode, so the client drops the frame before any
        // `apply`.
        let good = decode_raw(&raw_two_by_two()).expect("a well-formed diff decodes");
        let mut screen = TerminalScreen::default();
        screen.apply(&good);
        assert_eq!(screen.size(), (2, 2));
        assert_eq!(screen.screen().cell(0, 1).map(Cell::contents), Some("x"));
        let mutations: [fn(&mut RawDiff); 5] = [
            |d| d.rows[0].runs[0].count = 0,       // empty run
            |d| d.rows[0].runs[0].cell.kind = 3,   // unknown kind
            |d| d.rows[0].runs[0].cell.style = 32, // unknown style bit
            |d| d.modes.mouse_mode = 5,            // unknown mouse mode
            |d| d.modes.mouse_encoding = 3,        // unknown mouse encoding
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut raw = raw_two_by_two();
            mutate(&mut raw);
            assert!(
                decode_raw(&raw).is_err(),
                "mutation {i} must fail to decode"
            );
        }
    }

    #[test]
    fn snapshots_share_the_rows_they_hold_unchanged() {
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
        emu.process(b"one\r\ntwo\r\n");
        let before = emu.snapshot();
        emu.process(b"three");
        let after = emu.snapshot();
        assert!(after.grid.row_shared(&before.grid, 0));
        assert!(after.grid.row_shared(&before.grid, 1));
        assert!(!after.grid.row_shared(&before.grid, 2), "the changed row");
        assert_eq!(after.grid.row(2).map(<[Cell]>::len), Some(80));
        // Scrolled rows are shared too, wherever they moved: one screen and one row in all.
        for n in 0..30 {
            emu.process(format!("\r\nline {n}").as_bytes());
        }
        let before = emu.snapshot();
        emu.process(b"\r\nscrolled");
        let after = emu.snapshot();
        assert_eq!(
            TerminalScreen::distinct_cells([&before, &after]),
            (24 + 1) * 80
        );
        assert_eq!(after.screen().row(0), before.screen().row(1));
    }

    #[test]
    fn apply_replaces_only_the_rows_the_diff_carries() {
        let base = screen_from(24, 80, b"one\r\ntwo\r\nthree");
        let target = screen_from(24, 80, b"one\r\nTWO\r\nthree");
        let diff = target.diff_from(&base);
        assert_eq!(diff.rows.len(), 1);
        let mut client = base.clone();
        client.apply(&diff);
        assert_eq!(client, target);
        for row in (0..24).filter(|&row| row != 1) {
            assert!(client.grid.row_shared(&base.grid, row), "row {row}");
        }
        assert!(!client.grid.row_shared(&base.grid, 1));
        assert_eq!(TerminalScreen::distinct_cells([&base, &client]), 25 * 80);
    }

    #[test]
    fn identical_cells_are_run_length_encoded() {
        let target = screen_from(24, 80, b"ab");
        let diff = target.diff_from(&TerminalScreen::default());
        assert_eq!(diff.rows.len(), 1, "only the changed row is sent");
        assert_eq!(
            diff.rows[0].runs.len(),
            3,
            "'a', 'b', then one run of 78 blanks"
        );
        assert_eq!(diff.rows[0].runs[2].count.get(), 78);
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
        assert_eq!(a.diff_from(&b).rows, Vec::<RowDiff>::new());
    }

    #[test]
    fn icon_and_clipboard_roundtrip_and_resist_collapse() {
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
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
    fn many_incremental_applies_track_server() {
        // The client holds ONE TerminalScreen and applies a long run of incremental diffs. It must
        // track the server's snapshot exactly.
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
        emu.process(b"line 0\r\n");
        let mut client = emu.snapshot();
        let mut base = client.clone();

        for i in 1..=20 {
            emu.process(format!("line {i}\r\n").as_bytes());
            let target = emu.snapshot();
            let diff = target.diff_from(&base);
            assert!(diff.resize.is_none(), "no resize -> incremental diff");
            client.apply(&diff); // same object, repeated apply
            base = target;
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
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
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

    // --- Ported mosh terminal-emulation / unicode regression tests, recast as diff/apply
    // round-trip tests: feed the byte sequence from the corresponding mosh test to the server emulator, ship
    // the snapshot through diff/apply onto a fresh client, and assert the client reconstructs the
    // screen EXACTLY (koh's verification guarantee) plus the semantic outcome mosh checked.
    // mosh source: src/tests/emulation-*.test, unicode-*.test. ---

    /// Process `bytes`, ship server→client via diff/apply, assert exact reconstruction, and
    /// return the reconstructed client screen for semantic assertions.
    fn roundtrip(rows: u16, cols: u16, bytes: &[u8]) -> TerminalScreen {
        let mut emu = ServerTerminal::new(rows, cols, 0).expect("emulator");
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
    fn row_text(s: &Grid, row: u16) -> String {
        let (_, cols) = s.size();
        (0..cols)
            .map(|c| match s.cell(row, c).map(Cell::contents) {
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
            Color::Idx(1),
            "16-color red"
        );
        assert_eq!(
            s.cell(0, 5).unwrap().fgcolor(),
            Color::Idx(208),
            "256-color"
        );
        assert_eq!(
            s.cell(0, 6).unwrap().fgcolor(),
            Color::Rgb(10, 20, 30),
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
        // move between tab stops. fux-vt does NOT implement them (they are outside its sequence
        // matrix), so they are no-ops (a known, minor divergence from mosh). What we DO guarantee
        // is that the unhandled sequences round-trip identically server↔client and corrupt nothing.
        // If fux-vt ever gains CBT/CHT, this test flips and should become the real mosh assertion
        // ("hello, world" / a forward-tabbed "ab      tab").
        let c = roundtrip(24, 80, b"hello, wurld\x1b[Zo");
        assert_eq!(
            row_text(c.screen(), 0),
            "hello, wurldo",
            "CBT currently a no-op in fux-vt"
        );
        let c2 = roundtrip(24, 80, b"ab\x1b[Itab");
        assert_eq!(
            row_text(c2.screen(), 0),
            "abtab",
            "CHT currently a no-op in fux-vt"
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
        // frame N+1 broke mosh's round-trip verification (the wrap flag lived on the Cell). It
        // must reconstruct across an INCREMENTAL diff, not a repaint.
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
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
