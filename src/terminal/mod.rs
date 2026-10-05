//! The screen the server sends: a [`Grid`] of `fux_vt::Cell`s, which the server's emulator
//! ([`ServerTerminal`]) produces, plus the title, icon, clipboard, bell count and exit code.
//!
//! A [`ScreenDiff`] carries the changed rows as run-length-encoded cells, the cursor and the modes.
//! The client validates and copies cells; it never runs a terminal parser on server bytes.

use std::num::{NonZeroI16, NonZeroU16};
use std::ops::Range;
use std::sync::Arc;

use fux_vt::{
    Attributes, Blink, Cell, CellRef, Cells, Color, MouseProtocolEncoding, MouseProtocolMode,
    UnderlineStyle,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

mod grid;
mod history;
mod server;

pub use crate::predict::Size;
pub use grid::{drawn, Grid, Link, Modes, RowLinks, MAX_ROW_LINKS};
pub use history::{
    HistoryCache, HistoryMark, HistoryReply, HistoryRequest, HistoryRow, KeptRow,
    HISTORY_CACHE_CELLS, MAX_HISTORY_CELLS, MAX_HISTORY_ROWS,
};
pub use server::{FrameHold, ServerTerminal, FRAME_HOLD, IDENTITY, OPTIONS};

/// Default screen geometry, used for the blank screen both ends start from.
pub const DEFAULT_SIZE: Size = Size::new(24, 80);
/// Bounds on a peer-controlled geometry. A grid is allocated whole, so every size a peer sends
/// passes through [`clamp_dims`] first: 65000×65000 would be billions of cells. 1000×1000 dwarfs
/// any display.
pub const MIN_DIM: u16 = 2;
pub const MAX_DIM: u16 = 1000;

/// Most characters in a window title or icon name, as mosh caps them; applied by the server's
/// emulator and again by the client, which trusts nothing on the wire.
pub(crate) const MAX_TITLE_LEN: usize = 256;

/// Most bytes in a forwarded clipboard (OSC 52), as mosh caps it; a larger one is dropped. Applied
/// at both ends.
pub const MAXIMUM_CLIPBOARD_SIZE: usize = 16 * 1024;

/// The most bytes of hyperlinks (URIs and ids) one diff carries.
///
/// A screen's links are a few KiB (fux-vt keeps at most 4 MiB a screen); the server leaves off a row's links past this, and the
/// client drops a frame that carries more, so a hostile server cannot make the client keep much.
pub const MAX_LINK_BYTES: usize = 1 << 20;

/// Most bytes of a run's text: a character, of at most 4 bytes, for each cell of the widest row.
pub const MAX_RUN_TEXT: usize = 4 * MAX_DIM as usize;

/// Most bytes of a frame's dictionary ([`TerminalScreen::dictionary`]): DEFLATE's window, the
/// farthest back a compressed frame can reach.
pub const DICTIONARY_BYTES: usize = 32 * 1024;

/// Clamp a peer-supplied size into `[MIN_DIM, MAX_DIM]` on both axes: the one gate every resize
/// passes at both ends before a grid is built.
#[must_use]
pub fn clamp_dims(size: Size) -> Size {
    Size {
        rows: size.rows.clamp(MIN_DIM, MAX_DIM),
        cols: size.cols.clamp(MIN_DIM, MAX_DIM),
    }
}

/// Truncate `s` to at most `max` characters (not bytes), preserving whole scalars.
fn capped_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// Truncate `s` to at most `max` bytes, never splitting a scalar.
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
    /// Window title (OSC 2).
    title: String,
    /// Window icon name (OSC 1).
    icon: String,
    /// The clipboard the program set (OSC 52, base64), empty if none.
    clipboard: String,
    /// How many bells the program rang; the client rings when it grows.
    bell_count: u64,
    /// The program's exit code once it exited, for the client to exit with.
    exit_code: Option<u32>,
    /// Where the server's history stands: what the client may ask for.
    history: HistoryMark,
    /// How the PTY takes typed keys, if known.
    tty: Option<TtyModes>,
}

/// How the program's PTY takes typed keys: whether the kernel echoes them, and edits lines.
///
/// Line mode without echo is a password prompt (`getpass`, `read -s`, sudo, ssh,
/// passwd); neither is a line editor or a full-screen program, which echo for themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TtyModes {
    pub echo: bool,
    pub line: bool,
}

impl TtyModes {
    /// A password prompt: lines read without echo. Nothing typed may be shown.
    pub const fn password(self) -> bool {
        self.line && !self.echo
    }
}

impl Default for TerminalScreen {
    fn default() -> Self {
        Self::with_grid(Grid::blank(DEFAULT_SIZE))
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
            history: HistoryMark { newest: 0, len: 0 },
            tty: None,
        }
    }

    /// The screen a fresh emulator of this (clamped) size shows after `bytes`. For tests.
    pub fn from_bytes(rows: u16, cols: u16, bytes: &[u8]) -> Self {
        ServerTerminal::new(rows, cols, 0).map_or_else(
            |_| Self::default(),
            |mut emu| {
                emu.process(bytes);
                emu.snapshot()
            },
        )
    }

    /// The grid.
    pub const fn screen(&self) -> &Grid {
        &self.grid
    }

    /// The remote shell's exit code, once it has exited (`None` while alive).
    pub const fn exit_code(&self) -> Option<u32> {
        self.exit_code
    }

    pub const fn size(&self) -> Size {
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

    /// How many bells the program rang.
    pub const fn bell_count(&self) -> u64 {
        self.bell_count
    }

    /// Where the server's history stands.
    pub const fn history(&self) -> HistoryMark {
        self.history
    }

    /// How the program's PTY takes typed keys, if the server said.
    pub const fn tty(&self) -> Option<TtyModes> {
        self.tty
    }

    /// This screen scrolled `offset` rows back into the history `cache` holds part of: the
    /// history rows above its top, then its own rows, the top `rows` of them shown. A row not held
    /// is blank. The cursor is hidden, and mouse reporting on, so the wheel can scroll.
    #[must_use]
    pub fn scrolled_back(&self, cache: &HistoryCache, offset: usize) -> Self {
        let size = self.size();
        let mut grid = self.grid.clone();
        let blank: Arc<Cells> = Arc::new(Cells::new(usize::from(size.cols)));
        for row in 0..size.rows {
            // The row `offset - row` above the screen's top is history; the rest is the screen's.
            let shown = if let Some(above) = offset
                .checked_sub(usize::from(row))
                .filter(|&above| above > 0)
            {
                u64::try_from(above.saturating_sub(1))
                    .ok()
                    .map(|back| self.history.newest.saturating_sub(back))
                    .filter(|&name| self.history.holds(name))
                    .and_then(|name| cache.screen_row(name, size.cols))
            } else {
                let below = usize::from(row).saturating_sub(offset);
                u16::try_from(below)
                    .ok()
                    .and_then(|from| self.grid.row_parts(from))
            };
            let (cells, wrapped, links) =
                shown.unwrap_or_else(|| (Arc::clone(&blank), false, None));
            grid.set_row(row, cells, wrapped, links);
        }
        grid.set_modes(Modes {
            hide_cursor: true,
            mouse_mode: MouseProtocolMode::PressRelease,
            mouse_encoding: MouseProtocolEncoding::Sgr,
            ..self.grid.modes()
        });
        Self {
            grid,
            ..self.clone()
        }
    }

    /// The dictionary a frame diffed against this screen is compressed against: its rows as a
    /// frame encodes them ([`RowDiff`]), those nearest the cursor last, where a compressor reaches
    /// them most cheaply, then its side channels, cursor and modes as a frame carries them; at most
    /// [`DICTIONARY_BYTES`] in all.
    ///
    /// The rows are taken outwards from the cursor's until the budget is spent, so the cost is
    /// bounded on the largest screen: at most the budget and one row more.
    pub fn dictionary(&self) -> Vec<u8> {
        let rows = self.size().rows;
        let cursor = self.grid.cursor_position().0.min(rows.saturating_sub(1));
        let mut encoded: Vec<Vec<u8>> = Vec::new();
        let mut total = 0_usize;
        let mut budget = MAX_LINK_BYTES;
        for step in 0..rows.saturating_mul(2) {
            // The cursor's row, then one above, one below, and so on outwards.
            let away = step.div_ceil(2);
            let row = if step % 2 == 1 {
                cursor.checked_sub(away)
            } else {
                cursor.checked_add(away).filter(|&r| r < rows)
            };
            let Some(row) = row else {
                continue;
            };
            let Some(cells) = self.grid.row(row) else {
                continue;
            };
            let diff = RowDiff::of(
                row,
                cells,
                self.grid.row_wrapped(row),
                self.grid.row_links(row),
                &mut budget,
            );
            let Ok(bytes) = postcard::to_allocvec(&diff) else {
                continue;
            };
            total = total.saturating_add(bytes.len());
            encoded.push(bytes);
            if total >= DICTIONARY_BYTES {
                break;
            }
        }
        let mut out = Vec::with_capacity(total.min(DICTIONARY_BYTES));
        for bytes in encoded.iter().rev() {
            out.extend_from_slice(bytes);
        }
        // Last, the screen's side channels, cursor and modes as a frame that changes no row
        // carries them: most frames' own are the same, or nearly.
        if let Ok(header) = postcard::to_allocvec(&self.diff_from(self)) {
            out.extend_from_slice(&header);
        }
        // Only the last window's worth can be reached.
        let excess = out.len().saturating_sub(DICTIONARY_BYTES);
        out.split_off(excess)
    }

    /// How many rows differ between this screen and `other`, or `None` if their sizes do. Rows
    /// that share their cells compare without reading them.
    pub fn rows_differing(&self, other: &Self) -> Option<usize> {
        let size = self.size();
        (size == other.size()).then(|| {
            (0..size.rows)
                .filter(|&r| !self.grid.row_eq(&other.grid, r))
                .count()
        })
    }

    /// The cells `screens` hold in memory together: a row several of them share counts once.
    pub fn distinct_cells<'a>(screens: impl IntoIterator<Item = &'a Self>) -> usize {
        Grid::distinct_cells(screens.into_iter().map(|screen| &screen.grid))
    }

    /// The cells `screens` hold in memory beyond what `base` holds: a row they share with `base`
    /// costs nothing, and a row several of them share counts once.
    pub fn cells_beyond<'a>(base: &Self, screens: impl IntoIterator<Item = &'a Self>) -> usize {
        Grid::cells_beyond(&base.grid, screens.into_iter().map(|screen| &screen.grid))
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
            Color::Idx(i) => Self::Idx(i),
            Color::Rgb(r, g, b) => Self::Rgb(r, g, b),
            Color::Default | _ => Self::Default,
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
    /// A run's narrow cells, one character of its text each, in turn: same-style text as one
    /// string, about a byte a cell.
    Chars,
    /// A run's wide glyphs, one character of its text each, each with its continuation: two
    /// cells a character.
    WideChars,
}

/// A cell's style on the wire: one bit per attribute, for blinking one of two, and for an underline
/// its style.
///
/// Decoding rejects any bit outside those defined, both blinks at once, a style no
/// underline has, and a style without an underline, so every value is a style a cell can have.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireStyle(u16);

impl WireStyle {
    pub const BOLD: u16 = 1;
    pub const DIM: u16 = 2;
    pub const ITALIC: u16 = 4;
    pub const UNDERLINE: u16 = 8;
    pub const INVERSE: u16 = 16;
    pub const HIDDEN: u16 = 32;
    pub const STRIKEOUT: u16 = 64;
    pub const BLINK_SLOW: u16 = 128;
    pub const BLINK_RAPID: u16 = 256;
    /// The underline's style, in bits 9 to 11: a single underline is none of them, so a plain
    /// underline is [`WireStyle::UNDERLINE`] alone, as before styles were carried.
    pub const UNDERLINE_DOUBLE: u16 = 512;
    pub const UNDERLINE_CURLY: u16 = 1024;
    pub const UNDERLINE_DOTTED: u16 = 1536;
    pub const UNDERLINE_DASHED: u16 = 2048;
    const UNDERLINE_STYLE: u16 = 3584;
    const ALL: u16 = 4095;

    /// The style with exactly `bits`, or `None` if any is not a defined bit, both blinks are, the
    /// underline's style is none defined, or a style is given with no underline.
    pub const fn new(bits: u16) -> Option<Self> {
        let blinks = Self::BLINK_SLOW | Self::BLINK_RAPID;
        let style = bits & Self::UNDERLINE_STYLE;
        if bits & !Self::ALL == 0
            && bits & blinks != blinks
            && style <= Self::UNDERLINE_DASHED
            && (style == 0 || bits & Self::UNDERLINE != 0)
        {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    const fn has(self, bit: u16) -> bool {
        self.0 & bit != 0
    }

    /// The style of `attributes`.
    fn of(attributes: Attributes) -> Self {
        let bit = |on: bool, b: u16| if on { b } else { 0 };
        let blink = match attributes.blink() {
            Blink::Slow => Self::BLINK_SLOW,
            Blink::Rapid => Self::BLINK_RAPID,
            Blink::None | _ => 0,
        };
        // A style fux-vt adds later is carried as a single underline.
        let style = match attributes.underline_style() {
            UnderlineStyle::Double => Self::UNDERLINE_DOUBLE,
            UnderlineStyle::Curly => Self::UNDERLINE_CURLY,
            UnderlineStyle::Dotted => Self::UNDERLINE_DOTTED,
            UnderlineStyle::Dashed => Self::UNDERLINE_DASHED,
            UnderlineStyle::None | UnderlineStyle::Single | _ => 0,
        };
        // Only defined bits, at most one blink, and a style only with an underline.
        Self(
            bit(attributes.bold(), Self::BOLD)
                | bit(attributes.dim(), Self::DIM)
                | bit(attributes.italic(), Self::ITALIC)
                | bit(attributes.underline(), Self::UNDERLINE)
                | bit(attributes.inverse(), Self::INVERSE)
                | bit(attributes.hidden(), Self::HIDDEN)
                | bit(attributes.strikeout(), Self::STRIKEOUT)
                | blink
                | if attributes.underline() { style } else { 0 },
        )
    }

    /// `attributes` with this style.
    const fn on(self, attributes: Attributes) -> Attributes {
        let blink = if self.has(Self::BLINK_SLOW) {
            Blink::Slow
        } else if self.has(Self::BLINK_RAPID) {
            Blink::Rapid
        } else {
            Blink::None
        };
        let underline = if self.has(Self::UNDERLINE) {
            match self.0 & Self::UNDERLINE_STYLE {
                Self::UNDERLINE_DOUBLE => UnderlineStyle::Double,
                Self::UNDERLINE_CURLY => UnderlineStyle::Curly,
                Self::UNDERLINE_DOTTED => UnderlineStyle::Dotted,
                Self::UNDERLINE_DASHED => UnderlineStyle::Dashed,
                _ => UnderlineStyle::Single,
            }
        } else {
            UnderlineStyle::None
        };
        attributes
            .with_bold(self.has(Self::BOLD))
            .with_dim(self.has(Self::DIM))
            .with_italic(self.has(Self::ITALIC))
            .with_underline_style(underline)
            .with_inverse(self.has(Self::INVERSE))
            .with_hidden(self.has(Self::HIDDEN))
            .with_strikeout(self.has(Self::STRIKEOUT))
            .with_blink(blink)
    }
}

impl Serialize for WireStyle {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for WireStyle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u16::deserialize(deserializer)?;
        Self::new(bits).ok_or_else(|| {
            de::Error::invalid_value(
                de::Unexpected::Unsigned(u64::from(bits)),
                &"style bits within 0b1111_1111_1111, at most one blink, an underline style of \
                  at most 4 and only with an underline",
            )
        })
    }
}

/// A cell's text on the wire: one grapheme cluster, at most [`Cell::CLUSTER_CAPACITY`] bytes of
/// UTF-8 (or, for a run of characters, one character a cell), and no control character.
///
/// The client prints a cell's text to the user's terminal as is, so it must not be able to carry
/// an escape sequence: fux-vt never puts a control character in a cell, and decoding refuses one,
/// as it refuses text too long for a cell, which drops the frame. Text up to
/// [`CellText::INLINE`] bytes, nearly all of it, is stored inline, so building or decoding a run of
/// it allocates nothing; a longer cluster is boxed, which a frame pays for in its own bytes. It
/// encodes as a string.
#[derive(Clone, PartialEq, Eq)]
pub struct CellText(Text);

#[derive(Clone, PartialEq, Eq)]
enum Text {
    Inline {
        len: u8,
        bytes: [u8; CellText::INLINE],
    },
    Long(Box<str>),
}

impl Default for CellText {
    fn default() -> Self {
        Self(Text::Inline {
            len: 0,
            bytes: [0; Self::INLINE],
        })
    }
}

impl CellText {
    /// The most bytes kept inline.
    pub const INLINE: usize = 22;

    /// `text`, or `None` if it is longer than [`Cell::CLUSTER_CAPACITY`] bytes or holds a
    /// control character (C0, DEL or C1).
    pub fn new(text: &str) -> Option<Self> {
        if text.len() > Cell::CLUSTER_CAPACITY {
            return None;
        }
        Self::run(text)
    }

    /// `text` as a run's text ([`CellKind::Chars`], [`CellKind::WideChars`]): at most
    /// [`MAX_RUN_TEXT`] bytes, with no control character.
    fn run(text: &str) -> Option<Self> {
        if text.len() > MAX_RUN_TEXT || text.chars().any(char::is_control) {
            return None;
        }
        let mut bytes = [0; Self::INLINE];
        let Some(inline) = bytes.get_mut(..text.len()) else {
            return Some(Self(Text::Long(text.into())));
        };
        inline.copy_from_slice(text.as_bytes());
        Some(Self(Text::Inline {
            len: u8::try_from(text.len()).ok()?,
            bytes,
        }))
    }

    pub fn as_str(&self) -> &str {
        match &self.0 {
            // Only ever a whole `&str`'s bytes, so the prefix is valid UTF-8.
            Text::Inline { len, bytes } => bytes
                .get(..usize::from(*len))
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .unwrap_or_default(),
            Text::Long(text) => text,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }
}

impl std::fmt::Debug for CellText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl Serialize for CellText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CellText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(CellTextVisitor)
    }
}

/// Takes a borrowed or an owned string (serde hands both to `visit_str`) that fits a cell.
struct CellTextVisitor;

impl de::Visitor<'_> for CellTextVisitor {
    type Value = CellText;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a string of at most {MAX_RUN_TEXT} bytes with no control character"
        )
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<CellText, E> {
        // A cell's own text is held to a cluster's size by its run ([`Run`]), which knows its kind.
        CellText::run(text).ok_or_else(|| E::invalid_value(de::Unexpected::Str(text), &self))
    }
}

/// One cell on the wire. A continuation (the right half of a wide glyph) is empty with default
/// colours and no style.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCell {
    pub text: CellText,
    pub kind: CellKind,
    pub fg: WireColor,
    pub bg: WireColor,
    pub underline_color: WireColor,
    pub style: WireStyle,
    /// The cell's hyperlink: 0 for none, else one more than its place in its row's links.
    pub link: u16,
}

impl WireCell {
    fn of(cell: CellRef<'_>) -> Self {
        let a = cell.attributes();
        Self {
            // fux-vt keeps at most `CLUSTER_CAPACITY` bytes, and no control character.
            text: CellText::new(cell.contents()).unwrap_or_default(),
            kind: if cell.is_wide_continuation() {
                CellKind::Continuation
            } else if cell.is_wide() {
                CellKind::Wide
            } else {
                CellKind::Narrow
            },
            fg: a.foreground().into(),
            bg: a.background().into(),
            underline_color: a.underline_color().into(),
            style: WireStyle::of(a),
            link: 0,
        }
    }

    /// Set cell `at` of `cells` to this one, or return `None` if the encoding is malformed (a
    /// continuation carrying content). Text the row has no room left for is cut to what fits
    /// inline, as fux-vt cuts it; a row from fux-vt always has the room.
    fn write_to(&self, cells: &mut Cells, at: usize) -> Option<()> {
        match self.kind {
            CellKind::Continuation => self
                .plain_continuation()
                .then(|| cells.set_cell(at, Cell::wide_continuation())),
            CellKind::Narrow | CellKind::Wide => {
                cells.set_text(
                    at,
                    self.text.as_str(),
                    self.kind == CellKind::Wide,
                    self.attributes(),
                );
                Some(())
            }
            CellKind::Chars => {
                let mut buf = [0; 4];
                for (col, ch) in (at..).zip(self.text.as_str().chars()) {
                    cells.set_text(col, ch.encode_utf8(&mut buf), false, self.attributes());
                }
                Some(())
            }
            CellKind::WideChars => {
                let mut buf = [0; 4];
                for (pair, ch) in self.text.as_str().chars().enumerate() {
                    let col = pair.checked_mul(2).and_then(|c| c.checked_add(at))?;
                    cells.set_text(col, ch.encode_utf8(&mut buf), true, self.attributes());
                    cells.set_cell(col.checked_add(1)?, Cell::wide_continuation());
                }
                Some(())
            }
        }
    }

    /// Whether this is a continuation as one is sent: empty, with default colours and no style.
    fn plain_continuation(&self) -> bool {
        self.kind == CellKind::Continuation
            && self.text.is_empty()
            && self.fg == WireColor::Default
            && self.bg == WireColor::Default
            && self.underline_color == WireColor::Default
            && self.style == WireStyle::default()
    }

    fn attributes(&self) -> Attributes {
        self.style
            .on(Attributes::new(self.fg.into(), self.bg.into())
                .with_underline_color(self.underline_color.into()))
    }

    /// Whether this cell draws as `other` does: the same colours and style.
    fn same_look(&self, other: &Self) -> bool {
        self.fg == other.fg
            && self.bg == other.bg
            && self.underline_color == other.underline_color
            && self.style == other.style
            && self.link == other.link
    }
}

/// `count` consecutive identical cells, or `count` cells (or glyphs) of the text's characters.
///
/// For [`CellKind::Chars`] and [`CellKind::WideChars`] the text's characters go in turn. A run is
/// never empty: a zero count fails to decode, as does a cell's text longer than a cluster, or a
/// run's text whose characters are not `count`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawRun")]
pub struct Run {
    pub count: NonZeroU16,
    pub cell: WireCell,
}

/// A [`Run`] as it decodes, before its text is checked against its kind.
#[derive(Deserialize)]
struct RawRun {
    count: NonZeroU16,
    cell: WireCell,
}

impl TryFrom<RawRun> for Run {
    type Error = &'static str;

    fn try_from(raw: RawRun) -> Result<Self, Self::Error> {
        let text = raw.cell.text.as_str();
        let fits = match raw.cell.kind {
            CellKind::Narrow | CellKind::Wide | CellKind::Continuation => {
                text.len() <= Cell::CLUSTER_CAPACITY
            }
            CellKind::Chars | CellKind::WideChars => {
                text.chars().count() == usize::from(raw.count.get())
            }
        };
        if fits {
            Ok(Self {
                count: raw.count,
                cell: raw.cell,
            })
        } else {
            Err("a run whose text does not fit its kind")
        }
    }
}

impl Run {
    /// The cells the run covers.
    fn cells(&self) -> usize {
        let count = usize::from(self.count.get());
        match self.cell.kind {
            CellKind::WideChars => count.saturating_mul(2),
            CellKind::Narrow | CellKind::Wide | CellKind::Continuation | CellKind::Chars => count,
        }
    }

    /// Add `ch` to a run of characters.
    fn push_char(&mut self, ch: char) -> bool {
        let Some(count) = self.count.checked_add(1) else {
            return false;
        };
        let mut text = self.cell.text.as_str().to_owned();
        text.push(ch);
        let Some(text) = CellText::run(&text) else {
            return false;
        };
        self.count = count;
        self.cell.text = text;
        true
    }

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

/// A hyperlink on the wire: its URI and the id the program gave it (empty for none).
///
/// Each is within fux-vt's limits, which decoding holds it to. What they hold is checked again before the client
/// paints them ([`Link::safe`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawLink")]
pub struct WireLink {
    pub uri: String,
    pub id: String,
}

/// A [`WireLink`] as it decodes, before its lengths are checked.
#[derive(Deserialize)]
struct RawLink {
    uri: String,
    id: String,
}

impl TryFrom<RawLink> for WireLink {
    type Error = &'static str;

    fn try_from(raw: RawLink) -> Result<Self, Self::Error> {
        if raw.uri.len() <= fux_vt::URI_LIMIT && raw.id.len() <= fux_vt::ID_LIMIT {
            Ok(Self {
                uri: raw.uri,
                id: raw.id,
            })
        } else {
            Err("a hyperlink past fux-vt's limits")
        }
    }
}

/// One whole row: its runs cover exactly the screen width, and its links are the ones its cells
/// name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowDiff {
    pub row: u16,
    pub wrapped: bool,
    pub runs: Vec<Run>,
    /// The row's distinct hyperlinks, at most [`MAX_ROW_LINKS`].
    pub links: Vec<WireLink>,
}

impl RowDiff {
    /// The row `row` of `cells` with `links`, if they fit in what is left of `budget`, the link
    /// bytes the diff may still carry; past it, the row goes without its links.
    fn of(
        row: u16,
        cells: &Cells,
        wrapped: bool,
        links: Option<&RowLinks>,
        budget: &mut usize,
    ) -> Self {
        let links = links.filter(|links| {
            let fits = links.bytes() <= *budget;
            if fits {
                *budget = budget.saturating_sub(links.bytes());
            }
            fits
        });
        let (runs, links) = runs_of(cells, links);
        Self {
            row,
            wrapped,
            runs,
            links,
        }
    }

    /// The row these runs decode to, exactly `cols` cells, with its links (see [`cells_of`]).
    fn decode(&self, cols: u16) -> Option<(Cells, Option<Arc<RowLinks>>)> {
        cells_of(&self.runs, &self.links, cols)
    }

    /// The bytes of hyperlinks this row carries.
    fn link_bytes(&self) -> usize {
        link_bytes(&self.links)
    }
}

/// `cells` as runs, with `links`: identical cells as one run, same-looking narrow characters as one
/// run of their text ([`CellKind::Chars`]), and same-looking wide glyphs as one
/// ([`CellKind::WideChars`]); each run's cells name the same link.
fn runs_of(cells: &Cells, links: Option<&RowLinks>) -> (Vec<Run>, Vec<WireLink>) {
    let link_at = |col: usize| {
        links
            .and_then(|links| links.cells.get(col).copied())
            .unwrap_or(0)
    };
    // The one character of a cell that holds exactly one.
    let lone_char = |cell: CellRef<'_>| {
        let mut chars = cell.contents().chars();
        chars.next().filter(|_| chars.next().is_none())
    };
    let mut runs: Vec<Run> = Vec::new();
    // The last cell, while the last run is of cells identical to it.
    let mut previous: Option<(CellRef<'_>, u16)> = None;
    let mut col = 0_usize;
    while let Some(cell) = cells.get(col) {
        let link = link_at(col);
        let wire = WireCell {
            link,
            ..WireCell::of(cell)
        };
        let narrow = lone_char(cell).filter(|_| wire.kind == CellKind::Narrow);
        // A wide glyph of one character followed by its plain continuation, of the same link.
        let wide = lone_char(cell).filter(|_| {
            wire.kind == CellKind::Wide
                && cells
                    .get(col.saturating_add(1))
                    .is_some_and(|next| WireCell::of(next).plain_continuation())
                && link_at(col.saturating_add(1)) == link
        });
        let last = runs.last_mut();
        let joined = match (last, narrow, wide) {
            (Some(last), Some(ch), _)
                if last.cell.kind == CellKind::Chars && last.cell.same_look(&wire) =>
            {
                last.push_char(ch).then_some(1)
            }
            (Some(last), _, Some(ch))
                if last.cell.kind == CellKind::WideChars && last.cell.same_look(&wire) =>
            {
                last.push_char(ch).then_some(2)
            }
            (Some(last), _, _) if previous == Some((cell, link)) => {
                if last.extend() {
                    col = col.saturating_add(1);
                    continue;
                }
                None
            }
            // A lone character, then another that looks the same: a run of characters.
            (Some(last), Some(ch), _)
                if last.cell.kind == CellKind::Narrow
                    && last.count == NonZeroU16::MIN
                    && last.cell.same_look(&wire)
                    && last.cell.text.as_str().chars().count() == 1 =>
            {
                last.cell.kind = CellKind::Chars;
                last.push_char(ch).then_some(1)
            }
            _ => None,
        };
        if let Some(used) = joined {
            previous = None;
            col = col.saturating_add(used);
            continue;
        }
        if wide.is_some() {
            runs.push(Run {
                count: NonZeroU16::MIN,
                cell: WireCell {
                    kind: CellKind::WideChars,
                    ..wire
                },
            });
            previous = None;
            col = col.saturating_add(2);
        } else {
            runs.push(Run {
                count: NonZeroU16::MIN,
                cell: wire,
            });
            previous = Some((cell, link));
            col = col.saturating_add(1);
        }
    }
    let links = links.map_or_else(Vec::new, |links| {
        links
            .table
            .iter()
            .map(|link| WireLink {
                uri: link.uri.clone(),
                id: link.id.clone(),
            })
            .collect()
    });
    (runs, links)
}

/// The row `runs` decode to, exactly `cols` cells, with its `links`, or `None` if the runs are
/// malformed, don't cover the row exactly, or name a link the row does not have. Work is bounded
/// by `cols`: every run is non-empty, and each cell's text by [`Cell::CLUSTER_CAPACITY`].
fn cells_of(runs: &[Run], links: &[WireLink], cols: u16) -> Option<(Cells, Option<Arc<RowLinks>>)> {
    if links.len() > MAX_ROW_LINKS {
        return None;
    }
    let mut cells = Cells::new(usize::from(cols));
    let mut linked = Vec::new();
    let mut at = 0_usize;
    for run in runs {
        let end = at
            .checked_add(run.cells())
            .filter(|&end| end <= usize::from(cols))?;
        if usize::from(run.cell.link) > links.len() {
            return None;
        }
        match run.cell.kind {
            CellKind::Chars | CellKind::WideChars => run.cell.write_to(&mut cells, at)?,
            CellKind::Narrow | CellKind::Wide | CellKind::Continuation => {
                for col in at..end {
                    run.cell.write_to(&mut cells, col)?;
                }
            }
        }
        if !links.is_empty() {
            linked.extend(std::iter::repeat_n(run.cell.link, end.saturating_sub(at)));
        }
        at = end;
    }
    if at != usize::from(cols) {
        return None;
    }
    let links = (!links.is_empty()).then(|| {
        Arc::new(RowLinks {
            table: links
                .iter()
                .map(|link| Link {
                    uri: link.uri.clone(),
                    id: link.id.clone(),
                })
                .collect(),
            cells: linked,
        })
    });
    Some((cells, links))
}

/// The bytes of hyperlinks `links` carry.
fn link_bytes(links: &[WireLink]) -> usize {
    links
        .iter()
        .map(|link| link.uri.len().saturating_add(link.id.len()))
        .fold(0_usize, usize::saturating_add)
}

/// Whether `cell` is what a blank grid holds: no text, neither half of a wide glyph, the default
/// style.
fn is_blank(cell: CellRef<'_>) -> bool {
    !cell.has_contents()
        && !cell.is_wide()
        && !cell.is_wide_continuation()
        && cell.attributes() == Attributes::default()
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
            MouseProtocolMode::Press => Self::Press,
            MouseProtocolMode::PressRelease => Self::PressRelease,
            MouseProtocolMode::ButtonMotion => Self::ButtonMotion,
            MouseProtocolMode::AnyMotion => Self::AnyMotion,
            MouseProtocolMode::None | _ => Self::None,
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
            MouseProtocolEncoding::Utf8 => Self::Utf8,
            MouseProtocolEncoding::Sgr => Self::Sgr,
            MouseProtocolEncoding::Default | _ => Self::Default,
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

/// Most [`Shift`]s in one diff. Each costs at most O(rows) to apply; the server keeps the longest
/// runs when it finds more.
pub const MAX_SHIFTS: usize = 32;

/// Rows of the base that moved: rows `top..top + len` go to `top + by..top + len + by` (a negative
/// `by` is up).
///
/// Both ranges lie within `0..MAX_DIM`, which decoding checks; a zero length or offset fails to
/// decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shift {
    pub top: u16,
    pub len: NonZeroU16,
    pub by: NonZeroI16,
}

impl Shift {
    /// The rows it moves, if within `0..MAX_DIM`.
    pub fn source(self) -> Option<Range<u16>> {
        let end = self.top.checked_add(self.len.get())?;
        (end <= MAX_DIM).then_some(self.top..end)
    }

    /// The rows it moves them to, if within `0..MAX_DIM`.
    pub fn destination(self) -> Option<Range<u16>> {
        let source = self.source()?;
        let moved =
            |row: u16| u16::try_from(i32::from(row).checked_add(i32::from(self.by.get()))?).ok();
        let (start, end) = (moved(source.start)?, moved(source.end)?);
        (end <= MAX_DIM).then_some(start..end)
    }

    /// Each source row with its destination.
    pub(crate) fn pairs(self) -> impl Iterator<Item = (u16, u16)> {
        let source = self.source().unwrap_or_default();
        let destination = self.destination().unwrap_or_default();
        source.zip(destination)
    }
}

/// Whether no two of `ranges` share a row.
fn disjoint(ranges: &[Range<u16>]) -> bool {
    ranges.iter().enumerate().all(|(i, a)| {
        ranges
            .iter()
            .skip(i.saturating_add(1))
            .all(|b| a.end <= b.start || b.end <= a.start)
    })
}

/// The rows a diff moves before it replaces any.
///
/// At most [`MAX_SHIFTS`] [`Shift`]s, all reading the base, no two sharing a source row or a
/// destination row. A row a shift moved and no shift moved into is blank.
///
/// Decoding checks all of that; only the screen's size is left for [`TerminalScreen::apply`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Shifts(Vec<Shift>);

impl Shifts {
    /// `shifts`, or `None` if there are too many, one leaves `0..MAX_DIM`, or two share a row.
    pub fn new(shifts: Vec<Shift>) -> Option<Self> {
        if shifts.len() > MAX_SHIFTS {
            return None;
        }
        let sources: Vec<Range<u16>> = shifts.iter().map(|s| s.source()).collect::<Option<_>>()?;
        let destinations: Vec<Range<u16>> = shifts
            .iter()
            .map(|s| s.destination())
            .collect::<Option<_>>()?;
        (disjoint(&sources) && disjoint(&destinations)).then_some(Self(shifts))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Shift> {
        self.0.iter()
    }

    /// Whether every row they touch is within a screen of `rows` rows.
    fn fit(&self, rows: u16) -> bool {
        self.0.iter().all(|shift| {
            shift.source().is_some_and(|s| s.end <= rows)
                && shift.destination().is_some_and(|d| d.end <= rows)
        })
    }
}

impl<'a> IntoIterator for &'a Shifts {
    type Item = &'a Shift;
    type IntoIter = std::slice::Iter<'a, Shift>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'de> Deserialize<'de> for Shifts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(ShiftsVisitor)
    }
}

/// Reads at most [`MAX_SHIFTS`] shifts, so a hostile length costs nothing, then checks them.
struct ShiftsVisitor;

impl<'de> de::Visitor<'de> for ShiftsVisitor {
    type Value = Shifts;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "at most {MAX_SHIFTS} row shifts within the screen, no two sharing a row"
        )
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Shifts, A::Error> {
        let mut shifts = Vec::new();
        while let Some(shift) = seq.next_element()? {
            if shifts.len() == MAX_SHIFTS {
                return Err(de::Error::invalid_length(
                    MAX_SHIFTS.saturating_add(1),
                    &self,
                ));
            }
            shifts.push(shift);
        }
        Shifts::new(shifts).ok_or_else(|| de::Error::invalid_value(de::Unexpected::Seq, &self))
    }
}

/// The change from one [`TerminalScreen`] to another, on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenDiff {
    /// The new size if the screen was resized; the client starts from a blank grid of that size,
    /// and `rows` then carries every row that isn't blank.
    pub resize: Option<Size>,
    /// New window title if it changed.
    pub title: Option<String>,
    /// New window icon name if it changed.
    pub icon: Option<String>,
    /// New clipboard if it changed.
    pub clipboard: Option<String>,
    /// The bell count, always sent, so a change of it alone is not lost.
    pub bell_count: u64,
    /// The remote shell's exit code, set on the final (shutdown) frame.
    pub exit_code: Option<u32>,
    /// Where the server's history stands, if that changed.
    pub history: Option<HistoryMark>,
    /// How the PTY takes typed keys, if that changed.
    pub tty: Option<TtyModes>,
    /// The cursor at the target state.
    pub cursor: (u16, u16),
    /// The modes at the target state.
    pub modes: WireModes,
    /// Rows of the base that moved, applied before `rows`: a scroll, in or out of a region, or an
    /// inserted or deleted line. Never with a resize.
    pub shifts: Shifts,
    /// Every row that differs from the base once shifted (or from blank after a resize), whole.
    pub rows: Vec<RowDiff>,
}

impl TerminalScreen {
    /// The diff that turns `base` into `self`.
    pub fn diff_from(&self, base: &Self) -> ScreenDiff {
        let resized = self.size() != base.size();
        let rows = self.size().rows;
        // Rows that only moved are found by the cells they share with the base, and moved rather
        // than sent.
        let moves = if resized {
            Vec::new()
        } else {
            self.grid.moves_from(&base.grid, rows)
        };
        let (shifts, moved) = match Shifts::new(moves) {
            Some(shifts) if !shifts.is_empty() => match base.grid.shifted(&shifts) {
                Some(moved) => (shifts, Some(moved)),
                None => (Shifts::default(), None),
            },
            _ => (Shifts::default(), None),
        };
        let base_grid = moved.as_ref().unwrap_or(&base.grid);
        let mut budget = MAX_LINK_BYTES;
        let changed = (0..rows).filter_map(|r| {
            let cells = self.grid.row(r)?;
            let wrapped = self.grid.row_wrapped(r);
            // A row shared with the base is the same without comparing its cells.
            let same = if resized {
                !wrapped && cells.iter().all(is_blank)
            } else {
                self.grid.row_eq(base_grid, r)
            };
            (!same).then(|| RowDiff::of(r, cells, wrapped, self.grid.row_links(r), &mut budget))
        });
        ScreenDiff {
            resize: resized.then(|| self.size()),
            title: (self.title != base.title).then(|| self.title.clone()),
            icon: (self.icon != base.icon).then(|| self.icon.clone()),
            clipboard: (self.clipboard != base.clipboard).then(|| self.clipboard.clone()),
            bell_count: self.bell_count,
            exit_code: self.exit_code,
            history: (self.history != base.history).then_some(self.history),
            tty: self.tty.filter(|_| self.tty != base.tty),
            cursor: self.grid.cursor_position(),
            modes: self.grid.modes().into(),
            shifts,
            rows: changed.collect(),
        }
    }

    /// Apply `diff`, a diff against this screen. A malformed diff changes nothing.
    pub fn apply(&mut self, diff: &ScreenDiff) {
        // All server-controlled: the grid is validated whole before any of it is committed, so a
        // malformed frame changes nothing. This clamp is what bounds the grid a resize allocates.
        let Size { rows, cols } = diff.resize.map_or_else(|| self.size(), clamp_dims);
        if diff.rows.len() > usize::from(rows)
            || (!diff.shifts.is_empty() && (diff.resize.is_some() || !diff.shifts.fit(rows)))
        {
            return;
        }
        // A hostile server's links are bounded: more than a diff may carry drops the frame.
        let link_bytes = diff
            .rows
            .iter()
            .map(RowDiff::link_bytes)
            .fold(0_usize, usize::saturating_add);
        if link_bytes > MAX_LINK_BYTES {
            return;
        }
        // Every row decodes before any is committed, in the diff's order. At most `rows × cols`
        // cells, which the clamp bounds.
        let mut staged = Vec::with_capacity(diff.rows.len());
        for row in &diff.rows {
            let Some(cells) = (row.row < rows).then(|| row.decode(cols)).flatten() else {
                return;
            };
            staged.push(cells);
        }
        let grid = if diff.resize.is_some() {
            Grid::blank(Size { rows, cols })
        } else {
            // Rows move as shared cells, never copied.
            let Some(moved) = self.grid.shifted(&diff.shifts) else {
                return;
            };
            moved
        };
        self.grid = grid;
        // Only the rows the diff carries are replaced; the rest stay shared with the base.
        for (row, (cells, links)) in diff.rows.iter().zip(staged) {
            self.grid
                .set_row(row.row, Arc::new(cells), row.wrapped, links);
        }
        let (crow, ccol) = diff.cursor;
        self.grid
            .set_cursor((crow.min(rows.saturating_sub(1)), ccol.min(cols)));
        self.grid.set_modes(diff.modes.into());

        // Never backwards.
        self.bell_count = self.bell_count.max(diff.bell_count);
        // Capped again: the server's emulator caps them, but a hostile server need not.
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
        if let Some(history) = diff.history {
            self.history = history;
        }
        if diff.tty.is_some() {
            self.tty = diff.tty;
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
        assert_eq!(diff.resize, Some(Size::new(40, 120)));
        let mut c = a;
        c.apply(&diff);
        assert_eq!(c, b);
        assert_eq!(c.size(), Size::new(40, 120));
    }

    #[test]
    fn clamp_dims_bounds_both_extremes() {
        assert_eq!(
            clamp_dims(Size::new(65000, 65000)),
            Size::new(MAX_DIM, MAX_DIM),
            "huge -> MAX_DIM"
        );
        assert_eq!(
            clamp_dims(Size::new(0, 0)),
            Size::new(MIN_DIM, MIN_DIM),
            "zero -> MIN_DIM"
        );
        assert_eq!(
            clamp_dims(Size::new(24, 80)),
            Size::new(24, 80),
            "in-range passes through"
        );
        assert_eq!(
            clamp_dims(Size::new(0, 5000)),
            Size::new(MIN_DIM, MAX_DIM),
            "mixed clamps each axis"
        );
    }

    /// A diff that changes nothing but `resize`, for the clamp tests.
    fn resize_only(resize: Size) -> ScreenDiff {
        ScreenDiff {
            resize: Some(resize),
            title: None,
            icon: None,
            clipboard: None,
            history: None,
            tty: None,
            bell_count: 0,
            exit_code: None,
            cursor: (0, 0),
            modes: Modes::default().into(),
            shifts: Shifts::default(),
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
        // Inline and boxed text, every style bit, blink and underline style.
        let text = ".{0,40}".prop_filter_map("fits a cell", |text| CellText::new(&text));
        let style = (0u16..=4095).prop_filter_map("a style", WireStyle::new);
        (
            text,
            kind,
            color.clone(),
            color.clone(),
            color,
            style,
            0u16..4,
        )
            .prop_map(
                |(text, kind, fg, bg, underline_color, style, link)| WireCell {
                    text,
                    kind,
                    fg,
                    bg,
                    underline_color,
                    style,
                    link,
                },
            )
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
            proptest::collection::vec(
                ("[ -~]{0,40}", "[!-~]{0,8}").prop_map(|(uri, id)| WireLink { uri, id }),
                0..4,
            ),
        )
            .prop_map(|(row, wrapped, runs, links)| RowDiff {
                row,
                wrapped,
                runs,
                links,
            })
    }

    /// Shifts of any shape: within a small screen or not, overlapping or not, as many as allowed.
    fn shifts() -> impl proptest::strategy::Strategy<Value = Shifts> {
        use proptest::prelude::*;
        proptest::collection::vec(
            (0u16..40, 1u16..40, -40i16..40).prop_filter_map("nonzero", |(top, len, by)| {
                Some(Shift {
                    top,
                    len: NonZeroU16::new(len)?,
                    by: NonZeroI16::new(by)?,
                })
            }),
            0..4,
        )
        .prop_filter_map("valid shifts", Shifts::new)
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
            shifts in shifts(),
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
            let resize = resize.map(|(rows, cols)| Size::new(rows, cols));
            let diff = ScreenDiff {
                resize, title, icon, clipboard, bell_count, exit_code, history: None, tty: None, cursor, modes,
                shifts, rows,
            };
            let mut screen = TerminalScreen::default();
            screen.apply(&diff); // must not panic on adversarial input
            let Size { rows, cols } = screen.size();
            proptest::prop_assert!((MIN_DIM..=MAX_DIM).contains(&rows), "rows {rows} escaped the clamp");
            proptest::prop_assert!((MIN_DIM..=MAX_DIM).contains(&cols), "cols {cols} escaped the clamp");
            for r in 0..rows {
                proptest::prop_assert_eq!(screen.screen().row(r).map(Cells::len), Some(usize::from(cols)));
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
                let Size { rows, cols } = screen.size();
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
                emu.resize(Size::new(rows, cols));
            }
            emu.process(&second);
            let target = emu.snapshot();
            let mut client = base.clone();
            client.apply(&target.diff_from(&base));
            proptest::prop_assert_eq!(client, target);
        }
    }

    /// Scroll-heavy output: text, line feeds at the bottom, scroll regions, scrolling up and down,
    /// reverse index, inserted and deleted lines, erasing.
    const SCROLL_PIECES: [&str; 14] = [
        "text",
        "\r\n",
        "\r\nmore",
        "\x1b[2;7r",
        "\x1b[r",
        "\x1b[7;1H",
        "\x1b[2;1H\x1bM",
        "\x1b[2S",
        "\x1b[T",
        "\x1b[3;1H\x1b[2L",
        "\x1b[4;1H\x1b[M",
        "\x1b[K",
        "\x1b[2J",
        "日本",
    ];

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Scrolling output diffs against any older frame (the acknowledged one can be several
        /// back) and applies to exactly the server's screen, the moved rows shared with the base.
        #[test]
        fn scrolled_screens_roundtrip_from_any_older_base(
            steps in proptest::collection::vec(
                proptest::collection::vec(0..SCROLL_PIECES.len(), 1..5),
                1..10,
            ),
            back in 1usize..4,
        ) {
            let mut emu = ServerTerminal::new(8, 12, 0).expect("emulator");
            let mut frames = vec![emu.snapshot()];
            for pieces in steps {
                for piece in pieces {
                    emu.process(SCROLL_PIECES[piece].as_bytes());
                }
                let target = emu.snapshot();
                let base = &frames[frames.len().saturating_sub(back)];
                let diff = target.diff_from(base);
                let mut client = base.clone();
                client.apply(&diff);
                proptest::prop_assert_eq!(&client, &target);
                // Every shifted row is shared with the base, not copied, unless the diff also carries
                // it (its wrap flag changed).
                for (from, to) in diff.shifts.iter().flat_map(|shift| shift.pairs()) {
                    let sent = diff.rows.iter().any(|row| row.row == to);
                    proptest::prop_assert!(sent || client.grid.lines_share(to, &base.grid, from));
                }
                frames.push(target);
            }
        }
    }

    /// The diff from `base_bytes` to `base_bytes` then `more` on a 24×80 screen, applied.
    fn scrolled(base_bytes: &[u8], more: &[u8]) -> (TerminalScreen, TerminalScreen, ScreenDiff) {
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
        emu.process(base_bytes);
        let base = emu.snapshot();
        emu.process(more);
        let target = emu.snapshot();
        let diff = target.diff_from(&base);
        let mut client = base.clone();
        client.apply(&diff);
        assert_eq!(client, target);
        (base, target, diff)
    }

    /// 24 numbered rows.
    fn numbered() -> Vec<u8> {
        let mut bytes = Vec::from(&b"\x1b[H\x1b[2J"[..]);
        for i in 1..=24 {
            bytes.extend_from_slice(format!("\x1b[{i};1Hrow {i}").as_bytes());
        }
        bytes
    }

    fn shift(top: u16, len: u16, by: i16) -> Shift {
        Shift {
            top,
            len: NonZeroU16::new(len).unwrap(),
            by: NonZeroI16::new(by).unwrap(),
        }
    }

    #[test]
    fn a_scroll_moves_rows_instead_of_sending_them() {
        let mut lines = Vec::new();
        for n in 0..30 {
            lines.extend_from_slice(format!("line {n}\r\n").as_bytes());
        }
        let (_, _, diff) = scrolled(&lines, b"new line\r\n");
        assert_eq!(diff.shifts, Shifts(vec![shift(1, 22, -1)]));
        // Only the line that arrived is sent: the new row at the bottom is blank, as it was.
        assert_eq!(diff.rows.len(), 1);
        assert_eq!(diff.rows[0].row, 22);
    }

    #[test]
    fn a_scroll_in_a_region_inserted_and_deleted_lines_move_rows() {
        // Each moves one run of rows and brings in blank rows, which the rows the shift left blank
        // already are: no row is sent.
        let cases: [(&[u8], Shift); 5] = [
            // DECSTBM rows 5..=20, then a line feed at the region's bottom: rows 5..20 move up.
            (b"\x1b[5;20r\x1b[20;1H\n", shift(5, 15, -1)),
            // Reverse index at the region's top: rows 4..19 move down.
            (b"\x1b[5;20r\x1b[5;1H\x1bM", shift(4, 15, 1)),
            // Scroll down two lines in the region.
            (b"\x1b[5;20r\x1b[2T", shift(4, 14, 2)),
            // Insert two lines at row 3: rows 3..22 move down.
            (b"\x1b[3;1H\x1b[2L", shift(2, 20, 2)),
            // Delete a line at row 10: the rows below move up.
            (b"\x1b[10;1H\x1b[M", shift(10, 14, -1)),
        ];
        for (more, expected) in cases {
            let (_, _, diff) = scrolled(&numbered(), more);
            assert_eq!(diff.shifts, Shifts(vec![expected]), "{more:?}");
            assert_eq!(diff.rows, Vec::<RowDiff>::new(), "{more:?}");
        }
    }

    #[test]
    fn a_resize_sends_no_shifts() {
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
        emu.process(&numbered());
        let base = emu.snapshot();
        emu.resize(Size::new(24, 100));
        emu.process(b"\r\n");
        let diff = emu.snapshot().diff_from(&base);
        assert!(diff.resize.is_some() && diff.shifts.is_empty());
    }

    #[test]
    fn malformed_shifts_drop_the_whole_frame() {
        let (base, target, good) = scrolled(&numbered(), b"\x1b[24;1H\nlast");
        assert!(!good.shifts.is_empty());
        let mutations: [fn(&mut ScreenDiff); 4] = [
            // Past the bottom of a 24-row screen, though within `MAX_DIM`.
            |d| d.shifts = Shifts(vec![shift(20, 5, -1)]),
            |d| d.shifts = Shifts(vec![shift(0, 24, 1)]),
            // With a resize.
            |d| d.resize = Some(Size::new(24, 80)),
            // A row the shifts must bring into place is not sent: the frame is still well formed,
            // so this one applies, to something other than the target.
            |d| d.shifts = Shifts::default(),
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut diff = good.clone();
            mutate(&mut diff);
            let mut c = base.clone();
            c.apply(&diff);
            if i == 3 {
                assert_ne!(c, target, "the shifts matter");
            } else {
                assert_eq!(c, base, "mutation {i} must drop the frame");
            }
        }
    }

    #[test]
    fn malformed_shifts_fail_to_decode() {
        let with = |shifts: &[(u16, u16, i16)]| {
            let mut raw = raw_two_by_two();
            raw.resize = None;
            raw.shifts = shifts
                .iter()
                .map(|&(top, len, by)| RawShift { top, len, by })
                .collect();
            decode_raw(&raw)
        };
        assert!(with(&[(0, 1, 1)]).is_ok());
        assert!(with(&[(0, 1, 1), (5, 2, -1)]).is_ok());
        let spread: Vec<(u16, u16, i16)> = (0..=MAX_SHIFTS)
            .map(|i| (u16::try_from(i * 3).unwrap(), 1, 1))
            .collect();
        assert!(
            with(&spread[..MAX_SHIFTS]).is_ok(),
            "the most shifts allowed"
        );
        let bad: [&[(u16, u16, i16)]; 8] = [
            &[(0, 1, 0)],              // a zero offset
            &[(0, 0, 1)],              // an empty shift
            &[(0, 1, -1)],             // above the top
            &[(MAX_DIM - 1, 2, 1)],    // past MAX_DIM
            &[(MAX_DIM - 2, 1, 2)],    // moved past MAX_DIM
            &[(0, 3, 5), (2, 1, 9)],   // two sources share a row
            &[(0, 2, 5), (10, 2, -4)], // two destinations share a row
            &spread,                   // one too many
        ];
        for (i, shifts) in bad.iter().enumerate() {
            assert!(with(shifts).is_err(), "case {i} must fail to decode");
        }
    }

    #[test]
    fn client_apply_clamps_oom_resize() {
        // A malicious server ships a (65000, 65000) resize. The client must NOT build a giant
        // grid: apply clamps to MAX_DIM and reconstructs a bounded screen without OOM/panic.
        let mut c = TerminalScreen::default();
        c.apply(&resize_only(Size::new(65000, 65000))); // must not OOM/panic
        assert_eq!(
            c.size(),
            Size::new(MAX_DIM, MAX_DIM),
            "client clamps a giant resize"
        );
    }

    #[test]
    fn client_apply_clamps_zero_resize() {
        let mut c = TerminalScreen::default();
        c.apply(&resize_only(Size::new(0, 0))); // must not panic
        assert_eq!(
            c.size(),
            Size::new(MIN_DIM, MIN_DIM),
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
        let mutations: [fn(&mut ScreenDiff); 4] = [
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
        history: Option<(u64, u32)>,
        tty: Option<(bool, bool)>,
        cursor: (u16, u16),
        modes: RawModes,
        shifts: Vec<RawShift>,
        rows: Vec<RawRow>,
    }

    #[derive(Clone, Serialize)]
    struct RawShift {
        top: u16,
        len: u16,
        by: i16,
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
        links: Vec<(String, String)>,
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
        underline_color: WireColor,
        style: u16,
        link: u16,
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
            history: None,
            tty: None,
            cursor: (0, 0),
            modes: RawModes {
                hide_cursor: false,
                application_cursor: false,
                application_keypad: false,
                bracketed_paste: false,
                mouse_mode: 4,
                mouse_encoding: 2,
            },
            shifts: Vec::new(),
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
                        underline_color: WireColor::Idx(3),
                        style: 511 - 256,
                        link: 1,
                    },
                }],
                links: vec![("https://example.org/".to_owned(), "a".to_owned())],
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
        assert_eq!(screen.size(), Size::new(2, 2));
        assert_eq!(screen.screen().cell(0, 1).map(|c| c.contents()), Some("x"));
        let mutations: [fn(&mut RawDiff); 14] = [
            |d| d.rows[0].runs[0].count = 0, // empty run
            |d| d.rows[0].runs[0].cell.text = "x".repeat(Cell::CLUSTER_CAPACITY + 1),
            |d| d.rows[0].runs[0].cell.text = "\x1b".to_owned(), // an escape for the terminal
            |d| d.rows[0].runs[0].cell.text = "\u{9b}".to_owned(), // a C1 control
            |d| d.rows[0].runs[0].cell.kind = 3,                 // unknown kind
            |d| d.rows[0].runs[0].cell.style = 4096,             // unknown style bit
            |d| d.rows[0].runs[0].cell.style = 512,              // a style with no underline
            |d| d.rows[0].runs[0].cell.style = 8 | 0x0a00,       // an underline style past dashed
            |d| d.rows[0].runs[0].cell.style = 8 | 0x0e00,       // the last style value
            |d| d.rows[0].runs[0].cell.style = 128 | 256,        // both blinks
            |d| d.rows[0].links[0].0 = "x".repeat(fux_vt::URI_LIMIT + 1),
            |d| d.rows[0].links[0].1 = "x".repeat(fux_vt::ID_LIMIT + 1),
            |d| d.modes.mouse_mode = 5,     // unknown mouse mode
            |d| d.modes.mouse_encoding = 3, // unknown mouse encoding
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
    fn a_row_naming_a_link_it_lacks_or_too_many_links_changes_nothing() {
        let good = decode_raw(&raw_two_by_two()).expect("a well-formed diff decodes");
        let mut screen = TerminalScreen::default();
        screen.apply(&good);
        let link = screen.screen().link(0, 0).cloned();
        assert_eq!(
            link.map(|l| (l.uri, l.id)),
            Some(("https://example.org/".to_owned(), "a".to_owned()))
        );
        let mutations: [fn(&mut RawDiff); 3] = [
            |d| d.rows[0].runs[0].cell.link = 2, // a link the row lacks
            |d| d.rows[0].links = vec![("u".to_owned(), String::new()); MAX_ROW_LINKS + 1],
            // More link bytes than a diff may carry, over two rows.
            |d| {
                let long = ("x".repeat(fux_vt::URI_LIMIT), String::new());
                let row = d.rows[0].clone();
                d.rows = (0..2u16)
                    .map(|r| RawRow {
                        row: r,
                        links: vec![long.clone(); MAX_ROW_LINKS],
                        ..row.clone()
                    })
                    .collect();
                d.resize = Some((1000, 2));
                let many = d.rows.clone();
                d.rows = (0..400u16)
                    .map(|r| RawRow {
                        row: r,
                        ..many[0].clone()
                    })
                    .collect();
            },
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut raw = raw_two_by_two();
            mutate(&mut raw);
            let diff = decode_raw(&raw).expect("decodes");
            let mut screen = TerminalScreen::default();
            screen.apply(&diff);
            assert_eq!(
                screen,
                TerminalScreen::default(),
                "mutation {i} changed the screen"
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
        assert_eq!(after.grid.row(2).map(Cells::len), Some(80));
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
    fn a_snapshot_with_no_row_changed_shares_the_whole_row_list() {
        let mut emu = ServerTerminal::new(24, 80, 0).expect("emulator");
        emu.process(b"one\r\ntwo");
        let before = emu.snapshot();
        // A query, a title, the cursor moved: no row changed.
        emu.process(b"\x1b[6n\x1b]2;title\x07\x1b[5;5H");
        let after = emu.snapshot();
        assert!(after.grid.shares_all_rows(&before.grid));
        assert_eq!(after.grid.cursor_position(), (4, 4));
        // A client applying a frame that carries no row keeps sharing its base's.
        let mut client = before.clone();
        client.apply(&after.diff_from(&before));
        assert!(client.grid.shares_all_rows(&before.grid));
        assert_eq!(client, after);
        // A changed row: its own list, the base's untouched.
        emu.process(b"x");
        let changed = emu.snapshot();
        assert!(!changed.grid.shares_all_rows(&after.grid));
        let mut client = after.clone();
        client.apply(&changed.diff_from(&after));
        assert!(!client.grid.shares_all_rows(&after.grid));
        assert_eq!(client, changed);
        assert_eq!(after.screen().contents(), "one\ntwo");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// The window counts agree with the plain count, over frames that scroll, change rows,
        /// resize, and share a blank grid's one allocation.
        #[test]
        fn window_counts_agree_with_the_plain_count(
            steps in proptest::collection::vec(
                (
                    proptest::collection::vec(0..SCROLL_PIECES.len(), 0..4),
                    proptest::option::of((2u16..10, 2u16..14)),
                ),
                1..10,
            ),
            base in 0usize..10,
        ) {
            let mut emu = ServerTerminal::new(8, 12, 0).expect("emulator");
            let mut frames = vec![TerminalScreen::default(), emu.snapshot()];
            for (pieces, resize) in steps {
                for piece in pieces {
                    emu.process(SCROLL_PIECES[piece].as_bytes());
                }
                if let Some((rows, cols)) = resize {
                    emu.resize(Size::new(rows, cols));
                }
                let target = emu.snapshot();
                // As a client has it: applied to the last frame, sharing its rows.
                let mut applied = frames.last().cloned().unwrap_or_default();
                applied.apply(&target.diff_from(frames.last().unwrap()));
                frames.push(target);
                frames.push(applied);
            }
            let grids: Vec<&Grid> = frames.iter().map(|f| &f.grid).collect();
            let base = grids[base.min(grids.len().saturating_sub(1))];
            proptest::prop_assert_eq!(
                Grid::cells_beyond(base, grids.iter().copied()),
                Grid::cells_counted_plainly([base], grids.iter().copied())
            );
            proptest::prop_assert_eq!(
                Grid::distinct_cells(grids.iter().copied()),
                Grid::cells_counted_plainly([], grids.iter().copied())
            );
        }
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
    fn cell_text_holds_what_a_cell_holds() {
        // Inline, just past inline, and a whole cluster.
        for len in [
            CellText::INLINE,
            CellText::INLINE + 1,
            Cell::CLUSTER_CAPACITY,
        ] {
            let text = "x".repeat(len);
            assert_eq!(
                CellText::new(&text).map(|t| t.as_str().to_owned()),
                Some(text)
            );
        }
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}";
        assert_eq!(
            CellText::new(family).map(|t| t.as_str().to_owned()),
            Some(family.to_owned())
        );
        assert!(CellText::new(&"x".repeat(Cell::CLUSTER_CAPACITY + 1)).is_none());
        for control in ["\x1b[2J", "\x07", "\x7f", "\u{9d}", "a\nb"] {
            assert!(CellText::new(control).is_none(), "{control:?}");
        }
        assert!(CellText::default().is_empty());
        // The encoding is the string's, and a decoded string must fit.
        let text = CellText::new("日本").unwrap();
        let bytes = postcard::to_allocvec(&text).unwrap();
        assert_eq!(bytes, postcard::to_allocvec("日本").unwrap());
        assert_eq!(postcard::from_bytes::<CellText>(&bytes).unwrap(), text);
        // A run's text may be longer than a cluster, one character a cell, but no longer than a
        // row's; a cell's own text is held to a cluster by its run.
        let row = postcard::to_allocvec(&"x".repeat(MAX_RUN_TEXT)).unwrap();
        assert!(postcard::from_bytes::<CellText>(&row).is_ok());
        let long = postcard::to_allocvec(&"x".repeat(MAX_RUN_TEXT + 1)).unwrap();
        assert!(postcard::from_bytes::<CellText>(&long).is_err());
    }

    fn wire_run(count: u16, kind: CellKind, text: &str) -> Vec<u8> {
        #[derive(Serialize)]
        struct Raw<'a> {
            count: u16,
            text: &'a str,
            kind: CellKind,
            colors: [u8; 3],
            style: u16,
            link: u16,
        }
        postcard::to_allocvec(&Raw {
            count,
            text,
            kind,
            colors: [0; 3],
            style: 0,
            link: 0,
        })
        .unwrap()
    }

    #[test]
    fn a_run_s_text_must_fit_its_kind() {
        let run = |count, kind, text| postcard::from_bytes::<Run>(&wire_run(count, kind, text));
        assert!(run(3, CellKind::Chars, "abc").is_ok());
        assert!(
            run(2, CellKind::Chars, "abc").is_err(),
            "more characters than cells"
        );
        assert!(
            run(4, CellKind::Chars, "abc").is_err(),
            "fewer characters than cells"
        );
        assert!(run(2, CellKind::WideChars, "日本").is_ok());
        assert!(run(3, CellKind::WideChars, "日本").is_err());
        let cluster = "x".repeat(Cell::CLUSTER_CAPACITY + 1);
        assert!(
            run(1, CellKind::Narrow, &cluster).is_err(),
            "a cell's text is a cluster"
        );
        assert!(
            run(129, CellKind::Chars, &"x".repeat(129)).is_ok(),
            "a run's may be longer"
        );
    }

    #[test]
    fn runs_of_characters_decode_to_the_cells_they_name() {
        let target = screen_from(
            4,
            12,
            "ab\x1b[31mcd日本\x1b[m\u{1f468}\u{200d}\u{1f469}x".as_bytes(),
        );
        let diff = target.diff_from(&TerminalScreen::default());
        let kinds: Vec<(CellKind, u16)> = diff.rows[0]
            .runs
            .iter()
            .map(|r| (r.cell.kind, r.count.get()))
            .collect();
        assert_eq!(
            kinds,
            [
                (CellKind::Chars, 2),
                (CellKind::Chars, 2),
                (CellKind::WideChars, 2),
                (CellKind::Wide, 1),
                (CellKind::Continuation, 1),
                (CellKind::Narrow, 1),
                (CellKind::Narrow, 1),
            ],
            "a cluster of several characters goes as a cell of its own"
        );
        let mut client = TerminalScreen::default();
        client.apply(&diff);
        assert_eq!(client, target);
        // A run of characters that overruns the row drops the frame.
        let mut long = diff.clone();
        long.rows[0].runs[0].count = NonZeroU16::new(13).unwrap();
        long.rows[0].runs[0].cell.text = CellText::run(&"a".repeat(13)).unwrap();
        let mut client = TerminalScreen::default();
        client.apply(&long);
        assert_eq!(client, TerminalScreen::default());
    }

    #[test]
    fn identical_cells_are_run_length_encoded() {
        let target = screen_from(24, 80, b"ab");
        let diff = target.diff_from(&TerminalScreen::default());
        assert_eq!(diff.rows.len(), 1, "only the changed row is sent");
        assert_eq!(
            diff.rows[0].runs.len(),
            2,
            "'ab' as a run of characters, then one run of 78 blanks"
        );
        assert_eq!(diff.rows[0].runs[0].cell.kind, CellKind::Chars);
        assert_eq!(diff.rows[0].runs[1].count.get(), 78);
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
        let cols = s.size().cols;
        (0..cols)
            .map(|c| match s.cell(row, c).map(|c| c.contents()) {
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
    fn back_and_forward_tab_roundtrip() {
        // mosh emulation-back-tab: CBT (CSI Z) and CHT (CSI I) move between tab stops, and the
        // result round-trips identically server↔client. fux-vt implements both since 0.3.
        let c = roundtrip(24, 80, b"hello, wurld\x1b[Zo");
        assert_eq!(row_text(c.screen(), 0), "hello, world");
        let c2 = roundtrip(24, 80, b"ab\x1b[Itab");
        assert_eq!(row_text(c2.screen(), 0), "ab      tab");
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
    fn grapheme_clusters_and_every_attribute_roundtrip() {
        // Clusters fux-vt keeps whole, some too long to hold inline, and every attribute.
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}";
        let flag = "\u{1f1fa}\u{1f1f8}";
        let heart = "\u{2764}\u{fe0f}";
        let marked = format!("e{}", "\u{301}".repeat(40));
        let bytes = format!(
            "{family}{flag}{heart}{marked}\r\n\
             \x1b[5mA\x1b[6mB\x1b[8mC\x1b[9mD\x1b[m\x1b[4;58;5;9mE\x1b[58;2;1;2;3mF\x1b[m"
        );
        let c = roundtrip(24, 80, bytes.as_bytes());
        let s = c.screen();
        let cluster = |col| s.cell(0, col).map(|c| c.contents().to_owned());
        assert_eq!(cluster(0).as_deref(), Some(family));
        assert_eq!(cluster(2).as_deref(), Some(flag));
        assert_eq!(
            cluster(4).as_deref(),
            Some(heart),
            "a variation selector makes it wide"
        );
        assert!(s.cell(4, 0).is_none_or(|c| !c.is_wide()));
        assert!(s.cell(0, 4).is_some_and(|c| c.is_wide()));
        assert_eq!(cluster(6).map(|t| t.len()), Some(marked.len()));
        let cell = |col| s.cell(1, col).expect("a cell");
        assert_eq!(cell(0).blink(), Blink::Slow);
        assert_eq!(cell(1).blink(), Blink::Rapid);
        assert!(cell(2).hidden());
        assert!(cell(3).strikeout());
        assert!(cell(4).underline() && cell(4).underline_color() == Color::Idx(9));
        assert_eq!(cell(5).underline_color(), Color::Rgb(1, 2, 3));
    }

    #[test]
    fn a_row_past_its_text_budget_arrives_as_the_server_has_it() {
        // Clusters of 100 bytes in every cell of a 20-column row: more text than a row keeps, so
        // fux-vt cuts the last ones to what fits inline, and the client's row must match.
        let long = format!("e{}", "\u{301}".repeat(49));
        let row = long.repeat(20);
        let c = roundtrip(4, 20, row.as_bytes());
        let lens: Vec<usize> = (0..20)
            .filter_map(|col| c.screen().cell(0, col).map(|c| c.contents().len()))
            .collect();
        assert!(lens.contains(&long.len()), "{lens:?}");
        assert!(lens.iter().any(|&len| len < long.len()), "{lens:?}");
    }

    #[test]
    fn latin1_supplement_roundtrip() {
        // mosh emulation-ascii-iso-8859: ISO-8859-1 supplement characters render and round-trip.
        let c = roundtrip(24, 80, "àáâãäåæçèéêëìíîïñòóôõöøùúûüýþÿ".as_bytes());
        assert!(c.screen().contents().contains("àáâãä"));
    }
}
