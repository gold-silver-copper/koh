# vt100 0.16.2 — Ground-Truth API Reference

Source: `~/.cargo/registry/.../vt100-0.16.2/src/{lib,parser,screen,cell,grid,row,attrs,term,callbacks,perform}.rs`.
Crate version `0.16.2`. Internally drives `vte 0.15.0` (the `vte::Parser`/`vte::Perform` parser). Deps: `unicode-width 0.2.1`, `itoa 1.0.15`.

All signatures below are copy-pasteable-accurate against the read source. Where a method is `pub(crate)` or private it is marked as NOT public — do not plan to call it.

## 0. Public surface (lib.rs re-exports)

```rust
pub use attrs::Color;                                    // enum Color
pub use callbacks::Callbacks;                            // trait
pub use cell::Cell;                                      // struct
pub use parser::Parser;                                  // struct Parser<CB = ()>
pub use screen::{MouseProtocolEncoding, MouseProtocolMode, Screen};
```

That is the ENTIRE public type surface. Notably **NOT public**: `Grid`, `Row`, `Attrs`, `Pos`, `Size`, the whole `term` module (escape-code writers), `perform::WrappedScreen`. You only ever touch `Parser`, `Screen`, `Cell`, `Color`, `Callbacks`, `MouseProtocolMode`, `MouseProtocolEncoding`.

---

## 1. Parser

```rust
pub struct Parser<CB: crate::callbacks::Callbacks = ()> {
    parser: vte::Parser,
    screen: crate::perform::WrappedScreen<CB>,
}
```

Generic over a `Callbacks` impl; defaults to `()` (the unit type implements `Callbacks` as a no-op: `impl Callbacks for () {}`). The common case is just `vt100::Parser` (= `Parser<()>`).

### Constructors / methods

```rust
// Only on Parser<()>:
impl Parser {
    #[must_use]
    pub fn new(rows: u16, cols: u16, scrollback_len: usize) -> Self;
}

impl Default for Parser {
    fn default() -> Self;                  // == Parser::new(24, 80, 0)
}

// On any Parser<CB>:
impl<CB: crate::callbacks::Callbacks> Parser<CB> {
    pub fn new_with_callbacks(
        rows: u16, cols: u16, scrollback_len: usize, callbacks: CB,
    ) -> Self;

    pub fn process(&mut self, bytes: &[u8]);              // feed terminal output bytes

    #[must_use]
    pub fn screen(&self) -> &crate::Screen;

    #[must_use]
    pub fn screen_mut(&mut self) -> &mut crate::Screen;   // YES this exists

    pub fn callbacks(&self) -> &CB;
    pub fn callbacks_mut(&mut self) -> &mut CB;
}

impl std::io::Write for Parser {                          // only Parser<()>
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;  // calls process(); always Ok(buf.len())
    fn flush(&mut self) -> std::io::Result<()>;                 // Ok(())
}
```

- `Parser::new(rows, cols, scrollback_len)` — note the third arg is named `scrollback_len`, type `usize`. `0` = no scrollback.
- `process` returns `()` — no error, no "did it change" signal. To detect changes, snapshot via `screen().clone()` and diff (section 2).
- `screen()` returns `&Screen` borrowed from the parser. `Screen: Clone`, so `parser.screen().clone()` gives you an owned snapshot (used in the synopsis and required for diffing against future state).

### IMPORTANT: there is NO `Parser::set_size`

Resizing is done on the **Screen**, not the Parser:

```rust
parser.screen_mut().set_size(rows, cols);
```

`Screen::set_size(&mut self, rows: u16, cols: u16)` resizes both the normal and the alternate grid (section 2 / section 5).

---

## 2. Screen

```rust
#[derive(Clone, Debug)]
pub struct Screen { /* private: grid, alternate_grid, attrs, saved_attrs, modes: u8,
                       mouse_protocol_mode, mouse_protocol_encoding */ }
```

`Screen: Clone + Debug`. NOT `PartialEq` (you can't `==` two screens; diff instead). `Screen::new` is `pub(crate)` — construct via `Parser`.

### Size / resize / scrollback

```rust
pub fn set_size(&mut self, rows: u16, cols: u16);   // resize; affects both normal + alt grid
#[must_use] pub fn size(&self) -> (u16, u16);       // returns (rows, cols)  <-- order!

pub fn set_scrollback(&mut self, rows: usize);      // offset from top; 0 = live screen
#[must_use] pub fn scrollback(&self) -> usize;      // current scrollback offset (clamped to actual len)
```

`size()` returns **(rows, cols)** — rows first. Same order for `Parser::new(rows, cols, ...)` and `set_size(rows, cols)`.

### Plain-text contents

```rust
#[must_use] pub fn contents(&self) -> String;       // whole screen, no formatting, trailing newlines trimmed

pub fn rows(&self, start: u16, width: u16) -> impl Iterator<Item = String> + '_;
//   one String per VISIBLE row, columns [start, start+width); no newlines, no formatting

#[must_use]
pub fn contents_between(
    &self, start_row: u16, start_col: u16, end_row: u16, end_col: u16,
) -> String;   // logical text between two cells (selection-style)
```

### Formatted contents = FULL REPAINT escape sequence  ★

```rust
#[must_use] pub fn contents_formatted(&self) -> Vec<u8>;
```

Returns escape codes sufficient to reproduce the entire **visible** screen from scratch. Internally (`write_contents_formatted`):
1. `\x1b[?25h`/`\x1b[?25l` (hide-cursor state),
2. `\x1b[m` (clear attrs) + `\x1b[H\x1b[J` (home + clear screen) — see `ClearScreen` in term.rs,
3. all cell contents with inline SGR,
4. final cursor positioning,
5. leaves active drawing attrs in the correct state.

This is the "key frame" / full-state encoding. Example from lib.rs doctest:
`b"\x1b[?25h\x1b[m\x1b[H\x1b[Jthis text is \x1b[32mGREEN"`.

### Diff = MINIMAL escape sequence transforming prev → self  ★★★  (this is the SSP-style sync primitive)

```rust
#[must_use] pub fn contents_diff(&self, prev: &Self) -> Vec<u8>;
```

EXACT documented semantics (verbatim from screen.rs):
> Returns a terminal byte stream sufficient to turn the visible contents of the screen described by `prev` into the visible contents of the screen described by `self`. The result of rendering `prev.contents_formatted()` followed by `self.contents_diff(prev)` should be equivalent to rendering `self.contents_formatted()`.

So the contract is: **render(prev.contents_formatted()) ⨁ render(self.contents_diff(prev)) ≡ render(self.contents_formatted())**. The diff is keyed off the *previous Screen's state* (cursor pos, attrs, per-cell contents), walks visible rows pairwise, and emits only changed cells plus minimal cursor moves. It diffs: hide-cursor state, per-cell contents+attrs, wrapping changes, and final cursor position. It does NOT diff input modes / mouse modes (use `state_diff` / `input_mode_diff` for those — section 2.x).

Example from lib.rs doctest: after typing then moving+coloring, `self.contents_diff(&prev)` == `b"\x1b[1;14H\x1b[32mGREEN"`.

**This IS the intended sync mechanism.** For a mosh/SSP-style transport:
- Keep an owned `prev: Screen` = last state the *receiver* is known to have.
- After `process`, compute `new = parser.screen()`. Send `new.contents_diff(&prev)` (the framebuffer delta). On ack, set `prev = new.clone()`.
- For a fresh/desynced receiver, send `contents_formatted()` (full repaint) instead.
- "Did the screen change?" = `contents_diff(&prev).is_empty()` is the cheapest correct test (empty Vec ⇒ no visible change). There is no dirty flag / generation counter; you must diff or clone-and-compare cells.

### state_* and input_mode_* (diff/formatted that also carry input modes)

```rust
#[must_use] pub fn state_formatted(&self) -> Vec<u8>;            // contents_formatted + input_mode_formatted
#[must_use] pub fn state_diff(&self, prev: &Self) -> Vec<u8>;    // contents_diff + input_mode_diff

#[must_use] pub fn input_mode_formatted(&self) -> Vec<u8>;
#[must_use] pub fn input_mode_diff(&self, prev: &Self) -> Vec<u8>;
//   covers: application keypad, application cursor, bracketed paste,
//   mouse protocol mode, mouse protocol encoding

#[must_use] pub fn attributes_formatted(&self) -> Vec<u8>;       // just current SGR drawing attrs
#[must_use] pub fn cursor_state_formatted(&self) -> Vec<u8>;     // hide-cursor + cursor position
```

For a complete remote-terminal mirror, **`state_formatted()` / `state_diff(prev)` are the fullest sync primitives** (contents + cursor + input/mouse modes). Prefer these over `contents_*` if you want input modes (bracketed paste, app cursor, mouse) mirrored too.

### Per-row formatted/diff (if you tile rows yourself)

```rust
pub fn rows_formatted(&self, start: u16, width: u16) -> impl Iterator<Item = Vec<u8>> + '_;
pub fn rows_diff<'a>(&'a self, prev: &'a Self, start: u16, width: u16)
    -> impl Iterator<Item = Vec<u8>> + 'a;
```
You must position the cursor before each emitted row yourself; final cursor pos per row is unspecified.

### Cursor

```rust
#[must_use] pub fn cursor_position(&self) -> (u16, u16);   // (row, col)  <-- row first
#[must_use] pub fn hide_cursor(&self) -> bool;             // true = cursor hidden (DECTCEM reset)
```
There is NO `cursor_visible()`. Use `!screen.hide_cursor()`. Cursor position is 0-indexed `(row, col)`.

### Cell access

```rust
#[must_use] pub fn cell(&self, row: u16, col: u16) -> Option<&crate::Cell>;
//   returns None if out of bounds; honors current scrollback offset

#[must_use] pub fn row_wrapped(&self, row: u16) -> bool;   // does this row soft-wrap into the next?
```

### Mode / attribute getters (all `#[must_use]`, take `&self`)

```rust
pub fn alternate_screen(&self) -> bool;     // are we in the alt screen buffer?
pub fn application_keypad(&self) -> bool;
pub fn application_cursor(&self) -> bool;
pub fn hide_cursor(&self) -> bool;
pub fn bracketed_paste(&self) -> bool;
pub fn mouse_protocol_mode(&self) -> MouseProtocolMode;
pub fn mouse_protocol_encoding(&self) -> MouseProtocolEncoding;

// current ACTIVE drawing attributes (what newly-drawn text would use):
pub fn fgcolor(&self) -> crate::Color;
pub fn bgcolor(&self) -> crate::Color;
pub fn bold(&self) -> bool;
pub fn dim(&self) -> bool;
pub fn italic(&self) -> bool;
pub fn underline(&self) -> bool;
pub fn inverse(&self) -> bool;
```

### ★ MISSING getters (surprising — handle via Callbacks, see section 6)

There is **no** `Screen::title()`, `icon_name()`, `audible_bell_count()`, `visual_bell()`, or any bell counter. The crate does NOT store window title / icon name / bell events on the Screen at all — they are delivered only as `Callbacks` method calls during `process`. If you need title/icon/bell, you MUST construct the parser via `Parser::new_with_callbacks` with a custom `Callbacks` impl that records them (section 6).

---

## 3. Cell

```rust
#[derive(Clone, Debug, Eq)]   // also impls PartialEq (custom)
pub struct Cell { /* contents: [u8;22], len: u8, attrs: Attrs */ }   // 32 bytes, asserted
```

`Cell: Clone + Debug + Eq + PartialEq`. `PartialEq` compares `len`, `attrs`, then the content bytes — so two cells are equal iff same glyph(s) AND same attributes. (This is exactly what the diff logic keys on.) Construction is `pub(crate)`; you only ever get `&Cell` from `Screen::cell`.

```rust
#[must_use] pub fn contents(&self) -> &str;   // NOTE: &str, NOT String. May hold a base char + combining marks.
#[must_use] pub fn has_contents(&self) -> bool;            // len > 0 (false for blank/erased cells)
#[must_use] pub fn is_wide(&self) -> bool;                 // this cell holds a 2-col-wide char
#[must_use] pub fn is_wide_continuation(&self) -> bool;    // this is the 2nd half of a wide char (prev cell is_wide)

#[must_use] pub fn fgcolor(&self) -> crate::Color;
#[must_use] pub fn bgcolor(&self) -> crate::Color;
#[must_use] pub fn bold(&self) -> bool;
#[must_use] pub fn dim(&self) -> bool;        // YES, dim exists (in addition to bold)
#[must_use] pub fn italic(&self) -> bool;
#[must_use] pub fn underline(&self) -> bool;
#[must_use] pub fn inverse(&self) -> bool;
```

★ `contents()` returns `&str` (the task said `String` — it is actually `&str` in 0.16.2). Empty `""` for a cell with no glyph. A wide char occupies two cells: the first returns the glyph with `is_wide()==true`; the second has empty contents and `is_wide_continuation()==true`. There is NO `attrs()` public getter on Cell (it's `pub(crate)`); read individual attributes via the methods above.

---

## 4. Color (attrs.rs)

```rust
#[derive(Eq, PartialEq, Debug, Copy, Clone, Default)]
pub enum Color {
    #[default]
    Default,            // terminal default fg/bg
    Idx(u8),            // 256-color palette index (0..=255)
    Rgb(u8, u8, u8),    // truecolor (r, g, b)
}
```

`Color: Copy + Clone + Eq + PartialEq + Debug + Default` (`Default` variant). That's all three variants — exactly `Default`, `Idx(u8)`, `Rgb(u8,u8,u8)`.

How vt100 maps SGR → `Color::Idx` (from screen.rs `sgr`): `30..=37`→`Idx(n-30)`, `90..=97`→`Idx(n-82)` (i.e. bright 8..15), `40..=47`→`Idx(n-40)`, `100..=107`→`Idx(n-92)`, `38;5;i`/`48;5;i`→`Idx(i)`, `38;2;r;g;b`/`48;2;...`→`Rgb`. `39`/`49`→`Default`. When you re-encode `Color` back to SGR (term.rs `Attrs::write_buf`): `Idx(i)` with `i<8`→`30+i`/`40+i`, `i<16`→`82+i`/`92+i`, else `38;5;i`/`48;5;i`. So `Idx(0..=15)` round-trips through the 16 ANSI/bright codes, `Idx(16..=255)` through `38;5;`. Useful if you serialize cells yourself.

Note attribute model: `bold` and `dim` are mutually-exclusive "intensity" bits internally (SGR 1 vs 2; 22 resets both). `italic`/`underline`/`inverse` are independent flags (SGR 3/4/7, off via 23/24/27).

---

## 5. Resize semantics (grid.rs `set_size`, called by `Screen::set_size`)

`Screen::set_size(rows, cols)` calls `grid.set_size` on BOTH the normal grid and the alternate grid. Per-grid behavior (`Grid::set_size`):
- If `cols` changed: every existing row's `wrapped` flag is cleared (`row.wrap(false)`).
- Each row is resized to new `cols` (truncate or pad with blank `Cell::new()`).
- Row count resized to new `rows` (truncate or append blank rows).
- Scroll region (`scroll_bottom`) and saved cursor pos are clamped to the new size; cursor is clamped (`row_clamp_top/bottom`, `col_clamp`).

Surprising: vt100 does **NOT reflow** text on width change — it just clears wrap flags and truncates/pads. Content is not re-wrapped to the new width. Plan your reimplementation accordingly (mosh also doesn't reflow). Resize the parser via `parser.screen_mut().set_size(rows, cols)`.

`ESC c` (RIS, full reset) recreates the screen at the same size/scrollback (`*self = Screen::new(...)`). `\e[?1049h` enters alt screen after saving cursor; `\e[?47h`/`\e[?1049h` toggle alt grid; alt grid always has `scrollback_len = 0`.

---

## 6. Callbacks (callbacks.rs) — required for title / icon / bell / unhandled seqs

```rust
pub trait Callbacks {
    fn audible_bell(&mut self, _: &mut crate::Screen) {}
    fn visual_bell(&mut self, _: &mut crate::Screen) {}
    fn resize(&mut self, _: &mut crate::Screen, _request: (u16, u16)) {}   // (rows, cols) from \e[8;r;ct
    fn set_window_icon_name(&mut self, _: &mut crate::Screen, _icon_name: &[u8]) {}  // OSC 1
    fn set_window_title(&mut self, _: &mut crate::Screen, _title: &[u8]) {}          // OSC 2
    fn copy_to_clipboard(&mut self, _: &mut crate::Screen, _ty: &[u8], _data: &[u8]) {}  // OSC 52, data is base64
    fn paste_from_clipboard(&mut self, _: &mut crate::Screen, _ty: &[u8]) {}
    fn unhandled_char(&mut self, _: &mut crate::Screen, _c: char) {}
    fn unhandled_control(&mut self, _: &mut crate::Screen, _b: u8) {}
    fn unhandled_escape(&mut self, _: &mut crate::Screen, _i1: Option<u8>, _i2: Option<u8>, _b: u8) {}
    fn unhandled_csi(&mut self, _: &mut crate::Screen, _i1: Option<u8>, _i2: Option<u8>,
                     _params: &[&[u16]], _c: char) {}
    fn unhandled_osc(&mut self, _: &mut crate::Screen, _params: &[&[u8]]) {}
}
impl Callbacks for () {}   // default no-op
```

All methods have default no-op bodies, so implement only what you need. `audible_bell` fires on `^G` (0x07); `visual_bell` fires on `ESC g`. Title/icon arrive as raw `&[u8]` (decode UTF-8 yourself). Access your callbacks state after processing via `parser.callbacks()` / `parser.callbacks_mut()`.

### Minimal title/bell-capturing setup

```rust
#[derive(Default)]
struct Cbs { title: String, icon: String, bell_count: u64 }
impl vt100::Callbacks for Cbs {
    fn set_window_title(&mut self, _: &mut vt100::Screen, t: &[u8]) {
        self.title = String::from_utf8_lossy(t).into_owned();
    }
    fn set_window_icon_name(&mut self, _: &mut vt100::Screen, n: &[u8]) {
        self.icon = String::from_utf8_lossy(n).into_owned();
    }
    fn audible_bell(&mut self, _: &mut vt100::Screen) { self.bell_count += 1; }
}
let mut parser = vt100::Parser::new_with_callbacks(24, 80, 0, Cbs::default());
parser.process(b"\x1b]2;hello\x07\x07");
assert_eq!(parser.callbacks().title, "hello");
assert_eq!(parser.callbacks().bell_count, 1);
```

---

## 7. Minimal happy-path snippet (the SSP/diff sync loop)

```rust
fn main() {
    // server-side: parse the child PTY's output into a screen model.
    let (rows, cols, scrollback) = (24u16, 80u16, 0usize);
    let mut parser = vt100::Parser::new(rows, cols, scrollback);

    // `prev` = the screen state the remote receiver is currently known to have.
    // Start it as a blank screen of the same size.
    let mut prev: vt100::Screen = vt100::Parser::new(rows, cols, scrollback).screen().clone();

    // feed bytes from the child process:
    parser.process(b"hello \x1b[31mworld\x1b[m\r\n");

    // produce a minimal framebuffer delta to ship over the wire (iroh/QUIC):
    let delta: Vec<u8> = parser.screen().contents_diff(&prev);
    if !delta.is_empty() {
        // send `delta` to the peer; the peer feeds it into ITS terminal.
        // (full repaint alternative for a fresh/desynced peer:)
        let _full_repaint: Vec<u8> = parser.screen().contents_formatted();

        // once acked, advance the baseline:
        prev = parser.screen().clone();
    }

    // resize:
    parser.screen_mut().set_size(40, 120);

    // inspect a cell:
    if let Some(cell) = parser.screen().cell(0, 0) {
        let _glyph: &str = cell.contents();          // "h"
        let _fg: vt100::Color = cell.fgcolor();
        let _is_blank = !cell.has_contents();
    }

    // cursor + flags:
    let (crow, ccol) = parser.screen().cursor_position();   // (row, col)
    let _visible = !parser.screen().hide_cursor();
    let _alt = parser.screen().alternate_screen();
    let _ = (crow, ccol);
}
```

---

## 8. Reimplementation gotchas / version notes (0.16.2)

- **Ordering**: every `(u16, u16)` pair on `Screen` is **(rows, cols)** / **(row, col)** — rows/row first. `Parser::new(rows, cols, scrollback_len)` likewise.
- **`set_size` is on `Screen`, not `Parser`.** Reach it via `parser.screen_mut().set_size(rows, cols)`.
- **`Cell::contents() -> &str`** (not `String`); empty for blank cells. Wide chars span two cells (`is_wide` + `is_wide_continuation`).
- **`contents_diff` semantics** are the load-bearing sync primitive: `prev.contents_formatted()` then `self.contents_diff(prev)` ≡ `self.contents_formatted()` (visible region only). Empty `Vec<u8>` ⇒ no visible change since `prev`. Use `state_diff`/`state_formatted` to also carry cursor + input/mouse modes.
- **No change/dirty flag.** Detect change by diffing against a cloned baseline (`Screen: Clone`).
- **No title/icon/bell on `Screen`.** Only via `Callbacks` during `process` → must use `Parser::new_with_callbacks`.
- **No `cursor_visible`**, use `!hide_cursor()`.
- **No reflow on resize** — width changes truncate/pad and drop wrap flags; rows are not re-wrapped.
- **`Color::Idx(0..=15)`** maps to the 16 ANSI/bright SGR codes on re-encode (not `38;5;`); `16..=255` use `38;5;`/`48;5;`.
- Intensity is a single 2-bit field: `bold` and `dim` are mutually exclusive (SGR 1/2, both reset by 22).
- Control-char handling (perform.rs): `^G`→audible_bell, BS/TAB/LF/VT/FF/CR handled, SI/SO (14/15) ignored as no-ops, `U+FFFD` and C1 chars `U+80..U+9F` are routed to `unhandled_char` rather than drawn.
- `process` does NOT need to be fed complete escape sequences; `vte` is a streaming state machine, so partial sequences across `process` calls are fine — feed raw bytes as they arrive over the wire.
- vt100 0.16.2 internally requires `vte = 0.15.0`; if you mirror its parser, that's the version it tracks.
