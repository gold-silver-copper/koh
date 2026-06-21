# Porting from crossterm to termina 0.3.3 (output/lifecycle only)

Source read: `termina-0.3.3/src/{lib.rs,terminal.rs,style.rs,escape.rs,event.rs,parse.rs}`,
`src/terminal/unix.rs`, `src/escape/csi.rs`, plus the `examples/colors.rs` reference.

## TL;DR mental model

Termina has **no queue/execute command API** like crossterm. The entire model is:

1. `PlatformTerminal::new()?` gives you a value that implements both `termina::Terminal` (raw/cooked
   mode, dimensions, events, panic hook) and `std::io::Write` (buffered stdout / `/dev/tty`).
2. You emit control sequences by `write!`/`writeln!`-ing typed `Display` values
   (`Csi::...`, `Osc::...`) into that terminal, then call `.flush()`.
3. Raw mode and cooked mode are methods on the terminal. **Alternate screen, cursor
   show/hide, synchronized output, bracketed paste, mouse — all of these are NOT terminal
   methods.** They are DEC private modes you write yourself as `Csi::Mode(...)`. Termina models
   the typed enums for all of them.

So everything you need for "output/lifecycle only" exists. There is no async runtime pulled in;
termina is synchronous. It is fine to call from a tokio task as long as you write synchronously.

---

## 0. Crate facts (platform / features / deps)

From `Cargo.toml`:

- `edition = "2021"`, `rust-version = "1.71"`.
- **Both Unix and Windows are supported.** `PlatformTerminal` is a type alias:
  `#[cfg(unix)] pub type PlatformTerminal = UnixTerminal;` / `#[cfg(windows)] = WindowsTerminal`
  (in `terminal.rs:60-63`). Likewise `PlatformHandle = FileDescriptor` (unix) / `OutputHandle` (windows).
- `default = []` features. **No feature flag is required** for the output/lifecycle use described here.
  - `event-stream` (optional, pulls `futures-core`) — only needed for `termina::EventStream`. You are
    using raw stdin for input, so **do NOT enable it.**
  - `windows-legacy` — only for the win32 legacy keyboard example; not needed.
- Runtime deps: `bitflags 2`, `parking_lot 0.12`; unix adds `rustix 1` and `signal-hook 0.3`;
  windows adds `windows-sys`. **No async runtime, no tokio, no futures in the default build.** All
  terminal I/O is synchronous blocking I/O. Safe to drive from a tokio task that writes synchronously
  (but the writes are blocking — keep frames small or use `spawn_blocking` if a write could stall).

`Cargo.toml` dep line:
```toml
termina = "0.3.3"
```

---

## 1. Terminal handle / writer

`terminal.rs` exports: `pub use terminal::{PlatformHandle, PlatformTerminal, Terminal};`
and `lib.rs` re-exports `PlatformTerminal`, `Terminal`, `PlatformHandle` at crate root.

The concrete unix type is `UnixTerminal` (`terminal/unix.rs:124`). It owns a
`BufWriter<FileDescriptor>` over stdout (or `/dev/tty` if stdout is not a tty), captures the original
termios on construction, and **restores cooked mode + flushes on `Drop`** (`unix.rs:236-243`).

Construction (the ONLY constructor):
```rust
pub fn new() -> io::Result<Self>   // UnixTerminal::new / via PlatformTerminal::new
```
`PlatformTerminal::new()` is just `UnixTerminal::new()`.

The `Terminal` trait (`terminal.rs:95-140`), full signatures:
```rust
pub trait Terminal: io::Write {
    fn enter_raw_mode(&mut self) -> io::Result<()>;
    fn enter_cooked_mode(&mut self) -> io::Result<()>;
    fn get_dimensions(&self) -> io::Result<WindowSize>;
    fn event_reader(&self) -> EventReader;
    fn poll<F: Fn(&Event) -> bool>(&self, filter: F, timeout: Option<Duration>) -> io::Result<bool>;
    fn read<F: Fn(&Event) -> bool>(&self, filter: F) -> io::Result<Event>;
    fn set_panic_hook(&mut self, f: impl Fn(&mut PlatformHandle) + Send + Sync + 'static);
}
```
Because `Terminal: io::Write`, the terminal value IS your writer. There is no separate
`Stdout`-like type to acquire. Bring the trait into scope: `use termina::Terminal;` (or
`use termina::Terminal as _;`).

`io::Write` impl (`unix.rs:245-253`): `write` and `flush` delegate to the internal `BufWriter`, so
output is buffered — **you must call `terminal.flush()?` to actually emit a frame.**

Drop behavior: on drop it flushes and calls `enter_cooked_mode()` for you (restores original termios).
It does NOT leave the alternate screen or re-show the cursor for you — those are app-level writes you
must emit yourself before drop (see §3, §5).

crossterm mapping:
- `std::io::stdout()` / `io::Stdout` → `PlatformTerminal::new()?` (it is the writer).

---

## 2. Raw mode (crossterm `enable_raw_mode` / `disable_raw_mode`)

Methods on the terminal, not free functions:
```rust
terminal.enter_raw_mode()?;     // crossterm enable_raw_mode()
terminal.enter_cooked_mode()?;  // crossterm disable_raw_mode()
```
Unix impl (`unix.rs:155-174`): `enter_raw_mode` does `tcgetattr`, `termios.make_raw()`,
`tcsetattr(..., Flush, ...)`. `enter_cooked_mode` restores the `original_termios` captured in `new()`.
Drop also restores cooked mode, so even if you forget to call it the tty is left sane (unless you
panic AND set a panic hook — see `unix.rs:236-242`).

Note: raw mode here affects the **write** fd's termios (stdout/`/dev/tty`). Since your input is raw
stdin handled separately, be aware termina sets raw on the tty device; if your stdin and this tty are
the same device (normal case) raw mode applies to your input too, which is what you want for a raw
client.

---

## 3. Alternate screen (crossterm `EnterAlternateScreen` / `LeaveAlternateScreen`)

**No termina method.** It is a DEC private mode you write. Termina models it as
`DecPrivateModeCode::ClearAndEnableAlternateScreen = 1049` (`csi.rs:1487`). Enter = set, leave = reset:

```rust
use termina::escape::csi::{Csi, Mode, DecPrivateMode, DecPrivateModeCode};

// Enter alt screen (== crossterm EnterAlternateScreen), emits "\x1b[?1049h"
write!(terminal, "{}", Csi::Mode(Mode::SetDecPrivateMode(
    DecPrivateMode::Code(DecPrivateModeCode::ClearAndEnableAlternateScreen))))?;

// Leave alt screen (== crossterm LeaveAlternateScreen), emits "\x1b[?1049l"
write!(terminal, "{}", Csi::Mode(Mode::ResetDecPrivateMode(
    DecPrivateMode::Code(DecPrivateModeCode::ClearAndEnableAlternateScreen))))?;
```
Verified in `examples/colors.rs` (uses exactly this set/reset pair). Display rules:
`SetDecPrivateMode(m)` → `CSI ?{m}h`, `ResetDecPrivateMode(m)` → `CSI ?{m}l` (`csi.rs:1249-1250`).

Older modes also available if needed: `EnableAlternateScreen = 47` (`csi.rs:1492`),
`OptEnableAlternateScreen = 1047` (`csi.rs:1497`). Use 1049 to match crossterm.

---

## 4. Terminal size (crossterm `terminal::size()`)

```rust
let size: termina::WindowSize = terminal.get_dimensions()?;
let cols = size.cols;   // u16, width in cells
let rows = size.rows;   // u16, height in cells
```
`WindowSize` (`lib.rs:154-169`):
```rust
pub struct WindowSize {
    pub cols: u16,          // width in cells   (doc alias "width")
    pub rows: u16,          // height in cells  (doc alias "height")
    pub pixel_width: Option<u16>,
    pub pixel_height: Option<u16>,
}
```
crossterm `size()` returns `(cols, rows)`; here it is `(size.cols, size.rows)`. Unix impl uses
`TIOCGWINSZ` and falls back to `$LINES`/`$COLUMNS`, erroring if both are zero (`unix.rs:176-204`).

Note: your resize handling is a separate signal in the client today — that is fine. termina also
surfaces resize as `Event::WindowResized(WindowSize)` via its event reader (`event.rs:67`), but you
don't need it; keep your SIGWINCH path and just call `get_dimensions()` when you need fresh size.

---

## 5. Writing output / escape & command types

There is **one** way to emit: format a typed value into the terminal with `write!`/`writeln!`, then
`flush()`. Every escape type implements `std::fmt::Display`. There is NO `queue!`/`execute!` macro and
no `Command` trait. The top-level type is `Csi` (`escape/csi.rs:33`), formatted as `ESC [` + payload
(`csi.rs:80-95`). Plain text is just written as bytes/`&str` — there is **no `Print` command**; you
`write!(terminal, "{}", glyph)`.

Bring into scope:
```rust
use termina::escape::csi::{Csi, Cursor, Sgr, Edit, EraseInLine, EraseInDisplay,
                           Mode, DecPrivateMode, DecPrivateModeCode};
use termina::style::{ColorSpec, RgbColor, Intensity, Underline};
use termina::OneBased;
```

### Cursor move (crossterm `MoveTo(col, row)`)
`Csi::Cursor(Cursor::Position { line, col })` — note these are `OneBased` and **line/col, i.e.
row first, column second**. `OneBased` is 1-based; use `from_zero_based` to convert your 0-based model
indices (`lib.rs:114`). Emits `CSI {line};{col}H` (`csi.rs:887`).
```rust
// move to 0-based (row, col) = (y, x)
Csi::Cursor(Cursor::Position {
    line: OneBased::from_zero_based(y),   // row
    col:  OneBased::from_zero_based(x),   // column
})
// home (1;1): Cursor::default_position()  (csi.rs:842-847)
```
`OneBased::from_zero_based(n)` **panics if `n == u16::MAX`** (`lib.rs:114-117`). `OneBased::new(n)`
returns `Option`, `None` for 0.

Other moves: `Cursor::Up(u32)`/`Down`/`Left`/`Right` (default arg 1), `Cursor::SaveCursor` (`CSI s`),
`Cursor::RestoreCursor` (`CSI u`) (`csi.rs:769-887`).

### Show / hide cursor (crossterm `Show` / `Hide`)
**No termina method.** DEC private mode `ShowCursor = 25` (`csi.rs:1376`):
```rust
// Show cursor: "\x1b[?25h"
Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(DecPrivateModeCode::ShowCursor)))
// Hide cursor: "\x1b[?25l"
Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(DecPrivateModeCode::ShowCursor)))
```

### SGR set color / attributes (crossterm `SetForegroundColor`, `SetAttribute`, etc.)
`Csi::Sgr(Sgr)` emits `CSI {sgr}m` (`csi.rs:85`). The `Sgr` enum (`csi.rs:106-155`), exact variants:
```rust
pub enum Sgr {
    Reset,                          // SGR 0  -> "\x1b[m"  (writes empty, terminal defaults to 0)
    Intensity(Intensity),           // Bold=1 / Dim=2 / Normal=22
    Underline(Underline),           // None=24 Single=4 Double=21 Curly="4:3" Dotted="4:4" Dashed="4:5"
    Blink(Blink),                   // None=25 Slow=5 Rapid=6
    Italic(bool),                   // true=3  false=23
    Reverse(bool),                  // true=7  false=27   (crossterm Attribute::Reverse)
    Invisible(bool),                // true=8  false=28
    StrikeThrough(bool),            // true=9  false=29
    Overline(bool),                 // true=53 false=55
    Font(Font),                     // 10..19
    VerticalAlign(VerticalAlign),   // 73/74/75
    Foreground(ColorSpec),          // SetForegroundColor
    Background(ColorSpec),          // SetBackgroundColor
    UnderlineColor(ColorSpec),      // SGR 58
    Attributes(SgrAttributes),      // batch of all of the above in one CSI ... m
}
```
Mapping crossterm attributes to `Sgr` variants:
- bold → `Sgr::Intensity(Intensity::Bold)` (`"\x1b[1m"`)
- dim → `Sgr::Intensity(Intensity::Dim)` (`"\x1b[2m"`)
- italic → `Sgr::Italic(true)` (`"\x1b[3m"`)
- underline → `Sgr::Underline(Underline::Single)` (`"\x1b[4m"`)
- reverse → `Sgr::Reverse(true)` (`"\x1b[7m"`)
- reset all → `Sgr::Reset` (`"\x1b[m"`)

Example snippets (verified from doc tests in source):
```rust
Csi::Sgr(Sgr::Foreground(ColorSpec::RED)).to_string()           // "\x1b[31m"
Csi::Sgr(Sgr::Foreground(ColorSpec::from(RgbColor::new(0,0,255)))).to_string() // "\x1b[38;2;0;0;255m"
Csi::Sgr(Sgr::Intensity(Intensity::Bold)).to_string()           // "\x1b[1m"
Csi::Sgr(Sgr::Reset).to_string()                                // "\x1b[m"
```

**Batched SGR (recommended for per-cell rendering to cut bytes):** `Sgr::Attributes(SgrAttributes)`.
`SgrAttributes` (`csi.rs:439-463`):
```rust
pub struct SgrAttributes {
    pub foreground: Option<ColorSpec>,
    pub background: Option<ColorSpec>,
    pub underline_color: Option<ColorSpec>,
    pub modifiers: SgrModifiers,          // bitflags: RESET, INTENSITY_BOLD, ITALIC, UNDERLINE_SINGLE, REVERSE, ...
    pub parameter_chunk_size: NonZeroU16, // default 10; splits into multiple CSI if exceeded
}
impl Default; impl SgrAttributes::is_empty(&self) -> bool;
```
`SgrModifiers` flags (`csi.rs:514-582`): `NONE, RESET, INTENSITY_NORMAL, INTENSITY_DIM, INTENSITY_BOLD,
UNDERLINE_NONE, UNDERLINE_SINGLE, UNDERLINE_DOUBLE, UNDERLINE_CURLY, UNDERLINE_DOTTED, UNDERLINE_DASHED,
BLINK_NONE, BLINK_SLOW, BLINK_RAPID, ITALIC, NO_ITALIC, REVERSE, NO_REVERSE, INVISIBLE, NO_INVISIBLE,
STRIKE_THROUGH, NO_STRIKE_THROUGH`. (No flag for overline/font/vertical-align — use the `Sgr` variants
for those.) Example:
```rust
use termina::escape::csi::{SgrAttributes, SgrModifiers};
let attrs = SgrAttributes {
    foreground: Some(ColorSpec::from(RgbColor::new(255, 200, 0))),
    background: Some(ColorSpec::PaletteIndex(0)),
    modifiers: SgrModifiers::INTENSITY_BOLD | SgrModifiers::REVERSE,
    ..Default::default()
};
write!(terminal, "{}", Csi::Sgr(Sgr::Attributes(attrs)))?; // one CSI ... m
```

### Clear (crossterm `Clear(ClearType::*)`)
Use `Csi::Edit(Edit::...)` (`csi.rs:1012-1116`, Display `csi.rs:1118-1141`):
- whole screen → `Csi::Edit(Edit::EraseInDisplay(EraseInDisplay::EraseDisplay))` → `CSI 2J`
  (variants: `EraseToEndOfDisplay=0`, `EraseToStartOfDisplay=1`, `EraseDisplay=2`, `EraseScrollback=3`).
- whole line → `Csi::Edit(Edit::EraseInLine(EraseInLine::EraseLine))` → `CSI 2K`
  (variants: `EraseToEndOfLine=0`, `EraseToStartOfLine=1`, `EraseLine=2`).
- erase N chars → `Edit::EraseCharacter(u32)` (`CSI {n}X`), scroll → `Edit::ScrollUp/Down(u32)`.

### Print text (crossterm `Print`)
No command. Just write the string/char:
```rust
write!(terminal, "{}", 'X')?;       // or write!(terminal, "{}", some_str)?;
```

### Window title (crossterm `SetTitle`) — via OSC
`termina::escape::osc::Osc` exists (`escape.rs:35`, full enum in `escape/osc.rs`). For titles look at
`Osc` variants there; titles/clipboard/dynamic-colors are OSC. (Not load-bearing for the cell-render
port; mentioned for completeness. If you set titles, read `escape/osc.rs` for the exact variant name.)

### There is no `queue!`/`execute!`
crossterm's `queue!(w, cmd)` / `execute!(w, cmd)` have no equivalent. Replace
`queue!(w, MoveTo(x,y), SetForegroundColor(c), Print(s))` with a single
`write!(w, "{}{}{}", Csi::Cursor(...), Csi::Sgr(...), s)` and an explicit `w.flush()` where
`execute!` would have auto-flushed.

---

## 6. Synchronized output (BSU/ESU, DEC mode 2026)

**Yes, termina models it.** `DecPrivateModeCode::SynchronizedOutput = 2026` (`csi.rs:1524-1527`).
Begin = set (`CSI ?2026h`), End = reset (`CSI ?2026l`):
```rust
// Begin Synchronized Update (BSU): "\x1b[?2026h"
Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(DecPrivateModeCode::SynchronizedOutput)))
// End Synchronized Update (ESU): "\x1b[?2026l"
Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(DecPrivateModeCode::SynchronizedOutput)))
```
This produces byte-identical output to emitting `ESC[?2026h` / `ESC[?2026l` raw, so the typed form is
the right choice — no need to write raw bytes. (Confirmed by the `Mode` Display impl at
`csi.rs:1249-1250`: set→`?{mode}h`, reset→`?{mode}l`, and `DecPrivateMode::Code(c)` formats as `c as u16`.)

---

## 7. Color & attribute model (map vt100 `Color::{Default, Idx(u8), Rgb(u8,u8,u8)}`)

The single color input type is `termina::style::ColorSpec` (`style.rs:390-409`):
```rust
pub enum ColorSpec {
    Reset,                       // back to terminal default  (fg -> "39", bg -> "49")
    PaletteIndex(PaletteIndex),  // PaletteIndex = u8 (style.rs:371); 0..255 indexed
    TrueColor(RgbaColor),        // 24-bit; RgbaColor has red/green/blue/alpha: u8
}
```
Direct mapping for `vt100::Color`:
```rust
use termina::style::{ColorSpec, RgbColor};

fn map_color(c: vt100::Color) -> ColorSpec {
    match c {
        vt100::Color::Default      => ColorSpec::Reset,                       // -> SGR 39/49
        vt100::Color::Idx(i)       => ColorSpec::PaletteIndex(i),             // -> 38;5;{i} / 48;5;{i} (or 30-37/40-47 for 0..7)
        vt100::Color::Rgb(r, g, b) => ColorSpec::from(RgbColor::new(r, g, b)),// -> 38;2;r;g;b / 48;2;r;g;b
    }
}
```
Notes:
- `ColorSpec::PaletteIndex(i)` for `i` 0..15 that match a named ANSI const formats as the short
  SGR (e.g. `PaletteIndex(1)` fg → `"31"`); 16..255 format as `"38;5;{i}"` / `"48;5;{i}"` (fg/bg)
  (`csi.rs:228-264`). Either way it is correct indexed color, so a plain `PaletteIndex(i)` is fine for
  all 0..255.
- `RgbColor::new(r,g,b) -> ColorSpec` via `From` produces `ColorSpec::TrueColor(RgbaColor{alpha:255})`
  → `"38;2;r;g;b"` (semicolon form, conhost-compatible) (`style.rs:458-462`, `csi.rs:180`).
- `RgbColor { pub red: u8, pub green: u8, pub blue: u8 }`; `RgbColor::new(r,g,b)` const ctor
  (`style.rs:158-172`). Also `RgbColor::new_f32`, `FromStr` ("#rrggbb" / "rgb:r/g/b").
- Convenience consts on `ColorSpec`: `ColorSpec::BLACK..WHITE`, `BRIGHT_BLACK..BRIGHT_WHITE`,
  `ColorSpec::RED` etc. (`style.rs:412-444`). `AnsiColor` enum (16 named, `style.rs:327-368`) and
  `WebColor(u8)` (`style.rs:138`) both `Into<ColorSpec>` if you prefer named/256 helpers.

Attribute model: there is no single "Attributes" struct combining bold/italic/etc. as separate
booleans; you either emit individual `Sgr` variants (§5) or pack them with `SgrAttributes` +
`SgrModifiers` bitflags (§5). The `style.rs` enums to map onto: `Intensity{Normal,Bold,Dim}`,
`Underline{None,Single,Double,Curly,Dotted,Dashed}`, `Blink{None,Slow,Rapid}`, plus the bool-carrying
`Sgr::{Italic,Reverse,Invisible,StrikeThrough,Overline}`.

---

## 8. Platform / async — answered

- **Unix and Windows both supported** (§0). For your unix-targeted client, `PlatformTerminal` =
  `UnixTerminal`, all the above works as written.
- **No feature flags needed.** Do not enable `event-stream` (you use raw stdin).
- **No async runtime is pulled in.** termina is fully synchronous. Driving it from a tokio task is
  fine; just remember writes are **blocking** buffered I/O and you must `flush()`. If a frame write
  could block on a slow tty and you don't want to stall the async executor, wrap the flush in
  `tokio::task::spawn_blocking` — but for normal terminals direct synchronous writes are fine.

---

## END-TO-END SNIPPET (acquire, raw + alt screen, synchronized frame loop, clean exit)

```rust
use std::io::{self, Write as _};

use termina::{
    escape::csi::{Csi, Cursor, Sgr, DecPrivateMode, DecPrivateModeCode, Mode},
    style::{ColorSpec, RgbColor},
    OneBased, PlatformTerminal, Terminal as _,
};

/// One cell of your render model.
struct Cell { row: u16, col: u16, fg: ColorSpec, bg: ColorSpec, glyph: char }

fn run(frames: impl IntoIterator<Item = Vec<Cell>>) -> io::Result<()> {
    // 1. acquire terminal (this is your writer; impls io::Write)
    let mut term = PlatformTerminal::new()?;

    // 2. enter raw mode + alt screen + hide cursor
    term.enter_raw_mode()?;
    write!(
        term,
        "{}{}",
        Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(
            DecPrivateModeCode::ClearAndEnableAlternateScreen,   // ESC[?1049h
        ))),
        Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(
            DecPrivateModeCode::ShowCursor,                      // ESC[?25l  (hide)
        ))),
    )?;
    term.flush()?;

    // 3. render loop: each frame wrapped in synchronized output (BSU/ESU)
    for frame in frames {
        // Begin Synchronized Update: ESC[?2026h
        write!(term, "{}", Csi::Mode(Mode::SetDecPrivateMode(
            DecPrivateMode::Code(DecPrivateModeCode::SynchronizedOutput))))?;

        for cell in &frame {
            write!(
                term,
                "{}{}{}{}",
                Csi::Cursor(Cursor::Position {                   // MoveTo(row, col)
                    line: OneBased::from_zero_based(cell.row),
                    col:  OneBased::from_zero_based(cell.col),
                }),
                Csi::Sgr(Sgr::Foreground(cell.fg)),             // SGR fg
                Csi::Sgr(Sgr::Background(cell.bg)),             // SGR bg
                cell.glyph,                                      // the glyph (no Print command)
            )?;
        }

        // reset SGR so trailing state doesn't bleed
        write!(term, "{}", Csi::Sgr(Sgr::Reset))?;              // ESC[m

        // End Synchronized Update: ESC[?2026l
        write!(term, "{}", Csi::Mode(Mode::ResetDecPrivateMode(
            DecPrivateMode::Code(DecPrivateModeCode::SynchronizedOutput))))?;

        term.flush()?; // buffered writer: nothing reaches the tty until flush
    }

    // 4. clean exit: show cursor + leave alt screen, then cooked mode.
    write!(
        term,
        "{}{}",
        Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(
            DecPrivateModeCode::ShowCursor,                      // ESC[?25h
        ))),
        Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(
            DecPrivateModeCode::ClearAndEnableAlternateScreen,  // ESC[?1049l
        ))),
    )?;
    term.flush()?;
    term.enter_cooked_mode()?; // Drop also does this, but be explicit
    Ok(())
}

// build a color: vt100::Color -> ColorSpec
fn _example_color() -> ColorSpec { ColorSpec::from(RgbColor::new(255, 128, 0)) }
```

Robustness note: termina's `Drop` restores cooked mode and flushes, but does **not** leave the alt
screen or re-show the cursor. For panic safety, register a cleanup via `term.set_panic_hook(|h| { ...
write ESC[?25h ESC[?1049l to h ... })` (signature §1; `h: &mut PlatformHandle` which is
`FileDescriptor` on unix and impls `io::Write`). Otherwise on panic the user is left on the alt
screen with a hidden cursor.

---

## Things with NO termina method (write the typed `Csi`/`Csi::Mode` yourself — all modeled, no raw bytes needed)

| crossterm | termina (no method; emit this typed value) |
|---|---|
| `EnterAlternateScreen` / `LeaveAlternateScreen` | `Csi::Mode(Set/ResetDecPrivateMode(Code(ClearAndEnableAlternateScreen)))` (1049) |
| `Show` / `Hide` cursor | `Csi::Mode(Set/ResetDecPrivateMode(Code(ShowCursor)))` (25) |
| synchronized update (no crossterm public command) | `Csi::Mode(Set/ResetDecPrivateMode(Code(SynchronizedOutput)))` (2026) |
| `EnableBracketedPaste` etc. | `Csi::Mode(... Code(BracketedPaste))` (2004) — not needed for output-only |
| `queue!` / `execute!` macros | none — use `write!(...)` + explicit `flush()` |
| `Print(x)` | none — just `write!(term, "{}", x)` |

**Nothing in the required feature set lacks a typed termina equivalent.** Every escape you need
(alt screen, raw mode, cursor move/show/hide, SGR fg/bg/attrs, clear, synchronized output) is either a
`Terminal` method (raw/cooked, dimensions) or a `Display`-able `Csi`/`Csi::Mode` value. You should not
need to write any raw escape byte strings.
