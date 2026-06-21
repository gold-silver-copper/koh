# PTY + crossterm API ground-truth cheat-sheet

Extracted verbatim from installed sources:
- `portable-pty 0.9.0` (`~/.cargo/.../portable-pty-0.9.0/src/{lib.rs, cmdbuilder.rs, unix.rs}`)
- `crossterm 0.29.0` (`~/.cargo/.../crossterm-0.29.0/src/{lib.rs, event.rs, terminal.rs, style.rs, cursor.rs, command.rs, macros.rs, style/types/{color,attribute}.rs}`)

All signatures below are copy-paste-accurate against those files. `Error` = `anyhow::Error`, `IoResult<T>` = `std::io::Result<T>`. portable-pty returns `anyhow::Result` everywhere except the `Child` trait (which uses `std::io::Result`); crossterm returns `std::io::Result` everywhere.

---

## 1. portable-pty 0.9.0

### 1.1 Entry point + system

```rust
pub fn native_pty_system() -> Box<dyn PtySystem + Send>;

// NOTE: the return type is `Box<dyn PtySystem + Send>`, NOT `Box<dyn PtySystem>`.
// type alias on unix:    pub type NativePtySystem = unix::UnixPtySystem;
// type alias on windows: pub type NativePtySystem = win::conpty::ConPtySystem;

pub trait PtySystem: Downcast {
    fn openpty(&self, size: PtySize) -> anyhow::Result<PtyPair>;
}
```

`openpty` is the only required method. `PtySystem: Downcast` (downcast-rs), so it is NOT object-safe-trivial but is used as `Box<dyn PtySystem + Send>` fine.

### 1.2 PtySize

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl Default for PtySize { /* rows:24, cols:80, pixel_width:0, pixel_height:0 */ }
```

Construct with struct literal (all four fields are required unless you use `..Default::default()`). `pixel_width`/`pixel_height` may be set to 0; on unix they ARE passed to `openpty`/`TIOCSWINSZ` as `ws_xpixel`/`ws_ypixel`.

### 1.3 PtyPair

```rust
pub struct PtyPair {
    pub slave: Box<dyn SlavePty + Send>,   // declared first => dropped first (RFC 1857)
    pub master: Box<dyn MasterPty + Send>,
}
```

Drop order matters: `slave` is listed first so it drops first. Take the writer/reader and spawn the child BEFORE dropping things you still need.

### 1.4 MasterPty trait (the control end)

```rust
pub trait MasterPty: Downcast + Send {
    fn resize(&self, size: PtySize) -> Result<(), Error>;
    fn get_size(&self) -> Result<PtySize, Error>;
    fn try_clone_reader(&self) -> Result<Box<dyn std::io::Read + Send>, Error>;
    fn take_writer(&self) -> Result<Box<dyn std::io::Write + Send>, Error>;

    // unix-only methods:
    #[cfg(unix)] fn process_group_leader(&self) -> Option<libc::pid_t>;
    #[cfg(unix)] fn as_raw_fd(&self) -> Option<unix::RawFd>;   // RawFd = std::os::unix::io::RawFd
    #[cfg(unix)] fn tty_name(&self) -> Option<std::path::PathBuf>;
    #[cfg(unix)] fn get_termios(&self) -> Option<nix::sys::termios::Termios> { None }
}
```

Notes / gotchas:
- `resize` / `get_size` / `try_clone_reader` take `&self` (NOT `&mut self`) — the master is shareable.
- `take_writer()` may be called only ONCE. The unix impl tracks `took_writer: RefCell<bool>` and `anyhow::bail!("cannot take writer more than once")` on the 2nd call. Each `try_clone_reader()` call dups the fd, so you CAN clone the reader multiple times.
- The reader (`Box<dyn Read + Send>`) is a **blocking** `read()` over the master fd. On unix, when the slave closes, `read()` translates `EIO` into `Ok(0)` (EOF). **You MUST read it on a dedicated blocking OS thread** (`std::thread::spawn`); there is no async/poll variant in this crate. Forward bytes from that thread into your channel / iroh stream.
- The writer (`Box<dyn Write + Send>`) on unix is a `UnixMasterWriter` whose `Drop` sends `\n` + VEOF (EOT) to the slave before closing — i.e. dropping the writer signals EOF to the child. Keep it alive while the session is live.
- `process_group_leader()` returns `tcgetpgrp(master_fd)` — the foreground process group of the pty (useful to detect what's running). `as_raw_fd()` returns the master fd. `tty_name()` returns the slave's `/dev/ttys…` path.
- `resize` issues `ioctl(TIOCSWINSZ)` which generates `SIGWINCH` to the child. This is how you propagate remote terminal resizes.

### 1.5 SlavePty trait (spawn end)

```rust
pub trait SlavePty {
    fn spawn_command(&self, cmd: CommandBuilder) -> Result<Box<dyn Child + Send + Sync>, Error>;
}
```

`spawn_command` consumes the `CommandBuilder` by value and returns a boxed `Child + Send + Sync`. On unix it wires the slave fd to the child's stdin/stdout/stderr, calls `setsid()`, sets the controlling tty (`TIOCSCTTY`) unless disabled, resets signal dispositions, and closes random inherited fds.

### 1.6 Child + ChildKiller traits

```rust
pub trait Child: std::fmt::Debug + ChildKiller + Downcast + Send {
    fn try_wait(&mut self) -> IoResult<Option<ExitStatus>>;  // non-blocking; None = still running
    fn wait(&mut self) -> IoResult<ExitStatus>;              // blocks
    fn process_id(&self) -> Option<u32>;
    #[cfg(windows)] fn as_raw_handle(&self) -> Option<std::os::windows::io::RawHandle>;
}

pub trait ChildKiller: std::fmt::Debug + Downcast + Send {
    fn kill(&mut self) -> IoResult<()>;
    fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync>;
}
```

- `try_wait` / `wait` / `kill` all take `&mut self`. So if you want to `wait()` on a blocking thread AND be able to `kill()` from elsewhere, call `child.clone_killer()` first to get an independent `Box<dyn ChildKiller + Send + Sync>` you can move to another thread.
- On unix `kill()` first sends `SIGHUP`, waits up to ~250ms (5×50ms) polling `try_wait`, then falls back to a real kill. Returns `Ok(())` when already gone.

### 1.7 ExitStatus

```rust
#[derive(Debug, Clone)]
pub struct ExitStatus { /* private: code: u32, signal: Option<String> */ }

impl ExitStatus {
    pub fn with_exit_code(code: u32) -> Self;
    pub fn with_signal(signal: &str) -> Self;   // code is forced to 1
    pub fn success(&self) -> bool;               // true iff signal.is_none() && code == 0
    pub fn exit_code(&self) -> u32;
    pub fn signal(&self) -> Option<&str>;
}
// impl From<std::process::ExitStatus> for ExitStatus
// impl std::fmt::Display for ExitStatus
```

### 1.8 CommandBuilder (cmdbuilder.rs)

```rust
#[derive(Clone, Debug, PartialEq)]
pub struct CommandBuilder { /* all fields private */ }

impl CommandBuilder {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self;        // argv[0] = program
    pub fn from_argv(args: Vec<OsString>) -> Self;
    pub fn new_default_prog() -> Self;                       // run the user's default shell

    pub fn is_default_prog(&self) -> bool;
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S);          // PANICS if called on new_default_prog()
    pub fn args<I, S>(&mut self, args: I)
        where I: IntoIterator<Item = S>, S: AsRef<OsStr>;    // also panics on default_prog
    pub fn get_argv(&self) -> &Vec<OsString>;
    pub fn get_argv_mut(&mut self) -> &mut Vec<OsString>;

    pub fn env<K, V>(&mut self, key: K, value: V)
        where K: AsRef<OsStr>, V: AsRef<OsStr>;
    pub fn env_remove<K>(&mut self, key: K) where K: AsRef<OsStr>;
    pub fn env_clear(&mut self);
    pub fn get_env<K>(&self, key: K) -> Option<&OsStr> where K: AsRef<OsStr>;

    pub fn cwd<D>(&mut self, dir: D) where D: AsRef<OsStr>;
    pub fn clear_cwd(&mut self);
    pub fn get_cwd(&self) -> Option<&OsString>;

    pub fn set_controlling_tty(&mut self, controlling_tty: bool);  // default true
    pub fn get_controlling_tty(&self) -> bool;

    pub fn iter_extra_env_as_str(&self) -> impl Iterator<Item = (&str, &str)>; // only caller-set vars
    pub fn iter_full_env_as_str(&self)  -> impl Iterator<Item = (&str, &str)>;
    pub fn as_unix_command_line(&self) -> anyhow::Result<String>;

    #[cfg(unix)] pub fn umask(&mut self, mask: Option<libc::mode_t>);
    #[cfg(unix)] pub fn get_shell(&self) -> String;
}
```

Critical gotchas:
- **All mutator methods (`arg`, `args`, `env`, `cwd`, ...) take `&mut self` and return `()`** — this is NOT a fluent/chaining builder like `std::process::Command`. You must call them as statements:
  ```rust
  let mut cmd = CommandBuilder::new("bash");
  cmd.arg("-l");
  cmd.env("TERM", "xterm-256color");
  cmd.cwd("/home/user");
  ```
- `CommandBuilder::new(...)` and `new_default_prog()` **pre-populate the environment** from the current process via `std::env::vars_os()` (plus, on unix, a `SHELL` derived from the passwd db if unset). So the child inherits your env unless you `env_clear()`. `get_env("CARGO_PKG_AUTHORS")` works inside this crate's own build, illustrating that base env is loaded.
- `new_default_prog()` produces an empty argv; the unix impl runs the login shell (`-bash` style argv0). Calling `arg`/`args` on it panics.
- Windows env vars are case-insensitive (keys are lowercased internally); unix preserves case.
- `set_controlling_tty(false)` is the flatpak/container workaround.

### 1.9 Minimal happy-path usage (unix, blocking-thread reader)

```rust
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};

fn main() -> anyhow::Result<()> {
    let pty_system = native_pty_system();

    let pair = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    // Build the command (statement-style; methods return ()).
    let mut cmd = CommandBuilder::new("bash");
    cmd.env("TERM", "xterm-256color");
    cmd.cwd("/tmp");

    // Spawn into the slave end.
    let mut child = pair.slave.spawn_command(cmd)?;
    let mut killer = child.clone_killer(); // move to another thread if you need async kill

    // Reader MUST run on a blocking OS thread.
    let mut reader = pair.master.try_clone_reader()?;
    let reader_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,            // EOF (slave closed; EIO is mapped to 0 on unix)
                Ok(n) => { /* forward &buf[..n] to vt100 parser / iroh stream */ }
                Err(_) => break,
            }
        }
    });

    // Writer: take once. Keep alive for the session (Drop sends EOF to child).
    let mut writer = pair.master.take_writer()?;
    writer.write_all(b"ls -l\r\n")?;
    writer.flush()?;

    // Propagate a remote resize:
    pair.master.resize(PtySize { rows: 40, cols: 120, pixel_width: 0, pixel_height: 0 })?;

    // Wait for exit (blocks). Could be on its own thread.
    let status = child.wait()?;
    let _ = status.exit_code();
    let _ = killer.kill();           // no-op if already exited
    let _ = reader_thread.join();
    Ok(())
}
```

---

## 2. crossterm 0.29.0

### 2.1 Feature flags (DEFAULT matters)

```
default = ["bracketed-paste", "events", "windows", "derive-more"]
```

So with default features you get `event::{poll,read}`, `Event::Paste`, and the `is_variant`/`as_*_event` helpers. If you turn off default features you must re-enable `events` (gated on `mio`/`signal-hook`) for `poll`/`read`/`position`/`supports_keyboard_enhancement`, and `bracketed-paste` for `Event::Paste`. `use-dev-tty` is opt-in. New in 0.29: `derive-more` adds `is_variant()` methods; `KeyboardEnhancementFlags::REPORT_ALTERNATE_KEYS` exists.

### 2.2 Command machinery (lib.rs re-exports, command.rs)

```rust
pub use crate::command::{Command, ExecutableCommand, QueueableCommand, SynchronizedUpdate};

pub trait Command {
    fn write_ansi(&self, f: &mut impl fmt::Write) -> fmt::Result;
    #[cfg(windows)] fn execute_winapi(&self) -> io::Result<()>;
    #[cfg(windows)] fn is_ansi_code_supported(&self) -> bool { /* ... */ }
}

pub trait QueueableCommand  { fn queue(&mut self, command: impl Command) -> io::Result<&mut Self>; }
pub trait ExecutableCommand { fn execute(&mut self, command: impl Command) -> io::Result<&mut Self>; }
// Blanket impls for all T: Write + ?Sized.
```

Macros (from macros.rs, `#[macro_export]` at crate root):

```rust
queue!(writer $(, command)* $(,)?)   -> io::Result<()>   // queues, does NOT flush
execute!(writer $(, command)* $(,)?) -> io::Result<()>   // queues then flushes
```

- `queue!`/`execute!` take a writer expression (e.g. `stdout()`, `&mut out`) followed by comma-separated commands; both expand to `io::Result<()>` so end with `?`.
- `queue!` does NOT flush — call `writer.flush()?` yourself. `execute!` flushes each call (slower; prefer `queue!` + one `flush` for full-screen rendering).
- Method forms: `stdout.queue(cmd)?.queue(cmd2)?;` then `stdout.flush()?;` or `stdout.execute(cmd)?;`.
- Every command type also implements `Display` (via `impl_display!`), so you can `write!(out, "{}", MoveTo(0,0))` to get the raw ANSI — handy when targeting a non-Write sink.

### 2.3 terminal module (terminal.rs)

```rust
pub fn is_raw_mode_enabled() -> io::Result<bool>;
pub fn enable_raw_mode()     -> io::Result<()>;
pub fn disable_raw_mode()    -> io::Result<()>;
pub fn size()        -> io::Result<(u16, u16)>;   // (columns, rows); top-left cell is (1,1)
pub fn window_size() -> io::Result<WindowSize>;

#[derive(Debug)]
pub struct WindowSize { pub rows: u16, pub columns: u16, pub width: u16, pub height: u16 }
// width/height are pixels and may be 0 / unimplemented.

#[cfg(feature = "events")]
pub use sys::supports_keyboard_enhancement; // fn supports_keyboard_enhancement() -> io::Result<bool>
```

Command structs (all `#[derive(Debug, Clone, Copy, PartialEq, Eq)]` unless noted):

```rust
pub struct EnterAlternateScreen;       // CSI ?1049h
pub struct LeaveAlternateScreen;       // CSI ?1049l
pub struct DisableLineWrap;            // CSI ?7l
pub struct EnableLineWrap;             // CSI ?7h
pub struct ScrollUp(pub u16);          // CSI {n}S
pub struct ScrollDown(pub u16);        // CSI {n}T
pub struct SetSize(pub u16, pub u16);  // (cols, rows) -> CSI 8;{rows};{cols}t
pub struct SetTitle<T>(pub T);         // T: fmt::Display -> OSC 0
pub struct Clear(pub ClearType);
pub struct BeginSynchronizedUpdate;    // CSI ?2026h
pub struct EndSynchronizedUpdate;      // CSI ?2026l

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum ClearType { All, Purge, FromCursorDown, FromCursorUp, CurrentLine, UntilNewLine }
//   All -> 2J, Purge -> 3J, FromCursorDown -> J, FromCursorUp -> 1J,
//   CurrentLine -> 2K, UntilNewLine -> K
```

`size()` returns **(columns, rows)** — same order as `Event::Resize`. Map straight to `PtySize { cols, rows, .. }`.

### 2.4 cursor module (cursor.rs)

```rust
pub struct MoveTo(pub u16, pub u16);   // MoveTo(column, row); 0-based. -> CSI {row+1};{col+1}H
pub struct MoveToNextLine(pub u16);
pub struct MoveToPreviousLine(pub u16);
pub struct MoveToColumn(pub u16);      // 0-based
pub struct MoveToRow(pub u16);         // 0-based
pub struct MoveUp(pub u16);
pub struct MoveRight(pub u16);
// (cursor.rs also: MoveDown, MoveLeft, Show, Hide, SavePosition, RestorePosition,
//  EnableBlinking, DisableBlinking, SetCursorStyle)
#[cfg(feature = "events")] pub use sys::position; // fn position() -> io::Result<(u16,u16)>
```

`MoveTo(col, row)` — **column first, then row, both 0-based** (top-left = `MoveTo(0,0)`). This is the opposite field order to vt100's `(row, col)` cursor accessors, so swap when bridging.

### 2.5 style module (style.rs + types)

Command structs:

```rust
pub struct SetForegroundColor(pub Color);   // CSI 38;…m
pub struct SetBackgroundColor(pub Color);   // CSI 48;…m
pub struct SetUnderlineColor(pub Color);    // CSI 58;…m  (not supported on legacy winapi)
pub struct SetColors(pub Colors);           // fg+bg in one SGR (faster for full-cell rendering)
pub struct SetAttribute(pub Attribute);
pub struct SetAttributes(pub Attributes);
pub struct SetStyle(pub ContentStyle);
pub struct PrintStyledContent<D: Display>(pub StyledContent<D>);  // #[derive(Debug, Copy, Clone)]
pub struct ResetColor;                       // CSI 0m
pub struct Print<T: Display>(pub T);         // writes the Display output verbatim

pub fn style<D: Display>(val: D) -> StyledContent<D>;
pub fn available_color_count() -> u16;
pub fn force_color_output(enabled: bool);
```

Re-exported types: `Attributes, ContentStyle, StyledContent, Stylize, Attribute, Color, Colored, Colors`.

`Color` (style/types/color.rs):

```rust
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum Color {
    Reset,
    Black, DarkGrey, Red, DarkRed, Green, DarkGreen, Yellow, DarkYellow,
    Blue, DarkBlue, Magenta, DarkMagenta, Cyan, DarkCyan, White, Grey,
    Rgb { r: u8, g: u8, b: u8 },
    AnsiValue(u8),
}
// impl From<(u8,u8,u8)> for Color  (=> Rgb)
// Color::parse_ansi(&str) -> Option<Color>
```

For a vt100 bridge: vt100's RGB cell colors map to `Color::Rgb { r, g, b }`; vt100 indexed (0..=255) maps to `Color::AnsiValue(idx)` (or the named 16 for 0..=15); default maps to `Color::Reset`.

`Attribute` (style/types/attribute.rs, `#[non_exhaustive]`): variants include `Reset, Bold, Dim, Italic, Underlined, DoubleUnderlined, Undercurled, Underdotted, Underdashed, SlowBlink, RapidBlink, Reverse, Hidden, CrossedOut, Fraktur, NoBold, NormalIntensity, NoItalic, NoUnderline, NoBlink, NoReverse, NoHidden, NotCrossedOut, Framed, Encircled, OverLined, NotFramedOrEncircled, NotOverLined`.

```rust
impl Attribute {
    pub const fn bytes(self) -> u32;   // bitset signature for Attributes
    pub fn sgr(self) -> String;        // SGR parameter string
    pub fn iterator() -> impl Iterator<Item = Attribute>;
}
```

`Colors` is `Colors { foreground: Option<Color>, background: Option<Color> }` with `Colors::new(fg, bg)`. `Attributes` is a bitset of `Attribute` with `.has(attr)`/`.is_empty()`.

### 2.6 event module (event.rs)

Functions:

```rust
pub fn poll(timeout: Duration) -> std::io::Result<bool>;   // Ok(true) => read() won't block
pub fn read() -> std::io::Result<Event>;                   // blocks until an event
```

`poll`/`read` (and `EventStream`) MUST be used from a single thread; do not mix threads or combine `read`/`poll` with `EventStream`. Raw mode must be enabled for keyboard events to behave.

`Event` enum:

```rust
#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Hash)]   // Copy only when bracketed-paste off
pub enum Event {
    FocusGained,
    FocusLost,
    Key(KeyEvent),
    Mouse(MouseEvent),
    #[cfg(feature = "bracketed-paste")] Paste(String),
    Resize(u16, u16),    // (columns, rows)
}
```

Helper methods on `Event`: `is_key_press()`, `is_key_release()`, `is_key_repeat()`, `as_key_event() -> Option<KeyEvent>`, `as_key_press_event() -> Option<KeyEvent>`, `as_key_release_event()`, `as_key_repeat_event()`, `as_mouse_event() -> Option<MouseEvent>`, `as_paste_event() -> Option<&str>` (bracketed-paste only), `as_resize_event() -> Option<(u16,u16)>`.

`KeyEvent`:

```rust
#[derive(Debug, PartialOrd, Clone, Copy)]   // PartialEq/Eq/Hash are hand-written, case-normalizing
pub struct KeyEvent {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
    pub kind: KeyEventKind,
    pub state: KeyEventState,
}

impl KeyEvent {
    pub const fn new(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent;            // kind=Press
    pub const fn new_with_kind(code, modifiers, kind: KeyEventKind) -> KeyEvent;
    pub const fn new_with_kind_and_state(code, modifiers, kind, state) -> KeyEvent;
    pub fn is_press(&self) -> bool;
    pub fn is_release(&self) -> bool;
    pub fn is_repeat(&self) -> bool;
}
// impl From<KeyCode> for KeyEvent  (modifiers empty, kind Press)
```

WARNING: `KeyEvent`'s `PartialEq`/`Hash` normalize case — `KeyEvent::new(Char('A'), NONE)` compares equal to `Char('a') + SHIFT`. Don't rely on derived equality semantics. `kind` is only meaningful (non-`Press`) if you pushed `REPORT_EVENT_TYPES` (unix); on Windows `kind` is always set. So **on a stock unix terminal you only get `KeyEventKind::Press`** unless enhancement flags are enabled — filter on `is_key_press()` to avoid double-handling once enhancements are on.

```rust
#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Copy, Hash)]
pub enum KeyEventKind { Press, Repeat, Release }
```

`KeyCode`:

```rust
#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Copy, Hash)]
pub enum KeyCode {
    Backspace, Enter, Left, Right, Up, Down, Home, End, PageUp, PageDown,
    Tab, BackTab, Delete, Insert,
    F(u8),          // F(1) = F1
    Char(char),     // Char('c')
    Null, Esc,
    CapsLock, ScrollLock, NumLock, PrintScreen, Pause, Menu, KeypadBegin,
    Media(MediaKeyCode),
    Modifier(ModifierKeyCode),
}
impl KeyCode {
    pub fn is_function_key(&self, n: u8) -> bool;
    pub fn is_char(&self, c: char) -> bool;
    pub fn as_char(&self) -> Option<char>;
    pub fn is_media_key(&self, media: MediaKeyCode) -> bool;
}
```

`CapsLock/ScrollLock/NumLock/PrintScreen/Pause/Menu/KeypadBegin/Media/Modifier` are only delivered when kitty keyboard enhancement flags are active.

`KeyModifiers` (bitflags, `u8`):

```rust
pub struct KeyModifiers: u8 {
    const SHIFT   = 0b0000_0001;
    const CONTROL = 0b0000_0010;
    const ALT     = 0b0000_0100;
    const SUPER   = 0b0000_1000;   // only with DISAMBIGUATE_ESCAPE_CODES
    const HYPER   = 0b0001_0000;   // only with DISAMBIGUATE_ESCAPE_CODES
    const META    = 0b0010_0000;   // only with DISAMBIGUATE_ESCAPE_CODES
    const NONE    = 0b0000_0000;
}
```

Use `mods.contains(KeyModifiers::CONTROL)`, `KeyModifiers::CONTROL | KeyModifiers::ALT`, `KeyModifiers::empty()`/`NONE`.

`KeyEventState` (bitflags, `u8`): `KEYPAD`, `CAPS_LOCK`, `NUM_LOCK`, `NONE` — only set under `DISAMBIGUATE_ESCAPE_CODES`.

`MouseEvent` / `MouseEventKind` / `MouseButton`:

```rust
pub struct MouseEvent { pub kind: MouseEventKind, pub column: u16, pub row: u16, pub modifiers: KeyModifiers }
pub enum MouseEventKind { Down(MouseButton), Up(MouseButton), Drag(MouseButton), Moved,
                          ScrollDown, ScrollUp, ScrollLeft, ScrollRight }
pub enum MouseButton { Left, Right, Middle }
```

`MediaKeyCode` / `ModifierKeyCode`: large enums (Play/Pause/.../MuteVolume; LeftShift/LeftControl/.../IsoLevel5Shift) — only relevant with enhancement flags.

### 2.7 event-mode toggle commands (event.rs)

All are `#[derive(Debug, Clone, Copy, PartialEq, Eq)]` and implement `Command`:

```rust
pub struct EnableMouseCapture;            // CSI ?1000h;?1002h;?1003h;?1015h;?1006h
pub struct DisableMouseCapture;
pub struct EnableFocusChange;             // CSI ?1004h
pub struct DisableFocusChange;
#[cfg(feature = "bracketed-paste")] pub struct EnableBracketedPaste;   // CSI ?2004h
#[cfg(feature = "bracketed-paste")] pub struct DisableBracketedPaste;  // CSI ?2004l
pub struct PushKeyboardEnhancementFlags(pub KeyboardEnhancementFlags); // CSI > {bits} u
pub struct PopKeyboardEnhancementFlags;                                // CSI < 1 u

pub struct KeyboardEnhancementFlags: u8 {   // bitflags
    const DISAMBIGUATE_ESCAPE_CODES        = 0b0000_0001;
    const REPORT_EVENT_TYPES               = 0b0000_0010;
    const REPORT_ALTERNATE_KEYS            = 0b0000_0100;
    const REPORT_ALL_KEYS_AS_ESCAPE_CODES  = 0b0000_1000;
}
```

`PushKeyboardEnhancementFlags`/`EnableBracketedPaste` etc. error (`Unsupported`) on legacy Windows API but work on ANSI terminals. Gate `PushKeyboardEnhancementFlags` behind `supports_keyboard_enhancement()?`.

### 2.8 Minimal happy-path: raw mode + alt screen + render loop

```rust
use std::io::{stdout, Write};
use std::time::Duration;
use crossterm::{
    execute, queue,
    terminal::{enable_raw_mode, disable_raw_mode, size,
               EnterAlternateScreen, LeaveAlternateScreen, Clear, ClearType},
    event::{poll, read, Event, KeyCode, KeyModifiers,
            EnableBracketedPaste, DisableBracketedPaste},
    cursor::MoveTo,
    style::{Print, SetForegroundColor, SetBackgroundColor, ResetColor, Color},
};

fn main() -> std::io::Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableBracketedPaste)?;

    let (cols, rows) = size()?;   // (columns, rows) -> feed to PtySize { cols, rows, .. }

    'main: loop {
        // RENDER: one synchronized frame, single flush.
        queue!(out, Clear(ClearType::All))?;
        for row in 0..rows {
            for col in 0..cols {
                // pull cell (ch, fg, bg) from your synced vt100 grid here:
                queue!(out,
                    MoveTo(col, row),                 // (column, row), 0-based
                    SetForegroundColor(Color::White),
                    SetBackgroundColor(Color::Reset),
                    Print('.'),                       // a single cell glyph
                )?;
            }
        }
        queue!(out, ResetColor)?;
        out.flush()?;                                  // one flush per frame

        // INPUT
        if poll(Duration::from_millis(16))? {
            match read()? {
                Event::Key(k) if k.is_press() => {
                    if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                        break 'main;
                    }
                    // encode k -> bytes -> write to PTY (see section 3)
                }
                Event::Resize(c, r) => { /* master.resize(PtySize{cols:c, rows:r, ..}) */ }
                Event::Paste(_data) => { /* forward bytes (already bracketed by terminal) */ }
                _ => {}
            }
        }
    }

    execute!(out, DisableBracketedPaste, LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}
```

---

## 3. Input capture: raw stdin bytes vs decoded crossterm Events (design note for a terminal client)

You need to send to the PTY exactly the byte sequences the remote child expects. Two strategies:

**(A) Raw stdin passthrough (recommended for a mosh-style client).**
Put the local terminal in raw mode (`enable_raw_mode()`) and read raw bytes off `stdin` on a blocking thread, forwarding them verbatim to the PTY writer (over iroh). Because the local terminal is in raw mode, the bytes the OS hands you are already the canonical terminal input encoding (e.g. `Ctrl-C` = `0x03`, arrow up = `ESC [ A` or `ESC O A` depending on app cursor-key mode, UTF-8 multibyte chars intact, bracketed-paste wrappers `ESC [ 200~ … ESC [ 201~` if you enabled them). No re-encoding, no information loss, full fidelity (function keys, modifyOtherKeys/kitty sequences, mouse SGR reports, etc.). This is the simplest and most correct path and is what real mosh/ssh do.
- crossterm's `poll`/`read` are NOT usable for byte-perfect passthrough: they DECODE bytes into `Event` and discard the original sequence (and may merge/normalize). Use crossterm here only for the lifecycle commands (raw mode, alt screen, mouse/paste/kbd enable) — read stdin raw yourself (e.g. `std::io::stdin().lock().read(&mut buf)` on a thread, or on unix read the tty fd directly).
- Caveat: if you read raw stdin AND also call `crossterm::event::read()`, they fight over the same fd. Pick one consumer of stdin. For passthrough, do not also run crossterm's event reader on stdin; instead detect resize via a `SIGWINCH` handler (or poll `terminal::size()`), and detect local-only hotkeys by scanning the raw byte stream yourself.

**(B) Decode to `Event`, then re-encode to PTY bytes (more work, lossy).**
Use `event::read()` to get `Event::Key(KeyEvent)` etc., then translate each `KeyEvent` back into the byte sequence the child wants. You must reimplement the terminal's input encoder:
- `KeyCode::Char(c)` with no/又SHIFT → the UTF-8 bytes of `c`.
- `CONTROL + Char(c)` → control byte `c.to_ascii_uppercase() as u8 & 0x1f` (e.g. Ctrl-C → 0x03), with special-cases (Ctrl-Space → 0x00, etc.).
- `ALT + key` → prefix `ESC` (0x1b) then the key's bytes (meta-prefix).
- `Enter` → `\r` (0x0d) typically (not `\n`); `Tab` → `\t`; `Backspace` → 0x7f (usually) or 0x08; `Esc` → 0x1b.
- Arrows/Home/End/PageUp/PageDown/F-keys → CSI/SS3 sequences, and these DEPEND on the remote app's modes (DECCKM cursor-key application mode flips `ESC [ A` vs `ESC O A`), which the client cannot reliably know. This is exactly the information you lose by decoding, and why (A) is preferred.
- `Event::Paste(s)` → you'd have to re-wrap with bracketed-paste markers if the child enabled them; with (A) the wrappers are preserved automatically.

**Recommendation:** Use (A) raw passthrough for stdin→PTY. Use crossterm purely as the OUTPUT/rendering and terminal-mode-control layer (raw mode, alt screen, `queue!`/`MoveTo`/`Set*Color`/`Print` to paint the synced vt100 grid), plus optionally as a convenience event source for *local* control keys if you can dedicate it a separate input channel. Mixing crossterm's decoder into the keystroke-forwarding path will drop fidelity (cursor-key modes, kitty/CSI-u, exact backspace byte) and is the classic source of "my arrow keys / vim / tmux are broken over the wire" bugs.
