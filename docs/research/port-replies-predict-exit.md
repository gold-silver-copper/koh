# Port notes: terminal reply synthesis, predictor arrows/wide chars, exit-status propagation

Engineer-facing, code-from-these notes. Versions: `vt100 0.16.2`, `vte 0.15.0`,
`portable-pty` (workspace). Current repo = `moshers2` (crate names `rmosh-*`), reference =
`moshers` (crate names `moshers-*`).

Three independent work items: A (server answers terminal queries), B (predict arrow keys +
wide chars), C (propagate remote shell exit code to client process).

---

## A. TERMINAL REPLY SYNTHESIS (server answers DSR / DA / DEC-mode queries)

### A.0 What the reference repo actually does — NOTHING

I grepped `moshers/crates/moshers-terminal/src/lib.rs` and `moshers-server/src/main.rs` for
`read_octets_to_host` / `to_host` / `reply` / `DSR` / device-attr / `6n` / `[c`. **There is
no reply-synthesis code in the reference repo.** The only `moshers-terminal/lib.rs` "match"
was `#[cfg(test)]`; `moshers-server/main.rs` matches were the doc comment and pty plumbing.

`moshers-terminal::ScreenState` wraps a plain `vt100::Parser` (no callbacks) and exposes only
`act(bytes)` / `resize` / `screen()` / echo-ack machinery. It never generates host-bound
bytes. So **this is a real parity gap vs. mosh in BOTH repos** — neither answers `ESC[6n`,
`ESC[c`, etc. You are adding new behavior, not porting existing behavior. (mosh's C++ does
this in `Emulator::read_octets_to_host`; there is no Rust precedent to copy here.)

### A.1 Why it matters

The server is the only real terminal in the system (the client just paints the synced grid).
When an app on the server's PTY emits a query — cursor-position report `ESC[6n`, primary DA
`ESC[c`, secondary DA `ESC[>c`, DECRQM `ESC[?<n>$p` — it blocks waiting for the terminal's
answer on its stdin (= the PTY master's input, = `pty.write_input`). vt100 does NOT
auto-answer. If nobody answers, apps that probe (vim, tmux, anything calling `tigetstr`-style
cursor probes, bracketed-paste detection, etc.) hang or mis-detect capabilities.

### A.2 vt100 0.16.2 surfacing — confirmed against source

`vt100::Parser` is generic: `Parser<CB: Callbacks = ()>`. Build with
`vt100::Parser::new_with_callbacks(rows, cols, scrollback, cb)`; read state back with
`parser.callbacks()` / `parser.callbacks_mut()`. The current code already does this — see
`crates/terminal/src/server.rs` `struct Callbacks { title, icon, bell_count }` and
`vt100::Parser::new_with_callbacks(...)` in `ServerTerminal::new`.

`vt100` does NOT implement DSR/DA/DECRQM internally; these fall straight through to
`Callbacks::unhandled_csi`. Verified in
`~/.cargo/.../vt100-0.16.2/src/perform.rs` `fn csi_dispatch` (lines 87–196). Exact routing
(the `unhandled` closure passes `(intermediates.first().copied(), intermediates.get(1).copied(),
&params.iter().collect::<Vec<_>>(), c)`):

| Input bytes        | meaning                | intermediates.first() | `c`   | reaches `unhandled_csi` as `(i1, i2, params, c)`                |
|--------------------|------------------------|-----------------------|-------|----------------------------------------------------------------|
| `ESC [ 6 n`        | DSR cursor pos report  | `None`                | `'n'` | `(None, None, [[6]], 'n')` — falls to the `None => _` arm      |
| `ESC [ 5 n`        | DSR "are you ok?"      | `None`                | `'n'` | `(None, None, [[5]], 'n')`                                      |
| `ESC [ c` / `ESC [ 0 c` | primary DA        | `None`                | `'c'` | `(None, None, [] or [[0]], 'c')` — `None => _` arm             |
| `ESC [ > c` / `ESC [ > 0 c` | secondary DA  | `Some(b'>')`          | `'c'` | `(Some(b'>'), None, …, 'c')` — `Some(i) => …` arm             |
| `ESC [ ? 6 n`      | DECDSR (with `?`)      | `Some(b'?')`          | `'n'` | `(Some(b'?'), …, [[6]], 'n')` — `Some(b'?') => _` arm         |
| `ESC [ ? <n> $ p`  | DECRQM mode request    | `Some(b'?')`          | `'p'` | `(Some(b'?'), Some(b'$'), [[n]], 'p')` — `Some(b'?') => _`    |

The `unhandled_csi` signature (callbacks.rs lines 55–63), copy-paste exact:

```rust
fn unhandled_csi(
    &mut self,
    _: &mut crate::Screen,            // mutable Screen, can read cursor here
    _i1: Option<u8>,                  // intermediates[0]  e.g. Some(b'>') or Some(b'?')
    _i2: Option<u8>,                  // intermediates[1]  e.g. Some(b'$')
    _params: &[&[u16]],               // CSI params, each a sub-param list; usually [[n]]
    _c: char,                         // final byte: 'n' / 'c' / 'p' / ...
) {}
```

NOTE: params is `&[&[u16]]` (a slice of sub-param slices). For `ESC[6n` it is `[[6]]`. An
*empty* parameter (bare `ESC[n`, `ESC[c`) arrives as `params == []` (NOT `[[0]]`); only
explicit `0` arrives as `[[0]]`. So read the first param defensively:
`params.first().and_then(|p| p.first()).copied().unwrap_or(0)`.

IMPORTANT borrow detail: `unhandled_csi` receives `&mut crate::Screen` as its first arg —
**use THAT screen to read the cursor** (`screen.cursor_position()`), because inside the
callback you cannot also borrow `parser.screen()`. The callback runs *during* `parser.process`.

### A.3 Where the reply must go

Replies are bytes the terminal sends to the application = write to the PTY master input. The
existing path is `pty.write_input(bytes)` (see `crates/server/src/lib.rs` line 72, used for
client keystrokes). So the plan: collect reply bytes in the `Callbacks` impl during
`emu.process(&bytes)`, then drain them in `run_session` and `pty.write_input` them right after
processing the PTY chunk.

### A.4 Exact reply byte sequences

Cursor is 0-indexed in vt100 (`Screen::cursor_position() -> (row, col)`); the wire report is
**1-indexed**. So `row+1`, `col+1`.

- DSR cursor position (`ESC[6n`)  →  `ESC [ <row+1> ; <col+1> R`
  e.g. cursor at (0,0) → `b"\x1b[1;1R"`.
- DSR status ok (`ESC[5n`)        →  `ESC [ 0 n`  = `b"\x1b[0n"`.
- Primary DA (`ESC[c` / `ESC[0c`) →  `ESC [ ? 6 2 ; 1 ; 6 c` = `b"\x1b[?62;1;6c"`
  (mosh answers as a VT220 with 132-col + selective-erase; matching mosh keeps app behavior
  identical. `?62`=VT220, `1`=132-columns, `6`=selective erase. Acceptable simpler answer:
  `b"\x1b[?6c"` = plain VT102, but prefer the mosh string.)
- Secondary DA (`ESC[>c` / `ESC[>0c`) → `ESC [ > <type> ; <ver> ; 0 c`. mosh answers
  `b"\x1b[>1;10;0c"` (VT220-ish, firmware 10). Any stable triple is fine; match mosh.
- DECRQM (`ESC[?<n>$p`): reply `ESC [ ? <n> ; <status> $ y`. `status`: 0=not recognized,
  1=set, 2=reset, 3=permanently set, 4=permanently reset. **Recommended: answer `0` (not
  recognized) for every mode** unless you wire up real per-mode lookup — vt100 does not expose
  most mode states. e.g. for mode 2004 (bracketed paste): only mode you can answer accurately
  is via `screen.bracketed_paste()`; everything else → `0`. Honest "0" is safe; lying risks
  app misbehavior. If unsure, I recommend implementing only DSR + primary/secondary DA first
  and leaving DECRQM returning `0` or unimplemented.

### A.5 Concrete implementation plan

In `crates/terminal/src/server.rs`, extend the existing `Callbacks` struct to also accumulate
host replies, and implement `unhandled_csi`:

```rust
#[derive(Default)]
struct Callbacks {
    title: String,
    icon: String,
    bell_count: u64,
    /// Bytes the emulator must send back to the application (DSR/DA/DECRQM answers).
    host_replies: Vec<u8>,
}

impl vt100::Callbacks for Callbacks {
    fn set_window_title(&mut self, _: &mut vt100::Screen, t: &[u8]) {
        self.title = String::from_utf8_lossy(t).into_owned();
    }
    fn set_window_icon_name(&mut self, _: &mut vt100::Screen, n: &[u8]) {
        self.icon = String::from_utf8_lossy(n).into_owned();
    }
    fn audible_bell(&mut self, _: &mut vt100::Screen) { self.bell_count += 1; }

    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        i1: Option<u8>,
        i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        let p0 = params.first().and_then(|p| p.first()).copied().unwrap_or(0);
        match (i1, i2, c) {
            // DSR. ESC[6n -> cursor position report (1-indexed). ESC[5n -> status ok.
            (None, _, 'n') => match p0 {
                6 => {
                    let (row, col) = screen.cursor_position(); // 0-indexed
                    self.host_replies
                        .extend_from_slice(format!("\x1b[{};{}R", row + 1, col + 1).as_bytes());
                }
                5 => self.host_replies.extend_from_slice(b"\x1b[0n"),
                _ => {}
            },
            // DECDSR ESC[?6n -> position report bracketed by ?. Some apps use this form.
            (Some(b'?'), _, 'n') if p0 == 6 => {
                let (row, col) = screen.cursor_position();
                self.host_replies
                    .extend_from_slice(format!("\x1b[?{};{}R", row + 1, col + 1).as_bytes());
            }
            // Primary DA: ESC[c / ESC[0c. Answer as VT220 (matches mosh).
            (None, _, 'c') => self.host_replies.extend_from_slice(b"\x1b[?62;1;6c"),
            // Secondary DA: ESC[>c / ESC[>0c.
            (Some(b'>'), _, 'c') => self.host_replies.extend_from_slice(b"\x1b[>1;10;0c"),
            // DECRQM: ESC[?<n>$p -> ESC[?<n>;<status>$y. Default: not recognized (0).
            (Some(b'?'), Some(b'$'), 'p') => {
                let status = match p0 {
                    2004 => if screen.bracketed_paste() { 1 } else { 2 },
                    _ => 0u16, // not recognized; honest and safe
                };
                self.host_replies
                    .extend_from_slice(format!("\x1b[?{};{}$y", p0, status).as_bytes());
            }
            _ => {}
        }
    }
}
```

Then expose a drain on `ServerTerminal`:

```rust
impl ServerTerminal {
    /// Take and clear any pending host replies produced while processing PTY output
    /// (DSR/DA/DECRQM answers). The caller must write these back to the PTY input.
    pub fn take_host_replies(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.parser.callbacks_mut().host_replies)
    }
}
```

Wire it in `crates/server/src/lib.rs` `run_session`, in the `pty_rx.recv()` arm right after
`emu.process(&bytes)`:

```rust
Some(bytes) => {
    emu.process(&bytes);
    let replies = emu.take_host_replies();
    if !replies.is_empty() {
        if let Err(e) = pty.write_input(&replies) {
            warn!(error = %e, "pty write (host reply) failed");
        }
    }
    dirty = true;
}
```

Notes / gotchas:
- `parser.callbacks_mut()` exists (confirmed in vt100-api.md §1). Good.
- The reply must NOT be fed back into `emu.process` — it goes only to the PTY input.
- `vte` is a streaming parser: a query split across two PTY chunks still fires the callback
  once on completion, so accumulating across `process` calls is correct.
- Do not echo replies onto the synced screen; they are invisible host I/O.

### A.6 Test sketch (in `server.rs` `#[cfg(test)]`)

```rust
#[test]
fn answers_cursor_position_report() {
    let mut t = ServerTerminal::new(24, 80, 0);
    t.process(b"\x1b[5;3H");   // move cursor to row 5 col 3 (1-indexed input)
    t.process(b"\x1b[6n");     // DSR
    assert_eq!(t.take_host_replies(), b"\x1b[5;3R"); // 1-indexed report
}
#[test]
fn answers_primary_da() {
    let mut t = ServerTerminal::new(24, 80, 0);
    t.process(b"\x1b[c");
    assert_eq!(t.take_host_replies(), b"\x1b[?62;1;6c");
}
```

---

## B. PREDICTOR ARROWS + WIDE CHARS

### B.1 How the reference engine does it (`moshers-predict/src/engine.rs`)

The reference uses a REAL `vte::Parser` plus a tiny `Perform` collector
(`moshers-predict/src/parser.rs`). Exact `Action` enum and collector:

```rust
// parser.rs
pub enum Action { Print(char), Execute(u8), EscDispatch(u8), CsiDispatch(char) }

#[derive(Default)]
pub struct Collector { pub actions: Vec<Action> }
impl vte::Perform for Collector {
    fn print(&mut self, c: char) { self.actions.push(Action::Print(c)); }
    fn execute(&mut self, byte: u8) { self.actions.push(Action::Execute(byte)); }
    fn esc_dispatch(&mut self, _i: &[u8], _ig: bool, byte: u8) { self.actions.push(Action::EscDispatch(byte)); }
    fn csi_dispatch(&mut self, _p: &vte::Params, _i: &[u8], _ig: bool, action: char) {
        self.actions.push(Action::CsiDispatch(action));
    }
}
```

The engine holds a `vte: vte::Parser` and feeds one byte at a time. `new_user_byte`
(engine.rs 335–355):

```rust
self.cull(screen, now);
// ESC O x  ->  ESC [ x  (so SS3 arrows look like CSI arrows below).
if self.last_byte == 0x1b && the_byte == b'O' { the_byte = b'['; }
self.last_byte = the_byte;
let actions = self.feed(the_byte);          // runs vte.advance, returns Vec<Action>
for act in actions { self.handle_action(act, screen, now); }
```

`feed` special-cases DEL → `Print('\u{7f}')` (mosh routes DEL through Print, vte would
`execute` it):

```rust
fn feed(&mut self, byte: u8) -> Vec<Action> {
    if byte == 0x7f { return vec![Action::Print('\u{7f}')]; }
    let mut c = Collector::default();
    self.vte.advance(&mut c, &[byte]);
    c.actions
}
```

Arrow handling lives in `handle_action` (engine.rs 367–400). The right/left arrows arrive as
`CsiDispatch('C')` / `CsiDispatch('D')`:

```rust
Action::CsiDispatch(ch) => {
    if ch == 'C' {                                     // right arrow
        self.init_cursor(screen);
        let (_h, w) = scr_size(screen);
        let last = self.cursors.last_mut().unwrap();
        if last.base.col < w - 1 {
            last.base.col += 1;
            last.base.expire(self.local_frame_sent + 1, now);
        }
    } else if ch == 'D' {                              // left arrow
        self.init_cursor(screen);
        let last = self.cursors.last_mut().unwrap();
        if last.base.col > 0 {
            last.base.col -= 1;
            last.base.expire(self.local_frame_sent + 1, now);
        }
    } else {
        self.become_tentative();                       // any other CSI: bail
    }
}
Action::Print(ch) => self.handle_print(ch, screen, now),
Action::Execute(b) => { if b == 0x0d { self.become_tentative(); self.newline_carriage_return(...);} else { self.become_tentative(); } }
Action::EscDispatch(_) => self.become_tentative(),
```

KEY: the SS3→CSI normalization (`ESC O` → `ESC [`) means by the time vte sees the final
byte, an app-cursor-mode `ESC O C` has been rewritten to `ESC [ C`, so the SAME
`CsiDispatch('C')` branch handles both `CSI C` and `SS3 C`. Up/down (`A`/`B`) are NOT
predicted (they fall to `become_tentative()` — the engine can't predict vertical movement
content safely; it opens a new epoch and waits for the server). Note the reference predicts
ONLY cursor movement for arrows; it does not move content.

Wide / multibyte chars: `handle_print` (engine.rs 468–473):

```rust
let width1 = UnicodeWidthChar::width(ch) == Some(1);
if (ch as u32) < 0x20 || !width1 {
    // control char inside Print, or wide/zero-width char: bail.
    self.become_tentative();
    return;
}
```

So a wide char (CJK, emoji, width 2) or zero-width/combining char does NOT get a concrete
prediction — it just opens a new epoch (`become_tentative`) and the engine waits for the
server's real echo. Same for multi-byte UTF-8: vte's `print(c: char)` only fires once the
full codepoint is assembled, and then width-2 chars bail. This is the "predict vs.
become-tentative" split: ASCII width-1 → predict; everything else → tentative.

### B.2 What the current engine does (`moshers2/crates/predict/src/lib.rs`)

NO escape parser. `new_user_byte(now, byte, screen)` (lib.rs 246–399) matches raw bytes:

```rust
let mut byte = byte;
if self.last_byte == 0x1b && byte == b'O' { byte = b'['; }   // SS3 normalization (already present!)
self.last_byte = byte;
...
match byte {
    0x20..=0x7e => { /* printable ASCII insert/overwrite prediction */ }
    0x7f | 0x08 => { /* backspace */ }
    0x0d | 0x0a => { self.become_tentative(); self.newline_cr(screen); }
    _ => { self.become_tentative(); }   // <-- ESC, '[', 'C', 'D' all land here today
}
```

Problem: an arrow key `ESC [ C` arrives as THREE separate `new_user_byte` calls: `0x1b`,
`b'['` (0x5b, which IS in 0x20..=0x7e so it would be mis-predicted as a literal "[" glyph!),
`b'C'` (0x43, also in printable range → mis-predicted as literal "C"). So today arrows are
not just unpredicted, they are actively MISpredicted (each byte drawn as a literal char,
later culled). That's the bug to fix.

Crate deps: `crates/predict/Cargo.toml` does NOT depend on `vte`. `vte 0.15.0` IS in
`Cargo.lock` (vt100 pulls it transitively), so `vte = "0.15"` can be added. But the task asks
for arrow prediction over raw bytes WITHOUT a full escape parser — a small hand-rolled state
machine across `new_user_byte` calls is the lighter path and avoids a new dep.

### B.3 Concrete plan — hand-rolled escape-sequence state machine

Add a small escape-tracking state to `PredictionEngine` and consume bytes that are part of an
escape sequence so they are never mis-drawn as glyphs. Recognize exactly the four arrow forms
(after the existing `ESC O`→`ESC [` normalization, only the `ESC [` forms remain to match):

- `ESC [ C` → right, `ESC [ D` → left  (cursor-key / normal mode)
- `ESC O C` → right, `ESC O D` → left  (application-cursor mode) — already normalized to
  `ESC [ C` / `ESC [ D` by the `last_byte == 0x1b && byte == b'O'` rewrite.

Add a field (mirror the existing `last_byte: u8`):

```rust
/// Multi-byte escape-sequence tracker for the raw byte stream. None = not mid-escape.
enum EscState {
    None,
    Esc,        // saw 0x1b
    Csi,        // saw ESC [ (or normalized ESC O)
}
```

Add `esc: EscState` to the struct (init `EscState::None` in `new`). Then at the TOP of
`new_user_byte`, BEFORE the `match byte`, intercept escape bytes. Keep the existing
`ESC O`→`ESC [` normalization (it makes app-cursor `O` look like `[`). Replacement for the
prelude + match:

```rust
pub fn new_user_byte(&mut self, now: u64, byte: u8, screen: &Screen) {
    if self.pref == DisplayPreference::Never { return; }
    self.cull(now, screen);

    let mut byte = byte;
    if self.last_byte == 0x1b && byte == b'O' { byte = b'['; } // SS3 -> CSI normalization
    self.last_byte = byte;

    let (rows, cols) = screen.size();
    if rows == 0 || cols == 0 { return; }

    // --- escape-sequence state machine (runs before the printable/backspace match) ---
    match self.esc {
        EscState::Esc => {
            if byte == b'[' {            // ESC [ ...  (also covers normalized ESC O)
                self.esc = EscState::Csi;
                return;                  // swallow '['; it's not a glyph
            } else {
                // ESC <other>: an escape we don't predict. Open a new epoch, give up on it.
                self.esc = EscState::None;
                self.become_tentative();
                return;
            }
        }
        EscState::Csi => {
            // Final byte of the CSI. Only C/D (right/left arrow, no params) are predicted.
            self.esc = EscState::None;
            match byte {
                b'C' => { self.predict_arrow_right(now, screen); return; }
                b'D' => { self.predict_arrow_left(now, screen); return; }
                // A/B (up/down), H/F (home/end), digits/';' (parameterized), etc.: bail.
                // NOTE: a parameterized arrow like ESC[1;5C (ctrl-right) lands here on the
                // intermediate digit and bails — acceptable (we just don't speed it up).
                _ => { self.become_tentative(); return; }
            }
        }
        EscState::None => {}
    }
    if byte == 0x1b {                    // start of an escape sequence
        self.esc = EscState::Esc;
        return;                          // swallow ESC; never a glyph
    }

    match byte {
        0x20..=0x7e => { /* ... unchanged printable path ... */ }
        0x7f | 0x08 => { /* ... unchanged backspace path ... */ }
        0x0d | 0x0a => { self.become_tentative(); self.newline_cr(screen); }
        _ => { self.become_tentative(); }   // other control / non-ASCII (wide/emoji) lead byte
    }
}
```

The two arrow helpers (port of reference `CsiDispatch('C'/'D')`, using existing `init_cursor`
and the `PredCursor { expiration_frame, tentative_epoch, row, col }` field set):

```rust
fn predict_arrow_right(&mut self, now: u64, screen: &Screen) {
    let _ = now;
    self.init_cursor(screen);
    let (_, cols) = screen.size();
    if let Some(c) = self.cursor.as_mut() {
        if c.col + 1 < cols {
            c.col += 1;
            c.expiration_frame = self.local_frame_sent + 1;
        }
    }
}
fn predict_arrow_left(&mut self, now: u64, screen: &Screen) {
    let _ = now;
    self.init_cursor(screen);
    if let Some(c) = self.cursor.as_mut() {
        if c.col > 0 {
            c.col -= 1;
            c.expiration_frame = self.local_frame_sent + 1;
        }
    }
}
```

(`now` is unused here because the current engine stamps `prediction_time` only on cell preds,
not cursor preds — the current `PredCursor` has no `prediction_time` field, unlike the
reference `Base`. Keep parity with the current struct; do not add a time field unless you also
update `cursor_validity`.)

Epoch handling — matches the reference exactly:
- Arrows do NOT call `become_tentative()`. They reuse the current epoch so a confirmed-epoch
  cursor move is shown immediately, just like typed chars. `init_cursor` already carries the
  cursor forward into the current epoch and reseeds from the real cursor on epoch change.
- Cursor-only predictions confirm via the existing `cursor_validity` (cull, lib.rs 636–651):
  once `late_acked >= expiration_frame`, it compares predicted `(row,col)` to
  `screen.cursor_position()` → `Correct` (clears) or `IncorrectOrExpired` (full `reset`).
- An arrow at the screen edge (`col+1 >= cols` or `col == 0`) is a no-op (clamped), same as
  the reference (`< w - 1` / `> 0` guards). No epoch bump.

### B.4 Wide / multibyte chars in the current engine

The current `_ =>` arm of the byte match already does `become_tentative()` for any non-ASCII
lead byte (≥ 0x80) and control chars — which is the desired "don't predict, wait for server"
behavior for wide/emoji/multibyte input. That is ALREADY correct and matches the reference's
`!width1 -> become_tentative` policy. The only nuance: the reference reaches that decision
after assembling the full `char` and checking `UnicodeWidthChar::width(ch) == Some(1)`,
whereas the current engine bails on the first non-ASCII byte. Both outcomes are identical
(non-ASCII → tentative → server echo wins), so **no change is needed for wide chars** beyond
ensuring multi-byte UTF-8 lead/continuation bytes (0x80..=0xff) all hit the `_ =>` tentative
arm — which they do. The module doc comment (lib.rs 12–17) already states this is the intended
scope. Optionally tighten by noting it in the comment; functionally it's done.

If you later want to ALSO predict precomposed width-1 non-ASCII (e.g. "é" as one codepoint),
you'd need UTF-8 reassembly + `UnicodeWidthChar::width` — that's a bigger change and out of
scope; the reference itself bails on anything not width-1, and "é" via combining marks is
multi-codepoint anyway. Leave as tentative.

### B.5 Test sketch (`crates/predict/src/lib.rs` tests)

```rust
#[test]
fn right_arrow_moves_cursor_prediction() {
    let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
    e.set_local_frame_sent(1);
    // server echoed "x", real cursor at (0,1). Right arrow over the edge of typed text...
    // type a char first so there is room, then arrow back/forth. Simplest: arrow LEFT.
    for &b in b"\x1b[D" { e.new_user_byte(300, b, &echoed); } // ESC [ D
    let ov = e.overlay(&echoed);
    assert_eq!(ov.cursor(), Some((0, 0)), "left arrow predicts cursor one col left");
    assert!(ov.cell(0, 0).is_none() && ov.cell(0, 1).is_none(),
            "arrow keys must not leave literal '[' or 'D' glyphs");
}
#[test]
fn ss3_left_arrow_normalized() {
    let (mut e, echoed) = confirm_first_keystroke(DisplayPreference::Always, 250.0);
    e.set_local_frame_sent(1);
    for &b in b"\x1bOD" { e.new_user_byte(300, b, &echoed); } // ESC O D (app cursor mode)
    assert_eq!(e.overlay(&echoed).cursor(), Some((0, 0)));
}
```

(Adjust the confirmed-epoch fixture so the cursor pred is visible; `confirm_first_keystroke`
already advances `confirmed_epoch` to 1, and `init_cursor` stamps `prediction_epoch`. If the
cursor pred ends up tentative, type one confirmed char before the arrow.)

---

## C. EXIT STATUS PROPAGATION

### C.1 Reference repo does NOT propagate exit codes either

Grepped `moshers-server`, `moshers-client`, `moshers-ssp`, `moshers-pty` for
`exit_code`/`exit_status`/`ExitStatus`/`process::exit`/`.code()`/`.wait()`. The ONLY hits are
SSP shutdown bookkeeping: `OutgoingResult.shutdown_acked: bool`, `start_shutdown`,
`shutdown_done`, `SHUTDOWN_RETRIES`. The reference `moshers-ssp/src/wire.rs` `Instruction`
has fields `protocol_version, old_seq, new_seq, ack, throwaway, diff` — **no exit field**.
`moshers-server/main.rs` logs `"shell exited"` then `pty.kill()` and returns; the client just
ends. So **exit-code propagation is a parity gap in BOTH repos** (mosh-server does send the
exit status in its `ServerMessage`/disconnect; neither Rust port replicates it). You are
adding new behavior.

### C.2 Current moshers2 mechanism

- `crates/server/src/lib.rs run_session`: the shell-exit signal is `pty_rx.recv()` returning
  `None` (reader EOF) → sets `child_alive = false` (line 56). Then (lines 106–108) it calls
  `transport.start_shutdown(now)`, which makes outgoing instructions carry
  `new_num = SHUTDOWN_SENTINEL` (= `u64::MAX`, ssp/lib.rs:40). It NEVER calls `pty.wait()` —
  the actual `ExitStatus` is discarded. `pty.kill()` at the end.
- `crates/client/src/lib.rs run_client`: detects `transport.remote_num() == SHUTDOWN_SENTINEL`
  (line 183), paints "[rmosh] session ended", sleeps 400ms, breaks, returns `Ok(())`.
- `crates/client/src/main.rs`: `async fn main() -> anyhow::Result<()>`; returns `result` from
  `run_client` (line 210/214). So the process exits 0 on success, 1 on `Err` — it can NEVER
  reflect the remote shell's exit code.

`portable_pty::ExitStatus` (confirmed in the installed source) exposes:
```rust
pub fn exit_code(&self) -> u32;   // NOT Option, NOT i32
pub fn success(&self) -> bool;    // false if killed by signal
```
NOTE: `signal` info is collapsed (`with_signal` sets `code = 1`); you only get a `u32`. The
`rmosh-pty::Pty` wrapper re-exposes `wait(&mut self) -> io::Result<ExitStatus>` and
`try_wait(&mut self) -> io::Result<Option<ExitStatus>>` (crates/pty/src/lib.rs 113–120).

### C.3 Proposed mechanism — carry the exit code in the shutdown path

Two viable carriers. **Recommended: a field on `ScreenDiff`** (the existing
`HostMessage`-style diff in `crates/terminal/src/lib.rs`), populated only on the final
shutdown snapshot. This rides the existing SSP reliability (retransmits until acked), so the
code survives loss — exactly what mosh does (the exit status is part of the last reliable
state). A side-band datagram would not be retransmitted and could be lost.

#### C.3.1 Server: capture the real exit code

In `run_session`, when the child exits, call `pty.wait()` to reap the real status BEFORE
shutdown. The reader EOF (`child_alive = false`) is the trigger; `wait()` will return promptly
since the child is already gone.

```rust
// add near top of run_session:
let mut exit_code: Option<u32> = None;
...
Some(bytes) => { emu.process(&bytes); /* + host replies from item A */ dirty = true; }
None => {
    child_alive = false;                    // shell exited; reader hit EOF
    // Reap the real status (child already exited, so this returns promptly).
    exit_code = Some(pty.wait().map(|s| s.exit_code()).unwrap_or(1));
}
...
if !child_alive && !transport.shutdown_in_progress() {
    if let Some(code) = exit_code {
        emu.set_exit_code(code);            // stamp the snapshot (see below)
        *transport.current_mut() = emu.snapshot();  // re-snapshot so the diff carries it
    }
    transport.start_shutdown(now);
}
```

Plumb the code through `ServerTerminal` → `TerminalScreen` → `ScreenDiff`:

- `crates/terminal/src/server.rs`: add `exit_code: Option<u32>` to `ServerTerminal`, a setter
  `pub fn set_exit_code(&mut self, c: u32) { self.exit_code = Some(c); }`, and include it in
  `snapshot()`: `TerminalScreen { ..., exit_code: self.exit_code }`.
- `crates/terminal/src/lib.rs`:
  - add `exit_code: Option<u32>` to `TerminalScreen` (and to `Clone`, `Default` = `None`,
    `from_bytes` = `None`, the `Debug` impl, and the `snapshot` constructor in server.rs).
  - add `pub fn exit_code(&self) -> Option<u32> { self.exit_code }`.
  - add `pub exit_code: Option<u32>` to `ScreenDiff`.
  - in `SyncState::diff_from`: `exit_code: (self.exit_code != base.exit_code).then_some(self.exit_code).flatten()`
    — i.e. carry it when it changed. Simpler/robust: always `exit_code: self.exit_code` (it's
    8 bytes, negligible; postcard `Option<u32>` is 1–5 bytes).
  - in `SyncState::apply`: `if diff.exit_code.is_some() { self.exit_code = diff.exit_code; }`.
  - in `PartialEq`: include `&& self.exit_code == other.exit_code` (so a state that newly
    carries the code is not collapsed away as "equal").

#### C.3.2 Client: read the code and exit with it

In `crates/client/src/lib.rs run_client`, change the return type to surface the code, and read
it at the SHUTDOWN_SENTINEL break:

```rust
// return Result<Option<u32>> (None = clean local quit / no remote code)
pub async fn run_client<T: ClientTerminal>(...) -> anyhow::Result<Option<u32>> {
    ...
    if transport.remote_num() == SHUTDOWN_SENTINEL {
        let code = transport.remote_state().exit_code();   // Option<u32>
        let screen = transport.remote_state().screen();
        let _ = term.render(screen, &Overlay::empty(), Some("[rmosh] session ended"));
        tokio::time::sleep(Duration::from_millis(400)).await;
        channel.close(0, b"client exit");
        return Ok(code);
    }
    ...
    // other break paths (input closed, peer error, Ctrl-^ .): return Ok(None)
    channel.close(0, b"client exit");
    Ok(None)
}
```

In `crates/client/src/main.rs`, switch `main` to return `std::process::ExitCode` (or call
`std::process::exit`). `anyhow::Result<()>` can only yield 0/1, so it cannot carry the shell
code. Pattern:

```rust
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match real_main().await {
        Ok(Some(code)) => ExitCode::from(code as u8),  // u32 -> u8 (POSIX wait status is 8-bit)
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => { eprintln!("error: {e:#}"); ExitCode::FAILURE }
    }
}

// move the existing body into:
async fn real_main() -> anyhow::Result<Option<u32>> {
    ...
    let result = run_client(channel, args.predict.into(), rows, cols, input_rx, resize_rx, term).await;
    drop(_guard);
    endpoint.close().await;
    result
}
```

CAVEAT on `code as u8`: POSIX exit statuses are 8-bit, and `portable_pty::ExitStatus`
collapses signal deaths to `code = 1`. So `ExitCode::from(code as u8)` is correct for normal
exits (0–255). If you want signal fidelity you'd need to extend the wire type to carry the
signal too — out of scope; mosh itself reports just the integer status.

#### C.3.3 Alternative carrier (if you don't want to touch ScreenDiff)

Add `exit_code: Option<u32>` directly to `wire::Instruction` (crates/wire/src/lib.rs) and set
it on the shutdown instruction. Downside: the SSP `Transport` builds `Instruction`s
internally (transport.rs lines ~413/436 set `new_num = SHUTDOWN_SENTINEL`); you'd thread the
code through `start_shutdown`/`tick`. More invasive than the `ScreenDiff` field, which the
state-sync machinery already serializes and retransmits for free. **Prefer the ScreenDiff
field (C.3.1/.2).**

### C.4 Edge cases / notes

- Loss resilience: because the code rides the SHUTDOWN_SENTINEL state, the SSP layer
  retransmits until the client acks (or the server's shutdown-ack timeout fires,
  `shutdown_ack_timed_out`). If the client times out without ever receiving the sentinel
  state, it returns `Ok(None)` → exit 0. Acceptable; mosh degrades similarly on a dead link.
- `pty.wait()` after EOF: the child is already gone so it won't block; still, wrap with
  `unwrap_or(1)` so a reaping error doesn't panic the session.
- Do NOT call `pty.wait()` while `child_alive` — only in the EOF (`None`) arm.
- The existing `pty.kill()` at the end of `run_session` is still fine (no-op if already
  reaped).
- Tests: `crates/client/tests/` has `mock_session.rs`-style harnesses; assert that a server
  snapshot stamped with `exit_code = 42` and shipped to SHUTDOWN_SENTINEL makes
  `run_client` return `Ok(Some(42))`.
