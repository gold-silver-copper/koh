# Porting notes: prediction / local-echo engine

Targets:
- Reference (correct): `/Users/kisaczka/Desktop/code/moshers/crates/moshers-predict/src/engine.rs` (+ `parser.rs`, `rend.rs`, `lib.rs`).
- Current (to fix): `/Users/kisaczka/Desktop/code/moshers2/crates/predict/src/lib.rs` (single file; no `parser`/`rend`/`engine` split).

Quick orientation on the two data models:
- Reference stores predictions as **dense per-row `OverlayCell` vectors** (`OverlayRow { row_num, overlay_cells: Vec<OverlayCell> }`, one cell slot per column, allocated in `get_or_make_row`). Each `OverlayCell` carries a `Base` (lifecycle/epoch state), a `replacement: PredictionCell`, an `unknown: bool` flag, and `original_contents: Vec<PredictionCell>` history. This density is what makes row-shifting (insert/backspace) and the "match the rest of the row's rendition" loop possible.
- Current stores predictions as a **sparse `BTreeMap<(u16,u16), PredCell>`** plus a single `Option<PredCursor>`. There is no per-row vector, no `unknown` flag, and `original` is a single `String`, not a history `Vec`. This sparse model is the root cause of items 2 and 3 below (can't shift a row you don't fully hold), and it complicates item 1 because epochs are tracked per-cell only.

---

## 1. THE EPOCH MODEL (P0 security fix — password / no-echo leak)

### 1a. What the reference does and WHY it is correct

Initial epoch values (`engine.rs`, `PredictionEngine::new`, lines 218-239):

```rust
prediction_epoch: 1,
confirmed_epoch: 0,
```

The gate is `Base::tentative` (lines 81-83):

```rust
fn tentative(&self, confirmed_epoch: u64) -> bool {
    self.tentative_until_epoch > confirmed_epoch
}
```

Every new prediction stamps its `tentative_until_epoch` (and cursor `tentative_until_epoch`) with the **current `prediction_epoch`**. Concretely, in `handle_print` for a normal printable (lines 535) and the inserted-cell loop (line 501): `cell.base.tentative_until_epoch = epoch;` where `epoch = self.prediction_epoch` (line 407). New cursors are seeded with `self.prediction_epoch` in `init_cursor` (lines 287, 293) and `kill_epoch` (line 733). New overlay cells are created with `self.prediction_epoch` in `get_or_make_row` (line 306).

The draw gate in `overlay` is two checks (lines 766, 778):

```rust
// cursor:
if cm.base.active && !cm.base.tentative(self.confirmed_epoch) && cm.row < h && cm.base.col < w {
    ov.cursor = Some(...);
}
// cells:
if cell.base.tentative(self.confirmed_epoch) {
    continue;
}
```

So a cell/cursor is drawn **only if** `tentative_until_epoch <= confirmed_epoch`.

The crux: at startup `prediction_epoch == 1` and `confirmed_epoch == 0`. Every freshly-typed prediction gets `tentative_until_epoch = 1`. The gate `1 > 0` ⇒ `tentative()` is true ⇒ **nothing is drawn**. Predictions only become visible after `confirmed_epoch` is advanced to ≥ the epoch they were stamped with, which happens **only** when the server actually echoes a typed char.

`confirmed_epoch` advances **only** on a `Validity::Correct` validation in `cull` (lines 614-621):

```rust
Validity::Correct => {
    let (tue, ptime) = {
        let cell = &self.overlays[ri].overlay_cells[ci];
        (cell.base.tentative_until_epoch, cell.base.prediction_time)
    };
    if tue > self.confirmed_epoch {
        self.confirmed_epoch = tue;   // <-- the ONLY place confirmed_epoch advances
    }
    ...
}
```

`Validity::Correct` is returned by `cell_validity` (lines 696-703) only when the predicted glyph **matches the server's actual cell**, the cell is non-blank (line 691: blank ⇒ `CorrectNoCredit`), not `unknown` (line 688), past its `expiration_frame` (line 685: else `Pending`), and the match is **not** explainable by the cell's prior contents (`matched_history` ⇒ `CorrectNoCredit`, lines 698-700). I.e. the server must have demonstrably echoed something the prediction caused.

`become_tentative` (lines 265-269) bumps the epoch wall so all *subsequent* predictions are stamped one epoch higher (and thus hidden again until that epoch is confirmed):

```rust
fn become_tentative(&mut self) {
    if self.display_preference != DisplayPreference::Experimental {
        self.prediction_epoch += 1;
    }
}
```

Exactly where `become_tentative` is called (every risky/ambiguous action):
- `handle_action`: `Execute(0x0d)` CR before `newline_carriage_return` (line 372); any other `Execute` (line 375); every `EscDispatch` (line 378); any `CsiDispatch` other than `C`/`D` (line 396).
- `handle_print`: a control char inside Print or a non-width-1 (wide/zero-width) char (line 471); when about to write into the last column (`col + 1 >= w`, line 482); when the cursor wraps off the right edge before `newline_carriage_return` (line 551).
- `reset` (line 274) and `kill_epoch` (line 743) both call it after tearing down predictions, so the next predictions are gated again.

WHY correct: a brand-new connection has confirmed nothing. The very first keystrokes (e.g. into a password prompt the server never echoes) are stamped epoch 1, gate `1 > 0` keeps them invisible, and `cull` never sees a `Correct` (the server screen stays blank → `cell_validity` hits `is_blank` ⇒ `CorrectNoCredit`, or a non-blank mismatch ⇒ `IncorrectOrExpired` → reset). `confirmed_epoch` stays 0. **Nothing is ever drawn.** Only after the server proves it echoes (one `Correct`) does `confirmed_epoch` reach 1 and ordinary typing in epoch 1 start showing.

### 1b. Trace: typing a secret the server never echoes (reference)

1. `new()` ⇒ `prediction_epoch=1`, `confirmed_epoch=0`.
2. Type `s` ⇒ `new_user_byte` → `cull` (no-op, nothing pending) → `handle_print('s')`. Cell `(0,0)` created with `tentative_until_epoch = prediction_epoch = 1`, `replacement = "s"`, `expiration_frame = local_frame_sent+1`. Cursor stamped epoch 1.
3. `overlay()`: gate `tentative(0)` = `1 > 0` = true ⇒ cell skipped, cursor skipped ⇒ `ov.cells.is_empty()`, `ov.cursor.is_none()`. **Drawn: nothing.** (This is exactly the test `predictions_hidden_until_server_confirms_echo`, lines 822-836, which uses `DisplayPreference::Always` to prove it is the *epoch* gate, not the SRTT gate, doing the suppression.)
4. Continue typing `e`, `c`, `r`, `e`, `t`: all stamped epoch 1, all hidden.
5. Server frame arrives still blank, echo-ack reaches the cells' expiration frame ⇒ `cull` grades each cell `CorrectNoCredit` (server cell blank → `is_blank` on the server side / `cell.replacement.is_blank()` path) or, if the server shows a *different* non-blank char, `IncorrectOrExpired` → since the cell is **not tentative-relative-to-confirmed only when confirmed advanced**, it goes through the reset branch (line 610) and trusts the server. `confirmed_epoch` never advances past 0. The secret never appears.

Contrast: `confirmed_echo_makes_subsequent_typing_visible` (lines 838-859) — type `x` (epoch 1, hidden), server echoes `x` and `late_acked` reaches frame 1, then typing `y` first culls → grades `x` `Correct` → `confirmed_epoch = 1`; the new `y` is also stamped epoch 1; gate `1 > 1` = false ⇒ `y` is now shown.

### 1c. What the current crate does — the DEFECT

Initial values (`lib.rs`, `PredictionEngine::new`, lines 142-143):

```rust
prediction_epoch: 0,
confirmed_epoch: 0,
```

The gate (`lib.rs`, lines 176-178):

```rust
fn tentative(&self, epoch: u64) -> bool {
    epoch > self.confirmed_epoch
}
```

`become_tentative` (lines 172-174):

```rust
fn become_tentative(&mut self) {
    self.prediction_epoch += 1;
}
```

Defect: at startup **both** epochs are 0. The first printable byte path (`new_user_byte`, lines 238-274) stamps the new `PredCell` and cursor with `tentative_epoch: self.prediction_epoch` = **0**. In `overlay` (lines 443-461) the gate is `self.tentative(cell.tentative_epoch)` = `tentative(0)` = `0 > 0` = **false** ⇒ the cell is **NOT** hidden. It is drawn on the very first keystroke, before any server confirmation. With `DisplayPreference::Always` (or `Adaptive` on a slow link where `srtt_trigger` is set), the first run of typed characters renders immediately. **Typing a secret into a non-echoing password prompt leaks it to the local display.** The current test `mispredict_is_reconciled_away` (lines 592-609) only checks that the prediction is *removed after a cull*; it does NOT check that the prediction was *hidden before* the cull — so the leak passes the existing suite. The comment at lines 139-141 ("keep prediction_epoch == confirmed_epoch during ordinary typing so the current epoch's predictions show immediately") is precisely the wrong policy: it documents the bug.

### 1d. Precise change for the current `lib.rs`

(1) Fix the init in `PredictionEngine::new` (lines 142-143). Change:

```rust
prediction_epoch: 0,
confirmed_epoch: 0,
```

to:

```rust
prediction_epoch: 1,
confirmed_epoch: 0,
```

and delete/replace the misleading comment at lines 139-141.

(2) Add `confirmed_epoch` advancement on `Validity::Correct` in `cull`. Currently the `Correct` arm (lines 371-384) updates `max_confirm` from `cell.tentative_epoch` and then `self.confirmed_epoch = max_confirm` at line 404 — **this part is actually present and correct**, so once init is fixed, confirmation will advance. Verify the chain: `cull` computes `let confirmed = self.confirmed_epoch;` (line 350) → `max_confirm` starts at `confirmed` → `Correct` raises it (lines 372-374) → `self.confirmed_epoch = max_confirm;` (line 404). Good. The single one-line init change is the load-bearing fix for the leak.

(3) Confirm the cursor is also gated. `overlay` lines 457-461 already gate the cursor via `if !self.tentative(c.tentative_epoch)`. With init fixed, the first cursor (stamped epoch 1) is hidden too. Good.

(4) Add a regression test mirroring the reference (the existing suite does NOT catch the leak):

```rust
#[test]
fn predictions_hidden_until_server_confirms_echo() {
    let mut e = PredictionEngine::new(DisplayPreference::Always);
    e.set_local_frame_sent(0);
    let blank = screen_of(b"");
    for &b in b"secret" {
        e.new_user_byte(100, b, &blank);
    }
    let ov = e.overlay(&blank);
    assert!(ov.is_empty(), "predictions must stay hidden until the server confirms it echoes");
}
```

Note on a subtle interaction after the fix: with `prediction_epoch=1`, any later `become_tentative()` makes `prediction_epoch=2`, etc. Predictions stamped at epoch N are shown once `confirmed_epoch >= N`. The current `cull` already raises `confirmed_epoch` to the max confirmed cell epoch, so a confirmed CR/escape-following keystroke will un-hide the next batch. No off-by-one beyond the init: `tentative()` uses strict `>`, so epoch == confirmed shows (correct), epoch == confirmed+1 hides (correct).

---

## 2. INSERT-MODE prediction with row cell-shifting (P2)

### 2a. What the reference does and WHY

The reference predicts an inserted mid-line char by **shifting the whole row right** from the right edge down to `col+1`, copying each source cell's predicted-or-real content into the next column, then writing the typed char at `col`. From `handle_print` (lines 485-519):

```rust
// insert: shift cells right from rightmost down to col+1
let rightmost = if self.predict_overwrite { col } else { w - 1 };
for i in ((col + 1)..=rightmost).rev() {
    let i = i as usize;
    let orig = scr_cell(screen, row, i as i32);
    let neighbor = {
        let prev = &self.overlays[idx].overlay_cells[i - 1];
        if prev.base.active {
            Some((prev.unknown, prev.replacement.clone()))
        } else {
            Some((false, scr_cell(screen, row, (i - 1) as i32)))
        }
    };
    let cell = &mut self.overlays[idx].overlay_cells[i];
    cell.reset_with_orig();
    cell.base.active = true;
    cell.base.tentative_until_epoch = epoch;
    cell.base.expire(exp, now);
    cell.original_contents.push(orig);
    if i == (w as usize) - 1 {
        cell.unknown = true;                 // rightmost: what falls off is unknown
    } else {
        match neighbor {
            Some((unknown, repl)) => {
                if unknown { cell.unknown = true; }
                else { cell.unknown = false; cell.replacement = repl; }
            }
            None => cell.unknown = true,
        }
    }
}
```

Key points:
- `rightmost = if self.predict_overwrite { col } else { w - 1 }`. In **insert** mode (`predict_overwrite == false`) the loop runs from `w-1` down to `col+1`. In overwrite mode `rightmost == col`, so the range `(col+1)..=col` is empty and **no shift happens** — only the single cell at `col` is written below.
- Each shifted cell at `i` takes the **predicted** content of `i-1` if `i-1` has an active prediction (`prev.replacement`), otherwise the **real screen** content of `i-1` (`scr_cell(screen, row, i-1)`). This composes a chain of inserts correctly.
- The very last column (`i == w-1`) is marked `unknown` (its prior content is pushed off the right edge — the result is uncertain). See item 3.
- After the shift, the typed char is written at `col` (lines 522-540), inheriting the rendition of the predicted/real left neighbor (lines 522-530).

WHY correct: in a shell line editor (readline insert mode), typing mid-line pushes the tail of the line one column right. Shifting the row models this so the prediction matches what the server will actually render, instead of clobbering one char.

### 2b. What the current crate does — the DEFECT

The current printable path (`lib.rs`, lines 238-274) only writes a **single** cell at `(row, col)`:

```rust
0x20..=0x7e => {
    self.init_cursor(screen);
    let col = self.cursor.as_ref().unwrap().col;
    if col + 1 >= cols { self.become_tentative(); self.init_cursor(screen); }
    let (row, col) = { let c = self.cursor.as_ref().unwrap(); (c.row, c.col) };
    let original = cell_glyph(screen, row, col);
    let (fg, bg) = glyph_style(screen, row, col);
    self.cells.insert((row, col), PredCell { ... glyph: (byte as char).to_string(), ... original });
    if let Some(c) = self.cursor.as_mut() { ... c.col += 1; ... }
}
```

There is no shift loop; `self.cells.insert((row, col), ...)` overwrites exactly one cell. Mid-line insert is mispredicted (the trailing characters are not moved). The module doc (lines 12-17) admits it "predicts in overwrite mode" — so this is a known scoping gap, and item 2 is to close it.

### 2c. Precise change

This requires a per-row dense representation to shift; the sparse `BTreeMap` cannot cheaply "shift the row." The minimal faithful port is to restructure `cells` toward the reference's `Vec<OverlayCell>` per row (recommended), or to emulate a shift over the `BTreeMap` for the affected row. Add a `predict_overwrite: bool` field to `PredictionEngine` (default `false` for insert mode; the reference defaults `predict_overwrite: false`, `engine.rs` line 236).

Emulation over the existing `BTreeMap` (smallest diff), inside the `0x20..=0x7e` arm, replacing the single `insert` with a shift + write. Add helper that reads the predicted-or-real glyph for a cell:

```rust
// helper on PredictionEngine
fn pred_or_real_glyph(&self, screen: &Screen, row: u16, col: u16) -> (String, Color, Color, bool /*unknown*/) {
    if let Some(p) = self.cells.get(&(row, col)) {
        (p.glyph.clone(), p.fg, p.bg, p.unknown)   // requires `unknown` field — see item 3
    } else {
        let g = cell_glyph(screen, row, col);
        let (fg, bg) = glyph_style(screen, row, col);
        (g, fg, bg, false)
    }
}
```

In the printable arm, after computing `(row, col)` and BEFORE inserting the typed char:

```rust
if !self.predict_overwrite {
    // shift the row right from cols-1 down to col+1
    for i in ((col + 1)..cols).rev() {
        let (g, fg, bg, src_unknown) = self.pred_or_real_glyph(screen, row, i - 1);
        let original = cell_glyph(screen, row, i);
        let unknown = (i == cols - 1) || src_unknown;
        self.cells.insert((row, i), PredCell {
            expiration_frame: self.local_frame_sent + 1,
            tentative_epoch: self.prediction_epoch,
            prediction_time: now,
            glyph: if unknown { String::new() } else { g },
            fg, bg,
            original,
            unknown,
        });
    }
}
// then the existing single-cell write of the typed char at (row, col)
```

Note: `((col+1)..cols).rev()` must iterate **right-to-left** so each `i` reads `i-1`'s pre-shift state. Because `pred_or_real_glyph` reads `self.cells` which we mutate as we go, descending order guarantees `i-1` is still the original (we only wrote columns `> i` so far). This matches the reference's `.rev()` (line 487). The `unknown` flag and `String::new()` glyph for the rightmost/unknown cell depend on item 3.

---

## 3. UNKNOWN / UNDERLINE uncertain-cell concept (P2)

### 3a. What the reference does and WHY

An `OverlayCell` has `unknown: bool` (`engine.rs`, line 104). `unknown == true` means "we know **something** changed at this cell, but not **what**" — typically because content was shifted in from off-screen, or content fell off the right edge, or a tail was deleted at the row's right boundary.

Validity: an `unknown` cell can never be graded `Correct` (no credit / never confirms an epoch). From `cell_validity` (lines 688-690):

```rust
if cell.unknown {
    return Validity::CorrectNoCredit;
}
```

Render: an `unknown` cell is **never** drawn as text. Instead, when flagging is on and it's not the rightmost column, it is drawn as an **underline-only hint** (empty grapheme, default rend, `underline: true`, `unknown: true`). From `overlay` (lines 785-797):

```rust
if cell.unknown {
    if flag && cell.base.col != w - 1 {
        ov.cells.push(OverlayCellOut {
            row: row.row_num as u16,
            col: cell.base.col as u16,
            grapheme: String::new(),   // don't overwrite the real cell, only hint
            rend: Rend::default(),
            underline: true,
            unknown: true,
        });
    }
    continue;   // never push a text cell for an unknown
}
```

The `OverlayCellOut` contract (lines 145-153) documents it: `grapheme` is "empty when `unknown` (don't overwrite, only hint)". The renderer underlines the existing real glyph rather than replacing it.

**Backspace mid-line uses `unknown` instead of blanking one cell.** In insert mode, `handle_print('\u{7f}')` shifts the row **left** from `col` to the right edge, and the right edge becomes `unknown` because the cell that scrolled in from beyond the right margin is unknowable (lines 431-463):

```rust
} else {
    // shift the row left from cursor.col to the right edge
    for i in (col as usize)..(w as usize) {
        let orig = scr_cell(screen, row, i as i32);
        let neighbor = if i + 2 < w as usize {
            let n = &self.overlays[idx].overlay_cells[i + 1];
            if n.base.active {
                Some((n.unknown, n.replacement.clone()))
            } else {
                Some((false, scr_cell(screen, row, (i + 1) as i32)))
            }
        } else {
            None // near right edge: unknown post-shift content
        };
        let cell = &mut self.overlays[idx].overlay_cells[i];
        cell.reset_with_orig();
        cell.base.active = true;
        cell.base.tentative_until_epoch = epoch;
        cell.base.expire(exp, now);
        cell.original_contents.push(orig);
        match neighbor {
            Some((unknown, repl)) => {
                if unknown { cell.unknown = true; }
                else { cell.unknown = false; cell.replacement = repl; }
            }
            None => cell.unknown = true,   // <-- right edge is uncertain
        }
    }
}
```

(Contrast: the **overwrite** backspace branch, lines 420-430, just blanks the single cell at `col` with a space — that is what the current crate does for *all* backspaces.)

WHY correct: when you backspace mid-line, the tail shifts left by one and one column at the far right becomes whatever was off-screen (unknown). Marking it `unknown` and only underlining (never overwriting with a guessed glyph) avoids painting a wrong character; the underline signals "pending change here" on flaky links, and the cell can never falsely confirm an epoch (`CorrectNoCredit`), preserving the security property in item 1.

`original_contents` is a **Vec** (history) precisely so a cell that has been shifted/rewritten multiple times can check `matched_history` (lines 698-700) — if the final predicted glyph equals any prior content, grade `CorrectNoCredit` (no false confirm). The reference's `reset_with_orig` (lines 118-126) pushes the prior `replacement` onto `original_contents` and resets the base **without** clearing `unknown`/`original_contents`, so the history survives across rewrites.

### 3b. What the current crate does — the DEFECT

- No `unknown` concept at all. `PredCell` (lines 84-94) has no `unknown` field; `original` is a single `String`, not a history `Vec`.
- Backspace (lines 275-303) handles `0x7f | 0x08` by stepping the cursor back one and writing a **single** blanked cell `glyph: " "`:

```rust
0x7f | 0x08 => {
    self.init_cursor(screen);
    let (row, col, do_pred) = { ... if c.col > 0 { c.col -= 1; ... (c.row, c.col, true) } else { (..., false) } };
    if do_pred {
        let original = cell_glyph(screen, row, col);
        self.cells.insert((row, col), PredCell { ... glyph: " ".to_string(), ... original });
    }
}
```

This is correct only for end-of-line / overwrite backspace. Mid-line backspace should shift the tail left and mark the right edge uncertain; instead it blanks one cell, mispredicting the line.
- Render (`overlay`, lines 443-461) always pushes a text `PredictedCell` for every non-tentative cell; there is no underline-only "hint" path.

### 3c. Precise change

(1) Add `unknown` to `PredCell` and make `original` a history (`lib.rs`, struct at lines 84-94):

```rust
#[derive(Clone)]
struct PredCell {
    expiration_frame: u64,
    tentative_epoch: u64,
    prediction_time: u64,
    glyph: String,
    fg: Color,
    bg: Color,
    /// History of prior contents at this cell so a rewrite that lands back on an
    /// earlier value grades "no credit" (cannot falsely confirm an epoch).
    original_contents: Vec<String>,
    /// "Something changed here, not sure what" — never drawn as text; underline-only hint.
    unknown: bool,
}
```

Update all `PredCell { ... }` constructors (printable arm lines 254-264, backspace arm lines 290-301) to set `original_contents: vec![original]` (or `Vec::new()` then push) and `unknown: false`.

(2) Add an `unknown`/underline path to the render-facing types. Extend `PredictedCell` (lines 48-55):

```rust
#[derive(Clone, Debug)]
pub struct PredictedCell {
    pub glyph: String,   // empty when `unknown`: do not overwrite, only hint
    pub fg: Color,
    pub bg: Color,
    pub underline: bool,
    pub unknown: bool,
}
```

(3) In `overlay` (lines 443-456), branch on `unknown`, mirroring reference lines 785-805. You need the live screen for the rightmost-column / blank checks — note `overlay` currently ignores `_screen` (line 433); take `screen: &Screen` and compute `(_, cols)` from `screen.size()`:

```rust
let (_, cols) = _screen.size();
let flag = self.flagging;
for (&(row, col), cell) in self.cells.iter() {
    if self.tentative(cell.tentative_epoch) { continue; }
    if cell.unknown {
        if flag && col != cols - 1 {
            ov.cells.insert((row, col), PredictedCell {
                glyph: String::new(),
                fg: Color::Default,
                bg: Color::Default,
                underline: true,
                unknown: true,
            });
        }
        continue;   // never draw text for an unknown cell
    }
    ov.cells.insert((row, col), PredictedCell {
        glyph: cell.glyph.clone(),
        fg: cell.fg,
        bg: cell.bg,
        underline: flag,
        unknown: false,
    });
}
```

The renderer (in `rmosh-client`) must then treat `unknown && grapheme.is_empty()` as "underline the existing real cell, do not replace its glyph."

(4) Validity: in `cell_validity` (lines 497-525), grade `unknown` cells `CorrectNoCredit` before the glyph compare (mirror reference lines 688-690):

```rust
if late_acked < cell.expiration_frame { return Validity::Pending; }
if cell.unknown { return Validity::CorrectNoCredit; }   // <-- add
if is_blank(&cell.glyph) { return Validity::CorrectNoCredit; }
let actual = cell_glyph(screen, row, col);
if actual == cell.glyph {
    if cell.original_contents.iter().any(|o| o == &actual) {   // history check, was: actual == cell.original
        Validity::CorrectNoCredit
    } else {
        Validity::Correct
    }
} else {
    Validity::IncorrectOrExpired
}
```

(5) Mid-line backspace shift (insert mode), replacing the single-cell blank in the `0x7f | 0x08` arm when `!self.predict_overwrite`. Shift the row **left** from `col` to `cols-1`; the right edge becomes `unknown` (mirror reference lines 431-463):

```rust
if do_pred {
    if self.predict_overwrite {
        // existing behavior: blank one cell at (row, col)
    } else {
        for i in col..cols {
            let original = cell_glyph(screen, row, i);
            let (g, fg, bg, unknown) = if i + 1 < cols {
                let (g, fg, bg, src_unknown) = self.pred_or_real_glyph(screen, row, i + 1);
                (g, fg, bg, src_unknown)
            } else {
                (String::new(), Color::Default, Color::Default, true) // right edge: unknown
            };
            self.cells.insert((row, i), PredCell {
                expiration_frame: self.local_frame_sent + 1,
                tentative_epoch: self.prediction_epoch,
                prediction_time: now,
                glyph: if unknown { String::new() } else { g },
                fg, bg,
                original_contents: vec![original],
                unknown,
            });
        }
    }
}
```

Here `col..cols` ascends; each `i` reads `i+1`, which has not yet been overwritten in this loop, so it sees pre-shift state (correct). `pred_or_real_glyph` is the helper added in item 2c (extended to also return the source cell's `unknown`).

API note (current crate's vt100 0.16.2, per `docs/research/vt100-api.md`): `Cell::contents() -> &str` (not `String`); `has_contents()`, `is_wide()`, `is_wide_continuation()` exist; `Screen::size() -> (rows, cols)`; `Screen::cursor_position() -> (row, col)`. `cell_glyph` (lines 473-479) already uses `has_contents()` + `contents().to_string()`. For a full insert-mode port you would also want to bail (`become_tentative`) on wide chars (`is_wide`), matching the reference's `width1` guard in `handle_print` (lines 468-473) which only predicts width-1 chars; the current arm restricts to `0x20..=0x7e` ASCII so wide input already falls through to the `_ =>` `become_tentative` arm (lines 309-312) — acceptable.

---

## Summary of edits to `/Users/kisaczka/Desktop/code/moshers2/crates/predict/src/lib.rs`

- **P0 (item 1):** `PredictionEngine::new` — `prediction_epoch: 0` → `prediction_epoch: 1` (line 142). Remove misleading comment lines 139-141. `confirmed_epoch` advancement on `Correct` already exists (lines 372-374, 404). Add `predictions_hidden_until_server_confirms_echo` test.
- **P2 (item 2):** Add `predict_overwrite: bool` field (default `false`). In the `0x20..=0x7e` arm of `new_user_byte`, add a right-shift loop over `((col+1)..cols).rev()` before the single-cell write. Requires per-cell `pred_or_real_glyph` helper.
- **P2 (item 3):** Add `unknown: bool` and `original_contents: Vec<String>` to `PredCell`; add `unknown` to `PredictedCell`. Branch `unknown` in `overlay` (underline-only hint, take `screen`), grade `unknown` `CorrectNoCredit` in `cell_validity`, use history in the no-credit check. Add a left-shift insert-mode backspace path marking the right edge `unknown`.
