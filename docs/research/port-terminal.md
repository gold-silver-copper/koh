# Porting notes — terminal screen state (P3: stop re-parsing the whole screen each frame) + cleanup

Scope: `rmosh-terminal` (`crates/terminal/src/lib.rs`, `crates/terminal/src/server.rs`) and `rmosh-transport-iroh` (`crates/transport-iroh/src/lib.rs`).
Reference: `moshers-terminal` (`crates/moshers-terminal/src/lib.rs`) and `moshers-iroh`.

TL;DR of the three asks:

1. **The P3 defect is real and lives only in `TerminalScreen::apply` in `crates/terminal/src/lib.rs`.** On every non-resize frame it builds a brand-new `vt100::Parser`, replays `self.screen.state_formatted()` (a full repaint of the *entire* current screen) into it, *then* replays the incremental `diff.vt`, then clones the resulting `Screen` back into `self`. That is a full re-parse of the whole grid per frame. The reference does NOT do this — it keeps a long-lived `vt100::Parser` and calls `parser.process(&diff.vt)` directly. The fix below makes the current crate hold a live parser too, while still satisfying `SyncState: Clone + Default + PartialEq` and the round-trip law.
2. **unicode-width is unused** in the current terminal crate — confirmed removable. (`thiserror` is also declared-but-unused there; remove it too.)
3. **The reference wires NO reliable-stream path for state.** Oversized state is fragmented over datagrams (the `rmosh_wire` fragmenter). `IrohChannel::send_reliable`/`recv_reliable` in the current `transport-iroh` are **dead code** — never called anywhere in the workspace. Delete them (and the `bytes`/uni-stream imports they alone need).

---

## 0. The trait contracts differ between the two crates — internalize this first

The current SSP trait (`crates/ssp/src/lib.rs:79`):

```rust
pub trait SyncState: Clone + Default + PartialEq {
    type Diff: Serialize + DeserializeOwned;
    fn diff_from(&self, base: &Self) -> Self::Diff;   // delta base -> self
    fn apply(&mut self, diff: &Self::Diff);
    fn subtract_prefix(&mut self, _prefix: &Self) {}  // default no-op
}
```

The reference SSP trait (`crates/moshers-ssp/src/state.rs:15`):

```rust
pub trait SyncState: Clone + Default {
    type Diff: Serialize + DeserializeOwned;
    fn diff(&self, target: &Self) -> Self::Diff;      // delta self -> target (OPPOSITE direction)
    fn apply(&mut self, diff: &Self::Diff);
    fn equals(&self, other: &Self) -> bool;           // explicit, NOT a Clone+PartialEq bound
    fn collapse_prefix(&mut self, _prefix: &Self) {}  // default no-op
}
```

Two structural differences that matter for the port:

- **Diff direction is reversed.** Reference `diff(&self, target)` produces `self → target`; current `diff_from(&self, base)` produces `base → self`. Do NOT copy the reference body verbatim; you only borrow the *parser-persistence mechanism*, not the call signature.
- **The current crate requires `PartialEq` (real `==`), the reference requires only an `equals()` method.** This is the crux of "how do you keep a non-`Clone` `Parser` while satisfying the bounds." The current crate already solved `Clone` + `PartialEq` by storing an owned `vt100::Screen` (which IS `Clone` and lets you derive nothing but implement `eq` via `state_diff`). You must KEEP that snapshot field to satisfy the bounds, and ADD a live parser for the apply hot path. See §1.4.

The current `ScreenDiff` (richer than reference — keep it):

```rust
pub struct ScreenDiff {
    pub resize: Option<(u16, u16)>,   // (rows, cols) — NOTE row-major; reference uses (cols, rows)
    pub echo_ack: u64,
    pub title: Option<String>,
    pub vt: Vec<u8>,
}
```

---

## 1. P3: persistent parser instead of per-frame full re-parse

### 1.1 What the reference does and WHY it is correct

Reference `ScreenState` holds the parser directly (`crates/moshers-terminal/src/lib.rs:35`):

```rust
pub struct ScreenState {
    parser: vt100::Parser,
    echo_ack: u64,
    input_history: VecDeque<(u64, u64)>,
}
```

Its `apply` (`:175`) is a true incremental apply — it feeds the diff bytes straight into the live, already-at-base parser, and feeds the resize first (geometry already baked into the escape bytes by `diff`):

```rust
fn apply(&mut self, diff: &ScreenDiff) {
    if let Some((cols, rows)) = diff.resize {
        self.parser.screen_mut().set_size(rows, cols);
    }
    if !diff.vt.is_empty() {
        self.parser.process(&diff.vt);   // <-- O(diff), NOT O(whole screen)
    }
    if let Some(a) = diff.echo_ack {
        self.echo_ack = a;
    }
}
```

Why it is correct: `vt100`'s `state_diff(base)` emits escape-sequence bytes whose semantics are "if a parser is currently showing `base`, these bytes drive it to `target`." A parser that has been kept alive through every previous `apply` is, by induction, already showing the acked base, so `process(&diff.vt)` lands exactly on target. Cost is proportional to the size of the diff (a few cells), not to the screen area.

How the reference satisfies the bounds **despite `vt100::Parser` not being `Clone`**:

- It implements `Clone` *by hand* (`:63`) using `rebuilt_parser()` (`:98`), which serializes the current screen with `state_formatted()` and replays it into a fresh parser. So cloning costs one full re-parse — but **clone is rare** (only when the transport snapshots a state into `sent_states`/`received_states`), whereas **apply is per-frame**. The reference pays the full-parse cost on the rare path, not the hot path.
- It does NOT need `PartialEq`; the reference trait uses `equals()` (`:187`), implemented as `state_formatted()` string equality plus `echo_ack`.

```rust
impl Clone for ScreenState {
    fn clone(&self) -> Self {
        Self { parser: self.rebuilt_parser(), echo_ack: self.echo_ack,
               input_history: self.input_history.clone() }
    }
}
fn rebuilt_parser(&self) -> vt100::Parser {
    let (rows, cols) = self.parser.screen().size();
    let mut p = vt100::Parser::new(rows, cols, 0);
    p.process(&self.parser.screen().state_formatted());
    p
}
```

### 1.2 What the current crate does and the specific defect

`TerminalScreen` (`crates/terminal/src/lib.rs:44`) stores only an owned `Screen`:

```rust
#[derive(Clone, Debug)]
pub struct TerminalScreen {
    screen: vt100::Screen,   // Screen IS Clone; Parser is not
    echo_ack: u64,
    title: String,
}
```

The defect is `apply` (`:130`), specifically the `diff.resize.is_none()` branch:

```rust
fn apply(&mut self, diff: &Self::Diff) {
    let (rows, cols) = diff.resize.unwrap_or_else(|| self.size());
    let mut p = vt100::Parser::new(rows, cols, 0);
    if diff.resize.is_none() {
        // Reload our current screen into a fresh parser, then replay the incremental diff.
        p.process(&self.screen.state_formatted());   // <-- FULL RE-PARSE OF WHOLE SCREEN, EVERY FRAME
        p.process(&diff.vt);
    } else {
        p.process(&diff.vt);   // (resize branch ships a self-contained state_formatted repaint)
    }
    self.screen = p.screen().clone();   // <-- plus a full Screen clone every frame
    self.echo_ack = self.echo_ack.max(diff.echo_ack);
    if let Some(title) = &diff.title {
        self.title = title.clone();
    }
}
```

Per non-resize frame this does: (a) allocate a fresh `Parser`, (b) `state_formatted()` of the entire current grid (serialize every cell with full SGR state), (c) `process()` that whole repaint (re-parse every cell), (d) `process(&diff.vt)`, (e) clone the whole resulting `Screen`. The incremental diff bytes in `diff.vt` are tiny; everything else is `O(rows*cols)` work attributable purely to the lack of a persistent parser. This is the P3 issue.

Note `diff_from` (`:114`) is already fine — it calls `self.screen.state_diff(&base.screen)` directly on the owned screens. The leak is `apply` only.

### 1.3 The same problem does NOT exist on the server

`ServerTerminal` (`crates/terminal/src/server.rs:31`) already keeps a long-lived parser and only clones a `Screen` snapshot on `snapshot()` (`:128`). That side is correct; leave it as is. The fix is purely about the *client-authoritative* `TerminalScreen` that the transport `apply`s into.

### 1.4 The precise change — add a live parser to `TerminalScreen`, keep the `Screen` snapshot for the bounds

You cannot drop the `screen: vt100::Screen` field, because `Clone`/`PartialEq`/`Default` (the current trait bounds) are derived/implemented against it. Keep it, and add a *lazily-built, long-lived* parser used only inside `apply`. Concrete design:

Change the struct (`crates/terminal/src/lib.rs:44`) to:

```rust
pub struct TerminalScreen {
    /// Authoritative snapshot. Always reflects the live parser when one exists; this is
    /// what `diff_from`/`PartialEq`/render read, and what survives `Clone`.
    screen: vt100::Screen,
    echo_ack: u64,
    title: String,
    /// Live parser kept across `apply` calls so incremental diffs are O(diff), not O(screen).
    /// `None` until the first `apply`; not part of identity. `Parser` is not `Clone`, so this
    /// is dropped on clone and rebuilt on the next `apply`.
    parser: Option<Box<vt100::Parser>>,
}
```

Because `Parser` is not `Clone`/`PartialEq`/`Debug`-friendly, you must STOP deriving and hand-implement the three impls so they ignore `parser`:

```rust
impl Clone for TerminalScreen {
    fn clone(&self) -> Self {
        // Drop the live parser on clone (Parser: !Clone). The snapshot carries the state;
        // the next apply rebuilds the parser from it. Clone is the rare path (transport
        // snapshots), so paying a rebuild later is acceptable; the per-frame apply stays cheap.
        Self { screen: self.screen.clone(), echo_ack: self.echo_ack,
               title: self.title.clone(), parser: None }
    }
}

impl std::fmt::Debug for TerminalScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalScreen")
            .field("size", &self.screen.size())
            .field("echo_ack", &self.echo_ack)
            .field("title", &self.title)
            .finish()
    }
}
```

`PartialEq` (`:152`) stays exactly as it is — it already reads only `echo_ack`, `title`, and `screen` via `state_diff`; just make sure it does not touch `parser`:

```rust
impl PartialEq for TerminalScreen {
    fn eq(&self, other: &Self) -> bool {
        self.echo_ack == other.echo_ack
            && self.title == other.title
            && self.screen.size() == other.screen.size()
            && self.screen.state_diff(&other.screen).is_empty()
    }
}
```

`Default` (`:53`) — drop the `derive(Clone, Debug)` from the struct (you now hand-roll both), keep the manual `Default` impl and add `parser: None`:

```rust
impl Default for TerminalScreen {
    fn default() -> Self {
        TerminalScreen { screen: blank_screen(DEFAULT_ROWS, DEFAULT_COLS),
                         echo_ack: 0, title: String::new(), parser: None }
    }
}
```

`from_bytes` (`:66`) — add `parser: None` to the constructed value (or seed the parser; `None` is simpler and correct).

Now rewrite `apply` (`:130`) so the non-resize path uses the persistent parser:

```rust
fn apply(&mut self, diff: &Self::Diff) {
    // Ensure we have a live parser already showing the current snapshot. On the first apply
    // (or right after a clone, which nulls `parser`) this rebuilds once via state_formatted;
    // every subsequent apply reuses it, so steady-state cost is O(diff.vt), not O(screen).
    if diff.resize.is_some() {
        // Resize: vt100 doesn't reflow, so `vt` is a self-contained repaint at the new size.
        // Rebuild the parser at the new geometry and replay the repaint. (Resize is rare.)
        let (rows, cols) = diff.resize.unwrap();
        let mut p = Box::new(vt100::Parser::new(rows, cols, 0));
        p.process(&diff.vt);
        self.screen = p.screen().clone();
        self.parser = Some(p);
    } else {
        let parser = self.parser.get_or_insert_with(|| {
            let (rows, cols) = self.screen.size();
            let mut p = Box::new(vt100::Parser::new(rows, cols, 0));
            p.process(&self.screen.state_formatted()); // one-time rebuild from snapshot
            p
        });
        if !diff.vt.is_empty() {
            parser.process(&diff.vt);                  // <-- the hot path: O(diff)
        }
        self.screen = parser.screen().clone();         // snapshot stays in sync for eq/render
    }
    self.echo_ack = self.echo_ack.max(diff.echo_ack);
    if let Some(title) = &diff.title {
        self.title = title.clone();
    }
}
```

Why this is correct and preserves the round-trip law `apply(diff_from(base, target)) == target`:

- The invariant maintained is: **whenever `parser` is `Some`, `parser.screen()` and `self.screen` are byte-identical** (we always `self.screen = parser.screen().clone()` after touching the parser).
- The transport flow is: it `clone()`s the acked base (which nulls `parser`), then `apply`s. The first `apply` lazily rebuilds the parser from the base snapshot via `state_formatted()` — exactly the same bytes the old code re-parsed, so the resulting screen is identical. After that one rebuild, repeated `apply`s on the *same* `TerminalScreen` object feed only `diff.vt`, matching the reference's persistent-parser semantics.
- `state_diff(base)` semantics ("drive a parser showing base to target") hold because the parser is, by the invariant, always showing the current snapshot = the diff's declared base.
- The non-resize `state_diff` path: `diff_from` already emits `self.screen.state_diff(&base.screen)`. Replaying those bytes into a parser showing `base` yields `target`. The lazy rebuild guarantees the parser shows `base` on the first apply; the persistence guarantees it on every subsequent apply.
- The resize path: `diff_from` (`:117`) ships `state_formatted()` (a full self-contained repaint) when `resized`, so a fresh parser at the new size replayed with `diff.vt` reproduces target exactly — unchanged from today, just now also re-seating `self.parser` so the next incremental apply is cheap again.

Cost summary after the fix: steady-state non-resize apply = one `parser.process(diff.vt)` (tens of bytes) + one `Screen` clone. The `Screen` clone is unavoidable while the bounds require `Clone`/`PartialEq` on the snapshot; if profiling shows the clone dominates, you can additionally gate it behind "only re-snapshot when someone reads `self.screen()`" but that is a follow-up, not required for P3. The full `state_formatted()` re-parse — the actual P3 regression — is eliminated from the per-frame path.

The existing round-trip tests (`diff_apply_roundtrip_simple`, `..._incremental`, `resize_roundtrip_full_repaint`, `equal_screens_compare_equal`, `wide_chars_and_emoji_roundtrip`, `converges_over_lossy_link`) all exercise `clone()` then `apply()` and must continue to pass unchanged — they are exactly the verification for the lazy-rebuild path. Add one extra test: apply N incremental diffs to the *same* object (without re-cloning between each) and assert it equals the server's final snapshot, to lock in the persistence (no rebuild between frames).

---

## 2. unicode-width — confirmed unused, remove it (and thiserror)

Grep over `crates/terminal/` shows `unicode-width` appears ONLY in `Cargo.toml:12`; there is no `unicode_width`, `UnicodeWidthStr`, `UnicodeWidthChar`, or `.width(` usage in any `.rs` file. `vt100` already does all wide/combining-char width handling internally (proven by the `wide_chars_and_emoji_roundtrip` test, which passes without the crate touching unicode-width). The reference terminal crate does NOT depend on unicode-width at all — see its `Cargo.toml` deps (`moshers-ssp`, `serde`, `vt100` only). So it is safe to remove.

Likewise `thiserror` is declared (`Cargo.toml:11`) but unused: there is no `Error`/`#[derive(thiserror::Error)]`/`thiserror` reference anywhere in `crates/terminal/src/`. Remove it too.

Precise change — `crates/terminal/Cargo.toml`, delete these two lines from `[dependencies]`:

```toml
unicode-width.workspace = true
thiserror.workspace = true
```

Resulting `[dependencies]` should be exactly:

```toml
rmosh-ssp.workspace = true
serde.workspace = true
vt100.workspace = true
```

(matching the reference's dependency shape). After removal run `cargo build -p rmosh-terminal` to confirm.

---

## 3. Reliable-stream path: the reference uses none — delete the dead `send_reliable`/`recv_reliable`

### 3.1 What the reference does

The reference ships state ONLY over QUIC unreliable datagrams, and splits oversized instructions with the `rmosh_wire`/`moshers` fragmenter — never a reliable stream. Evidence:

- `moshers-iroh/src/lib.rs:9`: the connection is described as "an unreliable-**datagram** loop that carries SSP instructions (NOT a reliable [stream])".
- `moshers-iroh/src/endpoint.rs:6-8`: "Send/recv are called directly on the returned `Connection` (`send_datagram` / `read_datagram`)". The endpoint module exposes only `bind`, `connect`, `accept_authorized`, `rtt`, `max_datagram_size`, `max_payload` — no reliable send/recv for state.
- `moshers-ssp/src/fragment.rs:1-7`: "An instruction larger than the path's `max_datagram_size` (a full repaint, a clear-and-redraw) is split into fragments, each its own datagram, and reassembled by the peer." So oversized state already has a datagram-based answer.
- The only reliable stream in the reference is `moshers-iroh/src/auth.rs` (`open_bi`/`accept_bi`), used solely for the one-time authentication handshake — NOT for state sync.

This matches the current crate's own stated policy (`transport-iroh/src/lib.rs:9-15`): "Oversized instructions are handled upstream by the `rmosh_wire` fragmenter (each fragment fits `max_datagram_size`), so we never put the steady flow on a reliable stream — that would reintroduce the head-of-line blocking mosh exists to avoid."

### 3.2 What the current crate does — dead code

`IrohChannel::send_reliable` (`transport-iroh/src/lib.rs:227`) and `recv_reliable` (`:235`) exist but are **called nowhere in the workspace.** Grep for `.send_reliable`/`.recv_reliable`/`send_reliable(`/`recv_reliable(` across all of `moshers2/` returns only the two definitions, no call sites. The actual channel surface used by both `crates/server/src/lib.rs` and `crates/client/src/lib.rs` is: `max_datagram_size()`, `rtt_ms()`, `send(&datagram)` (server `:111`, client `:160`), `recv()` (server `:61`, client `:126`), plus `close`/`closed`. No uni-stream is ever opened or accepted for state. The fragmenter (`crates/wire/src/lib.rs`, `Fragmenter::fragment` at `:142`, `FragmentAssembly` at `:193`, `DEFAULT_MAX_DATAGRAM = 1200` at `:30`) already covers oversized diffs over datagrams, with proptest coverage (`fragment_reassemble_roundtrip`, `large_instruction_fragments_and_reassembles`).

These two functions also carry a correctness smell worth noting if they were ever wired: `recv_reliable` does a single `accept_uni()`+`read_to_end()` with no concurrent acceptor loop, so a reliable repaint would only be received if the receiver happened to be blocked in `recv_reliable` at exactly the right time — there is no framing or multiplexing with the datagram loop. They are not just unused, they are not integrable as written. Delete rather than wire.

### 3.3 Precise change — delete the dead methods and their sole imports

In `crates/transport-iroh/src/lib.rs`:

1. Delete the two methods (`:224`–`:238`), the whole block:

```rust
    pub async fn send_reliable(&self, data: &[u8]) -> anyhow::Result<()> { ... }
    pub async fn recv_reliable(&self, size_limit: usize) -> anyhow::Result<Vec<u8>> { ... }
```

2. Trim the doc comment on the struct (`:162`) so it no longer advertises the reliable escape hatch:

```rust
/// A datagram channel over a single iroh [`Connection`].
```

3. Check imports: `VarInt` (`:22`) is still needed by `close` (`:241`). `Bytes` (`:21`) is still needed by `send` (`:188`). `open_uni`/`accept_uni`/`read_to_end`/`finish` were the only consumers of the uni-stream API, so after deletion confirm nothing else references them. Then run `cargo build -p rmosh-transport-iroh` — if `anyhow` becomes unused as a result, the compiler will warn (it is also used by `SetupError::Other(#[from] anyhow::Error)` at `:39`, so it stays). Resolve any resulting unused-import warnings.

If you'd rather keep an escape hatch on principle: don't. The reference proves datagram + fragmenter is the complete design, and a reliable state path reintroduces head-of-line blocking — the exact thing the protocol is built to avoid. Delete.

---

## File/function index for the edits

- `crates/terminal/src/lib.rs`
  - struct `TerminalScreen` (`:44`): add `parser: Option<Box<vt100::Parser>>`; drop `#[derive(Clone, Debug)]`.
  - hand-impl `Clone` and `Debug` ignoring `parser`; keep manual `Default` (`:53`, add `parser: None`); keep `PartialEq` (`:152`) unchanged; `from_bytes` (`:66`) add `parser: None`.
  - `impl SyncState for TerminalScreen::apply` (`:130`): rewrite to use the persistent parser (lazy rebuild on first apply / after clone; resize branch rebuilds at new size). `diff_from` (`:114`) unchanged.
  - add a "many incremental applies without re-clone" test.
- `crates/terminal/Cargo.toml`: remove `unicode-width` (`:12`) and `thiserror` (`:11`).
- `crates/terminal/src/server.rs`: no change (already holds a live parser; correct).
- `crates/transport-iroh/src/lib.rs`: delete `send_reliable` (`:227`) and `recv_reliable` (`:235`); trim struct doc (`:162`); resolve resulting unused imports.
