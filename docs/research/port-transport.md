# Porting Notes: SSP Transport (moshers2 `rmosh-*`)

Reference: `/Users/kisaczka/Desktop/code/moshers/crates/moshers-ssp/src/` (`transport.rs`, `wire.rs`, `state.rs`, `fragment.rs`, `lib.rs`)
Target:    `/Users/kisaczka/Desktop/code/moshers2/crates/ssp/src/transport.rs`, `/Users/kisaczka/Desktop/code/moshers2/crates/wire/src/lib.rs`, `/Users/kisaczka/Desktop/code/moshers2/crates/ssp/src/testkit.rs`

Constraint reminder: the transport must stay PURE and clock-injected — no I/O, no async. All fixes below preserve that.

Field/name map (reference -> current), so the rewrites below read cleanly:
- `Timestamped{ts,seq,state}` -> `TimestampedState{timestamp,num,state}`
- `sent` / `received` (`VecDeque`) -> `sent_states` (`VecDeque`) / `received_states` (`Vec`)
- `Instruction.old_seq/new_seq/ack/throwaway/diff` -> `Instruction.old_num/new_num/ack_num/throwaway_num/diff`
- `NO_SEQ` -> `SHUTDOWN_SENTINEL` (both `u64::MAX`); `NONE_TIME` -> `NEVER`
- `process_acknowledgment_through` exists in both; `process_throwaway_until` exists in both.

NOTE on a *correct* divergence the current crate already has and should KEEP: the current `recv()` calls `process_acknowledgment_through(instr.ack_num)` BEFORE the dedupe/missing-base checks (transport.rs:497), so the peer's ack of our stream is honored even for duplicate/out-of-order inbound. The reference does the same (transport.rs:405). Do not move that call. (Item B builds on it.)

---

## A. (P1) Receiver diff-base vs throwaway GC — the `.expect()` can panic on peer input

### What the reference does and WHY it is correct

`moshers-ssp/src/transport.rs`, `recv()`, lines 411-437. The reference **clones the base state BEFORE running the throwaway GC**, so GC can never invalidate it:

```rust
// Dedupe: already have this state.
if self.received.iter().any(|s| s.seq == inst.new_seq) {
    return Ok(outcome);
}
// Require a known base; a diff against an unknown reference is dropped (guards
// idempotency and reordering).
let ref_idx = match self.received.iter().position(|s| s.seq == inst.old_seq) {
    Some(i) => i,
    None => return Ok(outcome),
};
let base_state = self.received[ref_idx].state.clone();   // <-- CLONE FIRST

self.process_throwaway_until(inst.throwaway);             // <-- GC AFTER

if self.received.len() > RECEIVED_STATES_MAX {
    if now < self.quench_timer { return Ok(outcome); }
    self.quench_timer = now + QUENCH_WINDOW;
}

let mut new_state = base_state;                           // owned clone, never re-looked-up
if !inst.diff.is_empty() {
    let diff: <Remote as SyncState>::Diff =
        postcard::from_bytes(&inst.diff).map_err(|_| TransportError::Decode)?;
    new_state.apply(&diff);
}
```

There is **no second `position()` lookup and no `.expect()`** after GC. The order is: dedupe -> resolve+clone base -> GC -> quench -> apply. Even if `inst.throwaway > inst.old_seq` (a peer that lies about its throwaway floor, or a reordered/forged datagram), the GC drops the base from `received` but the reference already owns `base_state`, so apply still succeeds against the correct base. The newly built state is then inserted sorted (lines 442-454).

The reference `process_throwaway_until` also never empties the queue (`while self.received.len() > 1 ...`), keeping `received.back()` valid.

### What the current crate does and the specific defect

`ssp/src/transport.rs`, `recv()`, lines 499-533. It checks dedupe and missing-base, then runs GC, then **re-resolves the base with `.position(...).expect(...)` AFTER GC**:

```rust
// Idempotency: already have this state.
if self.received_states.iter().any(|s| s.num == instr.new_num) {
    return RecvOutcome::Duplicate;
}
// Must hold the diff base, else drop (out-of-order / replay defense).
if !self.received_states.iter().any(|s| s.num == instr.old_num) {
    return RecvOutcome::MissingBase;
}

self.process_throwaway_until(instr.throwaway_num);       // <-- GC runs first

if self.received_states.len() > RECEIVED_STATES_CAP {
    if now < self.receiver_quench_timer { return RecvOutcome::Quenched; }
    self.receiver_quench_timer = now + RECEIVER_QUENCH_MS;
}

// Re-resolve the base after the throwaway GC (positions may have shifted).
let ref_idx = self
    .received_states
    .iter()
    .position(|s| s.num == instr.old_num)
    .expect("base existed before throwaway and old_num >= throwaway");  // <-- PANIC
let mut new_state = self.received_states[ref_idx].state.clone();
```

The comment's invariant ("old_num >= throwaway") is **NOT enforced anywhere**. `process_throwaway_until` (transport.rs:560-572) drops every state with `num < throwaway_num`:

```rust
let keep_from = self
    .received_states
    .iter()
    .position(|s| s.num >= throwaway_num)
    .unwrap_or(0);
if keep_from > 0 { self.received_states.drain(0..keep_from); }
```

Concrete panic case: suppose `received_states` holds nums `[0]`. A datagram arrives with `old_num = 0`, `new_num = 5`, `throwaway_num = 3`. The missing-base check passes (0 is present). GC computes `keep_from = position(num >= 3) = None -> unwrap_or(0) = 0`, so `keep_from == 0` and nothing is dropped here — but consider `received_states = [0, 2]`, `old_num = 0`, `new_num = 5`, `throwaway_num = 1`. `keep_from = position(num >= 1) = 1`, so `drain(0..1)` removes num 0 — the base. Then `position(|s| s.num == 0).expect(...)` panics. This is **peer-controlled input panicking a pure state machine** — a remote DoS / crash. `recv` returns `RecvOutcome` (no `Result`), so the panic cannot even be surfaced as a drop.

### Precise change

In `ssp/src/transport.rs`, function `recv()`: clone the base BEFORE `process_throwaway_until`, and delete the post-GC `position().expect()`. Replace lines 499-524 (from the dedupe check through the `let mut new_state = ...clone();`) with:

```rust
// Idempotency: already have this state.
if self.received_states.iter().any(|s| s.num == instr.new_num) {
    return RecvOutcome::Duplicate;
}
// Must hold the diff base, else drop (out-of-order / replay defense).
let Some(ref_idx) = self
    .received_states
    .iter()
    .position(|s| s.num == instr.old_num)
else {
    return RecvOutcome::MissingBase;
};
// Clone the base BEFORE GC: process_throwaway_until may legitimately drop the base
// state (e.g. throwaway_num > old_num), and we must never re-resolve it afterwards.
let mut new_state = self.received_states[ref_idx].state.clone();

self.process_throwaway_until(instr.throwaway_num);

// Anti-DoS quench once the received list is huge.
if self.received_states.len() > RECEIVED_STATES_CAP {
    if now < self.receiver_quench_timer {
        return RecvOutcome::Quenched;
    }
    self.receiver_quench_timer = now + RECEIVER_QUENCH_MS;
}

if !instr.diff.is_empty() {
    match decode_diff::<Remote::Diff>(&instr.diff) {
        Ok(d) => new_state.apply(&d),
        Err(e) => {
            tracing::warn!(error=%e, "dropping instruction with undecodable diff");
            return RecvOutcome::Incomplete;
        }
    }
}
```

Then delete the now-dead block at lines 518-524 (the comment "Re-resolve the base after the throwaway GC" and the `ref_idx`/`new_state` it created). The subsequent `let ts = TimestampedState { ... state: new_state };` (lines 534-538) is unchanged and still compiles, now consuming the early-cloned `new_state`.

Net effect: zero `.expect()` on any value derived from peer input; the missing-base path returns `RecvOutcome::MissingBase` cleanly; GC dropping the base is harmless because we own the clone.

---

## B. (P1) `last_heard` / `last_recv` — update on EVERY decoded inbound, not only on a new newest-in-order state

### What the reference does and WHY it is correct

`moshers-ssp/src/transport.rs`, `recv()`, **line 388** — the very first thing after entering `recv`, before fragment decode even:

```rust
pub fn recv(&mut self, datagram: &[u8], now: u64) -> Result<RecvOutcome, TransportError> {
    let mut outcome = RecvOutcome::default();
    self.last_heard = now;          // <-- EVERY inbound datagram, unconditionally
    ...
```

`last_heard` is the gate for *active retransmission*. In `calculate_timers` the reference computes `let active = self.last_heard + ACTIVE_RETRY_TIMEOUT > now;` (transport.rs:235), and branches (B) and (C) — the retransmit-at-frame-rate and slow-retransmit paths — only fire when `active`. So `last_heard` answers "is the peer still there?" The correct answer must be driven by *any* sign of life: a duplicate, an out-of-order frame, a pure ack, even an undecodable-but-arrived datagram. mosh sets `last_heard` on receipt of the datagram, not on state advance. Setting it before fragment-decode means even a fragment that only completes part of a reassembly refreshes liveness — which is correct, since the peer is plainly transmitting.

(Note: in the reference, even fragment-decode-failure paths at lines 390-396 `return Ok(outcome)` *after* `last_heard` was already set on line 388, so they too refresh liveness.)

### What the current crate does and the specific defect

`ssp/src/transport.rs`, `recv()` sets `last_heard` ONLY on the `NewState` arm, deep inside the sorted-insert match (lines 546-555):

```rust
None => {
    self.received_states.push(ts);
    // Newest in-order state: advance our ack, mark the peer heard, owe a fast ack.
    self.ack_num = self.received_states.last().unwrap().num;
    self.last_heard = now;          // <-- ONLY here
    if !instr.diff.is_empty() {
        self.pending_data_ack = true;
    }
    RecvOutcome::NewState
}
```

Defect: `last_heard` is NOT updated on `Duplicate`, `OutOfOrder`, `MissingBase`, `Quenched`, or `Incomplete`. Concrete failure: a peer whose only newest-in-order traffic is being lost, but whose retransmits/dups/acks are arriving, will appear silent. After 10s (`ACTIVE_RETRY_TIMEOUT = 10_000`) `active`/`recently_heard` goes false, the sender drops out of branches (B)/(C) into (D) `next_send_time = NEVER`, and we **stop retransmitting our own state to a peer that is demonstrably still connected** — exactly the link-stall mosh's design avoids. Also a pure-ack-only keepalive from the peer (empty diff, `new_num` already seen -> `Duplicate`) never refreshes liveness, so a quiet-but-alive session can falsely time out.

### Precise change

In `ssp/src/transport.rs`, function `recv()`: set `self.last_heard = now;` once, unconditionally, immediately after the instruction is reassembled (i.e. right after the `let instr = match self.assembly.add(frag) { ... };` block at lines 487-494, before `process_acknowledgment_through`). Then **delete** the `self.last_heard = now;` line from the `NewState` arm (line 550).

Insert after line 494:

```rust
    // Any decoded datagram is a sign of life from the peer; refresh the
    // active-retransmission liveness gate (mosh sets last_heard on every recv).
    self.last_heard = now;
```

This makes liveness fire on Duplicate/OutOfOrder/MissingBase/Quenched/NewState alike (every path where reassembly completed). If you want to match the reference exactly (refresh even when a *fragment* arrives that does not complete an instruction), set it even earlier — right after `Fragment::decode` succeeds at line 480-486, before `self.assembly.add(frag)`. The reference sets it before fragment decode entirely (line 388); the practical minimum to fix the defect is "after reassembly completes," and matching the reference is "as early as a datagram is seen." Recommend the earliest placement (after successful `Fragment::decode`) to be faithful.

### Client staleness / link-down reset on ANY decoded datagram (Duplicate too)

This is the driver-layer corollary. The client's staleness/link-down reset (the logic that clears a "link down / waiting" UI banner and resyncs its predictor when the peer reappears) must key off ANY decoded inbound, not only `RecvOutcome::NewState`. Check `crates/client/src/lib.rs` where it matches on `recv()`'s `RecvOutcome`: the reset must also fire for `RecvOutcome::Duplicate` (and `OutOfOrder`) — a duplicate keepalive is proof the link is back even though no new state advanced. Concretely, the client should treat "any non-`Incomplete` outcome" (or simply "recv returned and decoded") as the link-up signal, mirroring the transport's now-unconditional `last_heard` refresh. Once the transport change above is in, the cleanest contract is: the client reads liveness from the transport (expose `last_heard`/an `is_link_up(now)` accessor) rather than re-deriving it from the `RecvOutcome` variant, so the two cannot disagree.

---

## C. (P1) Shutdown path — `back_num + 1` overflow and pushing a fresh `u64::MAX` state every tick

### What the reference does and WHY it is correct

Two distinct mechanisms.

**(C1) Compute `new_seq` from the real predecessor BEFORE the sentinel override — no `+1` on `u64::MAX`.**

`moshers-ssp/src/transport.rs`, `send_to_receiver`, lines 320-331:

```rust
fn send_to_receiver(&mut self, diff: Vec<u8>, now: u64, max: usize) -> Vec<Vec<u8>> {
    let back_seq = self.sent.back().unwrap().seq;
    let cur_eq_back = self.current.equals(&self.sent.back().unwrap().state);
    let mut new_seq = if cur_eq_back { back_seq } else { back_seq + 1 };  // computed from real back_seq
    if self.shutdown_in_progress {
        new_seq = NO_SEQ;                                                  // override AFTER
    }
    if new_seq == back_seq {
        self.sent.back_mut().unwrap().ts = now;                            // dedup: bump ts, no push
    } else {
        self.add_sent_state(now, new_seq);                                // push only when seq advances
    }
    ...
```

The `+1` is taken against `back_seq` which, once shutdown starts and a sentinel state has been pushed, is `NO_SEQ` (`u64::MAX`) — BUT the override `new_seq = NO_SEQ` happens *after* the `if cur_eq_back { back_seq } else { back_seq + 1 }` expression has already been bound to whatever it was, and then unconditionally clobbered to `NO_SEQ`. The crucial protection is the **`if new_seq == back_seq` dedup**: once the back state is already the sentinel, `new_seq == NO_SEQ == back_seq`, so the branch taken is `self.sent.back_mut().unwrap().ts = now;` — it bumps the timestamp of the existing sentinel state instead of pushing a new one.

Wait on the overflow: when `back_seq == NO_SEQ` (`u64::MAX`) and `cur_eq_back` is false, the expression `back_seq + 1` *is* evaluated and overflows. The reference avoids this because, after the first shutdown tick pushes the sentinel, `current.equals(&sent.back().state)` is true on every subsequent shutdown tick (the current local state was cloned into that sentinel state, and shutdown does not mutate `current`), so `cur_eq_back == true` and the `else back_seq + 1` arm is never taken when `back_seq == NO_SEQ`. The override-after-compute plus the equals-driven branch together keep `+1` away from `u64::MAX`.

**(C2) Dedup so we do NOT push a fresh `u64::MAX` state every tick.**

The `if new_seq == back_seq { bump ts } else { add_sent_state }` split (lines 327-331, above) is the dedup. First shutdown tick: `back_seq` is some real N, `new_seq` overridden to `NO_SEQ != N`, so `add_sent_state` pushes ONE sentinel state. Every later shutdown tick: `back_seq == NO_SEQ == new_seq`, so it only bumps the timestamp — the `sent` queue does not grow. `shutdown_tries` is still incremented per sentinel datagram in `send_in_fragments` (lines 374-376: `if new_seq == NO_SEQ { self.shutdown_tries += 1; }`), so the retry/give-up counter still advances.

`send_empty_ack` in the reference (lines 340-350) does `let mut new_seq = self.sent.back().unwrap().seq + 1; if self.shutdown_in_progress { new_seq = NO_SEQ; }` — but `send_empty_ack` is only reachable from the `diff.is_empty()` branch of `tick`; during shutdown the diff branch in `tick` is the empty-ack path too. Critically, even here, if `back().seq` is already `NO_SEQ`, `back().seq + 1` overflows. See the rewrite — the current crate's `send_empty_ack` has the *same* shape and must get the *same* dedup guard.

### What the current crate does and the specific defect

`ssp/src/transport.rs`, `send_to_receiver`, lines 390-410:

```rust
fn send_to_receiver(&mut self, now: u64, old_num: u64, diff: Vec<u8>) -> Vec<Vec<u8>> {
    let back_num = self.sent_states.back().unwrap().num;
    let current_eq_back = self.current_state == self.sent_states.back().unwrap().state;
    let mut new_num = if current_eq_back { back_num } else { back_num + 1 };  // (#1) back_num+1
    if self.shutdown_in_progress {
        new_num = SHUTDOWN_SENTINEL;
    }
    if new_num == back_num {
        self.sent_states.back_mut().unwrap().timestamp = now;
    } else {
        self.add_sent_state(now, new_num, self.current_state.clone());        // (#2)
    }
    ...
```

This arm is structurally identical to the reference and is mostly OK — the `if new_num == back_num` dedup is present (matches the reference): once `back_num == SHUTDOWN_SENTINEL`, the override makes `new_num == back_num` and only the timestamp is bumped. So `send_to_receiver` does NOT push a new sentinel every tick.

The defect is in `send_empty_ack`, lines 413-426:

```rust
fn send_empty_ack(&mut self, now: u64) -> Vec<Vec<u8>> {
    let back_num = self.sent_states.back().unwrap().num;
    let new_num = if self.shutdown_in_progress {
        SHUTDOWN_SENTINEL
    } else {
        back_num + 1                       // (#1) overflow if back_num == SHUTDOWN_SENTINEL
    };
    let old_num = self.assumed_receiver_num;
    self.add_sent_state(now, new_num, self.current_state.clone());   // (#2) NO dedup — pushes EVERY tick
    let out = self.send_in_fragments(old_num, new_num, Vec::new());
    self.next_ack_time = now + ACK_INTERVAL;
    self.next_send_time = NEVER;
    out
}
```

Two defects here:

1. **Unconditional push.** `send_empty_ack` calls `add_sent_state` with NO `if new_num == back_num` guard. During shutdown, `new_num == SHUTDOWN_SENTINEL` every tick; if `back_num` is already `SHUTDOWN_SENTINEL`, this pushes ANOTHER sentinel state every empty-ack tick. `add_sent_state` (lines 454-465) only caps at `SENT_STATES_CAP = 32` by evicting the 16th-from-end — so the queue churns with duplicate sentinels, and `local_acked_num()`/`shutdown_acknowledged()` (which read `sent_states.front().num`) behave on a polluted queue. During a normal (non-shutdown) idle keepalive this is also wrong: every keepalive tick increments `new_num` and pushes a state for a no-change ack, growing/churning `sent_states` needlessly (the reference's empty-ack also pushes, but during shutdown its `tick` path collapses to the dedup'd sentinel via the equals check — see below).

2. **Overflow.** When shutdown is NOT in progress but `back_num == SHUTDOWN_SENTINEL` (can occur after a sentinel was added and shutdown flag logic races, or simply defensively), `back_num + 1` overflows in debug (panic) / wraps to 0 in release. More directly: even *with* shutdown in progress the value is forced to `SHUTDOWN_SENTINEL` so the `else` is skipped — but the *non-shutdown keepalive after a sentinel* and any future refactor are unguarded.

The deeper issue vs. the reference: in the reference, the shutdown sentinel is pushed exactly once and thereafter `current.equals(back.state)` keeps `tick` on the dedup'd path. The current `send_empty_ack` has no equals-based dedup at all.

### Precise change

In `ssp/src/transport.rs`, function `send_empty_ack`: compute `new_num` from `back_num` (the override-after-compute pattern is fine), then add the `if new_num == back_num { bump ts } else { add_sent_state }` dedup, AND make the increment overflow-safe. Replace the body of `send_empty_ack` (lines 414-421) with:

```rust
let back_num = self.sent_states.back().unwrap().num;
// Compute the candidate from the real predecessor, then override for shutdown.
// saturating_add keeps us off u64::MAX even if back_num is already the sentinel.
let mut new_num = back_num.saturating_add(1);
if self.shutdown_in_progress {
    new_num = SHUTDOWN_SENTINEL;
}
let old_num = self.assumed_receiver_num;
if new_num == back_num {
    // Already at this num (e.g. repeat shutdown sentinel): bump ts, don't grow the queue.
    self.sent_states.back_mut().unwrap().timestamp = now;
} else {
    self.add_sent_state(now, new_num, self.current_state.clone());
}
let out = self.send_in_fragments(old_num, new_num, Vec::new());
```

(Keep the `next_ack_time`/`next_send_time` assignments after.) Result: at most one sentinel state is ever resident; repeated shutdown empty-acks only bump the timestamp; `shutdown_tries` still advances inside `send_in_fragments` (lines 437-439, `if new_num == SHUTDOWN_SENTINEL { self.shutdown_tries += 1; }`), so `shutdown_ack_timed_out` still fires after `SHUTDOWN_RETRIES = 16`.

Also apply `saturating_add` defensively in `send_to_receiver` line 393: change `back_num + 1` to `back_num.saturating_add(1)`. The dedup there already exists, so this is belt-and-suspenders against a `back_num == SHUTDOWN_SENTINEL` with `current_eq_back == false` (which would otherwise debug-panic before the override on the next line). Concrete value: `back_num = u64::MAX`, `current_eq_back = false` -> `u64::MAX + 1` panics in debug; `saturating_add` yields `u64::MAX`, then the shutdown override (if set) clobbers it anyway, and if shutdown is not set the subsequent `if new_num == back_num` dedup catches it.

---

## D. (P2) `protocol_version` in the `Instruction` — reference rejects mismatch at decode time

### What the reference does and WHY it is correct

The reference `Instruction` carries a version field as its FIRST member. `moshers-ssp/src/wire.rs`, lines 16-30:

```rust
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Instruction {
    /// Protocol version; the receiver rejects a mismatch.
    pub protocol_version: u32,
    pub old_seq: u64,
    pub new_seq: u64,
    pub ack: u64,
    pub throwaway: u64,
    pub diff: Vec<u8>,
}
```

The constant `moshers-ssp/src/lib.rs:33`:

```rust
pub const PROTOCOL_VERSION: u32 = 1;
```

Outbound, every instruction is stamped — `transport.rs:366-373`, `send_in_fragments`:

```rust
let inst = Instruction {
    protocol_version: PROTOCOL_VERSION,
    old_seq: self.sent[self.assumed_idx].seq,
    new_seq,
    ack: self.ack_num,
    throwaway: self.sent.front().unwrap().seq,
    diff: diff.to_vec(),
};
```

Inbound, `recv` rejects mismatch immediately after deserialize — `transport.rs:398-401`:

```rust
let inst = Instruction::deserialize(&bytes).map_err(|_| TransportError::Decode)?;
if inst.protocol_version != PROTOCOL_VERSION {
    return Err(TransportError::VersionMismatch(inst.protocol_version));
}
```

with the error variant `transport.rs:24-30`:

```rust
#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("instruction failed to decode")]
    Decode,
    #[error("protocol version mismatch: peer sent {0}, we speak {PROTOCOL_VERSION}")]
    VersionMismatch(u32),
}
```

Why correct: an incompatible peer (different envelope or diff encoding) is detected explicitly rather than mis-applying a foreign diff to local state (silent corruption). The check runs before any state mutation. (`PROTOCOL_VERSION` is documented as unrelated to mosh's own `MOSH_PROTOCOL_VERSION`, lib.rs:30-33.)

### What the current crate does and the defect

`wire/src/lib.rs` `Instruction` (lines 48-60) has **no `protocol_version` field at all**:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub old_num: u64,
    pub new_num: u64,
    pub ack_num: u64,
    pub throwaway_num: u64,
    pub diff: Vec<u8>,
}
```

The module doc even says (wire/src/lib.rs:21): "Unlike mosh we drop `protocol_version` chaff…". That conflates two things: mosh's *protobuf-padding chaff* (correctly dropped — QUIC AEAD pads) with the *version-gate* (which the reference keeps and is a correctness feature, not chaff). `ssp/src/transport.rs` `send_in_fragments` (lines 428-435) builds the instruction with no version, and `recv` never checks one. Defect: a peer speaking an incompatible diff encoding is undetected; its bytes are fed straight into `decode_diff::<Remote::Diff>` and `apply`, silently corrupting the remote-state mirror, or producing confusing `Incomplete` decode errors with no diagnostic.

### Precise change

**`wire/src/lib.rs`:** add the constant and the field (first, to match reference layout), keep encode/decode as-is (postcard serializes the new field automatically):

```rust
/// rmosh wire protocol version. Bump on any incompatible envelope or diff-encoding change.
/// (Unrelated to upstream mosh's MOSH_PROTOCOL_VERSION; rmosh never speaks to mosh.)
pub const PROTOCOL_VERSION: u32 = 1;
```

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    /// Protocol version; the receiver rejects a mismatch (see PROTOCOL_VERSION).
    pub protocol_version: u32,
    pub old_num: u64,
    pub new_num: u64,
    pub ack_num: u64,
    pub throwaway_num: u64,
    pub diff: Vec<u8>,
}
```

Update `Instruction::ack_only` (lines 64-72) to stamp the version:

```rust
pub fn ack_only(state_num: u64, ack_num: u64, throwaway_num: u64) -> Self {
    Instruction {
        protocol_version: PROTOCOL_VERSION,
        old_num: state_num,
        new_num: state_num,
        ack_num,
        throwaway_num,
        diff: Vec::new(),
    }
}
```

Update the `tests` `sample_instruction` (lines 265-273) and the proptest literal `Instruction { old_num: 1, ... }` (lines 367-370) to include `protocol_version: PROTOCOL_VERSION,` or they won't compile.

**`ssp/src/transport.rs`:** import the constant — change the `rmosh_wire` use (line 7) to `use rmosh_wire::{Fragment, FragmentAssembly, Fragmenter, Instruction, PROTOCOL_VERSION};`. In `send_in_fragments` (lines 429-435) add the field:

```rust
let instr = Instruction {
    protocol_version: PROTOCOL_VERSION,
    old_num,
    new_num,
    ack_num: self.ack_num,
    throwaway_num: self.sent_states.front().unwrap().num,
    diff,
};
```

In `recv`, reject mismatch right after reassembly produces `instr` (after lines 487-494, before `process_acknowledgment_through` at line 497):

```rust
if instr.protocol_version != PROTOCOL_VERSION {
    tracing::warn!(
        peer = instr.protocol_version,
        ours = PROTOCOL_VERSION,
        "dropping instruction: protocol version mismatch"
    );
    return RecvOutcome::Incomplete;
}
```

`RecvOutcome` has no version variant; mapping to `Incomplete` (a benign "nothing applied") is the minimal change and keeps the signature `RecvOutcome` (no `Result`). If you prefer parity with the reference's explicit signal, add a `RecvOutcome::VersionMismatch` variant to the enum (transport.rs:27-41) and return it here — but note the testkit's `step()` (testkit.rs:209-214) calls `recv` and discards the outcome, so either is safe for the sim. Put the version check BEFORE `process_acknowledgment_through` so a foreign peer's ack never culls our `sent_states`.

---

## E. (P3) Fragment MTU budget — exact header size vs the current `FRAGMENT_HEADER_OVERHEAD = 24` estimate

### What the reference does and WHY it is correct (EXACT, not estimated)

The reference does NOT serialize the fragment with postcard. It uses a hand-rolled fixed 10-byte header, so the per-fragment overhead is an exact constant. `moshers-ssp/src/fragment.rs`:

```rust
/// Fragment header: 8-byte big-endian id + 2-byte big-endian `(last << 15) | index`.
pub const FRAG_HEADER_LEN: usize = 10;       // line 15
```

`Fragment::to_bytes` (lines 35-43) writes exactly `id` (8 bytes BE) + `combined` (2 bytes BE) + `contents`, so a serialized fragment is precisely `10 + contents.len()` bytes. The chunk size used by the fragmenter (`make_fragments`, line 84) is `let chunk = mtu_payload.max(1);` where `mtu_payload` is passed in already reduced by the header: the transport computes it in `send_in_fragments` (transport.rs:377):

```rust
let payload_budget = max.saturating_sub(FRAG_HEADER_LEN).max(1);
let frags = self.fragmenter.make_fragments(&inst, payload_budget);
```

So with datagram budget `max`, each emitted fragment is at most `FRAG_HEADER_LEN + (max - FRAG_HEADER_LEN) = max` bytes — exact, with no slack wasted and no chance of exceeding the MTU. The 15-bit index cap (`MAX_FRAGMENT_INDEX = 0x7fff`, line 19) bounds an instruction to 32767 fragments.

### What the current crate does and the defect

`wire/src/lib.rs` serializes the WHOLE `Fragment` (header + payload) with postcard (`Fragment::encode`, lines 106-108: `postcard::to_allocvec(self)`), so the header size is variable (varints) and is *estimated* with a padded constant `FRAGMENT_HEADER_OVERHEAD = 24` (lines 33-35):

```rust
pub const FRAGMENT_HEADER_OVERHEAD: usize = 24;
```

and the chunk is `let chunk = mtu - FRAGMENT_HEADER_OVERHEAD;` (line 163), with the guard `if mtu <= FRAGMENT_HEADER_OVERHEAD { return Err(MtuTooSmall) }` (lines 143-148).

Defects of the estimate:
1. **Wastes payload.** The true postcard header is far smaller than 24 in the common case, so every datagram under-fills by up to ~20 bytes — more fragments than necessary for large repaints.
2. **Can still overflow for large `id`/`index`.** Postcard encodes `id: u64` as a LEB128 varint of 1..=10 bytes and `index: u16` as 1..=3 bytes, plus `final_: bool` = 1 byte, plus the `payload: Vec<u8>` LENGTH prefix as a varint of 1..=? bytes. The 24-byte budget assumed `payload` length varint ≤5 (per the doc comment, lines 33-35), which is true for chunk < 2^35. But the worst case is `id` varint 10 + `index` varint 3 + `final_` 1 + length varint 5 = 19, leaving 5 bytes of slack — so 24 is *currently* safe but only by a hardcoded margin, and it is fragile: it silently assumes the chunk-length varint never exceeds 5 bytes and that no field grows. It is an estimate the proptest happens to satisfy (mtu ≥ 30), not a derived bound.

### Precise change — compute the EXACT budget per (id, mtu)

Because the current crate postcard-encodes the whole `Fragment`, the header size depends on the actual `id` (its varint length) and on the chunk length's own varint length (a self-referential constraint: a bigger chunk needs a longer length-prefix varint, which shrinks the chunk). Two correct options; pick one.

**Option 1 (recommended, faithful to reference): switch to a fixed framing and an exact constant.** Replace postcard-encoding of `Fragment` with a hand-written fixed header, mirroring `moshers-ssp/src/fragment.rs`. Make `Fragment::encode` write `id.to_be_bytes()` (8) + a 2-byte `(final_ as u16) << 15 | (index & 0x7fff)` + `payload`, and `decode` parse the inverse, with `index` capped at `0x7fff`. Then:

```rust
/// Fixed fragment header: 8-byte BE id + 2-byte BE (final<<15 | index). Exact, not estimated.
pub const FRAGMENT_HEADER_OVERHEAD: usize = 10;
```

and in `fragment()` use `let chunk = mtu - FRAGMENT_HEADER_OVERHEAD;` (now exact: each emitted datagram is exactly `10 + chunk ≤ mtu`). Update the guard to `if mtu <= FRAGMENT_HEADER_OVERHEAD`. This makes the wire format byte-identical to the reference and removes all estimation. (Drop `final_: bool` from the postcard struct layout — it becomes the top bit of the 2-byte field — or keep the struct fields and only change encode/decode. Keeping the struct fields and changing only encode/decode is the smaller diff and is what the reference does: the struct has `last: bool`, encode folds it into the combined u16.)

**Option 2 (keep postcard framing): derive the exact per-id overhead.** If you must keep postcard `Fragment::encode`, compute the budget from the actual varint sizes rather than a flat 24. Add a varint-length helper and size the chunk so the *encoded* fragment fits exactly:

```rust
/// LEB128 varint byte length of a u64 (postcard's integer encoding).
fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 { v >>= 7; n += 1; }
    n
}

// Inside `fragment`, after computing `id`:
// Per-fragment fixed cost: id varint + index varint(<=3 for u16) + final_ bool(1).
// The payload itself is length-prefixed by a varint of `chunk`'s length; solve for chunk.
let fixed = varint_len(id) + /*index*/ 3 + /*bool*/ 1;
// Largest chunk c such that fixed + varint_len(c as u64) + c <= mtu.
let mut chunk = mtu.saturating_sub(fixed + 1); // assume 1-byte length to start
while fixed + varint_len(chunk as u64) + chunk > mtu {
    chunk -= 1;
}
if chunk == 0 {
    return Err(WireError::MtuTooSmall { mtu, min: fixed + 2 });
}
```

`index` is `u16`, postcard varint ≤ 3 bytes; using the constant 3 is the exact worst case for that field. This yields the maximal payload that still fits `mtu` exactly. Keep the `mtu <= FRAGMENT_HEADER_OVERHEAD` guard or replace with the `chunk == 0` check above.

Recommendation: **Option 1.** It matches the reference exactly, eliminates the self-referential varint solve, makes `FRAGMENT_HEADER_OVERHEAD` a true constant (10), and the existing wire proptest (`fragment_reassemble_roundtrip`, mtu ∈ 30..1500) still passes since `10 + chunk ≤ mtu` holds by construction. Update the wire tests that assert `fr.encode().unwrap().len() <= mtu` (lines 317, 373) — they will still hold and now with no wasted slack. Callers (`transport-iroh/src/lib.rs:204-207`, `DEFAULT_MAX_DATAGRAM = 1200`) are unaffected; they pass `max_datagram_size()` straight through and the fragmenter now packs tighter.

---

## Summary of files/functions to edit

- `crates/ssp/src/transport.rs`
  - `recv()` — A: clone base before `process_throwaway_until`, delete post-GC `.expect()` (lines 499-524). B: set `self.last_heard = now;` unconditionally after `Fragment::decode`/reassembly, remove it from the `NewState` arm (line 550). D: add version import + reject-on-mismatch before `process_acknowledgment_through`.
  - `send_empty_ack()` — C: add `saturating_add` and the `if new_num == back_num { bump ts } else { add }` dedup (lines 414-421).
  - `send_to_receiver()` — C: `back_num.saturating_add(1)` (line 393). D: stamp `protocol_version` in `send_in_fragments` (lines 429-435).
- `crates/wire/src/lib.rs`
  - D: add `pub const PROTOCOL_VERSION: u32 = 1;`, add `protocol_version: u32` as the first `Instruction` field, stamp it in `ack_only`, fix the two test literals.
  - E: switch `Fragment` encode/decode to the fixed 10-byte header and set `FRAGMENT_HEADER_OVERHEAD = 10` (Option 1), or derive the exact chunk via `varint_len` (Option 2).
- `crates/client/src/lib.rs`
  - B (corollary): fire the staleness/link-down reset on ANY decoded `RecvOutcome` (including `Duplicate`/`OutOfOrder`), not only `NewState`; preferably read liveness from the transport.
- `crates/ssp/src/testkit.rs` — no logic change required; `step()` (lines 209-214) discards the `RecvOutcome`, so the new version-mismatch/`last_heard` behavior is exercised transparently.
