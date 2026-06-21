# Mosh Transport / Send-Scheduler / Fragmentation — Ground-Truth Reference

Source of truth (read verbatim, mosh git `src/network/`):
- `transportsender.h`, `transportsender-impl.h`
- `transportstate.h`
- `transportfragment.h`, `transportfragment.cc`
- `networktransport.h`, `networktransport-impl.h`
- `network.h`, `network.cc` (constants, RTO/SRTT, MTU)
- `src/protobufs/transportinstruction.proto`
- `src/statesync/user.cc` (`UserStream::subtract`) — confirms rationalize semantics

This is the algorithm to replicate on top of **iroh/quinn QUIC datagrams**. We DROP: UDP socket, OCB/AES crypto (`Crypto::Session`), the `Packet` seq/nonce envelope, `timestamp`/`timestamp_reply` heartbeat fields, RTT estimation, port hopping, congestion-via-timestamp. **iroh owns the wire, the RTT, the encryption, and connectivity.** What we KEEP: the `Instruction` protobuf, the `sent_states` / `received_states` state-collapse logic, the tick() scheduler timers, and (optionally) the fragmenter.

---

## 0. The State contract (what `MyState` / `RemoteState` must provide)

Both the local (sender) state `MyState` (= `UserStream`) and the remote state `RemoteState` (= `Complete` terminal) are template params. The transport only ever calls this interface (from `statesync/user.h`, `statesync/completeterminal.h`):

```cpp
std::string diff_from( const State& existing ) const;   // serialize delta existing->this
std::string init_diff( void ) const;                    // == diff_from(default-constructed)
void apply_string( const std::string& diff );           // mutate self by applying delta
void subtract( const State* prefix ) ;                  // drop prefix from front (state collapse)
bool operator==( const State& x ) const;
bool compare( const State& other ) const;               // true == DIFFERS (used only in verbose verify)
void reset_input( void );                               // only MyState; clears pending input
```

`UserStream::subtract(prefix)` semantics (load-bearing for rationalize): it asserts `prefix` is an exact prefix of `this` and pops those leading `UserEvent`s off the front (`actions.pop_front()` per event). Special case: `subtract(this)` clears all actions. So "subtract the known-acked state" literally removes the already-acknowledged prefix of keystrokes, leaving only the un-acked tail. `diff` is then computed over that collapsed representation.

For Rust: `State` trait with `diff_from(&self, base: &Self) -> Vec<u8>`, `apply(&mut self, diff: &[u8])`, `subtract_prefix(&mut self, prefix: &Self)`, `PartialEq`. `compare` is only used in a verbose round-trip self-check; you can skip it.

---

## 1. Constants (EXACT, all milliseconds unless noted)

From `transportsender.h`:
```cpp
const int SEND_INTERVAL_MIN = 20;       // ms between frames (floor on frame interval)
const int SEND_INTERVAL_MAX = 250;      // ms between frames (ceiling)
const int ACK_INTERVAL = 3000;          // ms between empty (keep-alive) acks
const int ACK_DELAY = 100;              // ms before a delayed/coalesced data-ack
const int SHUTDOWN_RETRIES = 16;        // shutdown packets before giving up
const int ACTIVE_RETRY_TIMEOUT = 10000; // ms; only retransmit while peer heard-from recently
```
Default `SEND_MINDELAY = 8` (ms to coalesce a burst of input; set in ctor, overridable via `set_send_delay`).
`add_sent_state` queue cap: **32** sent states (drops from middle when exceeded).
`attempt_prospective_resend_optimization`: thresholds **1000** bytes / **100** bytes (see §2.4).
`make_chaff`: `CHAFF_MAX = 16` random bytes (DROP — iroh datagrams are already padded/encrypted; chaff was to hide plaintext length under OCB. Keep an empty `chaff` field or omit it).

From `network.h` / `network.cc`:
```cpp
static const unsigned int MOSH_PROTOCOL_VERSION = 2;     // "echo-ack"; put in Instruction; reject mismatches
static const uint64_t MIN_RTO = 50;     // ms
static const uint64_t MAX_RTO = 1000;   // ms
DEFAULT_SEND_MTU   = 500;   // fallback
DEFAULT_IPV4_MTU   = 1280;  // conservative (mobile tunneling); MTU = 1280 - 28 = 1252 usable
DEFAULT_IPV6_MTU   = 1280;  // MTU = 1280 - 64 = 1216 usable
// Connection::ADDED_BYTES = 8 (seqno/nonce) + 4 (timestamps) = 12  -> DROP under QUIC
// Crypto::Session::ADDED_BYTES = OCB tag/nonce overhead          -> DROP under QUIC
```

### 1.1 RTT / RTO — REPLACED by iroh, but you still need a `timeout()` and `SRTT`
`send_interval()` and `calculate_timers()` consume **`connection->get_SRTT()`** (double, ms) and **`connection->timeout()`** (RTO, ms). Mosh computes these from its own timestamp-echo (Jacobson/Karels):
```cpp
// init: SRTT = 1000, RTTVAR = 500, RTT_hit = false
// per sample R (ms), ignore R >= 5000:
//   first:  SRTT=R; RTTVAR=R/2; RTT_hit=true
//   else:   RTTVAR = 0.75*RTTVAR + 0.25*|SRTT-R|;  SRTT = 0.875*SRTT + 0.125*R
uint64_t Connection::timeout() {            // == RTO
  uint64_t RTO = lrint(ceil(SRTT + 4*RTTVAR));
  return clamp(RTO, MIN_RTO=50, MAX_RTO=1000);
}
```
**Under iroh:** quinn exposes RTT via `Connection::rtt() -> Duration` (smoothed). Map `SRTT_ms = conn.rtt().as_millis()` and synthesize `timeout()` either as quinn's PTO or as the same clamp `clamp(srtt + 4*rttvar, 50, 1000)` if you track your own RTTVAR. Simplest faithful shim: keep your own SRTT/RTTVAR EWMA off iroh RTT samples and reuse mosh's `timeout()` clamp verbatim. Do NOT just use 0; the timers below divide and add by these.

### 1.2 `send_interval()` — "two frames per RTT", clamped
```cpp
unsigned int send_interval() const {
  int SEND_INTERVAL = lrint(ceil(get_SRTT() / 2.0));   // half the RTT
  return clamp(SEND_INTERVAL, SEND_INTERVAL_MIN=20, SEND_INTERVAL_MAX=250);
}
```
Effective frame interval is `SRTT/2`, never faster than 20ms, never slower than 250ms.

---

## 2. State model & collapse (`sent_states`, `received_states`)

### 2.1 `TimestampedState<State>` (`transportstate.h`)
```cpp
template<class State> class TimestampedState {
public:
  uint64_t timestamp;   // ms (mosh frozen_timestamp)
  uint64_t num;         // sequence number of this state (0-based, monotonic; uint64_t(-1) == shutdown)
  State state;
  TimestampedState(uint64_t s_timestamp, uint64_t s_num, const State& s_state);
};
```

### 2.2 Sender bookkeeping (`TransportSender<MyState>`, `transportsender.h`)
```cpp
Connection* connection;
MyState current_state;                                  // the live, latest local state
using sent_states_type = std::list<TimestampedState<MyState>>;
sent_states_type sent_states;
  // INVARIANT: front() == the most-recent state KNOWN-ACKED by receiver (the "base").
  //            back()  == the last state we transmitted.
  //            never empty.
typename sent_states_type::iterator assumed_receiver_state; // somewhere in [begin..end);
                                                            // our best guess of what the peer has
Fragmenter fragmenter;
uint64_t next_ack_time, next_send_time;                 // wall-clock ms deadlines; uint64_t(-1) == "never"
uint64_t ack_num;        // newest RemoteState num we have received (what WE will ack to peer)
bool pending_data_ack;   // peer sent us data -> we owe a fast (ACK_DELAY) ack
uint64_t last_heard;     // last time we received any new state from peer
uint64_t mindelay_clock; // time of first pending change to current_state; uint64_t(-1) == none
unsigned int SEND_MINDELAY; // = 8
bool shutdown_in_progress; int shutdown_tries; uint64_t shutdown_start;
```
Ctor: `sent_states = { TimestampedState(now, 0, initial_state) }`, `assumed_receiver_state = begin()`, `next_ack_time = next_send_time = now`, `ack_num = 0`, `mindelay_clock = -1`, `shutdown_start = -1`.

### 2.3 `add_sent_state` — append + drop-from-middle cap
```cpp
void add_sent_state(uint64_t ts, uint64_t num, MyState& state) {
  sent_states.push_back(TimestampedState(ts, num, state));
  if (sent_states.size() > 32) {            // queue cap
    auto last = sent_states.end();
    for (int i=0;i<16;i++) last--;          // 16th-from-end
    sent_states.erase(last);                // erase from MIDDLE (keeps base + recent tail)
  }
}
```
Note: drops a *middle* element, never front (base) or the recent tail. This keeps the acked base and the freshest states while bounding memory.

### 2.4 `update_assumed_receiver_state` — "benefit of the doubt"
```cpp
void update_assumed_receiver_state() {
  uint64_t now = timestamp();
  assumed_receiver_state = sent_states.begin();   // start at known-acked base
  auto i = ++sent_states.begin();
  while (i != end) {
    // assume peer HAS state i if we sent it recently enough to still be in flight/acked-soon
    if ((now - i->timestamp) < connection->timeout() + ACK_DELAY)
      assumed_receiver_state = i;                  // advance the guess forward
    else
      return;                                      // older-than-RTO: stop; everything past is "unknown"
    i++;
  }
}
```
So `assumed_receiver_state` = the newest state we believe the peer already has (acked base, plus any state sent within `RTO + 100ms`).

### 2.5 `rationalize_states` — collapse common prefix (called every tick via `calculate_timers`)
```cpp
void rationalize_states() {
  const MyState* known = &sent_states.front().state;   // the acked base
  current_state.subtract(known);                       // collapse live state
  for (auto i = sent_states.rbegin(); i != rend(); i++)
    i->state.subtract(known);                          // collapse every stored state by same base
}
```
This is the heart of mosh: every stored state and the live state are re-expressed *relative to the acked base*, so diffs stay small and old keystrokes that were already acked are physically dropped from the buffers. (For `UserStream`, `subtract` pops the acked keystroke prefix off each deque.)

### 2.6 `attempt_prospective_resend_optimization` — prophylactic full resend
```cpp
void attempt_prospective_resend_optimization(std::string& proposed_diff) {
  if (assumed_receiver_state == sent_states.begin()) return;  // already diffing vs base; nothing to do
  std::string resend_diff = current_state.diff_from(sent_states.front().state); // diff vs ACKED base
  // resend from base if it's shorter, OR only modestly longer (within 100B AND under 1000B total)
  if ( resend_diff.size() <= proposed_diff.size()
       || (resend_diff.size() < 1000 && resend_diff.size() - proposed_diff.size() < 100) ) {
    assumed_receiver_state = sent_states.begin();  // retarget to base
    proposed_diff = resend_diff;                    // and send the bigger-but-self-contained diff
  }
}
```
Rationale: if a recent packet may have been lost, recomputing the diff against the *known-acked* base (instead of the *assumed* state) makes the packet self-healing without needing the in-flight one. The thresholds keep us from doing this when it would bloat the packet a lot. Note `resend_diff.size() - proposed_diff.size()` is unsigned subtraction; it's only reached when `resend_diff > proposed_diff`, so it's the intended positive delta.

### 2.7 KEY PROPERTY: retransmit the NEWEST state recomputed against CURRENT, never stale
Mosh never resends an old serialized diff. The diff sent each tick is **always** `current_state.diff_from(assumed_receiver_state->state)` (then maybe retargeted to base by §2.6). Because `current_state` is the live latest state, a retransmission automatically carries everything up to *now*, not the stale snapshot from when the lost packet was first sent. Superseded intermediate states are simply never re-serialized — they exist only to track acks and to be `subtract`ed away.

### 2.8 `process_acknowledgment_through(ack_num)` — drop everything below the ack
Called on recv with `inst.ack_num()` (what the peer says it has of OUR stream).
```cpp
void process_acknowledgment_through(uint64_t ack_num) {
  // ignore stale ack if we've already culled the state it names
  bool present = any(sent_states, .num == ack_num);
  if (present)
    erase every i in sent_states where i->num < ack_num;   // front() becomes the acked base
  assert(!sent_states.empty());
}
```
After this, `sent_states.front().num == ack_num` becomes the new base (unless ack was stale/already-culled, in which case it's a no-op).

---

## 3. The seq/ack envelope — `Instruction` protobuf

`src/protobufs/transportinstruction.proto` (proto2, `optimize_for = LITE_RUNTIME`):
```proto
message Instruction {
  optional uint32 protocol_version = 1;   // must == MOSH_PROTOCOL_VERSION (2); recv rejects mismatch
  optional uint64 old_num = 2;            // base num this diff is computed FROM (assumed_receiver_state->num)
  optional uint64 new_num = 3;            // num this diff PRODUCES (the new state); uint64_t(-1) == shutdown
  optional uint64 ack_num = 4;            // newest RemoteState num WE have received (acking the peer)
  optional uint64 throwaway_num = 5;      // sender's acked base num; tells peer it may drop received_states < this
  optional bytes  diff = 6;               // serialized delta from old_num-state to new_num-state ("" == pure ack)
  optional bytes  chaff = 7;              // random length-hiding padding (DROP under QUIC)
}
```
Set in `send_in_fragments`:
```cpp
inst.set_protocol_version(MOSH_PROTOCOL_VERSION);
inst.set_old_num( assumed_receiver_state->num );  // diff base
inst.set_new_num( new_num );                       // target state (or -1 for shutdown)
inst.set_ack_num( ack_num );                       // our receiver's latest num
inst.set_throwaway_num( sent_states.front().num ); // our acked base -> peer's GC watermark
inst.set_diff( diff );
inst.set_chaff( make_chaff() );                    // DROP
```
Semantics summary:
- `old_num` → `new_num` with `diff` is an idempotent "apply diff to the state numbered old_num to get the state numbered new_num". Receiver requires it already has `old_num` and lacks `new_num`, else drops (idempotency / replay safety).
- `ack_num` is the cumulative ack of the *reverse* stream (this side's view of remote).
- `throwaway_num` is a GC hint: "I've collapsed my sent_states to base N; you can forget your received_states below N."
- A packet with empty `diff` is a pure ack/keepalive (still carries fresh `ack_num`/`throwaway_num`).

---

## 4. Fragmentation

### 4.1 MTU budget
Usable per-fragment payload = `connection->get_MTU() - Network::Connection::ADDED_BYTES - Crypto::Session::ADDED_BYTES`, then inside `make_fragments`: `MTU -= Fragment::frag_header_len`.
- `get_MTU()` = `1280 - 28` (v4) or `1280 - 64` (v6) → 1252 / 1216.
- `ADDED_BYTES` = 12, `Crypto::Session::ADDED_BYTES` = OCB overhead. **Both DROP under QUIC** (iroh datagrams handle framing+crypto). For iroh, your budget = `endpoint.max_datagram_size()` (quinn `Connection::max_datagram_size() -> Option<usize>`) minus your `frag_header_len` (10).

### 4.2 `Fragment` (`transportfragment.h`/`.cc`)
```cpp
class Fragment {
  static const size_t frag_header_len = sizeof(uint64_t) + sizeof(uint16_t); // = 10 bytes
  uint64_t id;            // instruction id (groups fragments of one Instruction)
  uint16_t fragment_num;  // 0-based index within the instruction
  bool     final;         // last fragment flag
  bool     initialized;
  std::string contents;   // this fragment's slice of the compressed Instruction bytes
};
```
Wire format (`Fragment::tostring`, big-endian):
```
[ uint64 id (BE) ][ uint16 combined (BE) ][ contents... ]
combined = (final << 15) | fragment_num     // top bit = final, low 15 bits = fragment_num
```
`fatal_assert(!(fragment_num & 0x8000))` → **max 32767 fragments** per instruction (the "effective limit on size of a terminal screen change or buffered user input").
Parse (`Fragment(const std::string&)`): require `size >= 10`; read BE id (8B) + BE combined (2B); `final = (combined>>15)&1`; `fragment_num = combined & 0x7FFF`; rest is `contents`.

### 4.3 `Fragmenter` (sender side)
```cpp
class Fragmenter {
  uint64_t next_instruction_id;   // starts 0
  Instruction last_instruction;   // ctor sets old_num=-1, new_num=-1
  size_t last_MTU;                // starts -1
  std::vector<Fragment> make_fragments(const Instruction& inst, size_t MTU);
  uint64_t last_ack_sent() const { return last_instruction.ack_num(); }
};
```
`make_fragments(inst, MTU)`:
1. `MTU -= frag_header_len;`
2. **Bump `next_instruction_id`** iff ANY envelope field changed vs `last_instruction`: `old_num | new_num | ack_num | throwaway_num | chaff | protocol_version | MTU` differs. (i.e. a genuinely new instruction gets a new id; an identical retransmit reuses the id so the receiver's `FragmentAssembly` dedups it.)
3. If `old_num` and `new_num` are unchanged, `assert(inst.diff() == last_instruction.diff())` (same state pair must imply same diff).
4. `last_instruction = inst; last_MTU = MTU;`
5. `payload = compress( inst.SerializeAsString() )` — **zlib-compress the serialized protobuf** (mosh `Compressor`). Then slice into ≤MTU chunks; each chunk → `Fragment(id, fragment_num++, final, chunk)`; last chunk `final=true`. An empty payload yields zero fragments (won't happen in practice — serialized Instruction is never empty).

### 4.4 `FragmentAssembly` (receiver side, reassembly + dedup)
```cpp
class FragmentAssembly {
  std::vector<Fragment> fragments;
  uint64_t current_id;          // -1
  int fragments_arrived, fragments_total; // 0, -1
  bool add_fragment(Fragment& f);  // returns true when complete
  Instruction get_assembly();
};
```
`add_fragment(f)`:
- If `f.id != current_id` → brand-new instruction: clear, `resize(f.fragment_num+1)`, store, `arrived=1`, `total=-1`, `current_id=f.id`. (Switching id mid-way silently discards a partial older instruction.)
- Else (same id): if slot already filled, `assert(existing == f)` (idempotent duplicate); else store, grow vector if needed, `arrived++`.
- If `f.final` → `total = f.fragment_num + 1`, resize to total.
- Return `arrived == total`.

`get_assembly()`: `assert(arrived == total)`; concatenate all `fragments[i].contents`; `fatal_assert(ret.ParseFromString(uncompress(encoded)))`; reset state; return `Instruction`. (Decompress THEN parse — compression wraps the whole serialized protobuf, not per-fragment.)

### 4.5 Rust mapping options (our deviation)
Two valid choices for oversized state, you pick per size:
- **Fragmenter path (faithful):** reimplement the 10-byte BE header + id/dedup over iroh **unreliable datagrams**. Keep it for typical states (a few hundred bytes to a few KB). Compress with `flate2` to match (or drop compression and bump protocol — your call, but then both ends must agree).
- **One-shot reliable stream (pragmatic):** if a single Instruction exceeds the datagram budget (huge terminal repaint), open a QUIC uni-stream, write the whole compressed Instruction, and let QUIC do reliable delivery + reassembly. This subsumes `FragmentAssembly` for the big case. Keep datagrams for the steady keystroke/small-diff path so you preserve mosh's lossy-but-latest semantics (a lost datagram is fine; the next tick resends current state). Do NOT send the steady stream over a reliable QUIC stream — that reintroduces head-of-line blocking that mosh deliberately avoids.

---

## 5. The send scheduler

### 5.1 `calculate_timers()` (run at the top of both `tick()` and `wait_time()`)
```cpp
void calculate_timers() {
  uint64_t now = timestamp();
  update_assumed_receiver_state();   // §2.4
  rationalize_states();              // §2.5

  // owe a fast data-ack? pull next_ack_time in to now+100ms
  if (pending_data_ack && next_ack_time > now + ACK_DELAY)
    next_ack_time = now + ACK_DELAY;

  if ( !(current_state == sent_states.back().state) ) {
    // (A) we have NEW unsent input
    if (mindelay_clock == -1) mindelay_clock = now;          // start coalescing window
    next_send_time = max( mindelay_clock + SEND_MINDELAY,     // wait >=8ms to coalesce
                          sent_states.back().timestamp + send_interval() ); // and respect frame rate
  } else if ( !(current_state == assumed_receiver_state->state)
              && last_heard + ACTIVE_RETRY_TIMEOUT > now ) {
    // (B) nothing new, but peer may not have our latest -> retransmit at frame rate
    next_send_time = sent_states.back().timestamp + send_interval();
    if (mindelay_clock != -1)
      next_send_time = max(next_send_time, mindelay_clock + SEND_MINDELAY);
  } else if ( !(current_state == sent_states.front().state)
              && last_heard + ACTIVE_RETRY_TIMEOUT > now ) {
    // (C) peer assumed-current but not yet ACKed our base -> slow retransmit at RTO+ACK_DELAY
    next_send_time = sent_states.back().timestamp + connection->timeout() + ACK_DELAY;
  } else {
    // (D) fully in sync (or peer silent > 10s) -> nothing to send
    next_send_time = -1;   // never
  }

  // shutdown / we-need-to-ack-shutdown: ack at frame rate
  if (shutdown_in_progress || ack_num == uint64_t(-1))
    next_ack_time = sent_states.back().timestamp + send_interval();
}
```
Notes:
- `last_heard + ACTIVE_RETRY_TIMEOUT > now` gates ALL retransmission: if we haven't heard from the peer in 10s, stop retransmitting (don't blast a dead/roaming peer; mosh waits for it to come back).
- Branch (A) is "new input" → coalesce ≥`SEND_MINDELAY`(8ms) but never faster than `send_interval()` since last send. This is the input-batching that gives mosh its smoothness.
- Branches (B)/(C) are pure retransmission of state the peer hasn't confirmed, at decreasing urgency.

### 5.2 `tick()` — the send decision (REPLICATE THIS)
```cpp
void tick() {
  calculate_timers();
  if (!connection->get_has_remote_addr()) return;     // (iroh: if (!connected) return;)
  uint64_t now = timestamp();
  if (now < next_ack_time && now < next_send_time) return;   // nothing due yet

  std::string diff = current_state.diff_from(assumed_receiver_state->state); // §2.7
  attempt_prospective_resend_optimization(diff);       // §2.6 (may retarget to base + replace diff)
  // [verbose] optional round-trip self-verification — skip in prod

  if (diff.empty()) {
    if (now >= next_ack_time) { send_empty_ack(); mindelay_clock = -1; }
    if (now >= next_send_time){ next_send_time = -1; mindelay_clock = -1; }
  } else if (now >= next_send_time || now >= next_ack_time) {
    send_to_receiver(diff);   // sends the data packet (which also carries the ack)
    mindelay_clock = -1;
  }
}
```
Key: a data send (`send_to_receiver`) doubles as an ack (it carries `ack_num`/`throwaway_num`), so we only send a *separate* empty ack when `diff` is empty.

### 5.3 `send_to_receiver(diff)` — assign new_num, store, transmit
```cpp
void send_to_receiver(const std::string& diff) {
  uint64_t new_num = (current_state == sent_states.back().state)
                       ? sent_states.back().num         // resend of existing state
                       : sent_states.back().num + 1;    // genuinely new state
  if (shutdown_in_progress) new_num = uint64_t(-1);     // shutdown sentinel

  if (new_num == sent_states.back().num)
    sent_states.back().timestamp = timestamp();         // just bump ts (retransmit)
  else
    add_sent_state(timestamp(), new_num, current_state);// append new state

  send_in_fragments(diff, new_num);                     // build Instruction + fragment + send

  assumed_receiver_state = --sent_states.end();         // we now assume peer will have back()
  next_ack_time  = timestamp() + ACK_INTERVAL;          // pushed out 3s (data carried the ack)
  next_send_time = uint64_t(-1);
}
```

### 5.4 `send_empty_ack()` — keepalive / pure ack
```cpp
void send_empty_ack() {
  uint64_t now = timestamp();        // assert(now >= next_ack_time)
  uint64_t new_num = sent_states.back().num + 1;
  if (shutdown_in_progress) new_num = uint64_t(-1);
  add_sent_state(now, new_num, current_state);  // empty acks also bump the state list
  send_in_fragments("", new_num);               // empty diff
  next_ack_time  = now + ACK_INTERVAL;          // next keepalive in 3s
  next_send_time = uint64_t(-1);
}
```
(Surprising: an empty ack creates a new sent_state with an incremented num even though `current_state` equals the previous state's content. It's the same `current_state` value; `new_num` advances so the peer's ack of it confirms liveness. The 32-cap GC keeps this bounded.)

### 5.5 `send_in_fragments(diff, new_num)` — build + emit
```cpp
void send_in_fragments(const std::string& diff, uint64_t new_num) {
  Instruction inst;
  inst.set_protocol_version(MOSH_PROTOCOL_VERSION);
  inst.set_old_num(assumed_receiver_state->num);
  inst.set_new_num(new_num);
  inst.set_ack_num(ack_num);
  inst.set_throwaway_num(sent_states.front().num);
  inst.set_diff(diff);
  inst.set_chaff(make_chaff());                  // DROP under QUIC
  if (new_num == uint64_t(-1)) shutdown_tries++; // count shutdown attempts

  auto fragments = fragmenter.make_fragments(inst, MTU_budget);
  for (auto& f : fragments) connection->send(f.tostring());
  pending_data_ack = false;
}
```

### 5.6 `wait_time()` — for the event loop
```cpp
int wait_time() {
  calculate_timers();
  uint64_t next = min(next_ack_time, next_send_time);
  if (!connection->get_has_remote_addr()) return INT_MAX;   // not connected: sleep forever
  uint64_t now = timestamp();
  return (next > now) ? (next - now) : 0;
}
```
Drive your async loop with this: `tokio::time::sleep(Duration::from_millis(wait_time()))` raced against datagram-recv readiness.

---

## 6. The receive path (`Transport::recv`, `networktransport-impl.h`)

Receiver bookkeeping:
```cpp
std::list<TimestampedState<RemoteState>> received_states; // ctor: {(now,0,initial_remote)}; sorted by num
uint64_t receiver_quench_timer;        // 0
RemoteState last_receiver_state;        // snapshot at last get_remote_diff()
FragmentAssembly fragments;
```
`recv()` (REPLICATE; the per-datagram body):
```cpp
void recv() {
  std::string s = connection.recv();                 // (iroh: one datagram)
  Fragment frag(s);
  if (!fragments.add_fragment(frag)) return;         // incomplete -> wait for more
  Instruction inst = fragments.get_assembly();

  if (inst.protocol_version() != MOSH_PROTOCOL_VERSION)
    throw NetworkException("mosh protocol version mismatch", 0);

  sender.process_acknowledgment_through(inst.ack_num());          // §2.8 (peer acks OUR stream)
  connection.set_last_roundtrip_success(sender.get_sent_state_acked_timestamp()); // RTT bookkeeping (DROP/replace)

  // (a) idempotency: already have new_num? drop.
  for (auto& i : received_states) if (inst.new_num() == i.num) return;

  // (b) must have the base old_num, else drop (out-of-order / replayed). Security-sensitive.
  auto reference_state = find(received_states, .num == inst.old_num());
  if (reference_state == end) return;

  process_throwaway_until(inst.throwaway_num());      // §6.1 GC our received_states < throwaway_num

  // (c) queue cap 1024 with 15s quench window (anti-DoS)
  if (received_states.size() > 1024) {
    uint64_t now = timestamp();
    if (now < receiver_quench_timer) return;          // drop this state
    receiver_quench_timer = now + 15000;              // else allow, set next quench
  }

  // (d) build new state = reference + diff
  TimestampedState new_state = *reference_state;
  new_state.timestamp = timestamp();
  new_state.num = inst.new_num();
  if (!inst.diff().empty()) new_state.state.apply_string(inst.diff());

  // (e) insert sorted by num (handles out-of-order)
  for (auto i = received_states.begin(); i != end; i++)
    if (i->num > new_state.num) { received_states.insert(i, new_state); return; } // OUT-OF-ORDER, done
  received_states.push_back(new_state);               // in-order tail

  sender.set_ack_num(received_states.back().num);     // we will now ack this num back
  sender.remote_heard(new_state.timestamp);           // last_heard = now -> re-enables retransmit & RTT
  if (!inst.diff().empty()) sender.set_data_ack();     // got data -> owe a fast ack (ACK_DELAY)
}
```
Critical ordering subtleties:
- `process_acknowledgment_through` runs **before** the dedup/old-num checks, so even an out-of-order or duplicate packet still advances our ack culling (it carries a valid `ack_num`).
- The `old_num` presence check (b) is the idempotency/replay defense: a diff can only be applied to a base we actually hold; this prevents desync and is "security-sensitive."
- Out-of-order insert (e) returns early without setting `ack_num`/`remote_heard`/`data_ack` — those only fire when the newly-received state lands at the tail (i.e. it's the newest in-order state).

### 6.1 `process_throwaway_until(throwaway_num)`
```cpp
void process_throwaway_until(uint64_t throwaway_num) {
  erase every i in received_states where i->num < throwaway_num;
  fatal_assert(received_states.size() > 0);
}
```
Driven by the sender's `throwaway_num` (its acked base). Mosh deliberately GCs the *receiver* list only on the sender's instruction (not from the middle), because dropping a received state we'd already ACKed would be wrong.

### 6.2 `get_remote_diff()` — consume the latest remote state (called by app, not transport)
```cpp
std::string get_remote_diff() {
  std::string ret = received_states.back().state.diff_from(last_receiver_state);
  const RemoteState* oldest = &received_states.front().state;
  for (auto i = received_states.rbegin(); i != rend(); i++) i->state.subtract(oldest); // collapse
  last_receiver_state = received_states.back().state;
  return ret;
}
```
Returns the delta from "what the app last saw" to "newest received remote state," then rationalizes the received list against its oldest element (mirror of §2.5 for the receive side).

---

## 7. Shutdown handshake

State/flags (`transportsender.h` getters):
```cpp
void start_shutdown();              // sets shutdown_in_progress=true, shutdown_start=now (once)
bool get_shutdown_in_progress();    // we are trying to close
bool get_shutdown_acknowledged();   // sent_states.front().num == uint64_t(-1)  -> peer ACKed our shutdown
bool get_counterparty_shutdown_acknowledged(); // fragmenter.last_ack_sent() == uint64_t(-1)
                                               // -> WE have sent an ack whose ack_num == -1 (acking peer's shutdown)
bool shutdown_ack_timed_out();      // see below
```
Mechanism:
1. **Signal:** once `shutdown_in_progress`, every outgoing Instruction sets `new_num = uint64_t(-1)` (the shutdown sentinel state number) — see `send_to_receiver`/`send_empty_ack`/`send_in_fragments`. `shutdown_tries++` each time a `new_num==-1` packet is built.
2. **Speed:** `calculate_timers` sets `next_ack_time = sent_states.back().timestamp + send_interval()` while shutting down (or while `ack_num==-1`), so shutdown packets go out at frame rate, not the 3s keepalive rate.
3. **Peer side:** when a peer receives `new_num == -1`, that state enters its `received_states` with `num = -1`; it then `set_ack_num(-1)` and will reply with `ack_num = -1`. The fragmenter records that outgoing `ack_num` in `last_instruction`; `get_counterparty_shutdown_acknowledged()` becomes true once we've emitted an `ack_num == -1` (i.e. we've acknowledged the peer's shutdown).
4. **Our confirmation:** when the peer acks our shutdown, `process_acknowledgment_through(-1)` culls `sent_states` so `front().num == -1` → `get_shutdown_acknowledged()` true → we may close cleanly.
5. **Give up:** 
```cpp
bool shutdown_ack_timed_out() {
  if (!shutdown_in_progress) return false;
  if (shutdown_tries >= SHUTDOWN_RETRIES /*16*/) return true;
  if (timestamp() - shutdown_start >= ACTIVE_RETRY_TIMEOUT /*10000ms*/) return true;
  return false;
}
```
So: retransmit shutdown sentinel at frame rate, up to 16 tries or 10s, until peer acks (`shutdown_acknowledged`) or we time out.
6. `current_state` is frozen during shutdown: `get_current_state()`/`set_current_state()` both `assert(!shutdown_in_progress)`.

**iroh mapping:** you can either replicate this `-1`-sentinel handshake over datagrams (faithful, survives loss), or piggyback on QUIC's own close (`Connection::close(code, reason)`) once you've confirmed the last state was acked. Recommended hybrid: send the `new_num=-1` sentinel a couple of times (so the peer flushes the final terminal state), then issue a graceful `connection.close()`; treat `shutdown_ack_timed_out` (16 tries / 10s) as the hard fallback to force-close.

---

## 8. Rust / iroh implementation notes & deviations

- **Datagram budget:** quinn `Connection::max_datagram_size() -> Option<usize>`. Subtract your `frag_header_len` (10 if you keep the BE header). If `None` (peer disabled datagrams) → must use streams.
- **RTT:** quinn `Connection::rtt() -> Duration` (smoothed). Feed it into the same `SRTT/2` (clamped 20..250) for `send_interval`, and into a `timeout()` shim (`clamp(srtt + 4*rttvar, 50, 1000)`) for the (B)/(C)/`update_assumed_receiver_state` thresholds. Don't pass 0.
- **Time:** mosh uses a monotonic `frozen_timestamp()` (ms). Use `tokio::time::Instant` deltas in ms; store deadlines as `Instant` or `u64` ms. `uint64_t(-1)` "never" → `Option<Instant>::None` or `u64::MAX`.
- **`num` sentinel:** `uint64_t(-1)` == `u64::MAX`. Keep it as the shutdown sentinel; it sorts after all real nums (good, the `i->num > new_state.num` insert still works).
- **Compression:** mosh zlib-compresses `inst.SerializeAsString()` before fragmenting and decompresses before `ParseFromString`. Match with `flate2` (zlib) if you want wire-compat with a reference, or drop it and bump your own protocol version — but be consistent on both ends, and note `FragmentAssembly::get_assembly` decompresses the *concatenation*, not per-fragment.
- **DROP entirely:** `Packet`/`Message` seq+nonce+timestamp envelope, `Crypto::Session`/OCB, `make_chaff`, port hopping, `congestion_experienced`/timestamp penalty, `set_last_roundtrip_success` (or repurpose for stats). iroh provides connectivity, encryption, NAT traversal, RTT.
- **Reliable big states:** for an Instruction whose compressed size exceeds the datagram budget, prefer a one-shot QUIC uni-stream (write-all + finish) over many datagrams; the receiver reads-to-end, decompresses, `ParseFromString`-equivalent, and feeds it through the same `recv()` body (skip `FragmentAssembly`). Keep small steady-state diffs on **datagrams** to preserve mosh's "lossy, always-latest" property.
- **`pending_data_ack` / `ACK_DELAY`:** preserve the 100ms coalesced data-ack and 3000ms keepalive — they're what keep idle bandwidth near-zero while still giving fast echo confirmation.

### 8.1 Minimal happy-path send loop (Rust pseudocode)
```rust
loop {
    transport.calculate_timers();              // update_assumed + rationalize + recompute deadlines
    let wait = transport.wait_time();          // ms until next_ack or next_send
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(wait)) => {}
        datagram = conn.read_datagram() => {
            transport.recv(datagram?);          // §6 body; updates ack_num, remote_heard, data_ack
        }
        // local input events also wake us; they mutate transport.current_state
    }
    transport.tick();                           // §5.2: decide empty-ack vs data send, build+emit
    if transport.shutdown_in_progress() &&
       (transport.shutdown_acknowledged() || transport.shutdown_ack_timed_out()) {
        conn.close(0u32.into(), b"bye");
        break;
    }
}
```

### 8.2 `tick()` pseudocode (condensed, the part we must match)
```
calculate_timers()                         // assumed-recv state + rationalize + timers
if !connected: return
now = mono_ms()
if now < next_ack_time and now < next_send_time: return
diff = current_state.diff_from(assumed_receiver_state.state)
attempt_prospective_resend_optimization(&mut diff)   // maybe retarget to acked base
if diff.is_empty():
    if now >= next_ack_time:  send_empty_ack(); mindelay_clock = None
    if now >= next_send_time: next_send_time = NEVER; mindelay_clock = None
else if now >= next_send_time or now >= next_ack_time:
    send_to_receiver(diff)                  // assign new_num, store, fragment+emit, push acks 3s out
    mindelay_clock = None
```

### 8.3 `recv()` pseudocode (condensed)
```
frag = parse_fragment(datagram)             // 10B BE header: id, (final<<15)|fragnum
if !assembly.add_fragment(frag): return     // dedup by id; wait for final
inst = assembly.get_assembly()              // decompress -> protobuf parse
if inst.protocol_version != 2: error
sender.process_acknowledgment_through(inst.ack_num)   // cull our sent_states < ack
if received_states.any(|s| s.num == inst.new_num): return   // dup
ref = received_states.find(|s| s.num == inst.old_num)?      // must hold base, else drop (replay guard)
process_throwaway_until(inst.throwaway_num)                 // GC received_states < watermark
if received_states.len() > 1024 and quench-window-open: return
new = ref.clone(); new.num = inst.new_num; new.ts = now
if !inst.diff.is_empty(): new.state.apply_string(inst.diff)
insert new into received_states sorted-by-num
if new is now the tail (newest in-order):
    sender.set_ack_num(new.num)
    sender.remote_heard(new.ts)            // re-enables retransmit + feeds RTT
    if !inst.diff.is_empty(): sender.set_data_ack()  // owe fast ack in 100ms
```

---

## 9. Gotchas / version-specific

- `MOSH_PROTOCOL_VERSION = 2` ("bumped for echo-ack"). Receiver hard-rejects mismatches.
- `fragment_num` is **15-bit** (`& 0x7FFF`); top bit is `final`. Hard cap 32767 fragments/instruction (`fatal_assert`).
- Header is **big-endian** (`htobe64`/`htobe16`), header length **10 bytes**.
- Compression wraps the WHOLE serialized Instruction and spans all fragments; decompress after concatenation, not per-fragment.
- `attempt_prospective_resend_optimization` uses **unsigned** size subtraction; safe only because the branch guarantees `resend_diff.size() > proposed_diff.size()` there.
- Empty acks still advance `new_num` and append a sent_state (bounded by the 32-cap drop-from-middle).
- `assumed_receiver_state` is an iterator into `sent_states`; after `rationalize_states`/`add_sent_state`/erase you must recompute it (mosh recomputes it fresh in `update_assumed_receiver_state` each `calculate_timers`). In Rust, store it as an index/num, not a reference, and re-resolve each tick.
- All retransmission is gated by `last_heard + 10000ms > now`; a long-silent peer stops outbound retransmits entirely (mosh waits for the peer to reappear / roam).
- `wait_time()` returns `INT_MAX` when not connected — don't busy-loop before the iroh connection is established.
- The same `Connection::send` carries both data and ack; a standalone empty ack is sent only when the computed diff is empty.
