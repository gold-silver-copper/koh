//! The generic SSP [`Transport`]: one per peer, carrying the local state out and the
//! remote state in. A direct port of mosh's `TransportSender` + `Transport::recv`,
//! restructured as a pure, clock-injected state machine (no I/O, no async).

use std::collections::VecDeque;

use rmosh_wire::{Fragment, FragmentAssembly, Fragmenter, Instruction, PROTOCOL_VERSION};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::trace;

use crate::{
    RttEstimator, SyncState, ACK_DELAY, ACK_INTERVAL, ACTIVE_RETRY_TIMEOUT, NEVER,
    RECEIVED_STATES_CAP, RECEIVER_QUENCH_MS, SEND_MINDELAY, SENT_STATES_CAP, SHUTDOWN_RETRIES,
    SHUTDOWN_SENTINEL,
};

/// A state snapshot tagged with its sequence number and the wall-clock ms it was created.
#[derive(Debug, Clone)]
pub struct TimestampedState<S> {
    pub timestamp: u64,
    pub num: u64,
    pub state: S,
}

/// Outcome of feeding one datagram to [`Transport::recv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvOutcome {
    /// Fragment buffered; the instruction it belongs to is not yet complete.
    Incomplete,
    /// A new, newest-in-order remote state was applied. The app should react.
    NewState,
    /// An older (out-of-order) state was inserted; the newest state is unchanged.
    OutOfOrder,
    /// Already had this `new_num`; nothing applied (still processed the ack).
    Duplicate,
    /// The diff's base (`old_num`) is not in our `received_states`; dropped (replay guard).
    MissingBase,
    /// Dropped by the anti-DoS quench window.
    Quenched,
}

/// One synchronization channel to a single peer.
///
/// `Local` is the state this side authors and sends (`UserInput` on the client,
/// `TerminalScreen` on the server). `Remote` is the state it receives.
pub struct Transport<Local: SyncState, Remote: SyncState> {
    // ---- sender side (our authoritative local state) ----
    current_state: Local,
    /// Front = most-recent state known-acked by the peer (the diff base). Back = last
    /// transmitted. Never empty.
    sent_states: VecDeque<TimestampedState<Local>>,
    /// `num` of the newest sent state we believe the peer already has.
    assumed_receiver_num: u64,
    fragmenter: Fragmenter,
    next_ack_time: u64,
    next_send_time: u64,
    /// Newest remote `num` we have received in order — what we advertise as our ack.
    ack_num: u64,
    /// The most recent ack value we actually put on the wire (for shutdown bookkeeping).
    last_ack_sent: u64,
    pending_data_ack: bool,
    last_heard: u64,
    /// Start of the current input-coalescing window, or [`NEVER`] when none is pending.
    mindelay_clock: u64,
    // ---- shutdown ----
    shutdown_in_progress: bool,
    shutdown_tries: u32,
    shutdown_start: u64,
    // ---- receiver side (peer's remote state) ----
    received_states: Vec<TimestampedState<Remote>>,
    receiver_quench_timer: u64,
    assembly: FragmentAssembly,
    /// Snapshot of the remote state the app last consumed via [`get_remote_diff`](Transport::get_remote_diff).
    last_delivered_remote: Remote,
    // ---- shared ----
    rtt: RttEstimator,
    connected: bool,
    /// Datagram payload budget (bytes). Updated from `Connection::max_datagram_size()`.
    mtu: usize,
}

impl<Local: SyncState, Remote: SyncState> Transport<Local, Remote> {
    /// Create a transport at time `now` (ms). `mtu` is the datagram payload budget.
    pub fn new(now: u64, mtu: usize) -> Self {
        let mut sent_states = VecDeque::new();
        sent_states.push_back(TimestampedState {
            timestamp: now,
            num: 0,
            state: Local::default(),
        });
        let received_states = vec![TimestampedState {
            timestamp: now,
            num: 0,
            state: Remote::default(),
        }];
        Transport {
            current_state: Local::default(),
            sent_states,
            assumed_receiver_num: 0,
            fragmenter: Fragmenter::new(),
            next_ack_time: now,
            next_send_time: now,
            ack_num: 0,
            last_ack_sent: 0,
            pending_data_ack: false,
            last_heard: 0,
            mindelay_clock: NEVER,
            shutdown_in_progress: false,
            shutdown_tries: 0,
            shutdown_start: NEVER,
            received_states,
            receiver_quench_timer: 0,
            assembly: FragmentAssembly::new(),
            last_delivered_remote: Remote::default(),
            rtt: RttEstimator::new(),
            connected: false,
            mtu,
        }
    }

    // ----- accessors / driver hooks -----

    /// Mutable access to the live local state (append input, update the screen, …).
    pub fn current_mut(&mut self) -> &mut Local {
        &mut self.current_state
    }

    /// Read the live local state.
    pub fn current(&self) -> &Local {
        &self.current_state
    }

    /// The newest in-order remote state we hold (what the app should render/process).
    pub fn remote_state(&self) -> &Remote {
        &self.received_states.last().unwrap().state
    }

    /// `num` of the newest in-order remote state (what we ack to the peer).
    pub fn remote_num(&self) -> u64 {
        self.received_states.last().unwrap().num
    }

    /// Consume the change since the app last looked: the diff from the previously-delivered
    /// remote state to the newest one, then collapse stored received states (mosh
    /// `get_remote_diff`). The server uses this to drain newly-typed input for the PTY.
    pub fn get_remote_diff(&mut self) -> Remote::Diff {
        let newest = self.received_states.last().unwrap().state.clone();
        let diff = newest.diff_from(&self.last_delivered_remote);
        // Rationalize the received list against its oldest element (mirror of the send side).
        let oldest = self.received_states.first().unwrap().state.clone();
        for s in self.received_states.iter_mut() {
            s.state.subtract_prefix(&oldest);
        }
        self.last_delivered_remote = self.received_states.last().unwrap().state.clone();
        diff
    }

    /// The highest `num` of *our* local stream that the peer has acknowledged.
    ///
    /// On the client this is "how much of my typed input the server has applied" — the
    /// predictor uses it to confirm/kill local-echo predictions.
    pub fn local_acked_num(&self) -> u64 {
        self.sent_states.front().unwrap().num
    }

    /// `num` of the newest local state we have transmitted.
    pub fn newest_sent_num(&self) -> u64 {
        self.sent_states.back().unwrap().num
    }

    /// Mark the QUIC connection up/down. While down, [`tick`](Self::tick) sends nothing
    /// and [`wait_time`](Self::wait_time) returns [`NEVER`].
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Update the datagram payload budget (from `Connection::max_datagram_size()`).
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
    }

    /// Feed a smoothed RTT sample (ms), typically `Connection::rtt()` each tick.
    pub fn observe_rtt(&mut self, rtt_ms: f64) {
        self.rtt.sample(rtt_ms);
    }

    /// Current smoothed RTT estimate (ms) — used by the adaptive predictor.
    pub fn srtt_ms(&self) -> f64 {
        self.rtt.srtt_ms()
    }

    /// Wall-clock (ms) of the most recent decoded inbound datagram, or 0 if we've never heard
    /// from the peer. Updated on *every* inbound (incl. duplicates/keepalives), so the driver
    /// can drive its "link down / resuming" UI off real liveness rather than only new state.
    pub fn last_heard(&self) -> u64 {
        self.last_heard
    }

    /// Whether the peer has been heard from within the last `window` ms. Returns `false` until
    /// the first datagram is received (so the UI shows "connecting", not "link down", at start).
    pub fn link_up_within(&self, now: u64, window: u64) -> bool {
        self.last_heard > 0 && now.saturating_sub(self.last_heard) <= window
    }

    // ----- shutdown -----

    /// Begin a clean shutdown: outgoing instructions carry the [`SHUTDOWN_SENTINEL`]
    /// `new_num` so the peer flushes our final state, then acks the close.
    pub fn start_shutdown(&mut self, now: u64) {
        if !self.shutdown_in_progress {
            self.shutdown_in_progress = true;
            self.shutdown_start = now;
        }
    }

    pub fn shutdown_in_progress(&self) -> bool {
        self.shutdown_in_progress
    }

    /// The peer has acknowledged our shutdown (our acked base is the sentinel).
    pub fn shutdown_acknowledged(&self) -> bool {
        self.sent_states.front().unwrap().num == SHUTDOWN_SENTINEL
    }

    /// We have acknowledged the *peer's* shutdown (we put the sentinel ack on the wire).
    pub fn counterparty_shutdown_acknowledged(&self) -> bool {
        self.last_ack_sent == SHUTDOWN_SENTINEL
    }

    /// We have given up waiting for the peer to ack our shutdown.
    pub fn shutdown_ack_timed_out(&self, now: u64) -> bool {
        if !self.shutdown_in_progress {
            return false;
        }
        self.shutdown_tries >= SHUTDOWN_RETRIES
            || now.saturating_sub(self.shutdown_start) >= ACTIVE_RETRY_TIMEOUT
    }

    // ----- timers -----

    /// Recompute `assumed_receiver_num`, collapse states, and recompute send/ack deadlines.
    /// Idempotent; run at the top of [`tick`](Self::tick) and [`wait_time`](Self::wait_time).
    fn calculate_timers(&mut self, now: u64) {
        self.update_assumed_receiver_state(now);
        self.rationalize_states();

        if self.pending_data_ack && self.next_ack_time > now + ACK_DELAY {
            self.next_ack_time = now + ACK_DELAY;
        }

        let back_ts = self.sent_states.back().unwrap().timestamp;
        let interval = self.rtt.send_interval();
        let rto = self.rtt.timeout();
        let recently_heard = self.last_heard + ACTIVE_RETRY_TIMEOUT > now;

        let current_eq_back = self.current_state == self.sent_states.back().unwrap().state;
        let current_eq_assumed = self.current_state == *self.assumed_state();
        let current_eq_front = self.current_state == self.sent_states.front().unwrap().state;

        if !current_eq_back {
            // (A) new unsent input — coalesce ≥ SEND_MINDELAY, but respect the frame rate.
            if self.mindelay_clock == NEVER {
                self.mindelay_clock = now;
            }
            self.next_send_time = (self.mindelay_clock + SEND_MINDELAY).max(back_ts + interval);
        } else if !current_eq_assumed && recently_heard {
            // (B) nothing new, but the peer may lack our latest — retransmit at frame rate.
            self.next_send_time = back_ts + interval;
            if self.mindelay_clock != NEVER {
                self.next_send_time = self.next_send_time.max(self.mindelay_clock + SEND_MINDELAY);
            }
        } else if !current_eq_front && recently_heard {
            // (C) peer assumed-current but hasn't acked our base — slow retransmit.
            self.next_send_time = back_ts + rto + ACK_DELAY;
        } else {
            // (D) fully in sync (or peer silent > 10s).
            self.next_send_time = NEVER;
        }

        if self.shutdown_in_progress || self.ack_num == SHUTDOWN_SENTINEL {
            self.next_ack_time = back_ts + interval;
        }
    }

    /// `assumed_receiver_num` = newest state we believe the peer holds: the acked base plus
    /// any state sent within `RTO + ACK_DELAY` of now ("benefit of the doubt").
    fn update_assumed_receiver_state(&mut self, now: u64) {
        let horizon = self.rtt.timeout() + ACK_DELAY;
        let mut assumed = self.sent_states.front().unwrap().num;
        for s in self.sent_states.iter().skip(1) {
            if now.saturating_sub(s.timestamp) < horizon {
                assumed = s.num;
            } else {
                break;
            }
        }
        self.assumed_receiver_num = assumed;
    }

    /// Express the live state and every stored state relative to the acked base, so diffs
    /// stay small and acked input is physically dropped (see [`SyncState::subtract_prefix`]).
    fn rationalize_states(&mut self) {
        let known = self.sent_states.front().unwrap().state.clone();
        self.current_state.subtract_prefix(&known);
        for s in self.sent_states.iter_mut() {
            s.state.subtract_prefix(&known);
        }
    }

    fn assumed_idx(&self) -> usize {
        self.sent_states
            .iter()
            .position(|s| s.num == self.assumed_receiver_num)
            .unwrap_or(0)
    }

    fn assumed_state(&self) -> &Local {
        &self.sent_states[self.assumed_idx()].state
    }

    /// Milliseconds until the next send/ack is due, or [`NEVER`] when idle/disconnected.
    pub fn wait_time(&mut self, now: u64) -> u64 {
        self.calculate_timers(now);
        if !self.connected {
            return NEVER;
        }
        let next = self.next_ack_time.min(self.next_send_time);
        if next == NEVER {
            NEVER
        } else {
            next.saturating_sub(now)
        }
    }

    // ----- send -----

    /// Decide whether to send this tick and return the datagrams (encoded [`Fragment`]s) to
    /// transmit. Empty when nothing is due. Mirrors mosh `TransportSender::tick`.
    pub fn tick(&mut self, now: u64) -> Vec<Vec<u8>> {
        self.calculate_timers(now);
        if !self.connected {
            return Vec::new();
        }
        if now < self.next_ack_time && now < self.next_send_time {
            return Vec::new();
        }

        // Compute the diff against the assumed receiver state, then maybe retarget to the
        // acked base if that is cheaper / self-healing (prospective resend optimization).
        let assumed_idx = self.assumed_idx();
        let mut chosen_idx = assumed_idx;
        let mut diff = self
            .current_state
            .diff_from(&self.sent_states[assumed_idx].state);
        let mut diff_bytes = encode_diff(&diff);

        if self.assumed_receiver_num != self.sent_states.front().unwrap().num {
            let resend = self
                .current_state
                .diff_from(&self.sent_states.front().unwrap().state);
            let resend_bytes = encode_diff(&resend);
            let shorter = resend_bytes.len() <= diff_bytes.len();
            let modestly_longer = resend_bytes.len() < 1000
                && resend_bytes.len().saturating_sub(diff_bytes.len()) < 100;
            if shorter || modestly_longer {
                chosen_idx = 0;
                diff = resend;
                diff_bytes = resend_bytes;
            }
        }
        let _ = &diff; // typed diff kept only for clarity; we transmit the bytes.

        let chosen_base_num = self.sent_states[chosen_idx].num;
        // The diff is empty exactly when the live state equals the chosen base state.
        let is_empty = self.current_state == self.sent_states[chosen_idx].state;

        if is_empty {
            let mut out = Vec::new();
            if now >= self.next_ack_time {
                out = self.send_empty_ack(now);
                self.mindelay_clock = NEVER;
            }
            if now >= self.next_send_time {
                self.next_send_time = NEVER;
                self.mindelay_clock = NEVER;
            }
            out
        } else if now >= self.next_send_time || now >= self.next_ack_time {
            let out = self.send_to_receiver(now, chosen_base_num, diff_bytes);
            self.mindelay_clock = NEVER;
            out
        } else {
            Vec::new()
        }
    }

    /// Assign `new_num`, store the state, build the instruction, and fragment it.
    fn send_to_receiver(&mut self, now: u64, old_num: u64, diff: Vec<u8>) -> Vec<Vec<u8>> {
        let back_num = self.sent_states.back().unwrap().num;
        let current_eq_back = self.current_state == self.sent_states.back().unwrap().state;
        // saturating_add: once a shutdown sentinel state (num == u64::MAX) is the back, a
        // `+ 1` would overflow (debug panic) before the sentinel override on the next line.
        let mut new_num = if current_eq_back {
            back_num
        } else {
            back_num.saturating_add(1)
        };
        if self.shutdown_in_progress {
            new_num = SHUTDOWN_SENTINEL;
        }

        if new_num == back_num {
            self.sent_states.back_mut().unwrap().timestamp = now; // retransmit: bump ts only
        } else {
            self.add_sent_state(now, new_num, self.current_state.clone());
        }

        let out = self.send_in_fragments(old_num, new_num, diff);
        self.assumed_receiver_num = self.sent_states.back().unwrap().num;
        self.next_ack_time = now + ACK_INTERVAL;
        self.next_send_time = NEVER;
        self.pending_data_ack = false;
        out
    }

    /// Pure ack / keep-alive: advances `new_num`, stores the (unchanged) state, empty diff.
    fn send_empty_ack(&mut self, now: u64) -> Vec<Vec<u8>> {
        let back_num = self.sent_states.back().unwrap().num;
        // saturating_add so an already-sentinel back never overflows; override for shutdown.
        let mut new_num = back_num.saturating_add(1);
        if self.shutdown_in_progress {
            new_num = SHUTDOWN_SENTINEL;
        }
        let old_num = self.assumed_receiver_num;
        if new_num == back_num {
            // Repeat of an existing num (e.g. the shutdown sentinel every tick): bump the
            // timestamp, don't push a duplicate-num state and churn `sent_states`.
            self.sent_states.back_mut().unwrap().timestamp = now;
        } else {
            self.add_sent_state(now, new_num, self.current_state.clone());
        }
        let out = self.send_in_fragments(old_num, new_num, Vec::new());
        self.next_ack_time = now + ACK_INTERVAL;
        self.next_send_time = NEVER;
        out
    }

    fn send_in_fragments(&mut self, old_num: u64, new_num: u64, diff: Vec<u8>) -> Vec<Vec<u8>> {
        let instr = Instruction {
            protocol_version: PROTOCOL_VERSION,
            old_num,
            new_num,
            ack_num: self.ack_num,
            throwaway_num: self.sent_states.front().unwrap().num,
            diff,
        };
        self.last_ack_sent = self.ack_num;
        if new_num == SHUTDOWN_SENTINEL {
            self.shutdown_tries += 1;
        }
        trace!(
            old_num,
            new_num,
            ack_num = self.ack_num,
            "sending instruction"
        );
        let frags = match self.fragmenter.fragment(&instr, self.mtu) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error=%e, "fragmentation failed");
                return Vec::new();
            }
        };
        frags.iter().filter_map(|f| f.encode().ok()).collect()
    }

    fn add_sent_state(&mut self, now: u64, num: u64, state: Local) {
        self.sent_states.push_back(TimestampedState {
            timestamp: now,
            num,
            state,
        });
        if self.sent_states.len() > SENT_STATES_CAP {
            // Drop the 16th-from-end: keeps the acked base (front) and the recent tail.
            let idx = self.sent_states.len() - 16;
            self.sent_states.remove(idx);
        }
    }

    /// Drop every sent state below `ack` (peer confirmed it holds `ack`). No-op for a stale
    /// ack naming a state we already culled.
    fn process_acknowledgment_through(&mut self, ack: u64) {
        if self.sent_states.iter().any(|s| s.num == ack) {
            self.sent_states.retain(|s| s.num >= ack);
        }
    }

    // ----- receive -----

    /// Feed one inbound datagram (an encoded [`Fragment`]). Returns the outcome; on
    /// [`RecvOutcome::NewState`] the app should consume [`remote_state`](Self::remote_state).
    pub fn recv(&mut self, now: u64, datagram: &[u8]) -> RecvOutcome {
        let frag = match Fragment::decode(datagram) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error=%e, "dropping undecodable fragment");
                return RecvOutcome::Incomplete;
            }
        };
        // Any decoded datagram is a sign of life from the peer, so refresh the
        // active-retransmission liveness gate here — NOT only when a new newest-in-order state
        // lands. On a lossy link the peer's retransmits/dups/acks may be all that arrives; if
        // those didn't refresh `last_heard`, we'd stop retransmitting our own state to a peer
        // that is demonstrably still connected (mosh sets last_heard on every recv).
        self.last_heard = now;
        let instr = match self.assembly.add(frag) {
            Ok(Some(i)) => i,
            Ok(None) => return RecvOutcome::Incomplete,
            Err(e) => {
                tracing::warn!(error=%e, "dropping unreassemblable instruction");
                return RecvOutcome::Incomplete;
            }
        };

        // The peer's ack of OUR stream is processed even for dup/out-of-order packets.
        self.process_acknowledgment_through(instr.ack_num);

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
        // Clone the base BEFORE the throwaway GC. A peer controls `throwaway_num`, and
        // `process_throwaway_until` legitimately drops every state below it — including this
        // base when `throwaway_num > old_num`. Re-resolving the base after the GC and
        // `.expect()`-ing it is a peer-triggerable panic (remote DoS of a pure state machine).
        // Owning the clone makes the GC harmless.
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
        let ts = TimestampedState {
            timestamp: now,
            num: instr.new_num,
            state: new_state,
        };

        // Insert sorted by num (handles reordering).
        match self.received_states.iter().position(|s| s.num > ts.num) {
            Some(pos) => {
                self.received_states.insert(pos, ts);
                RecvOutcome::OutOfOrder
            }
            None => {
                self.received_states.push(ts);
                // Newest in-order state: advance our ack, owe a fast ack. (`last_heard` was
                // already refreshed for this datagram above, on any decoded inbound.)
                self.ack_num = self.received_states.last().unwrap().num;
                if !instr.diff.is_empty() {
                    self.pending_data_ack = true;
                }
                RecvOutcome::NewState
            }
        }
    }

    /// GC received states below `throwaway_num` (the peer's acked base). Always keeps ≥ 1.
    fn process_throwaway_until(&mut self, throwaway_num: u64) {
        if self.received_states.len() <= 1 {
            return;
        }
        let keep_from = self
            .received_states
            .iter()
            .position(|s| s.num >= throwaway_num)
            .unwrap_or(0);
        if keep_from > 0 {
            self.received_states.drain(0..keep_from);
        }
    }
}

/// Serialize a typed diff for the wire. A no-change diff still serializes to a few bytes,
/// which is why emptiness is decided by state equality, not by this length.
fn encode_diff<D: Serialize>(diff: &D) -> Vec<u8> {
    postcard::to_allocvec(diff).expect("diff serialization is infallible for our types")
}

fn decode_diff<D: DeserializeOwned>(bytes: &[u8]) -> Result<D, postcard::Error> {
    postcard::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmosh_wire::{Fragmenter, Instruction};
    use serde::{Deserialize, Serialize};

    /// A trivial absolute-value state: each diff fully describes the target, so we can craft
    /// arbitrary instructions without worrying about diff bases.
    #[derive(Clone, Default, PartialEq, Debug)]
    struct Abs(u64);
    #[derive(Serialize, Deserialize, Clone)]
    struct AbsDiff(u64);
    impl SyncState for Abs {
        type Diff = AbsDiff;
        fn diff_from(&self, _base: &Self) -> AbsDiff {
            AbsDiff(self.0)
        }
        fn apply(&mut self, d: &AbsDiff) {
            self.0 = d.0;
        }
    }

    fn instr(old: u64, new: u64, throwaway: u64, val: u64) -> Instruction {
        Instruction {
            protocol_version: PROTOCOL_VERSION,
            old_num: old,
            new_num: new,
            ack_num: 0,
            throwaway_num: throwaway,
            diff: postcard::to_allocvec(&AbsDiff(val)).unwrap(),
        }
    }

    /// Encode a (small) instruction as a single datagram, the way the wire layer ships it.
    fn datagram(i: &Instruction) -> Vec<u8> {
        let frags = Fragmenter::new().fragment(i, 1200).unwrap();
        assert_eq!(frags.len(), 1, "test instruction must fit one fragment");
        frags[0].encode().unwrap()
    }

    /// Regression for P1a: a peer-supplied `throwaway_num > old_num` makes the throwaway GC
    /// drop the diff base. Before the fix, recv() re-resolved the base after the GC with
    /// `.expect()` and panicked on this peer-controlled input. After the fix, the base is
    /// cloned before the GC and applied safely.
    #[test]
    fn throwaway_gc_dropping_base_does_not_panic() {
        let mut t = Transport::<Abs, Abs>::new(0, 1200);
        // received_states = [0, 2]
        assert_eq!(
            t.recv(10, &datagram(&instr(0, 2, 0, 22))),
            RecvOutcome::NewState
        );
        assert_eq!(t.remote_state().0, 22);
        // old=0 base, but throwaway_num=1 GCs num 0 (the base) before apply.
        assert_eq!(
            t.recv(20, &datagram(&instr(0, 5, 1, 55))),
            RecvOutcome::NewState
        );
        assert_eq!(
            t.remote_state().0,
            55,
            "diff must apply against the base cloned before the throwaway GC"
        );
    }

    /// Regression for P1c: `last_heard` (the active-retransmission liveness gate) must refresh
    /// on EVERY decoded datagram, including duplicate keepalives — not only on a new state.
    /// Otherwise a peer whose only-arriving traffic is dups/retransmits falsely times out.
    #[test]
    fn last_heard_updates_on_duplicate() {
        let mut t = Transport::<Abs, Abs>::new(0, 1200);
        let dg = datagram(&instr(0, 2, 0, 22));
        assert_eq!(t.recv(10, &dg), RecvOutcome::NewState);
        assert_eq!(t.last_heard(), 10);
        // The identical datagram again is a Duplicate (new_num 2 already held)...
        assert_eq!(t.recv(9000, &dg), RecvOutcome::Duplicate);
        // ...but it still proves the peer is alive, so liveness must advance.
        assert_eq!(
            t.last_heard(),
            9000,
            "a duplicate keepalive must refresh last_heard"
        );
        assert!(t.link_up_within(9100, 10_000));
        assert!(!t.link_up_within(20_000, 10_000));
    }

    /// Regression for P1d: a long shutdown must not overflow (`back_num + 1` on the sentinel)
    /// nor push a fresh u64::MAX state every tick. Exactly one sentinel state should be resident.
    #[test]
    fn shutdown_dedups_sentinel_and_never_overflows() {
        let mut t = Transport::<Abs, Abs>::new(0, 1200);
        t.set_connected(true);
        t.start_shutdown(0);
        // Many ticks at the frame rate; pre-fix this churned sent_states with sentinels (and
        // risked a `u64::MAX + 1` overflow). Reaching the end without panicking is half the test.
        for i in 0..200u64 {
            let _ = t.tick(i * 100);
        }
        assert_eq!(t.newest_sent_num(), SHUTDOWN_SENTINEL);
        // base (num 0) + a single deduped sentinel — not a queue churned toward the 32 cap.
        assert!(
            t.sent_states.len() <= 2,
            "shutdown sentinel must be deduped (bump ts), got {} sent_states",
            t.sent_states.len()
        );
    }

    /// Ported from mosh src/tests/network-no-diff.test: the sender must not generate a new diff/
    /// state while the application state is unchanged (mosh's regression was the server busy-
    /// looping / repainting when nothing changed). An unchanged state may be retransmitted for
    /// reliability but mints no new state number; a real change always gets a fresh one.
    #[test]
    fn unchanged_state_mints_no_new_content_state() {
        let mut t = Transport::<Abs, Abs>::new(0, 1200);
        t.set_connected(true);
        t.observe_rtt(20.0);

        // A real change is sent.
        t.current_mut().0 = 1;
        let mut now = 0u64;
        let mut sent = Vec::new();
        for _ in 0..100 {
            now += 20;
            sent = t.tick(now);
            if !sent.is_empty() {
                break;
            }
        }
        assert!(!sent.is_empty(), "a changed state must be sent");
        let after_first = t.newest_sent_num();

        // Unchanged across many ticks (well inside the ACK_INTERVAL): the transport may RETRANSMIT
        // the still-unacked state (reliability), but it must not mint a NEW state number — there
        // is no new screen content to diff. This is the heart of mosh's no-diff guarantee.
        for _ in 0..10 {
            now += 20;
            let _ = t.tick(now); // retransmits allowed; content is unchanged
            assert_eq!(
                t.newest_sent_num(),
                after_first,
                "unchanged state must not mint a new content state (retransmit reuses the number)"
            );
        }

        // A subsequent real change is sent again, with a fresh state number.
        t.current_mut().0 = 2;
        let mut sent_again = Vec::new();
        for _ in 0..100 {
            now += 20;
            sent_again = t.tick(now);
            if !sent_again.is_empty() {
                break;
            }
        }
        assert!(!sent_again.is_empty(), "a later change must be sent");
        assert!(
            t.newest_sent_num() > after_first,
            "the changed state gets a fresh number"
        );
    }
}
