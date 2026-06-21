//! # rmosh-wire
//!
//! The on-the-wire representation for rmosh's State Synchronization Protocol (SSP),
//! plus the (de)serialization and fragmentation/reassembly machinery that lets an
//! [`Instruction`] travel over QUIC unreliable datagrams.
//!
//! This crate is deliberately transport-agnostic: it knows nothing about iroh or
//! quinn. It produces [`Fragment`]s that are guaranteed to fit a caller-supplied MTU,
//! and reassembles them back into [`Instruction`]s, dropping superseded partials.
//!
//! ## The SSP envelope
//!
//! Mirrors mosh's `TransportInstruction`. Every datagram carries:
//!
//! - `old_num`  — the **diff base**: the sender's state number this diff transforms *from*.
//! - `new_num`  — the **diff target**: the sender's current state number this diff transforms *to*.
//! - `ack_num`  — the highest *peer* state number the sender has received and applied.
//! - `throwaway_num` — the peer may discard its sent states with number `<= throwaway_num`.
//! - `diff`     — the opaque, already-serialized state diff (the `ssp` layer owns its meaning).
//!
//! Unlike mosh we drop `protocol_version` chaff and the OCB-nonce padding — QUIC owns crypto.

use serde::{Deserialize, Serialize};

/// Conservative default datagram payload budget (bytes) when the path MTU is unknown.
///
/// QUIC's usable datagram payload is the path MTU minus IP/UDP/QUIC headers. 1200 is the
/// classic safe-everywhere QUIC packet size; subtracting QUIC overhead leaves us a safe
/// ceiling for a single datagram payload. Real code should prefer `Connection::max_datagram_size`.
pub const DEFAULT_MAX_DATAGRAM: usize = 1200;

/// Worst-case serialized overhead of a [`Fragment`] header (everything but `payload` bytes):
/// `id` varint (≤10) + `index` varint (≤3) + `final_` bool (1) + `payload` length varint (≤5),
/// rounded up for safety. Used to size payload chunks so a serialized `Fragment` never exceeds MTU.
pub const FRAGMENT_HEADER_OVERHEAD: usize = 24;

/// Errors produced while (de)serializing or reassembling wire structures.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("postcard (de)serialization error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("MTU {mtu} too small for fragment header (need > {min})")]
    MtuTooSmall { mtu: usize, min: usize },
}

/// The unit of state synchronization. Produced by `ssp::Transport`, serialized, then
/// fragmented for transport. See module docs for field semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    /// Diff base: the sender's state number the diff transforms *from*.
    pub old_num: u64,
    /// Diff target: the sender's current state number the diff transforms *to*.
    pub new_num: u64,
    /// Highest peer state number the sender has received and applied (the ack).
    pub ack_num: u64,
    /// The peer may discard its sent states numbered `<= throwaway_num`.
    pub throwaway_num: u64,
    /// Opaque serialized state diff. Empty means "no state change, this is a pure ack/keepalive".
    pub diff: Vec<u8>,
}

impl Instruction {
    /// A pure acknowledgement carrying no state change (`old_num == new_num`, empty diff).
    pub fn ack_only(state_num: u64, ack_num: u64, throwaway_num: u64) -> Self {
        Instruction {
            old_num: state_num,
            new_num: state_num,
            ack_num,
            throwaway_num,
            diff: Vec::new(),
        }
    }

    /// Serialize to bytes with postcard.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        Ok(postcard::to_allocvec(self)?)
    }

    /// Deserialize from bytes with postcard.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

/// A single datagram-sized piece of a (possibly fragmented) serialized [`Instruction`].
///
/// All fragments belonging to one serialized instruction share an `id`. The reassembler
/// keeps only the highest `id` it has seen, so a newer instruction's fragments supersede
/// and discard a stale partial — this is the "drop superseded state" property at the
/// framing layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fragment {
    /// Identifies the serialized instruction this fragment belongs to. Monotonic; bumped
    /// only when the instruction *content* changes (so identical retransmits reuse fragments).
    pub id: u64,
    /// 0-based index of this fragment within its instruction.
    pub index: u16,
    /// True for the last fragment of the instruction.
    pub final_: bool,
    /// The raw chunk of serialized-instruction bytes carried by this fragment.
    pub payload: Vec<u8>,
}

impl Fragment {
    /// Serialize this fragment to bytes ready for a datagram.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        Ok(postcard::to_allocvec(self)?)
    }

    /// Deserialize a fragment from datagram bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

/// Splits serialized [`Instruction`]s into datagram-sized [`Fragment`]s.
///
/// Tracks the last instruction it fragmented; if asked to fragment identical content for the
/// same MTU it reuses the previous `id` (so an unchanged retransmit reuses fragments and the
/// receiver can complete a partially-received instruction). Any content change bumps the `id`,
/// which causes the receiver to discard the now-stale partial.
#[derive(Debug, Default)]
pub struct Fragmenter {
    next_id: u64,
    last_serialized: Option<Vec<u8>>,
    last_mtu: usize,
}

impl Fragmenter {
    pub fn new() -> Self {
        Fragmenter::default()
    }

    /// The id that would be assigned to the next *new* instruction. Useful for tests/telemetry.
    pub fn current_id(&self) -> u64 {
        self.next_id
    }

    /// Fragment `instr` into pieces that each serialize to `<= mtu` bytes.
    ///
    /// Returns at least one fragment (a zero-length instruction still yields one final fragment).
    pub fn fragment(&mut self, instr: &Instruction, mtu: usize) -> Result<Vec<Fragment>, WireError> {
        if mtu <= FRAGMENT_HEADER_OVERHEAD {
            return Err(WireError::MtuTooSmall {
                mtu,
                min: FRAGMENT_HEADER_OVERHEAD,
            });
        }
        let serialized = instr.encode()?;

        // Bump the id only when the content (or MTU) changed, so identical retransmits reuse it.
        let changed = match &self.last_serialized {
            Some(prev) => prev != &serialized || self.last_mtu != mtu,
            None => true,
        };
        if changed {
            self.next_id = self.next_id.wrapping_add(1);
            self.last_serialized = Some(serialized.clone());
            self.last_mtu = mtu;
        }
        let id = self.next_id;

        let chunk = mtu - FRAGMENT_HEADER_OVERHEAD;
        let mut fragments = Vec::new();
        if serialized.is_empty() {
            fragments.push(Fragment {
                id,
                index: 0,
                final_: true,
                payload: Vec::new(),
            });
            return Ok(fragments);
        }
        let total = serialized.len().div_ceil(chunk);
        for (i, piece) in serialized.chunks(chunk).enumerate() {
            fragments.push(Fragment {
                id,
                index: i as u16,
                final_: i + 1 == total,
                payload: piece.to_vec(),
            });
        }
        Ok(fragments)
    }
}

/// Reassembles [`Fragment`]s back into [`Instruction`]s, discarding superseded partials.
///
/// Keeps a buffer for the highest `id` seen so far. Fragments with a lower `id` are stale and
/// dropped. A higher `id` clears the buffer and starts fresh. When all indices `0..=final` for
/// the current id are present, the instruction is decoded and returned.
#[derive(Debug, Default)]
pub struct FragmentAssembly {
    current_id: Option<u64>,
    /// Sparse store of received fragments for `current_id`, indexed by fragment index.
    parts: Vec<Option<Vec<u8>>>,
    final_index: Option<u16>,
    have: usize,
}

impl FragmentAssembly {
    pub fn new() -> Self {
        FragmentAssembly::default()
    }

    /// Feed a fragment. Returns `Ok(Some(instruction))` once the instruction it belongs to is
    /// complete, `Ok(None)` while still waiting for more (or if the fragment was stale).
    pub fn add(&mut self, frag: Fragment) -> Result<Option<Instruction>, WireError> {
        match self.current_id {
            Some(cur) if frag.id < cur => return Ok(None), // stale, superseded
            Some(cur) if frag.id == cur => {}              // same instruction, accumulate
            _ => {
                // First fragment, or a newer instruction supersedes the partial.
                self.current_id = Some(frag.id);
                self.parts.clear();
                self.final_index = None;
                self.have = 0;
            }
        }

        let idx = frag.index as usize;
        if idx >= self.parts.len() {
            self.parts.resize(idx + 1, None);
        }
        if self.parts[idx].is_none() {
            self.have += 1;
        }
        if frag.final_ {
            self.final_index = Some(frag.index);
        }
        self.parts[idx] = Some(frag.payload);

        // Complete only when we have a final marker and every index up to it.
        let Some(final_idx) = self.final_index else {
            return Ok(None);
        };
        let needed = final_idx as usize + 1;
        if self.have != needed || self.parts.len() != needed {
            return Ok(None);
        }
        if self.parts.iter().take(needed).any(|p| p.is_none()) {
            return Ok(None);
        }

        let mut buf = Vec::new();
        for part in self.parts.iter().take(needed) {
            buf.extend_from_slice(part.as_ref().unwrap());
        }
        // Reset so a duplicate of the just-completed final fragment doesn't re-emit forever:
        // bump past current_id by leaving it set; a re-sent identical fragment will rebuild and
        // re-complete, which is harmless (idempotent at the ssp layer), but we clear the buffer.
        self.parts.clear();
        self.final_index = None;
        self.have = 0;
        let instr = Instruction::decode(&buf)?;
        Ok(Some(instr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_instruction(diff_len: usize) -> Instruction {
        Instruction {
            old_num: 7,
            new_num: 9,
            ack_num: 4,
            throwaway_num: 2,
            diff: (0..diff_len).map(|i| (i % 251) as u8).collect(),
        }
    }

    #[test]
    fn instruction_roundtrip() {
        let i = sample_instruction(300);
        let bytes = i.encode().unwrap();
        assert_eq!(Instruction::decode(&bytes).unwrap(), i);
    }

    #[test]
    fn small_instruction_single_fragment() {
        let mut f = Fragmenter::new();
        let frags = f.fragment(&sample_instruction(10), 1200).unwrap();
        assert_eq!(frags.len(), 1);
        assert!(frags[0].final_);
    }

    #[test]
    fn empty_diff_yields_one_fragment() {
        // An ack-only instruction has an empty *diff*, but still serializes its seq/ack
        // fields, so it fits in exactly one (small, non-empty) fragment that round-trips.
        let mut f = Fragmenter::new();
        let instr = Instruction::ack_only(5, 3, 1);
        let frags = f.fragment(&instr, 1200).unwrap();
        assert_eq!(frags.len(), 1);
        assert!(frags[0].final_);
        assert!(instr.diff.is_empty());

        let mut asm = FragmentAssembly::new();
        assert_eq!(asm.add(frags[0].clone()).unwrap().unwrap(), instr);
    }

    #[test]
    fn large_instruction_fragments_and_reassembles() {
        let mut f = Fragmenter::new();
        let instr = sample_instruction(10_000);
        let frags = f.fragment(&instr, 200).unwrap();
        assert!(frags.len() > 1);
        for w in frags.windows(2) {
            assert_eq!(w[1].index, w[0].index + 1);
        }
        assert!(frags.last().unwrap().final_);
        // Each serialized fragment must fit the MTU.
        for fr in &frags {
            assert!(fr.encode().unwrap().len() <= 200, "fragment exceeds MTU");
        }
        let mut asm = FragmentAssembly::new();
        let mut got = None;
        for fr in frags {
            if let Some(i) = asm.add(fr).unwrap() {
                got = Some(i);
            }
        }
        assert_eq!(got.unwrap(), instr);
    }

    #[test]
    fn identical_retransmit_reuses_id() {
        let mut f = Fragmenter::new();
        let instr = sample_instruction(50);
        let a = f.fragment(&instr, 1200).unwrap();
        let b = f.fragment(&instr, 1200).unwrap();
        assert_eq!(a[0].id, b[0].id, "identical content must reuse fragment id");
        let mut instr2 = instr.clone();
        instr2.new_num += 1;
        let c = f.fragment(&instr2, 1200).unwrap();
        assert!(c[0].id > a[0].id, "changed content must bump fragment id");
    }

    #[test]
    fn newer_id_supersedes_partial() {
        let mut f = Fragmenter::new();
        let old = sample_instruction(5_000);
        let old_frags = f.fragment(&old, 300).unwrap();
        let mut newer = sample_instruction(5_000);
        newer.new_num = 999;
        let new_frags = f.fragment(&newer, 300).unwrap();

        let mut asm = FragmentAssembly::new();
        // Deliver only part of the old instruction...
        assert!(asm.add(old_frags[0].clone()).unwrap().is_none());
        // ...then the full newer one. The stale partial must be discarded.
        let mut got = None;
        for fr in new_frags {
            if let Some(i) = asm.add(fr).unwrap() {
                got = Some(i);
            }
        }
        assert_eq!(got.unwrap(), newer);
    }

    proptest! {
        #[test]
        fn fragment_reassemble_roundtrip(diff_len in 0usize..20_000, mtu in 30usize..1500) {
            let mut f = Fragmenter::new();
            let instr = Instruction {
                old_num: 1, new_num: 2, ack_num: 0, throwaway_num: 0,
                diff: (0..diff_len).map(|i| (i % 256) as u8).collect(),
            };
            let frags = f.fragment(&instr, mtu).unwrap();
            for fr in &frags {
                prop_assert!(fr.encode().unwrap().len() <= mtu);
            }
            let mut asm = FragmentAssembly::new();
            let mut got = None;
            for fr in frags {
                if let Some(i) = asm.add(fr).unwrap() { got = Some(i); }
            }
            prop_assert_eq!(got.unwrap(), instr);
        }
    }
}
