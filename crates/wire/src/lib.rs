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
//! Unlike mosh we drop the OCB-nonce padding/chaff — QUIC owns crypto — but we keep an
//! in-band [`PROTOCOL_VERSION`] (rejected on decode) to catch diff-encoding skew the ALPN can't.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tracing::trace;

/// Conservative default datagram payload budget (bytes) when the path MTU is unknown.
///
/// QUIC's usable datagram payload is the path MTU minus IP/UDP/QUIC headers. 1200 is the
/// classic safe-everywhere QUIC packet size; subtracting QUIC overhead leaves us a safe
/// ceiling for a single datagram payload. Real code should prefer `Connection::max_datagram_size`.
pub const DEFAULT_MAX_DATAGRAM: usize = 1200;

/// rmosh wire protocol version, carried in every [`Instruction`] and rejected on decode if it
/// doesn't match. Bump on any incompatible change to the envelope or the diff encoding.
///
/// The ALPN only proves both ends speak *some* rmosh; this catches diff-encoding skew between
/// rmosh builds that share an ALPN. (Unrelated to upstream mosh's `MOSH_PROTOCOL_VERSION` —
/// rmosh never interoperates with mosh.)
pub const PROTOCOL_VERSION: u32 = 1;

/// Exact serialized overhead of a [`Fragment`] header: an 8-byte big-endian `id` plus a 2-byte
/// big-endian `(final << 15) | index` field. A serialized fragment is therefore *exactly*
/// `FRAGMENT_HEADER_OVERHEAD + payload.len()` bytes, so the fragmenter packs each datagram up to
/// the MTU with no wasted slack (a fixed framing, matching the reference — not an estimate).
pub const FRAGMENT_HEADER_OVERHEAD: usize = 10;

/// Maximum fragment index: the index occupies the low 15 bits of the header's 2-byte field (the
/// top bit is the `final` flag), capping one instruction at 32768 fragments.
pub const MAX_FRAGMENT_INDEX: u16 = 0x7fff;

/// Errors produced while (de)serializing or reassembling wire structures.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("postcard (de)serialization error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("MTU {mtu} too small for fragment header (need > {min})")]
    MtuTooSmall { mtu: usize, min: usize },
    #[error("protocol version mismatch: peer sent {peer}, we speak {ours}")]
    VersionMismatch { peer: u32, ours: u32 },
    #[error("fragment too short: {len} bytes (need >= {min})")]
    ShortFragment { len: usize, min: usize },
    #[error("instruction needs {count} fragments, exceeds the {max}-fragment limit")]
    TooManyFragments { count: usize, max: usize },
}

/// The unit of state synchronization. Produced by `ssp::Transport`, serialized, then
/// fragmented for transport. See module docs for field semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    /// Wire protocol version (see [`PROTOCOL_VERSION`]); rejected on [`decode`](Instruction::decode).
    pub protocol_version: u32,
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
            protocol_version: PROTOCOL_VERSION,
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

    /// Deserialize from bytes with postcard, rejecting a protocol-version mismatch at decode
    /// time (before any state is touched) so a foreign/incompatible peer can't feed a diff with
    /// a different encoding into our state mirror.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let instr: Instruction = postcard::from_bytes(bytes)?;
        if instr.protocol_version != PROTOCOL_VERSION {
            return Err(WireError::VersionMismatch {
                peer: instr.protocol_version,
                ours: PROTOCOL_VERSION,
            });
        }
        Ok(instr)
    }
}

/// A single datagram-sized piece of a (possibly fragmented) serialized [`Instruction`].
///
/// All fragments belonging to one serialized instruction share an `id`. The reassembler
/// keeps only the highest `id` it has seen, so a newer instruction's fragments supersede
/// and discard a stale partial — this is the "drop superseded state" property at the
/// framing layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Identifies the serialized instruction this fragment belongs to. Monotonic; bumped
    /// only when the instruction *content* changes (so identical retransmits reuse fragments).
    pub id: u64,
    /// 0-based index of this fragment within its instruction (≤ [`MAX_FRAGMENT_INDEX`]).
    pub index: u16,
    /// True for the last fragment of the instruction.
    pub final_: bool,
    /// The raw chunk of serialized-instruction bytes carried by this fragment.
    pub payload: Vec<u8>,
}

impl Fragment {
    /// Serialize to datagram bytes: `id` (8 BE) ++ `(final << 15) | index` (2 BE) ++ `payload`.
    /// Exactly `FRAGMENT_HEADER_OVERHEAD + payload.len()` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let combined: u16 = ((self.final_ as u16) << 15) | (self.index & MAX_FRAGMENT_INDEX);
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_OVERHEAD + self.payload.len());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&combined.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Parse the fixed 10-byte header (inverse of [`encode`](Fragment::encode)).
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < FRAGMENT_HEADER_OVERHEAD {
            return Err(WireError::ShortFragment {
                len: bytes.len(),
                min: FRAGMENT_HEADER_OVERHEAD,
            });
        }
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&bytes[0..8]);
        let id = u64::from_be_bytes(id_bytes);
        let mut combined_bytes = [0u8; 2];
        combined_bytes.copy_from_slice(&bytes[8..10]);
        let combined = u16::from_be_bytes(combined_bytes);
        Ok(Fragment {
            id,
            index: combined & MAX_FRAGMENT_INDEX,
            final_: combined & 0x8000 != 0,
            payload: bytes[FRAGMENT_HEADER_OVERHEAD..].to_vec(),
        })
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
    pub fn fragment(
        &mut self,
        instr: &Instruction,
        mtu: usize,
    ) -> Result<Vec<Fragment>, WireError> {
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
            trace!(
                id,
                changed,
                mtu,
                "fragmented empty instruction into 1 fragment"
            );
            fragments.push(Fragment {
                id,
                index: 0,
                final_: true,
                payload: Vec::new(),
            });
            return Ok(fragments);
        }
        let total = serialized.len().div_ceil(chunk);
        if total > MAX_FRAGMENT_INDEX as usize + 1 {
            return Err(WireError::TooManyFragments {
                count: total,
                max: MAX_FRAGMENT_INDEX as usize + 1,
            });
        }
        trace!(
            id,
            fragments = total,
            bytes = serialized.len(),
            mtu,
            changed,
            "fragmented instruction"
        );
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
    /// Received fragments for `current_id`, keyed by index. A *map* (not a Vec sized to the
    /// fragment index) so an untrusted peer that sends a single near-[`MAX_FRAGMENT_INDEX`]
    /// fragment allocates one entry, not a ~32K-slot buffer — closing a cheap memory-amplification
    /// knob while preserving the protocol's fragment-count ceiling.
    parts: BTreeMap<u16, Vec<u8>>,
    final_index: Option<u16>,
}

impl FragmentAssembly {
    pub fn new() -> Self {
        FragmentAssembly::default()
    }

    /// Feed a fragment. Returns `Ok(Some(instruction))` once the instruction it belongs to is
    /// complete, `Ok(None)` while still waiting for more (or if the fragment was stale).
    pub fn add(&mut self, frag: Fragment) -> Result<Option<Instruction>, WireError> {
        match self.current_id {
            Some(cur) if frag.id < cur => {
                trace!(
                    stale_id = frag.id,
                    current = cur,
                    "dropping superseded fragment"
                );
                return Ok(None); // stale, superseded
            }
            Some(cur) if frag.id == cur => {} // same instruction, accumulate
            _ => {
                // First fragment, or a newer instruction supersedes the partial.
                if let Some(prev) = self.current_id {
                    trace!(
                        prev_id = prev,
                        new_id = frag.id,
                        "newer instruction supersedes partial"
                    );
                }
                self.current_id = Some(frag.id);
                self.parts.clear();
                self.final_index = None;
            }
        }

        if frag.final_ {
            self.final_index = Some(frag.index);
        }
        self.parts.insert(frag.index, frag.payload);

        // Complete only when we have a final marker and exactly indices `0..=final` are present
        // (no gap, no stray index beyond the final).
        let Some(final_idx) = self.final_index else {
            return Ok(None);
        };
        let needed = final_idx as usize + 1;
        if self.parts.len() != needed || self.parts.keys().next_back() != Some(&final_idx) {
            return Ok(None);
        }

        let mut buf = Vec::new();
        for i in 0..=final_idx {
            match self.parts.get(&i) {
                Some(part) => buf.extend_from_slice(part),
                None => return Ok(None), // gap (defensive; the count+max check rules it out)
            }
        }
        // Reset so a duplicate of the just-completed final fragment doesn't re-emit forever:
        // bump past current_id by leaving it set; a re-sent identical fragment will rebuild and
        // re-complete, which is harmless (idempotent at the ssp layer), but we clear the buffer.
        self.parts.clear();
        self.final_index = None;
        trace!(
            id = self.current_id,
            fragments = needed,
            "reassembled complete instruction"
        );
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
            protocol_version: PROTOCOL_VERSION,
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
    fn decode_rejects_protocol_version_mismatch() {
        // A peer speaking a different (incompatible diff-encoding) version is rejected at decode
        // time, before any state is touched — not silently fed into the state mirror.
        let mut i = sample_instruction(10);
        i.protocol_version = PROTOCOL_VERSION + 1;
        let bytes = i.encode().unwrap();
        match Instruction::decode(&bytes) {
            Err(WireError::VersionMismatch { peer, ours }) => {
                assert_eq!(peer, PROTOCOL_VERSION + 1);
                assert_eq!(ours, PROTOCOL_VERSION);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
        // A correctly-versioned instruction still decodes fine.
        let ok = sample_instruction(10);
        assert_eq!(Instruction::decode(&ok.encode().unwrap()).unwrap(), ok);
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
    fn fragment_header_is_exact_and_packs_to_mtu() {
        assert_eq!(FRAGMENT_HEADER_OVERHEAD, 10);
        // A single fragment encodes to exactly 10 + payload, and round-trips (incl. final flag).
        let f = Fragment {
            id: 0xdead_beef_cafe_babe,
            index: 5,
            final_: true,
            payload: vec![7u8; 100],
        };
        let bytes = f.encode().unwrap();
        assert_eq!(bytes.len(), FRAGMENT_HEADER_OVERHEAD + 100);
        assert_eq!(Fragment::decode(&bytes).unwrap(), f);

        // Every non-final fragment of a large instruction fills the MTU EXACTLY (no slack —
        // the old estimated 24-byte overhead wasted ~14 bytes per datagram).
        let mut fr = Fragmenter::new();
        let frags = fr.fragment(&sample_instruction(5000), 200).unwrap();
        assert!(frags.len() > 1);
        for f in &frags[..frags.len() - 1] {
            assert_eq!(
                f.encode().unwrap().len(),
                200,
                "non-final fragments pack to exactly the MTU"
            );
        }
    }

    #[test]
    fn decode_rejects_short_fragment() {
        assert!(matches!(
            Fragment::decode(&[0u8; 5]),
            Err(WireError::ShortFragment { .. })
        ));
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

    #[test]
    fn high_index_partial_does_not_complete_and_is_superseded() {
        // A peer can send a near-MAX_FRAGMENT_INDEX, non-final fragment before any final marker.
        // With the map-backed store this is a single entry (not a ~32K-slot buffer), it can't
        // complete on its own, and a newer instruction supersedes it cleanly.
        let mut asm = FragmentAssembly::new();
        let high = Fragment {
            id: 5,
            index: MAX_FRAGMENT_INDEX,
            final_: false,
            payload: vec![1u8; 8],
        };
        assert!(
            asm.add(high).unwrap().is_none(),
            "a lone non-final fragment can never complete"
        );
        // A newer id (> 5) supersedes the stale high-index partial and reassembles normally.
        let instr = sample_instruction(20);
        let frags = Fragmenter::new().fragment(&instr, 1200).unwrap();
        let mut got = None;
        for mut fr in frags {
            fr.id = 6; // force a superseding id; the assembler only cares about id ordering
            if let Some(i) = asm.add(fr).unwrap() {
                got = Some(i);
            }
        }
        assert_eq!(
            got.unwrap(),
            instr,
            "the newer instruction supersedes the stale high-index partial"
        );
    }

    proptest! {
        #[test]
        fn fragment_reassemble_roundtrip(diff_len in 0usize..20_000, mtu in 30usize..1500) {
            let mut f = Fragmenter::new();
            let instr = Instruction {
                protocol_version: PROTOCOL_VERSION,
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
