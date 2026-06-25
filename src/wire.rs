//! # koh-wire
//!
//! The on-the-wire representation for koh's State Synchronization Protocol (SSP),
//! plus the (de)serialization and fragmentation/reassembly machinery that lets an
//! [`Instruction`] travel over QUIC unreliable datagrams.
//!
//! This module is deliberately transport-agnostic: it knows nothing about iroh or
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

/// koh wire protocol version, carried in every [`Instruction`] and rejected on decode if it
/// doesn't match. Bump on any incompatible change to the envelope or the diff encoding.
///
/// The ALPN only proves both ends speak *some* koh; this catches diff-encoding skew between
/// koh builds that share an ALPN. (Unrelated to upstream mosh's `MOSH_PROTOCOL_VERSION` —
/// koh never interoperates with mosh.)
pub const PROTOCOL_VERSION: u32 = 3;

/// Exact serialized overhead of a [`Fragment`] header.
///
/// It is an 8-byte big-endian `id` plus a 2-byte big-endian `(final << 15) | index` field. A
/// serialized fragment is therefore *exactly* `FRAGMENT_HEADER_OVERHEAD + payload.len()` bytes, so
/// the fragmenter packs each datagram up to the MTU with no wasted slack (a fixed framing,
/// matching the reference — not an estimate).
pub const FRAGMENT_HEADER_OVERHEAD: usize = 10;

/// Maximum fragment index: the index occupies the low 15 bits of the header's 2-byte field (the
/// top bit is the `final` flag), capping one instruction at 32768 fragments.
pub const MAX_FRAGMENT_INDEX: u16 = 0x7fff;

/// Sanity ceiling on a single fragment's payload, decoded straight from untrusted bytes.
///
/// The live transport delivers fragments as QUIC datagrams, inherently bounded by the negotiated
/// `max_datagram_size` (~1.2–1.5 KiB), so a real fragment is tiny. This explicit cap makes the
/// transport-agnostic wire layer self-protecting rather than silently relying on that external
/// invariant: it is far larger than any real datagram (so it never rejects honest traffic) yet far
/// below the reassembly cap, so a future stream transport can't smuggle a multi-MB single fragment
/// past [`FragmentAssembly`]'s per-id byte budget by hiding it in one over-large frame (K-12).
pub const MAX_FRAGMENT_PAYLOAD: usize = 64 * 1024;

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
    #[error("fragment payload {len} bytes exceeds the {max}-byte per-fragment limit")]
    FragmentTooLarge { len: usize, max: usize },
    #[error("instruction needs {count} fragments, exceeds the {max}-fragment limit")]
    TooManyFragments { count: usize, max: usize },
    #[error("reassembly buffer {bytes} bytes exceeds the {max}-byte limit")]
    ReassemblyTooLarge { bytes: usize, max: usize },
    #[error("could not inflate instruction (corrupt or oversized payload)")]
    Decompress,
}

/// DEFLATE level for instruction payloads. Terminal diffs are extremely compressible (runs of
/// spaces, repeated SGR, ASCII), so a mid level gives most of the ratio at negligible CPU.
const COMPRESSION_LEVEL: u8 = 6;

/// Global hard cap on an inflated instruction (anti-decompression-bomb on untrusted peer input).
///
/// A full repaint of a large scrolled-back screen is well under this; anything larger is rejected.
/// The *per-direction* limit a transport actually applies is [`crate::ssp::SyncState::RECV_DECODE_LIMIT`]
/// (e.g. far tighter for the keystroke direction); this is the default/ceiling.
pub const MAX_DECOMPRESSED: usize = 16 * 1024 * 1024;

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
    pub const fn ack_only(state_num: u64, ack_num: u64, throwaway_num: u64) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            old_num: state_num,
            new_num: state_num,
            ack_num,
            throwaway_num,
            diff: Vec::new(),
        }
    }

    /// Serialize to bytes: postcard, then DEFLATE-compressed (mosh compresses the whole serialized
    /// instruction *before* fragmenting, so compression directly raises how much screen change
    /// fits per datagram). Always compressed — the tiny deflate overhead on small instructions is
    /// dwarfed by the win on screen diffs, and it keeps the wire format flag-free.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let raw = postcard::to_allocvec(self)?;
        Ok(miniz_oxide::deflate::compress_to_vec(
            &raw,
            COMPRESSION_LEVEL,
        ))
    }

    /// Deserialize with the global [`MAX_DECOMPRESSED`] inflate ceiling. Prefer
    /// [`decode_with_limit`](Instruction::decode_with_limit) with the receiver's per-direction
    /// budget on the hot path.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Self::decode_with_limit(bytes, MAX_DECOMPRESSED)
    }

    /// Deserialize: inflate (bounded by `max_decompressed`, anti-bomb), then postcard, rejecting a
    /// protocol-version mismatch at decode time (before any state is touched) so a
    /// foreign/incompatible peer can't feed a diff with a different encoding into our state mirror.
    ///
    /// `max_decompressed` is the caller's per-direction cap (the keystroke direction is far tighter
    /// than the screen direction), so one small datagram set can't be inflated into a huge resident
    /// payload (KOH-02).
    pub fn decode_with_limit(bytes: &[u8], max_decompressed: usize) -> Result<Self, WireError> {
        let raw = miniz_oxide::inflate::decompress_to_vec_with_limit(bytes, max_decompressed)
            .map_err(|_| WireError::Decompress)?;
        let instr: Self = postcard::from_bytes(&raw)?;
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
        let combined: u16 = (u16::from(self.final_) << 15) | (self.index & MAX_FRAGMENT_INDEX);
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_OVERHEAD + self.payload.len());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&combined.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Parse the fixed 10-byte header (inverse of [`encode`](Fragment::encode)).
    ///
    /// Decodes untrusted peer bytes, so it is written without any indexing or `unwrap`:
    /// `split_first_chunk` peels the fixed-size header fields and yields the rest as payload,
    /// returning [`WireError::ShortFragment`] if the input is too short — it cannot panic.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let short = || WireError::ShortFragment {
            len: bytes.len(),
            min: FRAGMENT_HEADER_OVERHEAD,
        };
        let (id_bytes, rest) = bytes.split_first_chunk::<8>().ok_or_else(short)?;
        let (combined_bytes, payload) = rest.split_first_chunk::<2>().ok_or_else(short)?;
        // Bound a single fragment's payload up front (K-12). With the datagram transport this can't
        // trip (datagrams are MTU-bounded), but it keeps the wire layer self-protecting if it is
        // ever fed by a transport without that bound.
        if payload.len() > MAX_FRAGMENT_PAYLOAD {
            return Err(WireError::FragmentTooLarge {
                len: payload.len(),
                max: MAX_FRAGMENT_PAYLOAD,
            });
        }
        let id = u64::from_be_bytes(*id_bytes);
        let combined = u16::from_be_bytes(*combined_bytes);
        Ok(Self {
            id,
            index: combined & MAX_FRAGMENT_INDEX,
            final_: combined & 0x8000 != 0,
            payload: payload.to_vec(),
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
        Self::default()
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
#[derive(Debug)]
pub struct FragmentAssembly {
    current_id: Option<u64>,
    /// Received fragments for `current_id`, keyed by index. A *map* (not a Vec sized to the
    /// fragment index) so an untrusted peer that sends a single near-[`MAX_FRAGMENT_INDEX`]
    /// fragment allocates one entry, not a ~32K-slot buffer — closing a cheap memory-amplification
    /// knob while preserving the protocol's fragment-count ceiling.
    parts: BTreeMap<u16, Vec<u8>>,
    final_index: Option<u16>,
    /// Sum of `parts`' payload bytes for the current id, so a never-completing partial can't
    /// buffer unbounded pre-decompression scratch (KOH-07).
    buffered_bytes: usize,
    /// The highest `id` that has already been fully reassembled + decoded. Fragments with an `id`
    /// at or below this are a replay of an already-delivered instruction; they are dropped O(1)
    /// **before** any reassembly or the (potentially multi-MB) inflate (K-06). Without this, a peer
    /// replaying a completed fragment set at line rate forces a fresh `decode_with_limit` per replay
    /// — re-running the DEFLATE inflate every time — only for the SSP layer to then discard it as a
    /// duplicate after paying the full decompression cost.
    last_completed_id: Option<u64>,
    /// The per-direction inflate ceiling passed to [`Instruction::decode_with_limit`] on
    /// completion (and the basis for the `buffered_bytes` cap).
    max_decompressed: usize,
}

impl Default for FragmentAssembly {
    fn default() -> Self {
        Self::with_limit(MAX_DECOMPRESSED)
    }
}

impl FragmentAssembly {
    pub fn new() -> Self {
        Self::default()
    }

    /// A reassembler whose completed instructions inflate to at most `max_decompressed` bytes, and
    /// whose pre-decompression scratch is bounded proportionally. Callers pass their per-direction
    /// [`crate::ssp::SyncState::RECV_DECODE_LIMIT`].
    pub fn with_limit(max_decompressed: usize) -> Self {
        Self {
            current_id: None,
            parts: BTreeMap::new(),
            final_index: None,
            buffered_bytes: 0,
            last_completed_id: None,
            max_decompressed,
        }
    }

    /// Upper bound on buffered (still-compressed) scratch: a small multiple of the decompressed
    /// ceiling, so a legitimate near-limit instruction still reassembles while a flood of
    /// never-completing fragments is cut off (KOH-07).
    fn buffered_cap(&self) -> usize {
        self.max_decompressed.saturating_mul(2).max(64 * 1024)
    }

    /// Feed a fragment. Returns `Ok(Some(instruction))` once the instruction it belongs to is
    /// complete, `Ok(None)` while still waiting for more (or if the fragment was stale).
    pub fn add(&mut self, frag: Fragment) -> Result<Option<Instruction>, WireError> {
        // A legitimate fragment is empty ONLY when it is the single final fragment of an empty
        // instruction (index 0, final). Any other empty-payload fragment is malformed — drop it up
        // front (before it can supersede a live partial or consume a `parts` slot), so a peer can't
        // flood ~32768 zero-length fragments (which add 0 to the byte cap, evading KOH-07) to pin
        // one BTreeMap entry per index (KR-08).
        if frag.payload.is_empty() && !(frag.index == 0 && frag.final_) {
            return Ok(None);
        }
        // Drop a replay of an already-decoded instruction O(1), before re-accumulating or paying the
        // multi-MB inflate on completion (K-06). `current_id` is intentionally retained after a
        // completion (idempotent at the SSP layer), so without this an identical fragment set would
        // re-enter the accumulate branch and re-inflate on every replay.
        if self.last_completed_id.is_some_and(|done| frag.id <= done) {
            trace!(
                replay_id = frag.id,
                "dropping replay of an already-decoded instruction"
            );
            return Ok(None);
        }
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
                self.buffered_bytes = 0;
            }
        }

        if frag.final_ {
            self.final_index = Some(frag.index);
        }
        // Track buffered bytes (subtracting any payload this index replaces) and refuse to hold
        // more than a small multiple of the decompressed ceiling, so a peer that only ever ships
        // never-completing partials can't pin unbounded scratch (KOH-07).
        if let Some(old) = self.parts.get(&frag.index) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(old.len());
        }
        self.buffered_bytes = self.buffered_bytes.saturating_add(frag.payload.len());
        let cap = self.buffered_cap();
        if self.buffered_bytes > cap {
            let bytes = self.buffered_bytes;
            self.current_id = None;
            self.parts.clear();
            self.final_index = None;
            self.buffered_bytes = 0;
            return Err(WireError::ReassemblyTooLarge { bytes, max: cap });
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
        // Reset so a duplicate of the just-completed final fragment doesn't re-emit forever, and
        // record this id as completed so any replay of its fragment set is dropped O(1) up front
        // (K-06) rather than rebuilt and re-inflated. `current_id` stays set (id ordering for the
        // supersede logic); `last_completed_id` is the cheap replay gate.
        self.last_completed_id = self.current_id;
        self.parts.clear();
        self.final_index = None;
        self.buffered_bytes = 0;
        trace!(
            id = self.current_id,
            fragments = needed,
            "reassembled complete instruction"
        );
        let instr = Instruction::decode_with_limit(&buf, self.max_decompressed)?;
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
    fn compression_shrinks_a_repetitive_diff_and_roundtrips() {
        // A highly-repetitive diff (runs of one byte — the shape of a sparse screen repaint) must
        // encode to far fewer bytes than its raw size, and still round-trip exactly.
        let instr = Instruction {
            protocol_version: PROTOCOL_VERSION,
            old_num: 1,
            new_num: 2,
            ack_num: 0,
            throwaway_num: 0,
            diff: vec![b' '; 8000],
        };
        let encoded = instr.encode().unwrap();
        assert!(
            encoded.len() < 2000,
            "8000-byte repetitive diff should compress well, got {} bytes",
            encoded.len()
        );
        assert_eq!(Instruction::decode(&encoded).unwrap(), instr);
    }

    #[test]
    fn decode_rejects_garbage_without_panicking() {
        // Bytes that aren't a valid DEFLATE stream (or inflate to non-postcard) must error, never
        // panic — this is untrusted peer input.
        assert!(Instruction::decode(&[0xff, 0x00, 0x13, 0x37, 0xab, 0xcd]).is_err());
        assert!(Instruction::decode(&[]).is_err());
    }

    #[test]
    fn decode_with_limit_rejects_oversized_inflation() {
        // KOH-02: an instruction that inflates beyond the caller's per-direction limit is rejected,
        // not expanded into a huge resident payload. A 512 KiB diff of zeros compresses tiny.
        let big = Instruction {
            protocol_version: PROTOCOL_VERSION,
            old_num: 0,
            new_num: 1,
            ack_num: 0,
            throwaway_num: 0,
            diff: vec![0u8; 512 * 1024],
        };
        let bytes = big.encode().unwrap();
        assert!(
            bytes.len() < 4096,
            "the bomb compresses small ({} bytes)",
            bytes.len()
        );
        // The generous global ceiling admits it...
        assert!(Instruction::decode(&bytes).is_ok());
        // ...but a tight 256 KiB per-direction limit refuses the 512 KiB inflation.
        assert!(matches!(
            Instruction::decode_with_limit(&bytes, 256 * 1024),
            Err(WireError::Decompress)
        ));
    }

    #[test]
    fn reassembly_rejects_oversized_buffered_bytes() {
        // KOH-07: a peer shipping many never-completing non-final fragments under one id must not
        // pin unbounded scratch — the buffered-bytes cap returns ReassemblyTooLarge and resets.
        let mut asm = FragmentAssembly::with_limit(64 * 1024); // cap = max(2*64 KiB, 64 KiB) = 128 KiB
        let mut rejected = false;
        for i in 0..2000u16 {
            let frag = Fragment {
                id: 1,
                index: i,
                final_: false,
                payload: vec![0u8; 1000],
            };
            match asm.add(frag) {
                Ok(None) => {}
                Err(WireError::ReassemblyTooLarge { .. }) => {
                    rejected = true;
                    break;
                }
                other => panic!("unexpected reassembly outcome: {other:?}"),
            }
        }
        assert!(
            rejected,
            "a flood of non-final fragments must trip the buffered-bytes cap"
        );
        // After the reset a fresh, well-formed instruction still reassembles normally.
        let frags = Fragmenter::new()
            .fragment(&sample_instruction(20), 1200)
            .unwrap();
        let mut got = None;
        for fr in frags {
            if let Some(i) = asm.add(fr).unwrap() {
                got = Some(i);
            }
        }
        assert!(got.is_some(), "assembler recovers after an over-cap reset");
    }

    #[test]
    fn empty_nonfinal_fragments_are_dropped_and_dont_accumulate() {
        // KR-08: a flood of zero-length non-final fragments must be dropped (they'd add 0 to the
        // byte cap and otherwise pin one map entry per index), must not disturb a live partial, and
        // must leave the assembler able to reassemble a subsequent real instruction.
        let mut asm = FragmentAssembly::with_limit(64 * 1024);
        for i in 0..5000u16 {
            let empty = Fragment {
                id: 1,
                index: i,
                final_: false,
                payload: Vec::new(),
            };
            assert!(
                asm.add(empty).unwrap().is_none(),
                "an empty non-final fragment is dropped, never buffered"
            );
        }
        // A subsequent well-formed instruction (higher id) still reassembles — the empties left no
        // residue and didn't advance any final marker.
        let instr = sample_instruction(20);
        let mut got = None;
        for mut fr in Fragmenter::new().fragment(&instr, 1200).unwrap() {
            fr.id = 2;
            if let Some(i) = asm.add(fr).unwrap() {
                got = Some(i);
            }
        }
        assert_eq!(
            got.unwrap(),
            instr,
            "a real instruction reassembles after an empty-fragment flood"
        );
    }

    #[test]
    fn replayed_completed_instruction_is_dropped_without_redecoding() {
        // K-06: once a fragment set completes, replaying it must be dropped O(1) (Ok(None)) — NOT
        // reassembled and re-inflated — so a peer can't force a repeated multi-MB DEFLATE inflate by
        // replaying one completed instruction at line rate. A single-fragment instruction is the
        // tightest case (one datagram re-completes on every replay without the guard).
        let mut f = Fragmenter::new();
        let instr = sample_instruction(40);
        let frags = f.fragment(&instr, 1200).unwrap();
        assert_eq!(frags.len(), 1, "small instruction is one fragment");

        let mut asm = FragmentAssembly::new();
        assert_eq!(
            asm.add(frags[0].clone()).unwrap().unwrap(),
            instr,
            "first delivery reassembles + decodes"
        );
        // Every subsequent replay of the SAME id is dropped up front, before any decode.
        for _ in 0..5 {
            assert!(
                asm.add(frags[0].clone()).unwrap().is_none(),
                "a replay of a completed instruction must be dropped, not re-decoded"
            );
        }

        // A genuinely newer instruction (higher id) still flows through normally.
        let mut newer = sample_instruction(40);
        newer.new_num = 123;
        let new_frags = f.fragment(&newer, 1200).unwrap();
        assert!(new_frags[0].id > frags[0].id, "content change bumps the id");
        assert_eq!(
            asm.add(new_frags[0].clone()).unwrap().unwrap(),
            newer,
            "a newer instruction is not blocked by the replay gate"
        );
    }

    #[test]
    fn decode_rejects_oversized_single_fragment() {
        // K-12: a single fragment whose payload exceeds the per-fragment ceiling is refused at
        // decode, before FragmentAssembly would buffer it — a self-protection bound that does not
        // depend on the QUIC datagram size invariant.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u64.to_be_bytes()); // id
        bytes.extend_from_slice(&0x8000u16.to_be_bytes()); // final, index 0
        bytes.extend(std::iter::repeat_n(0u8, MAX_FRAGMENT_PAYLOAD + 1));
        assert!(matches!(
            Fragment::decode(&bytes),
            Err(WireError::FragmentTooLarge { .. })
        ));
        // A payload exactly at the cap still decodes.
        let mut ok = Vec::new();
        ok.extend_from_slice(&1u64.to_be_bytes());
        ok.extend_from_slice(&0x8000u16.to_be_bytes());
        ok.extend(std::iter::repeat_n(0u8, MAX_FRAGMENT_PAYLOAD));
        assert!(
            Fragment::decode(&ok).is_ok(),
            "a payload at the cap is accepted"
        );
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
