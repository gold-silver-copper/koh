//! What the oracle exempts: the input that sets off a change made on purpose since the commit it
//! compares against. Each exemption is taken out of every case before either side sees it, so
//! that everything else in the case is still compared. Once the commit compared against has the
//! change, its exemption comes off this list.
//!
//! Sequences are read as fux-vt reads them: CSI with its parameters, intermediates and final
//! byte; OSC and DCS up to BEL or ST. A sequence is taken out whole.

use crate::case::{Case, Step};

/// The changes exempted, each with what sets it off and why it differs.
pub const EXEMPTIONS: &[(&str, &str)] = &[(
    "reflow",
    "what a resize re-wraps, which fux-vt 0.3.1 does otherwise (a shrink brings no history row \
     back above the cursor): from its first resize on, a case runs on the alternate screen (which \
     resizes without reflow), and what would return to the primary screen (`CSI ? 1049 l`, \
     `CSI ? 1047 l`, `CSI ? 47 l`, RIS) is taken out, so resizes are still compared",
)];

/// How many times each exemption applied, and whether the case being stripped has moved to the
/// alternate screen for good (the reflow exemption).
#[derive(Default)]
pub struct Tally {
    pub counts: Vec<(&'static str, u64)>,
    alternate: bool,
}

impl Tally {
    fn add(&mut self, name: &'static str) {
        match self.counts.iter_mut().find(|(n, _)| *n == name) {
            Some((_, count)) => *count = count.saturating_add(1),
            None => self.counts.push((name, 1)),
        }
    }
}

/// `case` with what the exemptions name taken out. A sequence split between two output steps is
/// read whole: its start is carried into the next output step, for both sides alike.
pub fn strip(case: &Case, tally: &mut Tally) -> Case {
    tally.alternate = false;
    let mut steps = Vec::with_capacity(case.steps.len());
    let mut carried: Vec<u8> = Vec::new();
    for step in &case.steps {
        match step {
            Step::Resize(..) => {
                // The resize still compared, with nothing for reflow to re-wrap: from the first
                // resize on, the case runs on the alternate screen, which resizes without reflow.
                tally.add("reflow");
                if !tally.alternate {
                    tally.alternate = true;
                    steps.push(Step::Output(b"\x1b[?1049h".to_vec()));
                }
                steps.push(step.clone());
            }
            Step::Output(bytes) => {
                let mut all = std::mem::take(&mut carried);
                all.extend_from_slice(bytes);
                let (kept, rest) = output(&all, tally);
                carried = rest;
                steps.push(Step::Output(kept));
            }
            Step::Keys(_) | Step::Frame { .. } | Step::Tick(_) => steps.push(step.clone()),
        }
    }
    if !carried.is_empty() {
        // Unfinished at the case's end: judged by what it holds.
        let (len, exempt) = sequence(&carried);
        match exempt {
            Some(name) => tally.add(name),
            None => steps.push(Step::Output(
                carried
                    .get(..len.max(1))
                    .map_or_else(Vec::new, <[u8]>::to_vec),
            )),
        }
    }
    Case {
        name: case.name.clone(),
        rows: case.rows,
        cols: case.cols,
        steps,
    }
}

/// `bytes` with the exempted sequences taken out, and an unfinished sequence at their end, held
/// back for the next output.
fn output(bytes: &[u8], tally: &mut Tally) -> (Vec<u8>, Vec<u8>) {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    while let Some(&byte) = bytes.get(at) {
        let rest = bytes.get(at..).unwrap_or_default();
        if byte == 0x1b {
            let (len, exempt) = sequence(rest);
            if len >= rest.len() && !finished(rest) {
                return (out, rest.to_vec());
            }
            let whole = rest.get(..len).unwrap_or_default();
            let exempt =
                exempt.or_else(|| (tally.alternate && leaves_alternate(whole)).then_some("reflow"));
            match exempt {
                Some(name) => tally.add(name),
                None => out.extend_from_slice(whole),
            }
            at = at.saturating_add(len.max(1));
            continue;
        }
        // A character, taken whole, so that no byte of it is read as a sequence's. Only the
        // continuation bytes that follow its lead are its own; a broken one ends at the first byte
        // that is not, which may start a sequence.
        let len = rest
            .iter()
            .skip(1)
            .take(utf8_len(byte).saturating_sub(1))
            .take_while(|b| (0x80..=0xbf).contains(*b))
            .count()
            .saturating_add(1);
        let chunk = rest.get(..len).unwrap_or_default();
        out.extend_from_slice(chunk);
        at = at.saturating_add(len);
    }
    (out, Vec::new())
}

/// Whether the whole escape sequence `sequence` returns to the primary screen: RIS, or resetting
/// mode 1049, 1047 or 47.
fn leaves_alternate(sequence: &[u8]) -> bool {
    if sequence == b"\x1bc" {
        return true;
    }
    let Some(body) = sequence
        .strip_prefix(b"\x1b[?")
        .and_then(|b| b.strip_suffix(b"l"))
    else {
        return false;
    };
    body.split(|&b| b == b';')
        .any(|p| p == b"1049" || p == b"1047" || p == b"47")
}

/// Whether the escape sequence `bytes` (starting with ESC, running to their end) is finished: a
/// CSI with its final byte, an OSC or DCS with its terminator, or a two-byte escape.
fn finished(bytes: &[u8]) -> bool {
    match bytes.get(1) {
        None => false,
        Some(b'[') => bytes
            .get(2..)
            .unwrap_or_default()
            .iter()
            .any(|b| (0x40..=0x7e).contains(b)),
        Some(b']' | b'P') => {
            let body = bytes.get(2..).unwrap_or_default();
            body.contains(&0x07) || body.windows(2).any(|w| w.first() == Some(&0x1b))
        }
        Some(_) => true,
    }
}

fn utf8_len(lead: u8) -> usize {
    match lead {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// The length of the escape sequence at the start of `bytes` (which starts with ESC), and the
/// exemption it falls under. An unfinished sequence runs to the end.
fn sequence(bytes: &[u8]) -> (usize, Option<&'static str>) {
    match bytes.get(1) {
        Some(b'[') => {
            let body = bytes.get(2..).unwrap_or_default();
            let private = body.first().copied().filter(|b| b"?<>=".contains(b));
            let mut i = usize::from(private.is_some());
            while body.get(i).is_some_and(|b| (0x20..=0x3f).contains(b)) {
                i = i.saturating_add(1);
            }
            match body.get(i) {
                Some(&last) if (0x40..=0x7e).contains(&last) => (i.saturating_add(3), None),
                // Anything else ends it unfinished (an ESC starts the next sequence).
                Some(_) => (i.saturating_add(2), None),
                None => (bytes.len(), None),
            }
        }
        Some(b']' | b'P') => {
            let body = bytes.get(2..).unwrap_or_default();
            let mut i = 0usize;
            // BEL or ST ends it; an ESC that starts anything else ends it too, as fux-vt reads it,
            // and starts the next sequence.
            let end = loop {
                match (body.get(i), body.get(i.saturating_add(1))) {
                    (Some(0x07), _) => break Some((i, 1)),
                    (Some(0x1b), Some(b'\\')) => break Some((i, 2)),
                    (Some(0x1b), Some(_)) => break Some((i, 0)),
                    (Some(_), _) => i = i.saturating_add(1),
                    (None, _) => break None,
                }
            };
            // Unfinished, it is judged by what it holds so far.
            let (len, terminator) = end.unwrap_or((body.len(), 0));
            let whole = if end.is_some() {
                len.saturating_add(2).saturating_add(terminator)
            } else {
                bytes.len()
            };
            (whole, None)
        }
        // An ESC after an ESC starts over.
        Some(0x1b) | None => (1, None),
        Some(_) => (2, None),
    }
}
