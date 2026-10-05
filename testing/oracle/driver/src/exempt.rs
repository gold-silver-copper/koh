//! What the oracle exempts: the input that sets off a change made on purpose since the commit it
//! compares against. Each exemption is taken out of every case before either side sees it, so
//! that everything else in the case is still compared. Once the commit compared against has the
//! change, its exemption comes off this list.
//!
//! Sequences are read as fux-vt reads them: CSI with its parameters, intermediates and final
//! byte; OSC and DCS up to BEL or ST. A sequence is taken out whole.

use crate::case::{Case, Step};

/// The changes exempted, each with what sets it off and why it differs.
pub const EXEMPTIONS: &[(&str, &str)] = &[
    (
        "cluster",
        "a character that continues a cluster, written right after a sequence (a cursor move): \
         the client now places it with a cursor move rather than joining it to the glyph printed \
         before it",
    ),
    (
        "sync",
        "synchronized output (`CSI ? 2026 h`): the server holds a program's frame until it ends",
    ),
    (
        "reflow",
        "what a resize re-wraps: from its first resize on, a case runs on the alternate screen \
         (which resizes without reflow), and what would return to the primary screen \
         (`CSI ? 1049 l`, `CSI ? 1047 l`, `CSI ? 47 l`, RIS) is taken out, so resizes are still \
         compared",
    ),
    (
        "size",
        "mode 2048 and the size query `CSI 18 t`: the server answers both",
    ),
    (
        "identity",
        "device attributes (`CSI c`, `CSI > c`, DECID's `ESC Z`), XTVERSION (`CSI > q`) and \
         cursor reports (`CSI 6 n`, `CSI ? 6 n`): the server answers as koh",
    ),
    (
        "palette",
        "OSC 4, 5, 10–19, 104, 105 and 110–119: the server keeps a program's colours and draws \
         them as RGB",
    ),
    (
        "underline",
        "SGR underline styles (`4:n`, `21`) and DECRQSS (`DCS $ q`): carried on the wire, and \
         answered",
    ),
    ("links", "OSC 8 hyperlinks: carried on the wire and painted"),
];

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
    let mut after_sequence = false;
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
                let (kept, rest) = output(&all, tally, &mut after_sequence);
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

/// The parameter bytes of a CSI, split at `;`, each up to its first `:`.
fn params(params: &[u8]) -> impl Iterator<Item = &[u8]> {
    params
        .split(|&b| b == b';')
        .map(|p| p.split(|&b| b == b':').next().unwrap_or_default())
}

/// The exemption a CSI falls under, if any. `private` is its leading `?`, `>`, `<` or `=`.
fn csi(private: Option<u8>, raw: &[u8], intermediates: &[u8], last: u8) -> Option<&'static str> {
    let has = |n: &[u8]| params(raw).any(|p| p == n);
    match (private, intermediates, last) {
        (Some(b'?'), [], b'h' | b'l') if has(b"2026") => Some("sync"),
        (Some(b'?'), [], b'h' | b'l') | (Some(b'?'), [b'$'], b'p') if has(b"2048") => Some("size"),
        (None, [], b't') if has(b"18") => Some("size"),
        (None | Some(b'>' | b'='), [], b'c') | (Some(b'>'), [], b'q') => Some("identity"),
        (None | Some(b'?'), [], b'n') if has(b"6") => Some("identity"),
        (None, [], b'm') if raw.contains(&b':') || has(b"21") => Some("underline"),
        _ => None,
    }
}

/// The exemption an OSC falls under, if any, from its first parameter.
fn osc(payload: &[u8]) -> Option<&'static str> {
    let first = payload.split(|&b| b == b';').next().unwrap_or_default();
    let n: u32 = std::str::from_utf8(first).ok()?.parse().ok()?;
    match n {
        8 => Some("links"),
        4 | 5 | 10..=19 | 104 | 105 | 110..=119 => Some("palette"),
        _ => None,
    }
}

/// Whether `c` continues a cluster, after some glyph.
fn continues(c: char) -> bool {
    !c.is_ascii()
        && (fux_vt::continues_cluster("a", c) || fux_vt::continues_cluster("\u{1f44d}", c))
}

/// `bytes` with the exempted sequences, and the cluster characters written right after a
/// sequence, taken out; and an unfinished sequence at their end, held back for the next output.
/// `after_sequence` says whether the last thing kept was a sequence, so that a cluster character
/// now would start a cell of its own.
fn output(bytes: &[u8], tally: &mut Tally, after_sequence: &mut bool) -> (Vec<u8>, Vec<u8>) {
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
            *after_sequence = true;
            at = at.saturating_add(len.max(1));
            continue;
        }
        // A character: decoded whole, so that a cluster character can be told. Only the
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
        let c = std::str::from_utf8(chunk)
            .ok()
            .and_then(|s| s.chars().next());
        match c {
            Some(c) if *after_sequence && continues(c) => tally.add("cluster"),
            _ => {
                out.extend_from_slice(chunk);
                *after_sequence = false;
            }
        }
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
            let start = usize::from(private.is_some());
            let mut i = start;
            while body.get(i).is_some_and(|b| (0x30..=0x3f).contains(b)) {
                i = i.saturating_add(1);
            }
            let raw = body.get(start..i).unwrap_or_default();
            let mid = i;
            while body.get(i).is_some_and(|b| (0x20..=0x2f).contains(b)) {
                i = i.saturating_add(1);
            }
            let intermediates = body.get(mid..i).unwrap_or_default();
            match body.get(i) {
                Some(&last) if (0x40..=0x7e).contains(&last) => {
                    (i.saturating_add(3), csi(private, raw, intermediates, last))
                }
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
            let payload = body.get(..len).unwrap_or_default();
            let exempt = if bytes.get(1) == Some(&b']') {
                osc(payload)
            } else if payload.windows(2).any(|w| w == b"$q") {
                Some("underline")
            } else {
                None
            };
            let whole = if end.is_some() {
                len.saturating_add(2).saturating_add(terminator)
            } else {
                bytes.len()
            };
            (whole, exempt)
        }
        // An ESC after an ESC starts over.
        Some(0x1b) | None => (1, None),
        Some(_) => {
            // DECID (`ESC Z`), which is answered as DA1, read as fux-vt reads it: past the bytes
            // it ignores between the ESC and the `Z`.
            let skipped = bytes
                .iter()
                .skip(1)
                .take_while(|b| {
                    !(0x20..=0x7e).contains(*b) && **b != 0x1b && **b != 0x18 && **b != 0x1a
                })
                .count();
            if bytes.get(skipped.saturating_add(1)) == Some(&b'Z') {
                (skipped.saturating_add(2), Some("identity"))
            } else {
                (2, None)
            }
        }
    }
}
