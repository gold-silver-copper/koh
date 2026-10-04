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
        "a resize: the server re-wraps the primary screen and its history",
    ),
    (
        "size",
        "mode 2048 and the size query `CSI 18 t`: the server answers both",
    ),
    (
        "identity",
        "device attributes (`CSI c`, `CSI > c`), XTVERSION (`CSI > q`) and cursor reports \
         (`CSI 6 n`, `CSI ? 6 n`): the server answers as koh",
    ),
    (
        "palette",
        "OSC 4, 5, 10–19, 104, 105 and 110–119: the server keeps a program's colours and draws \
         them as RGB",
    ),
    (
        "margins",
        "DECRQM of mode 69 (`CSI ? 69 $ p`): the server answers it as not recognized",
    ),
    (
        "underline",
        "SGR underline styles (`4:n`, `21`) and DECRQSS (`DCS $ q`): carried on the wire, and \
         answered",
    ),
    ("links", "OSC 8 hyperlinks: carried on the wire and painted"),
];

/// How many times each exemption applied.
#[derive(Default)]
pub struct Tally(pub Vec<(&'static str, u64)>);

impl Tally {
    fn add(&mut self, name: &'static str) {
        match self.0.iter_mut().find(|(n, _)| *n == name) {
            Some((_, count)) => *count = count.saturating_add(1),
            None => self.0.push((name, 1)),
        }
    }
}

/// `case` with what the exemptions name taken out.
pub fn strip(case: &Case, tally: &mut Tally) -> Case {
    let mut steps = Vec::with_capacity(case.steps.len());
    for step in &case.steps {
        match step {
            Step::Resize(..) => tally.add("reflow"),
            Step::Output(bytes) => steps.push(Step::Output(output(bytes, tally))),
            Step::Keys(_) | Step::Frame { .. } | Step::Tick(_) => steps.push(step.clone()),
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
        (Some(b'?'), [b'$'], b'p') if has(b"69") => Some("margins"),
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
/// sequence, taken out.
fn output(bytes: &[u8], tally: &mut Tally) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    // Whether the last thing kept was a sequence, so that a cluster character now would start a
    // cell of its own.
    let mut after_sequence = false;
    while let Some(&byte) = bytes.get(at) {
        let rest = bytes.get(at..).unwrap_or_default();
        if byte == 0x1b {
            let (len, exempt) = sequence(rest);
            let whole = rest.get(..len).unwrap_or_default();
            match exempt {
                Some(name) => tally.add(name),
                None => out.extend_from_slice(whole),
            }
            after_sequence = true;
            at = at.saturating_add(len.max(1));
            continue;
        }
        // A character: decoded whole, so that a cluster character can be told.
        let len = utf8_len(byte).min(rest.len()).max(1);
        let chunk = rest.get(..len).unwrap_or_default();
        let c = std::str::from_utf8(chunk)
            .ok()
            .and_then(|s| s.chars().next());
        match c {
            Some(c) if after_sequence && continues(c) => tally.add("cluster"),
            _ => {
                out.extend_from_slice(chunk);
                after_sequence = false;
            }
        }
        at = at.saturating_add(len);
    }
    out
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
                Some(&last) => (i.saturating_add(3), csi(private, raw, intermediates, last)),
                None => (bytes.len(), None),
            }
        }
        Some(b']' | b'P') => {
            let body = bytes.get(2..).unwrap_or_default();
            let mut i = 0usize;
            let end = loop {
                match (body.get(i), body.get(i.saturating_add(1))) {
                    (Some(0x07), _) => break Some((i, 1)),
                    (Some(0x1b), Some(b'\\')) => break Some((i, 2)),
                    (Some(_), _) => i = i.saturating_add(1),
                    (None, _) => break None,
                }
            };
            let Some((len, terminator)) = end else {
                return (bytes.len(), None);
            };
            let payload = body.get(..len).unwrap_or_default();
            let exempt = if bytes.get(1) == Some(&b']') {
                osc(payload)
            } else if payload.windows(2).any(|w| w == b"$q") {
                Some("underline")
            } else {
                None
            };
            (len.saturating_add(2).saturating_add(terminator), exempt)
        }
        Some(_) => (2, None),
        None => (1, None),
    }
}
