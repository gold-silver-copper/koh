//! What of a program's output reaches the user's terminal: all of it but the questions the
//! server answers and the shell's marks, which travel apart ([`Piece::Mark`]).
//!
//! The server reads its sessions' output through a [`Filter`], and so does the client, before
//! the user's terminal does; each judges escape sequences whole, however the output is split.
//!
//! - **Questions** (device attributes, cursor and status reports, DECRQM, XTVERSION, the kitty
//!   keyboard flags, colour queries, DECRQSS, XTGETTCAP, window reports, ENQ, DECID) are dropped:
//!   the server's own terminal answers them, so the user's terminal must not answer too, and a
//!   server cannot make it answer anything.
//! - **Marks** (OSC 133) are taken out. The server relays a shell's marks as [`Piece::Mark`],
//!   the session's nonce removed, and only those that carry it when the shell was given one, so
//!   no program the shell runs can fake one; the client writes each again with the nonce its own
//!   terminal asks for. Marks a program prints never reach the user's terminal as they are.
//! - **The clipboard** (OSC 52) and **links** (OSC 8) pass, unless turned off: the client drops
//!   them for `--no-clipboard` and `--no-hyperlinks`, whatever the server sent. A clipboard read
//!   (`?`) is a question, and always dropped; a write passes only as base64 of at most
//!   [`MAX_CLIPBOARD`] bytes.
//! - **Titles** (OSC 0, 1, 2) pass cut to [`MAX_TITLE`] characters, with no control in them.
//!
//! Everything else passes as the program wrote it. [`Piece::Out`]s end where a sequence ends and
//! a UTF-8 character ends, so what is written between two of them never lands inside one. A
//! sequence longer than its bound is dropped to its end, so a filter holds at most
//! [`MAX_STRING`] bytes, whatever the program writes.

/// Most bytes of a control sequence (CSI) a filter gathers; a longer one is dropped.
pub const MAX_CSI: usize = 256;

/// Most bytes of a control string (OSC, DCS, APC, PM, SOS) a filter gathers; a longer one is
/// dropped.
pub const MAX_STRING: usize = 1 << 20;

/// Most bytes of an [`Piece::Out`].
pub const MAX_OUT: usize = 16 * 1024;

/// Most bytes of a mark's payload, after `133;`.
pub const MAX_MARK: usize = 256;

/// Most bytes of base64 a clipboard write (OSC 52) carries; a longer one is dropped.
pub const MAX_CLIPBOARD: usize = 16 * 1024;

/// Most characters of a title (OSC 0, 1, 2), as mosh cuts them; the rest is cut off.
pub const MAX_TITLE: usize = 256;

/// What a filter passes on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    /// Bytes for the user's terminal.
    Out(Vec<u8>),
    /// A shell mark: what followed `OSC 133 ;`, the nonce removed (`A`, `C`, `C;late`,
    /// `D;0`), printable ASCII.
    Mark(Vec<u8>),
}

/// Which shell marks a filter relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Marks {
    /// None: every OSC 133 is dropped.
    Drop,
    /// Every one, as a [`Piece::Mark`].
    All,
    /// Only those carrying `nonce=` this: a shell koh started so that it marks its commands.
    Signed(Vec<u8>),
}

/// What a filter lets through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub marks: Marks,
    pub clipboard: bool,
    pub links: bool,
}

/// Where the filter is in what it reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Ground,
    /// After ESC.
    Escape,
    /// After ESC and an intermediate byte.
    EscapeIntermediate,
    Csi,
    /// A control string: OSC, DCS, APC, PM or SOS.
    Text(Kind),
    /// ESC inside a control string: `\` ends it, anything else ends it and begins a sequence.
    TextEscape,
}

/// Which control string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Osc,
    Dcs,
    /// APC, PM or SOS: passed as they are.
    Other,
}

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;
const ENQ: u8 = 0x05;

/// Reads output however it is split, and passes on what reaches the user's terminal.
#[derive(Debug)]
pub struct Filter {
    policy: Policy,
    state: State,
    /// The sequence being read, from its ESC.
    seq: Vec<u8>,
    /// It passed its bound: it is read to its end and dropped.
    over: bool,
    /// What passes, not yet given out.
    out: Vec<u8>,
}

impl Filter {
    pub const fn new(policy: Policy) -> Self {
        Self {
            policy,
            state: State::Ground,
            seq: Vec::new(),
            over: false,
            out: Vec::new(),
        }
    }

    /// What it lets through.
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Whether the filter is between sequences: what is written now lands in none.
    pub fn between(&self) -> bool {
        self.state == State::Ground
    }

    /// Read `bytes`, giving `emit` what passes: whole sequences, and whole characters, held back
    /// until their end comes.
    pub fn feed(&mut self, bytes: &[u8], emit: &mut impl FnMut(Piece)) {
        for &byte in bytes {
            self.byte(byte, emit);
        }
        self.flush(emit);
    }

    /// Give out what passed, but a character whose end has not come.
    fn flush(&mut self, emit: &mut impl FnMut(Piece)) {
        let keep = incomplete_utf8(&self.out);
        let at = self.out.len().saturating_sub(keep);
        if at == 0 {
            return;
        }
        let rest = self.out.split_off(at);
        emit(Piece::Out(std::mem::replace(&mut self.out, rest)));
    }

    /// Pass `byte`, giving out a full chunk at a character's end.
    fn pass(&mut self, byte: u8, emit: &mut impl FnMut(Piece)) {
        self.out.push(byte);
        if self.out.len() >= MAX_OUT && incomplete_utf8(&self.out) == 0 {
            emit(Piece::Out(std::mem::take(&mut self.out)));
        }
    }

    fn begin(&mut self, state: State) {
        self.state = state;
        self.seq.clear();
        self.seq.push(ESC);
        self.over = false;
    }

    /// Add `byte` to the sequence being read, within `max`.
    fn gather(&mut self, byte: u8, max: usize) {
        if self.seq.len() >= max {
            self.over = true;
            self.seq.clear();
        }
        if !self.over {
            self.seq.push(byte);
        }
    }

    /// The sequence read is whole: pass it, or what it says, or nothing.
    fn finish(&mut self, emit: &mut impl FnMut(Piece)) {
        self.state = State::Ground;
        if std::mem::take(&mut self.over) {
            self.seq.clear();
            return;
        }
        let seq = std::mem::take(&mut self.seq);
        match judge(&seq, &self.policy) {
            Judged::Pass => {
                for &b in &seq {
                    self.pass(b, emit);
                }
            }
            Judged::Drop => {}
            Judged::Out(bytes) => {
                for &b in &bytes {
                    self.pass(b, emit);
                }
            }
            Judged::Mark(mark) => {
                self.flush(emit);
                // A character cut short before the mark never ends now: it goes before it, as
                // it came.
                if !self.out.is_empty() {
                    emit(Piece::Out(std::mem::take(&mut self.out)));
                }
                emit(Piece::Mark(mark));
            }
        }
        self.seq = seq;
        self.seq.clear();
    }

    fn byte(&mut self, byte: u8, emit: &mut impl FnMut(Piece)) {
        match self.state {
            State::Ground => match byte {
                ESC => self.begin(State::Escape),
                // The answerback: a question.
                ENQ => {}
                _ => self.pass(byte, emit),
            },
            State::Escape => match byte {
                b'[' => {
                    self.seq.push(byte);
                    self.state = State::Csi;
                }
                b']' | b'P' | b'_' | b'^' | b'X' => {
                    self.seq.push(byte);
                    self.state = State::Text(match byte {
                        b']' => Kind::Osc,
                        b'P' => Kind::Dcs,
                        _ => Kind::Other,
                    });
                }
                0x20..=0x2f => {
                    self.seq.push(byte);
                    self.state = State::EscapeIntermediate;
                }
                0x30..=0x7e => {
                    self.seq.push(byte);
                    self.finish(emit);
                }
                ESC => {
                    // A lone ESC, then another sequence.
                    self.pass(ESC, emit);
                    self.begin(State::Escape);
                }
                CAN | SUB => self.state = State::Ground,
                _ => {
                    // A control inside the sequence is done as it comes, and the sequence goes
                    // on, as a terminal does.
                    self.pass(byte, emit);
                }
            },
            State::EscapeIntermediate => match byte {
                0x20..=0x2f => self.gather(byte, MAX_CSI),
                0x30..=0x7e => {
                    self.gather(byte, MAX_CSI);
                    self.finish(emit);
                }
                ESC => self.begin(State::Escape),
                CAN | SUB => self.state = State::Ground,
                _ => self.pass(byte, emit),
            },
            State::Csi => match byte {
                0x20..=0x3f => self.gather(byte, MAX_CSI),
                0x40..=0x7e => {
                    self.gather(byte, MAX_CSI);
                    self.finish(emit);
                }
                ESC => self.begin(State::Escape),
                CAN | SUB => self.state = State::Ground,
                // A control inside a CSI is done as it comes, the CSI going on.
                0x00..=0x1f => self.pass(byte, emit),
                // DEL is ignored inside one; anything else ends it, malformed.
                0x7f => {}
                _ => self.state = State::Ground,
            },
            State::Text(kind) => match byte {
                ESC => self.state = State::TextEscape,
                BEL if kind == Kind::Osc => {
                    self.gather(byte, MAX_STRING);
                    self.finish(emit);
                }
                CAN | SUB => self.state = State::Ground,
                _ => self.gather(byte, MAX_STRING),
            },
            State::TextEscape => {
                if byte == b'\\' {
                    self.gather(ESC, MAX_STRING);
                    self.gather(byte, MAX_STRING);
                    self.finish(emit);
                } else {
                    // ESC ends the string unterminated, dropped as a terminal drops it, and
                    // begins a sequence of its own.
                    self.over = true;
                    self.finish(emit);
                    self.begin(State::Escape);
                    self.byte(byte, emit);
                }
            }
        }
    }
}

/// How many bytes at the end of `bytes` begin a UTF-8 character whose end has not come.
fn incomplete_utf8(bytes: &[u8]) -> usize {
    for back in 1..=3_usize.min(bytes.len()) {
        let Some(&b) = bytes.get(bytes.len().saturating_sub(back)) else {
            return 0;
        };
        if b & 0xc0 == 0x80 {
            continue;
        }
        let needs = match b {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return 0,
        };
        return if back < needs { back } else { 0 };
    }
    0
}

/// What becomes of a whole sequence.
enum Judged {
    Pass,
    Drop,
    /// These bytes instead.
    Out(Vec<u8>),
    Mark(Vec<u8>),
}

/// What `seq`, a whole sequence from its ESC, comes to under `policy`.
fn judge(seq: &[u8], policy: &Policy) -> Judged {
    let question = match seq.get(1) {
        Some(b'[') => csi_asks(seq.get(2..).unwrap_or_default()),
        Some(b']') => return osc(seq, policy),
        Some(b'P') => dcs_asks(seq.get(2..).unwrap_or_default()),
        // DECID asks who the terminal is.
        Some(b'Z') => seq.len() == 2,
        _ => false,
    };
    if question {
        Judged::Drop
    } else {
        Judged::Pass
    }
}

/// Whether a CSI's `body` (after `ESC [`) asks the terminal something.
fn csi_asks(body: &[u8]) -> bool {
    let Some((&last, rest)) = body.split_last() else {
        return false;
    };
    let (private, rest) = match rest.first() {
        Some(&p @ (b'<' | b'=' | b'>' | b'?')) => (Some(p), rest.get(1..).unwrap_or_default()),
        _ => (None, rest),
    };
    let split = rest
        .iter()
        .position(|b| (0x20..=0x2f).contains(b))
        .unwrap_or(rest.len());
    let (params, intermediates) = rest.split_at(split);
    let first = params
        .split(|&b| b == b';' || b == b':')
        .next()
        .and_then(|p| std::str::from_utf8(p).ok())
        .and_then(|p| p.parse::<u32>().ok());
    // Device attributes (primary, secondary, tertiary); status and cursor reports (DSR,
    // DECXCPR, the colour scheme); DECRQM of an ANSI or a DEC mode; XTVERSION; the kitty
    // keyboard flags; XTSMGRAPHICS; DECREQTPARM; DECRQLP, the locator; and the window reports:
    // its state, place, size in pixels and cells, the screen's, its titles.
    matches!(
        (private, intermediates, last),
        (None | Some(b'>' | b'='), b"", b'c')
            | (None | Some(b'?'), b"", b'n')
            | (None | Some(b'?'), b"$", b'p')
            | (Some(b'>'), b"", b'q')
            | (Some(b'?'), b"", b'u' | b'S')
            | (None, b"", b'x')
            | (None, b"'", b'|')
    ) || (private.is_none()
        && intermediates.is_empty()
        && last == b't'
        && matches!(first, Some(11 | 13 | 14 | 15 | 16 | 18 | 19 | 20 | 21)))
}

/// Whether a DCS's `body` (after `ESC P`) asks the terminal something: DECRQSS (`$q`) and
/// XTGETTCAP (`+q`).
fn dcs_asks(body: &[u8]) -> bool {
    let head: Vec<u8> = body
        .iter()
        .copied()
        .skip_while(|b| b.is_ascii_digit() || *b == b';')
        .take(2)
        .collect();
    head == b"$q" || head == b"+q"
}

/// What an OSC, `seq` from its ESC to its terminator, comes to.
fn osc(seq: &[u8], policy: &Policy) -> Judged {
    let body = seq.get(2..).unwrap_or_default();
    let body = body
        .strip_suffix(&[BEL])
        .or_else(|| body.strip_suffix(b"\x1b\\"))
        .unwrap_or(body);
    let (number, data) = match body.iter().position(|&b| b == b';') {
        Some(at) => (
            body.get(..at).unwrap_or_default(),
            body.get(at.saturating_add(1)..),
        ),
        None => (body, None),
    };
    let data = data.unwrap_or_default();
    let fields = || data.split(|&b| b == b';');
    match number {
        b"133" => mark(data, &policy.marks).map_or(Judged::Drop, Judged::Mark),
        // A read of the clipboard is a question; a write passes if the clipboard may be set.
        b"52" => {
            let written = fields().nth(1).unwrap_or_default();
            if policy.clipboard && written.len() <= MAX_CLIPBOARD && base64(written) {
                Judged::Pass
            } else {
                Judged::Drop
            }
        }
        b"0" | b"1" | b"2" => {
            let title: String = String::from_utf8_lossy(data)
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_TITLE)
                .collect();
            let mut out = b"\x1b]".to_vec();
            out.extend_from_slice(number);
            out.push(b';');
            out.extend_from_slice(title.as_bytes());
            out.push(BEL);
            Judged::Out(out)
        }
        b"8" if !policy.links => Judged::Drop,
        // A palette entry's colour asked, or a dynamic colour's.
        b"4" | b"10" | b"11" | b"12" | b"13" | b"14" | b"15" | b"16" | b"17" | b"18" | b"19"
            if fields().any(|field| field == b"?") =>
        {
            Judged::Drop
        }
        _ => Judged::Pass,
    }
}

/// Whether `text` is base64, and not empty: what a clipboard write must be.
fn base64(text: &[u8]) -> bool {
    !text.is_empty()
        && text
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// The mark `data` (after `133;`) relays under `marks`, its nonce removed: `None` if it is not
/// relayed, or is no mark a terminal reads (not printable ASCII, or too long).
fn mark(data: &[u8], marks: &Marks) -> Option<Vec<u8>> {
    if data.is_empty() || data.len() > MAX_MARK || !data.iter().all(|b| (0x20..0x7f).contains(b)) {
        return None;
    }
    let nonce = data
        .split(|&b| b == b';')
        .find_map(|field| field.strip_prefix(b"nonce="));
    let relayed = match (marks, nonce) {
        (Marks::Signed(ours), Some(theirs)) => ours.as_slice() == theirs,
        (Marks::Drop | Marks::Signed(_), _) => false,
        (Marks::All, _) => true,
    };
    if !relayed {
        return None;
    }
    // A state report is the server's to make, never a program's.
    if data.first() == Some(&b'S') {
        return None;
    }
    let kept: Vec<&[u8]> = data
        .split(|&b| b == b';')
        .filter(|field| !field.starts_with(b"nonce="))
        .collect();
    Some(kept.join(&b';'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(policy: Policy, chunks: &[&[u8]]) -> Vec<Piece> {
        let mut filter = Filter::new(policy);
        let mut pieces = Vec::new();
        for chunk in chunks {
            filter.feed(chunk, &mut |p| pieces.push(p));
        }
        pieces
    }

    fn signed() -> Policy {
        Policy {
            marks: Marks::Signed(b"k1".to_vec()),
            clipboard: true,
            links: true,
        }
    }

    /// What passes, as one string, marks shown as `<A>`.
    fn shown(pieces: &[Piece]) -> String {
        let mut s = String::new();
        for p in pieces {
            match p {
                Piece::Out(b) => s.push_str(&String::from_utf8_lossy(b)),
                Piece::Mark(m) => {
                    s.push('<');
                    s.push_str(&String::from_utf8_lossy(m));
                    s.push('>');
                }
            }
        }
        s
    }

    #[test]
    fn questions_are_dropped_and_the_rest_passes_however_it_is_split() {
        let input: &[u8] = b"a\x1b[c\x1b[>c\x1b[6n\x1b[?6n\x1b[?2026$p\x1b[>q\x1b[?u\x1b[18t\
            \x1b]11;?\x07\x1b]4;1;?\x1b\\\x1bP$qm\x1b\\\x1bP+q536d756c78\x1b\\\x05\x1bZ\
            b\x1b[1;31mc\x1b[2 q\x1b[?1049h\x1b]0;title\x07\x1b]11;rgb:0/0/0\x07\x1b[>1u\x1b[22t\
            \x1bPq#0;2;0;0;0\x1b\\\xc3\xa9";
        let want = "ab\x1b[1;31mc\x1b[2 q\x1b[?1049h\x1b]0;title\x07\x1b]11;rgb:0/0/0\x07\
            \x1b[>1u\x1b[22t\x1bPq#0;2;0;0;0\x1b\\é";
        let whole = shown(&run(signed(), &[input]));
        assert_eq!(whole, want);
        // Byte by byte: the same, and never a piece that ends inside a sequence or a character.
        let bytes: Vec<&[u8]> = input.chunks(1).collect();
        let pieces = run(signed(), &bytes);
        assert_eq!(shown(&pieces), want);
        let mut check = Filter::new(signed());
        for piece in &pieces {
            if let Piece::Out(bytes) = piece {
                assert!(std::str::from_utf8(bytes).is_ok(), "{bytes:?}");
                check.feed(bytes, &mut |_| {});
                assert!(
                    check.between(),
                    "a piece ended inside a sequence: {bytes:?}"
                );
            }
        }
    }

    #[test]
    fn only_the_shells_signed_marks_are_relayed_without_the_nonce() {
        let input: &[u8] = b"\x1b]133;A;nonce=k1\x07$ ls\r\n\x1b]133;C;nonce=k1\x07\
            \x1b]133;D;0;nonce=forged\x07\x1b]133;D;0\x07out\x1b]133;D;1;nonce=k1\x1b\\\
            \x1b]133;S;activity=busy;nonce=k1\x07";
        assert_eq!(shown(&run(signed(), &[input])), "<A>$ ls\r\n<C>out<D;1>",);
        let all = Policy {
            marks: Marks::All,
            ..signed()
        };
        assert_eq!(
            shown(&run(all, &[input])),
            "<A>$ ls\r\n<C><D;0><D;0>out<D;1>",
        );
        let none = Policy {
            marks: Marks::Drop,
            ..signed()
        };
        assert_eq!(shown(&run(none, &[input])), "$ ls\r\nout");
    }

    #[test]
    fn the_clipboard_and_links_pass_only_if_allowed_and_a_clipboard_read_never() {
        let mut input =
            b"\x1b]52;c;aGk=\x07\x1b]52;c;?\x07\x1b]52;c;not base64\x07\x1b]8;;https://x\x1b\\x\x1b]8;;\x1b\\"
                .to_vec();
        // A clipboard write over the cap is dropped whole.
        input.extend_from_slice(b"\x1b]52;c;");
        input.extend(std::iter::repeat_n(b'A', MAX_CLIPBOARD + 4));
        input.push(BEL);
        let input = input.as_slice();
        let off = Policy {
            marks: Marks::Drop,
            clipboard: false,
            links: false,
        };
        assert_eq!(shown(&run(off, &[input])), "x");
        assert_eq!(
            shown(&run(signed(), &[input])),
            "\x1b]52;c;aGk=\x07\x1b]8;;https://x\x1b\\x\x1b]8;;\x1b\\"
        );
    }

    #[test]
    fn a_title_is_cut_to_its_bound_with_no_control_in_it() {
        let mut input = b"\x1b]2;a\rb\xc2\x9b".to_vec();
        input.extend(std::iter::repeat_n(b'x', MAX_TITLE + 10));
        input.extend_from_slice(b"\x1b\\\x1b]0;\x07");
        let want = format!("\x1b]2;ab{}\x07\x1b]0;\x07", "x".repeat(MAX_TITLE - 2));
        assert_eq!(shown(&run(signed(), &[&input])), want);
    }

    #[test]
    fn a_sequence_past_its_bound_is_dropped_whole_and_what_follows_passes() {
        let mut input = b"\x1b]2;".to_vec();
        input.extend(std::iter::repeat_n(b'x', MAX_STRING + 10));
        input.extend_from_slice(b"\x07after\x1b[");
        input.extend(std::iter::repeat_n(b'1', MAX_CSI + 10));
        input.extend_from_slice(b"mend");
        let mut filter = Filter::new(signed());
        let mut out = Vec::new();
        for chunk in input.chunks(4096) {
            filter.feed(chunk, &mut |p| out.push(p));
            assert!(filter.seq.len() <= MAX_STRING);
        }
        assert_eq!(shown(&out), "afterend");
    }
}
