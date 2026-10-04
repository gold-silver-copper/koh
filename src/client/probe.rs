//! What the client asks the user's terminal once, at start-up, and the replies it reads back from
//! stdin before the session begins: whether the terminal draws underline styles (kitty's `4:n`).
//!
//! It asks two ways, as fux does, and either answer is enough:
//!
//! - XTGETTCAP for `Smulx` (`DCS + q 536d756c78 ST`, the name in hex), the terminfo capability
//!   that sets a style. Ghostty, kitty, WezTerm, foot and iTerm2 answer that they have it; xterm
//!   that it has not. Ghostty draws styles but reports a curly underline as plain to DECRQSS, so
//!   this is how it is known.
//! - The pen, as neovim asks it: a curly underline set, then DECRQSS (`DCS $ q m ST`); a terminal
//!   that kept the style answers with `4:3` in it, as VTE does, which answers no XTGETTCAP. Then
//!   the pen is reset.
//!
//! Primary device attributes (`CSI c`) come last: every terminal answers them, in order, so once
//! their answer is in, every other answer the terminal will give is too. A terminal that answers
//! neither question is painted plain underlines, as before: a terminal that does not know `4:3`
//! draws no underline at all, or reads the colon as a semicolon (underline and italic).
//!
//! The client asks this itself, once, before any frame: nothing a server sends makes it ask the
//! user's terminal anything. Bytes that are not these replies (keys typed meanwhile) are kept, in
//! order, for the session.

/// The questions, ending with primary device attributes.
pub const QUERIES: &[u8] = b"\x1bP+q536d756c78\x1b\\\x1b[0m\x1b[4:3m\x1bP$qm\x1b\\\x1b[0m\x1b[c";

/// The longest reply kept while it is read; a longer escape sequence is no reply to these.
const LONGEST: usize = 256;

/// The terminal's replies, read out of what stdin gives.
#[derive(Debug, Default)]
pub struct Replies {
    /// An escape sequence begun and not yet ended.
    pending: Vec<u8>,
    /// What is not a reply, for the session.
    typed: Vec<u8>,
    underline_styles: bool,
    /// Whether the device attributes' answer, the last, is in.
    done: bool,
}

impl Replies {
    /// Read `bytes`, as stdin gave them.
    pub fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.done {
                self.typed.push(byte);
                continue;
            }
            if self.pending.is_empty() {
                if byte == 0x1b {
                    self.pending.push(byte);
                } else {
                    self.typed.push(byte);
                }
                continue;
            }
            self.pending.push(byte);
            self.step();
        }
    }

    /// The escape sequence in `pending`, after its newest byte: taken if it is a whole reply,
    /// given back to what was typed if it cannot be one, else kept.
    fn step(&mut self) {
        let sequence = self.pending.as_slice();
        match sequence {
            // A DCS reply ends with ST.
            [0x1b, b'P', body @ ..] => {
                if let [payload @ .., 0x1b, b'\\'] = body {
                    let payload = payload.to_vec();
                    self.pending.clear();
                    self.reply(&payload);
                }
            }
            // A CSI ends with its final byte; DA1's answer is `CSI ? … c`.
            [0x1b, b'[', body @ ..] => match body.last() {
                Some(last) if (0x40..=0x7e).contains(last) => {
                    if body.first() == Some(&b'?') && *last == b'c' {
                        self.pending.clear();
                        self.done = true;
                    } else {
                        self.give_back();
                    }
                }
                Some(_) | None => {}
            },
            [0x1b] => {}
            // ESC then anything else: a key, not a reply.
            _ => self.give_back(),
        }
        if self.pending.len() > LONGEST {
            self.give_back();
        }
    }

    /// The sequence pending, given back to what was typed.
    fn give_back(&mut self) {
        self.typed.append(&mut self.pending);
    }

    /// A DCS reply's payload.
    fn reply(&mut self, payload: &[u8]) {
        // XTGETTCAP: `1 + r 536d756c78 = …`, the capability found.
        let has_smulx = payload
            .strip_prefix(b"1+r")
            .is_some_and(|rest| rest.starts_with(b"536d756c78"));
        // DECRQSS of the pen: `1 $ r … m`, with the curly underline kept.
        let kept_curly = payload
            .strip_prefix(b"1$r")
            .is_some_and(|pen| pen.windows(3).any(|w| w == b"4:3"));
        if has_smulx || kept_curly {
            self.underline_styles = true;
        }
    }

    /// Whether every reply is in.
    pub fn done(&self) -> bool {
        self.done
    }

    /// Whether the terminal draws underline styles.
    pub fn underline_styles(&self) -> bool {
        self.underline_styles
    }

    /// What was typed meanwhile, in order, an unfinished sequence included.
    pub fn typed(mut self) -> Vec<u8> {
        self.give_back();
        self.typed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(chunks: &[&[u8]]) -> Replies {
        let mut replies = Replies::default();
        for chunk in chunks {
            replies.push(chunk);
        }
        replies
    }

    #[test]
    fn a_terminal_with_smulx_draws_styles() {
        // Ghostty: XTGETTCAP finds Smulx; DECRQSS reports the curly underline plain.
        let r =
            read(&[b"\x1bP1+r536d756c78=1b5b343a25703125646d\x1b\\\x1bP1$r0;4m\x1b\\\x1b[?62;22c"]);
        assert!(r.done() && r.underline_styles());
        assert_eq!(r.typed(), b"");
    }

    #[test]
    fn a_terminal_that_kept_the_curly_pen_draws_styles() {
        // VTE: no XTGETTCAP answer, the pen comes back with 4:3.
        let r = read(&[b"\x1bP1$r0;4:3m\x1b\\\x1b[?65;1;9c"]);
        assert!(r.done() && r.underline_styles());
    }

    #[test]
    fn a_terminal_that_knows_neither_is_painted_plain() {
        // xterm: Smulx not found, the pen without 4:3. Apple's Terminal: DA1 alone.
        let xterm = read(&[b"\x1bP0+r536d756c78\x1b\\\x1bP1$r0;4m\x1b\\\x1b[?64;1;2c"]);
        assert!(xterm.done() && !xterm.underline_styles());
        let apple = read(&[b"\x1b[?1;2c"]);
        assert!(apple.done() && !apple.underline_styles());
    }

    #[test]
    fn keys_typed_meanwhile_are_kept_in_order_and_replies_split_between_reads_are_read() {
        let r = read(&[
            b"ls\x1b[A",
            b"\x1bP1+r536d",
            b"756c78=x\x1b",
            b"\\x\x1bOD\x1b[?62;",
            b"22cafter",
        ]);
        assert!(r.done() && r.underline_styles());
        assert_eq!(r.typed(), b"ls\x1b[Ax\x1bODafter");
    }

    #[test]
    fn an_unfinished_sequence_is_given_back_and_a_long_one_is_no_reply() {
        let r = read(&[b"a\x1b"]);
        assert!(!r.done());
        assert_eq!(r.typed(), b"a\x1b");
        let long = [&b"\x1bP"[..], &[b'x'; 300]].concat();
        let r = read(&[&long, b"\x1b[?1c"]);
        assert!(r.done() && !r.underline_styles());
        assert_eq!(r.typed(), long);
    }
}
