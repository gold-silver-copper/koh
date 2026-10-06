//! What the client asks the user's terminal once, at start-up, and the replies it reads back from
//! stdin before the session begins:
//!
//! - whether the terminal draws underline styles (kitty's `4:n`), asked two ways, as fux does, and
//!   either answer is enough:
//!   - XTGETTCAP for `Smulx` (`DCS + q 536d756c78 ST`, the name in hex), the terminfo capability
//!     that sets a style. Ghostty, kitty, WezTerm, foot and iTerm2 answer that they have it;
//!     xterm that it has not. Ghostty draws styles but reports a curly underline as plain to
//!     DECRQSS, so this is how it is known.
//!   - The pen, as neovim asks it: a curly underline set, then DECRQSS (`DCS $ q m ST`); a
//!     terminal that kept the style answers with `4:3` in it, as VTE does, which answers no
//!     XTGETTCAP. Then the pen is reset.
//! - whether it speaks the kitty keyboard protocol (`CSI ? u`): then the client pushes
//!   disambiguate and alternate keys (`CSI > 5 u`) while it runs, so keys legacy bytes cannot tell
//!   apart (Ctrl-I and Tab, Shift-Enter) reach the server apart;
//! - its colour scheme (`CSI ? 996 n`, mode 2031's query): a terminal that answers is asked to
//!   report changes too (`CSI ? 2031 h`);
//! - its foreground, background and palette entries 0 to 15 (OSC 10, 11, 4), which the server
//!   answers programs' colour queries with, unless the user turned that off (`--no-colours`).
//!
//! Primary device attributes (`CSI c`) come last: every terminal answers them, in order, so once
//! their answer is in, every other answer the terminal will give is too. What a terminal does not
//! answer is left as it was: plain underlines, legacy keys, no colours told.
//!
//! The replies are told from keys by their form, which no key has (a DCS, an OSC, a CSI with `?`),
//! and each is read with fux-vt's decoder, as the session reads later ones. The client asks this
//! itself, once, before any frame: nothing a server sends makes it ask the user's terminal
//! anything. Bytes that are not these replies (keys typed meanwhile) are kept, in order, for the
//! session.

use fux_vt::keys::decode::{Decoder, Input, Reply};

use crate::events::{narrow, WireColours, WireScheme, PALETTE};

/// The questions, ending with primary device attributes: underline styles, the kitty flags and
/// the scheme. The colours are asked too unless they are not told ([`queries`]).
pub const QUERIES: &[u8] =
    b"\x1bP+q536d756c78\x1b\\\x1b[0m\x1b[4:3m\x1bP$qm\x1b\\\x1b[0m\x1b[?u\x1b[?996n\x1b[c";

/// The colour questions, ending with primary device attributes: the foreground, the background and
/// palette entries 0 to 15. The session asks them again when the terminal reports a new scheme.
pub const COLOUR_QUERIES: &[u8] = b"\x1b]10;?\x1b\\\x1b]11;?\x1b\\\
\x1b]4;0;?\x1b\\\x1b]4;1;?\x1b\\\x1b]4;2;?\x1b\\\x1b]4;3;?\x1b\\\
\x1b]4;4;?\x1b\\\x1b]4;5;?\x1b\\\x1b]4;6;?\x1b\\\x1b]4;7;?\x1b\\\
\x1b]4;8;?\x1b\\\x1b]4;9;?\x1b\\\x1b]4;10;?\x1b\\\x1b]4;11;?\x1b\\\
\x1b]4;12;?\x1b\\\x1b]4;13;?\x1b\\\x1b]4;14;?\x1b\\\x1b]4;15;?\x1b\\\x1b[c";

/// Everything the client asks at start-up: the colours too if `colours`, before the rest.
pub fn queries(colours: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if colours {
        // Without its DA1: the one that ends `QUERIES` ends both.
        out.extend_from_slice(
            COLOUR_QUERIES
                .strip_suffix(b"\x1b[c")
                .unwrap_or(COLOUR_QUERIES),
        );
    }
    out.extend_from_slice(QUERIES);
    out
}

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
    kitty: bool,
    colours: WireColours,
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
        let whole = match sequence {
            // An OSC reply begins with a digit; it and a DCS reply end with ST, an OSC with BEL too.
            [0x1b, b']', first, ..] if !first.is_ascii_digit() => return self.give_back(),
            [0x1b, b'P' | b']', .., 0x1b, b'\\'] | [0x1b, b']', .., 0x07] => true,
            // A CSI reply has `?` and ends with its final byte.
            [0x1b, b'[', b'?', .., last] if (0x40..=0x7e).contains(last) => true,
            [0x1b, b'P' | b']', ..] | [0x1b, b'[', b'?', ..] | [0x1b, b'['] | [0x1b] => false,
            // ESC then anything else: a key, not a reply.
            _ => return self.give_back(),
        };
        if whole {
            let sequence = std::mem::take(&mut self.pending);
            self.reply(&sequence);
        } else if self.pending.len() > LONGEST {
            self.give_back();
        }
    }

    /// The sequence pending, given back to what was typed.
    fn give_back(&mut self) {
        self.typed.append(&mut self.pending);
    }

    /// A whole reply, read with fux-vt's decoder; one it does not read says nothing.
    fn reply(&mut self, sequence: &[u8]) {
        let mut decoder = Decoder::default();
        // As the answer to a question asked: a DCS answer is one only then.
        decoder.expect(std::time::Instant::now());
        let mut inputs = Vec::new();
        decoder.bytes(sequence, &mut inputs);
        for input in inputs {
            let Input::Reply(reply) = input else {
                continue;
            };
            match reply {
                Reply::UnderlineStyles => self.underline_styles = true,
                Reply::KittyFlags(_) => self.kitty = true,
                Reply::Scheme(scheme) => {
                    self.colours.scheme = Some(match scheme {
                        fux_vt::keys::colour::Scheme::Dark => WireScheme::Dark,
                        fux_vt::keys::colour::Scheme::Light => WireScheme::Light,
                    });
                }
                Reply::Colour { number: 10, rgb } => self.colours.foreground = Some(narrow(rgb)),
                Reply::Colour { number: 11, rgb } => self.colours.background = Some(narrow(rgb)),
                Reply::Palette { index, rgb } if usize::from(index) < PALETTE => {
                    self.colours.palette.resize(PALETTE, None);
                    if let Some(slot) = self.colours.palette.get_mut(usize::from(index)) {
                        *slot = Some(narrow(rgb));
                    }
                }
                Reply::Attributes => self.done = true,
                Reply::Colour { .. } | Reply::Palette { .. } | Reply::Mode { .. } => {}
            }
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

    /// Whether the terminal speaks the kitty keyboard protocol.
    pub fn kitty(&self) -> bool {
        self.kitty
    }

    /// Whether the terminal reports its colour scheme, and so can report changes (mode 2031).
    pub fn scheme_reports(&self) -> bool {
        self.colours.scheme.is_some()
    }

    /// What the terminal said of its colours.
    pub fn colours(&self) -> WireColours {
        self.colours.clone()
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

    #[test]
    fn the_kitty_flags_the_scheme_and_the_colours_are_read() {
        // Ghostty: kitty flags 0 (it speaks the protocol), a dark scheme, its colours.
        let r = read(&[
            b"\x1b]10;rgb:dddd/dddd/dddd\x1b\\\x1b]11;rgb:1e/1e/20\x07",
            b"\x1b]4;1;rgb:cdcd/0000/0000\x1b\\\x1b]4;15;rgb:ffff/ffff/ffff\x1b\\",
            b"\x1b[?0u\x1b[?997;1n\x1b[?62;22c",
        ]);
        assert!(r.done() && r.kitty() && r.scheme_reports());
        let colours = r.colours();
        assert_eq!(colours.foreground, Some([0xdd, 0xdd, 0xdd]));
        assert_eq!(colours.background, Some([0x1e, 0x1e, 0x20]));
        assert_eq!(colours.scheme, Some(WireScheme::Dark));
        assert_eq!(colours.palette.len(), PALETTE);
        assert_eq!(colours.palette.get(1), Some(&Some([0xcd, 0, 0])));
        assert_eq!(colours.palette.get(15), Some(&Some([0xff, 0xff, 0xff])));
        assert_eq!(colours.palette.get(2), Some(&None));
        assert_eq!(r.typed(), b"");
    }

    #[test]
    fn a_terminal_that_answers_none_of_it_is_left_as_it_was() {
        // Apple's Terminal: DA1 alone, keys typed around it.
        let r = read(&[b"a\x1b[?1;2cb"]);
        assert!(r.done() && !r.kitty() && !r.scheme_reports());
        assert!(!r.colours().known());
        assert_eq!(r.typed(), b"ab");
        // Keys that look like answers begun are given back: Alt-], an arrow, `OSC` past a digit.
        let r = read(&[b"\x1b]x\x1b[A\x1b[?1c"]);
        assert_eq!(r.typed(), b"\x1b]x\x1b[A");
    }

    #[test]
    fn the_colours_are_asked_unless_they_are_not_told() {
        assert_eq!(queries(false), QUERIES);
        let both = queries(true);
        assert!(both.starts_with(b"\x1b]10;?\x1b\\\x1b]11;?\x1b\\\x1b]4;0;?"));
        assert!(both.ends_with(QUERIES));
        // One DA1, the last.
        assert_eq!(both.windows(3).filter(|w| w == b"\x1b[c").count(), 1);
        for n in 0..16 {
            let asked = format!("\x1b]4;{n};?\x1b\\");
            assert!(COLOUR_QUERIES
                .windows(asked.len())
                .any(|w| w == asked.as_bytes()));
        }
    }
}
