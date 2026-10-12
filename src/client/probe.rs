//! What the client asks the user's terminal once, at start-up, as the first phase of its session
//! ([`ClientSession::ask_terminal`](super::ClientSession::ask_terminal)):
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
//! The answers are read by the session's own decoder, the one stdin has for the whole run, with
//! answers expected: they are told from keys by their form, which no key has (a DCS while one is
//! expected, an OSC, a CSI with `?`), however late they come, so none reaches the program as keys.
//! The client asks this itself, once, before any frame: nothing a server sends makes it ask the
//! user's terminal anything.

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

#[cfg(test)]
mod tests {
    use super::*;

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
