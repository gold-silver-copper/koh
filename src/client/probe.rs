//! What the client asks the user's terminal once, at start-up, before it connects:
//!
//! - its colour scheme (`CSI ? 996 n`, mode 2031's query): a terminal that answers is asked to
//!   report changes too (`CSI ? 2031 h`);
//! - its foreground, background and palette entries 0 to 15 (OSC 10, 11, 4), which the server
//!   answers programs' colour queries with, unless the user turned that off (`--no-colours`).
//!
//! Primary device attributes (`CSI c`) come last: every terminal answers them, in order, so once
//! their answer is in, every other answer the terminal will give is too. What a terminal does not
//! answer is left as it was: no colours told.
//!
//! The answers are read by the session's own decoder, the one stdin has for the whole run, with
//! answers expected: they are told from keys by their form, which no key has (an OSC, a CSI with
//! `?`), however late they come, so none reaches the program as keys. The client asks this
//! itself: nothing a server sends makes the user's terminal answer anything ([`crate::stream`]).

/// The questions, ending with primary device attributes: the scheme. The colours are asked too
/// unless they are not told ([`queries`]).
pub const QUERIES: &[u8] = b"\x1b[?996n\x1b[c";

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
