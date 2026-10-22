//! What `koh connect` reads from the user's terminal.
//!
//! Keys, pastes, the mouse and focus, decoded whatever protocol the terminal speaks (fux-vt's
//! decoder), for the server to encode as the program asked; the escape prefix (`Ctrl-^`) and its
//! commands; and the terminal's answers to the client's own questions, its colours
//! ([`super::probe`]), which go no further.

use std::time::Instant;

use fux_vt::keys::colour::Scheme;
use fux_vt::keys::decode::{Decoder, Input as Decoded, Reply};
use fux_vt::keys::encode::{key_bytes, KeyMode};
use fux_vt::keys::Keystroke;

use crate::events::{InputEvent, WireColours, WireScheme, MAX_PASTE};
use crate::stream::incomplete_utf8;

use super::probe::{self, COLOUR_QUERIES};

/// The escape prefix (Ctrl-^); followed by '.' it detaches.
pub const ESCAPE_PREFIX: u8 = 0x1e;

/// After the escape prefix, suspends the client (as mosh does): in raw mode `Ctrl-Z` is a plain
/// byte, not SIGTSTP.
pub const SUSPEND_KEY: u8 = 0x1a;

/// The keys the client reads its own commands in: xterm's legacy bytes, in normal cursor mode.
const LEGACY: KeyMode = KeyMode::Legacy {
    application: false,
    keypad: false,
    other_keys: None,
    backarrow: false,
};

/// What was read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// Input for the program, in order.
    pub events: Vec<InputEvent>,
    /// The user typed the escape prefix and `.`: detach.
    pub quit: bool,
    /// The user typed the escape prefix and `Ctrl-Z`: suspend, once the rest is taken.
    pub suspend: bool,
    /// The terminal's colours, to tell the server: a round of answers is in.
    pub colours: Option<WireColours>,
    /// A paste too long to send was dropped.
    pub paste_too_long: bool,
}

/// The input machine: one decoder for the whole run, so a sequence split across reads, or an
/// answer late in coming, is still taken as what it is.
pub struct Keys {
    decoder: Decoder,
    /// The escape prefix, typed: what the next key does.
    prefix: Option<Keystroke>,
    /// The terminal's colours as its answers said them, while they are told.
    colours: Option<WireColours>,
    /// A round of colour questions is out, its last answer (DA1) not in.
    asked: bool,
    /// The terminal was asked to report a new scheme (mode 2031).
    reports: bool,
    /// Questions for the terminal, for the caller to write.
    ask: Vec<u8>,
    /// The start of a character whose rest has not come: it waits for it however long that takes,
    /// as a terminal's own output does, rather than ending at an Escape's deadline as broken.
    partial: Vec<u8>,
    scratch: Vec<u8>,
}

impl Keys {
    /// The machine, its first questions asked at `now`: the colours too if `colours`.
    pub fn new(now: Instant, colours: bool) -> Self {
        let mut decoder = Decoder::with_paste_limit(MAX_PASTE);
        decoder.expect(now);
        Self {
            decoder,
            prefix: None,
            colours: colours.then(WireColours::default),
            asked: colours,
            reports: false,
            ask: probe::queries(colours),
            partial: Vec::new(),
            scratch: Vec::with_capacity(16),
        }
    }

    /// The questions for the terminal, to write to it.
    pub fn take_questions(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.ask)
    }

    /// The colours the terminal said, if any are known: told on each new connection.
    pub fn colours(&self) -> Option<&WireColours> {
        self.colours.as_ref().filter(|c| c.known())
    }

    /// Take `bytes`, as the terminal sent them at `now`. A character they end in the middle of
    /// waits for its rest, unless a sequence is begun that it may belong to (a mouse report's
    /// coordinates), which the decoder waits on as usual.
    pub fn bytes(&mut self, now: Instant, bytes: &[u8]) -> Read {
        let mut bytes = std::borrow::Cow::Borrowed(bytes);
        if !self.partial.is_empty() {
            let mut joined = std::mem::take(&mut self.partial);
            joined.extend_from_slice(&bytes);
            bytes = joined.into();
        }
        let (whole, rest) = bytes.split_at(bytes.len().saturating_sub(incomplete_utf8(&bytes)));
        let mut decoded = Vec::new();
        self.decoder.bytes(whole, &mut decoded);
        self.decoder.mark(now);
        if self.decoder.deadline().is_none() {
            self.partial.extend_from_slice(rest);
        } else {
            self.decoder.bytes(rest, &mut decoded);
        }
        self.take(now, decoded)
    }

    /// When an incomplete sequence is to be taken as it is (a lone Escape): call
    /// [`timeout`](Self::timeout) then.
    pub fn deadline(&self) -> Option<Instant> {
        self.decoder.deadline()
    }

    /// The [`deadline`](Self::deadline) passed.
    pub fn timeout(&mut self, now: Instant) -> Read {
        if self.decoder.deadline().is_none_or(|d| d > now) {
            return Read::default();
        }
        let mut decoded = Vec::new();
        self.decoder.timeout(&mut decoded);
        self.take(now, decoded)
    }

    /// Take decoded input: the escape prefix (a key whose legacy byte is `Ctrl-^`, from any
    /// terminal) then `.` detaches, then `Ctrl-Z` suspends, then the prefix again or `^` sends one
    /// Ctrl-^, then anything else forwards both. The terminal's answers go no further.
    fn take(&mut self, now: Instant, decoded: Vec<Decoded>) -> Read {
        let mut read = Read::default();
        for input in decoded {
            let key = match &input {
                Decoded::Reply(reply) => {
                    if let Some(colours) = self.reply(now, *reply) {
                        read.colours = Some(colours);
                    }
                    continue;
                }
                Decoded::PasteTooLong => {
                    read.paste_too_long = true;
                    continue;
                }
                // The prefix is a control: a key without Ctrl can only matter after one.
                Decoded::Key(stroke) if stroke.press.mods.ctrl || self.prefix.is_some() => {
                    self.scratch.clear();
                    key_bytes(stroke.press.into(), LEGACY, &mut self.scratch);
                    Some(self.scratch.as_slice())
                }
                Decoded::Key(_)
                | Decoded::Paste(_)
                | Decoded::FocusIn
                | Decoded::FocusOut
                | Decoded::Mouse(_) => None,
            };
            if let Some(prefix) = self.prefix.take() {
                match key {
                    Some(b".") => {
                        read.quit = true;
                        return read;
                    }
                    Some([SUSPEND_KEY]) => {
                        read.suspend = true;
                        continue;
                    }
                    _ => {}
                }
                // The prefix again, or `^`, is the prefix typed for itself: one Ctrl-^ goes on.
                let literal = matches!(key, Some([ESCAPE_PREFIX | b'^']));
                read.events.push(InputEvent::Key(prefix.into()));
                if !literal {
                    read.events.extend(InputEvent::from_input(input));
                }
            } else if key == Some(&[ESCAPE_PREFIX]) {
                if let Decoded::Key(stroke) = input {
                    self.prefix = Some(stroke);
                }
            } else {
                read.events.extend(InputEvent::from_input(input));
            }
        }
        read
    }

    /// An answer or report from the terminal: its colours are kept while they are told. A new
    /// scheme (mode 2031) asks the colours again; once a round's last answer (DA1) is in, the
    /// colours to tell the server.
    fn reply(&mut self, now: Instant, reply: Reply) -> Option<WireColours> {
        let colours = self.colours.as_mut()?;
        match reply {
            Reply::Scheme(scheme) => {
                colours.scheme = Some(match scheme {
                    Scheme::Dark => WireScheme::Dark,
                    Scheme::Light => WireScheme::Light,
                });
                if !std::mem::replace(&mut self.reports, true) {
                    self.ask.extend_from_slice(b"\x1b[?2031h");
                }
                if !self.asked {
                    self.asked = true;
                    self.ask.extend_from_slice(COLOUR_QUERIES);
                    self.decoder.expect(now);
                }
            }
            Reply::Foreground(rgb) => colours.foreground = Some(rgb.into()),
            Reply::Background(rgb) => colours.background = Some(rgb.into()),
            Reply::Palette { index, rgb } => {
                if let Some(slot) = colours.palette.get_mut(usize::from(index)) {
                    *slot = Some(rgb.into());
                }
            }
            Reply::Attributes { .. } if std::mem::take(&mut self.asked) => {
                return colours.known().then(|| colours.clone());
            }
            Reply::Attributes { .. }
            | Reply::Mode { .. }
            | Reply::KittyFlags(_)
            | Reply::CellSize { .. }
            | Reply::UnderlineStyles => {}
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fux_vt::keys::{Key, KeyPress};

    fn key(c: char) -> InputEvent {
        InputEvent::Key(Keystroke::from(KeyPress::plain(Key::Char(c))).into())
    }

    #[test]
    fn the_escape_prefix_takes_the_next_key() {
        let now = Instant::now();
        let mut keys = Keys::new(now, false);
        assert_eq!(keys.bytes(now, b"ab").events, [key('a'), key('b')]);
        // The prefix, then `.`: detach, from a legacy or a kitty terminal.
        assert!(keys.bytes(now, b"\x1e.").quit);
        assert!(keys.bytes(now, b"\x1b[54;5u.").quit);
        // Then Ctrl-Z: suspend.
        assert!(keys.bytes(now, b"\x1e\x1a").suspend);
        // Twice: one prefix goes to the program; then another key: both go.
        let twice = keys.bytes(now, b"\x1e\x1e");
        assert_eq!(twice.events.len(), 1);
        assert!(!twice.quit);
        assert_eq!(keys.bytes(now, b"\x1ex").events.len(), 2);
    }

    #[test]
    fn a_character_split_across_reads_arrives_whole_however_long_the_pause() {
        let mut now = Instant::now();
        let mut keys = Keys::new(now, false);
        let mut got = Vec::new();
        for byte in "é世😀".bytes() {
            got.extend(keys.bytes(now, &[byte]).events);
            // The pause outlasts any deadline the read left.
            now += std::time::Duration::from_secs(2);
            got.extend(keys.timeout(now).events);
        }
        assert_eq!(got, [key('é'), key('世'), key('😀')]);
        // A byte that cannot go on with the character ends it as it is.
        assert_eq!(keys.bytes(now, &[0xc3]), Read::default());
        assert_eq!(keys.bytes(now, b"a").events, [key('\u{fffd}'), key('a')]);
    }

    #[test]
    fn colours_are_told_once_their_round_is_in_and_asked_again_on_a_new_scheme() {
        let now = Instant::now();
        let mut keys = Keys::new(now, true);
        assert!(keys.take_questions().starts_with(b"\x1b]10;?"));
        let read = keys.bytes(
            now,
            b"\x1b]10;rgb:dddd/dddd/dddd\x1b\\\x1b]11;rgb:0000/0000/0000\x1b\\\x1b[?997;1n\x1b[?62c",
        );
        let colours = read.colours.expect("told once the DA1 came");
        assert_eq!(colours.background, Some([0, 0, 0]));
        assert!(read.events.is_empty(), "answers are not keys");
        // A new scheme reported: the colours are asked again.
        keys.bytes(now, b"\x1b[?997;2n");
        assert!(keys.take_questions().ends_with(COLOUR_QUERIES));
    }
}
