//! Input as the client decoded it, on the wire, and what the user's terminal said of its colours.
//!
//! Keys, mouse events, focus changes and pastes are [`InputEvent`]s, carried by `ClientMsg::Keys`;
//! colours are [`WireColours`], carried by `ClientMsg::Colours`.
//!
//! The client decodes what the user's terminal sends with fux-vt's decoder, whatever protocol the
//! terminal speaks (legacy bytes, xterm's modifiers, the kitty keyboard protocol, SGR mouse
//! reports), and the server encodes each event as the program on its screen asked for
//! (`fux_vt::Screen::encode_*`). So a program gets what it asked for from any terminal, and a
//! reattach from another terminal changes nothing for it.
//!
//! The types here are the wire's own, so its encoding is pinned here and not by fux-vt's types.
//! Decoding refuses what no terminal sends: a modifier mask with unknown bits, a function key past
//! F12, a kitty code that is no Unicode scalar, a paste piece over [`MAX_PASTE_PIECE`] bytes, more
//! than [`MAX_EVENTS`] events in a message, more than [`PALETTE`] palette entries ([`Events`],
//! [`WireColours::check`]).

use fux_vt::keys::colour::{Colours, Rgb, Scheme};
use fux_vt::keys::encode::{key_bytes, KeyMode, PASTE_END, PASTE_START};
use fux_vt::keys::mouse::{mouse_bytes, MouseAction, MouseButton, MouseEvent};
use fux_vt::keys::{Direction, Key, KeyPress, Keystroke, Kitty, Modifiers};
use serde::{Deserialize, Serialize};

use crate::proto::MAX_CLIENT_MESSAGE;

/// Most events in one `ClientMsg::Keys`.
pub const MAX_EVENTS: usize = 512;

/// Most bytes of one paste piece: a longer paste goes in pieces, in order, each its own message.
pub const MAX_PASTE_PIECE: usize = 60 * 1024;

/// Palette entries the client asks its terminal and tells the server: 0 to 15, the ones themes
/// change.
pub const PALETTE: usize = 16;

/// One decoded input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputEvent {
    /// A key.
    Key(WireKey),
    /// A mouse event over the screen.
    Mouse(WireMouse),
    /// The user's terminal gained (`true`) or lost focus.
    Focus(bool),
    /// A piece of a bracketed paste, its end markers already removed by the client: `first`
    /// begins the paste, `last` ends it. The server frames the whole paste once, for a program
    /// that set bracketed paste.
    Paste {
        text: String,
        first: bool,
        last: bool,
    },
}

/// A key, its modifiers (Shift 1, Alt 2, Ctrl 4), and what a kitty-protocol terminal said beyond
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireKey {
    pub key: WireKeyCode,
    pub mods: u8,
    pub kitty: Option<WireKitty>,
}

/// A key without its modifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireKeyCode {
    Char(char),
    Enter,
    Tab,
    Escape,
    Backspace,
    Delete,
    Insert,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    /// F1 to F12.
    F(u8),
}

/// What a kitty-protocol terminal reported of a key: its code, its shifted and base-layout keys,
/// and all eight modifier bits (Shift, Alt, Ctrl, Super, Hyper, Meta, Caps Lock, Num Lock).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireKitty {
    pub code: Option<u32>,
    pub shifted: Option<u32>,
    pub base: Option<u32>,
    pub mods: u8,
}

/// A mouse event: cell row and column from zero, the button and modifiers (as a key's).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMouse {
    pub action: WireMouseAction,
    pub button: Option<WireButton>,
    pub mods: u8,
    pub row: u16,
    pub col: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMouseAction {
    Press,
    Release,
    Motion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
    WheelLeft,
    WheelRight,
    Back,
    Forward,
}

/// What the user's terminal said of its colours, 8 bits a channel.
///
/// Its foreground (OSC 10), background (OSC 11), palette entries 0 to 15 (OSC 4), and dark or
/// light scheme (mode 2031); anything it did not say is `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireColours {
    pub foreground: Option<[u8; 3]>,
    pub background: Option<[u8; 3]>,
    pub palette: Vec<Option<[u8; 3]>>,
    pub scheme: Option<WireScheme>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireScheme {
    Dark,
    Light,
}

/// The modifier bits a key or mouse event may carry.
const MODS: u8 = 0b111;

/// What a `ClientMsg::Keys` holds beside its events, at most: its variant (1 byte), its sequence
/// number (a varint of at most 10) and the count of events (a varint of at most 2).
pub const KEYS_ENVELOPE: usize = 1 + 10 + 2;

// The count's varint is 2 bytes up to 16383, and one event of the longest kind always fits.
const _: () =
    assert!(MAX_EVENTS < 16384 && MAX_PASTE_PIECE + 16 + KEYS_ENVELOPE <= MAX_CLIENT_MESSAGE);

/// The events of one `ClientMsg::Keys`, in order.
///
/// Built only by [`try_push`](Self::try_push), which admits an event by its postcard encoding: so
/// a `Keys` message of them always encodes within [`MAX_CLIENT_MESSAGE`]. Decoded, they are
/// checked as [`try_push`](Self::try_push) checks each, and bounded by the message's length. On
/// the wire it is the `Vec<InputEvent>` it holds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Events {
    list: Vec<InputEvent>,
    /// The encoded size of `list`.
    #[serde(skip)]
    body: usize,
}

impl Events {
    /// Append `event` if it is one a terminal sends and the message stays within the wire's
    /// bounds; else hand it back.
    pub fn try_push(&mut self, event: InputEvent) -> Result<(), InputEvent> {
        if !self.admits(&event) {
            return Err(event);
        }
        self.body = self.body.saturating_add(encoded_len(&event));
        self.list.push(event);
        Ok(())
    }

    /// Whether [`try_push`](Self::try_push) would take `event`.
    pub fn admits(&self, event: &InputEvent) -> bool {
        event.check().is_ok()
            && self.list.len() < MAX_EVENTS
            && self
                .body
                .saturating_add(encoded_len(event))
                .saturating_add(KEYS_ENVELOPE)
                <= MAX_CLIENT_MESSAGE
    }

    /// The bytes the events take on the wire.
    pub const fn encoded_len(&self) -> usize {
        self.body
    }

    pub fn into_vec(self) -> Vec<InputEvent> {
        self.list
    }
}

impl std::ops::Deref for Events {
    type Target = [InputEvent];

    fn deref(&self) -> &[InputEvent] {
        &self.list
    }
}

/// The events, as [`try_push`](Events::try_push) takes them, or the first it refuses.
impl TryFrom<Vec<InputEvent>> for Events {
    type Error = InputEvent;

    fn try_from(list: Vec<InputEvent>) -> Result<Self, InputEvent> {
        let mut events = Self::default();
        list.into_iter()
            .try_for_each(|event| events.try_push(event))?;
        Ok(events)
    }
}

impl<'de> Deserialize<'de> for Events {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let list = Vec::<InputEvent>::deserialize(deserializer)?;
        if list.len() > MAX_EVENTS {
            return Err(serde::de::Error::custom("too many events"));
        }
        list.iter()
            .try_for_each(InputEvent::check)
            .map_err(serde::de::Error::custom)?;
        let body = list.iter().map(encoded_len).fold(0, usize::saturating_add);
        Ok(Self { list, body })
    }
}

/// The bytes `event` takes in postcard.
fn encoded_len(event: &InputEvent) -> usize {
    postcard::serialize_with_flavor(event, postcard::ser_flavors::Size::default())
        .unwrap_or(usize::MAX)
}

impl InputEvent {
    fn check(&self) -> Result<(), &'static str> {
        match self {
            Self::Key(key) => key.check(),
            Self::Mouse(mouse) if mouse.mods & !MODS != 0 => Err("unknown modifier bits"),
            Self::Paste { text, .. } if text.len() > MAX_PASTE_PIECE => Err("paste piece too long"),
            Self::Mouse(_) | Self::Focus(_) | Self::Paste { .. } => Ok(()),
        }
    }

    /// The bytes a legacy terminal sends for the event: a key in its legacy form (normal cursor
    /// mode), a paste bracketed, a mouse event in SGR, a focus change as `CSI I` or `CSI O`. What
    /// koh sent before it decoded input, for comparing with it (the oracle).
    pub fn sent_by_a_legacy_terminal(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Key(key) => key_bytes(key.stroke(), KeyMode::legacy(false), &mut out),
            Self::Mouse(mouse) => {
                mouse_bytes(
                    mouse.event(),
                    fux_vt::MouseProtocolMode::AnyMotion,
                    fux_vt::MouseProtocolEncoding::Sgr,
                    &mut out,
                );
            }
            Self::Focus(true) => out.extend_from_slice(b"\x1b[I"),
            Self::Focus(false) => out.extend_from_slice(b"\x1b[O"),
            Self::Paste { text, first, last } => {
                if *first {
                    out.extend_from_slice(PASTE_START);
                }
                out.extend_from_slice(text.as_bytes());
                if *last {
                    out.extend_from_slice(PASTE_END);
                }
            }
        }
        out
    }
}

impl WireKey {
    fn check(&self) -> Result<(), &'static str> {
        if self.mods & !MODS != 0 {
            return Err("unknown modifier bits");
        }
        if let WireKeyCode::F(n) = self.key {
            if !(1..=12).contains(&n) {
                return Err("no such function key");
            }
        }
        if let Some(kitty) = self.kitty {
            let scalar = |c: Option<u32>| c.is_none_or(|c| char::from_u32(c).is_some());
            if !(scalar(kitty.code) && scalar(kitty.shifted) && scalar(kitty.base)) {
                return Err("a kitty code that is no Unicode scalar");
            }
        }
        Ok(())
    }

    /// The keystroke, as fux-vt's encoder takes it.
    pub fn stroke(&self) -> Keystroke {
        let key = match self.key {
            WireKeyCode::Char(c) => Key::Char(c),
            WireKeyCode::Enter => Key::Enter,
            WireKeyCode::Tab => Key::Tab,
            WireKeyCode::Escape => Key::Escape,
            WireKeyCode::Backspace => Key::Backspace,
            WireKeyCode::Delete => Key::Delete,
            WireKeyCode::Insert => Key::Insert,
            WireKeyCode::Up => Key::Arrow(Direction::Up),
            WireKeyCode::Down => Key::Arrow(Direction::Down),
            WireKeyCode::Left => Key::Arrow(Direction::Left),
            WireKeyCode::Right => Key::Arrow(Direction::Right),
            WireKeyCode::Home => Key::Home,
            WireKeyCode::End => Key::End,
            WireKeyCode::PageUp => Key::PageUp,
            WireKeyCode::PageDown => Key::PageDown,
            WireKeyCode::F(n) => Key::F(n),
        };
        Keystroke {
            // `new` normalizes as the decoder does: a character carries its own shift.
            press: KeyPress::new(key, mods_of(self.mods)),
            kitty: self.kitty.map(|k| Kitty {
                code: k.code,
                shifted: k.shifted,
                base: k.base,
                mods: k.mods,
            }),
        }
    }
}

impl From<Keystroke> for WireKey {
    fn from(stroke: Keystroke) -> Self {
        let key = match stroke.press.key {
            Key::Char(c) => WireKeyCode::Char(c),
            Key::Enter => WireKeyCode::Enter,
            Key::Tab => WireKeyCode::Tab,
            Key::Escape => WireKeyCode::Escape,
            Key::Backspace => WireKeyCode::Backspace,
            Key::Delete => WireKeyCode::Delete,
            Key::Insert => WireKeyCode::Insert,
            Key::Arrow(Direction::Up) => WireKeyCode::Up,
            Key::Arrow(Direction::Down) => WireKeyCode::Down,
            Key::Arrow(Direction::Left) => WireKeyCode::Left,
            Key::Arrow(Direction::Right) => WireKeyCode::Right,
            Key::Home => WireKeyCode::Home,
            Key::End => WireKeyCode::End,
            Key::PageUp => WireKeyCode::PageUp,
            Key::PageDown => WireKeyCode::PageDown,
            Key::F(n) => WireKeyCode::F(n),
        };
        Self {
            key,
            mods: bits_of(stroke.press.mods),
            kitty: stroke.kitty.map(|k| WireKitty {
                code: k.code,
                shifted: k.shifted,
                base: k.base,
                mods: k.mods,
            }),
        }
    }
}

fn mods_of(bits: u8) -> Modifiers {
    Modifiers {
        shift: bits & 1 != 0,
        alt: bits & 2 != 0,
        ctrl: bits & 4 != 0,
    }
}

fn bits_of(mods: Modifiers) -> u8 {
    u8::from(mods.shift) | u8::from(mods.alt) << 1 | u8::from(mods.ctrl) << 2
}

impl WireMouse {
    /// The event, as fux-vt's encoder takes it.
    pub fn event(&self) -> MouseEvent {
        MouseEvent {
            action: match self.action {
                WireMouseAction::Press => MouseAction::Press,
                WireMouseAction::Release => MouseAction::Release,
                WireMouseAction::Motion => MouseAction::Motion,
            },
            button: self.button.map(|b| match b {
                WireButton::Left => MouseButton::Left,
                WireButton::Middle => MouseButton::Middle,
                WireButton::Right => MouseButton::Right,
                WireButton::WheelUp => MouseButton::WheelUp,
                WireButton::WheelDown => MouseButton::WheelDown,
                WireButton::WheelLeft => MouseButton::WheelLeft,
                WireButton::WheelRight => MouseButton::WheelRight,
                WireButton::Back => MouseButton::Back,
                WireButton::Forward => MouseButton::Forward,
            }),
            mods: mods_of(self.mods),
            row: self.row,
            col: self.col,
        }
    }
}

impl From<MouseEvent> for WireMouse {
    fn from(event: MouseEvent) -> Self {
        Self {
            action: match event.action {
                MouseAction::Press => WireMouseAction::Press,
                MouseAction::Release => WireMouseAction::Release,
                MouseAction::Motion => WireMouseAction::Motion,
            },
            button: event.button.map(|b| match b {
                MouseButton::Left => WireButton::Left,
                MouseButton::Middle => WireButton::Middle,
                MouseButton::Right => WireButton::Right,
                MouseButton::WheelUp => WireButton::WheelUp,
                MouseButton::WheelDown => WireButton::WheelDown,
                MouseButton::WheelLeft => WireButton::WheelLeft,
                MouseButton::WheelRight => WireButton::WheelRight,
                MouseButton::Back => WireButton::Back,
                MouseButton::Forward => WireButton::Forward,
            }),
            mods: bits_of(event.mods),
            row: event.row,
            col: event.col,
        }
    }
}

/// A 16-bit colour at 8 bits a channel.
pub fn narrow(rgb: Rgb) -> [u8; 3] {
    let channel = |c: u16| u8::try_from(c >> 8).unwrap_or(u8::MAX);
    [channel(rgb.r), channel(rgb.g), channel(rgb.b)]
}

/// An 8-bit colour at 16 bits a channel, each byte twice, as xterm answers it.
pub fn widen([r, g, b]: [u8; 3]) -> Rgb {
    let channel = |c: u8| u16::from_be_bytes([c, c]);
    Rgb {
        r: channel(r),
        g: channel(g),
        b: channel(b),
    }
}

impl WireColours {
    /// Whether the message is within the wire's bounds.
    pub fn check(&self) -> Result<(), &'static str> {
        if self.palette.len() > PALETTE {
            return Err("too many palette entries");
        }
        Ok(())
    }

    /// The foreground, background and scheme, as fux-vt answers programs from them.
    pub fn colours(&self) -> Colours {
        Colours {
            foreground: self.foreground.map(widen),
            background: self.background.map(widen),
            scheme: self.scheme.map(|s| match s {
                WireScheme::Dark => Scheme::Dark,
                WireScheme::Light => Scheme::Light,
            }),
        }
    }

    /// Whether the terminal said anything at all.
    pub fn known(&self) -> bool {
        self.foreground.is_some()
            || self.background.is_some()
            || self.scheme.is_some()
            || self.palette.iter().any(Option::is_some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_mouse_events_survive_the_wire_types() {
        let strokes = [
            Keystroke::from(KeyPress::plain(Key::Char('a'))),
            Keystroke::from(KeyPress::new(
                Key::Arrow(Direction::Left),
                Modifiers {
                    ctrl: true,
                    alt: true,
                    shift: true,
                },
            )),
            Keystroke {
                press: KeyPress::new(
                    Key::Char('i'),
                    Modifiers {
                        ctrl: true,
                        ..Modifiers::NONE
                    },
                ),
                kitty: Some(Kitty {
                    code: Some(105),
                    shifted: None,
                    base: Some(1096),
                    mods: 4 | 64,
                }),
            },
            Keystroke::from(KeyPress::plain(Key::F(12))),
        ];
        for stroke in strokes {
            let wire = WireKey::from(stroke);
            assert_eq!(wire.check(), Ok(()));
            assert_eq!(wire.stroke(), stroke);
        }
        let mouse = MouseEvent {
            action: MouseAction::Motion,
            button: Some(MouseButton::Right),
            mods: Modifiers {
                ctrl: true,
                ..Modifiers::NONE
            },
            row: 7,
            col: 300,
        };
        assert_eq!(WireMouse::from(mouse).event(), mouse);
    }

    #[test]
    fn what_no_terminal_sends_is_refused() {
        let key = |key, mods, kitty| InputEvent::Key(WireKey { key, mods, kitty });
        let bad = [
            key(WireKeyCode::Char('a'), 8, None),
            key(WireKeyCode::F(0), 0, None),
            key(WireKeyCode::F(13), 0, None),
            key(
                WireKeyCode::Char('a'),
                0,
                Some(WireKitty {
                    code: Some(0xd800),
                    shifted: None,
                    base: None,
                    mods: 0,
                }),
            ),
            key(
                WireKeyCode::Char('a'),
                0,
                Some(WireKitty {
                    code: None,
                    shifted: Some(0x11_0000),
                    base: None,
                    mods: 0,
                }),
            ),
            InputEvent::Mouse(WireMouse {
                action: WireMouseAction::Press,
                button: None,
                mods: 0x80,
                row: 0,
                col: 0,
            }),
            InputEvent::Paste {
                text: "x".repeat(MAX_PASTE_PIECE + 1),
                first: true,
                last: true,
            },
        ];
        for event in bad {
            assert!(Events::try_from(vec![event.clone()]).is_err(), "{event:?}");
        }
        let many = vec![InputEvent::Focus(true); MAX_EVENTS + 1];
        assert!(Events::try_from(many.clone()).is_err());
        assert!(Events::try_from(many[..MAX_EVENTS].to_vec()).is_ok());
        let palette = WireColours {
            palette: vec![None; PALETTE + 1],
            ..WireColours::default()
        };
        assert!(palette.check().is_err());
    }

    #[test]
    fn colours_narrow_and_widen_as_xterm_answers() {
        let rgb = Rgb {
            r: 0x1e1e,
            g: 0xffff,
            b: 0x0000,
        };
        assert_eq!(narrow(rgb), [0x1e, 0xff, 0x00]);
        assert_eq!(widen([0x1e, 0xff, 0x00]), rgb);
        assert_eq!(
            widen([0x1e, 0xff, 0]).answer(11, true),
            b"\x1b]11;rgb:1e1e/ffff/0000\x07"
        );
    }
}
