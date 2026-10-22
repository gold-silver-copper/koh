//! Input as the client decoded it, on the wire, and what the user's terminal said of its colours.
//!
//! Keys, mouse events, focus changes and pastes are [`InputEvent`]s, carried by `ClientMsg::Keys`;
//! colours are [`WireColours`], carried by `ClientMsg::Colours`.
//!
//! The client decodes what the user's terminal sends with fux-vt's decoder, whatever protocol the
//! terminal speaks (legacy bytes, xterm's modifiers, the kitty keyboard protocol, SGR mouse
//! reports), and the server encodes each event as the program on its screen asked for
//! (`fux_vt::keys::encode`). So a program gets what it asked for from any terminal, and a
//! reattach from another terminal changes nothing for it.
//!
//! The types here are the wire's own, mirroring fux-vt's, so its encoding is pinned here and
//! a fux-vt release never changes koh's protocol. Decoding refuses what no terminal sends: a
//! modifier mask with unknown bits, a function key past F35, a mouse press with no button, a kitty
//! code that is no Unicode scalar, a paste over [`MAX_PASTE`] bytes, more than [`MAX_EVENTS`]
//! events in a message ([`check_events`]).

use fux_vt::keys::colour::{Colours, Scheme};
use fux_vt::keys::mouse::{MouseAction, MouseButton, MouseEvent};
use fux_vt::keys::{Direction, Function, Key, KeyPress, Keystroke, Kitty, Modifiers};
use fux_vt::Rgb;
use serde::{Deserialize, Serialize};

/// Most events in one `ClientMsg::Keys`.
pub const MAX_EVENTS: usize = 512;

/// Most bytes of a paste, which goes whole in one message: a longer one is not sent.
pub const MAX_PASTE: usize = 1024 * 1024;

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
    /// A whole paste, its end markers already removed by the client. The server frames it, for a
    /// program that set bracketed paste.
    Paste(String),
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
    F(WireFunction),
}

/// A function key, F1 to F35 (F13 on are kitty's), on the wire as its number: another number does
/// not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct WireFunction(Function);

impl TryFrom<u8> for WireFunction {
    type Error = &'static str;
    fn try_from(number: u8) -> Result<Self, Self::Error> {
        Function::new(number)
            .map(Self)
            .ok_or("no such function key")
    }
}

impl From<WireFunction> for u8 {
    fn from(key: WireFunction) -> Self {
        key.0.number()
    }
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

/// A mouse event: what happened, with its button, the modifiers (as a key's), and the cell's row
/// and column from zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMouse {
    pub action: WireMouseAction,
    pub mods: u8,
    pub row: u16,
    pub col: u16,
}

/// A press always names its button; a release or a motion may not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMouseAction {
    Press(WireButton),
    Release(Option<WireButton>),
    Motion(Option<WireButton>),
}

/// A wire enum of unit variants, and its conversions to and from fux-vt's of the same names.
macro_rules! mirror {
    ($wire:ident <-> $theirs:ident { $($variant:ident),* $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum $wire {
            $($variant),*
        }

        impl From<$wire> for $theirs {
            fn from(wire: $wire) -> Self {
                match wire {
                    $($wire::$variant => Self::$variant),*
                }
            }
        }

        impl From<$theirs> for $wire {
            fn from(theirs: $theirs) -> Self {
                match theirs {
                    $($theirs::$variant => Self::$variant),*
                }
            }
        }
    };
}

mirror!(WireButton <-> MouseButton {
    Left, Middle, Right, WheelUp, WheelDown, WheelLeft, WheelRight, Back, Forward,
});

mirror!(WireScheme <-> Scheme { Dark, Light });

/// What the user's terminal said of its colours, 8 bits a channel.
///
/// Its foreground (OSC 10), background (OSC 11), palette entries 0 to 15 (OSC 4), and dark or
/// light scheme (mode 2031); anything it did not say is `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireColours {
    pub foreground: Option<[u8; 3]>,
    pub background: Option<[u8; 3]>,
    pub palette: [Option<[u8; 3]>; PALETTE],
    pub scheme: Option<WireScheme>,
}

/// The modifier bits a key or mouse event may carry.
const MODS: u8 = 0b111;

/// Whether `events` are within the wire's bounds: what decoding a `ClientMsg::Keys` checks.
pub fn check_events(events: &[InputEvent]) -> Result<(), &'static str> {
    if events.len() > MAX_EVENTS {
        return Err("too many events");
    }
    events.iter().try_for_each(InputEvent::check)
}

impl InputEvent {
    /// What the server gets for one input decoded from the user's terminal, if anything.
    pub fn from_input(input: fux_vt::keys::decode::Input) -> Option<Self> {
        use fux_vt::keys::decode::Input;
        match input {
            Input::Key(stroke) => Some(Self::Key(stroke.into())),
            Input::Mouse(event) => Some(Self::Mouse(event.into())),
            Input::FocusIn => Some(Self::Focus(true)),
            Input::FocusOut => Some(Self::Focus(false)),
            Input::Paste(text) => Some(Self::Paste(text)),
            Input::PasteTooLong | Input::Reply(_) => None,
        }
    }

    fn check(&self) -> Result<(), &'static str> {
        match self {
            Self::Key(key) => key.check(),
            Self::Mouse(mouse) if mouse.mods & !MODS != 0 => Err("unknown modifier bits"),
            Self::Paste(text) if text.len() > MAX_PASTE => Err("paste too long"),
            Self::Mouse(_) | Self::Focus(_) | Self::Paste(_) => Ok(()),
        }
    }
}

impl WireKey {
    fn check(&self) -> Result<(), &'static str> {
        if self.mods & !MODS != 0 {
            return Err("unknown modifier bits");
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
            WireKeyCode::F(WireFunction(key)) => Key::F(key),
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
            Key::F(key) => WireKeyCode::F(WireFunction(key)),
        };
        Self {
            key,
            mods: bits_of(stroke.press.mods),
            // A code no key has (a terminal's garbage) is dropped, as the wire refuses it.
            kitty: stroke.kitty.map(|k| {
                let scalar = |c: Option<u32>| c.filter(|&c| char::from_u32(c).is_some());
                WireKitty {
                    code: scalar(k.code),
                    shifted: scalar(k.shifted),
                    base: scalar(k.base),
                    mods: k.mods,
                }
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
                WireMouseAction::Press(b) => MouseAction::Press(b.into()),
                WireMouseAction::Release(b) => MouseAction::Release(b.map(Into::into)),
                WireMouseAction::Motion(b) => MouseAction::Motion(b.map(Into::into)),
            },
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
                MouseAction::Press(b) => WireMouseAction::Press(b.into()),
                MouseAction::Release(b) => WireMouseAction::Release(b.map(Into::into)),
                MouseAction::Motion(b) => WireMouseAction::Motion(b.map(Into::into)),
            },
            mods: bits_of(event.mods),
            row: event.row,
            col: event.col,
        }
    }
}

impl WireColours {
    /// The foreground, background and scheme, as fux-vt answers programs from them.
    pub fn colours(&self) -> Colours {
        Colours {
            foreground: self.foreground.map(Rgb::from),
            background: self.background.map(Rgb::from),
            scheme: self.scheme.map(Into::into),
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
            Keystroke::from(KeyPress::plain(Key::F(Function::new(35).unwrap()))),
        ];
        for stroke in strokes {
            let wire = WireKey::from(stroke);
            assert_eq!(wire.check(), Ok(()));
            assert_eq!(wire.stroke(), stroke);
        }
        // A code no key has, from a terminal's garbage, is dropped, not sent to be refused (with
        // every key sent beside it).
        let garbage = Keystroke {
            kitty: Some(Kitty {
                code: Some(0x11_0000),
                shifted: Some(0xd800),
                base: Some(1096),
                mods: 4,
            }),
            ..strokes[2]
        };
        let wire = WireKey::from(garbage);
        assert_eq!(wire.check(), Ok(()));
        assert_eq!(
            wire.kitty.map(|k| (k.code, k.shifted, k.base)),
            Some((None, None, Some(1096)))
        );
        let mouse = MouseEvent {
            action: MouseAction::Motion(Some(MouseButton::Right)),
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
    fn colours_round_trip_and_answer_as_xterm() {
        let rgb = Rgb {
            r: 0x1e,
            g: 0xff,
            b: 0x00,
        };
        assert_eq!(<[u8; 3]>::from(rgb), [0x1e, 0xff, 0x00]);
        assert_eq!(Rgb::from([0x1e, 0xff, 0x00]), rgb);
        assert_eq!(
            Colours {
                background: Some(rgb),
                ..Colours::default()
            }
            .answer(11, true)
            .expect("known background"),
            b"\x1b]11;rgb:1e1e/ffff/0000\x07"
        );
    }
}
