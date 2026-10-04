//! The corpus's recordings: what real programs wrote to a terminal while keys were typed into
//! them, each `NAME.bin` (the bytes) with its `NAME.json` (the size, and each step's keys, resize
//! and where its output ends). They come from fux (see `SOURCE.md`).
//!
//! koh's corpus test includes this file by path, and so do the harness crates
//! (`testing/oracle`, `testing/bench`), so that all of them read a recording the same way. It
//! reads only the JSON the recordings use, and needs no dependency for it.

use std::path::Path;

/// Recordings the user's terminal shows otherwise than the server, and why. Each must still
/// differ, so that a fix takes its recording off this list.
pub const DIFFERS: &[(&str, &str)] = &[
    ("micro-small", CLUSTER_JOINED),
    ("vim-unicode", CLUSTER_JOINED),
];

/// Why a recording whose program places a skin-tone modifier on its own differs.
pub const CLUSTER_JOINED: &str = "the program places 👍 and then 🏽 with a cursor move between \
    (`CSI 5;18H 👍 CSI 5;20H 🏽`), so the server's screen has two cells; the client prints adjacent \
    cells one after another with no cursor move, and the user's terminal joins the modifier to \
    the 👍, as one cluster.";

/// One step of a recording: the terminal resized first, if `resize` says so, then `keys` were
/// typed, and the program's output to the step's end followed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub resize: Option<(u16, u16)>,
    /// The keys, as typed: [`keys`] decodes the recording's notation.
    pub keys: Vec<u8>,
    /// Where the step's output ends in the recording's bytes.
    pub end: usize,
}

/// A recording: its name, the size it started at, its steps and its bytes.
#[derive(Clone, Debug)]
pub struct Recording {
    pub name: String,
    pub rows: u16,
    pub cols: u16,
    pub steps: Vec<Step>,
    pub bytes: Vec<u8>,
}

impl Recording {
    /// Read `NAME.json` and `NAME.bin` in `dir`.
    pub fn load(dir: &Path, name: &str) -> Result<Self, String> {
        let json_path = dir.join(format!("{name}.json"));
        let text = std::fs::read_to_string(&json_path)
            .map_err(|e| format!("{}: {e}", json_path.display()))?;
        let bytes_path = dir.join(format!("{name}.bin"));
        let bytes =
            std::fs::read(&bytes_path).map_err(|e| format!("{}: {e}", bytes_path.display()))?;
        let json = Json::parse(&text).map_err(|e| format!("{}: {e}", json_path.display()))?;
        let (rows, cols) = size(json.get("size")).ok_or_else(|| format!("{name}: no size"))?;
        let mut steps = Vec::new();
        let mut last = 0;
        for step in json.get("steps").and_then(Json::array).unwrap_or_default() {
            let end = step
                .get("end")
                .and_then(Json::number)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| format!("{name}: a step with no end"))?;
            if end < last || end > bytes.len() {
                return Err(format!(
                    "{name}: a step ends at {end}, out of order or past the bytes"
                ));
            }
            last = end;
            let resize = match step.get("resize") {
                None => None,
                Some(r) => Some(size(Some(r)).ok_or_else(|| format!("{name}: a bad resize"))?),
            };
            let typed = step.get("keys").and_then(Json::string).unwrap_or_default();
            let keys = keys(typed).map_err(|e| format!("{name}: {e}"))?;
            steps.push(Step { resize, keys, end });
        }
        Ok(Self {
            name: name.to_owned(),
            rows,
            cols,
            steps,
            bytes,
        })
    }

    /// Every recording in `dir`, by name.
    pub fn load_all(dir: &Path) -> Result<Vec<Self>, String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                name.strip_suffix(".json").map(str::to_owned)
            })
            .collect();
        names.sort();
        names.iter().map(|name| Self::load(dir, name)).collect()
    }

    /// Each step: its resize, if it has one, its keys, and the output the program wrote in it.
    pub fn outputs(&self) -> impl Iterator<Item = (&Step, &[u8])> + '_ {
        let mut start = 0;
        self.steps.iter().map(move |step| {
            let output = self.bytes.get(start..step.end).unwrap_or_default();
            start = step.end;
            (step, output)
        })
    }
}

/// `[rows, cols]`.
fn size(json: Option<&Json>) -> Option<(u16, u16)> {
    let pair = json?.array()?;
    let mut numbers = pair
        .iter()
        .map(|n| n.number().and_then(|n| u16::try_from(n).ok()));
    let rows = numbers.next()??;
    let cols = numbers.next()??;
    numbers.next().is_none().then_some((rows, cols))
}

/// Keys in the recordings' notation, which is fux's `replay`'s: `\e`, `\r`, `\n`, `\t`, `\\`,
/// `\xHH` and `\u{…}` escapes; every other character as itself.
pub fn keys(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut utf8 = [0; 4];
            out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
            continue;
        }
        match chars.next() {
            Some('e') => out.push(0x1b),
            Some('r') => out.push(b'\r'),
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('\\') => out.push(b'\\'),
            Some('x') => {
                let hex: String = chars.by_ref().take(2).collect();
                let byte = u8::from_str_radix(&hex, 16)
                    .map_err(|e| format!("a bad \\x escape in {text:?}: {e}"))?;
                out.push(byte);
            }
            Some('u') => {
                if chars.next() != Some('{') {
                    return Err(format!("a bad \\u escape in {text:?}"));
                }
                let hex: String = chars.by_ref().take_while(|&c| c != '}').collect();
                let c = u32::from_str_radix(&hex, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or_else(|| format!("a bad \\u escape in {text:?}"))?;
                let mut utf8 = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
            }
            other => return Err(format!("an unknown escape {other:?} in {text:?}")),
        }
    }
    Ok(out)
}

/// The JSON the recordings are written in.
#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    /// A number, as written: only whole numbers are read from it.
    Number(String),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl Json {
    fn parse(text: &str) -> Result<Self, String> {
        let mut reader = Reader {
            bytes: text.as_bytes(),
            at: 0,
        };
        let value = reader.value()?;
        reader.space();
        if reader.peek().is_some() {
            return Err(format!("text after the value at byte {}", reader.at));
        }
        Ok(value)
    }

    fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Array(_) => None,
        }
    }

    fn array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Object(_) => {
                None
            }
        }
    }

    fn number(&self) -> Option<u64> {
        match self {
            Self::Number(n) => n.parse().ok(),
            Self::Null | Self::Bool(_) | Self::String(_) | Self::Array(_) | Self::Object(_) => None,
        }
    }

    fn string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::Array(_) | Self::Object(_) => None,
        }
    }
}

/// Reads JSON text from `at`.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at = self.at.saturating_add(1);
        Some(byte)
    }

    fn space(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_whitespace()) {
            self.at = self.at.saturating_add(1);
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        self.space();
        if self.bump() == Some(byte) {
            Ok(())
        } else {
            Err(format!(
                "expected {:?} at byte {}",
                char::from(byte),
                self.at
            ))
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        let end = self.at.saturating_add(word.len());
        if self.bytes.get(self.at..end) == Some(word.as_bytes()) {
            self.at = end;
            Ok(value)
        } else {
            Err(format!("expected {word} at byte {}", self.at))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.space();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Json::String),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b) if b == b'-' || b.is_ascii_digit() => {
                let start = self.at;
                while self
                    .peek()
                    .is_some_and(|b| b.is_ascii_digit() || b"+-.eE".contains(&b))
                {
                    self.at = self.at.saturating_add(1);
                }
                let number = self.bytes.get(start..self.at).unwrap_or_default();
                Ok(Json::Number(String::from_utf8_lossy(number).into_owned()))
            }
            _ => Err(format!("expected a value at byte {}", self.at)),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut fields = Vec::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.at = self.at.saturating_add(1);
            return Ok(Json::Object(fields));
        }
        loop {
            self.space();
            let key = self.string()?;
            self.expect(b':')?;
            fields.push((key, self.value()?));
            self.space();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Json::Object(fields)),
                _ => return Err(format!("expected , or }} at byte {}", self.at)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.space();
        if self.peek() == Some(b']') {
            self.at = self.at.saturating_add(1);
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.space();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Json::Array(items)),
                _ => return Err(format!("expected , or ] at byte {}", self.at)),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let end = self.at.saturating_add(4);
        let hex = self
            .bytes
            .get(self.at..end)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .ok_or_else(|| format!("a bad \\u escape at byte {}", self.at))?;
        self.at = end;
        Ok(hex)
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        loop {
            match self.bump() {
                None => return Err("an unterminated string".to_owned()),
                Some(b'"') => {
                    return String::from_utf8(out).map_err(|e| format!("a string: {e}"));
                }
                Some(b'\\') => {
                    let c = match self.bump() {
                        Some(b'"') => '"',
                        Some(b'\\') => '\\',
                        Some(b'/') => '/',
                        Some(b'b') => '\u{8}',
                        Some(b'f') => '\u{c}',
                        Some(b'n') => '\n',
                        Some(b'r') => '\r',
                        Some(b't') => '\t',
                        Some(b'u') => {
                            let high = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&high) {
                                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                    return Err("a lone surrogate".to_owned());
                                }
                                let low = self.hex4()?;
                                let high = high.checked_sub(0xd800).ok_or("a bad surrogate")?;
                                let low = low.checked_sub(0xdc00).ok_or("a bad surrogate")?;
                                high.checked_mul(0x400)
                                    .and_then(|h| h.checked_add(low))
                                    .and_then(|c| c.checked_add(0x10000))
                                    .ok_or("a bad surrogate")?
                            } else {
                                high
                            };
                            char::from_u32(code).ok_or("a bad \\u escape")?
                        }
                        _ => return Err(format!("a bad escape at byte {}", self.at)),
                    };
                    let mut utf8 = [0; 4];
                    out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
                }
                Some(byte) => out.push(byte),
            }
        }
    }
}
