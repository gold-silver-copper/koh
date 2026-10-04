//! A case: a size and the steps a session goes through, in the sides' line format (see the side's
//! documentation), which is also how a case is saved and replayed.

use std::fmt::Write as _;

/// One step of a case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Output(Vec<u8>),
    Resize(u16, u16),
    Frame { dropped: bool },
    Keys(Vec<u8>),
    Tick(u64),
}

/// A session from a size, through its steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    pub name: String,
    pub rows: u16,
    pub cols: u16,
    pub steps: Vec<Step>,
}

impl Case {
    /// The case as the sides read it, without its `end`.
    pub fn text(&self) -> String {
        let mut out = format!("case {} {}\n", self.rows, self.cols);
        for step in &self.steps {
            let _ = match step {
                Step::Output(bytes) => writeln!(out, "output {}", hex(bytes)),
                Step::Resize(rows, cols) => writeln!(out, "resize {rows} {cols}"),
                Step::Frame { dropped } => writeln!(out, "frame {}", u8::from(*dropped)),
                Step::Keys(bytes) => writeln!(out, "keys {}", hex(bytes)),
                Step::Tick(ms) => writeln!(out, "tick {ms}"),
            };
        }
        out
    }

    /// Read a case saved by [`Case::text`].
    pub fn parse(name: &str, text: &str) -> Result<Self, String> {
        let mut lines = text.lines();
        let head = lines.next().ok_or("an empty case")?;
        let (rows, cols) = head
            .strip_prefix("case ")
            .and_then(|size| size.split_once(' '))
            .ok_or("no `case ROWS COLS` line")?;
        let mut case = Self {
            name: name.to_owned(),
            rows: number(rows)?,
            cols: number(cols)?,
            steps: Vec::new(),
        };
        for line in lines.filter(|l| !l.is_empty() && *l != "end") {
            let (verb, rest) = line.split_once(' ').unwrap_or((line, ""));
            let step = match verb {
                "output" => Step::Output(unhex(rest)?),
                "keys" => Step::Keys(unhex(rest)?),
                "frame" => Step::Frame {
                    dropped: rest == "1",
                },
                "tick" => Step::Tick(rest.parse().map_err(|e| format!("tick: {e}"))?),
                "resize" => {
                    let (rows, cols) = rest.split_once(' ').ok_or("resize: no size")?;
                    Step::Resize(number(rows)?, number(cols)?)
                }
                other => return Err(format!("unknown step {other:?}")),
            };
            case.steps.push(step);
        }
        Ok(case)
    }
}

fn number(word: &str) -> Result<u16, String> {
    word.parse().map_err(|e| format!("{word:?}: {e}"))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn unhex(text: &str) -> Result<Vec<u8>, String> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .filter(|pair| pair.len() == 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("bad hex {text:?}"))
        })
        .collect()
}
