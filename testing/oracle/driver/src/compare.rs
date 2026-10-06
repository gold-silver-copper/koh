//! What the two sides showed, compared step by step: the user's terminal as it reads what each
//! side painted (every cell's text, halves and attributes, the cursor and whether it is shown,
//! the input modes, the title, icon, bells and clipboard), the server's replies to the program,
//! the messages the client sent and what it made of typed bytes. Frame sizes are counted, not
//! compared.

use fux_vt::{Event, Options, Parser, Sink};

use crate::case::{unhex, Case, Step};

/// What one side printed for one step.
#[derive(Default)]
struct Printed {
    paint: Vec<u8>,
    replies: Vec<String>,
    sent: Vec<String>,
    outcome: Vec<String>,
    bytes: u64,
}

/// One side's run of a case: what it printed for each step.
pub struct Run {
    steps: Vec<Printed>,
}

impl Run {
    pub fn parse(lines: &[String]) -> Result<Self, String> {
        let mut steps: Vec<Printed> = Vec::new();
        for line in lines {
            let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
            if kind == "step" {
                steps.push(Printed::default());
                continue;
            }
            let step = steps.last_mut().ok_or("output before a step")?;
            match kind {
                "paint" => step.paint.extend(unhex(rest)?),
                "replies" => step.replies.push(rest.to_owned()),
                "sent" => step.sent.push(rest.to_owned()),
                "outcome" => step.outcome.push(rest.to_owned()),
                "bytes" => {
                    let n: u64 = rest.parse().map_err(|e| format!("bytes: {e}"))?;
                    step.bytes = step.bytes.saturating_add(n);
                }
                other => return Err(format!("unknown line {other:?}")),
            }
        }
        Ok(Self { steps })
    }

    /// The bytes of every frame the side sent.
    pub fn frame_bytes(&self) -> u64 {
        self.steps.iter().map(|s| s.bytes).sum()
    }
}

/// The out-of-band things a terminal is told: the latest title and icon, bells, clipboard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Told {
    title: Vec<u8>,
    icon: Vec<u8>,
    bells: u64,
    clipboard: Vec<u8>,
}

impl Sink for Told {
    fn event(&mut self, event: Event<'_>) {
        match event {
            Event::Title(t) => self.title = t.to_vec(),
            Event::IconName(n) => self.icon = n.to_vec(),
            Event::Bell => self.bells = self.bells.saturating_add(1),
            Event::Clipboard { data, .. } => self.clipboard = data.to_vec(),
            Event::ColorQuery { .. } | _ => {}
        }
    }
}

/// The user's terminal for one side.
struct Terminal {
    parser: Parser,
    told: Told,
}

impl Terminal {
    fn new(rows: u16, cols: u16) -> Result<Self, String> {
        let mut options = Options::default();
        options.events = true;
        Ok(Self {
            parser: Parser::with_options(rows, cols, 0, options).map_err(|e| e.to_string())?,
            told: Told::default(),
        })
    }

    fn read(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.parser
            .process_with(bytes, &mut self.told)
            .map_err(|e| e.to_string())
    }
}

/// The first difference between what `a` and `b` showed, as `name`s, if there is one.
fn screens(a: &Terminal, b: &Terminal, names: (&str, &str)) -> Option<String> {
    let (sa, sb) = (a.parser.screen(), b.parser.screen());
    let (rows, cols) = sa.size();
    for row in 0..rows {
        for col in 0..cols {
            let look = |screen: &fux_vt::Screen| {
                screen.cell(row, col).map(|cell| {
                    // A printed space and an erased cell of the same attributes look alike.
                    let text = if cell.contents() == " " {
                        String::new()
                    } else {
                        cell.contents().to_owned()
                    };
                    (
                        text,
                        cell.is_wide(),
                        cell.is_wide_continuation(),
                        cell.attributes(),
                    )
                })
            };
            let (la, lb) = (look(sa), look(sb));
            if la != lb {
                return Some(format!(
                    "cell ({row}, {col}): {} {la:?}, {} {lb:?}",
                    names.0, names.1
                ));
            }
        }
    }
    // The paste, cursor-key, keypad and mouse-encoding modes are the client's own now, not the
    // program's mirrored (the `input-modes` exemption).
    let modes = |s: &fux_vt::Screen| {
        (
            s.hide_cursor(),
            (!s.hide_cursor()).then(|| s.cursor_position()),
            s.mouse_protocol_mode(),
        )
    };
    let (ma, mb) = (modes(sa), modes(sb));
    if ma != mb {
        return Some(format!(
            "cursor and modes (hidden, at, mouse): {} {ma:?}, {} {mb:?}",
            names.0, names.1
        ));
    }
    (a.told != b.told).then(|| {
        format!(
            "title, icon, bells, clipboard: {} {:?}, {} {:?}",
            names.0, a.told, names.1, b.told
        )
    })
}

/// The first difference between two runs of `case`, if there is one.
pub fn difference(
    case: &Case,
    a: &Run,
    b: &Run,
    names: (&str, &str),
) -> Result<Option<String>, String> {
    if a.steps.len() != b.steps.len() {
        return Ok(Some(format!(
            "{} ran {} steps, {} ran {}",
            names.0,
            a.steps.len(),
            names.1,
            b.steps.len()
        )));
    }
    let mut ta = Terminal::new(case.rows, case.cols)?;
    let mut tb = Terminal::new(case.rows, case.cols)?;
    for (index, ((step, pa), pb)) in case.steps.iter().zip(&a.steps).zip(&b.steps).enumerate() {
        if let Step::Resize(rows, cols) = step {
            // The user's terminal resized before the client painted.
            ta.parser.resize(*rows, *cols).map_err(|e| e.to_string())?;
            tb.parser.resize(*rows, *cols).map_err(|e| e.to_string())?;
        }
        ta.read(&pa.paint)?;
        tb.read(&pb.paint)?;
        let at = |what: String| Some(format!("step {index} ({}): {what}", describe(step)));
        if pa.replies != pb.replies {
            return Ok(at(format!(
                "replies: {} {:?}, {} {:?}",
                names.0, pa.replies, names.1, pb.replies
            )));
        }
        if pa.sent != pb.sent {
            return Ok(at(format!(
                "sent: {} {:?}, {} {:?}",
                names.0, pa.sent, names.1, pb.sent
            )));
        }
        if pa.outcome != pb.outcome {
            return Ok(at(format!(
                "outcome: {} {:?}, {} {:?}",
                names.0, pa.outcome, names.1, pb.outcome
            )));
        }
        if let Some(what) = screens(&ta, &tb, names) {
            return Ok(at(what));
        }
    }
    Ok(None)
}

/// A step, short.
fn describe(step: &Step) -> String {
    match step {
        Step::Output(bytes) => format!("output of {} bytes", bytes.len()),
        Step::Keys(bytes) => format!("keys {:?}", String::from_utf8_lossy(bytes)),
        Step::Frame { dropped } => {
            if *dropped {
                "a lost frame".to_owned()
            } else {
                "a frame".to_owned()
            }
        }
        Step::Tick(ms) => format!("{ms} ms"),
        Step::Resize(rows, cols) => format!("resize to {rows}x{cols}"),
    }
}
