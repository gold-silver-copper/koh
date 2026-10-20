//! The corpus (`testing/corpus/`, real programs' output) through what a session carries: the
//! output cut into PTY-sized pieces, through the server's filter, on to the client, which writes
//! it to a fux-vt terminal. After every step, that terminal must show what a fux-vt parser fed the
//! output itself shows: each cell's text, halves, attributes and link, the cursor and whether it
//! is shown, the prompts' rows, the screen and the mouse modes, the title.
//!
//! And at every step a client attaching afresh is sent the server's redraw of its screen: a
//! terminal that saw only that must show the same, and go on to show the same as the program
//! writes on.
#![forbid(clippy::disallowed_methods)]

#[path = "../testing/corpus/recording.rs"]
mod recording;

use std::path::Path;

use koh::client::display::Display;
use koh::client::KohBackend;
use koh::proto::Shown;
use koh::stream::{Filter, Marks, Piece, Policy};
use koh::terminal::{ServerTerminal, Size};
use recording::Recording;

/// The most bytes one read of a PTY returns here.
const READ: usize = 4096;

/// The user's terminal: a fux-vt parser of what the client writes.
struct Term(fux_vt::Parser);

impl Term {
    fn new(rows: u16, cols: u16) -> Result<Self, String> {
        let size = fux_vt::Size::new(rows, cols).map_err(|e| e.to_string())?;
        fux_vt::Parser::with_options(size, 0, koh::terminal::OPTIONS)
            .map(Self)
            .map_err(|e| e.to_string())
    }
}

impl KohBackend for Term {
    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.0.process(bytes).map_err(std::io::Error::other)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn enter_raw_mode(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn leave_raw_mode(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn size(&self) -> std::io::Result<Size> {
        let (rows, cols) = self.0.screen().size().into();
        Ok(Size::new(rows, cols))
    }
}

/// A cell as compared here: its text, whether it is either half of a wide glyph, its
/// attributes and its link.
type ViewCell = (String, bool, bool, fux_vt::Attributes, Option<String>);

/// What a screen shows, as compared here.
#[derive(Debug, PartialEq, Eq)]
struct View {
    size: (u16, u16),
    cells: Vec<Option<ViewCell>>,
    prompts: Vec<u16>,
    hidden: bool,
    cursor: Option<(u16, u16)>,
    modes: (bool, fux_vt::MouseProtocolMode, bool),
}

impl View {
    fn of(screen: &fux_vt::Screen) -> Self {
        let (rows, cols) = screen.size().into();
        let cells = (0..rows)
            .flat_map(|row| (0..cols).map(move |col| (row, col)))
            .map(|(row, col)| {
                screen.cell(row, col).map(|cell| {
                    let text = if cell.contents() == " " {
                        String::new()
                    } else {
                        cell.contents().to_owned()
                    };
                    let link = screen.link(row, col).map(|l| l.uri().to_owned());
                    (
                        text,
                        cell.is_wide(),
                        cell.is_wide_continuation(),
                        cell.attributes(),
                        link,
                    )
                })
            })
            .collect();
        let window = screen.window();
        let hidden = !screen.mode(fux_vt::Mode::ShowCursor);
        Self {
            size: (rows, cols),
            cells,
            prompts: (0..rows)
                .filter(|&row| window.row(row).is_some_and(|r| r.starts_prompt()))
                .collect(),
            hidden,
            cursor: (!hidden).then(|| screen.cursor_position()),
            modes: (
                screen.mode(fux_vt::Mode::AlternateScreen),
                screen.mouse_protocol_mode(),
                screen.mode(fux_vt::Mode::BracketedPaste),
            ),
        }
    }

    /// The first difference between `shown` and this.
    fn difference(&self, shown: &Self) -> Option<String> {
        if shown.size != self.size {
            return Some(format!("size {:?}, expected {:?}", shown.size, self.size));
        }
        let cols = usize::from(self.size.1).max(1);
        for (at, (a, b)) in shown.cells.iter().zip(&self.cells).enumerate() {
            if a != b {
                return Some(format!(
                    "cell ({}, {}): shown {a:?}, expected {b:?}",
                    at.checked_div(cols).unwrap_or(0),
                    at.checked_rem(cols).unwrap_or(0)
                ));
            }
        }
        (shown != self).then(|| {
            format!(
                "prompts {:?} hidden {} cursor {:?} modes {:?}, expected {:?} {} {:?} {:?}",
                shown.prompts,
                shown.hidden,
                shown.cursor,
                shown.modes,
                self.prompts,
                self.hidden,
                self.cursor,
                self.modes
            )
        })
    }
}

/// A seeded sequence of numbers, for where reads end.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self, below: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        usize::try_from(self.0 >> 33)
            .unwrap_or(0)
            .checked_rem(below)
            .unwrap_or(0)
    }
}

/// Feed what `pieces` brings to `display`, writing to `term`.
fn show(display: &mut Display, term: &mut Term, pieces: &[Shown]) -> Result<(), String> {
    for piece in pieces {
        match piece {
            Shown::Out(bytes) => display.output(term, bytes),
            Shown::Mark(mark) => display.mark(term, mark.as_bytes()),
            Shown::Report { activity, .. } => display.report(term, *activity),
            Shown::Tty(_)
            | Shown::Echo(_)
            | Shown::Bell(_)
            | Shown::Title(_)
            | Shown::Exit { .. }
            | Shown::Beat => Ok(()),
        }
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// A filter's pieces as the wire carries them.
fn wire(pieces: Vec<Piece>) -> Vec<Shown> {
    pieces
        .into_iter()
        .filter_map(|piece| match piece {
            Piece::Out(bytes) => Some(Shown::Out(bytes)),
            Piece::Mark(mark) => koh::proto::MarkText::new(mark).map(Shown::Mark),
        })
        .collect()
}

/// Replay `recording` in reads from `seed`: the first step whose screen differs, if one does.
fn replay(recording: &Recording, seed: u64) -> Result<(), String> {
    let (rows, cols) = (recording.rows, recording.cols);
    let mut expected = Term::new(rows, cols)?;
    let mut server = ServerTerminal::new(rows, cols, 1 << 20).map_err(|e| e.to_string())?;
    let mut filter = Filter::new(Policy {
        marks: Marks::All,
        clipboard: true,
        links: true,
    });
    let mut term = Term::new(rows, cols)?;
    let mut display = Display::new(Size::new(rows, cols), true, true).map_err(|e| e.to_string())?;
    display
        .new_epoch(Size::new(rows, cols))
        .map_err(|e| e.to_string())?;
    let mut reads = Seeded(seed);
    for (index, (step, output)) in recording.outputs().enumerate() {
        if let Some((rows, cols)) = step.resize {
            let size = fux_vt::Size::new(rows, cols).map_err(|e| e.to_string())?;
            expected.0.resize(size).map_err(|e| e.to_string())?;
            term.0.resize(size).map_err(|e| e.to_string())?;
            server.resize(Size::new(rows, cols));
            display.resize(Size::new(rows, cols));
        }
        let mut rest = output;
        while !rest.is_empty() {
            let (read, tail) = rest.split_at(reads.next(READ).saturating_add(1).min(rest.len()));
            rest = tail;
            expected.0.process(read).map_err(|e| e.to_string())?;
            server.process(read);
            let mut pieces = Vec::new();
            filter.feed(read, &mut |piece| pieces.push(piece));
            show(&mut display, &mut term, &wire(pieces))?;
        }
        let want = View::of(expected.0.screen());
        if let Some(difference) = want.difference(&View::of(term.0.screen())) {
            return Err(format!("{} step {index}: {difference}", recording.name));
        }
        // A client attaching now, sent the redraw.
        let size = server.live().size();
        let (r, c) = size.into();
        let mut fresh = Term::new(r, c)?;
        let mut fresh_display =
            Display::new(Size::new(r, c), true, true).map_err(|e| e.to_string())?;
        fresh_display
            .new_epoch(Size::new(r, c))
            .map_err(|e| e.to_string())?;
        let redrawn = wire(koh::terminal::redraw(server.live(), server.title(), 0));
        show(&mut fresh_display, &mut fresh, &redrawn)?;
        if let Some(difference) = want.difference(&View::of(fresh.0.screen())) {
            return Err(format!(
                "{} step {index}, redrawn: {difference}",
                recording.name
            ));
        }
    }
    Ok(())
}

#[test]
fn every_recording_shows_through_koh_as_it_does_in_a_terminal_and_redrawn() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("testing/corpus");
    let recordings = Recording::load_all(&corpus).expect("the recordings");
    assert!(recordings.len() > 100, "{} recordings", recordings.len());
    let failures: Vec<String> = recordings
        .iter()
        .zip(1u64..)
        .filter_map(|(recording, seed)| replay(recording, seed).err())
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} recordings differ:\n{}",
        failures.len(),
        recordings.len(),
        failures.join("\n")
    );
}
