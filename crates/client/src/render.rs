//! Painting the synchronized `vt100` screen (plus prediction overlays and a status line)
//! onto the local terminal via crossterm.
//!
//! We render cell-by-cell — rather than just blitting `screen.contents_formatted()` — because
//! the predictor needs to draw speculative cells (underlined) *on top of* the authoritative
//! grid. Style changes are diffed against the previous cell so we emit minimal SGR.

use std::io::{self, Write};

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::queue;
use crossterm::style::{
    Attribute, Color as CtColor, Print, SetAttribute, SetBackgroundColor, SetForegroundColor,
};
use rmosh_predict::Overlay;
use vt100::{Color as VtColor, Screen};

/// Map a vt100 color to a crossterm color.
pub fn to_ct_color(c: VtColor) -> CtColor {
    match c {
        VtColor::Default => CtColor::Reset,
        VtColor::Idx(i) => CtColor::AnsiValue(i),
        VtColor::Rgb(r, g, b) => CtColor::Rgb { r, g, b },
    }
}

/// A compact style fingerprint so we only re-emit SGR when it actually changes.
#[derive(PartialEq, Clone, Copy)]
struct Style {
    fg: VtColor,
    bg: VtColor,
    bold: bool,
    dim: bool,
    italic: bool,
    underline: bool,
    inverse: bool,
}

fn emit_style(out: &mut impl Write, s: Style) -> io::Result<()> {
    // Reset clears everything (incl. colors), then re-apply.
    queue!(out, SetAttribute(Attribute::Reset))?;
    if s.bold {
        queue!(out, SetAttribute(Attribute::Bold))?;
    }
    if s.dim {
        queue!(out, SetAttribute(Attribute::Dim))?;
    }
    if s.italic {
        queue!(out, SetAttribute(Attribute::Italic))?;
    }
    if s.underline {
        queue!(out, SetAttribute(Attribute::Underlined))?;
    }
    if s.inverse {
        queue!(out, SetAttribute(Attribute::Reverse))?;
    }
    queue!(
        out,
        SetForegroundColor(to_ct_color(s.fg)),
        SetBackgroundColor(to_ct_color(s.bg))
    )?;
    Ok(())
}

/// Render the authoritative `screen` with prediction `overlay` and an optional `status` line
/// (drawn reverse-video on the last row) to `out`. Leaves the cursor at its real position.
pub fn render(
    out: &mut impl Write,
    screen: &Screen,
    overlay: &Overlay,
    status: Option<&str>,
) -> io::Result<()> {
    let (rows, cols) = screen.size();
    queue!(out, Hide)?;

    let mut cur_style: Option<Style> = None;
    for row in 0..rows {
        queue!(out, MoveTo(0, row))?;
        let mut col = 0u16;
        while col < cols {
            let cell = screen.cell(row, col);
            if let Some(c) = cell {
                if c.is_wide_continuation() {
                    col += 1;
                    continue;
                }
            }
            // A prediction, if any, wins on glyph/underline for this cell.
            let pred = overlay.cell(row, col);

            let style = match (&pred, cell) {
                (Some(p), _) => Style {
                    fg: p.fg,
                    bg: p.bg,
                    bold: false,
                    dim: false,
                    italic: false,
                    // mosh flags predictions with underline on high-latency links.
                    underline: p.underline,
                    inverse: false,
                },
                (None, Some(c)) => Style {
                    fg: c.fgcolor(),
                    bg: c.bgcolor(),
                    bold: c.bold(),
                    dim: c.dim(),
                    italic: c.italic(),
                    underline: c.underline(),
                    inverse: c.inverse(),
                },
                (None, None) => Style {
                    fg: VtColor::Default,
                    bg: VtColor::Default,
                    bold: false,
                    dim: false,
                    italic: false,
                    underline: false,
                    inverse: false,
                },
            };

            if cur_style != Some(style) {
                emit_style(out, style)?;
                cur_style = Some(style);
            }

            let glyph: String = match (&pred, cell) {
                (Some(p), _) => p.glyph.clone(),
                (None, Some(c)) if c.has_contents() => c.contents().to_string(),
                _ => " ".to_string(),
            };
            queue!(out, Print(if glyph.is_empty() { " ".into() } else { glyph }))?;
            col += 1;
        }
    }

    queue!(out, SetAttribute(Attribute::Reset))?;

    if let Some(st) = status {
        let mut line = format!(" {st} ");
        let max = cols as usize;
        if line.len() > max {
            line.truncate(max);
        }
        queue!(
            out,
            MoveTo(0, rows.saturating_sub(1)),
            SetAttribute(Attribute::Reverse),
            Print(line),
            SetAttribute(Attribute::Reset)
        )?;
    }

    // Place and show the cursor: the predicted cursor wins if present, else the real one.
    let (crow, ccol) = overlay.cursor().unwrap_or_else(|| screen.cursor_position());
    queue!(out, MoveTo(ccol, crow))?;
    if !screen.hide_cursor() {
        queue!(out, Show)?;
    }
    out.flush()
}
