//! Painting the synchronized `vt100` screen (plus prediction overlays and a status line)
//! onto the local terminal, emitting escape sequences via **termina**.
//!
//! We render cell-by-cell — rather than just blitting `screen.contents_formatted()` — because
//! the predictor needs to draw speculative cells (underlined) *on top of* the authoritative
//! grid. Style changes are diffed against the previous cell so we emit minimal SGR. Each frame
//! is wrapped in synchronized output (DEC mode 2026) so the terminal shows it atomically
//! (no tearing/flicker on full repaints or resizes).
//!
//! termina has no `queue!`/`execute!` / `Command` layer: every escape is a `Display`-able
//! `Csi`/`Csi::Mode`/`Csi::Sgr` value written into any `io::Write` (here, the termina terminal,
//! which itself impls `io::Write`).

use std::io::{self, Write};

use crate::predict::Overlay;
use termina::escape::csi::{Csi, Cursor, DecPrivateMode, DecPrivateModeCode, Mode, Sgr};
use termina::style::{ColorSpec, Intensity, RgbColor, Underline};
use termina::OneBased;
use vt100::{Color as VtColor, Screen};

/// Map a vt100 color to a termina color spec.
pub fn to_spec(c: VtColor) -> ColorSpec {
    match c {
        VtColor::Default => ColorSpec::Reset,
        VtColor::Idx(i) => ColorSpec::PaletteIndex(i),
        VtColor::Rgb(r, g, b) => ColorSpec::from(RgbColor::new(r, g, b)),
    }
}

/// `Csi` to move the cursor to a 0-based `(row, col)`.
fn move_to(row: u16, col: u16) -> Csi {
    Csi::Cursor(Cursor::Position {
        line: OneBased::from_zero_based(row),
        col: OneBased::from_zero_based(col),
    })
}

fn set_mode(code: DecPrivateModeCode) -> Csi {
    Csi::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(code)))
}
fn reset_mode(code: DecPrivateModeCode) -> Csi {
    Csi::Mode(Mode::ResetDecPrivateMode(DecPrivateMode::Code(code)))
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
    write!(out, "{}", Csi::Sgr(Sgr::Reset))?;
    if s.bold {
        write!(out, "{}", Csi::Sgr(Sgr::Intensity(Intensity::Bold)))?;
    }
    if s.dim {
        write!(out, "{}", Csi::Sgr(Sgr::Intensity(Intensity::Dim)))?;
    }
    if s.italic {
        write!(out, "{}", Csi::Sgr(Sgr::Italic(true)))?;
    }
    if s.underline {
        write!(out, "{}", Csi::Sgr(Sgr::Underline(Underline::Single)))?;
    }
    if s.inverse {
        write!(out, "{}", Csi::Sgr(Sgr::Reverse(true)))?;
    }
    write!(
        out,
        "{}{}",
        Csi::Sgr(Sgr::Foreground(to_spec(s.fg))),
        Csi::Sgr(Sgr::Background(to_spec(s.bg)))
    )?;
    Ok(())
}

/// Render the authoritative `screen` with prediction `overlay` and an optional `status` line
/// (drawn reverse-video on the last row) to `out`, wrapped in one synchronized-output frame.
pub fn render(
    out: &mut impl Write,
    screen: &Screen,
    overlay: &Overlay,
    status: Option<&str>,
) -> io::Result<()> {
    let (rows, cols) = screen.size();

    // Begin Synchronized Update (atomic frame) and hide the cursor while we paint.
    write!(out, "{}", set_mode(DecPrivateModeCode::SynchronizedOutput))?;
    write!(out, "{}", reset_mode(DecPrivateModeCode::ShowCursor))?;

    let mut cur_style: Option<Style> = None;
    for row in 0..rows {
        write!(out, "{}", move_to(row, 0))?;
        let mut col = 0u16;
        while col < cols {
            let cell = screen.cell(row, col);
            if let Some(c) = cell {
                if c.is_wide_continuation() {
                    col += 1;
                    continue;
                }
            }
            // A prediction wins on glyph/underline for this cell — EXCEPT an "unknown" cell,
            // which only hints: it underlines the real cell rather than overwriting its glyph.
            let pred = overlay.cell(row, col);
            let concrete = pred.filter(|p| !p.unknown); // prediction carrying a real glyph
            let hint_underline = pred.is_some_and(|p| p.unknown && p.underline);

            let style = if let Some(p) = concrete {
                Style {
                    fg: p.fg,
                    bg: p.bg,
                    bold: false,
                    dim: false,
                    italic: false,
                    // mosh flags predictions with underline on high-latency links.
                    underline: p.underline,
                    inverse: false,
                }
            } else if let Some(c) = cell {
                Style {
                    fg: c.fgcolor(),
                    bg: c.bgcolor(),
                    bold: c.bold(),
                    dim: c.dim(),
                    italic: c.italic(),
                    underline: c.underline() || hint_underline,
                    inverse: c.inverse(),
                }
            } else {
                Style {
                    fg: VtColor::Default,
                    bg: VtColor::Default,
                    bold: false,
                    dim: false,
                    italic: false,
                    underline: hint_underline,
                    inverse: false,
                }
            };

            if cur_style != Some(style) {
                emit_style(out, style)?;
                cur_style = Some(style);
            }

            let glyph: String = if let Some(p) = concrete {
                p.glyph.clone()
            } else if let Some(c) = cell.filter(|c| c.has_contents()) {
                c.contents().to_string()
            } else {
                " ".to_string()
            };
            write!(out, "{}", if glyph.is_empty() { " " } else { &glyph })?;
            col += 1;
        }
    }

    write!(out, "{}", Csi::Sgr(Sgr::Reset))?;

    if let Some(st) = status {
        let mut line = format!(" {st} ");
        let max = cols as usize;
        if line.len() > max {
            line.truncate(max);
        }
        write!(
            out,
            "{}{}{}{}",
            move_to(rows.saturating_sub(1), 0),
            Csi::Sgr(Sgr::Reverse(true)),
            line,
            Csi::Sgr(Sgr::Reset)
        )?;
    }

    // Place and show the cursor: the predicted cursor wins if present, else the real one.
    let (crow, ccol) = overlay.cursor().unwrap_or_else(|| screen.cursor_position());
    write!(out, "{}", move_to(crow, ccol))?;
    if !screen.hide_cursor() {
        write!(out, "{}", set_mode(DecPrivateModeCode::ShowCursor))?;
    }

    // End Synchronized Update: the terminal now reveals the whole frame at once.
    write!(
        out,
        "{}",
        reset_mode(DecPrivateModeCode::SynchronizedOutput)
    )?;
    out.flush()
}

/// Strip control chars from a window title so it can't break the OSC sequence we wrap it in.
fn sanitize_title(t: &str) -> String {
    t.chars().filter(|c| !c.is_control()).collect()
}

/// Tracks the *out-of-band* terminal state the client mirrors onto the real terminal — the window
/// title (OSC), the bell, and the input modes (bracketed-paste / mouse / cursor-key) — so each is
/// re-emitted only when it changes. These ride alongside the cell grid but aren't part of it.
#[derive(Default)]
pub struct OutOfBand {
    last_title: String,
    last_bell: u64,
    /// Previous frame's screen, kept only to diff its input modes against the current frame.
    prev_screen: Option<Screen>,
}

impl OutOfBand {
    /// Emit this frame's title / bell / input-mode changes to `out`, updating the tracked state.
    /// The title is never blanked (mosh's title-initialized guard); the bell rings once when the
    /// server's monotonic count climbs; input modes are diffed against the previous frame.
    pub fn emit(
        &mut self,
        out: &mut impl Write,
        screen: &Screen,
        title: &str,
        bell_count: u64,
    ) -> io::Result<()> {
        if !title.is_empty() && title != self.last_title {
            write!(out, "\x1b]0;{}\x07", sanitize_title(title))?;
            self.last_title = title.to_string();
        }
        if bell_count > self.last_bell {
            out.write_all(b"\x07")?;
            self.last_bell = bell_count;
        }
        let mode_bytes = match &self.prev_screen {
            Some(prev) => screen.input_mode_diff(prev),
            None => screen.input_mode_formatted(),
        };
        if !mode_bytes.is_empty() {
            out.write_all(&mode_bytes)?;
        }
        self.prev_screen = Some(screen.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predict::{DisplayPreference, PredictionEngine};

    fn screen_of(bytes: &[u8]) -> Screen {
        let mut p = vt100::Parser::new(24, 80, 0);
        p.process(bytes);
        p.screen().clone()
    }

    #[test]
    fn renders_authoritative_text_with_escapes() {
        let screen = screen_of(b"hi");
        let mut buf = Vec::new();
        render(&mut buf, &screen, &Overlay::empty(), None).unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("hi"), "rendered text missing");
        assert!(s.contains('\x1b'), "expected ANSI escape sequences");
    }

    #[test]
    fn render_wraps_frame_in_synchronized_output() {
        let screen = screen_of(b"x");
        let mut buf = Vec::new();
        render(&mut buf, &screen, &Overlay::empty(), None).unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(
            s.contains("\x1b[?2026h"),
            "frame must begin synchronized output"
        );
        assert!(
            s.contains("\x1b[?2026l"),
            "frame must end synchronized output"
        );
    }

    #[test]
    fn out_of_band_title_emits_once_and_guards_empty() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");

        // Empty title before the shell sets one: never blank the user's terminal title.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, "", 0).unwrap();
        assert!(
            !String::from_utf8_lossy(&buf).contains("\x1b]0;"),
            "no title OSC for an empty title"
        );

        // A real title is emitted as OSC 0.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, "vim - file.rs", 0).unwrap();
        assert!(String::from_utf8_lossy(&buf).contains("\x1b]0;vim - file.rs\x07"));

        // Unchanged title is not re-emitted.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, "vim - file.rs", 0).unwrap();
        assert!(!String::from_utf8_lossy(&buf).contains("\x1b]0;"));
    }

    #[test]
    fn out_of_band_rings_bell_on_increase_only() {
        let mut oob = OutOfBand::default();
        let scr = screen_of(b"");
        // Establish the mode baseline (so later emits don't also carry mode bytes).
        let mut warm = Vec::new();
        oob.emit(&mut warm, &scr, "", 0).unwrap();

        // No increase → no bell.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, "", 0).unwrap();
        assert!(buf.is_empty(), "no bell when the count is unchanged");

        // Count climbs (possibly by more than one) → exactly one bell.
        let mut buf = Vec::new();
        oob.emit(&mut buf, &scr, "", 3).unwrap();
        assert_eq!(buf, b"\x07", "one bell on an increase, even if it jumped");
    }

    #[test]
    fn out_of_band_reasserts_input_modes_on_change() {
        let mut oob = OutOfBand::default();
        // Baseline frame in default modes.
        let mut warm = Vec::new();
        oob.emit(&mut warm, &screen_of(b""), "", 0).unwrap();

        // The remote turns on bracketed paste + mouse reporting → re-asserted to the real terminal.
        let modes = screen_of(b"\x1b[?2004h\x1b[?1000h");
        let mut buf = Vec::new();
        oob.emit(&mut buf, &modes, "", 0).unwrap();
        let s = String::from_utf8_lossy(&buf);
        assert!(s.contains("2004"), "bracketed-paste re-asserted, got {s:?}");
        assert!(s.contains("1000"), "mouse reporting re-asserted, got {s:?}");
    }

    #[test]
    fn renders_status_line() {
        let screen = screen_of(b"");
        let mut buf = Vec::new();
        render(&mut buf, &screen, &Overlay::empty(), Some("link down")).unwrap();
        assert!(String::from_utf8_lossy(&buf).contains("link down"));
    }

    #[test]
    fn renders_prediction_overlay_glyph() {
        // A predicted glyph (once the server has confirmed it echoes) must appear in the output.
        // Predictions are epoch-gated and hidden until confirmed, so confirm a first keystroke,
        // then a subsequent typed char becomes visible and should render.
        let mut pe = PredictionEngine::new(DisplayPreference::Always);
        pe.set_local_frame_sent(0);
        let blank = screen_of(b"");
        pe.new_user_byte(0, b'a', &blank); // hidden (epoch 1, unconfirmed)
        let echoed = screen_of(b"a");
        pe.set_local_frame_late_acked(1);
        pe.cull(50, &echoed); // confirms -> confirmed_epoch = 1

        pe.set_local_frame_sent(1);
        pe.new_user_byte(60, b'Z', &echoed); // now visible at (0,1)
        let overlay = pe.overlay(&echoed);
        assert!(
            !overlay.is_empty(),
            "confirmed prediction should be visible"
        );

        let mut buf = Vec::new();
        render(&mut buf, &echoed, &overlay, None).unwrap();
        assert!(
            String::from_utf8_lossy(&buf).contains('Z'),
            "predicted glyph not rendered"
        );
    }
}
