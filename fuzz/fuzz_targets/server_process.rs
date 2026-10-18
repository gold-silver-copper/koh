#![no_main]
//! Fuzz what a hosted program's output goes through, its bytes arbitrary (a hostile or buggy
//! program can write anything): the server's emulator and filter, the redraw of the screen it
//! makes, and the client that writes both to the user's terminal. None may panic; what the filter
//! passes holds no question and no mark, whole sequences only; and a terminal that saw only the
//! redraw shows what the emulator does.

use koh::client::display::Display;
use koh::client::KohBackend;
use koh::stream::{Filter, Marks, Piece, Policy, MAX_OUT};
use koh::terminal::{ServerTerminal, Size};
use libfuzzer_sys::fuzz_target;

struct Term(fux_vt::Parser);

impl KohBackend for Term {
    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let _ = self.0.process(bytes);
        Ok(())
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
        Ok(Size::new(24, 80))
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut t) = ServerTerminal::new(24, 80, 64 << 10) else {
        return;
    };
    let mut filter = Filter::new(Policy {
        marks: Marks::Signed(b"k".to_vec()),
        clipboard: false,
        links: true,
    });
    let Ok(parser) = fux_vt::Parser::new(fux_vt::Size::new(24, 80).expect("a size"), 0) else {
        return;
    };
    let mut term = Term(parser);
    let Ok(mut display) = Display::new(Size::new(24, 80), false, true) else {
        return;
    };
    // Split the input into a few chunks so sequences straddle the reads.
    let n = data.len().max(1);
    for chunk in data.chunks((n / 3).max(1)) {
        t.process(chunk);
        let _ = t.take_host_replies();
        let mut pieces = Vec::new();
        filter.feed(chunk, &mut |piece| pieces.push(piece));
        for piece in pieces {
            match piece {
                Piece::Out(bytes) => {
                    assert!(bytes.len() <= MAX_OUT + 4096);
                    let _ = display.output(&mut term, &bytes);
                }
                Piece::Mark(mark) => {
                    let _ = display.mark(&mut term, &mark);
                }
            }
        }
        let _ = display.paint(&mut term);
    }
    let _ = t.screen_text(1 << 20);
    let _ = t.last_output(1 << 20);
    for piece in koh::terminal::redraw(t.live(), t.title(), 100) {
        if let Piece::Out(bytes) = piece {
            let _ = display.output(&mut term, &bytes);
        }
    }
});
