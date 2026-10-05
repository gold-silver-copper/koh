//! Scrollback over the corpus: each recording played into a server emulator keeping the default
//! scrollback, its screens sent to a client as frames, then the client's scrollback view opened
//! and paged from the oldest history row down to the live screen, fetching rows as a client does,
//! through the wire's encoding. At every page the view must show what the server's own emulator
//! shows scrolled back as far: each row's cells, wrap flag and links.

#[path = "../testing/corpus/recording.rs"]
#[expect(
    dead_code,
    reason = "the recordings' list of known differences is not read here"
)]
mod recording;

use std::path::Path;
use std::time::Instant;

use koh::client::ClientSession;
use koh::predict::DisplayPreference;
use koh::proto::{decode_server, encode_history, ClientMsg, Frame, FrameNum, InputSeq, ServerMsg};
use koh::terminal::{ServerTerminal, Size, TerminalScreen};
use recording::Recording;

/// The scrollback a server keeps by default (`koh serve --scrollback`).
const SCROLLBACK: usize = 1000;

/// The escape prefix (`Ctrl-^`).
const ESCAPE: u8 = 0x1e;

/// A server and a client, the client in step with the server's screens.
struct Pair {
    server: ServerTerminal,
    client: ClientSession,
    sent: TerminalScreen,
    num: u64,
    now: Instant,
    /// Bytes of history rows sent, compressed, as their streams carry them.
    history_bytes: u64,
    history_rows: usize,
}

impl Pair {
    fn new(rows: u16, cols: u16) -> Result<Self, String> {
        Ok(Self {
            server: ServerTerminal::new(rows, cols, SCROLLBACK).map_err(|e| e.to_string())?,
            client: ClientSession::new(DisplayPreference::Never, Size::new(rows, cols)),
            sent: TerminalScreen::default(),
            num: 0,
            now: Instant::now(),
            history_bytes: 0,
            history_rows: 0,
        })
    }

    /// Send the server's screen as a frame, and answer what the client asks.
    fn frame(&mut self) -> Result<(), String> {
        let screen = self.server.snapshot();
        let frame = Frame {
            num: FrameNum(self.num.saturating_add(1)),
            base: FrameNum(self.num),
            echo_ack: InputSeq::default(),
            diff: screen.diff_from(&self.sent),
        };
        self.num = self.num.saturating_add(1);
        self.sent = screen;
        self.client.on_frame(self.now, &frame);
        self.answer()
    }

    /// Answer the client's history requests until it asks no more.
    fn answer(&mut self) -> Result<(), String> {
        for _ in 0..10_000 {
            self.client.on_tick(self.now, None);
            let requests: Vec<_> = std::iter::from_fn(|| self.client.pop_outgoing())
                .filter_map(|msg| match msg {
                    ClientMsg::History(request) => Some(request),
                    ClientMsg::Input { .. }
                    | ClientMsg::Resize(_)
                    | ClientMsg::Ack { .. }
                    | ClientMsg::Resync => None,
                })
                .collect();
            if requests.is_empty() {
                return Ok(());
            }
            for request in requests {
                let reply = self.server.history(request);
                self.history_rows = self.history_rows.saturating_add(reply.rows.len());
                let bytes = encode_history(&reply).map_err(|e| e.to_string())?;
                self.history_bytes = self
                    .history_bytes
                    .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                match decode_server(&bytes).map_err(|e| e.to_string())? {
                    ServerMsg::History(reply) => self.client.on_history(&reply),
                    ServerMsg::Frame { .. } => return Err("a frame for history".to_owned()),
                }
            }
        }
        Err("the client never stopped asking for history".to_owned())
    }

    fn keys(&mut self, keys: &[u8]) -> Result<(), String> {
        self.client.on_input(self.now, keys);
        self.answer()
    }

    /// The view against the server's emulator at the same offset: the first row that differs.
    fn check(&self) -> Result<(), String> {
        let offset = self
            .client
            .scrollback()
            .offset()
            .ok_or("the view is closed")?;
        let view = self.client.view().ok_or("no view")?;
        let truth = self.server.window(offset);
        let (shown, want) = (view.screen(), truth.screen());
        for row in 0..want.size().rows {
            if shown.row(row) != want.row(row)
                || shown.row_wrapped(row) != want.row_wrapped(row)
                || shown.row_links(row) != want.row_links(row)
            {
                return Err(format!(
                    "offset {offset} row {row}: shows {:?}, the server {:?}",
                    shown.row(row).map(|r| r
                        .iter()
                        .map(|c| c.contents().to_owned())
                        .collect::<String>()),
                    want.row(row).map(|r| r
                        .iter()
                        .map(|c| c.contents().to_owned())
                        .collect::<String>()),
                ));
            }
        }
        Ok(())
    }

    /// Open the view at the oldest row and page down to the live screen, checking every page.
    fn page_through(&mut self) -> Result<(), String> {
        self.keys(&[ESCAPE, b'[', b'g'])?;
        loop {
            self.check()?;
            if self.client.scrollback().offset() == Some(0) {
                return Ok(());
            }
            self.keys(b"f")?;
        }
    }
}

fn scroll_back(recording: &Recording) -> Result<Pair, String> {
    let mut pair = Pair::new(recording.rows, recording.cols)?;
    for (index, (step, output)) in recording.outputs().enumerate() {
        if let Some((rows, cols)) = step.resize {
            pair.server.resize(Size::new(rows, cols));
            pair.client.on_resize(Size::new(rows, cols));
        }
        pair.server.process(output);
        pair.frame()?;
        // Midway too, every few steps that left history: a program in the alternate screen at
        // the end hides the primary screen's history.
        if index % 5 == 4 && pair.sent.history().len > 0 {
            pair.page_through()
                .map_err(|e| format!("step {index}: {e}"))?;
            pair.keys(b"q")?;
        }
    }
    pair.page_through()?;
    Ok(pair)
}

#[test]
fn every_recording_scrolls_back_in_full_as_the_server_keeps_it() {
    let corpus = Recording::load_all(&Path::new(env!("CARGO_MANIFEST_DIR")).join("testing/corpus"))
        .expect("the corpus");
    let mut failures = Vec::new();
    let mut with_history = 0_usize;
    for recording in &corpus {
        match scroll_back(recording) {
            Ok(pair) => {
                if pair.history_rows > 0 {
                    with_history = with_history.saturating_add(1);
                    println!(
                        "{}: {} history rows in {} bytes",
                        recording.name, pair.history_rows, pair.history_bytes
                    );
                }
            }
            Err(e) => failures.push(format!("{}: {e}", recording.name)),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        with_history > 10,
        "only {with_history} recordings left history"
    );
}

#[test]
fn the_view_stays_on_its_rows_while_output_goes_on_below() {
    let mut pair = Pair::new(6, 20).expect("pair");
    for n in 0..40 {
        pair.server.process(format!("line {n}\r\n").as_bytes());
    }
    pair.frame().expect("frame");
    // Back five rows: the top row is the one five above the screen.
    pair.keys(&[ESCAPE, b'[', b'k', b'k', b'k', b'k', b'k'])
        .expect("keys");
    pair.check().expect("the view");
    let top = pair.client.view().expect("view").screen().contents();
    for n in 40..43 {
        pair.server.process(format!("line {n}\r\n").as_bytes());
    }
    pair.frame().expect("frame");
    pair.check().expect("the view after more output");
    assert_eq!(pair.client.scrollback().offset(), Some(8));
    assert_eq!(pair.client.view().expect("view").screen().contents(), top);
    // At the live screen the view follows the output.
    pair.keys(b"G").expect("keys");
    pair.server.process(b"line 43\r\n");
    pair.frame().expect("frame");
    assert_eq!(pair.client.scrollback().offset(), Some(0));
    pair.check().expect("the live view");
    // q leaves; keys go to the program again.
    pair.keys(b"q").expect("keys");
    assert!(pair.client.view().is_none());
}

#[test]
fn rows_held_are_never_fetched_again() {
    let mut pair = Pair::new(6, 20).expect("pair");
    for n in 0..100 {
        pair.server.process(format!("line {n}\r\n").as_bytes());
    }
    pair.frame().expect("frame");
    pair.page_through().expect("first pass");
    let fetched = pair.history_rows;
    assert_eq!(fetched, 95, "every history row once");
    pair.keys(b"q").expect("keys");
    pair.page_through().expect("second pass");
    assert_eq!(pair.history_rows, fetched, "nothing fetched twice");
}

#[test]
fn history_past_the_servers_scrollback_is_not_there_to_fetch() {
    let mut pair = Pair::new(6, 20).expect("pair");
    for n in 0..1500 {
        pair.server.process(format!("line {n}\r\n").as_bytes());
    }
    pair.frame().expect("frame");
    pair.page_through().expect("pages");
    assert_eq!(pair.history_rows, SCROLLBACK);
    pair.keys(b"g").expect("top");
    assert_eq!(pair.client.scrollback().offset(), Some(SCROLLBACK));
    let top = pair.client.view().expect("view").screen().contents();
    assert!(top.starts_with("line 495"), "{top:?}");
}

#[test]
fn a_resize_names_the_history_afresh_and_the_view_still_matches() {
    let mut pair = Pair::new(6, 20).expect("pair");
    for n in 0..30 {
        pair.server
            .process(format!("a longer line number {n}\r\n").as_bytes());
    }
    pair.frame().expect("frame");
    pair.page_through().expect("before");
    pair.server.resize(Size::new(8, 12));
    pair.client.on_resize(Size::new(8, 12));
    pair.frame().expect("frame");
    pair.page_through().expect("after the reflow");
}

#[test]
fn history_keeps_its_colours_wide_glyphs_and_links() {
    let mut pair = Pair::new(6, 30).expect("pair");
    // A set palette entry, true colour, a wide glyph and a link, all scrolled into history.
    pair.server.process(b"\x1b]4;1;rgb:12/34/56\x07");
    for n in 0..20 {
        pair.server.process(
            format!(
                "\x1b[31mred {n}\x1b[m \x1b[38;2;1;2;3mrgb\x1b[m \u{65e5}\u{672c} \
                 \x1b]8;id=a;https://koh.example/{n}\x1b\\link\x1b]8;;\x1b\\\r\n"
            )
            .as_bytes(),
        );
    }
    pair.frame().expect("frame");
    pair.page_through().expect("pages");
    pair.keys(b"g").expect("top");
    let view = pair.client.view().expect("view");
    let top = view.screen();
    let link = (0..30).find_map(|col| top.link(0, col).cloned());
    assert_eq!(
        link.map(|l| l.uri),
        Some("https://koh.example/0".to_owned()),
        "the link came back with its row"
    );
    let red = top.cell(0, 0).expect("cell").attributes().foreground();
    assert_eq!(
        red,
        fux_vt::Color::Rgb(0x12, 0x34, 0x56),
        "drawn in the set colour"
    );
}

#[test]
fn a_search_finds_text_in_history_older_then_newer() {
    let mut pair = Pair::new(6, 20).expect("pair");
    for n in 0..200 {
        let tag = if n % 50 == 7 { " MARK" } else { "" };
        pair.server.process(format!("item {n}{tag}\r\n").as_bytes());
    }
    pair.frame().expect("frame");
    let top = |pair: &Pair| {
        pair.client
            .view()
            .expect("view")
            .screen()
            .contents()
            .lines()
            .next()
            .unwrap_or_default()
            .trim_end()
            .to_owned()
    };
    // Typed, the search goes older from the live screen, fetching history as it goes.
    pair.keys(&[ESCAPE, b'[']).expect("open");
    pair.keys(b"/MARK\r").expect("search");
    assert_eq!(top(&pair), "item 157 MARK");
    pair.keys(b"n").expect("next older");
    assert_eq!(top(&pair), "item 107 MARK");
    pair.keys(b"nn").expect("two older");
    assert_eq!(top(&pair), "item 7 MARK");
    pair.keys(b"n").expect("none older");
    assert!(
        pair.client
            .scrollback()
            .status()
            .is_some_and(|s| s.contains("not found")),
        "{:?}",
        pair.client.scrollback().status()
    );
    pair.keys(b"N").expect("next newer");
    assert_eq!(top(&pair), "item 57 MARK");
    pair.check().expect("the view at a match");
    // Escape while typing cancels the search, not the view.
    pair.keys(b"/abc\x1b").expect("cancel");
    assert!(pair.client.view().is_some());
}
