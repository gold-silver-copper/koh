//! The corpus over the fault link: a real server hosts a script that writes a recording's output
//! a step at a time, and a real client paints it into a fux-vt terminal. After each step, the
//! terminal must come to show what a fux-vt parser fed the same output and resizes shows, under
//! loss and delay: the client converges on every step, whichever frames were lost.
//!
//! The script is the program: it writes each step's bytes when the test types one byte (so a
//! step's output never races its resize), after waiting for the step's size, with the PTY in raw
//! mode so the bytes reach the emulator as recorded.

#[path = "../../testing/corpus/recording.rs"]
mod recording;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use koh::client::{run_client, BackendTerminal, ClientTerminal, IrohConnector, KohBackend};
use koh::predict::{DisplayPreference, Overlay};
use koh::terminal::{Size, TerminalScreen};
use recording::Recording;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::harness::{identity, runtime, Server};
use crate::link::{FaultNet, Profile};

/// How long a step may take to show.
const STEP: Duration = Duration::from_secs(30);

/// The recordings replayed by default: every one that resizes, and a few that redraw heavily.
/// `KOH_NET_CORPUS=all` replays every recording, and `KOH_NET_CORPUS=a,b` those named.
const DEFAULT: &[&str] = &[
    "btop-small",
    "claude-resize",
    "emacs-resize",
    "fzf-preview",
    "helix-resize",
    "htop",
    "lazygit-stage",
    "nvim-resize",
    "nvim-split",
    "vim-resize",
    "zsh-resize",
];

/// The user's terminal: every byte the client paints, read by a fux-vt parser.
#[derive(Clone)]
struct Shared {
    painted: Arc<Mutex<Vec<u8>>>,
    size: Arc<Mutex<Size>>,
}

impl KohBackend for Shared {
    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.painted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
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
        Ok(*self.size.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// The client's terminal: koh's own, painting into [`Shared`], whose bytes go to `shown` after
/// every frame.
struct Readback {
    terminal: BackendTerminal<Shared>,
    shared: Shared,
    shown: Arc<Mutex<fux_vt::Parser>>,
    paints: watch::Sender<u64>,
}

impl ClientTerminal for Readback {
    fn render(
        &mut self,
        state: &TerminalScreen,
        overlay: &Overlay<'_>,
        status: Option<&str>,
    ) -> std::io::Result<()> {
        self.terminal.render(state, overlay, status)?;
        let painted = std::mem::take(
            &mut *self
                .shared
                .painted
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        self.shown
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .process(&painted)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.paints.send_modify(|n| *n = n.wrapping_add(1));
        Ok(())
    }

    fn size(&self) -> std::io::Result<Size> {
        self.shared.size()
    }

    fn window_resized(&mut self) {
        self.terminal.window_resized();
    }
}

/// The first difference between `shown` and `expected`, cell by cell, then the cursor.
fn difference(shown: &fux_vt::Screen, expected: &fux_vt::Screen) -> Option<String> {
    if shown.size() != expected.size() {
        return Some(format!(
            "size {:?}, expected {:?}",
            shown.size(),
            expected.size()
        ));
    }
    let (rows, cols) = expected.size();
    for row in 0..rows {
        for col in 0..cols {
            let look = |screen: &fux_vt::Screen| {
                screen.cell(row, col).map(|cell| {
                    let text = if cell.contents() == " " {
                        String::new()
                    } else {
                        cell.contents().to_owned()
                    };
                    let link = screen
                        .link(row, col)
                        .map(|l| (l.uri().to_owned(), l.id().map(str::to_owned)));
                    (
                        text,
                        cell.is_wide(),
                        cell.is_wide_continuation(),
                        cell.attributes(),
                        link,
                    )
                })
            };
            let mut b = look(expected);
            // The server draws a program's colours as RGB.
            if let Some(cell) = b.as_mut() {
                cell.3 = koh::terminal::drawn(cell.3, expected);
            }
            let (a, b) = (look(shown), b);
            if a != b {
                return Some(format!("cell ({row}, {col}): shown {a:?}, expected {b:?}"));
            }
        }
    }
    if shown.hide_cursor() != expected.hide_cursor() {
        return Some(format!("cursor hidden {}", shown.hide_cursor()));
    }
    if !expected.hide_cursor() && shown.cursor_position() != expected.cursor_position() {
        return Some(format!(
            "cursor at {:?}, expected {:?}",
            shown.cursor_position(),
            expected.cursor_position()
        ));
    }
    None
}

/// The script that writes `recording` a step at a time, and the directory holding it and its
/// steps' bytes.
fn script(recording: &Recording, dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let mut text = String::from("stty raw -echo\n");
    let wait = |text: &mut String, (rows, cols): (u16, u16)| {
        let _ = writeln!(
            text,
            "while [ \"$(stty size)\" != \"{rows} {cols}\" ]; do sleep 0.01; done"
        );
    };
    let mut size = (recording.rows, recording.cols);
    for (index, (step, output)) in recording.outputs().enumerate() {
        let file = dir.join(format!("{index}.bin"));
        std::fs::write(&file, output)?;
        if index > 0 {
            // Up to the test's 0x01: the server's replies to the recording's queries arrive on
            // the same input, and must not start a step.
            text.push_str(
                "while [ \"$(dd bs=1 count=1 2>/dev/null | od -An -tx1 | tr -d ' ')\" != 01 ]; do :; done\n",
            );
        }
        if let Some(resize) = step.resize {
            size = resize;
        }
        wait(&mut text, size);
        let _ = writeln!(text, "cat '{}'", file.display());
        let _ = writeln!(
            text,
            "echo {index} written >> '{}'",
            dir.join("log").display()
        );
    }
    text.push_str("while :; do sleep 60; done\n");
    let path = dir.join("replay.sh");
    std::fs::write(&path, text)?;
    Ok(path)
}

/// Replay `recording` through a server and client on `net`, checking each step's screen.
async fn replay(net: &FaultNet, recording: &Recording, dir: &Path) -> anyhow::Result<()> {
    let script = script(recording, dir)?;
    let script = script.to_string_lossy().into_owned();
    let secret = identity()?;
    let server = Server::start(net, &[secret.public()], &["sh", &script]).await?;
    let endpoint = net.endpoint(secret, false).await?;
    let connector = IrohConnector::new(endpoint, FaultNet::addr(server.id));
    let channel = connector.connect().await?;
    let start = Size::new(recording.rows, recording.cols);
    let shared = Shared {
        painted: Arc::default(),
        size: Arc::new(Mutex::new(start)),
    };
    // A terminal that keeps hyperlinks, as the user's does.
    let shown = Arc::new(Mutex::new(
        fux_vt::Parser::with_options(
            start.rows,
            start.cols,
            0,
            fux_vt::Options::new().with_hyperlinks(true),
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    ));
    let (paints_tx, mut paints) = watch::channel(0u64);
    let terminal = Readback {
        terminal: {
            // The user's terminal draws underline styles, as the one reading the paint does.
            let mut terminal = BackendTerminal::enter(shared.clone(), false)?;
            terminal.set_underline_styles(true);
            terminal.set_hyperlinks(true);
            terminal
        },
        shared: shared.clone(),
        shown: shown.clone(),
        paints: paints_tx,
    };
    let (input, input_rx) = mpsc::channel(64);
    let (resize, resize_rx) = mpsc::channel(8);
    let task = tokio::spawn(run_client(
        channel,
        connector,
        DisplayPreference::Never,
        start,
        input_rx,
        resize_rx,
        terminal,
        CancellationToken::new(),
        None,
    ));
    // The server's parser, with its options; the harness's server keeps no scrollback.
    let mut expected =
        fux_vt::Parser::with_options(start.rows, start.cols, 0, koh::terminal::OPTIONS)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut result = Ok(());
    for (index, (step, output)) in recording.outputs().enumerate() {
        if let Some((rows, cols)) = step.resize {
            expected
                .resize(rows, cols)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            // The user's terminal resizes, then the client hears of it.
            *shared.size.lock().unwrap_or_else(PoisonError::into_inner) = Size::new(rows, cols);
            shown
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .resize(rows, cols)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            resize.send(()).await?;
        }
        expected
            .process(output)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if index > 0 {
            input.send(vec![0x01]).await?;
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(STEP)
            .ok_or_else(|| anyhow::anyhow!("no deadline"))?;
        // The script says when it has written the step, so that a step which changes nothing on
        // the screen is not taken as shown before its bytes are out, and the next resize does not
        // overtake them.
        let written = format!("{index} written\n");
        while !std::fs::read_to_string(dir.join("log")).is_ok_and(|log| log.contains(&written)) {
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "{} step {index}: never written",
                    recording.name
                ));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let last = loop {
            let difference = difference(
                shown
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .screen(),
                expected.screen(),
            );
            if difference.is_none()
                || tokio::time::timeout_at(deadline, paints.changed())
                    .await
                    .map_or(true, |changed| changed.is_err())
            {
                break difference;
            }
        };
        if let Some(difference) = last {
            let rows = |screen: &fux_vt::Screen| {
                let (_, cols) = screen.size();
                (0..4u16)
                    .map(|row| {
                        (0..cols)
                            .map(|col| {
                                screen
                                    .cell(row, col)
                                    .map_or_else(|| " ".to_owned(), |c| c.contents().to_owned())
                            })
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
                    .join("|\n")
            };
            let shown_rows = rows(
                shown
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .screen(),
            );
            result = Err(anyhow::anyhow!(
                "{} step {index}: never showed the step: {difference}\nshown:\n{shown_rows}\nexpected:\n{}",
                recording.name,
                rows(expected.screen())
            ));
            break;
        }
    }
    drop(input);
    drop(resize);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    server.stop().await;
    result
}

#[test]
fn the_corpus_converges_over_a_lossy_link() {
    let wanted = std::env::var("KOH_NET_CORPUS").unwrap_or_default();
    let named: Vec<&str> = if wanted.is_empty() {
        DEFAULT.to_vec()
    } else {
        wanted.split(',').collect()
    };
    let corpus = Recording::load_all(&Path::new(env!("CARGO_MANIFEST_DIR")).join("testing/corpus"))
        .expect("the corpus");
    let chosen: Vec<&Recording> = corpus
        .iter()
        .filter(|r| wanted == "all" || named.contains(&r.name.as_str()))
        .filter(|r| !recording::DIFFERS.iter().any(|(name, _)| *name == r.name))
        .collect();
    assert!(!chosen.is_empty(), "no recording named {wanted:?}");
    let dir = std::env::temp_dir().join(format!("koh-net-corpus-{}", std::process::id()));
    runtime().expect("runtime").block_on(async {
        let mut failures = Vec::new();
        for (seed, recording) in (1u64..).zip(chosen) {
            let net = FaultNet::new(
                Profile {
                    loss: 0.05,
                    delay: Duration::from_millis(25),
                    ..Profile::default()
                },
                seed,
            );
            if let Err(e) = replay(&net, recording, &dir.join(&recording.name)).await {
                failures.push(format!("seed {seed}: {e:#}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
    let _ = std::fs::remove_dir_all(&dir);
}
