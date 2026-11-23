//! Interactive sessions backed directly by new `fux` (`fux-vt` 0.19 + `fuxix` 0.11):
//! every remote session writes a genuine frozen v1 `fux` pane folder on disk AND
//! pushes frames immediately over a `tokio::sync::watch` channel (zero double-polling).
//! OSC 133 `marks` (`Term::marks()`) replace old koh's brittle `--reading` PTY hack.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::symlink;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fux_vt::{Mark, MarkKind, Term, files};
use fuxix::Winsize;
use tokio::sync::watch;

use crate::proto::{ScreenFrame, SessionInfo, WaitResult};
use crate::{Exit, KohError, Result, atomic_write};

/// One live (or recently exited) interactive session backed by a real v1 `fux` pane folder.
pub struct PaneSession {
    pub id: u32,
    pub dir: PathBuf,
    started: Instant,
    attached: AtomicBool,
    pty_master: Mutex<Option<File>>,
    term: Mutex<Term>,
    history_lines: Mutex<String>,
    frame_tx: watch::Sender<ScreenFrame>,
    mark_tx: watch::Sender<usize>,
    generation: Mutex<u64>,
}

impl PaneSession {
    pub fn spawn(
        id: u32,
        dir: PathBuf,
        cols: u16,
        rows: u16,
        argv: &[String],
        cwd: &Path,
        default_shell: &str,
    ) -> Result<Arc<Self>> {
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("main"))
            .map_err(|e| KohError::failed(format!("mkdir pane dir: {e}")))?;

        let (cols, rows) = (cols.clamp(1, 500), rows.clamp(1, 500));
        let winsz = Winsize {
            rows,
            cols,
            xpixel: cols.saturating_mul(10),
            ypixel: rows.saturating_mul(20),
        };
        let (master, slave) =
            fuxix::pty(winsz).map_err(|e| KohError::failed(format!("openpty: {e}")))?;

        let (prog, args): (&str, &[String]) = match argv.split_first() {
            Some((p, rest)) => (p.as_str(), rest),
            None => (default_shell, &[]),
        };
        let mut cmd = Command::new(prog);
        cmd.args(args)
            .current_dir(cwd)
            .env("TERM", fux_vt::TERM)
            .env("COLORTERM", "truecolor")
            .stdin(Stdio::from(
                slave
                    .try_clone()
                    .map_err(|e| KohError::failed(format!("clone slave: {e}")))?,
            ))
            .stdout(Stdio::from(
                slave
                    .try_clone()
                    .map_err(|e| KohError::failed(format!("clone slave: {e}")))?,
            ))
            .stderr(Stdio::from(slave));
        fuxix::new_session(&mut cmd, true);

        let mut child = cmd.spawn().map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                Exit::NOT_FOUND
            } else {
                Exit::CANNOT_START
            };
            KohError::new(code, "cannot_start", format!("spawn session: {e}"))
        })?;
        let pid = child.id();
        let command_str = if argv.is_empty() {
            default_shell.to_string()
        } else {
            argv.join(" ")
        };
        let _ = atomic_write(
            &dir.join("status"),
            format!(
                "holder {}\npid {pid}\ncommand {command_str}\n",
                std::process::id()
            )
            .as_bytes(),
        );
        let _ = File::create(dir.join("history"));
        let _ = File::create(dir.join("history.styled"));

        let mut term = Term::new(usize::from(cols), usize::from(rows));
        term.told().name = format!("koh {}", env!("CARGO_PKG_VERSION"));
        let init_frame = snapshot(&mut term, id, 2, "running", None);
        let (frame_tx, _) = watch::channel(init_frame);
        let (mark_tx, _) = watch::channel(0usize);

        let session = Arc::new(Self {
            id,
            dir: dir.clone(),
            started: Instant::now(),
            attached: AtomicBool::new(false),
            pty_master: Mutex::new(Some(
                master
                    .try_clone()
                    .map_err(|e| KohError::failed(format!("clone master: {e}")))?,
            )),
            term: Mutex::new(term),
            history_lines: Mutex::new(String::new()),
            frame_tx,
            mark_tx,
            generation: Mutex::new(0),
        });
        session.publish("running", None);

        let reader_session = session.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 32 << 10];
            loop {
                let ready = fuxix::wait([(Some(master.as_fd()), fuxix::POLLIN)], 50);
                if matches!(ready, Ok([ev]) if ev != 0) {
                    let mut read_any = false;
                    loop {
                        match (&master).read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                read_any = true;
                                if let Some(slice) = buf.get(..n) {
                                    reader_session.feed(slice);
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                    if read_any {
                        reader_session.publish("running", None);
                    }
                }
                if let Ok(Some(status)) = child.try_wait() {
                    // Drain final PTY output before marking exited.
                    loop {
                        match (&master).read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if let Some(slice) = buf.get(..n) {
                                    reader_session.feed(slice);
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let (state, code) = if let Some(c) = status.code() {
                        (format!("exited {c}"), Some(c))
                    } else if let Some(sig) = status.signal() {
                        (format!("killed {sig}"), Some(128 + sig))
                    } else {
                        ("exited 1".to_string(), Some(1))
                    };
                    if let Ok(mut m) = reader_session.pty_master.lock() {
                        *m = None;
                    }
                    reader_session.publish(&state, code);
                    break;
                }
            }
        });

        Ok(session)
    }

    fn feed(&self, bytes: &[u8]) {
        let reply = {
            let Ok(mut term) = self.term.lock() else {
                return;
            };
            term.feed(bytes);
            let out = term.take(0);
            if !out.history.is_empty() {
                if let Ok(mut hist) = self.history_lines.lock() {
                    hist.push_str(&out.history);
                    if hist.len() > (4 << 20) {
                        let cut = hist.len() - (4 << 20);
                        let boundary = hist.ceil_char_boundary(cut);
                        hist.drain(..boundary);
                    }
                }
                if let Ok(mut f) = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(self.dir.join("history"))
                {
                    let _ = f.write_all(out.history.as_bytes());
                }
            }
            if !out.styled.is_empty()
                && let Ok(mut f) = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(self.dir.join("history.styled"))
            {
                let _ = f.write_all(out.styled.as_bytes());
            }
            let mark_count = term.marks().len();
            if *self.mark_tx.borrow() != mark_count {
                let _ = self.mark_tx.send_replace(mark_count);
            }
            out.reply
        };
        if !reply.is_empty() {
            let _ = self.write_input(&reply);
        }
    }

    /// Writes frozen v1 `fux` pane files atomically under odd->even `generation` and notifies attached clients.
    fn publish(&self, state: &str, exit: Option<i32>) {
        let Ok(mut term) = self.term.lock() else {
            return;
        };
        let Ok(mut generation) = self.generation.lock() else {
            return;
        };

        *generation = generation.wrapping_add(1);
        let _ = atomic_write(
            &self.dir.join("generation"),
            format!("{}\n", *generation).as_bytes(),
        );

        // Write any new pictures beside the screen files.
        for (pic_id, fmt, data) in term.new_pictures() {
            let _ = fs::write(self.dir.join(format!("pic-{pic_id}.{}", fmt.ext())), data);
        }

        if let Some(main_f) = files::render(&term, false) {
            write_screen_dir(&self.dir.join("main"), &main_f);
        }
        if let Some(alt_f) = files::render(&term, true) {
            let _ = fs::create_dir_all(self.dir.join("alt"));
            write_screen_dir(&self.dir.join("alt"), &alt_f);
            replace_shown_link(&self.dir, "alt");
        } else {
            replace_shown_link(&self.dir, "main");
            let _ = fs::remove_dir_all(self.dir.join("alt"));
        }

        let frame = snapshot(&mut term, self.id, generation.wrapping_add(1), state, exit);
        let shown_word = if frame.cursor_shown {
            "shown"
        } else {
            "hidden"
        };
        let _ = atomic_write(
            &self.dir.join("size"),
            format!("{} {}\n", frame.cols, frame.rows).as_bytes(),
        );
        let _ = atomic_write(
            &self.dir.join("cursor"),
            format!(
                "{} {} {shown_word} {}\n",
                frame.cursor_row, frame.cursor_col, frame.cursor_shape
            )
            .as_bytes(),
        );
        let _ = atomic_write(
            &self.dir.join("modes"),
            format!("{}\n", frame.modes).as_bytes(),
        );
        let _ = atomic_write(&self.dir.join("marks"), frame.marks.as_bytes());
        let _ = atomic_write(&self.dir.join("state"), format!("{state}\n").as_bytes());
        if frame.title.is_empty() {
            let _ = fs::remove_file(self.dir.join("title"));
        } else {
            let _ = atomic_write(
                &self.dir.join("title"),
                format!("{}\n", frame.title).as_bytes(),
            );
        }

        *generation = generation.wrapping_add(1);
        let _ = atomic_write(
            &self.dir.join("generation"),
            format!("{}\n", *generation).as_bytes(),
        );
        let _ = self.frame_tx.send_replace(frame);
    }

    pub fn write_input(&self, bytes: &[u8]) -> Result<()> {
        let mut guard = self
            .pty_master
            .lock()
            .map_err(|_| KohError::internal("pty lock"))?;
        if let Some(master) = guard.as_mut() {
            let mut offset = 0usize;
            while offset < bytes.len() {
                let Some(slice) = bytes.get(offset..) else {
                    break;
                };
                match master.write(slice) {
                    Ok(0) => break,
                    Ok(n) => offset += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => return Err(KohError::failed(format!("write pty: {e}"))),
                }
            }
        }
        Ok(())
    }

    pub fn resize(&self, cols: u16, rows: u16) {
        let (cols, rows) = (cols.clamp(1, 500), rows.clamp(1, 500));
        if let Ok(guard) = self.pty_master.lock()
            && let Some(master) = guard.as_ref()
        {
            let winsz = Winsize {
                rows,
                cols,
                xpixel: cols.saturating_mul(10),
                ypixel: rows.saturating_mul(20),
            };
            let _ = fuxix::set_winsize(master, winsz);
        }
        if let Ok(mut term) = self.term.lock() {
            term.resize(usize::from(cols), usize::from(rows));
        }
        let cur = self.frame_tx.borrow().clone();
        self.publish(&cur.state, cur.exit);
    }

    pub fn set_attached(&self, attached: bool) {
        self.attached.store(attached, Ordering::Relaxed);
    }

    pub fn subscribe(&self) -> watch::Receiver<ScreenFrame> {
        self.frame_tx.subscribe()
    }

    pub fn info(&self) -> SessionInfo {
        let frame = self.frame_tx.borrow().clone();
        let marks = self.term.lock().map(|t| t.marks()).unwrap_or_default();
        let (running_command, last_exit) = marks_state(&marks);
        SessionInfo {
            id: self.id,
            attached: self.attached.load(Ordering::Relaxed),
            state: frame.state,
            cols: frame.cols,
            rows: frame.rows,
            title: frame.title,
            running_command,
            last_exit,
            age_secs: self.started.elapsed().as_secs(),
            pane_dir: self.dir.display().to_string(),
        }
    }

    /// Returns the pane's screen text, or with `last = true`, the last OSC 133 command output.
    pub fn output(&self, last: bool) -> String {
        if !last {
            return self.frame_tx.borrow().screen.clone();
        }
        let (marks, main_screen, history) = {
            let Ok(term) = self.term.lock() else {
                return String::new();
            };
            let marks = term.marks();
            let screen = files::render(&term, false)
                .map(|f| f.screen)
                .unwrap_or_default();
            let hist = self
                .history_lines
                .lock()
                .map(|h| h.clone())
                .unwrap_or_default();
            (marks, screen, hist)
        };
        extract_last_output(&marks, &history, &main_screen)
    }

    /// Waits for the next OSC 133 `MarkKind::End` mark (or session exit), replacing `--reading`.
    pub async fn wait_command(&self, timeout_secs: Option<u64>) -> Result<WaitResult> {
        let mut frame_rx = self.frame_tx.subscribe();
        let mut mark_rx = self.mark_tx.subscribe();
        let initial_ends = self
            .term
            .lock()
            .map(|t| t.marks().iter().filter(|m| m.kind == MarkKind::End).count())
            .unwrap_or(0);
        let deadline = timeout_secs.map(|s| Instant::now() + Duration::from_secs(s));

        loop {
            {
                let marks = self.term.lock().map(|t| t.marks()).unwrap_or_default();
                let ends: Vec<&Mark> = marks.iter().filter(|m| m.kind == MarkKind::End).collect();
                if ends.len() > initial_ends {
                    let exit = ends.last().and_then(|m| m.exit).map_or(0, i32::from);
                    let tail = self.output(true);
                    return Ok(WaitResult {
                        timed_out: false,
                        exit,
                        tail,
                        detail: "command ended (OSC 133)".into(),
                    });
                }
            }
            {
                let cur = frame_rx.borrow().clone();
                if cur.state != "running" {
                    return Ok(WaitResult {
                        timed_out: false,
                        exit: cur.exit.unwrap_or(0),
                        tail: cur.screen,
                        detail: cur.state,
                    });
                }
            }
            if let Some(dl) = deadline
                && Instant::now() >= dl
            {
                return Ok(WaitResult {
                    timed_out: true,
                    exit: i32::from(Exit::TIMEOUT.0),
                    tail: self.output(false),
                    detail: "timed out".into(),
                });
            }
            let wait_for = deadline.map_or(Duration::from_millis(200), |dl| {
                dl.saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(200))
            });
            tokio::select! {
                _ = mark_rx.changed() => {}
                _ = frame_rx.changed() => {}
                () = tokio::time::sleep(wait_for) => {}
            }
        }
    }
}

/// Manages all interactive `fux`-backed sessions on the server.
pub struct SessionManager {
    root: PathBuf,
    next_id: u32,
    last_id: Option<u32>,
    sessions: BTreeMap<u32, Arc<PaneSession>>,
}

pub struct AttachSpec<'a> {
    pub requested: Option<u32>,
    pub new: bool,
    pub cols: u16,
    pub rows: u16,
    pub argv: &'a [String],
    pub cwd: &'a Path,
    pub default_shell: &'a str,
}

impl SessionManager {
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .map_err(|e| KohError::failed(format!("mkdir {}: {e}", root.display())))?;
        Ok(Self {
            root,
            next_id: 1,
            last_id: None,
            sessions: BTreeMap::new(),
        })
    }

    pub fn attach_or_create(&mut self, spec: AttachSpec<'_>) -> Result<Arc<PaneSession>> {
        if let Some(id) = spec.requested {
            let sess = self.sessions.get(&id).cloned().ok_or_else(|| {
                KohError::new(Exit::NOT_FOUND, "not_found", format!("no session {id}"))
            })?;
            self.last_id = Some(id);
            return Ok(sess);
        }
        if !spec.new
            && spec.argv.is_empty()
            && let Some(last) = self.last_id
            && let Some(sess) = self.sessions.get(&last)
            && sess.info().state == "running"
        {
            return Ok(sess.clone());
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let dir = self.root.join(format!("s{id}"));
        let sess = PaneSession::spawn(
            id,
            dir,
            spec.cols,
            spec.rows,
            spec.argv,
            spec.cwd,
            spec.default_shell,
        )?;
        self.sessions.insert(id, sess.clone());
        self.last_id = Some(id);
        Ok(sess)
    }

    pub fn get(&self, id: u32) -> Result<Arc<PaneSession>> {
        self.sessions
            .get(&id)
            .cloned()
            .ok_or_else(|| KohError::new(Exit::NOT_FOUND, "not_found", format!("no session {id}")))
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        self.sessions.values().map(|s| s.info()).collect()
    }
}

fn snapshot(
    term: &mut Term,
    session_id: u32,
    generation: u64,
    state: &str,
    exit: Option<i32>,
) -> ScreenFrame {
    let modes = files::modes(term);
    let marks = files::marks(term);
    let shown = term.shown();
    let alt = shown.is_alt();
    let rendered = files::render(term, alt).or_else(|| files::render(term, false));
    let (screen, styled, lines, links) = rendered
        .map(|f| (f.screen, f.styled, f.lines, f.links))
        .unwrap_or_default();
    ScreenFrame {
        session_id,
        generation,
        cols: shown.cols,
        rows: shown.rows,
        alt,
        screen,
        styled,
        lines,
        links,
        cursor_row: shown.cursor.row,
        cursor_col: shown.cursor.col,
        cursor_shown: shown.cursor_shown,
        cursor_shape: shown.cursor_shape,
        modes,
        title: term.title().to_string(),
        marks,
        state: state.to_string(),
        exit,
    }
}

fn write_screen_dir(dir: &Path, f: &files::Files<'_>) {
    let mut pictures = String::new();
    for p in f.pictures {
        let row = if p.off > 0 {
            format!("-{}", p.off)
        } else {
            p.row.to_string()
        };
        pictures.push_str(&format!(
            "pic-{}.{} {row} {} {} {} {} {}\n",
            p.id,
            p.format.ext(),
            p.col,
            p.cols,
            p.rows + p.off,
            p.cell.0,
            p.cell.1
        ));
    }
    let _ = atomic_write(&dir.join("lines"), f.lines.as_bytes());
    let _ = atomic_write(&dir.join("links"), f.links.as_bytes());
    let _ = atomic_write(&dir.join("pictures"), pictures.as_bytes());
    let _ = atomic_write(&dir.join("screen"), f.screen.as_bytes());
    let _ = atomic_write(&dir.join("screen.styled"), f.styled.as_bytes());
}

fn replace_shown_link(dir: &Path, target: &str) {
    let tmp = dir.join(".shown.new");
    let _ = fs::remove_file(&tmp);
    if symlink(target, &tmp).is_ok() {
        let _ = fs::rename(&tmp, dir.join("shown"));
    }
}

fn marks_state(marks: &[Mark]) -> (bool, Option<u8>) {
    let last_exit = marks
        .iter()
        .rev()
        .find(|m| m.kind == MarkKind::End)
        .and_then(|m| m.exit);
    let running = matches!(
        marks.last().map(|m| m.kind),
        Some(MarkKind::Command | MarkKind::Output)
    );
    (running, last_exit)
}

fn extract_last_output(marks: &[Mark], history: &str, main_screen: &str) -> String {
    let end_idx = marks.iter().rposition(|m| m.kind == MarkKind::End);
    let end_line = end_idx.and_then(|i| marks.get(i)).map(|m| m.line);
    let search_slice = end_idx.and_then(|i| marks.get(..i)).unwrap_or(marks);
    let Some(out_mark) = search_slice
        .iter()
        .rev()
        .find(|m| m.kind == MarkKind::Output)
    else {
        return main_screen.to_string();
    };
    let mut combined = String::with_capacity(history.len() + main_screen.len());
    combined.push_str(history);
    combined.push_str(main_screen);
    let all_lines: Vec<&str> = combined.lines().collect();
    let start = out_mark.line.min(all_lines.len());
    let stop = end_line.unwrap_or(all_lines.len()).min(all_lines.len());
    if start >= stop {
        return String::new();
    }
    let mut out = all_lines.get(start..stop).unwrap_or_default().join("\n");
    out.push('\n');
    out
}
