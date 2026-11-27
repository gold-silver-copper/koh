//! A koh server and its clients on the fault link.
//!
//! The server is `koh serve`'s own (`start_server`) and a client is `koh connect`'s own
//! (`Client::connect_terminal`), both in this process, each on an endpoint whose only transport
//! is the link. A session is a pane started as `koh serve` starts one, by the real binary, and
//! its viewer is the real binary too. A client's terminal is a pty of the test's, and what koh
//! writes there is fed to a pane of fux's as its program's output: that pane is the terminal
//! emulator, and its files say what a terminal would show (`screen`, `modes`, `cursor`, and
//! which screen, `shown`).

use std::fs::{self, File};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iroh::EndpointId;
use koh::client::{Client, ConnectOptions};
use koh::keys::{Role, load_or_create_key};
use koh::server::{RunningServer, ServeOptions, start_server};
use tokio::sync::watch;

use crate::net::{FaultNet, Profile};

pub struct Rig {
    pub net: FaultNet,
    pub server_id: EndpointId,
    sessions: PathBuf,
    client_terms: PathBuf,
    tmp: PathBuf,
    _server: RunningServer,
}

/// Kills the holders of the panes in `dir` that live: a holder keeps its folder locked, and a
/// folder that is not locked names a holder that is gone (its number may be another's now).
fn kill_holders(dir: &Path) {
    for pane in fs::read_dir(dir).into_iter().flatten().flatten() {
        let folder = fuxix::open(pane.path(), false).map(|folder| folder.try_lock_shared());
        if !matches!(folder, Ok(Err(fs::TryLockError::WouldBlock))) {
            continue;
        }
        let status = fs::read_to_string(pane.path().join("status")).unwrap_or_default();
        if let Some(holder) = status
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("holder "))
        {
            let _ = Command::new("kill").args(["-KILL", holder]).status();
        }
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        kill_holders(&self.sessions);
        kill_holders(&self.client_terms);
        let _ = fs::remove_dir_all(&self.tmp);
    }
}

impl Rig {
    /// A server on a link of `profile`.
    pub async fn start(tag: &str, profile: Profile) -> Rig {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let name = format!("koh-link-{tag}-{}-{}", std::process::id(), nanos.as_nanos());
        let tmp = std::env::temp_dir().join(name);
        fs::create_dir_all(&tmp).unwrap();
        let tmp = fs::canonicalize(tmp).unwrap();
        let net = FaultNet::new(profile);
        let key_file = tmp.join("srv_cfg/server.key");
        let secret = load_or_create_key(Role::Server, Some(&key_file)).unwrap();
        let server_id = secret.public();
        let server = start_server(ServeOptions {
            key_file: Some(key_file),
            allow: vec![Self::key(&tmp, "a").public(), Self::key(&tmp, "b").public()],
            shell: Some("/bin/sh".into()),
            state_dir: Some(tmp.join("state")),
            endpoint: Some(net.endpoint(secret, true).await),
            session_exe: Some(PathBuf::from(env!("CARGO_BIN_EXE_koh"))),
            quiet: true,
            ..ServeOptions::default()
        })
        .await
        .unwrap();
        let client_terms = tmp.join("client-terms");
        fs::create_dir_all(&client_terms).unwrap();
        Rig {
            net,
            server_id,
            sessions: tmp.join("state/fux/koh-sessions"),
            client_terms,
            tmp,
            _server: server,
        }
    }

    fn key(tmp: &Path, who: &str) -> iroh::SecretKey {
        let file = tmp.join(who).join("client.key");
        load_or_create_key(Role::Client, Some(&file)).unwrap()
    }

    /// A file of the test's own.
    pub fn file(&self, name: &str) -> PathBuf {
        self.tmp.join(name)
    }

    /// Starts the session `name` running `program`, 80 by 24, as the server starts one, and
    /// gives its folder.
    pub fn pane(&self, name: &str, program: &[&str]) -> PathBuf {
        self.start_pane(&self.sessions.join(name), program, 80, 24)
    }

    fn start_pane(&self, pane: &Path, program: &[&str], cols: u16, rows: u16) -> PathBuf {
        let mut start = Command::new(env!("CARGO_BIN_EXE_koh"));
        start
            .args(["fux", "start"])
            .arg(pane)
            .arg("--")
            .args(program);
        start
            .env("COLUMNS", cols.to_string())
            .env("LINES", rows.to_string())
            .env("XDG_RUNTIME_DIR", self.tmp.join("run"))
            .env("HOME", &self.tmp)
            .env("HISTFILE", "/dev/null")
            .current_dir(&self.tmp)
            .stdin(std::process::Stdio::null());
        let said = start.output().unwrap();
        assert!(
            said.status.success(),
            "{}",
            String::from_utf8_lossy(&said.stderr)
        );
        pane.to_path_buf()
    }

    /// A client of the key `who` that has dialled the server, and its endpoint's name.
    pub async fn dialled(&self, who: &str) -> (Client, EndpointId) {
        self.dialled_to(who, self.server_id).await
    }

    /// The same, to another server on the link: a test's own, which says what it likes.
    pub async fn dialled_to(&self, who: &str, server: EndpointId) -> (Client, EndpointId) {
        let secret = Self::key(&self.tmp, who);
        let id = secret.public();
        let endpoint = self.net.endpoint(secret.clone(), false).await;
        let client = Client::connect_on(secret, endpoint, FaultNet::addr(server))
            .await
            .unwrap();
        (client, id)
    }

    /// The names of the sessions there are.
    pub fn sessions(&self) -> Vec<String> {
        let folders = fs::read_dir(&self.sessions).unwrap().flatten();
        let names = folders.map(|folder| folder.file_name().to_string_lossy().into_owned());
        names.filter(|name| !name.starts_with('.')).collect()
    }

    /// `koh connect` of a client that has dialled, to the session `name` or (`new`) a new one,
    /// on a pty of 80 by 24 of the test's own.
    pub fn connect_on(&self, on: (Client, EndpointId), name: Option<&str>, new: bool) -> Connected {
        let ((client, id), (cols, rows)) = (on, (80, 24));
        let tag = id.fmt_short().to_string();
        let (master, slave) = fuxix::pty(fuxix::Winsize {
            cols,
            rows,
            xpixel: cols * 8,
            ypixel: rows * 16,
        })
        .unwrap();
        let slave_out = slave.try_clone().unwrap();
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let tag = format!("{tag}-{}", nanos.as_nanos());
        let feed_path = self.tmp.join(format!("feed-{tag}"));
        let _feed_keep = fuxix::fifo(&feed_path).unwrap();
        let term = self.start_pane(
            &self.client_terms.join(&tag),
            &[
                "sh",
                "-c",
                "stty raw -echo; exec cat < \"$0\"",
                feed_path.to_str().unwrap(),
            ],
            cols,
            rows,
        );
        let feed_w = fs::OpenOptions::new().write(true).open(&feed_path).unwrap();
        let raw_out = Arc::new(Mutex::new(Vec::<u8>::new()));
        let raw_clone = raw_out.clone();
        let master_r = master.try_clone().unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let reader_stop = stop_rx.clone();
        std::thread::spawn(move || {
            let mut feed_w = feed_w;
            let mut buf = [0u8; 4096];
            // (What koh asks its terminal at its start is answered as every terminal answers,
            // with what it is and no more, and is not of what is drawn.)
            let mut asked = Some(Vec::new());
            while !*reader_stop.borrow() {
                let Ok([ready]) = fuxix::wait([(Some(master_r.as_fd()), fuxix::POLLIN)], 30) else {
                    break;
                };
                if ready == 0 {
                    continue;
                }
                match (&master_r).read(&mut buf) {
                    Ok(n @ 1..) => {
                        let mut slice = buf[..n].to_vec();
                        if let Some(mut question) = asked.take() {
                            question.extend_from_slice(&slice);
                            let Some(end) = question.windows(3).position(|at| at == b"\x1b[c")
                            else {
                                asked = Some(question);
                                continue;
                            };
                            write_all_pty(&master_r, b"\x1b[?62c");
                            slice = question.split_off(end + 3);
                        }
                        raw_clone.lock().unwrap().extend_from_slice(&slice);
                        let _ = feed_w.write_all(&slice);
                    }
                    Ok(0) => break,
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                    Err(_) => break,
                }
            }
            drop(_feed_keep);
        });
        let asks = ConnectOptions {
            session: name.map(String::from),
            new,
            ..ConnectOptions::default()
        };
        let task = tokio::spawn(client.connect_terminal(asks, slave, slave_out));
        Connected {
            term,
            master,
            raw_out,
            id,
            stop_tx,
            task,
        }
    }

    /// Connects and waits until the client's terminal has received its first screen bytes.
    pub async fn connect(&self, name: &str, who: &str) -> Connected {
        let conn = self.connect_on(self.dialled(who).await, Some(name), false);
        conn.has_output(Duration::from_secs(20));
        conn
    }
}

/// An in-process `koh connect` session on a real PTY, with a local fux-vt pane rendering its
/// terminal output.
pub struct Connected {
    /// Local fux pane rendering everything `koh connect` wrote to its terminal.
    pub term: PathBuf,
    master: File,
    raw_out: Arc<Mutex<Vec<u8>>>,
    /// The client's endpoint: what the link counts towards it is what the server sent.
    pub id: EndpointId,
    stop_tx: watch::Sender<bool>,
    pub task: tokio::task::JoinHandle<koh::Result<i32>>,
}

impl Drop for Connected {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(true);
        self.task.abort();
    }
}

impl Connected {
    pub fn has_output(&self, long: Duration) {
        until("the client received output", long, || {
            !self.raw_out.lock().unwrap().is_empty() || self.task.is_finished()
        });
        assert!(!self.task.is_finished(), "koh connect ended unexpectedly");
    }

    /// Types bytes into the client's terminal (blocking until all bytes are written to PTY).
    pub fn types(&self, bytes: &[u8]) {
        write_all_pty(&self.master, bytes);
    }

    /// Clones the master fd so a background thread can type while the test runs.
    pub fn master_clone(&self) -> File {
        self.master.try_clone().unwrap()
    }

    /// Resizes the client's PTY and its local terminal emulator.
    pub fn resize(&self, cols: u16, rows: u16) {
        fuxix::set_winsize(
            &self.master,
            fuxix::Winsize {
                cols,
                rows,
                xpixel: cols * 8,
                ypixel: rows * 16,
            },
        )
        .unwrap();
        let _ = fs::write(self.term.join("ctl"), format!("resize {cols} {rows}\n"));
    }

    /// Rendered screen text in the client's terminal emulator.
    pub fn screen(&self) -> String {
        screen(&self.term)
    }

    /// Raw bytes written by `koh connect` to the client's terminal so far.
    pub fn raw(&self) -> Vec<u8> {
        self.raw_out.lock().unwrap().clone()
    }

    /// The file of the client's terminal that says `what` of it (`modes`, `cursor`), and which
    /// of its screens is shown (`main` or `alt`).
    pub fn says(&self, what: &str) -> String {
        fs::read_to_string(self.term.join(what)).unwrap_or_default()
    }

    pub fn shown(&self) -> String {
        let shown = fs::read_link(self.term.join("shown")).unwrap_or_default();
        shown.to_string_lossy().into_owned()
    }

    /// Waits until `koh connect` has ended, and gives what it ended with.
    pub async fn ends(&mut self, long: Duration) -> koh::Result<i32> {
        let ended = tokio::time::timeout(long, &mut self.task).await;
        ended.expect("koh connect did not end").unwrap()
    }
}

/// Writes all `bytes` to a non-blocking PTY master fd.
pub fn write_all_pty(master: &File, bytes: &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        match (&*master).write(&bytes[at..]) {
            Ok(n @ 1..) => at += n,
            Ok(0) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("write to PTY failed: {e}"),
        }
    }
}

/// A program for a session that takes what is typed as it is typed, into the file `out`: it
/// says READY once its terminal is raw, and then reads.
pub fn reads_into(out: &Path) -> [&str; 4] {
    let script = "stty raw -echo; echo READY; exec cat > \"$0\"";
    ["sh", "-c", script, out.to_str().unwrap()]
}

/// Waits, `long` at most, until `done` says so.
pub fn until(what: &str, long: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + long;
    while !done() {
        assert!(Instant::now() < deadline, "not in {long:?}: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// What a pane's `state` says became of its program.
pub fn state(dir: &Path) -> String {
    let state = fs::read_to_string(dir.join("state")).unwrap_or_default();
    state.trim().to_string()
}

/// The screen a pane's folder shows.
pub fn screen(dir: &Path) -> String {
    fs::read_to_string(dir.join("shown/screen")).unwrap_or_default()
}

/// Waits until the client's terminal shows what the session's pane shows: the same rows of
/// text. (But for blanks at a row's end. A pane's `screen` keeps a blank a program typed where
/// its line wraps and drops one that was only drawn there, and a viewer draws every cell: the
/// two files differ in such a blank, and no terminal shows it.)
pub fn screen_agrees(pane: &Path, client: &Connected) {
    let rows = |screen: String| -> Vec<String> {
        let rows = screen.lines().map(|row| row.trim_end().to_string());
        rows.collect()
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (want, got) = (screen(pane), client.screen());
        if !want.is_empty() && rows(want.clone()) == rows(got.clone()) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "client screen != pane screen:\n--- pane ---\n{want}\n--- client ---\n{got}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The numbered line `n` of sixteen bytes, as a test types them.
pub fn line(n: u64) -> Vec<u8> {
    format!("{n:015}\n").into_bytes()
}
