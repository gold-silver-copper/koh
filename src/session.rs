//! The server's side of a session. A session is a fux pane in a fux session of koh's own
//! (`STATE/fux/koh-sessions/NAME`), kept by fux's holder, which is this binary run as
//! `koh hold`: no child of `koh serve`, and alive without it. Here one is found or started,
//! known by its run (fux's `run` file), and shown to each attached client by a viewer of its
//! own: this binary again, run on a pty of the client's size (`koh view-session`, which is
//! `fux::view_pane`). What the viewer draws is sent as it comes and what the client types is
//! written to it; nothing of the session's folder leaves the server. `koh serve` keeps no
//! table of sessions: the folders are the sessions. It keeps which stream each attached
//! client has on a run.

use std::collections::HashMap;
use std::fs::{self, DirBuilder, TryLockError};
use std::os::fd::AsFd as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use fux::run_of;
use iroh::endpoint::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::unix::pipe;
use tokio::sync::watch;
use tokio::time::Instant as Timer;

use crate::pane::{self, Marks};
use crate::proto::{
    Attach, Attached, MAX_CTRL, Reply, SessionInfo, VIEW_FRAME, ViewInput, ViewOutput, WaitResult,
    recv_msg, send_msg, send_pieces, session_name,
};
use crate::{Aside, Exit, KohError, Result, after};

/// Which run of a session's name a folder is: what its holder wrote in `run` at its start
/// (`fux::run_of`). A name started anew is another run, whatever folder it is given.
type Run = u128;

/// A stream of a client on a run: its number among this server's streams, and what ends it.
/// (Whoever ends it sends, and then waits until the receiver is dropped: it writes no more.)
type Stream = (u64, watch::Sender<bool>);

pub struct Sessions {
    /// `STATE/fux/koh-sessions`, by its whole path: a workspace of a fux session of koh's own.
    dir: PathBuf,
    /// Most folders kept there at once.
    max: usize,
    shell: String,
    /// This binary, which is fux, the holder and the viewer too.
    exe: PathBuf,
    /// One at a time finds or starts a session: the folders are counted under this.
    starting: tokio::sync::Mutex<()>,
    streams: Mutex<HashMap<(Run, u64), Stream>>,
    streamed: AtomicU64,
}

/// Whether a holder keeps the folder: its lock is held. Asked only of a folder that has a
/// `status`: `fux start` makes a folder before it locks it, and a lock asked in that moment
/// would fail that start.
pub(crate) fn lives(dir: &Path) -> bool {
    let asked = fuxix::open(dir, false).map(|folder| folder.try_lock_shared());
    matches!(asked, Ok(Err(TryLockError::WouldBlock)))
}

/// Reads a pane's state by probing `is_alive` BEFORE reading `state`: once the lock is seen
/// free, the holder has already published its final `state`.
pub(crate) fn state_now(dir: &Path, is_alive: impl FnOnce(&Path) -> bool) -> String {
    let alive = is_alive(dir);
    state_of(pane::line(dir, "state"), alive)
}

/// How a run ended, if it has: `None` while its holder lives and `state` is `running` or `hungup`,
/// `Some(Ok(state))` once ended (`exited N`, `killed S`, or `ended`), `Some(Err(()))` if its
/// folder is gone or now another run's. Probes `lives` before `state` and checks `run` after.
pub(crate) fn ended(dir: &Path, run: Run) -> Option<std::result::Result<String, ()>> {
    let alive = lives(dir);
    let state = state_of(pane::line(dir, "state"), alive);
    if run_of(dir) != Some(run) {
        return Some(Err(()));
    }
    (!(alive && matches!(state.as_str(), "running" | "hungup"))).then_some(Ok(state))
}

/// Creates and canonicalizes `STATE/fux/<name>` with mode `0700`.
pub(crate) fn workspace_dir(state: &Path, name: &str) -> Result<PathBuf> {
    let dir = state.join("fux").join(name);
    DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&dir)
        .and_then(|()| fs::canonicalize(&dir))
        .map_err(|e| KohError::failed(format!("{}: {e}", dir.display())))
}

/// Looks up a valid pane-named folder and its `run` under `root`.
pub(crate) fn named_in(
    root: &Path,
    name: &str,
    need_status: bool,
    what: String,
) -> Result<(PathBuf, Run)> {
    session_name(name)
        .then(|| root.join(name))
        .filter(|d| !need_status || d.join("status").is_file())
        .and_then(|d| Some((d.clone(), run_of(&d)?)))
        .ok_or_else(|| not_found(what))
}

pub(crate) fn not_found(what: String) -> KohError {
    KohError::new(Exit::NOT_FOUND, what)
}

/// What `state` says became of a pane's program. It runs only while a holder lives:
/// where none does and the file says nothing else, nothing says how it ended.
pub(crate) fn state_of(said: Option<String>, alive: bool) -> String {
    match said {
        Some(state) if state != "running" => state,
        _ if alive => "running".into(),
        _ => "ended".into(),
    }
}

/// A session as its folder says it is, read of one round of its holder's writing.
fn info(dir: &Path, attached: bool) -> SessionInfo {
    let ((alive, state, size, title, marks), _) = pane::together(dir, lives, || {
        let line = |name| pane::line(dir, name);
        let size = line("size").unwrap_or_default();
        (
            lives(dir),
            line("state"),
            size,
            line("title"),
            Marks::read(dir, None),
        )
    });
    let mut size = size.split(' ').map(|cells| cells.parse().unwrap_or(0));
    SessionInfo {
        name: dir.file_name().unwrap_or_default().to_string_lossy().into(),
        attached,
        state: state_of(state, alive),
        cols: size.next().unwrap_or(0),
        rows: size.next().unwrap_or(0),
        title: title.unwrap_or_default(),
        running_command: alive && marks.busy,
        last_exit: marks.ended.and_then(|(_, code, _)| code),
    }
}

/// What a session shows; or with `last` what its last command printed, which is what it
/// shows where its shell has marked no command that ended.
fn text(dir: &Path, last: bool) -> Vec<u8> {
    let printed = last.then(|| pane::together(dir, lives, || pane::last(dir)).0);
    printed.flatten().unwrap_or_else(|| screen(dir))
}

/// The screen a session shows.
fn screen(dir: &Path) -> Vec<u8> {
    pane::read(dir, "shown/screen").unwrap_or_default()
}

/// What a wait finds when it looks: nothing while the session runs on and no `end` of its
/// shell has a number above `asked`; else the exit code, how it ended, and the text. The
/// first command that ended, its code and what it printed, of one round; or, of a session
/// that ended, what `state` says and its last screen. A folder that is gone or another run's
/// once all that was read has ended, and nothing of it is given.
fn looked(dir: &Path, run: Run, asked: u64) -> Option<(i32, String, Vec<u8>)> {
    // (What is not known to be of one round is not believed: the next look is.)
    let (ended, whole) = pane::together(dir, lives, || pane::ended_since(asked, dir));
    let answer = match (ended.filter(|_| whole), lives(dir)) {
        (Some((code, printed, unread)), _) => {
            let said = match unread {
                0 => "command ended (OSC 133)".to_string(),
                // (More marks came than the file keeps: what is left of them is not all.)
                n => format!(
                    "command ended (OSC 133): the oldest still kept, not known to be the first ({n} marks came and went unread)"
                ),
            };
            Some((
                code.map_or(0, i32::from),
                said,
                printed.unwrap_or_else(|| screen(dir)),
            ))
        }
        (None, false) => {
            let state = state_of(pane::line(dir, "state"), false);
            Some((pane::code(&state).unwrap_or(1), state, screen(dir)))
        }
        (None, true) => None,
    };
    match run_of(dir) == Some(run) {
        true => answer,
        false => Some((1, "ended".into(), Vec::new())),
    }
}

/// File work on the blocking pool: reading pane folders, logs, and waiting while a holder writes.
pub(crate) async fn pooled<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
    let read = tokio::task::spawn_blocking(work).await;
    read.map_err(|e| KohError::internal(format!("reading a pane: {e}")))
}

impl Sessions {
    /// The sessions kept beneath the state directory `state`, `max` of them at most, each a new
    /// one running `shell` unless its client names a program. `exe` is this binary where the
    /// process is another (a test's): it is run as fux, as a holder and as a viewer.
    pub fn new(state: &Path, max: usize, shell: String, exe: PathBuf) -> Result<Self> {
        let dir = workspace_dir(state, "koh-sessions")?;
        // A viewer's folder that no viewer reads the FIFO of was left by one that was killed
        // (with its `koh serve`, as a rule): it goes. A viewer that lives keeps its own.
        let session = dir.parent().unwrap_or(&dir);
        for left in fs::read_dir(session).into_iter().flatten().flatten() {
            let viewer = left.file_name().to_string_lossy().starts_with(".view.");
            if viewer && fuxix::open_fifo(left.path().join("ctl")).is_err() {
                let _ = fs::remove_dir_all(left.path());
            }
        }
        Ok(Self {
            exe,
            dir,
            max,
            shell,
            starting: tokio::sync::Mutex::new(()),
            streams: Mutex::new(HashMap::new()),
            streamed: AtomicU64::new(0),
        })
    }

    /// Where the sessions are: `koh fux view` of it, on the server, shows each as a tab.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn streams(&self) -> MutexGuard<'_, HashMap<(Run, u64), Stream>> {
        self.streams.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn named(&self, name: &str) -> Result<(PathBuf, Run)> {
        named_in(&self.dir, name, false, format!("no session {name}"))
    }

    /// `koh sessions`: every session as its folder says it is, the oldest first, and whether
    /// a client has a stream of it.
    pub async fn list(&self) -> Result<Vec<SessionInfo>> {
        let panes = panes_in(&self.dir).into_iter().filter_map(|(dir, pane)| {
            let (run, written) = pane?;
            let attached = self.streams().keys().any(|(streamed, _)| *streamed == run);
            Some((written, dir, attached))
        });
        let mut panes: Vec<_> = panes.collect();
        panes.sort();
        let info = |(_, dir, attached): (SystemTime, PathBuf, _)| info(&dir, attached);
        pooled(move || panes.into_iter().map(info).collect()).await
    }

    /// `koh output`: what the session `name` shows, or with `last` what its last command
    /// printed.
    pub async fn output(&self, name: &str, last: bool) -> Result<Vec<u8>> {
        let (dir, _) = self.named(name)?;
        pooled(move || text(&dir, last)).await
    }

    /// `koh wait --session`: until a command of the session's shell has ended since this was
    /// asked (`Ok` is sent once its marks were read), the session has ended, or `seconds` have
    /// gone by; answered with how it ended and, in pieces, with what the first such command
    /// printed, or what the session shows. It is the run that was asked about that is waited
    /// for. A client that has left is waited for no longer: that is seen between two looks.
    pub async fn wait(
        &self,
        name: &str,
        seconds: Option<u64>,
        send: &mut SendStream,
    ) -> Result<()> {
        let (dir, run) = self.named(name)?;
        let read = dir.clone();
        // No number to count from: an older holder's pane, or one whose two files were not
        // read as of one round. No wait is taken for either.
        let numbered = move || pane::together(&read, lives, || Marks::read(&read, None).asked());
        let (asked, whole) = pooled(numbered).await?;
        let Some(asked) = asked.filter(|_| whole) else {
            let older = "is kept by a holder of before fux 0.43.2, which does not number its marks (it has no `marks.dropped`): a wait cannot tell its commands' ends. End that session and start it anew";
            let moving =
                "is written without a pause: its marks were not read as of one moment. Ask again";
            let why = if whole { older } else { moving };
            return Err(KohError::failed(format!("the session {name} {why}")));
        };
        send_msg(send, &Reply::Ok, MAX_CTRL).await?;
        // (More seconds than the clock has are no limit, as for a job: `after`.)
        let until = seconds.map(|s| after(Timer::now(), Duration::from_secs(s)));
        let (exit, detail, text) = loop {
            let look = dir.clone();
            if let Some(ended) = pooled(move || looked(&look, run, asked)).await? {
                break ended;
            }
            if until.is_some_and(|until| Timer::now() >= until) {
                let shown = dir.clone();
                let ours = move || (run_of(&shown) == Some(run)).then(|| screen(&shown));
                let shown = pooled(ours).await?.unwrap_or_default();
                break (i32::from(Exit::TIMEOUT.0), "timed out".into(), shown);
            }
            tokio::select! {
                _ = send.stopped() => return Ok(()),
                () = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        };
        let waited = WaitResult {
            exit,
            tail: String::new(),
            detail,
        };
        send_msg(send, &waited, MAX_CTRL).await?;
        send_pieces(send, &text).await
    }

    /// The folder of the session that is asked for, found or started. With a name, the session
    /// of that name, started if there is none. With none, the newest that lives; or a new
    /// one, always if `new` or a program was given. A new one is one more folder: with `max`
    /// there, the oldest that has ended and has no client goes for it, once it has started.
    async fn find(&self, asked: &Attach, cwd: &Path) -> Result<PathBuf> {
        let one = self.starting.lock().await;
        let folders = panes_in(&self.dir);
        let wanted = asked.name.as_ref().map(|name| self.dir.join(name));
        let newest = || {
            let living = folders.iter().filter(|(dir, _)| lives(dir));
            let panes = living.filter_map(|(dir, pane)| Some((pane.as_ref()?.1, dir)));
            panes.max().map(|(_, dir)| dir.clone())
        };
        let found = match &wanted {
            Some(dir) => run_of(dir).map(|_| dir.clone()),
            None if asked.new || !asked.argv.is_empty() => None,
            None => newest(),
        };
        if let Some(found) = found {
            self.told(asked);
            return Ok(found);
        }
        let goes = if folders.len() >= self.max {
            let ended = |(dir, pane): &(PathBuf, Option<(Run, SystemTime)>)| {
                let (run, written) = (*pane)?;
                let streamed = self.streams().keys().any(|(streamed, _)| *streamed == run);
                (!lives(dir) && !streamed).then(|| (written, dir.clone()))
            };
            let oldest = folders.iter().filter_map(ended).min();
            let (_, oldest) = oldest.ok_or_else(|| {
                let most = self.max;
                let why = format!(
                    "server busy: it keeps at most {most} sessions (--max-sessions), and all are running or attached"
                );
                KohError::new(Exit::BUSY, why)
            })?;
            Some(oldest)
        } else {
            None
        };
        self.told(asked);
        let argv = if asked.argv.is_empty() {
            std::slice::from_ref(&self.shell)
        } else {
            &asked.argv
        };
        let size = [
            ("COLUMNS", asked.size.cols.clamp(1, 500).to_string()),
            ("LINES", asked.size.rows.clamp(1, 500).to_string()),
        ];
        let name = asked.name.as_deref().unwrap_or("");
        let started = start(&self.exe, &self.dir, name, false, argv, &size, cwd).await?;
        // (Only now that the new one runs does the old one go; and what it held is removed
        // with nothing held, where no other request waits for it: the next start does not
        // either, for the folder has no session's name any more.)
        if let Some(gone) = goes.and_then(|gone| self.goes(&gone)) {
            drop(one);
            let _ = pooled(move || drop(gone)).await;
        }
        Ok(started)
    }

    /// A client's seat on a session: its place among the streams of the folder's run, which is
    /// the run it named if it named one. The place is taken under the lock `goes` looks under:
    /// so a folder is not removed for a new session once a client has its place on it, and a
    /// client whose folder went before that has no seat and no answer.
    fn seat(&self, dir: &Path, named: Option<Run>, client: u64) -> Option<Seat<'_>> {
        let mut streams = self.streams();
        let run = run_of(dir).filter(|run| named.is_none_or(|named| named == *run))?;
        let number = self.streamed.fetch_add(1, Ordering::Relaxed);
        let (stop, stopped) = watch::channel(false);
        let place = Place(self, (run, client), number);
        let older = streams.insert(place.1, (number, stop));
        Some((place, older, stopped, run))
    }

    /// Removes an ended session's folder for a new one, unless a client has come to it since
    /// it was chosen (one that comes again does not wait for a start): then the folder stays,
    /// and there is one session more than the cap until a later start finds it without a
    /// client. Looked at and given another name under the streams' lock, which a client takes
    /// its place under before it opens anything (`seat`): it has its place before this looks,
    /// or finds no folder. What the folder held is removed when what this gives is let go: the
    /// lock is not held during removal.
    fn goes(&self, dir: &Path) -> Option<Aside> {
        let streams = self.streams();
        let streamed = run_of(dir).is_some_and(|run| streams.keys().any(|(had, _)| *had == run));
        if streamed { None } else { Aside::of(dir) }
    }

    /// What a client says its terminal is like goes where fux's viewer would have written it:
    /// into koh's own fux session, where its panes' holders read it and answer their programs
    /// from it: once this attach will be shown a session, and no sooner (one that is refused
    /// changes nothing), and before a new session's program is started.
    /// `keyboard` always, `colours` if the terminal told of any. Each under a name of
    /// the writer's own and then given its name, as fux's viewer writes them: of two at once the
    /// last is believed and neither fails.
    fn told(&self, asked: &Attach) {
        let Some(session) = self.dir.parent() else {
            return;
        };
        let number = self.streamed.fetch_add(1, Ordering::Relaxed);
        let keyboard = format!("{}\n", asked.keyboard);
        let files = [("colours", &asked.colours), ("keyboard", &keyboard)];
        for (name, text) in files.into_iter().filter(|(_, text)| !text.is_empty()) {
            let own = session.join(format!(".{name}.{}.{number}", std::process::id()));
            let written = fux::write_new(&own, text.as_bytes());
            if written
                .and_then(|()| fs::rename(&own, session.join(name)))
                .is_err()
            {
                let _ = fs::remove_file(&own);
            }
        }
    }

    /// Serves one attach, from the request to the stream's end. Checked before anything is
    /// made: the name, what the client says of its terminal, then the run a client that comes
    /// again names. What is wrong before the answer is the caller's to say; after `Ok` the
    /// stream is this one's: what the session's viewer draws, and at the end `Exit` if the
    /// session ended or its user left it. A stream that ends without that word was cut.
    pub async fn attach(
        &self,
        asked: Attach,
        cwd: &Path,
        send: &mut SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        if !asked.name.as_deref().is_none_or(session_name) {
            return Err(KohError::usage(
                "a session's name is letters, digits, '.', '_' and '-', at most 64, not starting with a dot, and none of fux's own: -, colours, keyboard, layout",
            ));
        }
        // (`TERM` is for the viewer's environment, and the colours are lines of fux's `colours`
        // file: the three a client asks its terminal for, and nothing else.)
        let colour = |line: &str| {
            let hex = |hex: &str| hex.len() == 6 && hex.bytes().all(|b| b.is_ascii_hexdigit());
            matches!(line.split_once(" #"), Some(("foreground" | "background" | "cursor", value)) if hex(value))
        };
        let term = asked.term.len() <= 64 && asked.term.bytes().all(|b| b.is_ascii_graphic());
        let colours = asked.colours.split_terminator('\n');
        if !term || colours.clone().count() > 3 || !colours.clone().all(colour) {
            return Err(KohError::usage(
                "what a client says of its terminal is its TERM (printable, at most 64 bytes) and its foreground, background and cursor colours",
            ));
        }
        let dir = match (&asked.run, &asked.name) {
            (Some(run), Some(name)) => {
                let dir = self.dir.join(name);
                match run_of(&dir) {
                    Some(there) if there == *run => {
                        self.told(&asked);
                        dir
                    }
                    Some(_) => {
                        let why = "another run has the session's name";
                        return Err(not_found(format!("{why} {name}: nothing is typed into it")));
                    }
                    None => return Err(not_found(format!("no session {name}"))),
                }
            }
            (Some(_), None) => return Err(KohError::usage("a run of no session")),
            (None, _) => self.find(&asked, cwd).await?,
        };
        let seat = self.seat(&dir, asked.run, asked.client);
        let (_place, older, mut stopped, run) =
            seat.ok_or_else(|| not_found(format!("the session at {} is gone", dir.display())))?;
        // This client's older stream on the run ends first, and its viewer has left before
        // this one's starts: what it still held is not typed after what this one brings.
        if let Some((_, older)) = older {
            let _ = older.send(true);
            older.closed().await;
        }
        // The viewer: this binary on a pty of the client's size, with the client's `TERM`, told
        // the keyboard's flags its terminal takes. It has no keys: every key that reaches it
        // is the session's (koh's own key is the client's). It leads a session of its own, and the pty
        // is not its controlling terminal: when the pty's other end closes it is not hung up
        // but reads the end, and leaves as a viewer leaves (a key that is down is let go in
        // the session, its folder goes).
        let (master, slave) = fuxix::pty(asked.size.tty()).map_err(io_error)?;
        // (The pty's end here is read and written as it is ready, as a pipe's is: tokio's two
        // ends of one take any descriptor that does not wait.)
        let reads = master
            .try_clone()
            .and_then(pipe::Receiver::from_file_unchecked);
        let writes = master
            .try_clone()
            .and_then(pipe::Sender::from_file_unchecked);
        let (mut reads, mut writes) = (reads.map_err(io_error)?, writes.map_err(io_error)?);
        let end = || slave.try_clone().map(Stdio::from).map_err(io_error);
        let mut viewer = std::process::Command::new(&self.exe);
        viewer
            .arg("view-session")
            .arg(&dir)
            .arg(asked.keyboard.to_string())
            .stdin(end()?)
            .stdout(end()?)
            .stderr(end()?);
        if !asked.term.is_empty() {
            viewer.env("TERM", &asked.term);
        }
        fuxix::new_session(&mut viewer, false);
        // (Its folder in the session, which a viewer that is killed does not remove: named
        // before the viewer, so that whatever ends this, the viewer goes first and its folder
        // after it.)
        let _folder;
        let mut viewer = tokio::process::Command::from(viewer)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| KohError::failed(format!("cannot run {}: {e}", self.exe.display())))?;
        // (The viewer's end of the pty is kept open here too, to see what the viewer has not
        // read of it. So the pty does not say when the viewer has left: the viewer does.)
        let session = self.dir.parent().zip(viewer.id());
        _folder = session.map(|(session, id)| Folder(session.join(format!(".view.{id}"))));
        let name = dir.file_name().unwrap_or_default().to_string_lossy();
        send_msg(send, &Reply::Ok, MAX_CTRL).await?;
        let attached = Attached {
            name: name.into_owned(),
            run,
        };
        send_msg(send, &attached, MAX_CTRL).await?;
        // What the viewer draws is sent as the link takes it, and what the client types is
        // written as the viewer takes it: each waits for its own end alone, so a key is not
        // held behind a screen's piece, nor a screen behind a paste.
        let unread = send.stopped();
        let drawn = async {
            let mut piece = vec![0; 8 << 10];
            loop {
                // (Once the viewer has left, what it drew last is all there to be read.)
                let read = tokio::select! {
                    biased;
                    read = reads.read(&mut piece) => read,
                    _ = viewer.wait() => reads.try_read(&mut piece),
                };
                let Ok(n @ 1..) = read else {
                    break;
                };
                let bytes = piece.get(..n).unwrap_or_default().to_vec();
                send_msg(send, &ViewOutput::Bytes(bytes), VIEW_FRAME).await?;
            }
            Ok::<_, KohError>(())
        };
        let typed = async {
            loop {
                let taken = match recv_msg(&mut recv, VIEW_FRAME).await {
                    Ok(ViewInput::Bytes(bytes)) => writes.write_all(&bytes).await,
                    Ok(ViewInput::Resize(size)) => fuxix::set_winsize(&master, size.tty()),
                    // The stream's end; or a message no client of this sends.
                    Err(_) => break,
                };
                if taken.is_err() {
                    break;
                }
            }
        };
        let left = tokio::select! {
            biased;
            drawn = drawn => drawn.is_ok(),
            // (All the client typed is typed: this side of the stream ends with it, which a
            // client that leaves waits for before it lets its connection go.)
            () = typed => {
                let _ = send.finish();
                false
            }
            // A newer attach of this client to the run: this one writes no more.
            _ = stopped.changed() => false,
            // A client that reads its stream no further: nothing is drawn for it.
            _ = unread => false,
        };
        // What was typed is the viewer's to read before its terminal goes: a pty that is closed
        // drops what its other end has not read, and a client that leaves has typed what it
        // typed. A second for it: a viewer that reads nothing holds nothing up for longer.
        // (While the viewer lives: one that has left reads no more.)
        let unread = || fuxix::wait([(Some(slave.as_fd()), fuxix::POLLIN)], 0);
        let read = async {
            while matches!(viewer.try_wait(), Ok(None)) && unread().is_ok_and(|[typed]| typed != 0)
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(1), read).await;
        // The viewer leaves by itself: its pane ended and it drew the last screen, its user
        // left it, or its terminal is gone now. One that has not in a second is killed, and
        // waited for: it is gone when this is over.
        drop((master, reads, writes, slave));
        let gone = tokio::time::timeout(Duration::from_secs(1), viewer.wait()).await;
        if gone.is_err() {
            let _ = viewer.kill().await;
        }
        // The last word, where the viewer left of itself: how the session ended, or 0 if it
        // runs on and the viewer was told to leave. (One that failed says nothing: the client
        // comes again.)
        if let (true, Ok(Ok(status))) = (left, gone) {
            let code = ended(&dir, run)
                .map(|r| r.ok().and_then(|s| pane::code(&s)).unwrap_or(1))
                .or(status.success().then_some(0));
            if let Some(code) = code {
                send_msg(send, &ViewOutput::Exit(code), VIEW_FRAME).await?;
            }
        }
        Ok(())
    }
}

/// Every valid pane-named folder in `root`, and its `(run, status mtime)` if initialized.
pub(crate) fn panes_in(root: &Path) -> Vec<(PathBuf, Option<(Run, SystemTime)>)> {
    fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name().to_str().is_some_and(session_name)
                && e.file_type().is_ok_and(|k| k.is_dir())
        })
        .map(|e| {
            let dir = e.path();
            let written = fs::metadata(dir.join("status"))
                .and_then(|s| s.modified())
                .ok();
            (dir.clone(), run_of(&dir).zip(written))
        })
        .collect()
}

/// Starts a pane (`koh fux start [--out] WORKSPACE/NAME -- PROGRAM`) in `cwd` with `env`.
pub(crate) async fn start(
    exe: &Path,
    workspace: &Path,
    name: &str,
    out: bool,
    argv: &[String],
    env: &[(&str, String)],
    cwd: &Path,
) -> Result<PathBuf> {
    let said = tokio::process::Command::new(exe)
        .args(["fux", "start"])
        .args(out.then_some("--out"))
        .arg(workspace.join(name))
        .arg("--")
        .args(argv)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| {
            KohError::new(
                Exit::CANNOT_START,
                format!("cannot run {}: {e}", exe.display()),
            )
        })?;
    if !said.status.success() {
        let why = String::from_utf8_lossy(&said.stderr);
        let why = why.trim().trim_start_matches("fux: ");
        if let Some((f, _)) = why.split_once(": cannot start ")
            && Path::new(f).parent() == Some(workspace)
        {
            let _ = fs::remove_dir_all(f);
        }
        let code = if out && why.ends_with("(os error 2)") {
            Exit::NOT_FOUND
        } else {
            Exit::CANNOT_START
        };
        return Err(KohError::new(code, format!("nothing was started: {why}")));
    }
    let dir = PathBuf::from(String::from_utf8_lossy(&said.stdout).trim_end());
    (dir.parent() == Some(workspace))
        .then_some(dir.clone())
        .ok_or_else(|| KohError::new(Exit::CANNOT_START, format!("no pane at {}", dir.display())))
}

fn io_error(e: std::io::Error) -> KohError {
    KohError::failed(format!("a viewer's terminal: {e}"))
}

/// A viewer's folder in the session, removed with the attach: a viewer that left removed it.
struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A stream's place among those of its run: given up when the stream ends, unless a newer one
/// of the same client has it by then.
struct Place<'a>(&'a Sessions, (Run, u64), u64);

/// What an attach has once it is seated: its place, this client's older stream on the run if
/// there is one, what tells this stream to stop, and the run.
type Seat<'a> = (Place<'a>, Option<Stream>, watch::Receiver<bool>, Run);

impl Drop for Place<'_> {
    fn drop(&mut self) {
        let mut streams = self.0.streams();
        if streams
            .get(&self.1)
            .is_some_and(|(number, _)| *number == self.2)
        {
            streams.remove(&self.1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder as a pane's is, as far as its run goes: the run `run`.
    fn pane(dir: &Path, run: Run) {
        fs::create_dir(dir).unwrap();
        fs::write(dir.join("run"), format!("{run:032x}\n")).unwrap();
        fs::write(dir.join("status"), "holder 1\npid 1\n").unwrap();
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("koh-session-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn lock(dir: &Path) -> fs::File {
        let held = fuxix::open(dir, false).unwrap();
        held.try_lock().unwrap();
        held
    }

    #[test]
    fn a_wait_is_for_the_run_it_was_asked_about() {
        let tmp = scratch("looked");
        let (dir, aside) = (tmp.join("s"), tmp.join("aside"));
        // A session that runs (the test holds its lock), and has marked no command.
        pane(&dir, 7);
        let holder = lock(&dir);
        fs::write(dir.join("marks.dropped"), "0\n").unwrap();
        let asked = Marks::read(&dir, None).asked().unwrap();
        assert_eq!((asked, looked(&dir, 7, asked)), (0, None));
        // Between two looks it ends, and another run has its name, whose shell has marked a
        // command's end with 7: that is not what was waited for. The session has ended.
        drop(holder);
        fs::rename(&dir, &aside).unwrap();
        pane(&dir, 8);
        let _holder = lock(&dir);
        fs::write(dir.join("marks.dropped"), "0\n").unwrap();
        fs::write(dir.join("marks"), "0 0 output\n1 0 end 7\n").unwrap();
        let ended = Some((1, "ended".to_string(), Vec::new()));
        assert_eq!(looked(&dir, 7, asked), ended);
        // The folder gone is the same; and the run itself, ended, says how.
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(looked(&dir, 7, asked), ended);
        fs::rename(&aside, &dir).unwrap();
        fs::write(dir.join("state"), "exited 3\n").unwrap();
        assert_eq!(
            looked(&dir, 7, asked),
            Some((3, "exited 3".to_string(), Vec::new()))
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn a_session_ends_as_its_state_says_and_with_1_where_nothing_says() {
        let tmp = scratch("ended");
        let dir = tmp.join("s");
        pane(&dir, 7);
        // It runs while its holder lives; what `state` says then is how it ended.
        let holder = lock(&dir);
        fs::write(dir.join("state"), "running\n").unwrap();
        assert_eq!(ended(&dir, 7), None);
        fs::write(dir.join("state"), "killed 9\n").unwrap();
        assert_eq!(ended(&dir, 7), Some(Ok("killed 9".into())));
        // A holder that is gone and said nothing: "ended". Another run under the name, or none: Err.
        drop(holder);
        fs::write(dir.join("state"), "running\n").unwrap();
        assert_eq!(ended(&dir, 7), Some(Ok("ended".into())));
        assert_eq!(
            (ended(&dir, 8), ended(&tmp.join("none"), 7)),
            (Some(Err(())), Some(Err(())))
        );
        // Lock must be probed BEFORE reading `state`: if the holder publishes `exited 0` and
        // unlocks right as we probe, `state_now` must read `exited 0`, never `ended`.
        let d = dir.clone();
        assert_eq!(
            state_now(&dir, move |_| {
                fs::write(d.join("state"), "exited 0\n").unwrap();
                false
            }),
            "exited 0"
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn marks_that_came_and_went_unread_are_said_with_the_oldest_end_still_kept() {
        let tmp = scratch("unread");
        let dir = tmp.join("s");
        pane(&dir, 7);
        // The last `end` was number 6 when the wait was asked. By its next look 1,200 marks
        // have come, and the file has dropped 206: those up to 206 went unread, an `end` or
        // more among them. The oldest it lists is given, with that said; never as the first.
        let command = |n: usize| format!("{n} 0 output\n{n} 9 end {}\n", n % 100);
        fs::write(
            dir.join("marks"),
            (50..550).map(command).collect::<String>(),
        )
        .unwrap();
        fs::write(dir.join("marks.dropped"), "206\n").unwrap();
        let (code, said, _) = looked(&dir, 7, 6).unwrap();
        let unread =
            "the oldest still kept, not known to be the first (200 marks came and went unread)";
        assert_eq!(
            (code, said),
            (50, format!("command ended (OSC 133): {unread}"))
        );
        // With the last `end` still listed nothing went unread, and the first is the first.
        let (code, said, _) = looked(&dir, 7, 208).unwrap();
        assert_eq!((code, said.as_str()), (51, "command ended (OSC 133)"));
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn a_session_a_client_has_a_seat_on_does_not_go_and_one_that_went_has_no_seat() {
        let tmp = scratch("goes");
        let sessions = Sessions::new(&tmp, 2, "sh".into(), PathBuf::new()).unwrap();
        let dir = sessions.dir().join("1");
        pane(&dir, 7);
        // Chosen to go for a new one, with no client; one came before it went: it stays. A
        // client that names another run than the folder's has no seat on it.
        let seat = sessions.seat(&dir, Some(7), 1);
        assert!(seat.is_some() && sessions.seat(&dir, Some(8), 2).is_none());
        assert!(sessions.goes(&dir).is_none() && dir.is_dir());
        // With no client it goes: under the lock it is given a name that is no session's, whole,
        // and it is removed by whoever lets go of what `goes` gave.
        drop(seat);
        let gone = sessions.goes(&dir);
        let names = || {
            let entries = fs::read_dir(sessions.dir()).unwrap();
            let names = entries.map(|entry| entry.unwrap().file_name().into_string().unwrap());
            names.collect::<Vec<_>>()
        };
        let aside = names();
        assert!(!dir.exists() && panes_in(sessions.dir()).is_empty());
        assert!(
            matches!(aside.as_slice(), [name] if name.starts_with('.')
                && sessions.dir().join(name).join("status").is_file()),
            "{aside:?}"
        );
        drop(gone);
        assert_eq!(names(), [""; 0]);
        assert!(sessions.seat(&dir, Some(7), 1).is_none() && sessions.streams().is_empty());
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn a_server_that_starts_removes_the_folders_of_viewers_that_are_gone() {
        let tmp = scratch("sweep");
        let session = tmp.join("fux");
        let (dead, living) = (session.join(".view.11"), session.join(".view.12"));
        for viewer in [&dead, &living] {
            fs::create_dir_all(viewer.join("3")).unwrap();
        }
        // A viewer that lives reads its FIFO; one that was killed left the folder and the FIFO.
        drop(fuxix::fifo(dead.join("ctl")).unwrap());
        let _reads = fuxix::fifo(living.join("ctl")).unwrap();
        fs::create_dir_all(session.join("koh-sessions/kept")).unwrap();
        Sessions::new(&tmp, 2, "sh".into(), PathBuf::new()).unwrap();
        assert!(!dead.exists() && living.join("3").is_dir());
        assert!(session.join("koh-sessions/kept").is_dir());
        let _ = fs::remove_dir_all(tmp);
    }
}
