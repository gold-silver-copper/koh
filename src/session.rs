//! The server's side of a session. A session is a fux pane in a fux session of koh's own
//! (`STATE/fux/koh-sessions/NAME`), kept by fux's holder, which is this binary run as
//! `koh hold`: no child of `koh serve`, and alive without it. Here one is found or started,
//! known by its run, and carried to each attached client as rounds of its folder
//! (`carry::Reader`) against what that client types. `koh serve` keeps no table of sessions:
//! the folders are the sessions. It keeps which stream each attached client has on a run.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, DirBuilder, File, TryLockError};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use iroh::endpoint::{RecvStream, SendStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::carry::{Look, Reader};
use crate::pane::{self, Marks};
use crate::proto::{
    Attach, Attached, FromMirror, Had, MAX_CHUNK, MAX_CTRL, MAX_HELD, MAX_TYPED, Reply, Run,
    SessionInfo, ToMirror, WaitResult, send_msg, send_pieces, session_name, spawn_msg_reader,
};
use crate::{Exit, KohError, Result};

/// The most bytes a FIFO is given in one write: no other writer's bytes come between them.
const PIECE: usize = 512;

/// A stream of a client on a run: its number among this server's streams, and what ends it.
/// (Whoever ends it sends, and then waits until the receiver is dropped: it writes no more.)
type Stream = (u64, watch::Sender<bool>);

pub struct Sessions {
    /// `STATE/fux/koh-sessions`, by its whole path: a workspace of a fux session of koh's own.
    dir: PathBuf,
    /// Most folders kept there at once.
    max: usize,
    shell: String,
    /// One at a time finds or starts a session: the folders are counted under this.
    starting: tokio::sync::Mutex<()>,
    streams: Mutex<HashMap<(Run, u64), Stream>>,
    streamed: AtomicU64,
}

/// Which run a folder is, if it is a pane's: the folder, and the holder its `status` names
/// first. (fux writes `status` twice at a start; that line is the same both times.)
fn run_of(dir: &Path) -> Option<Run> {
    let folder = fs::metadata(dir).ok()?;
    let mut status = String::new();
    let file = fuxix::open_regular(dir.join("status")).ok()?;
    file.take(64 << 10).read_to_string(&mut status).ok()?;
    let holder = status.lines().next()?.strip_prefix("holder ")?;
    Some(Run {
        device: folder.dev(),
        folder: folder.ino(),
        holder: holder.trim().parse().ok()?,
    })
}

/// Whether a holder keeps the folder: its lock is held. Asked only of a folder that has a
/// `status`: `fux start` makes a folder before it locks it, and a lock asked in that moment
/// would fail that start.
fn lives(dir: &Path) -> bool {
    let asked = fuxix::open(dir, false).map(|folder| folder.try_lock_shared());
    matches!(asked, Ok(Err(TryLockError::WouldBlock)))
}

/// What tells one writing of a folder's `generation` from the next.
fn number_of(dir: &Path) -> fux::Stamp {
    fs::metadata(dir.join("generation")).ok().map(fux::stamp)
}

/// The two FIFOs of a session's folder, `in` and `ctl`, and the run they are of: the run a
/// client named, or with none the folder's. They are opened as fux's viewer opens them (no
/// link is followed; a FIFO or nothing) and held from then on: typed bytes go into these two,
/// whatever has their names later. The folder is that run after they were opened, or there
/// is no answer: a name that another run took meanwhile gets nothing typed into it.
fn held(dir: &Path, named: Option<Run>) -> Option<(Run, [Option<File>; 2])> {
    let run = named.or_else(|| run_of(dir))?;
    let fifos = ["in", "ctl"].map(|name| fuxix::open_fifo(dir.join(name)).ok());
    (run_of(dir) == Some(run)).then_some((run, fifos))
}

fn not_found(what: String) -> KohError {
    KohError::new(Exit::NOT_FOUND, "not_found", what)
}

/// What `state` says became of a session's program. It runs only while a holder lives:
/// where none does and the file says nothing else, nothing says how it ended.
fn state_of(said: Option<String>, alive: bool) -> String {
    match said {
        Some(state) if state != "running" => state,
        _ if alive => "running".into(),
        _ => "ended".into(),
    }
}

/// A session as its folder says it is, read of one round of its holder's writing.
fn info(dir: &Path, written: SystemTime, attached: bool) -> SessionInfo {
    let (alive, state, size, title, marks) = pane::together(dir, lives, || {
        let line = |name| pane::line(dir, name);
        let size = line("size").unwrap_or_default();
        (
            lives(dir),
            line("state"),
            size,
            line("title"),
            Marks::read(dir),
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
        running_command: alive && marks.busy(),
        last_exit: marks.command(usize::MAX).0,
        age_secs: written.elapsed().map_or(0, |age| age.as_secs()),
        pane_dir: dir.display().to_string(),
    }
}

/// What a session shows; or with `last` what its last command printed, which is what it
/// shows where its shell has marked no command that ended.
fn text(dir: &Path, last: bool) -> Vec<u8> {
    let printed = last.then(|| pane::together(dir, lives, || pane::last(dir)));
    printed.flatten().unwrap_or_else(|| screen(dir))
}

/// The screen a session shows.
fn screen(dir: &Path) -> Vec<u8> {
    pane::read(dir, "shown/screen").unwrap_or_default()
}

/// What a wait finds when it looks: nothing while the session runs on and no command of its
/// shell has ended since `was` was read; else the exit code, how it ended, and the text. The
/// first command that ended, its code and what it printed read as one; or, of a session that
/// ended, what `state` says and its last screen. A folder that is gone or another run's by
/// then has ended, and nothing of it is given.
fn looked(dir: &Path, run: Run, was: &Marks) -> Option<(i32, String, Vec<u8>)> {
    // (The marks alone first, a file: the pane's text is read only once they say so.)
    let ended = was.first_since(&Marks::read(dir)).is_some();
    let ended = ended.then(|| pane::together(dir, lives, || pane::ended_since(was, dir)));
    let (ended, alive) = (ended.flatten(), lives(dir));
    if run_of(dir) != Some(run) {
        return Some((1, "ended".into(), Vec::new()));
    }
    if let Some((code, printed)) = ended {
        let said = "command ended (OSC 133)".to_string();
        let printed = printed.unwrap_or_else(|| screen(dir));
        return Some((code.map_or(0, i32::from), said, printed));
    }
    let state = (!alive).then(|| state_of(pane::line(dir, "state"), false))?;
    Some((pane::code(&state).unwrap_or(1), state, screen(dir)))
}

/// File work of the three commands, on the blocking pool: it reads megabytes of history, and
/// waits where a holder is writing.
async fn pooled<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    let read = tokio::task::spawn_blocking(work).await;
    read.map_err(|e| KohError::internal(format!("reading a session: {e}")))
}

/// What the blocking pool read of a pane's folder for a stream.
enum Read {
    /// The client's list, whether it was read while the folder stood still, and whether a
    /// holder lived just before.
    Listed(Vec<Had>, bool, bool),
    /// A look, whether a holder lived just before it, the run the folder was just after, and
    /// what the folder's number was when the look began.
    Looked(Look, bool, Option<Run>, fux::Stamp),
}

/// The work a stream has on the blocking pool, once it is done: none while there is none.
async fn done(work: &mut Option<JoinHandle<(Reader, Option<Read>)>>) -> Option<(Reader, Read)> {
    let Some(running) = work else {
        return std::future::pending().await;
    };
    let read = running.await.ok();
    *work = None;
    read.and_then(|(reader, read)| Some((reader, read?)))
}

impl Sessions {
    /// The sessions kept beneath the state directory `state`, `max` of them at most, each a new
    /// one running `shell` unless its client names a program.
    pub fn new(state: &Path, max: usize, shell: String) -> Result<Self> {
        let dir = state.join("fux").join("koh-sessions");
        // (What is made is the owner's alone; what is there is taken as it is. Its whole path,
        // as fux prints a pane's.)
        let made = DirBuilder::new().mode(0o700).recursive(true).create(&dir);
        let dir = made
            .and_then(|()| fs::canonicalize(&dir))
            .map_err(|e| KohError::failed(format!("{}: {e}", dir.display())))?;
        Ok(Self {
            dir,
            max,
            shell,
            starting: tokio::sync::Mutex::new(()),
            streams: Mutex::new(HashMap::new()),
            streamed: AtomicU64::new(0),
        })
    }

    /// Where the sessions are: `koh fux view` of it shows each as a tab.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn streams(&self) -> MutexGuard<'_, HashMap<(Run, u64), Stream>> {
        self.streams.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every folder that counts as a session, and of one that is a pane its run and when its
    /// `status` was written: by that time one is newer than another.
    fn folders(&self) -> Vec<(PathBuf, Option<(Run, SystemTime)>)> {
        let entries = fs::read_dir(&self.dir).into_iter().flatten().flatten();
        let folders = entries.filter(|entry| {
            let name = entry.file_name();
            name.to_str().is_some_and(session_name)
                && entry.file_type().is_ok_and(|kind| kind.is_dir())
        });
        let pane = |dir: &PathBuf| {
            let written = fs::metadata(dir.join("status")).and_then(|status| status.modified());
            Some((run_of(dir)?, written.ok()?))
        };
        folders
            .map(|entry| entry.path())
            .map(|dir| (pane(&dir), dir))
            .map(|(pane, dir)| (dir, pane))
            .collect()
    }

    /// The folder of the session `name` and its run: a pane's, or there is no such session.
    /// (A name that is none is no path.)
    fn named(&self, name: &str) -> Result<(PathBuf, Run)> {
        let dir = session_name(name).then(|| self.dir.join(name));
        let pane = dir.and_then(|dir| Some((run_of(&dir)?, dir)));
        let pane = pane.map(|(run, dir)| (dir, run));
        pane.ok_or_else(|| not_found(format!("no session {name}")))
    }

    /// `koh sessions`: every session as its folder says it is, the oldest first, and whether
    /// a client has a stream of it.
    pub async fn list(&self) -> Result<Vec<SessionInfo>> {
        let panes = self.folders().into_iter().filter_map(|(dir, pane)| {
            let (run, written) = pane?;
            let attached = self.streams().keys().any(|(streamed, _)| *streamed == run);
            Some((written, dir, attached))
        });
        let mut panes: Vec<_> = panes.collect();
        panes.sort();
        let info = |(written, dir, attached): (_, PathBuf, _)| info(&dir, written, attached);
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
        let was = Arc::new(pooled(move || Marks::read(&read)).await?);
        send_msg(send, &Reply::Ok, MAX_CTRL).await?;
        // (A time too far off for the clock is no time.)
        let until = seconds.and_then(|s| Instant::now().checked_add(Duration::from_secs(s)));
        let (timed_out, (exit, detail, text)) = loop {
            let (look, was) = (dir.clone(), was.clone());
            if let Some(ended) = pooled(move || looked(&look, run, &was)).await? {
                break (false, ended);
            }
            if until.is_some_and(|until| Instant::now() >= until) {
                let shown = dir.clone();
                let shown = pooled(move || screen(&shown)).await?;
                break (
                    true,
                    (i32::from(Exit::TIMEOUT.0), "timed out".into(), shown),
                );
            }
            tokio::select! {
                _ = send.stopped() => return Ok(()),
                () = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        };
        let waited = WaitResult {
            timed_out,
            exit,
            tail: String::new(),
            detail,
        };
        send_msg(send, &waited, MAX_CTRL).await?;
        send_pieces(send, &text).await
    }

    /// Starts a pane with this binary as fux, `koh fux start SESSIONS/NAME -- PROGRAM` (no
    /// name: fux's first free number), and gives the folder fux printed.
    async fn start(&self, asked: &Attach, cwd: &Path) -> Result<PathBuf> {
        let cannot = |why: String| KohError::new(Exit::CANNOT_START, "cannot_start", why);
        let me = std::env::current_exe().map_err(|e| cannot(format!("no path to koh: {e}")))?;
        let pane = self.dir.join(asked.name.as_deref().unwrap_or(""));
        let mut fux = tokio::process::Command::new(&me);
        fux.args(["fux", "start"]).arg(pane).arg("--");
        match asked.argv.is_empty() {
            true => fux.arg(&self.shell),
            false => fux.args(&asked.argv),
        };
        // (A size fux would refuse is the nearest it takes: a pane is 1 to 500 each way.)
        fux.env("COLUMNS", asked.cols.clamp(1, 500).to_string())
            .env("LINES", asked.rows.clamp(1, 500).to_string())
            .current_dir(cwd)
            .stdin(Stdio::null());
        let said = fux.output().await;
        let said = said.map_err(|e| cannot(format!("cannot run {}: {e}", me.display())))?;
        if !said.status.success() {
            let why = String::from_utf8_lossy(&said.stderr);
            let why = why.trim().trim_start_matches("fux: ");
            return Err(cannot(format!("no session was started: {why}")));
        }
        let dir = PathBuf::from(String::from_utf8_lossy(&said.stdout).trim_end());
        match dir.parent() == Some(&self.dir) {
            true => Ok(dir),
            false => Err(cannot(format!("no session at {}", dir.display()))),
        }
    }

    /// The folder of the session that is asked for, found or started. With a name, the session
    /// of that name, started if there is none. With none, the newest that lives; or a new
    /// one, always if `new` or a program was given. A new one is one more folder: with `max`
    /// there, the oldest that has ended and has no client goes for it, once it has started.
    async fn find(&self, asked: &Attach, cwd: &Path) -> Result<PathBuf> {
        let _one = self.starting.lock().await;
        let folders = self.folders();
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
                KohError::new(Exit::BUSY, "busy", why)
            })?;
            Some(oldest)
        } else {
            None
        };
        let started = self.start(asked, cwd).await?;
        // (Only now that the new one runs does the old one go.)
        if let Some(gone) = goes {
            self.goes(&gone);
        }
        Ok(started)
    }

    /// A client's seat on a session: its place among the streams of the folder's run, and
    /// then the run's two FIFOs (`held`), in that order. The place is taken under the lock
    /// `goes` looks under, before anything of the folder is opened: so a folder is not removed
    /// for a new session once a client has its place on it, and a client whose folder went
    /// before that has no FIFOs, no seat and no answer.
    fn seat(&self, dir: &Path, named: Option<Run>, client: u64) -> Option<Seat<'_>> {
        let run = named.or_else(|| run_of(dir))?;
        let number = self.streamed.fetch_add(1, Ordering::Relaxed);
        let (stop, stopped) = watch::channel(false);
        let place = Place(self, (run, client), number);
        let older = self.streams().insert(place.1, (number, stop));
        #[cfg(test)]
        tests::MIDWAY.take().into_iter().for_each(|midway| midway());
        let (run, fifos) = held(dir, Some(run))?;
        Some((place, older, stopped, run, fifos))
    }

    /// Removes an ended session's folder for a new one, unless a client has come to it since
    /// it was chosen (one that comes again does not wait for a start): then the folder stays,
    /// and there is one session more than the cap until a later start finds it without a
    /// client. Looked at and removed under the streams' lock, which a client takes its place
    /// under before it opens anything (`seat`): it has its place before this looks, or finds
    /// no folder.
    fn goes(&self, dir: &Path) {
        let streams = self.streams();
        let streamed = run_of(dir).is_some_and(|run| streams.keys().any(|(had, _)| *had == run));
        if !streamed {
            let _ = fs::remove_dir_all(dir);
        }
    }

    /// Serves one attach, from the request to the stream's end. Checked in this order before
    /// anything is made: the format, then the run a client that comes again names. What is
    /// wrong before the answer is the caller's to say; after `Ok` the stream is this one's.
    pub async fn attach(
        &self,
        asked: Attach,
        cwd: &Path,
        send: &mut SendStream,
        recv: RecvStream,
    ) -> Result<()> {
        let (ours, theirs) = (fux::FORMAT, asked.format);
        if theirs != ours {
            let older = if theirs < ours { "client" } else { "server" };
            return Err(KohError::failed(format!(
                "the server's sessions are of fux's format {ours} and the client reads format {theirs}: the {older}'s koh is the older one"
            )));
        }
        if !asked.name.as_deref().is_none_or(session_name) {
            return Err(KohError::usage(
                "a session's name is letters, digits, '.', '_' and '-', at most 64, not starting with a dot, and none of fux's own: -, colours, keyboard, layout",
            ));
        }
        let dir = match (&asked.run, &asked.name) {
            (Some(run), Some(name)) => {
                let dir = self.dir.join(name);
                match run_of(&dir) {
                    Some(there) if there == *run => dir,
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
        // The run is the one the client named, or with none the folder's as it is now; the
        // client takes its place on it, and the two FIFOs are that run's (`seat`).
        let gone = || match &asked.run {
            Some(_) => not_found(format!(
                "another run has the session's name {name}: nothing is typed into it",
                name = dir.file_name().unwrap_or_default().to_string_lossy()
            )),
            None => not_found(format!("the session at {} is gone", dir.display())),
        };
        let seat = self.seat(&dir, asked.run, asked.client);
        let (place, older, mut stopped, run, fifos) = seat.ok_or_else(gone)?;
        // This client's older stream on the run ends first, and has stopped writing before
        // this one is answered: what it still held for the FIFOs is not typed after what
        // this one brings.
        if let Some((_, older)) = older {
            let _ = older.send(true);
            older.closed().await;
        }
        let number = place.2;
        let name = dir.file_name().unwrap_or_default().to_string_lossy();
        send_msg(send, &Reply::Ok, MAX_CTRL).await?;
        let attached = Attached {
            name: name.into_owned(),
            run,
        };
        send_msg(send, &attached, MAX_CTRL).await?;
        self.stream(&dir, run, number, fifos, &mut stopped, send, recv)
            .await;
        drop(place);
        Ok(())
    }

    /// What a client says its terminal is like, into koh's own fux session, where its panes'
    /// holders read it: written under a name of the writer's own and then given its name, as
    /// fux's viewer writes them, so of two at once the last is believed and neither fails.
    fn told(&self, name: &str, bytes: &[u8], number: u64) {
        let Some(session) = self.dir.parent() else {
            return;
        };
        let own = session.join(format!(".{name}.{}.{number}", std::process::id()));
        let written = fux::write_new(&own, bytes);
        if written
            .and_then(|()| fs::rename(&own, session.join(name)))
            .is_err()
        {
            let _ = fs::remove_file(&own);
        }
    }

    /// One client's stream of a run, until the link, the run or the stream ends. Awaiting the
    /// client's list it sends nothing; then rounds, the first whatever it holds. With no
    /// holder left, or the folder gone or another run's, the last word is `Ended`.
    #[allow(clippy::too_many_arguments)]
    async fn stream(
        &self,
        dir: &Path,
        run: Run,
        number: u64,
        mut fifos: [Option<File>; 2],
        stopped: &mut watch::Receiver<bool>,
        send: &mut SendStream,
        recv: RecvStream,
    ) {
        let mut from = spawn_msg_reader::<FromMirror>(recv, MAX_CHUNK);
        // What is sent goes through one writer, a message at a time: while the link takes a
        // round, typed bytes are still read and written.
        let (out, mut queue) = mpsc::channel::<ToMirror>(1);
        // The writer is also where the stream's end is seen, whatever else waits: a client
        // that left while typed bytes wait for a program that does not read is gone, and
        // nothing of its stream is kept.
        let writer = async move {
            loop {
                let message = tokio::select! {
                    message = queue.recv() => message,
                    _ = send.stopped() => None,
                };
                let sent = match message {
                    Some(message) => send_msg(send, &message, MAX_CHUNK).await.is_ok(),
                    None => false,
                };
                if !sent {
                    break;
                }
            }
        };
        tokio::pin!(writer);
        // What each FIFO has not taken yet, and what of a round the writer has not.
        let mut waits: [VecDeque<u8>; 2] = [VecDeque::new(), VecDeque::new()];
        let mut round: VecDeque<ToMirror> = VecDeque::new();
        // The reader is here or with its work on the blocking pool. The client's list: said,
        // and then read while the folder stood still.
        let (mut reader, mut work) = (Some(Reader::new(dir)), None);
        let (mut list, mut listed, mut live, mut ending) = (None::<Vec<Had>>, false, false, false);
        // When the folder was looked at last and what its number was then; whether to look
        // whatever the number is; before when not to; and how many looks in a row moved.
        let began = Instant::now();
        let (mut looked, mut seen) = (began, None);
        let (mut again, mut rests, mut moved) = (true, began, 0u32);
        // When a key was last typed whose echo has not been read yet; and when anything happened.
        let (mut keyed, mut active) = (None::<Instant>, began);
        loop {
            let now = Instant::now();
            // What waits for a FIFO is written as the FIFO takes it. One whose reader is gone
            // takes nothing: what waited for it is dropped (the run's end is told below).
            for (fifo, waits) in fifos.iter_mut().zip(&mut waits) {
                while !waits.is_empty() {
                    let piece = waits.make_contiguous();
                    let piece = piece.get(..piece.len().min(PIECE)).unwrap_or_default();
                    match fifo.as_ref().map(|mut fifo| fifo.write(piece)) {
                        Some(Ok(n @ 1..)) => {
                            waits.drain(..n);
                            (keyed, active) = (Some(now), now);
                        }
                        Some(Err(e))
                            if matches!(
                                e.kind(),
                                ErrorKind::WouldBlock | ErrorKind::Interrupted
                            ) =>
                        {
                            break;
                        }
                        _ => {
                            *fifo = None;
                            waits.clear();
                        }
                    }
                }
            }
            if ending && round.is_empty() {
                break;
            }
            // A look: when the folder's number is another file than at the last, and now and
            // then whatever it is (`log` and `cwd` change without it; a holder ends without
            // it; the folder goes). Never while a round waits for the link, so the next read
            // is the newest; nor before a rest is over.
            if work.is_none() && round.is_empty() && !ending && now >= rests {
                let number = number_of(dir);
                let often = if active.elapsed() < Duration::from_millis(300) {
                    16
                } else {
                    250
                };
                // (Just after a key its echo is a millisecond or two away: the number is waited
                // for with the look, on the blocking pool, where a wait is that short.)
                let echo = keyed.map_or(Duration::ZERO, |keyed| {
                    Duration::from_millis(40).saturating_sub(keyed.elapsed())
                });
                let changed = again || number != seen;
                let due =
                    changed || !echo.is_zero() || looked.elapsed() >= Duration::from_millis(often);
                let dir = dir.to_path_buf();
                let asked = reader.take_if(|_| list.is_some()).zip(list.take());
                if let Some((mut reader, had)) = asked {
                    work = Some(tokio::task::spawn_blocking(move || {
                        let dead = !lives(&dir);
                        let listed = reader.has(&had, dead).ok();
                        (reader, listed.map(|listed| Read::Listed(had, listed, dead)))
                    }));
                } else if let Some(mut reader) = reader.take_if(|_| live && due) {
                    (again, looked) = (false, now);
                    let until = now + if changed { Duration::ZERO } else { echo };
                    work = Some(tokio::task::spawn_blocking(move || {
                        while number_of(&dir) == number && Instant::now() < until {
                            std::thread::sleep(Duration::from_micros(200));
                        }
                        let (seeing, dead) = (number_of(&dir), !lives(&dir));
                        let look = reader.look(dead, Instant::now());
                        (reader, Some(Read::Looked(look, dead, run_of(&dir), seeing)))
                    }));
                }
            }
            let waiting = waits.iter().any(|waits| !waits.is_empty());
            let pace = match active.elapsed().as_millis() {
                _ if waiting
                    || keyed.is_some_and(|keyed| keyed.elapsed() < Duration::from_millis(40)) =>
                {
                    1
                }
                0..3000 => 4,
                _ => 16,
            };
            let wake = now + Duration::from_millis(pace);
            let wake = if rests > now { wake.min(rests) } else { wake };
            // (With as many typed bytes waiting as are kept, the stream is read no more: the
            // client, and then whoever writes to its mirror, waits.)
            let room = waits.iter().all(|waits| waits.len() < MAX_HELD);
            tokio::select! {
                // A newer attach of this client to the run: this one writes no more.
                _ = stopped.changed() => return,
                () = &mut writer => return,
                permit = out.reserve(), if !round.is_empty() => {
                    let (Ok(permit), Some(message)) = (permit, round.pop_front()) else { return };
                    permit.send(message);
                }
                read = done(&mut work) => {
                    let Some((back, read)) = read else { return };
                    // (From when the work was done: it may have taken long.)
                    let (reader_back, now) = (back, Instant::now());
                    reader = Some(reader_back);
                    let mut last = |round: &mut VecDeque<ToMirror>| {
                        round.push_back(ToMirror::Ended);
                        ending = true;
                    };
                    match read {
                        Read::Listed(_, true, _) => (live, again) = (true, true),
                        // Read again: the folder was being written, by a holder that lived
                        // then. If that was its last round, the list is read once more with no
                        // holder, and the last round follows: a session that ends as a
                        // client comes is shown to its end. (Only a folder that was read with
                        // no holder and has no number never will have one.)
                        Read::Listed(had, false, false) => {
                            (list, rests) = (Some(had), now + Duration::from_millis(2));
                        }
                        Read::Listed(..) => last(&mut round),
                        // The folder is gone, or another run has its name: nothing of it is sent.
                        Read::Looked(_, _, there, _) if there != Some(run) => last(&mut round),
                        Read::Looked(Look::Round(messages), dead, _, seeing) => {
                            (seen, moved) = (seeing, 0);
                            if !messages.is_empty() {
                                (keyed, active) = (None, now);
                            }
                            round.extend(messages);
                            // No holder was left before it was read: it is the last there is.
                            if dead {
                                last(&mut round);
                            }
                        }
                        Read::Looked(Look::Odd, true, ..) => last(&mut round),
                        Read::Looked(Look::Odd, _, _, seeing) => seen = seeing,
                        // At once, but for a folder that keeps moving under the look: then
                        // after a while, which grows to 16 ms.
                        Read::Looked(Look::Moved, ..) => {
                            (again, moved) = (true, moved.saturating_add(1));
                            let wait = 1u64 << moved.saturating_sub(4).min(4);
                            if moved > 3 {
                                rests = now + Duration::from_millis(wait);
                            }
                        }
                        Read::Looked(Look::Rests(until), ..) => (again, rests) = (true, until),
                    }
                }
                message = from.recv(), if room => match message {
                    Some(Ok(FromMirror::Has(had))) if !listed => (list, listed) = (Some(had), true),
                    Some(Ok(FromMirror::Write { name, bytes })) if listed && bytes.len() <= MAX_TYPED => {
                        let Some(at) = ["in", "ctl"].iter().position(|fifo| *fifo == name) else { return };
                        waits.get_mut(at).into_iter().for_each(|waits| waits.extend(&bytes));
                    }
                    Some(Ok(FromMirror::Told { name, bytes }))
                        if listed && bytes.len() <= MAX_TYPED && matches!(name.as_str(), "colours" | "keyboard") =>
                    {
                        self.told(&name, &bytes, number);
                    }
                    // The stream's end; or a message no client of this sends.
                    _ => return,
                },
                () = tokio::time::sleep_until(wake.into()) => {}
            }
        }
        // (The last round and `Ended` are sent before the stream is let go; but a newer attach
        // of this client is not kept waiting for a link that takes them no more.)
        drop(out);
        tokio::select! {
            _ = stopped.changed() => {}
            () = writer => {}
        }
    }
}

/// A stream's place among those of its run: given up when the stream ends, unless a newer one
/// of the same client has it by then.
struct Place<'a>(&'a Sessions, (Run, u64), u64);

/// What an attach has once it is seated: its place, this client's older stream on the run if
/// there is one, what tells this stream to stop, the run and the run's two FIFOs.
type Seat<'a> = (
    Place<'a>,
    Option<Stream>,
    watch::Receiver<bool>,
    Run,
    [Option<File>; 2],
);

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

    thread_local! {
        /// What a test does between a client's taking its place and the opening of its FIFOs.
        pub(super) static MIDWAY: std::cell::Cell<Option<Box<dyn FnOnce()>>> = const { std::cell::Cell::new(None) };
    }

    /// A folder as a pane's is, as far as a run and its FIFOs go: held by `holder`.
    fn pane(dir: &Path, holder: u32) -> [File; 2] {
        fs::create_dir(dir).unwrap();
        fs::write(dir.join("status"), format!("holder {holder}\npid 1\n")).unwrap();
        ["in", "ctl"].map(|name| fuxix::fifo(dir.join(name)).unwrap())
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("koh-session-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_fifos_are_of_the_run_that_was_named() {
        let tmp = scratch("held");
        let (dir, aside) = (tmp.join("s"), tmp.join("aside"));
        let _first = pane(&dir, 7);
        let named = run_of(&dir).unwrap();
        // With no run named the FIFOs are the folder's as it is; with its run named, that run's.
        assert_eq!(held(&dir, None).map(|(run, _)| run), Some(named));
        assert!(
            held(&dir, Some(named)).is_some_and(|(_, fifos)| fifos.iter().all(Option::is_some))
        );
        // Another run takes the name, after a client that comes again was found to name the
        // run that was there: its FIFOs are not given for the run that was named.
        fs::rename(&dir, &aside).unwrap();
        let _second = pane(&dir, 8);
        assert!(run_of(&dir).is_some_and(|run| run != named));
        assert!(held(&dir, Some(named)).is_none());
        fs::remove_dir_all(&dir).unwrap();
        assert!(held(&dir, Some(named)).is_none() && held(&dir, None).is_none());
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn a_wait_is_for_the_run_it_was_asked_about() {
        let tmp = scratch("looked");
        let (dir, aside) = (tmp.join("s"), tmp.join("aside"));
        let lock = |dir: &Path| {
            let held = File::open(dir).unwrap();
            held.try_lock().unwrap();
            held
        };
        // A session that runs (the test holds its lock), and has marked no command.
        let (_fifos, holder) = (pane(&dir, 7), lock(&dir));
        let (run, was) = (run_of(&dir).unwrap(), Marks::read(&dir));
        assert_eq!(looked(&dir, run, &was), None);
        // Between two looks it ends, and another run has its name, whose shell has marked a
        // command's end with 7: that is not what was waited for. The session has ended.
        drop(holder);
        fs::rename(&dir, &aside).unwrap();
        let (_others, _holder) = (pane(&dir, 8), lock(&dir));
        fs::write(dir.join("marks"), "0 0 output\n1 0 end 7\n").unwrap();
        assert_eq!(
            looked(&dir, run, &was),
            Some((1, "ended".to_string(), Vec::new()))
        );
        // The folder gone is the same; and the run itself, ended, says how.
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            looked(&dir, run, &was),
            Some((1, "ended".to_string(), Vec::new()))
        );
        fs::rename(&aside, &dir).unwrap();
        fs::write(dir.join("state"), "exited 3\n").unwrap();
        assert_eq!(
            looked(&dir, run, &was),
            Some((3, "exited 3".to_string(), Vec::new()))
        );
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn a_session_a_client_came_to_since_it_was_chosen_does_not_go() {
        let tmp = scratch("goes");
        let sessions = Sessions::new(&tmp, 2, "sh".into()).unwrap();
        let dir = sessions.dir().join("1");
        let _fifos = pane(&dir, 7);
        let place = (run_of(&dir).unwrap(), 1);
        // Chosen to go for a new one, with no client; one came before it went: it stays.
        sessions
            .streams()
            .insert(place, (0, watch::channel(false).0));
        sessions.goes(&dir);
        assert!(dir.is_dir());
        // With no client it goes.
        sessions.streams().remove(&place);
        sessions.goes(&dir);
        assert!(!dir.exists());
        let _ = fs::remove_dir_all(tmp);
    }

    #[test]
    fn a_client_has_its_place_before_the_folder_is_looked_at_to_go() {
        let tmp = scratch("seat");
        let sessions = std::sync::Arc::new(Sessions::new(&tmp, 1, "sh".into()).unwrap());
        let dir = sessions.dir().join("1");
        let _fifos = pane(&dir, 7);
        let named = run_of(&dir);
        // The session was chosen to go for a new one. As a client that comes back to it is
        // seated, the new one has started, and the folder is looked at to be removed.
        let (looks, chosen) = (sessions.clone(), dir.clone());
        MIDWAY.set(Some(Box::new(move || looks.goes(&chosen))));
        // The client had its place by then: the folder stays, and it is seated on it.
        let seat = sessions.seat(&dir, named, 1);
        assert!(seat.is_some() && dir.is_dir());
        drop(seat);
        // Once it has left the folder goes, and a client that comes then has no seat and no place.
        sessions.goes(&dir);
        assert!(!dir.exists() && sessions.seat(&dir, named, 1).is_none());
        assert!(sessions.streams().is_empty());
        let _ = fs::remove_dir_all(tmp);
    }
}
