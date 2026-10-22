//! `koh cp`: files and trees brought into line from one end to the other, the same whichever end
//! is the server.
//!
//! The sending end walks its sources and sends a header for each entry ([`Item`]); the receiving
//! end answers each file's ([`Answer`]): send it all (or the rest of a copy cut short before, whose
//! start it holds), or here is the hash of a file of the same size it has. The sender then sends
//! the file's bytes, or [`Item::Same`] if the hashes agree. So a copy sends only the files that
//! changed, and one run again after a cut sends only what did not arrive. Headers run ahead of
//! the answers by [`WINDOW`] files, so a tree of small files costs no round trip each.
//!
//! What lands, and how:
//!
//! - **Merged, parents made:** a directory merges into one already there, and the destination's
//!   missing parents are made. With [`Opts::delete`], entries the source does not have go.
//! - **Each file whole:** a file's bytes go to `.koh-HASH.part` beside it (`HASH` from its name),
//!   renamed over it once all came; a copy cut short leaves that part, which the next copy of the
//!   file resumes.
//! - **Arrival times:** a file that changed gets the time it arrived, as `cp` and `scp` give it,
//!   so a build on the other end sees it changed; [`Opts::keep_times`] keeps the source's. A file
//!   that did not change is left as it is. Modes come with files and new directories; a
//!   directory's mode and time are set once all its files landed.
//! - **Never through a symlink:** every entry is reached from the directory above it by its
//!   descriptor, never following a symlink, so no name a sender chooses reaches outside the
//!   destination. A symlink in a tree goes as a symlink; fifos, sockets and devices are skipped and
//!   counted. A source named on the command line is followed if it is a symlink, as `cp` follows
//!   one, but not under a scoped key.
//!
//! The ends run on blocking threads; channels join them to the tasks moving the QUIC streams.

use std::ffi::OsStr;
use std::future::Future;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::pin::pin;

use iroh::endpoint::{RecvStream, SendStream};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::bounded::at_most;
use crate::request::{RemotePath, Sources, MAX_PATH, MAX_SOURCES};

mod fsat;
pub mod glob;
mod receive;
mod send;

pub use receive::{receive, Dest, Target};
pub use send::{send, Source};

/// Most bytes of an item's encoding.
pub const MAX_ITEM: usize = 8 * 1024;

/// Most bytes of a reply's encoding: the end's [`Summary`] lists a dry run's changes.
pub const MAX_REPLY_ITEM: usize = 512 * 1024;

/// Most bytes one [`Item::Chunk`] brings.
pub const CHUNK: usize = 64 * 1024;

/// Most directories deep a tree goes, counting the top: each one sent holds a descriptor open.
pub const MAX_DEPTH: usize = 128;

/// How many files' headers run ahead of their answers: each holds a descriptor open at either end.
pub const WINDOW: usize = 64;

/// Most patterns `--exclude` names.
pub const MAX_EXCLUDES: usize = 256;

/// Most bytes of a name: past every filesystem's own limit.
const MAX_NAME: usize = 1024;

/// Most bytes of a symlink's target: Linux's `PATH_MAX` less its NUL.
const MAX_LINK: usize = MAX_PATH - 1;

/// How many of a dry run's changes a summary lists, and how many bytes of their paths at most
/// (past either, the rest are counted): within [`MAX_REPLY_ITEM`].
const CHANGES_SHOWN: usize = 1000;
const CHANGES_SHOWN_BYTES: usize = 256 * 1024;

/// One name in a directory: not empty, `.` or `..`, and holding no `/` or NUL, so it names an
/// entry of the directory it is in and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Name(Vec<u8>);

impl Name {
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        match bytes.as_slice() {
            [] | b"." | b".." => Err("a name that names no entry"),
            b if b.len() > MAX_NAME => Err("a name over 1024 bytes"),
            b if b.contains(&b'/') || b.contains(&0) => Err("a name holding a / or NUL"),
            _ => Ok(Self(bytes)),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn os(&self) -> &OsStr {
        OsStr::from_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(at_most::<MAX_NAME, D, u8>(deserializer)?).map_err(de::Error::custom)
    }
}

/// A symlink's target, as it is: any bytes but NUL, at most [`MAX_LINK`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LinkTarget(Vec<u8>);

impl LinkTarget {
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.contains(&0) || bytes.len() > MAX_LINK {
            return Err("a symlink target empty, too long or holding a NUL");
        }
        Ok(Self(bytes))
    }
}

impl<'de> Deserialize<'de> for LinkTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(at_most::<MAX_LINK, D, u8>(deserializer)?).map_err(de::Error::custom)
    }
}

/// Permission bits, with setuid, setgid and sticky: at most `0o7777`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Mode(u32);

impl Mode {
    /// `bits`, if they are permission bits, setuid, setgid and sticky alone.
    pub const fn new(bits: u32) -> Option<Self> {
        if bits > 0o7777 {
            None
        } else {
            Some(Self(bits))
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The bits an entry lands with: all but setuid and setgid, which no copy gives a file, so
    /// a peer cannot leave a program here that runs as this user for whoever starts it.
    pub const fn landed(self) -> u32 {
        self.0 & 0o1777
    }
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u32::deserialize(deserializer)?)
            .ok_or_else(|| de::Error::custom("a mode past 0o7777"))
    }
}

/// A modification time at or after 1970, to the nanosecond.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Time {
    secs: u64,
    nanos: u32,
}

impl Time {
    /// `secs` and `nanos` after 1970, if `nanos` is less than a second.
    pub const fn new(secs: u64, nanos: u32) -> Option<Self> {
        if nanos >= 1_000_000_000 {
            None
        } else {
            Some(Self { secs, nanos })
        }
    }
}

impl<'de> Deserialize<'de> for Time {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (secs, nanos) = <(u64, u32)>::deserialize(deserializer)?;
        Self::new(secs, nanos).ok_or_else(|| de::Error::custom("nanoseconds past a second"))
    }
}

/// How many bytes follow an [`Item::Chunk`]: 1 to [`CHUNK`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DataLen(u32);

impl DataLen {
    /// `len`, if it is 1 to [`CHUNK`].
    pub fn new(len: usize) -> Option<Self> {
        if (1..=CHUNK).contains(&len) {
            u32::try_from(len).ok().map(Self)
        } else {
            None
        }
    }

    fn get(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

impl<'de> Deserialize<'de> for DataLen {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let len = usize::try_from(u32::deserialize(deserializer)?).unwrap_or(usize::MAX);
        Self::new(len).ok_or_else(|| de::Error::custom("a data chunk empty or past 64 KiB"))
    }
}

/// A file's whole-content hash (BLAKE3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

/// A file in flight: the sender's number for it, unique within a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId(pub u32);

/// How a copy goes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opts {
    /// Keep the source's modification times (`-p`), on files and directories, changed or not.
    pub keep_times: bool,
    /// Remove what the source does not have from the directories it merges into.
    pub delete: bool,
    /// Change nothing and send no file's bytes: the receiver says what the copy would do
    /// ([`Summary::changes`]), the sender each file's hash agreeing or not ([`Item::Differs`]).
    pub dry_run: bool,
    /// Entries neither sent nor removed.
    pub excludes: glob::Excludes,
}

/// A copy, as the client asks it: exactly one side is the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Copy {
    /// The server sends these paths; the client says where they land.
    Get { sources: Sources, opts: Opts },
    /// What the client sends, `sources` sources, lands at `dest` on the server.
    Put {
        dest: RemotePath,
        sources: SourceCount,
        opts: Opts,
    },
}

/// How many sources a copy to the server brings: 1 to [`MAX_SOURCES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SourceCount(u32);

impl SourceCount {
    pub fn new(count: usize) -> Option<Self> {
        (1..=MAX_SOURCES)
            .contains(&count)
            .then(|| u32::try_from(count).ok().map(Self))
            .flatten()
    }

    pub fn get(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

impl<'de> Deserialize<'de> for SourceCount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = usize::try_from(u32::deserialize(deserializer)?).unwrap_or(usize::MAX);
        Self::new(n).ok_or_else(|| de::Error::custom("no sources, or more than 1024"))
    }
}

/// A file's header: the receiver answers it ([`Answer`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHeader {
    pub id: FileId,
    pub name: Name,
    pub mode: Mode,
    pub mtime: Option<Time>,
    pub size: u64,
}

/// One step of what the sender sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Item {
    /// A directory, whose entries follow until its [`Item::End`].
    Dir {
        name: Name,
        mode: Mode,
        mtime: Option<Time>,
    },
    /// What is in a directory, landing in the destination itself (`koh cp dir/. …`): its entries
    /// follow until its [`Item::End`]. Only at the top.
    Contents {
        mode: Mode,
        mtime: Option<Time>,
    },
    File(FileHeader),
    Symlink {
        name: Name,
        target: LinkTarget,
    },
    /// Closes the innermost open directory.
    End,
    /// An entry of the open directory not copied: a fifo, a socket or a device.
    Skipped(Name),
    /// File `id`'s bytes from byte `from` follow, as [`Item::Chunk`]s until [`Item::Sent`].
    Data {
        id: FileId,
        from: u64,
    },
    /// Raw bytes of the file being sent follow, this many.
    Chunk(DataLen),
    /// The file being sent is all sent.
    Sent,
    /// File `id` is the same as the receiver's: nothing is sent of it.
    Same(FileId),
    /// The sender gave up.
    Failed(Failure),
    /// Everything was sent.
    Done,
    /// In a dry run, in place of its bytes: file `id` is not the receiver's, and would be sent
    /// from byte `from`.
    Differs {
        id: FileId,
        from: u64,
    },
}

/// The receiver's answer to a file's header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Answer {
    /// Send it: from byte `have` if the file's first `have` bytes hash to `prefix` (the start the
    /// receiver kept of a copy cut short), else all of it.
    Want {
        id: FileId,
        have: u64,
        prefix: Option<Hash>,
    },
    /// The receiver has a file of the same size, of this hash: send it only if it differs.
    Check { id: FileId, hash: Hash },
}

/// What the receiver says to the sender.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Answer(Answer),
    /// The copy is over, and how it went.
    End(Result<Summary, Failure>),
}

/// What a copy did, as the receiver counts it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// Files written that were not there.
    pub new: u64,
    /// Files written over one that differed.
    pub replaced: u64,
    /// Files already the same, left as they were.
    pub unchanged: u64,
    /// Files resumed from what a copy cut short left.
    pub resumed: u64,
    /// Bytes of files sent.
    pub bytes: u64,
    /// Directories made.
    pub dirs: u64,
    /// Symlinks made or replaced.
    pub links: u64,
    /// Entries removed ([`Opts::delete`]).
    pub deleted: u64,
    /// Fifos, sockets and devices the sender skipped.
    pub skipped: u64,
    /// A dry run's changes, in order of path, as many as its reply holds ([`CHANGES_SHOWN`]);
    /// the rest are counted.
    pub changes: Vec<Change>,
    pub changes_unshown: u64,
}

/// What a dry run would do to one entry of the destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub kind: ChangeKind,
    /// From the destination.
    pub path: String,
    /// A file's size, as it would land (new, replaced).
    pub size: Option<u64>,
    /// The size of the file it would replace.
    pub was: Option<u64>,
}

/// What a change is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A file sent where there was none.
    New,
    /// A file sent over one that differs.
    Replaced,
    /// An entry removed (`--delete`), with what is in it.
    Deleted,
    /// A directory made.
    Dir,
    /// A symlink made or replaced.
    Link,
}

impl ChangeKind {
    /// Its word, as a dry run lists it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Replaced => "replaced",
            Self::Deleted => "deleted",
            Self::Dir => "dir",
            Self::Link => "link",
        }
    }
}

impl Summary {
    /// Files written, new and replaced.
    pub const fn written(&self) -> u64 {
        self.new.saturating_add(self.replaced)
    }

    /// Note a dry run's change of `path`: of a file `size` bytes long, over one of `was` bytes.
    fn change(&mut self, kind: ChangeKind, path: &Path, size: Option<u64>, was: Option<u64>) {
        let bytes: usize = self.changes.iter().map(|c| c.path.len()).sum();
        if self.changes.len() >= CHANGES_SHOWN || bytes >= CHANGES_SHOWN_BYTES {
            self.changes_unshown = self.changes_unshown.saturating_add(1);
            return;
        }
        let shown = path.to_string_lossy();
        let shown = shown.get(..shown.floor_char_boundary(MAX_PATH));
        self.changes.push(Change {
            kind,
            path: shown.unwrap_or_default().to_owned(),
            size,
            was,
        });
    }
}

/// Why a copy failed, and where: a path at the end that met it, said to the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub struct Failure {
    pub kind: FailKind,
    path: Vec<u8>,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.path.is_empty() {
            write!(
                f,
                "{}: ",
                crate::log::Peer(String::from_utf8_lossy(&self.path))
            )?;
        }
        f.write_str(self.kind.text())
    }
}

impl Failure {
    pub fn new(kind: FailKind, path: &Path) -> Self {
        let path = path.as_os_str().as_bytes();
        Self {
            kind,
            path: path.get(..MAX_PATH).unwrap_or(path).to_vec(),
        }
    }

    /// `error`, from acting on `path`.
    pub fn io(path: &Path, error: &io::Error) -> Self {
        Self::new(FailKind::of(error), path)
    }

    pub fn path(&self) -> String {
        String::from_utf8_lossy(&self.path).into_owned()
    }
}

/// The stream ended before the copy was done.
fn cut() -> Failure {
    Failure::new(FailKind::Truncated, Path::new(""))
}

fn malformed() -> Failure {
    Failure::new(FailKind::Malformed, Path::new(""))
}

/// [`FailKind`]: each kind, its name in `--json` output and its words.
macro_rules! fail_kinds {
    ($($(#[$doc:meta])* $kind:ident $name:literal $text:literal,)*) => {
        /// What went wrong, by kind, so it reads the same whatever system either end runs.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum FailKind {
            $($(#[$doc])* $kind,)*
        }

        impl FailKind {
            /// Its name in `--json` output.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$kind => $name,)*
                }
            }

            const fn text(self) -> &'static str {
                match self {
                    $(Self::$kind => $text,)*
                }
            }
        }
    };
}

fail_kinds! {
    NotFound "not_found" "no such file or directory",
    PermissionDenied "permission_denied" "permission denied",
    NotADirectory "not_a_directory" "not a directory",
    IsADirectory "is_a_directory" "is a directory, where the source has none",
    IsASymlink "is_a_symlink" "is a symlink, where the source has a directory: not merged through",
    NoSpace "no_space" "no space left",
    ReadOnly "read_only" "read-only filesystem",
    NameTooLong "name_too_long" "name too long",
    TooDeep "too_deep" "more than 128 directories deep",
    /// A fifo, socket or device named as a source.
    NotCopyable "not_copyable" "not a file, directory or symlink",
    /// A source with no name to land as (`/`, `..`).
    NoName "no_name" "has no name to copy as",
    SeveralIntoOne "several_into_one" "is a file, to copy several sources into",
    NoHome "no_home" "the server user has no home directory",
    OutOfScope "out_of_scope" "outside the directory this key may copy in",
    /// More names than `--delete` keeps track of.
    TooMany "too_many" "too many entries for this copy to keep track of",
    Truncated "truncated"
        "the copy was cut short: run it again to send the rest (files are whole or not there)",
    Malformed "malformed" "the other end sent a malformed copy stream",
    Other "failed" "failed",
}

impl FailKind {
    fn of(error: &io::Error) -> Self {
        use io::ErrorKind as E;
        const KINDS: [(E, FailKind); 8] = [
            (E::NotFound, FailKind::NotFound),
            (E::PermissionDenied, FailKind::PermissionDenied),
            (E::NotADirectory, FailKind::NotADirectory),
            (E::IsADirectory, FailKind::IsADirectory),
            (E::StorageFull, FailKind::NoSpace),
            (E::QuotaExceeded, FailKind::NoSpace),
            (E::ReadOnlyFilesystem, FailKind::ReadOnly),
            (E::InvalidFilename, FailKind::NameTooLong),
        ];
        let kind = KINDS.iter().find(|(kind, _)| *kind == error.kind());
        kind.map_or(Self::Other, |&(_, ours)| ours)
    }
}

/// The hash of `file`'s first `len` bytes (all of them if `None`). Its cursor is at its start:
/// a copy reads files only at offsets otherwise.
fn hash_of(file: &std::fs::File, len: Option<u64>) -> io::Result<Hash> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(io::Read::take(file, len.unwrap_or(u64::MAX)))?;
    Ok(Hash(*hasher.finalize().as_bytes()))
}

// --- joining the ends to the streams --------------------------------------------------------------

/// How many chunks wait between a blocking end and its stream's task.
pub const PIPE_DEPTH: usize = 8;

/// How many replies wait between the receiver and its stream: room for every answer the sender
/// may be owed ([`WINDOW`]), so the receiver never waits on one while the sender sends.
pub const REPLY_DEPTH: usize = WINDOW + 8;

/// A blocking reader of what a channel brings: an end's input, from its stream's task.
pub struct ChannelReader<B> {
    rx: mpsc::Receiver<B>,
    chunk: Option<B>,
    at: usize,
}

impl<B> ChannelReader<B> {
    pub const fn new(rx: mpsc::Receiver<B>) -> Self {
        Self {
            rx,
            chunk: None,
            at: 0,
        }
    }
}

impl<B: AsRef<[u8]>> io::Read for ChannelReader<B> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let rest = self
                .chunk
                .as_ref()
                .and_then(|chunk| chunk.as_ref().get(self.at..))
                .unwrap_or_default();
            if !rest.is_empty() {
                let n = rest.len().min(buf.len());
                if let (Some(to), Some(from)) = (buf.get_mut(..n), rest.get(..n)) {
                    to.copy_from_slice(from);
                }
                self.at = self.at.saturating_add(n);
                return Ok(n);
            }
            match self.rx.blocking_recv() {
                Some(chunk) => (self.chunk, self.at) = (Some(chunk), 0),
                None => return Ok(0),
            }
        }
    }
}

/// Send `sources` (or say why not) on `out`, the receiver's replies coming on the stream
/// `replies` brings: what the receiver said of the copy.
pub async fn send_on(
    sources: Result<Vec<Source>, Failure>,
    opts: Opts,
    out: &mut SendStream,
    replies: impl Future<Output = Option<RecvStream>>,
) -> Result<Summary, Failure> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PIPE_DEPTH);
    let (reply_tx, reply_rx) = mpsc::channel(REPLY_DEPTH);
    let sending = tokio::task::spawn_blocking(move || match sources {
        Ok(sources) => send(&sources, &opts, tx, reply_rx),
        Err(failure) => {
            if let Ok(item) = crate::request::encode(&Item::Failed(failure.clone()), MAX_ITEM) {
                let _ = tx.blocking_send(item);
            }
            Err(failure)
        }
    });
    let sent = async {
        while let Some(bytes) = rx.recv().await {
            if out.write_chunk(bytes.into()).await.is_err() {
                return;
            }
        }
        let _ = out.finish();
    };
    let replied = async {
        let Some(mut recv) = replies.await else {
            return;
        };
        while let Ok(body) = crate::transport_iroh::read_framed(&mut recv, MAX_REPLY_ITEM).await {
            let Ok(reply) = postcard::from_bytes::<Reply>(&body) else {
                return;
            };
            if reply_tx.send(reply).await.is_err() {
                return;
            }
        }
    };
    tokio::join!(sent, replied);
    sending
        .await
        .unwrap_or_else(|_panicked| Err(Failure::new(FailKind::Other, Path::new(""))))
}

/// Land what the stream `input` brings at `dest`, for `count` sources, answering on `replies`,
/// and say there how it went: that, too.
pub async fn receive_on(
    (dest, count): (Result<Dest, Failure>, usize),
    opts: Opts,
    input: impl Future<Output = Option<RecvStream>>,
    replies: &mut SendStream,
) -> Result<Summary, Failure> {
    let (tx, rx) = mpsc::channel(PIPE_DEPTH);
    let (reply_tx, mut reply_rx) = mpsc::channel(REPLY_DEPTH);
    let end_tx = reply_tx.clone();
    let mut landing = pin!(tokio::task::spawn_blocking(move || {
        let (target, made) = Target::resolve(&dest?, count, opts.dry_run)?;
        let mut summary = receive(ChannelReader::new(rx), target, &opts, &reply_tx)?;
        summary.dirs = summary.dirs.saturating_add(made);
        Ok(summary)
    }));
    let pumped = async move {
        let Some(mut recv) = input.await else {
            return;
        };
        while let Ok(Some(chunk)) = recv.read_chunk(CHUNK).await {
            if tx.send(chunk).await.is_err() {
                let _ = recv.stop(0u32.into());
                return;
            }
        }
    };
    let landed = async move {
        // The receiver may be done before the stream is (it failed): the stream is then read no
        // further.
        let landed = tokio::select! {
            landed = &mut landing => landed,
            () = pumped => landing.await,
        };
        let outcome = landed.unwrap_or_else(|error| {
            tracing::error!(%error, "a copy's receiver failed");
            Err(Failure::new(FailKind::Other, Path::new("")))
        });
        let _ = end_tx.send(Reply::End(outcome.clone())).await;
        outcome
    };
    let replied = async {
        while let Some(reply) = reply_rx.recv().await {
            let Ok(bytes) = crate::request::encode(&reply, MAX_REPLY_ITEM) else {
                return;
            };
            if replies.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = replies.finish();
    };
    tokio::join!(landed, replied).0
}

/// Whether `path` names an entry beneath `root`, each directory on the way reached without
/// following a symlink: what a scoped key may ask of its directory, and nothing outside it.
pub(crate) fn exists_beneath(root: &Path, path: &[Name]) -> bool {
    let Some((last, parents)) = path.split_last() else {
        return root.is_dir();
    };
    fsat::open_dir_path(root)
        .and_then(|dir| fsat::walk(dir, parents))
        .and_then(|dir| fsat::stat(dir, last.os()))
        .is_ok_and(|entry| entry.is_some())
}

#[cfg(test)]
mod tests;
