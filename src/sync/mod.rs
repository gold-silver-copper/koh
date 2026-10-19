//! `koh cp`: files and trees brought into line from one end to the other, the same whichever end
//! is the server.
//!
//! The sending end walks its sources and sends a header for each entry ([`Item`]); the receiving
//! end answers each file's ([`Answer`]): send it all (or the rest of a copy cut short before, whose
//! start it holds), or here is the hash of a file of the same size it has. The sender then sends
//! the file's bytes, or [`Item::Same`] if the hashes agree. So a copy sends only the files that
//! changed, and one run again after a cut sends only what did not arrive. A dry run sends no
//! file's bytes, but one with [`Opts::diff`] sends a text file's to the end that has an older one,
//! which says how they differ. Headers run ahead of
//! the answers by [`WINDOW`] files, so a tree of small files costs no round trip each.
//!
//! What lands, and how:
//!
//! - **Merged, parents made:** a directory merges into one already there, and the destination's
//!   missing parents are made. With [`Opts::delete`], entries the source does not have go.
//! - **Each file whole:** a file's bytes go to `.koh-HASH.part` beside it (`HASH` from its name),
//!   renamed over it once all came; a copy cut short leaves that part, which the next copy of the
//!   file resumes. With [`Opts::atomic`], no file is renamed and nothing deleted until the whole
//!   copy came.
//! - **Arrival times:** a file that changed gets the time it arrived, as `cp` and `scp` give it,
//!   so a build on the other end sees it changed; [`Opts::keep_times`] keeps the source's. A file
//!   that did not change is left as it is. Modes come with files and new directories.
//! - **Never through a symlink:** every entry is reached from the directory above it by its
//!   descriptor, never following a symlink, so no name a sender chooses reaches outside the
//!   destination. A symlink in a tree goes as a symlink; fifos, sockets and devices are skipped and
//!   said so. A source named on the command line is followed if it is a symlink, as `cp` follows
//!   one, but not under a scoped key.
//!
//! The ends run on blocking threads; channels join them to the tasks moving the QUIC streams.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

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

/// How many files' headers run ahead of their answers: each holds a descriptor open at the
/// sender.
pub const WINDOW: usize = 64;

/// Most patterns `--exclude` names.
pub const MAX_EXCLUDES: usize = 256;

/// Most bytes of a name: past every filesystem's own limit.
const MAX_NAME: usize = 1024;

/// Most bytes of a symlink's target: Linux's `PATH_MAX` less its NUL.
const MAX_LINK: usize = MAX_PATH - 1;

/// How many skipped names a summary keeps to say; the rest are counted.
const SKIPPED_SHOWN: usize = 16;

/// How many of a dry run's changes a summary keeps to say, and how many bytes of their paths at
/// most (past either, the rest are counted): within [`MAX_REPLY_ITEM`].
const CHANGES_SHOWN: usize = 1000;
const CHANGES_SHOWN_BYTES: usize = 256 * 1024;

/// Most bytes of a file [`Opts::diff`] compares, and of the diffs a summary keeps (within
/// [`MAX_REPLY_ITEM`]); how long it spends on one.
pub const DIFF_MAX: usize = 1 << 20;
const DIFFS_SHOWN_BYTES: usize = 128 * 1024;
const DIFF_TIME: std::time::Duration = std::time::Duration::from_secs(1);

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
    /// Rename no file into place, and remove nothing, until the whole copy came.
    pub atomic: bool,
    /// Change nothing and send no file's bytes: the receiver says what the copy would do
    /// ([`Summary::changes`]), the sender each file's hash agreeing or not ([`Item::Differs`]).
    pub dry_run: bool,
    /// In a dry run, send each file that differs from one there, both at most [`DIFF_MAX`], to
    /// the receiver, which says how their text differs ([`Change::diff`]).
    pub diff: bool,
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
    /// A file's header: the receiver answers it ([`Answer`]).
    File {
        id: FileId,
        name: Name,
        mode: Mode,
        mtime: Option<Time>,
        size: u64,
    },
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
    /// Entries of the destination's directories the source does not have, left there, but for
    /// directories (most often made there, as a build's output): what [`Opts::delete`] would
    /// remove.
    pub kept: u64,
    /// Fifos, sockets and devices the sender skipped, and the first few of them, from the
    /// destination.
    pub skipped: u64,
    #[serde(deserialize_with = "skipped_shown")]
    pub skipped_shown: Vec<String>,
    /// The name the one source landed as inside the destination, a directory: `None` when it
    /// landed as the destination itself, or its contents did (`dir/.`).
    #[serde(deserialize_with = "inside")]
    pub inside: Option<String>,
    /// A dry run's changes, in the order they would be made, the first few of them; the rest
    /// are counted.
    #[serde(deserialize_with = "changes")]
    pub changes: Vec<Change>,
    pub changes_unshown: u64,
}

/// What a dry run would do to one entry of the destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub kind: ChangeKind,
    /// From the destination, as [`Summary::inside`] names it.
    #[serde(deserialize_with = "change_path")]
    pub path: String,
    /// A file's size, as it would land (new, replaced).
    pub size: Option<u64>,
    /// The size of the file it would replace.
    pub was: Option<u64>,
    /// With [`Opts::diff`], how a replaced file's text differs: a unified diff, `a/` the file
    /// there and `b/` the one sent, or a line saying why there is none.
    #[serde(deserialize_with = "diff")]
    pub diff: Option<String>,
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

fn change_path<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let bytes = at_most::<MAX_PATH, D, u8>(deserializer)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn diff<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    struct Diff(#[serde(deserialize_with = "at_most::<DIFFS_SHOWN_BYTES, _, _>")] Vec<u8>);
    let diff = Option::<Diff>::deserialize(deserializer)?;
    Ok(diff.map(|Diff(d)| String::from_utf8_lossy(&d).into_owned()))
}

fn changes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Change>, D::Error> {
    at_most::<CHANGES_SHOWN, D, Change>(deserializer)
}

fn inside<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    struct Inside(#[serde(deserialize_with = "at_most::<MAX_NAME, _, _>")] Vec<u8>);
    let inside = Option::<Inside>::deserialize(deserializer)?;
    Ok(inside.map(|Inside(name)| String::from_utf8_lossy(&name).into_owned()))
}

fn skipped_shown<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    struct Shown(#[serde(deserialize_with = "at_most::<MAX_PATH, _, _>")] Vec<u8>);
    let shown = at_most::<SKIPPED_SHOWN, D, Shown>(deserializer)?;
    Ok(shown
        .into_iter()
        .map(|Shown(s)| String::from_utf8_lossy(&s).into_owned())
        .collect())
}

impl Summary {
    /// Files written, new and replaced.
    pub const fn written(&self) -> u64 {
        self.new.saturating_add(self.replaced)
    }

    /// Note a dry run's change of `path`.
    fn change(&mut self, kind: ChangeKind, path: &Path) {
        self.change_sized(kind, path, (None, None), None);
    }

    /// As [`Self::change`], of a file `size` bytes long, over one of `was` bytes, differing from
    /// it as `diff` says.
    fn change_sized(
        &mut self,
        kind: ChangeKind,
        path: &Path,
        (size, was): (Option<u64>, Option<u64>),
        diff: Option<String>,
    ) {
        let shown = path.to_string_lossy();
        let shown = shown
            .get(..shown.floor_char_boundary(MAX_PATH))
            .unwrap_or_default();
        let bytes: usize = self.changes.iter().map(|c| c.path.len()).sum();
        let diffs: usize = self
            .changes
            .iter()
            .filter_map(|c| c.diff.as_ref())
            .map(String::len)
            .sum();
        let diff = diff.map(|diff| {
            if diffs.saturating_add(diff.len()) > DIFFS_SHOWN_BYTES {
                "no diff: the diffs shown came to 128 KiB\n".to_owned()
            } else {
                diff
            }
        });
        if self.changes.len() < CHANGES_SHOWN && bytes < CHANGES_SHOWN_BYTES {
            self.changes.push(Change {
                kind,
                path: shown.to_owned(),
                size,
                was,
                diff,
            });
        } else {
            self.changes_unshown = self.changes_unshown.saturating_add(1);
        }
    }

    fn skip(&mut self, path: &Path) {
        if self.skipped_shown.len() < SKIPPED_SHOWN {
            let shown = path.to_string_lossy();
            self.skipped_shown.push(
                shown
                    .get(..shown.floor_char_boundary(MAX_PATH))
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
        self.skipped = self.skipped.saturating_add(1);
    }
}

/// Why a copy failed, and where: a path at the end that met it, said to the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub struct Failure {
    pub kind: FailKind,
    #[serde(deserialize_with = "at_most::<MAX_PATH, _, _>")]
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

/// What went wrong, by kind, so it reads the same whatever system either end runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailKind {
    NotFound,
    PermissionDenied,
    NotADirectory,
    IsADirectory,
    /// A symlink where the source has a directory: never merged through.
    IsASymlink,
    NoSpace,
    ReadOnly,
    NameTooLong,
    /// More than [`MAX_DEPTH`] directories deep.
    TooDeep,
    /// A fifo, socket or device named as a source.
    NotCopyable,
    /// A source with no name to land as (`/`, `..`).
    NoName,
    /// Several sources, and the destination is a file.
    SeveralIntoOne,
    /// The server user has no home directory, which the path is relative to.
    NoHome,
    /// A scoped key named a path outside its directory.
    OutOfScope,
    /// More entries than a copy can keep track of (`--delete`'s names, `--atomic`'s files).
    TooMany,
    /// The stream ended before it was done (the link was lost).
    Truncated,
    /// The stream was malformed.
    Malformed,
    /// Any other error.
    Other,
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
        KINDS
            .iter()
            .find(|(kind, _)| *kind == error.kind())
            .map_or(Self::Other, |&(_, ours)| ours)
    }

    /// Its name in `--json` output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::NotADirectory => "not_a_directory",
            Self::IsADirectory => "is_a_directory",
            Self::IsASymlink => "is_a_symlink",
            Self::NoSpace => "no_space",
            Self::ReadOnly => "read_only",
            Self::NameTooLong => "name_too_long",
            Self::TooDeep => "too_deep",
            Self::NotCopyable => "not_copyable",
            Self::NoName => "no_name",
            Self::SeveralIntoOne => "several_into_one",
            Self::NoHome => "no_home",
            Self::OutOfScope => "out_of_scope",
            Self::TooMany => "too_many",
            Self::Truncated => "truncated",
            Self::Malformed => "malformed",
            Self::Other => "failed",
        }
    }

    const fn text(self) -> &'static str {
        match self {
            Self::NotFound => "no such file or directory",
            Self::PermissionDenied => "permission denied",
            Self::NotADirectory => "not a directory",
            Self::IsADirectory => "is a directory, where the source has none",
            Self::IsASymlink => {
                "is a symlink, where the source has a directory: not merged through"
            }
            Self::NoSpace => "no space left",
            Self::ReadOnly => "read-only filesystem",
            Self::NameTooLong => "name too long",
            Self::TooDeep => "more than 128 directories deep",
            Self::NotCopyable => "not a file, directory or symlink",
            Self::NoName => "has no name to copy as",
            Self::SeveralIntoOne => "is a file, to copy several sources into",
            Self::NoHome => "the server user has no home directory",
            Self::OutOfScope => "outside the directory this key may copy in",
            Self::TooMany => "too many entries for this copy to keep track of",
            Self::Truncated => {
                "the copy was cut short: run it again to send the rest (files are whole or not \
                 there)"
            }
            Self::Malformed => "the other end sent a malformed copy stream",
            Self::Other => "failed",
        }
    }
}

/// Write `item` to `out`, then `data` if it brings any.
fn write_item(out: &mut impl io::Write, item: &Item, data: &[u8]) -> io::Result<()> {
    let bytes = crate::request::encode(item, MAX_ITEM).map_err(io::Error::other)?;
    out.write_all(&bytes)?;
    out.write_all(data)
}

/// How `theirs`, the file sent, differs from `ours`, the one at `path` it would replace: a
/// unified diff, or why there is none.
fn text_diff(ours: &[u8], theirs: &[u8], path: &Path) -> String {
    let text = |bytes| {
        std::str::from_utf8(bytes)
            .ok()
            .filter(|t| !t.contains('\0'))
    };
    let (Some(old), Some(new)) = (text(ours), text(theirs)) else {
        return "no diff: not text\n".to_owned();
    };
    let path = path.to_string_lossy();
    similar::TextDiff::configure()
        .timeout(DIFF_TIME)
        .diff_lines(old, new)
        .unified_diff()
        .header(&format!("a/{path}"), &format!("b/{path}"))
        .to_string()
}

/// The hash of `file`'s first `len` bytes (all of them if `None`).
fn hash_of(file: &std::fs::File, len: Option<u64>) -> io::Result<Hash> {
    use std::os::unix::fs::FileExt as _;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut at: u64 = 0;
    loop {
        let want = len.map_or(CHUNK, |len| {
            usize::try_from(len.saturating_sub(at))
                .unwrap_or(usize::MAX)
                .min(CHUNK)
        });
        if want == 0 {
            break;
        }
        let n = match file.read_at(buf.get_mut(..want).unwrap_or_default(), at) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        hasher.update(buf.get(..n).unwrap_or_default());
        at = at.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok(Hash(*hasher.finalize().as_bytes()))
}

// --- joining the ends to the streams --------------------------------------------------------------

/// How many chunks wait between a blocking end and its stream's task.
pub const PIPE_DEPTH: usize = 8;

/// A blocking reader of what a channel brings: an end's input, from its stream's task.
pub struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    chunk: Vec<u8>,
    at: usize,
}

impl ChannelReader {
    pub const fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            chunk: Vec::new(),
            at: 0,
        }
    }
}

impl io::Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.at >= self.chunk.len() {
            match self.rx.blocking_recv() {
                Some(chunk) => (self.chunk, self.at) = (chunk, 0),
                None => return Ok(0),
            }
        }
        let rest = self.chunk.get(self.at..).unwrap_or_default();
        let n = rest.len().min(buf.len());
        if let (Some(to), Some(from)) = (buf.get_mut(..n), rest.get(..n)) {
            to.copy_from_slice(from);
        }
        self.at = self.at.saturating_add(n);
        Ok(n)
    }
}

/// A blocking writer into a channel: an end's output, for its stream's task.
pub struct ChannelWriter(pub mpsc::Sender<Vec<u8>>);

impl io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .blocking_send(buf.to_vec())
            .map_err(|_gone| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Hand what `recv` brings to `tx` until either ends.
pub async fn from_stream(mut recv: iroh::endpoint::RecvStream, tx: mpsc::Sender<Vec<u8>>) {
    while let Ok(Some(chunk)) = recv.read_chunk(CHUNK).await {
        if tx.send(chunk.to_vec()).await.is_err() {
            let _ = recv.stop(0u32.into());
            return;
        }
    }
}

/// Write what `rx` brings to `send` until the writer is done, then finish `send`.
pub async fn to_stream(
    mut rx: mpsc::Receiver<Vec<u8>>,
    send: &mut iroh::endpoint::SendStream,
) -> anyhow::Result<()> {
    while let Some(bytes) = rx.recv().await {
        send.write_all(&bytes).await?;
    }
    send.finish()?;
    Ok(())
}

/// The replies on `recv`, framed, to `tx`, for a blocking sender, until either ends or one does
/// not decode.
pub async fn replies_from(mut recv: iroh::endpoint::RecvStream, tx: mpsc::Sender<Reply>) {
    loop {
        let Ok(body) = crate::transport_iroh::read_framed(&mut recv, MAX_REPLY_ITEM).await else {
            return;
        };
        let Ok(reply) = crate::request::decode::<Reply>(&body) else {
            return;
        };
        if tx.send(reply).await.is_err() {
            return;
        }
    }
}

/// The replies `rx` brings, framed, on `send`, until the receiver is done; then `send` is
/// finished.
pub async fn replies_to(mut rx: mpsc::Receiver<Reply>, send: &mut iroh::endpoint::SendStream) {
    while let Some(reply) = rx.recv().await {
        let Ok(bytes) = crate::request::encode(&reply, MAX_REPLY_ITEM) else {
            return;
        };
        if send.write_all(&bytes).await.is_err() {
            return;
        }
    }
    let _ = send.finish();
}

/// How many replies wait between the receiver and its stream: room for every answer the sender
/// may be owed, so the receiver never waits on one while the sender sends.
pub const REPLY_DEPTH: usize = WINDOW + 8;

/// Whether `path` names an entry beneath `root`, each directory on the way reached without
/// following a symlink: what a scoped key may ask of its directory, and nothing outside it.
pub(crate) fn exists_beneath(root: &std::path::Path, path: &[Name]) -> bool {
    let Some((last, parents)) = path.split_last() else {
        return root.is_dir();
    };
    fsat::open_dir_path(root)
        .and_then(|dir| fsat::walk(dir, parents, false, &mut 0))
        .and_then(|dir| fsat::stat(dir, last.os()))
        .is_ok_and(|entry| entry.is_some())
}

#[cfg(test)]
mod tests;
