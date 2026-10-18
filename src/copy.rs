//! `koh cp`'s files and trees, as a stream of items: what the sending end walks and the
//! receiving end lands, the same whichever end is the server.
//!
//! A stream is a sequence of [`Item`]s, each a 4-byte big-endian length then its postcard
//! encoding, at most [`MAX_ITEM`] bytes; a file's bytes follow [`Item::Data`] raw. A directory or a
//! file opens with its item and is closed by [`Item::End`]; [`Item::Done`] ends the stream, and a
//! stream that ends before it was cut short. So nothing is held but the item being read and a
//! chunk of [`CHUNK`] bytes, however large the tree.
//!
//! Nothing lands half done. Each item named at the top lands beside its target under a hidden
//! temporary name, and is renamed into place once all of it (a whole tree) is written; a stream
//! cut short, or an [`Item::Failed`], removes what was staged. Every entry is created anew
//! (`O_EXCL`, `mkdir`), and an entry goes only into a directory this stream created, so no name a
//! sender chooses can reach through a symlink, nor outside the target.
//!
//! The sending end follows a source it was given if it is a symlink, as `cp` does a path named on
//! its command line, and sends the symlinks inside a tree as symlinks; fifos, sockets and devices
//! inside a tree are skipped and said so ([`Item::Skipped`]). Modes (permission bits, setuid,
//! setgid and sticky) and modification times are kept.
//!
//! The ends run on blocking threads, over [`std::io::Read`] and [`std::io::Write`]; a
//! [`ChannelReader`] or [`ChannelWriter`] joins one to the task moving a QUIC stream.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::bounded::at_most;
use crate::request::{Arity, MAX_PATH};

/// Most bytes of an item's encoding.
pub const MAX_ITEM: usize = 8 * 1024;

/// Most bytes one [`Item::Data`] brings.
pub const CHUNK: usize = 64 * 1024;

/// Most directories deep a tree goes, counting the top: each one sent holds a descriptor open.
pub const MAX_DEPTH: usize = 128;

/// Most bytes of a name: past every filesystem's own limit.
const MAX_NAME: usize = 1024;

/// Most bytes of a symlink's target: Linux's `PATH_MAX` less its NUL.
const MAX_LINK: usize = MAX_PATH - 1;

/// How many skipped names a receiver keeps to say; the rest are counted.
const SKIPPED_SHOWN: usize = 16;

/// One name in a directory: not empty, `.` or `..`, and holding no `/` or NUL, so it names an
/// entry of the directory it is in and nothing else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
        if bytes.is_empty() || bytes.contains(&0) {
            return Err("a symlink target empty or holding a NUL");
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

    fn of(meta: &fs::Metadata) -> Self {
        Self(meta.permissions().mode() & 0o7777)
    }

    fn permissions(self) -> fs::Permissions {
        fs::Permissions::from_mode(self.0)
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

    fn of(meta: &fs::Metadata) -> Option<Self> {
        let since = meta
            .modified()
            .ok()?
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?;
        Some(Self {
            secs: since.as_secs(),
            nanos: since.subsec_nanos(),
        })
    }

    fn system(self) -> Option<SystemTime> {
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(self.secs, self.nanos))
    }
}

impl<'de> Deserialize<'de> for Time {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (secs, nanos) = <(u64, u32)>::deserialize(deserializer)?;
        Self::new(secs, nanos).ok_or_else(|| de::Error::custom("nanoseconds past a second"))
    }
}

/// How many bytes follow an [`Item::Data`]: 1 to [`CHUNK`].
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

/// One step of a copy stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Item {
    /// A directory, whose entries follow until its [`Item::End`].
    Dir {
        name: Name,
        mode: Mode,
        mtime: Option<Time>,
    },
    /// A file, whose bytes follow as [`Item::Data`] until its [`Item::End`].
    File {
        name: Name,
        mode: Mode,
        mtime: Option<Time>,
    },
    /// Raw bytes of the open file follow, this many.
    Data(DataLen),
    Symlink {
        name: Name,
        target: LinkTarget,
    },
    /// Closes the open file, or else the innermost open directory.
    End,
    /// An entry of the open directory not copied: a fifo, a socket or a device.
    Skipped(Name),
    /// The sender gave up: what was staged goes.
    Failed(Failure),
    /// Everything was sent.
    Done,
}

/// Why a copy failed, and where: the receiver's or the sender's own path, said to the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub struct Failure {
    pub kind: FailKind,
    #[serde(deserialize_with = "at_most::<MAX_PATH, _, _>")]
    path: Vec<u8>,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.path.is_empty() {
            write!(f, "{}: ", String::from_utf8_lossy(&self.path))?;
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
}

/// What went wrong, by kind, so it reads the same whatever system either end runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailKind {
    NotFound,
    PermissionDenied,
    /// A directory is copied only to a new name: never merged into or over what is there.
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    NoSpace,
    ReadOnly,
    NameTooLong,
    /// More than [`MAX_DEPTH`] directories deep.
    TooDeep,
    /// A fifo, socket or device named as a source.
    NotCopyable,
    /// A source with no name to land as (`/`, `..`).
    NoName,
    /// Several sources, and the destination is no directory.
    SeveralIntoOne,
    /// The server user has no home directory, which the path is relative to.
    NoHome,
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
        const KINDS: [(E, FailKind); 10] = [
            (E::NotFound, FailKind::NotFound),
            (E::PermissionDenied, FailKind::PermissionDenied),
            (E::AlreadyExists, FailKind::AlreadyExists),
            (E::DirectoryNotEmpty, FailKind::AlreadyExists),
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

    const fn text(self) -> &'static str {
        match self {
            Self::NotFound => "no such file or directory",
            Self::PermissionDenied => "permission denied",
            Self::AlreadyExists => {
                "already exists (a directory is copied only to a new name, never merged into or \
                 over another: remove it, or copy into it)"
            }
            Self::NotADirectory => "not a directory",
            Self::IsADirectory => "is a directory",
            Self::NoSpace => "no space left",
            Self::ReadOnly => "read-only filesystem",
            Self::NameTooLong => "name too long",
            Self::TooDeep => "more than 128 directories deep",
            Self::NotCopyable => "not a file, directory or symlink",
            Self::NoName => "has no name to copy as",
            Self::SeveralIntoOne => "is not a directory, to copy several sources into",
            Self::NoHome => "the server user has no home directory",
            Self::Truncated => "the copy was cut short (nothing of it was kept)",
            Self::Malformed => "the other end sent a malformed copy stream",
            Self::Other => "failed",
        }
    }
}

/// Write `item` to `out`, then `data` if it brings any.
fn write_item(out: &mut impl Write, item: &Item, data: &[u8]) -> io::Result<()> {
    let bytes = crate::request::encode(item, MAX_ITEM).map_err(io::Error::other)?;
    out.write_all(&bytes)?;
    out.write_all(data)
}

/// The names a receiver was told it was not sent, the first few kept.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Skipped {
    pub shown: Vec<PathBuf>,
    pub count: u64,
}

impl Skipped {
    fn add(&mut self, path: PathBuf) {
        if self.shown.len() < SKIPPED_SHOWN {
            self.shown.push(path);
        }
        self.count = self.count.saturating_add(1);
    }
}

// --- the sending end ------------------------------------------------------------------------------

/// Send each of `sources`, then [`Item::Done`], to `out`; on a failure, [`Item::Failed`] in its
/// place. The skipped entries, or the failure. Fails itself only when `out` does: the other end
/// is gone.
pub fn send(sources: &[PathBuf], out: impl Write) -> io::Result<Result<Skipped, Failure>> {
    let mut out = io::BufWriter::with_capacity(CHUNK.saturating_add(MAX_ITEM), out);
    let mut skipped = Skipped::default();
    let mut sent = Ok(());
    for source in sources {
        sent = send_source(source, &mut out, &mut skipped)?;
        if sent.is_err() {
            break;
        }
    }
    let result = match sent {
        Ok(()) => {
            write_item(&mut out, &Item::Done, &[])?;
            Ok(skipped)
        }
        Err(failure) => {
            write_item(&mut out, &Item::Failed(failure.clone()), &[])?;
            Err(failure)
        }
    };
    out.flush()?;
    Ok(result)
}

/// Send `failure` alone: the copy failed before anything was sent.
pub fn send_failure(failure: &Failure, mut out: impl Write) -> io::Result<()> {
    write_item(&mut out, &Item::Failed(failure.clone()), &[])?;
    out.flush()
}

/// What sending one entry came to: `out` failing (outer), or the copy (inner).
type Sending = io::Result<Result<(), Failure>>;

/// Send `source`, followed if it is a symlink, as its own name.
fn send_source(source: &Path, out: &mut impl Write, skipped: &mut Skipped) -> Sending {
    let Some(name) = source
        .file_name()
        .and_then(|name| Name::new(name.as_bytes().to_vec()).ok())
    else {
        return Ok(Err(Failure::new(FailKind::NoName, source)));
    };
    match fs::metadata(source) {
        Ok(meta) if meta.is_dir() => send_dir(source, name, &meta, 1, out, skipped),
        Ok(meta) if meta.is_file() => send_file(source, name, out),
        Ok(_) => Ok(Err(Failure::new(FailKind::NotCopyable, source))),
        Err(error) => Ok(Err(Failure::io(source, &error))),
    }
}

/// Send the directory at `path`, `depth` deep, and what is in it.
fn send_dir(
    path: &Path,
    name: Name,
    meta: &fs::Metadata,
    depth: usize,
    out: &mut impl Write,
    skipped: &mut Skipped,
) -> Sending {
    if depth > MAX_DEPTH {
        return Ok(Err(Failure::new(FailKind::TooDeep, path)));
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => return Ok(Err(Failure::io(path, &error))),
    };
    let dir = Item::Dir {
        name,
        mode: Mode::of(meta),
        mtime: Time::of(meta),
    };
    write_item(out, &dir, &[])?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => return Ok(Err(Failure::io(path, &error))),
        };
        let child = entry.path();
        let Ok(name) = Name::new(entry.file_name().as_bytes().to_vec()) else {
            return Ok(Err(Failure::new(FailKind::NameTooLong, &child)));
        };
        let sent = match fs::symlink_metadata(&child) {
            Err(error) => Ok(Err(Failure::io(&child, &error))),
            Ok(meta) if meta.is_symlink() => match fs::read_link(&child) {
                Ok(target) => match LinkTarget::new(target.into_os_string().into_vec()) {
                    Ok(target) => write_item(out, &Item::Symlink { name, target }, &[]).map(Ok),
                    Err(_) => Ok(Err(Failure::new(FailKind::NameTooLong, &child))),
                },
                Err(error) => Ok(Err(Failure::io(&child, &error))),
            },
            Ok(meta) if meta.is_dir() => {
                send_dir(&child, name, &meta, depth.saturating_add(1), out, skipped)
            }
            Ok(meta) if meta.is_file() => send_file(&child, name, out),
            Ok(_) => {
                skipped.add(child);
                write_item(out, &Item::Skipped(name), &[]).map(Ok)
            }
        };
        match sent {
            Ok(Ok(())) => {}
            failed => return failed,
        }
    }
    write_item(out, &Item::End, &[]).map(Ok)
}

/// Send the file at `path`, as it reads to its end: its mode and time as it was opened.
fn send_file(path: &Path, name: Name, out: &mut impl Write) -> Sending {
    let opened = fs::File::open(path).and_then(|file| Ok((file.metadata()?, file)));
    let (meta, mut file) = match opened {
        Ok(opened) => opened,
        Err(error) => return Ok(Err(Failure::io(path, &error))),
    };
    let item = Item::File {
        name,
        mode: Mode::of(&meta),
        mtime: Time::of(&meta),
    };
    write_item(out, &item, &[])?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Ok(Err(Failure::io(path, &error))),
        };
        let (Some(len), Some(data)) = (DataLen::new(n), buf.get(..n)) else {
            return Ok(Err(Failure::new(FailKind::Other, path)));
        };
        write_item(out, &Item::Data(len), data)?;
    }
    write_item(out, &Item::End, &[]).map(Ok)
}

// --- the receiving end ----------------------------------------------------------------------------

/// Where the items named at a stream's top land.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Each inside this directory, under its own name.
    Into(PathBuf),
    /// The one item, as this path.
    As(PathBuf),
}

impl Target {
    /// Where `arity` items for `dest` land: inside it if it is a directory (or a symlink to one),
    /// else as it, if there is one and `dest` does not end in `/`.
    pub fn resolve(dest: PathBuf, arity: Arity) -> Result<Self, Failure> {
        let names_a_dir = dest.as_os_str().as_bytes().ends_with(b"/");
        match (fs::metadata(&dest), arity) {
            (Ok(meta), _) if meta.is_dir() => Ok(Self::Into(dest)),
            (Ok(_), _) if names_a_dir => Err(Failure::new(FailKind::NotADirectory, &dest)),
            (Ok(_), Arity::Several) => Err(Failure::new(FailKind::SeveralIntoOne, &dest)),
            (Err(error), _) if names_a_dir || error.kind() != io::ErrorKind::NotFound => {
                Err(Failure::io(&dest, &error))
            }
            (Err(_), Arity::Several) => Err(Failure::new(FailKind::NotFound, &dest)),
            (_, Arity::One) => Ok(Self::As(dest)),
        }
    }

    /// Where the `nth` item, named `name`, lands.
    fn place(&self, name: &Name, nth: usize) -> Result<PathBuf, Failure> {
        match self {
            Self::Into(dir) => Ok(dir.join(name.os())),
            Self::As(path) if nth == 0 => Ok(path.clone()),
            Self::As(path) => Err(Failure::new(FailKind::SeveralIntoOne, path)),
        }
    }
}

/// Reads a stream's items, and the bytes after a [`Item::Data`].
struct Items<R> {
    input: R,
    buf: Vec<u8>,
}

impl<R: Read> Items<R> {
    /// The next item: a stream that ends or breaks before it is cut short.
    fn next(&mut self) -> Result<Item, Failure> {
        let mut prefix = [0u8; 4];
        self.input.read_exact(&mut prefix).map_err(|_cut| cut())?;
        let len = crate::request::body_len(prefix, MAX_ITEM).map_err(|_bad| malformed())?;
        let mut body = vec![0u8; len];
        self.input.read_exact(&mut body).map_err(|_cut| cut())?;
        crate::request::decode(&body).map_err(|_bad| malformed())
    }

    /// Copy the `len` bytes of a [`Item::Data`] to `file`, at `path`.
    fn data(&mut self, len: DataLen, file: &mut fs::File, path: &Path) -> Result<(), Failure> {
        self.buf.resize(len.get(), 0);
        self.input.read_exact(&mut self.buf).map_err(|_cut| cut())?;
        file.write_all(&self.buf)
            .map_err(|error| Failure::io(path, &error))
    }
}

fn cut() -> Failure {
    Failure::new(FailKind::Truncated, Path::new(""))
}

fn malformed() -> Failure {
    Failure::new(FailKind::Malformed, Path::new(""))
}

/// Land the items read from `input` at `target`, each staged and renamed into place once whole;
/// the entries skipped, or why it failed. On a failure nothing of the item it struck is left.
pub fn receive(input: impl Read, target: &Target) -> Result<Skipped, Failure> {
    let mut items = Items {
        input,
        buf: Vec::new(),
    };
    let mut skipped = Skipped::default();
    let mut placed = 0;
    loop {
        let item = items.next()?;
        let name = match &item {
            Item::Done => return Ok(skipped),
            Item::Failed(failure) => return Err(failure.clone()),
            Item::Skipped(name) => {
                skipped.add(PathBuf::from(name.os()));
                continue;
            }
            Item::Dir { name, .. } | Item::File { name, .. } | Item::Symlink { name, .. } => {
                name.clone()
            }
            Item::End | Item::Data(_) => return Err(malformed()),
        };
        let path = target.place(&name, placed)?;
        placed = placed.saturating_add(1);
        land(&mut items, item, &path, &mut skipped)?;
    }
}

/// Land `item`, the start of a top-level entry, as `path`: staged beside it, then renamed.
fn land<R: Read>(
    items: &mut Items<R>,
    item: Item,
    path: &Path,
    skipped: &mut Skipped,
) -> Result<(), Failure> {
    // Replacing a file or a symlink is atomic; a directory is never replaced, nor merged into.
    if let Ok(there) = fs::symlink_metadata(path) {
        if matches!(item, Item::Dir { .. }) {
            return Err(Failure::new(FailKind::AlreadyExists, path));
        }
        if there.is_dir() {
            return Err(Failure::new(FailKind::IsADirectory, path));
        }
    }
    let staged = staging(path)?;
    let landed = create(items, item, &staged, 1, Path::new(""), skipped)
        .and_then(|()| fs::rename(&staged, path).map_err(|error| Failure::io(path, &error)));
    if landed.is_err() {
        remove_staged(&staged, 0);
    }
    landed
}

/// A hidden name beside `path` for staging it.
fn staging(path: &Path) -> Result<PathBuf, Failure> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|error| Failure::io(path, &error.into()))?;
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(dir.join(format!(".koh-{:016x}.part", u64::from_le_bytes(random))))
}

/// Create `item` at `path`, `depth` directories deep, `rel` its directory's path in the tree, and
/// what it holds.
fn create<R: Read>(
    items: &mut Items<R>,
    item: Item,
    path: &Path,
    depth: usize,
    rel: &Path,
    skipped: &mut Skipped,
) -> Result<(), Failure> {
    let io = |error: io::Error| Failure::io(path, &error);
    match item {
        Item::Symlink { target, .. } => {
            std::os::unix::fs::symlink(OsStr::from_bytes(&target.0), path).map_err(io)
        }
        Item::File { mode, mtime, .. } => {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(io)?;
            loop {
                match items.next()? {
                    Item::Data(len) => items.data(len, &mut file, path)?,
                    Item::End => break,
                    Item::Failed(failure) => return Err(failure),
                    Item::Dir { .. }
                    | Item::File { .. }
                    | Item::Symlink { .. }
                    | Item::Skipped(_)
                    | Item::Done => return Err(malformed()),
                }
            }
            file.set_permissions(mode.permissions()).map_err(io)?;
            if let Some(time) = mtime.and_then(Time::system) {
                file.set_modified(time).map_err(io)?;
            }
            Ok(())
        }
        Item::Dir { name, mode, mtime } => {
            if depth > MAX_DEPTH {
                return Err(Failure::new(FailKind::TooDeep, path));
            }
            fs::DirBuilder::new().mode(0o700).create(path).map_err(io)?;
            let rel = rel.join(name.os());
            loop {
                let entry = items.next()?;
                let name = match &entry {
                    Item::End => break,
                    Item::Failed(failure) => return Err(failure.clone()),
                    Item::Skipped(name) => {
                        skipped.add(rel.join(name.os()));
                        continue;
                    }
                    Item::Dir { name, .. }
                    | Item::File { name, .. }
                    | Item::Symlink { name, .. } => name.clone(),
                    Item::Data(_) | Item::Done => return Err(malformed()),
                };
                let child = path.join(name.os());
                create(items, entry, &child, depth.saturating_add(1), &rel, skipped)?;
            }
            // Last, so a directory made read-only still took what is in it.
            fs::set_permissions(path, mode.permissions()).map_err(io)?;
            if let Some(time) = mtime.and_then(Time::system) {
                fs::File::open(path)
                    .and_then(|dir| dir.set_modified(time))
                    .map_err(io)?;
            }
            Ok(())
        }
        Item::Data(_) | Item::End | Item::Skipped(_) | Item::Failed(_) | Item::Done => {
            Err(malformed())
        }
    }
}

/// Remove what was staged at `path`, `depth` deep, as far as it can: a directory made read-only
/// is made writable first.
fn remove_staged(path: &Path, depth: usize) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() && depth <= MAX_DEPTH {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                remove_staged(&entry.path(), depth.saturating_add(1));
            }
        }
        let _ = fs::remove_dir(path);
    } else {
        let _ = fs::remove_file(path);
    }
}

// --- joining the ends to a task -------------------------------------------------------------------

/// How many chunks wait between a blocking end and its task.
pub const PIPE_DEPTH: usize = 8;

/// The bytes a task hands on, read by a blocking end: they end when the task drops its sender.
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

impl Read for ChannelReader {
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

/// A blocking end's writes, handed to a task: a write fails once the task is gone.
pub struct ChannelWriter(pub mpsc::Sender<Vec<u8>>);

impl Write for ChannelWriter {
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

/// Hand what `recv` brings to `tx` until it ends, or breaks, or the reader is gone: a stream that
/// breaks reads as one cut short.
pub async fn from_stream(mut recv: iroh::endpoint::RecvStream, tx: mpsc::Sender<Vec<u8>>) {
    while let Ok(Some(chunk)) = recv.read_chunk(CHUNK).await {
        if tx.send(chunk.to_vec()).await.is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    /// What is in `dir`, recursively: each entry's relative path, kind, mode and contents (a
    /// file's bytes, a symlink's target), sorted.
    fn tree(dir: &Path) -> Vec<(PathBuf, char, u32, Vec<u8>)> {
        fn walk(root: &Path, at: &Path, out: &mut Vec<(PathBuf, char, u32, Vec<u8>)>) {
            for entry in fs::read_dir(at).unwrap() {
                let path = entry.unwrap().path();
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                let meta = fs::symlink_metadata(&path).unwrap();
                let mode = meta.mode() & 0o7777;
                if meta.is_symlink() {
                    let target = fs::read_link(&path).unwrap().into_os_string().into_vec();
                    out.push((rel, 'l', 0, target));
                } else if meta.is_dir() {
                    out.push((rel, 'd', mode, Vec::new()));
                    walk(root, &path, out);
                } else {
                    out.push((rel, 'f', mode, fs::read(&path).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    /// A tree with a mode, an odd name, a symlink, an empty file and one past a chunk.
    fn sample(root: &Path) -> PathBuf {
        let top = root.join("top dir");
        fs::create_dir_all(top.join("sub")).unwrap();
        let odd = OsStr::from_bytes(b"line\nbreak \xff name");
        fs::write(top.join(odd), b"odd").unwrap();
        fs::write(top.join("sub/big"), vec![7u8; CHUNK * 2 + 5]).unwrap();
        fs::write(top.join("empty"), b"").unwrap();
        fs::set_permissions(top.join("empty"), fs::Permissions::from_mode(0o751)).unwrap();
        std::os::unix::fs::symlink("sub/big", top.join("link")).unwrap();
        fs::set_permissions(top.join("sub"), fs::Permissions::from_mode(0o555)).unwrap();
        top
    }

    #[test]
    fn a_tree_lands_whole_and_a_stream_cut_anywhere_leaves_nothing_that_looks_landed() {
        let scratch = crate::test_runtime::scratch("copy-core");
        let top = sample(&scratch.join("from"));
        let mut stream = Vec::new();
        send(std::slice::from_ref(&top), &mut stream)
            .unwrap()
            .unwrap();
        let into = scratch.join("into");
        fs::create_dir(&into).unwrap();
        let target = Target::resolve(into.clone(), Arity::One).unwrap();
        assert_eq!(target, Target::Into(into.clone()));
        receive(stream.as_slice(), &target).unwrap();
        assert_eq!(tree(&into.join("top dir")), tree(&top));
        assert_eq!(
            fs::metadata(into.join("top dir/empty")).unwrap().mtime(),
            fs::metadata(top.join("empty")).unwrap().mtime()
        );
        // Again into the same place: a directory is never merged into.
        let again = receive(stream.as_slice(), &target).unwrap_err();
        assert_eq!(again.kind, FailKind::AlreadyExists);
        // Cut short anywhere, nothing lands, and nothing is left beside the target.
        let cuts = scratch.join("cuts");
        fs::create_dir(&cuts).unwrap();
        let target = Target::resolve(cuts.join("copy"), Arity::One).unwrap();
        for cut in (0..stream.len()).step_by(997) {
            let failed = receive(&stream[..cut], &target).unwrap_err();
            assert_eq!(failed.kind, FailKind::Truncated, "cut at {cut}");
            assert_eq!(fs::read_dir(&cuts).unwrap().count(), 0, "cut at {cut}");
        }
        // As its own name, a file replaces the file there.
        let file = scratch.join("one");
        fs::write(&file, b"old").unwrap();
        let mut one = Vec::new();
        send(&[top.join("sub/big")], &mut one).unwrap().unwrap();
        receive(
            one.as_slice(),
            &Target::resolve(file.clone(), Arity::One).unwrap(),
        )
        .unwrap();
        assert_eq!(fs::read(&file).unwrap().len(), CHUNK * 2 + 5);
        for sub in [top.join("sub"), into.join("top dir/sub")] {
            fs::set_permissions(sub, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn a_name_that_reaches_outside_its_directory_is_refused() {
        // Built by hand past the constructor: refused as it is decoded.
        #[derive(Serialize)]
        enum Raw {
            Dir(Vec<u8>, u32, Option<(u64, u32)>),
        }
        for name in [&b""[..], b".", b"..", b"a/b", b"a\0"] {
            assert!(Name::new(name.to_vec()).is_err(), "{name:?}");
        }
        let bytes =
            crate::request::encode(&Raw::Dir(b"..".to_vec(), 0o755, None), MAX_ITEM).unwrap();
        let mut items = Items {
            input: bytes.as_slice(),
            buf: Vec::new(),
        };
        assert_eq!(items.next().unwrap_err().kind, FailKind::Malformed);
    }
}
