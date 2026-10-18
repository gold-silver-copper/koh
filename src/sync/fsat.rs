//! Entries reached from the directory above them by its descriptor, never through a symlink: what
//! `koh cp`'s ends do to files, so a name in a tree reaches nothing outside it.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode as RawMode, OFlags};

use super::{Name, Time, MAX_DEPTH};

/// What an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Dir,
    File,
    Link,
    /// A fifo, socket or device.
    Other,
}

/// An entry as `lstat` sees it.
#[derive(Clone, Copy, Debug)]
pub(super) struct Entry {
    pub(super) kind: Kind,
    pub(super) size: u64,
    /// Permission bits, setuid, setgid and sticky.
    pub(super) mode: u32,
    pub(super) mtime: Option<Time>,
}

impl Entry {
    fn of(stat: &rustix::fs::Stat) -> Self {
        let kind = match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => Kind::Dir,
            FileType::RegularFile => Kind::File,
            FileType::Symlink => Kind::Link,
            FileType::Fifo
            | FileType::Socket
            | FileType::CharacterDevice
            | FileType::BlockDevice
            | FileType::Unknown => Kind::Other,
        };
        let secs = u64::try_from(stat.st_mtime).ok();
        let nanos = u32::try_from(stat.st_mtime_nsec).ok();
        Self {
            kind,
            size: u64::try_from(stat.st_size).unwrap_or(0),
            mode: wide(stat.st_mode) & 0o7777,
            mtime: secs.zip(nanos).and_then(|(s, n)| Time::new(s, n)),
        }
    }
}

const fn flags(more: OFlags) -> OFlags {
    OFlags::CLOEXEC.union(OFlags::NOFOLLOW).union(more)
}

/// The entry `name` of `dir`, not followed; `None` if there is none.
pub(super) fn stat(dir: impl AsFd, name: &OsStr) -> io::Result<Option<Entry>> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(Entry::of(&stat))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(errno) => Err(errno.into()),
    }
}

/// What `file` is.
pub(super) fn stat_of(file: impl AsFd) -> io::Result<Entry> {
    Ok(Entry::of(&rustix::fs::fstat(file)?))
}

/// Directory `name` of `dir`, refused if it is a symlink.
pub(super) fn open_dir(dir: impl AsFd, name: &OsStr) -> io::Result<OwnedFd> {
    Ok(rustix::fs::openat(
        dir,
        name,
        flags(OFlags::RDONLY.union(OFlags::DIRECTORY)),
        RawMode::empty(),
    )?)
}

/// The directory at `path`, as the system finds it, symlinks followed.
pub(super) fn open_dir_path(path: &Path) -> io::Result<OwnedFd> {
    Ok(rustix::fs::open(
        path,
        OFlags::CLOEXEC
            .union(OFlags::RDONLY)
            .union(OFlags::DIRECTORY),
        RawMode::empty(),
    )?)
}

/// File `name` of `dir`, to read, refused if it is a symlink.
pub(super) fn open_file(dir: impl AsFd, name: &OsStr) -> io::Result<File> {
    Ok(rustix::fs::openat(dir, name, flags(OFlags::RDONLY), RawMode::empty())?.into())
}

/// File `name` of `dir`, to write, made (mode 0600) if it is not there, emptied if `truncate`;
/// refused if it is a symlink.
pub(super) fn create(dir: impl AsFd, name: &OsStr, truncate: bool) -> io::Result<File> {
    let more = OFlags::WRONLY.union(OFlags::CREATE);
    let more = if truncate {
        more.union(OFlags::TRUNC)
    } else {
        more
    };
    Ok(rustix::fs::openat(dir, name, flags(more), RawMode::from_raw_mode(0o600))?.into())
}

/// Make directory `name` in `dir`, mode 0700 until its own is set.
pub(super) fn make_dir(dir: impl AsFd, name: &OsStr) -> io::Result<()> {
    Ok(rustix::fs::mkdirat(
        dir,
        name,
        RawMode::from_raw_mode(0o700),
    )?)
}

pub(super) fn rename(dir: impl AsFd, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let dir = dir.as_fd();
    Ok(rustix::fs::renameat(dir, from, dir, to)?)
}

pub(super) fn symlink(target: &[u8], dir: impl AsFd, name: &OsStr) -> io::Result<()> {
    Ok(rustix::fs::symlinkat(OsStr::from_bytes(target), dir, name)?)
}

pub(super) fn read_link(dir: impl AsFd, name: &OsStr) -> io::Result<Vec<u8>> {
    Ok(rustix::fs::readlinkat(dir, name, Vec::new())?.into_bytes())
}

/// Set the mode of `name` in `dir`, a directory reached by its descriptor.
pub(super) fn chmod(dir: impl AsFd, mode: u32) -> io::Result<()> {
    let raw = narrow(mode & 0o7777).ok_or_else(|| io::Error::other("a mode past 0o7777"))?;
    Ok(rustix::fs::fchmod(dir, RawMode::from_raw_mode(raw))?)
}

/// A system's mode bits (`u32` on Linux, `u16` on macOS) as a `u32`.
fn wide(raw: impl Into<u32>) -> u32 {
    raw.into()
}

/// Mode bits as the system takes them, if they fit.
fn narrow<T: TryFrom<u32>>(bits: u32) -> Option<T> {
    T::try_from(bits).ok()
}

/// Set the modification time of `file` (a file or a directory), leaving its access time.
pub(super) fn set_mtime(file: impl AsFd, time: Time) -> io::Result<()> {
    let at = rustix::fs::Timespec {
        tv_sec: i64::try_from(time.secs).unwrap_or(i64::MAX),
        tv_nsec: i64::from(time.nanos),
    };
    let times = rustix::fs::Timestamps {
        last_access: rustix::fs::Timespec {
            tv_sec: 0,
            tv_nsec: rustix::fs::UTIME_OMIT,
        },
        last_modification: at,
    };
    Ok(rustix::fs::futimens(file, &times)?)
}

/// The names in `dir`, but `.` and `..`.
pub(super) fn names(dir: impl AsFd) -> io::Result<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    Ok(names)
}

/// Remove entry `name` of `dir`, a directory with all it holds, never following a symlink; at
/// most [`MAX_DEPTH`] directories deep.
pub(super) fn remove(dir: impl AsFd, name: &OsStr, depth: usize) -> io::Result<u64> {
    let dir = dir.as_fd();
    match stat(dir, name)?.map(|e| e.kind) {
        None => Ok(0),
        Some(Kind::Dir) => {
            if depth > MAX_DEPTH {
                return Err(io::Error::other("more than 128 directories deep"));
            }
            let sub = open_dir(dir, name)?;
            // A read-only directory is made writable first, so what is in it can go.
            let _ = chmod(&sub, 0o700);
            let mut removed: u64 = 0;
            for entry in names(&sub)? {
                removed = removed.saturating_add(remove(
                    &sub,
                    OsStr::from_bytes(&entry),
                    depth.saturating_add(1),
                )?);
            }
            rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR)?;
            Ok(removed.saturating_add(1))
        }
        Some(Kind::File | Kind::Link | Kind::Other) => {
            rustix::fs::unlinkat(dir, name, AtFlags::empty())?;
            Ok(1)
        }
    }
}

/// The directory `names` reach from `dir`, each opened from the last, none a symlink; made where
/// missing if `make`, each a directory made counted in `made`.
pub(super) fn walk(
    dir: OwnedFd,
    names: &[Name],
    make: bool,
    made: &mut u64,
) -> io::Result<OwnedFd> {
    let mut at = dir;
    for name in names {
        at = match open_dir(&at, name.os()) {
            Ok(next) => next,
            Err(error) if make && error.kind() == io::ErrorKind::NotFound => {
                make_dir(&at, name.os())?;
                *made = made.saturating_add(1);
                let next = open_dir(&at, name.os())?;
                chmod(&next, 0o755)?;
                next
            }
            Err(error) => return Err(error),
        };
    }
    Ok(at)
}
