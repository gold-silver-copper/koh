//! Delta file sync using blake3 hashes: manifest diff, chunked transfer,
//! `--delete`, `--exclude` globs, `-p` mtime preservation, and `--dry-run`.
//!
//! Every entry of a tree is reached from the directory above it, by that directory's descriptor
//! and with `O_NOFOLLOW`: no name a peer sends and no symlink already in the tree takes a copy
//! outside the tree. Symlinks are neither sent, followed nor removed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint::{RecvStream, SendStream};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::Serialize;

use crate::proto::{MAX_CHUNK, MAX_CTRL, SyncEntry, SyncMsg, SyncSummary, recv_msg, send_msg};
use crate::{KohError, Result};

/// Most entries a tree may hold, on either end.
pub const MAX_FILES: usize = 100_000;
/// Most directories deep an entry may be.
const MAX_DEPTH: usize = 128;
const CHUNK_SIZE: usize = 64 << 10;

/// Simple glob matcher supporting `*`, `?`, and `**` against relative paths and basenames.
pub fn matches_exclude(rel: &str, patterns: &[String]) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    patterns.iter().any(|pat| {
        let pat = pat.trim_end_matches('/');
        if pat.contains('/') {
            glob_match(pat.as_bytes(), rel.as_bytes())
        } else {
            glob_match(pat.as_bytes(), base.as_bytes())
                || rel
                    .split('/')
                    .any(|seg| glob_match(pat.as_bytes(), seg.as_bytes()))
        }
    })
}

fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None::<usize>, 0usize);
    while t < text.len() {
        match pat.get(p).copied() {
            Some(b'*') => {
                star_p = Some(p);
                star_t = t;
                p += 1;
            }
            Some(b'?') => {
                p += 1;
                t += 1;
            }
            Some(c) if Some(c) == text.get(t).copied() => {
                p += 1;
                t += 1;
            }
            _ => {
                if let Some(sp) = star_p {
                    p = sp + 1;
                    star_t += 1;
                    t = star_t;
                } else {
                    return false;
                }
            }
        }
    }
    while pat.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pat.len()
}

/// A tree on this machine as a copy reaches it: `base` as the system finds it (the path its
/// owner gave, symlinks followed), then `beneath` it one name at a time, never through a symlink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    pub base: PathBuf,
    pub beneath: Vec<String>,
}

/// What a tree is read from: a directory, or one regular file.
enum Source {
    Dir(File),
    File(File, fs::Metadata),
}

impl Place {
    /// A path of the user's own, taken as given.
    pub fn path(path: &Path) -> Self {
        Self {
            base: path.to_path_buf(),
            beneath: Vec::new(),
        }
    }

    fn shown(&self) -> String {
        let whole: PathBuf = std::iter::once(self.base.as_os_str())
            .chain(self.beneath.iter().map(AsRef::as_ref))
            .collect();
        whole.display().to_string()
    }

    /// Its last name: what a tree's entries are sent under when several share a destination.
    fn name(&self) -> Option<&str> {
        let last = match self.beneath.last() {
            Some(name) => Some(name.as_str()),
            None => self.base.file_name().and_then(|n| n.to_str()),
        };
        last.filter(|n| !n.is_empty() && *n != "." && *n != "..")
    }

    fn open_base(&self, more: OFlags) -> io::Result<File> {
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | more;
        Ok(rustix::fs::open(&self.base, flags, Mode::empty())?.into())
    }

    /// Its directory; made first (with those above it) if `make`, else `None` if it is not there.
    fn open_dir(&self, make: bool) -> Result<Option<File>> {
        let shown = self.shown();
        if make && self.beneath.is_empty() {
            fs::create_dir_all(&self.base)
                .map_err(|e| KohError::failed(format!("create_dir_all {shown}: {e}")))?;
        }
        let mut at = match self.open_base(OFlags::DIRECTORY) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound && !make => return Ok(None),
            Err(e) => return Err(KohError::failed(format!("open {shown}: {e}"))),
        };
        for name in &self.beneath {
            let Some(next) = open_dir(&at, name, &shown, make)? else {
                return Ok(None);
            };
            at = next;
        }
        Ok(Some(at))
    }

    /// The file or directory it names, to read.
    fn open_source(&self) -> Result<Source> {
        let shown = self.shown();
        let missing = || KohError::failed(format!("stat {shown}: No such file or directory"));
        let file = match self.beneath.split_last() {
            None => self
                .open_base(OFlags::NONBLOCK)
                .map_err(|e| KohError::failed(format!("stat {shown}: {e}")))?,
            Some((last, dirs)) => {
                let mut at = self
                    .open_base(OFlags::DIRECTORY)
                    .map_err(|e| KohError::failed(format!("open {shown}: {e}")))?;
                for name in dirs {
                    at = open_dir(&at, name, &shown, false)?.ok_or_else(missing)?;
                }
                open_file(&at, last, &shown)?
            }
        };
        let meta = file
            .metadata()
            .map_err(|e| KohError::failed(format!("stat {shown}: {e}")))?;
        if meta.is_dir() {
            Ok(Source::Dir(file))
        } else if meta.is_file() {
            Ok(Source::File(file, meta))
        } else {
            Err(KohError::usage(format!(
                "{shown} is neither file nor directory"
            )))
        }
    }
}

const fn nofollow(more: OFlags) -> OFlags {
    OFlags::CLOEXEC.union(OFlags::NOFOLLOW).union(more)
}

/// What entry `name` of `dir` is, not followed; `None` if there is none.
fn kind_at(dir: &File, name: &str) -> io::Result<Option<FileType>> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(FileType::from_raw_mode(stat.st_mode))),
        Err(Errno::NOENT) => Ok(None),
        Err(errno) => Err(errno.into()),
    }
}

/// Why `name` of `dir` could not be opened: a symlink there is refused, the rest failed.
fn not_opened(dir: &File, name: &str, rel: &str, errno: Errno) -> KohError {
    if matches!(kind_at(dir, name), Ok(Some(FileType::Symlink))) {
        KohError::refused(format!(
            "{rel}: {name:?} is a symlink, and a copy follows none"
        ))
    } else {
        KohError::failed(format!("open {rel}: {}", io::Error::from(errno)))
    }
}

/// Directory `name` of `dir`, never a symlink; made if `make` and not there, else `None` then.
fn open_dir(dir: &File, name: &str, rel: &str, make: bool) -> Result<Option<File>> {
    let flags = nofollow(OFlags::RDONLY.union(OFlags::DIRECTORY));
    let open = || rustix::fs::openat(dir, name, flags, Mode::empty());
    let found = match open() {
        Err(Errno::NOENT) if make => {
            match rustix::fs::mkdirat(dir, name, Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(Errno::EXIST) => open(),
                Err(errno) => Err(errno),
            }
        }
        found => found,
    };
    match found {
        Ok(fd) => Ok(Some(fd.into())),
        Err(Errno::NOENT) if !make => Ok(None),
        Err(errno) => Err(not_opened(dir, name, rel, errno)),
    }
}

/// File `name` of `dir` to read, never a symlink (and never waiting on a FIFO's writer).
fn open_file(dir: &File, name: &str, rel: &str) -> Result<File> {
    let flags = nofollow(OFlags::RDONLY.union(OFlags::NONBLOCK));
    rustix::fs::openat(dir, name, flags, Mode::empty())
        .map(File::from)
        .map_err(|errno| not_opened(dir, name, rel, errno))
}

/// The names of the wire path `rel`: a path beneath a tree, and nothing else.
fn names(rel: &str) -> Result<Vec<&str>> {
    let names: Vec<&str> = rel.split('/').collect();
    let plain = |n: &&str| !n.is_empty() && *n != "." && *n != ".." && !n.contains('\0');
    if names.len() > MAX_DEPTH || !names.iter().all(plain) {
        return Err(KohError::refused(format!("unsafe relative path {rel:?}")));
    }
    Ok(names)
}

/// File `rel` beneath `root` to read, each name opened from the one above it.
fn open_beneath(root: &File, rel: &str) -> Result<File> {
    let names = names(rel)?;
    let Some((last, dirs)) = names.split_last() else {
        return Err(KohError::refused(format!("unsafe relative path {rel:?}")));
    };
    let mut at = None::<File>;
    for name in dirs {
        let next = open_dir(at.as_ref().unwrap_or(root), name, rel, false)?;
        at = Some(next.ok_or_else(|| KohError::failed(format!("open {rel}: no such directory")))?);
    }
    open_file(at.as_ref().unwrap_or(root), last, rel)
}

/// A tree a copy lands in: its root, and the directory last reached in it (a manifest goes
/// directory by directory).
struct Tree {
    root: File,
    last: Option<(String, File)>,
}

impl Tree {
    /// The directory `rel` beneath the root (the root itself if empty), each name opened from
    /// the one above it; made where missing if `make`, else `None` where missing.
    fn dir(&mut self, rel: &str, make: bool) -> Result<Option<&File>> {
        if rel.is_empty() {
            return Ok(Some(&self.root));
        }
        if self.last.as_ref().is_none_or(|(at, _)| at != rel) {
            self.last = None;
            let mut at = None::<File>;
            for name in names(rel)? {
                let above = at.as_ref().unwrap_or(&self.root);
                let Some(next) = open_dir(above, name, rel, make)? else {
                    return Ok(None);
                };
                at = Some(next);
            }
            self.last = at.map(|dir| (rel.to_string(), dir));
        }
        Ok(self.last.as_ref().map(|(_, dir)| dir))
    }

    /// The directory that holds `rel`'s last name, and that name.
    fn parent<'a>(&'a mut self, rel: &'a str, make: bool) -> Result<Option<(&'a File, &'a str)>> {
        names(rel)?;
        let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
        Ok(self.dir(dir, make)?.map(|dir| (dir, name)))
    }
}

/// A file written under a name of its own beside where it lands: removed unless it lands.
struct Temp<'a> {
    dir: &'a File,
    name: String,
    landed: bool,
}

impl<'a> Temp<'a> {
    /// A new file in `dir` under a name nothing has: never one that is there, symlink or not.
    fn create(dir: &'a File, rel: &str) -> Result<(File, Self)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let flags = nofollow(OFlags::WRONLY.union(OFlags::CREATE).union(OFlags::EXCL));
        let mut why = Errno::EXIST;
        for _ in 0..16 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let name = format!(
                ".koh-{:x}-{:x}-{nanos:x}.tmp",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            match rustix::fs::openat(dir, &name, flags, Mode::from_raw_mode(0o600)) {
                Ok(fd) => {
                    let temp = Self {
                        dir,
                        name,
                        landed: false,
                    };
                    return Ok((fd.into(), temp));
                }
                Err(Errno::EXIST) => {}
                Err(errno) => {
                    why = errno;
                    break;
                }
            }
        }
        Err(KohError::failed(format!(
            "create a temporary file for {rel}: {}",
            io::Error::from(why)
        )))
    }

    /// Give it the name it lands under: whatever was there goes, a symlink as the link it is.
    fn land(mut self, name: &str, rel: &str) -> Result<()> {
        rustix::fs::renameat(self.dir, &self.name, self.dir, name)
            .map_err(|e| KohError::failed(format!("rename {rel}: {}", io::Error::from(e))))?;
        self.landed = true;
        Ok(())
    }
}

impl Drop for Temp<'_> {
    fn drop(&mut self) {
        if !self.landed {
            let _ = rustix::fs::unlinkat(self.dir, &self.name, AtFlags::empty());
        }
    }
}

fn entry(path: String, meta: &fs::Metadata, hash: [u8; 32]) -> SyncEntry {
    SyncEntry {
        path,
        size: if meta.is_dir() { 0 } else { meta.len() },
        mtime_secs: meta.mtime(),
        mode: meta.permissions().mode() & 0o777,
        hash,
        is_dir: meta.is_dir(),
    }
}

fn hash_file(mut file: &File, rel: &str) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 32 << 10];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| KohError::failed(format!("read {rel}: {e}")))?;
        if n == 0 {
            break;
        }
        if let Some(slice) = buf.get(..n) {
            hasher.update(slice);
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

/// The directories and regular files beneath `dir`, into `out`: a symlink is not an entry and
/// is not entered. With `hash`, each file's size, time, mode and blake3; without, its path alone.
fn scan(
    dir: &File,
    rel: &str,
    prefix: Option<&str>,
    excludes: &[String],
    hash: bool,
    depth: usize,
    out: &mut Vec<SyncEntry>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(KohError::failed(format!(
            "{rel}: more than {MAX_DEPTH} directories deep"
        )));
    }
    let failed = |e: io::Error| KohError::failed(format!("read_dir {rel:?}: {e}"));
    let mut names = Vec::new();
    for item in rustix::fs::Dir::read_from(dir).map_err(|e| failed(e.into()))? {
        let item = item.map_err(|e| failed(e.into()))?;
        if let Ok(name) = item.file_name().to_str()
            && name != "."
            && name != ".."
        {
            names.push(name.to_string());
        }
    }
    names.sort();
    for name in names {
        let child = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        if matches_exclude(&child, excludes) {
            continue;
        }
        let is_dir = match kind_at(dir, &name) {
            Ok(Some(FileType::Directory)) => true,
            Ok(Some(FileType::RegularFile)) => false,
            _ => continue,
        };
        if out.len() >= MAX_FILES {
            return Err(KohError::failed("tree exceeds maximum file count (100000)"));
        }
        let wire = match prefix {
            Some(p) => format!("{p}/{child}"),
            None => child.clone(),
        };
        let stat = |file: &File| {
            file.metadata()
                .map_err(|e| KohError::failed(format!("stat {child}: {e}")))
        };
        if is_dir {
            let Some(sub) = open_dir(dir, &name, &child, false)? else {
                continue;
            };
            out.push(entry(wire, &stat(&sub)?, [0u8; 32]));
            scan(&sub, &child, prefix, excludes, hash, depth + 1, out)?;
        } else if hash {
            let file = open_file(dir, &name, &child)?;
            let meta = stat(&file)?;
            if meta.is_file() {
                out.push(entry(wire, &meta, hash_file(&file, &child)?));
            }
        } else {
            out.push(SyncEntry {
                path: wire,
                size: 0,
                mtime_secs: 0,
                mode: 0,
                hash: [0u8; 32],
                is_dir: false,
            });
        }
    }
    Ok(())
}

/// The sorted blake3 manifest of `source`, and the name its paths are prefixed with: with
/// `preserve_root` a directory's own, so several directories can share one destination.
fn manifest(
    source: &Source,
    name: Option<&str>,
    excludes: &[String],
    preserve_root: bool,
) -> Result<(Vec<SyncEntry>, Option<String>)> {
    let mut entries = Vec::new();
    let dir = match source {
        Source::File(file, meta) => {
            let name = name.ok_or_else(|| KohError::usage("invalid filename"))?;
            entries.push(entry(name.to_string(), meta, hash_file(file, name)?));
            return Ok((entries, None));
        }
        Source::Dir(dir) => dir,
    };
    let prefix = if preserve_root {
        let name = name.ok_or_else(|| KohError::usage("cannot determine the directory's name"))?;
        let meta = dir
            .metadata()
            .map_err(|e| KohError::failed(format!("stat {name}: {e}")))?;
        entries.push(entry(name.to_string(), &meta, [0u8; 32]));
        Some(name.to_string())
    } else {
        None
    };
    scan(dir, "", prefix.as_deref(), excludes, true, 0, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((entries, prefix))
}

/// What the peer said went wrong, if that is why sending to it failed.
async fn peer_failure(recv: &mut RecvStream) -> Option<KohError> {
    let said = recv_msg::<SyncMsg>(recv, MAX_CTRL * 4);
    match tokio::time::timeout(Duration::from_secs(2), said).await {
        Ok(Ok(SyncMsg::Failed(err))) => Some(err.into()),
        _ => None,
    }
}

async fn send_file_msg<T: Serialize>(
    send: &mut SendStream,
    recv: &mut RecvStream,
    msg: &T,
    max: usize,
) -> Result<()> {
    match send_msg(send, msg, max).await {
        Ok(()) => Ok(()),
        Err(err) => Err(peer_failure(recv).await.unwrap_or(err)),
    }
}

/// Sender half of delta sync: sends manifest, streams only requested files, receives summary.
pub async fn send_tree(
    place: &Place,
    excludes: &[String],
    preserve_root: bool,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<SyncSummary> {
    let source = place.open_source()?;
    let (manifest, prefix) = manifest(&source, place.name(), excludes, preserve_root)?;
    let files: BTreeMap<String, SyncEntry> = manifest
        .iter()
        .filter(|e| !e.is_dir)
        .cloned()
        .map(|e| (e.path.clone(), e))
        .collect();
    send_msg(send, &SyncMsg::Manifest(manifest), MAX_CTRL * 8).await?;

    let needed = match recv_msg(recv, MAX_CTRL * 4).await? {
        SyncMsg::Need(needed) => needed,
        SyncMsg::Failed(err) => return Err(err.into()),
        _ => return Err(KohError::failed("expected Need message from receiver")),
    };
    let mut buf = vec![0u8; CHUNK_SIZE];
    for rel in needed {
        let Some(entry) = files.get(&rel) else {
            continue;
        };
        let opened;
        let mut file: &File = match &source {
            Source::File(file, _) => file,
            Source::Dir(root) => {
                let inner = match prefix.as_deref() {
                    Some(prefix) => rel
                        .strip_prefix(prefix)
                        .and_then(|s| s.strip_prefix('/'))
                        .ok_or_else(|| {
                            KohError::refused(format!("unexpected prefixed path {rel:?}"))
                        })?,
                    None => &rel,
                };
                opened = open_beneath(root, inner)?;
                &opened
            }
        };
        file.seek(SeekFrom::Start(0))
            .map_err(|e| KohError::failed(format!("seek {rel}: {e}")))?;
        let start = SyncMsg::FileStart {
            path: rel.clone(),
            size: entry.size,
            mtime_secs: entry.mtime_secs,
            mode: entry.mode,
        };
        send_file_msg(send, recv, &start, MAX_CTRL).await?;
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| KohError::failed(format!("read {rel}: {e}")))?;
            if n == 0 {
                break;
            }
            if let Some(slice) = buf.get(..n) {
                let chunk = SyncMsg::FileChunk(slice.to_vec());
                send_file_msg(send, recv, &chunk, MAX_CHUNK).await?;
            }
        }
        send_file_msg(send, recv, &SyncMsg::FileEnd, MAX_CTRL).await?;
    }
    match recv_msg(recv, MAX_CTRL * 4).await? {
        SyncMsg::Summary(summary) => Ok(summary),
        SyncMsg::Failed(err) => Err(err.into()),
        _ => Err(KohError::failed("expected Summary from receiver")),
    }
}

/// The regular file `name` of `dir`, open, if one is there: not a symlink to one.
fn existing(dir: &File, name: &str, rel: &str) -> Result<Option<(File, fs::Metadata)>> {
    if !matches!(kind_at(dir, name), Ok(Some(FileType::RegularFile))) {
        return Ok(None);
    }
    let file = open_file(dir, name, rel)?;
    let meta = file
        .metadata()
        .map_err(|e| KohError::failed(format!("stat {rel}: {e}")))?;
    Ok(meta.is_file().then_some((file, meta)))
}

/// Receiver half of delta sync: diffs manifest against the tree at `place`, requests changed
/// files, applies updates.
pub async fn receive_tree(
    place: &Place,
    excludes: &[String],
    delete: bool,
    preserve_mtime: bool,
    dry_run: bool,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<SyncSummary> {
    let src_entries = match recv_msg(recv, MAX_CTRL * 8).await? {
        SyncMsg::Manifest(entries) => entries,
        SyncMsg::Failed(err) => return Err(err.into()),
        _ => return Err(KohError::failed("expected Manifest from sender")),
    };
    if src_entries.len() > MAX_FILES {
        return Err(KohError::refused(format!(
            "manifest exceeds maximum file count ({MAX_FILES})"
        )));
    }
    let mut summary = SyncSummary {
        dry_run,
        ..SyncSummary::default()
    };
    let mut needed = Vec::new();
    let mut src_set = BTreeSet::new();
    // In a dry run nothing is made: a destination that is not there holds nothing.
    let mut tree = place
        .open_dir(!dry_run)?
        .map(|root| Tree { root, last: None });

    for entry in &src_entries {
        names(&entry.path)?;
        src_set.insert(entry.path.clone());
        let here = match (tree.as_mut(), entry.is_dir) {
            (Some(tree), true) => {
                tree.dir(&entry.path, !dry_run)?;
                continue;
            }
            (None, true) => continue,
            (Some(tree), false) => match tree.parent(&entry.path, false)? {
                Some((dir, name)) => existing(dir, name, &entry.path)?,
                None => None,
            },
            (None, false) => None,
        };
        match here {
            Some((file, meta)) if meta.len() == entry.size => {
                if hash_file(&file, &entry.path)? == entry.hash {
                    summary.unchanged += 1;
                    continue;
                }
                summary.updated.push(entry.path.clone());
            }
            Some(_) => summary.updated.push(entry.path.clone()),
            None => summary.added.push(entry.path.clone()),
        }
        needed.push(entry.path.clone());
    }

    if delete && let Some(tree) = tree.as_mut() {
        let mut local = Vec::new();
        scan(&tree.root, "", None, excludes, false, 0, &mut local)?;
        local.sort_by(|a, b| a.path.cmp(&b.path));
        for local in local.into_iter().rev() {
            if src_set.contains(&local.path) {
                continue;
            }
            if !dry_run && let Some((dir, name)) = tree.parent(&local.path, false)? {
                let how = if local.is_dir {
                    AtFlags::REMOVEDIR
                } else {
                    AtFlags::empty()
                };
                let _ = rustix::fs::unlinkat(dir, name, how);
            }
            summary.deleted.push(local.path);
        }
    }

    let Some(tree) = tree.as_mut().filter(|_| !dry_run) else {
        send_msg(send, &SyncMsg::Need(Vec::new()), MAX_CTRL).await?;
        send_msg(send, &SyncMsg::Summary(summary.clone()), MAX_CTRL * 4).await?;
        return Ok(summary);
    };

    send_msg(send, &SyncMsg::Need(needed.clone()), MAX_CTRL * 4).await?;
    let mut wanted: BTreeSet<String> = needed.into_iter().collect();
    while !wanted.is_empty() {
        let (path, size, mtime_secs, mode) = match recv_msg(recv, MAX_CTRL).await? {
            SyncMsg::FileStart {
                path,
                size,
                mtime_secs,
                mode,
            } => (path, size, mtime_secs, mode),
            SyncMsg::Failed(err) => return Err(err.into()),
            _ => return Err(KohError::failed("expected FileStart")),
        };
        if !wanted.remove(&path) {
            return Err(KohError::refused(format!(
                "{path:?} was sent but not asked for"
            )));
        }
        let Some((dir, name)) = tree.parent(&path, true)? else {
            return Err(KohError::failed(format!("open {path}: no such directory")));
        };
        let (mut out, temp) = Temp::create(dir, &path)?;
        let mut written = 0u64;
        loop {
            match recv_msg(recv, MAX_CHUNK).await? {
                SyncMsg::FileChunk(bytes) => {
                    written += bytes.len() as u64;
                    if written > size {
                        break;
                    }
                    out.write_all(&bytes)
                        .map_err(|e| KohError::failed(format!("write {path}: {e}")))?;
                }
                SyncMsg::FileEnd => break,
                SyncMsg::Failed(err) => return Err(err.into()),
                _ => return Err(KohError::failed("unexpected message during file transfer")),
            }
        }
        if written != size {
            return Err(KohError::failed(format!(
                "size mismatch on {path} ({written} != {size})"
            )));
        }
        let perms = fs::Permissions::from_mode(if mode & 0o111 != 0 { 0o755 } else { 0o644 });
        let _ = out.set_permissions(perms);
        if preserve_mtime {
            let at = rustix::fs::Timespec {
                tv_sec: mtime_secs,
                tv_nsec: 0,
            };
            let times = rustix::fs::Timestamps {
                last_access: at,
                last_modification: at,
            };
            let _ = rustix::fs::futimens(&out, &times);
        }
        drop(out);
        temp.land(name, &path)?;
        summary.bytes_transferred += written;
    }

    send_msg(send, &SyncMsg::Summary(summary.clone()), MAX_CTRL * 4).await?;
    Ok(summary)
}
