//! The receiving end of a copy: land each entry where it goes, answer each file's header, and
//! count what was done; in a dry run, count and list it, changing nothing.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use tokio::sync::mpsc;

use super::fsat::{self, Kind};
use super::{
    cut, hash_of, malformed, Answer, ChangeKind, FailKind, Failure, FileHeader, FileId, Item,
    LinkTarget, Mode, Name, Opts, Reply, Summary, Time, MAX_DEPTH, MAX_ITEM, WINDOW,
};

/// Most names `--delete` keeps of what the sender sent, all open directories' together.
const MAX_SEEN: usize = 4_000_000;

/// Where what is copied lands: a directory, `None` in a dry run where one would be made.
#[derive(Debug)]
pub enum Target {
    /// Each item inside this directory, under its own name.
    Into(Option<OwnedFd>),
    /// The one item, as `name` in this directory.
    As { dir: Option<OwnedFd>, name: Name },
}

/// Where a copy's destination is, before it is resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dest {
    /// A path, as the system finds it; `/` at its end names a directory.
    Path(PathBuf),
    /// A path beneath a scoped key's directory, reached from it without following a symlink.
    Beneath {
        root: PathBuf,
        path: Vec<Name>,
        dir: bool,
    },
}

impl Target {
    /// Where `count` items for `dest` land, as `cp` would take it: inside it if it is a directory
    /// (or `/` ends it, or there are several, and it is made), else as it, its parents made where
    /// missing; with the directories made (only counted, if `dry`).
    pub fn resolve(dest: &Dest, count: usize, dry: bool) -> Result<(Self, u64), Failure> {
        let mut made = 0;
        let target = match dest {
            Dest::Path(path) => {
                let names_dir = path.as_os_str().as_bytes().ends_with(b"/") || count > 1;
                let io = |error: io::Error| Failure::io(path, &error);
                match std::fs::metadata(path) {
                    Ok(meta) if meta.is_dir() => {
                        Self::Into(Some(fsat::open_dir_path(path).map_err(io)?))
                    }
                    Ok(_) if count > 1 => return Err(Failure::new(FailKind::SeveralIntoOne, path)),
                    Ok(_) if names_dir => return Err(Failure::new(FailKind::NotADirectory, path)),
                    Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(io(error)),
                    _ if names_dir => {
                        made = made_dirs(path);
                        Self::Into(made_path(path, dry).map_err(io)?)
                    }
                    _ => {
                        let name = path
                            .file_name()
                            .and_then(|name| Name::new(name.as_bytes().to_vec()).ok())
                            .ok_or_else(|| Failure::new(FailKind::NoName, path))?;
                        let parent = path
                            .parent()
                            .filter(|p| !p.as_os_str().is_empty())
                            .unwrap_or_else(|| Path::new("."));
                        made = made_dirs(parent);
                        Self::As {
                            dir: made_path(parent, dry && made > 0).map_err(io)?,
                            name,
                        }
                    }
                }
            }
            Dest::Beneath { root, path, dir } => {
                let shown: PathBuf = path.iter().map(Name::os).collect();
                let io = |error: io::Error| Failure::io(&shown, &error);
                let root_fd = fsat::open_dir_path(root).map_err(io)?;
                let Some((last, parents)) = path.split_last() else {
                    return Ok((Self::Into(Some(root_fd)), 0));
                };
                let names_dir = *dir || count > 1;
                let parent = fsat::walk_making(root_fd, parents, dry, &mut made).map_err(io)?;
                let there = match &parent {
                    Some(parent) => fsat::stat(parent, last.os()).map_err(io)?,
                    None => None,
                };
                match there.map(|e| e.kind) {
                    Some(Kind::Dir) => Self::Into(
                        parent
                            .map(|parent| fsat::open_dir(parent, last.os()))
                            .transpose()
                            .map_err(io)?,
                    ),
                    Some(Kind::Link) => return Err(Failure::new(FailKind::IsASymlink, &shown)),
                    Some(_) if count > 1 => {
                        return Err(Failure::new(FailKind::SeveralIntoOne, &shown))
                    }
                    Some(_) if names_dir => {
                        return Err(Failure::new(FailKind::NotADirectory, &shown))
                    }
                    None if names_dir => Self::Into(if let Some(parent) = parent {
                        let last = std::slice::from_ref(last);
                        fsat::walk_making(parent, last, dry, &mut made).map_err(io)?
                    } else {
                        made = made.saturating_add(1);
                        None
                    }),
                    Some(_) | None => Self::As {
                        dir: parent,
                        name: last.clone(),
                    },
                }
            }
        };
        Ok((target, made))
    }
}

/// The directory at `path`, made with its parents where missing; `None` if `dry`, which makes
/// nothing.
fn made_path(path: &Path, dry: bool) -> io::Result<Option<OwnedFd>> {
    if dry {
        return Ok(None);
    }
    std::fs::create_dir_all(path)?;
    fsat::open_dir_path(path).map(Some)
}

/// How many of `path` and its parents are missing, which making it makes.
fn made_dirs(path: &Path) -> u64 {
    let mut missing: u64 = 0;
    let mut at = Some(path);
    while let Some(p) = at.filter(|p| !p.as_os_str().is_empty() && !p.exists()) {
        missing = missing.saturating_add(1);
        at = p.parent();
    }
    missing
}

/// The name a file's bytes go to before it is whole, beside it: the same for the same name, so a
/// copy run again finds what one cut short left.
fn part_name(name: &Name) -> Name {
    let hash = blake3::hash(name.as_bytes());
    let hex = hash
        .as_bytes()
        .iter()
        .take(8)
        .fold(String::new(), |mut hex, b| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
            hex
        });
    // Hex digits and dots: always a name.
    Name(format!(".koh-{hex}.part").into_bytes())
}

/// A directory entries land in.
struct Dir {
    /// `None` in a dry run, where one would be made: nothing is in it.
    fd: Option<OwnedFd>,
    /// Its path from the target, to say.
    rel: PathBuf,
    /// What it gets once nothing under it is under way.
    mode: Option<Mode>,
    mtime: Option<Time>,
    /// The directory it is in, held until then.
    _parent: Option<Rc<Self>>,
}

impl Dir {
    /// Entry `name` of it, if it has one.
    fn stat(&self, name: &Name) -> io::Result<Option<fsat::Entry>> {
        self.fd
            .as_ref()
            .map_or(Ok(None), |fd| fsat::stat(fd, name.os()))
    }
}

/// A directory the sender sends entries into.
struct Open {
    dir: Rc<Dir>,
    /// With `--delete`, the names sent into it (and the parts of files under way): what else is
    /// there goes.
    seen: Option<HashSet<Vec<u8>>>,
}

/// A file whose header came, awaiting its bytes or [`Item::Same`]; its header's name is the one
/// it lands as.
struct Pending {
    dir: Rc<Dir>,
    header: FileHeader,
    rel: PathBuf,
    /// Something was there, which this replaces.
    existed: bool,
    /// Its size, if it was a file.
    was: Option<u64>,
}

struct Receiver<'a, R: Read> {
    input: R,
    buf: Vec<u8>,
    opts: &'a Opts,
    replies: &'a mpsc::Sender<Reply>,
    /// The target's directory, and the name the one item lands as there ([`Target::As`]).
    top: Rc<Dir>,
    named: Option<Name>,
    /// How many items came at the top.
    placed: usize,
    open: Vec<Open>,
    /// The path of the directory opened at the top: `--exclude` matches paths from it, as the
    /// sender does.
    tree: PathBuf,
    pending: HashMap<FileId, Pending>,
    /// Directories ended while files under them are under way, waiting for their mode and time.
    closing: Vec<Rc<Dir>>,
    seen: usize,
    summary: Summary,
}

/// Land what `input` brings at `target` under `opts`, answering on `replies`.
///
/// What was done, or why it stopped: what landed before a failure stays, and a file under way
/// keeps its part for the next copy.
pub fn receive(
    input: impl Read,
    target: Target,
    opts: &Opts,
    replies: &mpsc::Sender<Reply>,
) -> Result<Summary, Failure> {
    let (fd, named) = match target {
        Target::Into(fd) => (fd, None),
        Target::As { dir, name } => (dir, Some(name)),
    };
    let top = Rc::new(Dir {
        fd,
        rel: PathBuf::new(),
        mode: None,
        mtime: None,
        _parent: None,
    });
    Receiver {
        input,
        buf: Vec::new(),
        opts,
        replies,
        top,
        named,
        placed: 0,
        open: Vec::new(),
        tree: PathBuf::new(),
        pending: HashMap::new(),
        closing: Vec::new(),
        seen: 0,
        summary: Summary::default(),
    }
    .run()
}

impl<R: Read> Receiver<'_, R> {
    fn next(&mut self) -> Result<Item, Failure> {
        let mut prefix = [0u8; 4];
        self.input.read_exact(&mut prefix).map_err(|_cut| cut())?;
        let len = crate::request::body_len(prefix, MAX_ITEM).map_err(|_bad| malformed())?;
        self.buf.resize(len, 0);
        self.input.read_exact(&mut self.buf).map_err(|_cut| cut())?;
        crate::request::decode(&self.buf).map_err(|_bad| malformed())
    }

    fn run(&mut self) -> Result<Summary, Failure> {
        loop {
            let at_top = self.open.is_empty();
            let dry = self.opts.dry_run;
            match self.next()? {
                Item::Done if at_top && self.pending.is_empty() => {
                    // A file's change is known when its answer is: listed in order of path.
                    self.summary.changes.sort_by(|a, b| a.path.cmp(&b.path));
                    return Ok(std::mem::take(&mut self.summary));
                }
                Item::Failed(failure) => return Err(failure),
                Item::End if !at_top => self.leave()?,
                Item::Skipped(name) if !at_top => {
                    self.saw(name.as_bytes())?;
                    self.summary.skipped = self.summary.skipped.saturating_add(1);
                }
                Item::Data { id, from } if !dry => self.data(id, from)?,
                Item::Differs { id, from } if dry => self.differs(id, from)?,
                Item::Same(id) => self.same(id)?,
                Item::Contents { mode, mtime } if at_top => {
                    if let Some(name) = self.named.clone() {
                        let (parent, name) = self.place(name)?;
                        self.enter(parent, &name, mode, mtime)?;
                    } else {
                        // Into the target itself: it keeps its mode, and takes the source's time
                        // if asked.
                        let io = |error: io::Error| Failure::io(Path::new(""), &error);
                        let fd = self.top.fd.as_ref().map(OwnedFd::try_clone);
                        let dir = Dir {
                            fd: fd.transpose().map_err(io)?,
                            rel: PathBuf::new(),
                            mode: None,
                            mtime: mtime.filter(|_| self.opts.keep_times),
                            _parent: Some(Rc::clone(&self.top)),
                        };
                        self.open(dir);
                    }
                }
                Item::Dir { name, mode, mtime } => {
                    let (parent, name) = self.place(name)?;
                    self.enter(parent, &name, mode, mtime)?;
                }
                Item::File(mut header) => {
                    let (parent, name) = self.place(header.name)?;
                    header.name = name;
                    self.file(parent, header)?;
                }
                Item::Symlink { name, target } => {
                    let (parent, name) = self.place(name)?;
                    self.symlink(&parent, &name, &target)?;
                }
                Item::Done
                | Item::End
                | Item::Skipped(_)
                | Item::Data { .. }
                | Item::Differs { .. }
                | Item::Contents { .. }
                | Item::Chunk(_)
                | Item::Sent => return Err(malformed()),
            }
        }
    }

    /// The directory an entry named `name` goes in, and the name it lands as: the open
    /// directory, or the target, as it says.
    fn place(&mut self, name: Name) -> Result<(Rc<Dir>, Name), Failure> {
        if let Some(open) = self.open.last() {
            return Ok((Rc::clone(&open.dir), name));
        }
        self.placed = self.placed.saturating_add(1);
        match &self.named {
            None => Ok((Rc::clone(&self.top), name)),
            Some(named) if self.placed == 1 => Ok((Rc::clone(&self.top), named.clone())),
            Some(_) => Err(malformed()),
        }
    }

    /// Note `name` as sent into the open directory, for `--delete`.
    fn saw(&mut self, name: &[u8]) -> Result<(), Failure> {
        let Some(seen) = self.open.last_mut().and_then(|open| open.seen.as_mut()) else {
            return Ok(());
        };
        if seen.insert(name.to_vec()) {
            self.seen = self.seen.saturating_add(1);
            if self.seen > MAX_SEEN {
                return Err(Failure::new(FailKind::TooMany, Path::new("")));
            }
        }
        Ok(())
    }

    fn open(&mut self, dir: Dir) {
        if self.open.is_empty() {
            self.tree.clone_from(&dir.rel);
        }
        self.open.push(Open {
            dir: Rc::new(dir),
            seen: self.opts.delete.then(HashSet::new),
        });
    }

    /// Remove entry `name` of `dir` (`--delete`), with all it holds; in a dry run, count and list
    /// it.
    fn remove(&mut self, dir: &OwnedFd, name: &OsStr, rel: &Path) -> Result<(), Failure> {
        let dry = self.opts.dry_run;
        let removed = fsat::remove(dir, name, 0, dry).map_err(|e| Failure::io(rel, &e))?;
        self.summary.deleted = self.summary.deleted.saturating_add(removed);
        if dry {
            self.summary.change(ChangeKind::Deleted, rel, None, None);
        }
        Ok(())
    }

    /// Open directory `name` of `parent` for what follows, made if it is not there.
    fn enter(
        &mut self,
        parent: Rc<Dir>,
        name: &Name,
        mode: Mode,
        mtime: Option<Time>,
    ) -> Result<(), Failure> {
        let rel = parent.rel.join(name.os());
        if self.open.len() >= MAX_DEPTH {
            return Err(Failure::new(FailKind::TooDeep, &rel));
        }
        self.saw(name.as_bytes())?;
        let io = |error: io::Error| Failure::io(&rel, &error);
        let dry = self.opts.dry_run;
        let made = match (parent.stat(name).map_err(io)?.map(|e| e.kind), &parent.fd) {
            (None, _) => true,
            (Some(Kind::Dir), _) => false,
            (Some(Kind::Link), _) => return Err(Failure::new(FailKind::IsASymlink, &rel)),
            (Some(Kind::File | Kind::Other), Some(fd)) if self.opts.delete => {
                self.remove(fd, name.os(), &rel)?;
                true
            }
            (Some(Kind::File | Kind::Other), _) => {
                return Err(Failure::new(FailKind::NotADirectory, &rel))
            }
        };
        if made {
            self.summary.dirs = self.summary.dirs.saturating_add(1);
            if dry {
                self.summary.change(ChangeKind::Dir, &rel, None, None);
            }
        }
        let fd = match &parent.fd {
            Some(dir) if !(dry && made) => {
                if made {
                    fsat::make_dir(dir, name.os()).map_err(io)?;
                }
                Some(fsat::open_dir(dir, name.os()).map_err(io)?)
            }
            _ => None,
        };
        let keep = self.opts.keep_times;
        self.open(Dir {
            fd,
            rel,
            mode: (made || keep).then_some(mode),
            mtime: mtime.filter(|_| keep),
            _parent: Some(parent),
        });
        Ok(())
    }

    /// The open directory is done: remove what the sender did not send, if asked.
    fn leave(&mut self) -> Result<(), Failure> {
        let Open { dir, seen } = self.open.pop().ok_or_else(malformed)?;
        if let Some(seen) = seen {
            self.seen = self.seen.saturating_sub(seen.len());
            if let Some(fd) = &dir.fd {
                let names = fsat::names(fd).map_err(|e| Failure::io(&dir.rel, &e))?;
                for entry in names {
                    let path = dir.rel.join(OsStr::from_bytes(&entry));
                    let tree = path.strip_prefix(&self.tree).unwrap_or(&path);
                    let excluded = self
                        .opts
                        .excludes
                        .excludes(&entry, tree.as_os_str().as_bytes());
                    if !excluded && !seen.contains(&entry) {
                        self.remove(fd, OsStr::from_bytes(&entry), &path)?;
                    }
                }
            }
        }
        if !self.opts.dry_run {
            self.closing.push(dir);
        }
        self.close_ready()
    }

    /// Give each directory ended with nothing under it under way its mode and time: the bytes of
    /// its files may come after its end, and making them in a directory made read-only would
    /// fail, and change its time.
    fn close_ready(&mut self) -> Result<(), Failure> {
        while let Some(at) = self.closing.iter().position(|d| Rc::strong_count(d) == 1) {
            let dir = self.closing.swap_remove(at);
            let io = |error: io::Error| Failure::io(&dir.rel, &error);
            if let Some(fd) = &dir.fd {
                if let Some(mode) = dir.mode {
                    fsat::chmod(fd, mode.landed()).map_err(io)?;
                }
                if let Some(time) = dir.mtime {
                    fsat::set_mtime(fd, time).map_err(io)?;
                }
            }
        }
        Ok(())
    }

    /// A file's header, landing in `dir`: answer it.
    fn file(&mut self, dir: Rc<Dir>, header: FileHeader) -> Result<(), Failure> {
        // A sender keeps at most a window's headers unanswered, each holding its directory here.
        if self.pending.len() >= WINDOW || self.pending.contains_key(&header.id) {
            return Err(malformed());
        }
        let rel = dir.rel.join(header.name.os());
        let io = |error: io::Error| Failure::io(&rel, &error);
        self.saw(header.name.as_bytes())?;
        let there = dir.stat(&header.name).map_err(io)?;
        let id = header.id;
        let answer = match (there, &dir.fd) {
            (Some(e), _) if e.kind == Kind::Dir => {
                return Err(Failure::new(FailKind::IsADirectory, &rel))
            }
            (Some(e), Some(fd)) if e.kind == Kind::File && e.size == header.size => {
                let file = fsat::open_file(fd, header.name.os()).map_err(io)?;
                let hash = hash_of(&file, None).map_err(io)?;
                Answer::Check { id, hash }
            }
            _ => {
                let part = part_name(&header.name);
                self.saw(part.as_bytes())?;
                let kept = dir.stat(&part).map_err(io)?;
                match (kept, &dir.fd) {
                    (Some(p), Some(fd))
                        if p.kind == Kind::File && p.size > 0 && p.size <= header.size =>
                    {
                        let file = fsat::open_file(fd, part.os()).map_err(io)?;
                        let prefix = hash_of(&file, Some(p.size)).map_err(io)?;
                        Answer::Want {
                            id,
                            have: p.size,
                            prefix: Some(prefix),
                        }
                    }
                    _ => Answer::Want {
                        id,
                        have: 0,
                        prefix: None,
                    },
                }
            }
        };
        self.pending.insert(
            id,
            Pending {
                dir,
                header,
                rel,
                existed: there.is_some(),
                was: there.filter(|e| e.kind == Kind::File).map(|e| e.size),
            },
        );
        // A sender gone hears nothing, but what it sent before it went still lands. One that does
        // not read its answers fills the channel, and this end never waits on it.
        let _ = self.replies.try_send(Reply::Answer(answer));
        Ok(())
    }

    /// The next of a file's chunks, into `buf`, its length; `None` once it is all sent.
    fn chunk(&mut self) -> Result<Option<u64>, Failure> {
        let item = self.next()?;
        if item == Item::Sent {
            return Ok(None);
        }
        let Item::Chunk(len) = item else {
            return Err(malformed());
        };
        self.buf.resize(len.get(), 0);
        self.input.read_exact(&mut self.buf).map_err(|_cut| cut())?;
        let n = u64::try_from(len.get()).unwrap_or(u64::MAX);
        self.summary.bytes = self.summary.bytes.saturating_add(n);
        Ok(Some(n))
    }

    /// File `id`'s bytes from `from`: into its part, then it into place.
    fn data(&mut self, id: FileId, from: u64) -> Result<(), Failure> {
        let p = self.pending.remove(&id).ok_or_else(malformed)?;
        let Some(dir) = &p.dir.fd else {
            return Err(malformed());
        };
        let io = |error: io::Error| Failure::io(&p.rel, &error);
        let part = part_name(&p.header.name);
        let file = fsat::create(dir, part.os(), from == 0).map_err(io)?;
        file.set_len(from).map_err(io)?;
        let mut at = from;
        while let Some(n) = self.chunk()? {
            file.write_all_at(&self.buf, at).map_err(io)?;
            at = at.saturating_add(n);
        }
        file.set_permissions(std::fs::Permissions::from_mode(p.header.mode.landed()))
            .map_err(io)?;
        if let Some(time) = p.header.mtime.filter(|_| self.opts.keep_times) {
            fsat::set_mtime(&file, time).map_err(io)?;
        }
        drop(file);
        fsat::rename(dir, part.os(), p.header.name.os()).map_err(io)?;
        self.written(&p, from);
        drop(p);
        self.close_ready()
    }

    /// File `p` was written, from byte `from` on, or would be, in a dry run.
    fn written(&mut self, p: &Pending, from: u64) {
        let kind = if p.existed {
            self.summary.replaced = self.summary.replaced.saturating_add(1);
            ChangeKind::Replaced
        } else {
            self.summary.new = self.summary.new.saturating_add(1);
            ChangeKind::New
        };
        if from > 0 {
            self.summary.resumed = self.summary.resumed.saturating_add(1);
        }
        if self.opts.dry_run {
            let size = Some(p.header.size);
            self.summary.change(kind, &p.rel, size, p.was);
        }
    }

    /// In a dry run, file `id` differs from the one here, or there is none: it would be sent from
    /// byte `from`.
    fn differs(&mut self, id: FileId, from: u64) -> Result<(), Failure> {
        let p = self.pending.remove(&id).ok_or_else(malformed)?;
        let bytes = p.header.size.saturating_sub(from);
        self.summary.bytes = self.summary.bytes.saturating_add(bytes);
        self.written(&p, from);
        Ok(())
    }

    /// File `id` is the same as the one here: it keeps its time, unless asked for the source's,
    /// and takes the source's mode.
    fn same(&mut self, id: FileId) -> Result<(), Failure> {
        let p = self.pending.remove(&id).ok_or_else(malformed)?;
        self.summary.unchanged = self.summary.unchanged.saturating_add(1);
        if self.opts.dry_run {
            return Ok(());
        }
        let Some(dir) = &p.dir.fd else {
            return Err(malformed());
        };
        let io = |error: io::Error| Failure::io(&p.rel, &error);
        let file = fsat::open_file(dir, p.header.name.os()).map_err(io)?;
        let here = fsat::stat_of(&file).map_err(io)?;
        let mode = p.header.mode.landed();
        if here.mode != mode {
            file.set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(io)?;
        }
        let keep = self.opts.keep_times;
        if let Some(time) = p.header.mtime.filter(|t| keep && here.mtime != Some(*t)) {
            fsat::set_mtime(&file, time).map_err(io)?;
        }
        drop(file);
        drop(p);
        self.close_ready()
    }

    /// A symlink, made or put in place of what is there, unless it is the same already.
    fn symlink(&mut self, dir: &Dir, name: &Name, link: &LinkTarget) -> Result<(), Failure> {
        let rel = dir.rel.join(name.os());
        let io = |error: io::Error| Failure::io(&rel, &error);
        self.saw(name.as_bytes())?;
        match (dir.stat(name).map_err(io)?.map(|e| e.kind), &dir.fd) {
            (Some(Kind::Dir), _) => return Err(Failure::new(FailKind::IsADirectory, &rel)),
            // The same already: not a file, so not counted among those unchanged.
            (Some(Kind::Link), Some(fd))
                if fsat::read_link(fd, name.os()).map_err(io)? == link.0 =>
            {
                return Ok(());
            }
            _ if self.opts.dry_run => self.summary.change(ChangeKind::Link, &rel, None, None),
            (None, Some(fd)) => fsat::symlink(&link.0, fd, name.os()).map_err(io)?,
            (Some(Kind::Link | Kind::File | Kind::Other), Some(fd)) => {
                let part = part_name(name);
                let _ = fsat::remove(fd, part.os(), MAX_DEPTH, false);
                fsat::symlink(&link.0, fd, part.os()).map_err(io)?;
                fsat::rename(fd, part.os(), name.os()).map_err(io)?;
            }
            (_, None) => return Err(malformed()),
        }
        self.summary.links = self.summary.links.saturating_add(1);
        Ok(())
    }
}
