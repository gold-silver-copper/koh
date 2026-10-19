//! The receiving end of a copy: land each entry where it goes, answer each file's header, and
//! count what was done; in a dry run, count and list it, changing nothing.
//!
//! A directory is a descriptor, or, in a dry run, `None` where one would be made: nothing is in
//! it.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use super::fsat::{self, Kind};
use super::{
    hash_of, Answer, ChangeKind, DataLen, FailKind, Failure, FileId, Item, LinkTarget, Mode, Name,
    Opts, Reply, Summary, Time, DIFF_MAX, MAX_DEPTH, MAX_ITEM,
};

/// Most names `--delete` keeps of what the sender sent, all open directories' together.
const MAX_SEEN: usize = 4_000_000;

/// Most files `--atomic` keeps to rename at the end.
const MAX_DEFERRED: usize = 1_000_000;

/// Where what is copied lands.
#[derive(Debug)]
pub enum Target {
    /// Each item inside this directory, under its own name. `named` is its name when it was there
    /// and nothing else said to copy into it (a `/` at its end, several sources): a tree of that
    /// name is brought into line with it, as the tree's contents (`X/.`) would be, rather than
    /// nested in it as `cp`'s rule would (`koh cp -r X S:X` run again).
    Into {
        dir: Option<OwnedFd>,
        shown: PathBuf,
        named: Option<Name>,
    },
    /// The one item, as `name` in this directory.
    As {
        dir: Option<OwnedFd>,
        name: Name,
        shown: PathBuf,
    },
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
                    Ok(meta) if meta.is_dir() => Self::Into {
                        dir: Some(fsat::open_dir_path(path).map_err(io)?),
                        shown: path.clone(),
                        named: path
                            .file_name()
                            .and_then(|name| Name::new(name.as_bytes().to_vec()).ok())
                            .filter(|_| !names_dir),
                    },
                    Ok(_) if count > 1 => return Err(Failure::new(FailKind::SeveralIntoOne, path)),
                    Ok(_) if names_dir => return Err(Failure::new(FailKind::NotADirectory, path)),
                    Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(io(error)),
                    _ if names_dir => {
                        made = made_dirs(path);
                        Self::Into {
                            dir: made_path(path, dry).map_err(io)?,
                            shown: path.clone(),
                            named: None,
                        }
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
                            shown: path.clone(),
                        }
                    }
                }
            }
            Dest::Beneath { root, path, dir } => {
                let shown: PathBuf = path.iter().map(Name::os).collect();
                let io = |error: io::Error| Failure::io(&shown, &error);
                let root_fd = fsat::open_dir_path(root).map_err(io)?;
                let names_dir = *dir || count > 1;
                match path.split_last() {
                    None => Self::Into {
                        dir: Some(root_fd),
                        shown,
                        named: None,
                    },
                    Some((last, parents)) => {
                        let parent = if dry {
                            let (parent, missing) = fsat::walk_dry(root_fd, parents).map_err(io)?;
                            made = missing;
                            parent
                        } else {
                            Some(fsat::walk(root_fd, parents, true, &mut made).map_err(io)?)
                        };
                        match stat_in(parent.as_ref(), last).map_err(io)?.map(|e| e.kind) {
                            Some(Kind::Dir) => Self::Into {
                                dir: parent
                                    .as_ref()
                                    .map(|parent| fsat::open_dir(parent, last.os()))
                                    .transpose()
                                    .map_err(io)?,
                                shown,
                                named: (!names_dir).then(|| last.clone()),
                            },
                            Some(Kind::Link) => {
                                return Err(Failure::new(FailKind::IsASymlink, &shown))
                            }
                            Some(_) if count > 1 => {
                                return Err(Failure::new(FailKind::SeveralIntoOne, &shown))
                            }
                            Some(_) if names_dir => {
                                return Err(Failure::new(FailKind::NotADirectory, &shown))
                            }
                            None if names_dir => {
                                let dir = match parent {
                                    Some(parent) if !dry => Some(
                                        fsat::walk(
                                            parent,
                                            std::slice::from_ref(last),
                                            true,
                                            &mut made,
                                        )
                                        .map_err(io)?,
                                    ),
                                    _ => {
                                        made = made.saturating_add(1);
                                        None
                                    }
                                };
                                Self::Into {
                                    dir,
                                    shown,
                                    named: None,
                                }
                            }
                            Some(_) | None => Self::As {
                                dir: parent,
                                name: last.clone(),
                                shown,
                            },
                        }
                    }
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

/// Entry `name` of `dir`, if it has one: a dry run's directory to be made has none.
fn stat_in(dir: Option<&OwnedFd>, name: &Name) -> io::Result<Option<fsat::Entry>> {
    dir.map_or(Ok(None), |dir| fsat::stat(dir, name.os()))
}

/// Another descriptor of `dir`, if it is one.
fn dup(dir: Option<&OwnedFd>, shown: &Path) -> Result<Option<OwnedFd>, Failure> {
    dir.map(OwnedFd::try_clone)
        .transpose()
        .map_err(|e| Failure::io(shown, &e))
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

/// A directory open for what is copied into it.
struct Open {
    fd: Option<OwnedFd>,
    /// Its path from the target, to say.
    rel: PathBuf,
    /// Its names from the target's directory, for `--atomic`'s renames at the end.
    names: Vec<Name>,
    /// The names the sender sent into it (and the parts of files under way): what is not among
    /// them is removed (`--delete`) or counted as kept. None past [`MAX_SEEN`] without `--delete`.
    seen: Option<HashSet<Vec<u8>>>,
    /// The mode and time it gets at its end.
    mode: Option<Mode>,
    mtime: Option<Time>,
}

/// A file whose header came, awaiting its bytes or [`Item::Same`].
struct Pending {
    dir: Option<OwnedFd>,
    names: Vec<Name>,
    name: Name,
    rel: PathBuf,
    mode: Mode,
    mtime: Option<Time>,
    size: u64,
    /// A file was there, which this replaces.
    existed: bool,
    /// Its size, if it was a file.
    was: Option<u64>,
}

struct Receiver<'a, R: Read> {
    input: R,
    buf: Vec<u8>,
    opts: &'a Opts,
    answer: &'a mut dyn FnMut(Reply) -> bool,
    open: Vec<Open>,
    pending: HashMap<FileId, Pending>,
    seen: usize,
    summary: Summary,
    /// `--atomic`'s: parts to rename into place, and entries to remove, once all came.
    renames: Vec<(Vec<Name>, Name, Name)>,
    removals: Vec<(Vec<Name>, Name)>,
    /// The target's directory, which `--atomic`'s ends are reached from.
    top: Option<OwnedFd>,
}

fn cut() -> Failure {
    Failure::new(FailKind::Truncated, Path::new(""))
}

fn malformed() -> Failure {
    Failure::new(FailKind::Malformed, Path::new(""))
}

/// Land what `input` brings at `target` under `opts`, answering on `answer`.
///
/// `answer` says `false` once the sender is gone; the input is read on to its end all the same.
/// What was done, or why it stopped: what landed before a failure stays, and a file under way
/// keeps its part for the next copy.
pub fn receive(
    input: impl Read,
    target: &Target,
    opts: &Opts,
    answer: &mut dyn FnMut(Reply) -> bool,
) -> Result<Summary, Failure> {
    let mut receiver = Receiver {
        input,
        buf: Vec::new(),
        opts,
        answer,
        open: Vec::new(),
        pending: HashMap::new(),
        seen: 0,
        summary: Summary::default(),
        renames: Vec::new(),
        removals: Vec::new(),
        top: None,
    };
    receiver.run(target)
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

    /// Answer the sender. One gone hears nothing, but what it sent before it went is still
    /// landed: the bytes of a file answered earlier, behind this header, may be here already, and
    /// a cut copy keeps them for the next one. The input ends where the sender stopped.
    fn tell(&mut self, answer: Answer) {
        (self.answer)(Reply::Answer(answer));
    }

    /// Note `name` as sent into the open directory, for `--delete`.
    fn saw(&mut self, name: &[u8]) -> Result<(), Failure> {
        let delete = self.opts.delete;
        let Some(open) = self.open.last_mut() else {
            return Ok(());
        };
        if let Some(seen) = open.seen.as_mut() {
            if seen.insert(name.to_vec()) {
                self.seen = self.seen.saturating_add(1);
                if self.seen > MAX_SEEN {
                    if delete {
                        return Err(Failure::new(FailKind::TooMany, Path::new("")));
                    }
                    // Only counted: what is kept goes uncounted here.
                    self.seen = self.seen.saturating_sub(seen.len());
                    open.seen = None;
                }
            }
        }
        Ok(())
    }

    fn run(&mut self, target: &Target) -> Result<Summary, Failure> {
        self.top = match target {
            Target::Into { dir, shown, .. } | Target::As { dir, shown, .. } => {
                dup(dir.as_ref(), shown)?
            }
        };
        let mut placed: usize = 0;
        loop {
            let mut item = self.next()?;
            // A tree named as the directory it is copied to is that directory: its contents.
            if let Item::Dir { name, mode, mtime } = &item {
                if self.open.is_empty()
                    && matches!(target, Target::Into { named: Some(named), .. } if named == name)
                {
                    item = Item::Contents {
                        mode: *mode,
                        mtime: *mtime,
                    };
                }
            }
            // Where an entry goes: in the open directory, or at the top, where the target says.
            let at_top = self.open.is_empty();
            match item {
                Item::Done => {
                    if !at_top || !self.pending.is_empty() {
                        return Err(malformed());
                    }
                    self.finish()?;
                    // A file's change is known when its answer is: listed in order of path.
                    self.summary.changes.sort_by(|a, b| a.path.cmp(&b.path));
                    return Ok(std::mem::take(&mut self.summary));
                }
                Item::Failed(failure) => return Err(failure),
                Item::End if !at_top => self.leave()?,
                Item::Skipped(name) if !at_top => {
                    self.saw(name.as_bytes())?;
                    let rel = self.rel(&name);
                    self.summary.skip(&rel);
                }
                Item::Data { id, from } => self.data(id, from)?,
                Item::Same(id) => self.same(id)?,
                Item::Differs { id, from } => self.differs(id, from)?,
                Item::Contents { mode, mtime } if at_top => {
                    placed = placed.saturating_add(1);
                    match target {
                        Target::Into { dir, shown, .. } => {
                            let fd = dup(dir.as_ref(), shown)?;
                            self.open.push(Open {
                                fd,
                                rel: PathBuf::new(),
                                names: Vec::new(),
                                seen: Some(HashSet::new()),
                                mode: None,
                                mtime: mtime.filter(|_| self.opts.keep_times),
                            });
                        }
                        Target::As { dir, name, shown } => {
                            let dir = dup(dir.as_ref(), shown)?;
                            self.enter(dir.as_ref(), name, mode, mtime)?;
                        }
                    }
                }
                Item::Dir { name, mode, mtime } => {
                    let (dir, name) = self.place(target, name, &mut placed)?;
                    self.enter(dir.as_ref(), &name, mode, mtime)?;
                }
                Item::File {
                    id,
                    name,
                    mode,
                    mtime,
                    size,
                } => {
                    let (dir, name) = self.place(target, name, &mut placed)?;
                    self.file(dir, id, name, (mode, mtime, size))?;
                }
                Item::Symlink { name, target: link } => {
                    let (dir, name) = self.place(target, name, &mut placed)?;
                    self.symlink(dir.as_ref(), &name, &link)?;
                }
                Item::End
                | Item::Skipped(_)
                | Item::Contents { .. }
                | Item::Chunk(_)
                | Item::Sent => return Err(malformed()),
            }
        }
    }

    /// The directory an entry named `name` goes in, and the name it lands as: the open
    /// directory's, or at the top as `target` says.
    fn place(
        &mut self,
        target: &Target,
        name: Name,
        placed: &mut usize,
    ) -> Result<(Option<OwnedFd>, Name), Failure> {
        if let Some(open) = self.open.last() {
            return Ok((dup(open.fd.as_ref(), &open.rel)?, name));
        }
        let nth = *placed;
        *placed = placed.saturating_add(1);
        match target {
            Target::Into { dir, shown, .. } => {
                self.summary.inside = Some(String::from_utf8_lossy(name.as_bytes()).into_owned());
                Ok((dup(dir.as_ref(), shown)?, name))
            }
            Target::As { dir, name, shown } if nth == 0 => {
                Ok((dup(dir.as_ref(), shown)?, name.clone()))
            }
            Target::As { shown, .. } => Err(Failure::new(FailKind::SeveralIntoOne, shown)),
        }
    }

    /// The path of `name` in the open directory, from the target, to say.
    fn rel(&self, name: &Name) -> PathBuf {
        self.open
            .last()
            .map_or_else(PathBuf::new, |open| open.rel.clone())
            .join(name.os())
    }

    /// The names from the target's directory to `name` in the open directory.
    fn names(&self, name: &Name) -> Vec<Name> {
        let mut names = self.open.last().map_or_else(Vec::new, |o| o.names.clone());
        names.push(name.clone());
        names
    }

    /// Open directory `name` of `dir` for what follows, made if it is not there.
    fn enter(
        &mut self,
        dir: Option<&OwnedFd>,
        name: &Name,
        mode: Mode,
        mtime: Option<Time>,
    ) -> Result<(), Failure> {
        let rel = self.rel(name);
        if self.open.len() >= MAX_DEPTH {
            return Err(Failure::new(FailKind::TooDeep, &rel));
        }
        self.saw(name.as_bytes())?;
        let io = |error: io::Error| Failure::io(&rel, &error);
        let dry = self.opts.dry_run;
        let made = match stat_in(dir, name).map_err(io)?.map(|e| e.kind) {
            None => true,
            Some(Kind::Dir) => false,
            Some(Kind::Link) => return Err(Failure::new(FailKind::IsASymlink, &rel)),
            Some(Kind::File | Kind::Other) if self.opts.delete => {
                if let Some(dir) = dir {
                    let removed = fsat::remove(dir, name.os(), 0, dry).map_err(io)?;
                    self.summary.deleted = self.summary.deleted.saturating_add(removed);
                }
                if dry {
                    self.summary.change(ChangeKind::Deleted, &rel);
                }
                true
            }
            Some(Kind::File | Kind::Other) => {
                return Err(Failure::new(FailKind::NotADirectory, &rel))
            }
        };
        if made {
            if dry {
                self.summary.change(ChangeKind::Dir, &rel);
            } else if let Some(dir) = dir {
                fsat::make_dir(dir, name.os()).map_err(io)?;
            }
            self.summary.dirs = self.summary.dirs.saturating_add(1);
        }
        let fd = match dir {
            Some(dir) if !(dry && made) => Some(fsat::open_dir(dir, name.os()).map_err(io)?),
            _ => None,
        };
        let names = self.names(name);
        self.open.push(Open {
            fd,
            rel,
            names,
            seen: Some(HashSet::new()),
            mode: (made || self.opts.keep_times).then_some(mode),
            mtime: mtime.filter(|_| self.opts.keep_times),
        });
        Ok(())
    }

    /// The open directory is done: remove what the sender did not send, if asked, and give it its
    /// mode and time.
    fn leave(&mut self) -> Result<(), Failure> {
        let Some(open) = self.open.pop() else {
            return Err(malformed());
        };
        let io = |error: io::Error| Failure::io(&open.rel, &error);
        let dry = self.opts.dry_run;
        // A dry run's directory to be made holds nothing to remove, and takes no mode.
        let Some(fd) = &open.fd else {
            if let Some(seen) = &open.seen {
                self.seen = self.seen.saturating_sub(seen.len());
            }
            return Ok(());
        };
        if let Some(seen) = &open.seen {
            self.seen = self.seen.saturating_sub(seen.len());
            for entry in fsat::names(fd).map_err(io)? {
                let path = open.rel.join(OsStr::from_bytes(&entry));
                let excluded = self
                    .opts
                    .excludes
                    .excludes(&entry, path.as_os_str().as_bytes());
                if seen.contains(&entry) || excluded {
                    continue;
                }
                if !self.opts.delete {
                    self.summary.kept = self.summary.kept.saturating_add(1);
                    continue;
                }
                let Ok(name) = Name::new(entry) else { continue };
                if self.opts.atomic && !dry {
                    self.defer()?;
                    self.removals.push((open.names.clone(), name));
                } else {
                    let removed = fsat::remove(fd, name.os(), 0, dry).map_err(io)?;
                    self.summary.deleted = self.summary.deleted.saturating_add(removed);
                    if dry {
                        self.summary.change(ChangeKind::Deleted, &path);
                    }
                }
            }
        }
        if dry {
            return Ok(());
        }
        if let Some(mode) = open.mode {
            fsat::chmod(fd, mode.landed()).map_err(io)?;
        }
        if let Some(time) = open.mtime {
            fsat::set_mtime(fd, time).map_err(io)?;
        }
        Ok(())
    }

    /// Room for one more of `--atomic`'s ends, or [`FailKind::TooMany`].
    fn defer(&self) -> Result<(), Failure> {
        if self.renames.len().saturating_add(self.removals.len()) >= MAX_DEFERRED {
            return Err(Failure::new(FailKind::TooMany, Path::new("")));
        }
        Ok(())
    }

    /// A file's header: answer it.
    fn file(
        &mut self,
        dir: Option<OwnedFd>,
        id: FileId,
        name: Name,
        (mode, mtime, size): (Mode, Option<Time>, u64),
    ) -> Result<(), Failure> {
        let rel = self.rel(&name);
        let io = |error: io::Error| Failure::io(&rel, &error);
        self.saw(name.as_bytes())?;
        let there = stat_in(dir.as_ref(), &name).map_err(io)?;
        // A dry run's diff compares any two files small enough, sizes alike or not.
        let small = |size| usize::try_from(size).is_ok_and(|size| size <= DIFF_MAX);
        let compared = |there| self.opts.dry_run && self.opts.diff && small(there) && small(size);
        let answer = match (there, &dir) {
            (Some(e), _) if e.kind == Kind::Dir => {
                return Err(Failure::new(FailKind::IsADirectory, &rel))
            }
            (Some(e), Some(dir))
                if e.kind == Kind::File && (e.size == size || compared(e.size)) =>
            {
                let file = fsat::open_file(dir, name.os()).map_err(io)?;
                Answer::Check {
                    id,
                    hash: hash_of(&file, None).map_err(io)?,
                }
            }
            _ => {
                let part = part_name(&name);
                self.saw(part.as_bytes())?;
                let kept = stat_in(dir.as_ref(), &part)
                    .map_err(io)?
                    .filter(|p| p.kind == Kind::File && p.size > 0 && p.size <= size)
                    .zip(dir.as_ref());
                match kept {
                    Some((p, dir)) => {
                        let file = fsat::open_file(dir, part.os()).map_err(io)?;
                        Answer::Want {
                            id,
                            have: p.size,
                            prefix: Some(hash_of(&file, Some(p.size)).map_err(io)?),
                        }
                    }
                    None => Answer::Want {
                        id,
                        have: 0,
                        prefix: None,
                    },
                }
            }
        };
        let names = self.names(&name);
        self.pending.insert(
            id,
            Pending {
                dir,
                names,
                name,
                rel,
                mode,
                mtime,
                size,
                existed: there.is_some(),
                was: there.filter(|e| e.kind == Kind::File).map(|e| e.size),
            },
        );
        self.tell(answer);
        Ok(())
    }

    /// The next of a file's chunks, into `buf`, its length; `None` once it is all sent.
    fn chunk(&mut self) -> Result<Option<u64>, Failure> {
        match self.next()? {
            Item::Chunk(len) => {
                let len: DataLen = len;
                self.buf.resize(len.get(), 0);
                self.input.read_exact(&mut self.buf).map_err(|_cut| cut())?;
                let n = u64::try_from(len.get()).unwrap_or(u64::MAX);
                self.summary.bytes = self.summary.bytes.saturating_add(n);
                Ok(Some(n))
            }
            Item::Sent => Ok(None),
            Item::Dir { .. }
            | Item::Contents { .. }
            | Item::File { .. }
            | Item::Symlink { .. }
            | Item::End
            | Item::Skipped(_)
            | Item::Data { .. }
            | Item::Same(_)
            | Item::Differs { .. }
            | Item::Failed(_)
            | Item::Done => Err(malformed()),
        }
    }

    /// File `id`'s bytes from `from`: into its part, then it into place.
    fn data(&mut self, id: FileId, from: u64) -> Result<(), Failure> {
        if self.opts.dry_run {
            return self.compare(id, from);
        }
        let Some((p, dir)) = self
            .pending
            .remove(&id)
            .and_then(|mut p| p.dir.take().map(|dir| (p, dir)))
        else {
            return Err(malformed());
        };
        let io = |error: io::Error| Failure::io(&p.rel, &error);
        let part = part_name(&p.name);
        let file: File = fsat::create(&dir, part.os(), from == 0).map_err(io)?;
        file.set_len(from).map_err(io)?;
        let mut at = from;
        while let Some(n) = self.chunk()? {
            file.write_all_at(&self.buf, at).map_err(io)?;
            at = at.saturating_add(n);
        }
        file.set_permissions(std::fs::Permissions::from_mode(p.mode.landed()))
            .map_err(io)?;
        if let Some(time) = p.mtime.filter(|_| self.opts.keep_times) {
            fsat::set_mtime(&file, time).map_err(io)?;
        }
        drop(file);
        if self.opts.atomic {
            self.defer()?;
            let mut dir_names = p.names.clone();
            dir_names.pop();
            self.renames.push((dir_names, part, p.name.clone()));
        } else {
            fsat::rename(&dir, part.os(), p.name.os()).map_err(io)?;
        }
        self.written(&p, from, None);
        Ok(())
    }

    /// In a dry run with `--diff`, file `id`'s bytes, sent whole to compare with the one here:
    /// it would replace it, differing as the diff says.
    fn compare(&mut self, id: FileId, from: u64) -> Result<(), Failure> {
        let Some(p) = self
            .pending
            .remove(&id)
            .filter(|_| self.opts.diff && from == 0)
        else {
            return Err(malformed());
        };
        let mut sent = Vec::new();
        while self.chunk()?.is_some() {
            if sent.len().saturating_add(self.buf.len()) <= DIFF_MAX {
                sent.extend_from_slice(&self.buf);
            }
        }
        let mut here = Vec::new();
        let read = p.dir.as_ref().map(|dir| {
            let file = fsat::open_file(dir, p.name.os())?;
            let max = u64::try_from(DIFF_MAX).unwrap_or(u64::MAX);
            file.take(max).read_to_end(&mut here)
        });
        let diff = match read {
            Some(Ok(_)) if u64::try_from(sent.len()).is_ok_and(|n| n == p.size) => {
                super::text_diff(&here, &sent, &p.rel)
            }
            Some(Ok(_)) => "no diff: it changed while it was read\n".to_owned(),
            Some(Err(error)) => return Err(Failure::io(&p.rel, &error)),
            None => return Err(malformed()),
        };
        self.written(&p, 0, Some(diff));
        Ok(())
    }

    /// File `p` was written, from byte `from` on (or would be, in a dry run, differing from the
    /// one there as `diff` says).
    fn written(&mut self, p: &Pending, from: u64, diff: Option<String>) {
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
            self.summary
                .change_sized(kind, &p.rel, (Some(p.size), p.was), diff);
        }
    }

    /// In a dry run, file `id` differs from the one here, or there is none: it would be sent from
    /// byte `from`.
    fn differs(&mut self, id: FileId, from: u64) -> Result<(), Failure> {
        let Some(p) = self.pending.remove(&id).filter(|_| self.opts.dry_run) else {
            return Err(malformed());
        };
        let bytes = p.size.saturating_sub(from);
        self.summary.bytes = self.summary.bytes.saturating_add(bytes);
        let diff = (self.opts.diff && p.was.is_some()).then(|| "no diff: over 1 MiB\n".to_owned());
        self.written(&p, from, diff);
        Ok(())
    }

    /// File `id` is the same as the one here: it keeps its time, unless asked for the source's,
    /// and takes the source's mode.
    fn same(&mut self, id: FileId) -> Result<(), Failure> {
        let Some(p) = self.pending.remove(&id) else {
            return Err(malformed());
        };
        self.summary.unchanged = self.summary.unchanged.saturating_add(1);
        if self.opts.dry_run {
            return Ok(());
        }
        let Some(dir) = &p.dir else {
            return Err(malformed());
        };
        let io = |error: io::Error| Failure::io(&p.rel, &error);
        let file = fsat::open_file(dir, p.name.os()).map_err(io)?;
        let here = fsat::stat_of(&file).map_err(io)?;
        if here.mode != p.mode.landed() {
            file.set_permissions(std::fs::Permissions::from_mode(p.mode.landed()))
                .map_err(io)?;
        }
        if let Some(time) = p
            .mtime
            .filter(|t| self.opts.keep_times && here.mtime != Some(*t))
        {
            fsat::set_mtime(&file, time).map_err(io)?;
        }
        Ok(())
    }

    /// A symlink, made or put in place of what is there, unless it is the same already.
    fn symlink(
        &mut self,
        dir: Option<&OwnedFd>,
        name: &Name,
        link: &LinkTarget,
    ) -> Result<(), Failure> {
        let rel = self.rel(name);
        let io = |error: io::Error| Failure::io(&rel, &error);
        self.saw(name.as_bytes())?;
        let dry = self.opts.dry_run;
        match (stat_in(dir, name).map_err(io)?.map(|e| e.kind), dir) {
            (Some(Kind::Dir), _) => return Err(Failure::new(FailKind::IsADirectory, &rel)),
            // The same already: not a file, so not counted among those unchanged.
            (Some(Kind::Link), Some(dir))
                if fsat::read_link(dir, name.os()).map_err(io)? == link.0 =>
            {
                return Ok(());
            }
            _ if dry => self.summary.change(ChangeKind::Link, &rel),
            (None, Some(dir)) => fsat::symlink(&link.0, dir, name.os()).map_err(io)?,
            (Some(Kind::Link | Kind::File | Kind::Other), Some(dir)) => {
                let part = part_name(name);
                let _ = fsat::remove(dir, part.os(), MAX_DEPTH, false);
                fsat::symlink(&link.0, dir, part.os()).map_err(io)?;
                fsat::rename(dir, part.os(), name.os()).map_err(io)?;
            }
            (_, None) => return Err(malformed()),
        }
        self.summary.links = self.summary.links.saturating_add(1);
        Ok(())
    }

    /// All came: `--atomic`'s renames and removals.
    fn finish(&mut self) -> Result<(), Failure> {
        let Some(top) = self.top.take() else {
            return Ok(());
        };
        for (names, part, name) in std::mem::take(&mut self.renames) {
            let rel: PathBuf = names.iter().map(Name::os).collect();
            let io = |error: io::Error| Failure::io(&rel, &error);
            let from = top.try_clone().map_err(io)?;
            let dir = fsat::walk(from, &names, false, &mut 0).map_err(io)?;
            fsat::rename(&dir, part.os(), name.os()).map_err(io)?;
        }
        for (names, name) in std::mem::take(&mut self.removals) {
            let rel: PathBuf = names.iter().map(Name::os).collect();
            let io = |error: io::Error| Failure::io(&rel, &error);
            let from = top.try_clone().map_err(io)?;
            let dir = fsat::walk(from, &names, false, &mut 0).map_err(io)?;
            let removed = fsat::remove(&dir, name.os(), 0, false).map_err(io)?;
            self.summary.deleted = self.summary.deleted.saturating_add(removed);
        }
        Ok(())
    }
}
