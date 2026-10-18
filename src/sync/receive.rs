//! The receiving end of a copy: land each entry where it goes, answer each file's header, and
//! count what was done.

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
    hash_of, Answer, DataLen, FailKind, Failure, FileId, Item, LinkTarget, Mode, Name, Opts, Reply,
    Summary, Time, MAX_DEPTH, MAX_ITEM,
};

/// Most names `--delete` keeps of what the sender sent, all open directories' together.
const MAX_SEEN: usize = 4_000_000;

/// Most files `--atomic` keeps to rename at the end.
const MAX_DEFERRED: usize = 1_000_000;

/// Where what is copied lands.
#[derive(Debug)]
pub enum Target {
    /// Each item inside this directory, under its own name. `nest` is its name when it was there
    /// and nothing else said to copy into it (a `/` at its end, several sources): `cp`'s rule
    /// puts a tree of that name inside it, which is refused, as one copied there again would be.
    Into {
        dir: OwnedFd,
        shown: PathBuf,
        nest: Option<Name>,
    },
    /// The one item, as `name` in this directory.
    As {
        dir: OwnedFd,
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
    /// missing; with the directories made.
    pub fn resolve(dest: &Dest, count: usize) -> Result<(Self, u64), Failure> {
        let mut made = 0;
        let target = match dest {
            Dest::Path(path) => {
                let names_dir = path.as_os_str().as_bytes().ends_with(b"/") || count > 1;
                let io = |error: io::Error| Failure::io(path, &error);
                match std::fs::metadata(path) {
                    Ok(meta) if meta.is_dir() => Self::Into {
                        dir: fsat::open_dir_path(path).map_err(io)?,
                        shown: path.clone(),
                        nest: path
                            .file_name()
                            .and_then(|name| Name::new(name.as_bytes().to_vec()).ok())
                            .filter(|_| !names_dir),
                    },
                    Ok(_) if count > 1 => return Err(Failure::new(FailKind::SeveralIntoOne, path)),
                    Ok(_) if names_dir => return Err(Failure::new(FailKind::NotADirectory, path)),
                    Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(io(error)),
                    _ if names_dir => {
                        made = made_dirs(path);
                        std::fs::create_dir_all(path).map_err(io)?;
                        Self::Into {
                            dir: fsat::open_dir_path(path).map_err(io)?,
                            shown: path.clone(),
                            nest: None,
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
                        std::fs::create_dir_all(parent).map_err(io)?;
                        Self::As {
                            dir: fsat::open_dir_path(parent).map_err(io)?,
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
                        dir: root_fd,
                        shown,
                        nest: None,
                    },
                    Some((last, parents)) => {
                        let parent = fsat::walk(root_fd, parents, true, &mut made).map_err(io)?;
                        match fsat::stat(&parent, last.os()).map_err(io)?.map(|e| e.kind) {
                            Some(Kind::Dir) => Self::Into {
                                dir: fsat::open_dir(&parent, last.os()).map_err(io)?,
                                shown,
                                nest: (!names_dir).then(|| last.clone()),
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
                                let dir =
                                    fsat::walk(parent, std::slice::from_ref(last), true, &mut made)
                                        .map_err(io)?;
                                Self::Into {
                                    dir,
                                    shown,
                                    nest: None,
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
    fd: OwnedFd,
    /// Its path from the target, to say.
    rel: PathBuf,
    /// Its names from the target's directory, for `--atomic`'s renames at the end.
    names: Vec<Name>,
    /// The names the sender sent into it (and the parts of files under way), for `--delete`.
    seen: Option<HashSet<Vec<u8>>>,
    /// The mode and time it gets at its end.
    mode: Option<Mode>,
    mtime: Option<Time>,
}

/// A file whose header came, awaiting its bytes or [`Item::Same`].
struct Pending {
    dir: OwnedFd,
    names: Vec<Name>,
    name: Name,
    rel: PathBuf,
    mode: Mode,
    mtime: Option<Time>,
    /// A file was there, which this replaces.
    existed: bool,
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
/// `answer` says `false` once the sender is gone. What was done, or why it stopped: what landed
/// before a failure stays, and a file under way keeps its part for the next copy.
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

    fn tell(&mut self, answer: Answer) -> Result<(), Failure> {
        if (self.answer)(Reply::Answer(answer)) {
            Ok(())
        } else {
            Err(cut())
        }
    }

    /// Note `name` as sent into the open directory, for `--delete`.
    fn saw(&mut self, name: &[u8]) -> Result<(), Failure> {
        if let Some(seen) = self.open.last_mut().and_then(|open| open.seen.as_mut()) {
            if seen.insert(name.to_vec()) {
                self.seen = self.seen.saturating_add(1);
                if self.seen > MAX_SEEN {
                    return Err(Failure::new(FailKind::TooMany, Path::new("")));
                }
            }
        }
        Ok(())
    }

    fn run(&mut self, target: &Target) -> Result<Summary, Failure> {
        let top_dir = match target {
            Target::Into { dir, shown, .. } | Target::As { dir, shown, .. } => {
                dir.try_clone().map_err(|e| Failure::io(shown, &e))?
            }
        };
        self.top = Some(top_dir);
        let mut placed: usize = 0;
        loop {
            let item = self.next()?;
            // Where an entry goes: in the open directory, or at the top, where the target says.
            let at_top = self.open.is_empty();
            match item {
                Item::Done => {
                    if !at_top || !self.pending.is_empty() {
                        return Err(malformed());
                    }
                    self.finish()?;
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
                Item::Contents { mode, mtime } if at_top => {
                    placed = placed.saturating_add(1);
                    match target {
                        Target::Into { dir, shown, .. } => {
                            let fd = dir.try_clone().map_err(|e| Failure::io(shown, &e))?;
                            self.open.push(Open {
                                fd,
                                rel: PathBuf::new(),
                                names: Vec::new(),
                                seen: self.opts.delete.then(HashSet::new),
                                mode: None,
                                mtime: mtime.filter(|_| self.opts.keep_times),
                            });
                        }
                        Target::As { dir, name, shown } => {
                            let dir = dir.try_clone().map_err(|e| Failure::io(shown, &e))?;
                            self.enter(&dir, name, mode, mtime)?;
                        }
                    }
                }
                Item::Dir { name, mode, mtime } => {
                    if let (
                        true,
                        Target::Into {
                            nest: Some(nest),
                            shown,
                            ..
                        },
                    ) = (at_top, target)
                    {
                        if *nest == name {
                            return Err(Failure::new(FailKind::Nests, shown));
                        }
                    }
                    let (dir, name) = self.place(target, name, &mut placed)?;
                    self.enter(&dir, &name, mode, mtime)?;
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
                    self.symlink(&dir, &name, &link)?;
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
    ) -> Result<(OwnedFd, Name), Failure> {
        if let Some(open) = self.open.last() {
            let fd = open
                .fd
                .try_clone()
                .map_err(|e| Failure::io(&open.rel, &e))?;
            return Ok((fd, name));
        }
        let nth = *placed;
        *placed = placed.saturating_add(1);
        match target {
            Target::Into { dir, shown, .. } => {
                self.summary.inside = Some(String::from_utf8_lossy(name.as_bytes()).into_owned());
                Ok((dir.try_clone().map_err(|e| Failure::io(shown, &e))?, name))
            }
            Target::As { dir, name, shown } if nth == 0 => Ok((
                dir.try_clone().map_err(|e| Failure::io(shown, &e))?,
                name.clone(),
            )),
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
        dir: &OwnedFd,
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
        let made = match fsat::stat(dir, name.os()).map_err(io)?.map(|e| e.kind) {
            None => true,
            Some(Kind::Dir) => false,
            Some(Kind::Link) => return Err(Failure::new(FailKind::IsASymlink, &rel)),
            Some(Kind::File | Kind::Other) if self.opts.delete => {
                let removed = fsat::remove(dir, name.os(), 0).map_err(io)?;
                self.summary.deleted = self.summary.deleted.saturating_add(removed);
                true
            }
            Some(Kind::File | Kind::Other) => {
                return Err(Failure::new(FailKind::NotADirectory, &rel))
            }
        };
        if made {
            fsat::make_dir(dir, name.os()).map_err(io)?;
            self.summary.dirs = self.summary.dirs.saturating_add(1);
        }
        let fd = fsat::open_dir(dir, name.os()).map_err(io)?;
        let names = self.names(name);
        self.open.push(Open {
            fd,
            rel,
            names,
            seen: self.opts.delete.then(HashSet::new),
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
        if let Some(seen) = &open.seen {
            self.seen = self.seen.saturating_sub(seen.len());
            for entry in fsat::names(&open.fd).map_err(io)? {
                let path = open.rel.join(OsStr::from_bytes(&entry));
                let excluded = self
                    .opts
                    .excludes
                    .excludes(&entry, path.as_os_str().as_bytes());
                if seen.contains(&entry) || excluded {
                    continue;
                }
                let Ok(name) = Name::new(entry) else { continue };
                if self.opts.atomic {
                    self.defer()?;
                    self.removals.push((open.names.clone(), name));
                } else {
                    let removed = fsat::remove(&open.fd, name.os(), 0).map_err(io)?;
                    self.summary.deleted = self.summary.deleted.saturating_add(removed);
                }
            }
        }
        if let Some(mode) = open.mode {
            fsat::chmod(&open.fd, mode.landed()).map_err(io)?;
        }
        if let Some(time) = open.mtime {
            fsat::set_mtime(&open.fd, time).map_err(io)?;
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
        dir: OwnedFd,
        id: FileId,
        name: Name,
        (mode, mtime, size): (Mode, Option<Time>, u64),
    ) -> Result<(), Failure> {
        let rel = self.rel(&name);
        let io = |error: io::Error| Failure::io(&rel, &error);
        self.saw(name.as_bytes())?;
        let there = fsat::stat(&dir, name.os()).map_err(io)?;
        let answer = match there {
            Some(e) if e.kind == Kind::Dir => {
                return Err(Failure::new(FailKind::IsADirectory, &rel))
            }
            Some(e) if e.kind == Kind::File && e.size == size => {
                let file = fsat::open_file(&dir, name.os()).map_err(io)?;
                Answer::Check {
                    id,
                    hash: hash_of(&file, None).map_err(io)?,
                }
            }
            Some(_) | None => {
                let part = part_name(&name);
                self.saw(part.as_bytes())?;
                let kept = fsat::stat(&dir, part.os())
                    .map_err(io)?
                    .filter(|p| p.kind == Kind::File && p.size > 0 && p.size <= size);
                match kept {
                    Some(p) => {
                        let file = fsat::open_file(&dir, part.os()).map_err(io)?;
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
                existed: there.is_some(),
            },
        );
        self.tell(answer)
    }

    /// File `id`'s bytes from `from`: into its part, then it into place.
    fn data(&mut self, id: FileId, from: u64) -> Result<(), Failure> {
        let Some(p) = self.pending.remove(&id) else {
            return Err(malformed());
        };
        let io = |error: io::Error| Failure::io(&p.rel, &error);
        let part = part_name(&p.name);
        let file: File = fsat::create(&p.dir, part.os(), from == 0).map_err(io)?;
        file.set_len(from).map_err(io)?;
        let mut at = from;
        loop {
            match self.next()? {
                Item::Chunk(len) => {
                    let len: DataLen = len;
                    self.buf.resize(len.get(), 0);
                    self.input.read_exact(&mut self.buf).map_err(|_cut| cut())?;
                    file.write_all_at(&self.buf, at).map_err(io)?;
                    let n = u64::try_from(len.get()).unwrap_or(u64::MAX);
                    at = at.saturating_add(n);
                    self.summary.bytes = self.summary.bytes.saturating_add(n);
                }
                Item::Sent => break,
                Item::Dir { .. }
                | Item::Contents { .. }
                | Item::File { .. }
                | Item::Symlink { .. }
                | Item::End
                | Item::Skipped(_)
                | Item::Data { .. }
                | Item::Same(_)
                | Item::Failed(_)
                | Item::Done => return Err(malformed()),
            }
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
            fsat::rename(&p.dir, part.os(), p.name.os()).map_err(io)?;
        }
        if p.existed {
            self.summary.replaced = self.summary.replaced.saturating_add(1);
        } else {
            self.summary.new = self.summary.new.saturating_add(1);
        }
        if from > 0 {
            self.summary.resumed = self.summary.resumed.saturating_add(1);
        }
        Ok(())
    }

    /// File `id` is the same as the one here: it keeps its time, unless asked for the source's,
    /// and takes the source's mode.
    fn same(&mut self, id: FileId) -> Result<(), Failure> {
        let Some(p) = self.pending.remove(&id) else {
            return Err(malformed());
        };
        let io = |error: io::Error| Failure::io(&p.rel, &error);
        let file = fsat::open_file(&p.dir, p.name.os()).map_err(io)?;
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
        self.summary.unchanged = self.summary.unchanged.saturating_add(1);
        Ok(())
    }

    /// A symlink, made or put in place of what is there, unless it is the same already.
    fn symlink(&mut self, dir: &OwnedFd, name: &Name, link: &LinkTarget) -> Result<(), Failure> {
        let rel = self.rel(name);
        let io = |error: io::Error| Failure::io(&rel, &error);
        self.saw(name.as_bytes())?;
        match fsat::stat(dir, name.os()).map_err(io)?.map(|e| e.kind) {
            None => fsat::symlink(&link.0, dir, name.os()).map_err(io)?,
            Some(Kind::Dir) => return Err(Failure::new(FailKind::IsADirectory, &rel)),
            // The same already: not a file, so not counted among those unchanged.
            Some(Kind::Link) if fsat::read_link(dir, name.os()).map_err(io)? == link.0 => {
                return Ok(());
            }
            Some(Kind::Link | Kind::File | Kind::Other) => {
                let part = part_name(name);
                let _ = fsat::remove(dir, part.os(), MAX_DEPTH);
                fsat::symlink(&link.0, dir, part.os()).map_err(io)?;
                fsat::rename(dir, part.os(), name.os()).map_err(io)?;
            }
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
            let removed = fsat::remove(&dir, name.os(), 0).map_err(io)?;
            self.summary.deleted = self.summary.deleted.saturating_add(removed);
        }
        Ok(())
    }
}
