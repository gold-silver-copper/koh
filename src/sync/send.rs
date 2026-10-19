//! The sending end of a copy: walk the sources, send each entry's header, answer each file's
//! answer with its bytes or with [`Item::Same`] (in a dry run, [`Item::Differs`] in place of
//! the bytes, but with [`super::Opts::diff`] a file the receiver has one of to compare).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use super::fsat::{self, Kind};
use super::{
    hash_of, write_item, Answer, DataLen, FailKind, Failure, FileId, Item, LinkTarget, Mode, Name,
    Opts, Reply, Summary, CHUNK, MAX_DEPTH, MAX_ITEM, WINDOW,
};

/// A source of a copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A path, as the system finds it: followed if it is a symlink, as `cp` follows the paths it
    /// is given. One ending in `.` (`.`, `dir/.`) brings what is in the directory, not the
    /// directory.
    Path(PathBuf),
    /// A path beneath a scoped key's directory, reached from it without following a symlink.
    Beneath { root: PathBuf, path: Vec<Name> },
}

/// What sending one entry came to: `out` failing (outer), or the copy (inner).
type Sending = io::Result<Result<(), Failure>>;

/// Where the copy stopped early: the receiver said it was over.
struct Over(Result<Summary, Failure>);

struct Sender<'a, W: Write> {
    out: io::BufWriter<W>,
    answers: &'a mut dyn FnMut(bool) -> Option<Reply>,
    opts: &'a Opts,
    /// The files whose headers went, awaiting their answers: each one's file, and its path to say.
    pending: HashMap<FileId, (File, PathBuf)>,
    next: u32,
    /// The receiver ended the copy before the end: what it said.
    over: Option<Over>,
}

/// Send `sources` to `out` under `opts`, then [`Item::Done`]; the receiver's word for how it went.
///
/// The receiver's replies come from `answers` (waiting for one if asked, `None` once there are no
/// more). On a failure here, [`Item::Failed`] goes in place of the rest. Fails itself only
/// when `out` does: the other end is gone.
pub fn send(
    sources: &[Source],
    opts: &Opts,
    out: impl Write,
    answers: &mut dyn FnMut(bool) -> Option<Reply>,
) -> io::Result<Result<Summary, Failure>> {
    let mut sender = Sender {
        out: io::BufWriter::with_capacity(CHUNK.saturating_add(MAX_ITEM), out),
        answers,
        opts,
        pending: HashMap::new(),
        next: 0,
        over: None,
    };
    let mut sent = Ok(());
    for source in sources {
        sent = sender.source(source)?;
        if sent.is_err() || sender.over.is_some() {
            break;
        }
    }
    while sent.is_ok() && sender.over.is_none() && !sender.pending.is_empty() {
        sent = sender.answers(true)?;
    }
    if let Some(Over(over)) = sender.over.take() {
        sender.out.flush()?;
        return Ok(over);
    }
    if let Err(failure) = sent {
        write_item(&mut sender.out, &Item::Failed(failure.clone()), &[])?;
        sender.out.flush()?;
        return Ok(Err(failure));
    }
    write_item(&mut sender.out, &Item::Done, &[])?;
    sender.out.flush()?;
    // The receiver's word, once it has landed all.
    loop {
        match (sender.answers)(true) {
            Some(Reply::End(end)) => return Ok(end),
            Some(Reply::Answer(_)) => {}
            None => return Ok(Err(Failure::new(FailKind::Truncated, Path::new("")))),
        }
    }
}

impl<W: Write> Sender<'_, W> {
    /// Send `source`, as its own name, or what is in it if it ends in `.`.
    fn source(&mut self, source: &Source) -> Sending {
        match source {
            Source::Path(path) => {
                let contents =
                    path.as_os_str().as_bytes().ends_with(b"/.") || path.as_os_str() == ".";
                let name = path
                    .file_name()
                    .and_then(|name| Name::new(name.as_bytes().to_vec()).ok());
                let name = match (contents, name) {
                    (true, _) => None,
                    (false, Some(name)) => Some(name),
                    (false, None) => return Ok(Err(Failure::new(FailKind::NoName, path))),
                };
                match std::fs::metadata(path) {
                    Ok(meta) if meta.is_dir() => match fsat::open_dir_path(path) {
                        Ok(dir) => self.dir(&dir, name, Path::new(""), 1),
                        Err(error) => Ok(Err(Failure::io(path, &error))),
                    },
                    Ok(_) if contents => Ok(Err(Failure::new(FailKind::NotADirectory, path))),
                    Ok(meta) if meta.is_file() => match (File::open(path), name) {
                        (Ok(file), Some(name)) => self.file(file, name, path.clone()),
                        (Err(error), _) => Ok(Err(Failure::io(path, &error))),
                        (Ok(_), None) => Ok(Err(Failure::new(FailKind::NoName, path))),
                    },
                    Ok(_) => Ok(Err(Failure::new(FailKind::NotCopyable, path))),
                    Err(error) => Ok(Err(Failure::io(path, &error))),
                }
            }
            Source::Beneath { root, path } => {
                let shown: PathBuf = path.iter().map(Name::os).collect();
                let root_fd = match fsat::open_dir_path(root) {
                    Ok(fd) => fd,
                    Err(error) => return Ok(Err(Failure::io(&shown, &error))),
                };
                let Some((last, parents)) = path.split_last() else {
                    // The key's directory itself: what is in it.
                    return self.dir(&root_fd, None, Path::new(""), 1);
                };
                let parent = match fsat::walk(root_fd, parents, false, &mut 0) {
                    Ok(fd) => fd,
                    Err(error) => return Ok(Err(Failure::io(&shown, &error))),
                };
                self.entry(&parent, last.clone(), &shown, 1, true)
            }
        }
    }

    /// Send entry `name` of `dir`, at `rel` from the top: a directory, a file, a symlink as
    /// itself, anything else skipped (or, at the top, refused).
    fn entry(&mut self, dir: &OwnedFd, name: Name, rel: &Path, depth: usize, top: bool) -> Sending {
        let entry = match fsat::stat(dir, name.os()) {
            Ok(Some(entry)) => entry,
            Ok(None) => return Ok(Err(Failure::new(FailKind::NotFound, rel))),
            Err(error) => return Ok(Err(Failure::io(rel, &error))),
        };
        match entry.kind {
            Kind::Dir => match fsat::open_dir(dir, name.os()) {
                Ok(sub) => self.dir(&sub, Some(name), rel, depth),
                Err(error) => Ok(Err(Failure::io(rel, &error))),
            },
            Kind::File => match fsat::open_file(dir, name.os()) {
                Ok(file) => self.file(file, name, rel.to_path_buf()),
                Err(error) => Ok(Err(Failure::io(rel, &error))),
            },
            Kind::Link => match fsat::read_link(dir, name.os()) {
                Ok(target) => match LinkTarget::new(target) {
                    Ok(target) => {
                        write_item(&mut self.out, &Item::Symlink { name, target }, &[])?;
                        self.answers(false)
                    }
                    Err(_) => Ok(Err(Failure::new(FailKind::NameTooLong, rel))),
                },
                Err(error) => Ok(Err(Failure::io(rel, &error))),
            },
            Kind::Other if top => Ok(Err(Failure::new(FailKind::NotCopyable, rel))),
            Kind::Other => write_item(&mut self.out, &Item::Skipped(name), &[]).map(Ok),
        }
    }

    /// Send directory `dir`, named `name` (`None`: what is in it, into the destination itself),
    /// at `rel` from the top, `depth` deep, and what is in it.
    fn dir(&mut self, dir: &OwnedFd, name: Option<Name>, rel: &Path, depth: usize) -> Sending {
        if depth > MAX_DEPTH {
            return Ok(Err(Failure::new(FailKind::TooDeep, rel)));
        }
        let meta = match fsat::stat_of(dir) {
            Ok(meta) => meta,
            Err(error) => return Ok(Err(Failure::io(rel, &error))),
        };
        let mut names = match fsat::names(dir) {
            Ok(names) => names,
            Err(error) => return Ok(Err(Failure::io(rel, &error))),
        };
        names.sort();
        let mode = Mode::new(meta.mode).unwrap_or(Mode(0o755));
        let rel = match &name {
            Some(name) => rel.join(name.os()),
            None => rel.to_path_buf(),
        };
        let item = match name {
            Some(name) => Item::Dir {
                name,
                mode,
                mtime: meta.mtime,
            },
            None => Item::Contents {
                mode,
                mtime: meta.mtime,
            },
        };
        write_item(&mut self.out, &item, &[])?;
        for entry in names {
            let path = rel.join(OsStr::from_bytes(&entry));
            let Ok(name) = Name::new(entry) else {
                return Ok(Err(Failure::new(FailKind::NameTooLong, &path)));
            };
            if self
                .opts
                .excludes
                .excludes(name.as_bytes(), path.as_os_str().as_bytes())
            {
                continue;
            }
            match self.entry(dir, name, &path, depth.saturating_add(1), false)? {
                Ok(()) if self.over.is_none() => {}
                done => return Ok(done),
            }
        }
        write_item(&mut self.out, &Item::End, &[]).map(Ok)
    }

    /// Send `file`'s header, named `name`, `path` to say; its bytes go once it is answered.
    fn file(&mut self, file: File, name: Name, path: PathBuf) -> Sending {
        let meta = match fsat::stat_of(&file) {
            Ok(meta) => meta,
            Err(error) => return Ok(Err(Failure::io(&path, &error))),
        };
        let id = FileId(self.next);
        self.next = self.next.wrapping_add(1);
        let item = Item::File {
            id,
            name,
            mode: Mode::new(meta.mode).unwrap_or(Mode(0o644)),
            mtime: meta.mtime,
            size: meta.size,
        };
        write_item(&mut self.out, &item, &[])?;
        self.pending.insert(id, (file, path));
        self.answers(self.pending.len() >= WINDOW)
    }

    /// Take the answers there are, waiting for one if `wait`: the receiver must answer the
    /// oldest header before more go.
    fn answers(&mut self, wait: bool) -> Sending {
        if wait {
            // What was written must reach the receiver for it to answer.
            self.out.flush()?;
        }
        let mut block = wait;
        while let Some(reply) = (self.answers)(block) {
            block = false;
            match reply {
                Reply::Answer(answer) => {
                    if let Err(failure) = self.answer(&answer)? {
                        return Ok(Err(failure));
                    }
                }
                Reply::End(end) => {
                    self.over = Some(Over(end));
                    return Ok(Ok(()));
                }
            }
        }
        if wait && block {
            // No answer, and none will come: the receiver is gone.
            self.over = Some(Over(Err(Failure::new(FailKind::Truncated, Path::new("")))));
        }
        Ok(Ok(()))
    }

    /// Act on `answer`: send the file's bytes, or say it is the same.
    fn answer(&mut self, answer: &Answer) -> Sending {
        let id = match answer {
            Answer::Want { id, .. } | Answer::Check { id, .. } => *id,
        };
        let Some((file, path)) = self.pending.remove(&id) else {
            return Ok(Err(Failure::new(FailKind::Malformed, Path::new(""))));
        };
        let from = match answer {
            Answer::Want { have, prefix, .. } => {
                let kept = prefix.filter(|_| *have > 0);
                match kept.map(|prefix| hash_of(&file, Some(*have)).map(|h| h == prefix)) {
                    Some(Ok(true)) => *have,
                    Some(Ok(false)) | None => 0,
                    Some(Err(error)) => return Ok(Err(Failure::io(&path, &error))),
                }
            }
            Answer::Check { hash, .. } => match hash_of(&file, None) {
                Ok(ours) if ours == *hash => {
                    return write_item(&mut self.out, &Item::Same(id), &[]).map(Ok);
                }
                Ok(_) => 0,
                Err(error) => return Ok(Err(Failure::io(&path, &error))),
            },
        };
        // A dry run sends a file only for its end to compare it with the one there (`Check`).
        let compared = self.opts.diff
            && matches!(answer, Answer::Check { .. })
            && file
                .metadata()
                .is_ok_and(|m| u64::try_from(super::DIFF_MAX).is_ok_and(|max| m.len() <= max));
        if self.opts.dry_run && !compared {
            return write_item(&mut self.out, &Item::Differs { id, from }, &[]).map(Ok);
        }
        self.data(id, &file, from, &path)
    }

    /// Send file `id`'s bytes from `from` to its end.
    fn data(&mut self, id: FileId, file: &File, from: u64, path: &Path) -> Sending {
        use std::os::unix::fs::FileExt as _;
        write_item(&mut self.out, &Item::Data { id, from }, &[])?;
        let mut buf = vec![0u8; CHUNK];
        let mut at = from;
        loop {
            let n = match file.read_at(&mut buf, at) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Ok(Err(Failure::io(path, &error))),
            };
            let (Some(len), Some(data)) = (DataLen::new(n), buf.get(..n)) else {
                return Ok(Err(Failure::new(FailKind::Other, path)));
            };
            write_item(&mut self.out, &Item::Chunk(len), data)?;
            at = at.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        }
        write_item(&mut self.out, &Item::Sent, &[]).map(Ok)
    }
}
