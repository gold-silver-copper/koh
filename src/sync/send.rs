//! The sending end of a copy: walk the sources, send each entry's header, answer each file's
//! answer with its bytes or with [`Item::Same`] (in a dry run, [`Item::Differs`] in place of
//! the bytes).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use tokio::sync::mpsc;

use super::fsat::{self, Kind};
use super::{
    cut, hash_of, malformed, Answer, DataLen, FailKind, Failure, FileHeader, FileId, Item,
    LinkTarget, Mode, Name, Opts, Reply, Summary, CHUNK, MAX_DEPTH, MAX_ITEM, WINDOW,
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

/// Most bytes of a message to the stream's task: a chunk and its header, or a chunk's worth of
/// items.
const MESSAGE: usize = CHUNK + MAX_ITEM;

/// What is written, gathered into messages of about a chunk for the stream's task.
struct Out {
    tx: mpsc::Sender<Vec<u8>>,
    buf: Vec<u8>,
}

impl Out {
    /// Write `item`, then `data` if it brings any.
    fn item(&mut self, item: &Item, data: &[u8]) -> Result<(), Failure> {
        let head = crate::request::encode(item, MAX_ITEM)
            .map_err(|_too_long| Failure::new(FailKind::Other, Path::new("")))?;
        if self
            .buf
            .len()
            .saturating_add(head.len())
            .saturating_add(data.len())
            > CHUNK
        {
            self.flush()?;
        }
        self.buf.extend_from_slice(&head);
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Hand what was written to the stream's task; the stream gone cuts the copy short.
    fn flush(&mut self) -> Result<(), Failure> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let full = std::mem::replace(&mut self.buf, Vec::with_capacity(MESSAGE));
        self.tx.blocking_send(full).map_err(|_gone| cut())
    }
}

struct Sender<'a> {
    out: Out,
    replies: mpsc::Receiver<Reply>,
    opts: &'a Opts,
    /// The files whose headers went, awaiting their answers: each one's file, and its path to say.
    pending: HashMap<FileId, (File, PathBuf)>,
    next: u32,
    /// The path of the directory sent at the top: `--exclude` matches paths from it, as the
    /// receiver does.
    tree: PathBuf,
    buf: Vec<u8>,
    /// The receiver's word, once it ended the copy.
    over: Option<Result<Summary, Failure>>,
}

/// Send `sources` on `out` under `opts`, then [`Item::Done`] (or, on a failure here,
/// [`Item::Failed`]); the receiver's word for how it went, its replies coming on `replies`.
pub fn send(
    sources: &[Source],
    opts: &Opts,
    out: mpsc::Sender<Vec<u8>>,
    replies: mpsc::Receiver<Reply>,
) -> Result<Summary, Failure> {
    let mut sender = Sender {
        out: Out {
            tx: out,
            buf: Vec::with_capacity(MESSAGE),
        },
        replies,
        opts,
        pending: HashMap::new(),
        next: 0,
        tree: PathBuf::new(),
        buf: vec![0; CHUNK],
        over: None,
    };
    let sent = sender.all(sources);
    if let Some(over) = sender.over {
        return over;
    }
    let last = match &sent {
        Ok(()) => Item::Done,
        Err(failure) => Item::Failed(failure.clone()),
    };
    // The receiver gone, its word may still be on its way.
    let _ = sender
        .out
        .item(&last, &[])
        .and_then(|()| sender.out.flush());
    while let Some(reply) = sender.replies.blocking_recv() {
        if let Reply::End(end) = reply {
            return end;
        }
    }
    sent.and_then(|()| Err(cut()))
}

impl Sender<'_> {
    fn all(&mut self, sources: &[Source]) -> Result<(), Failure> {
        for source in sources {
            self.source(source)?;
        }
        while !self.pending.is_empty() {
            self.answers(true)?;
        }
        Ok(())
    }

    /// Send `source`, as its own name, or what is in it if it ends in `.`.
    fn source(&mut self, source: &Source) -> Result<(), Failure> {
        match source {
            Source::Path(path) => {
                let io = |error: io::Error| Failure::io(path, &error);
                let contents =
                    path.as_os_str().as_bytes().ends_with(b"/.") || path.as_os_str() == ".";
                let name = if contents {
                    None
                } else {
                    let name = path.file_name().map(|name| name.as_bytes().to_vec());
                    let name = name.and_then(|name| Name::new(name).ok());
                    Some(name.ok_or_else(|| Failure::new(FailKind::NoName, path))?)
                };
                let meta = std::fs::metadata(path).map_err(io)?;
                match name {
                    _ if meta.is_dir() => {
                        let dir = fsat::open_dir_path(path).map_err(io)?;
                        let rel = name.as_ref().map_or_else(PathBuf::new, |n| n.os().into());
                        self.dir(&dir, name, &rel, 1)
                    }
                    None => Err(Failure::new(FailKind::NotADirectory, path)),
                    Some(name) if meta.is_file() => {
                        self.file(File::open(path).map_err(io)?, name, path.clone())
                    }
                    Some(_) => Err(Failure::new(FailKind::NotCopyable, path)),
                }
            }
            Source::Beneath { root, path } => {
                let shown: PathBuf = path.iter().map(Name::os).collect();
                let io = |error: io::Error| Failure::io(&shown, &error);
                let root_fd = fsat::open_dir_path(root).map_err(io)?;
                match path.split_last() {
                    // The key's directory itself: what is in it.
                    None => self.dir(&root_fd, None, &shown, 1),
                    Some((last, parents)) => {
                        let parent = fsat::walk(root_fd, parents).map_err(io)?;
                        self.entry(&parent, last.clone(), shown, 1)
                    }
                }
            }
        }
    }

    /// Send entry `name` of `dir`, at `rel` from the top, `depth` deep: a directory, a file, a
    /// symlink as itself, anything else skipped (or, at the top, refused).
    fn entry(
        &mut self,
        dir: &OwnedFd,
        name: Name,
        rel: PathBuf,
        depth: usize,
    ) -> Result<(), Failure> {
        let io = |error: io::Error| Failure::io(&rel, &error);
        match fsat::stat(dir, name.os()).map_err(io)?.map(|e| e.kind) {
            None => Err(Failure::new(FailKind::NotFound, &rel)),
            Some(Kind::Dir) => {
                let sub = fsat::open_dir(dir, name.os()).map_err(io)?;
                self.dir(&sub, Some(name), &rel, depth)
            }
            Some(Kind::File) => {
                let file = fsat::open_file(dir, name.os()).map_err(io)?;
                self.file(file, name, rel)
            }
            Some(Kind::Link) => {
                let target = LinkTarget::new(fsat::read_link(dir, name.os()).map_err(io)?)
                    .map_err(|_too_long| Failure::new(FailKind::NameTooLong, &rel))?;
                self.out.item(&Item::Symlink { name, target }, &[])?;
                self.answers(false)
            }
            Some(Kind::Other) if depth == 1 => Err(Failure::new(FailKind::NotCopyable, &rel)),
            Some(Kind::Other) => self.out.item(&Item::Skipped(name), &[]),
        }
    }

    /// Send directory `dir`, named `name` (`None`: what is in it, into the destination itself),
    /// at `rel` from the top, `depth` deep, and what is in it.
    fn dir(
        &mut self,
        dir: &OwnedFd,
        name: Option<Name>,
        rel: &Path,
        depth: usize,
    ) -> Result<(), Failure> {
        if depth > MAX_DEPTH {
            return Err(Failure::new(FailKind::TooDeep, rel));
        }
        let io = |error: io::Error| Failure::io(rel, &error);
        let meta = fsat::stat_of(dir).map_err(io)?;
        let mut names = fsat::names(dir).map_err(io)?;
        names.sort();
        let (mode, mtime) = (Mode::new(meta.mode).unwrap_or(Mode(0o755)), meta.mtime);
        let item = match name {
            Some(name) => Item::Dir { name, mode, mtime },
            None => Item::Contents { mode, mtime },
        };
        self.out.item(&item, &[])?;
        if depth == 1 {
            self.tree = rel.to_path_buf();
        }
        for entry in names {
            let path = rel.join(OsStr::from_bytes(&entry));
            let Ok(name) = Name::new(entry) else {
                return Err(Failure::new(FailKind::NameTooLong, &path));
            };
            let tree = path.strip_prefix(&self.tree).unwrap_or(&path);
            if !self
                .opts
                .excludes
                .excludes(name.as_bytes(), tree.as_os_str().as_bytes())
            {
                self.entry(dir, name, path, depth.saturating_add(1))?;
            }
        }
        self.out.item(&Item::End, &[])
    }

    /// Send `file`'s header, named `name`, `path` to say; its bytes go once it is answered.
    fn file(&mut self, file: File, name: Name, path: PathBuf) -> Result<(), Failure> {
        let meta = fsat::stat_of(&file).map_err(|error| Failure::io(&path, &error))?;
        let id = FileId(self.next);
        self.next = self.next.wrapping_add(1);
        let header = FileHeader {
            id,
            name,
            mode: Mode::new(meta.mode).unwrap_or(Mode(0o644)),
            mtime: meta.mtime,
            size: meta.size,
        };
        self.out.item(&Item::File(header), &[])?;
        self.pending.insert(id, (file, path));
        self.answers(self.pending.len() >= WINDOW)
    }

    /// Take the answers there are, waiting for one if `wait`: the receiver must answer the
    /// oldest header before more go. Once the receiver ended the copy, an error to stop at.
    fn answers(&mut self, wait: bool) -> Result<(), Failure> {
        let mut reply = if wait {
            // What was written must reach the receiver for it to answer.
            self.out.flush()?;
            Some(
                self.replies
                    .blocking_recv()
                    .unwrap_or_else(|| Reply::End(Err(cut()))),
            )
        } else {
            self.replies.try_recv().ok()
        };
        while let Some(next) = reply {
            match next {
                Reply::Answer(answer) => self.answer(&answer)?,
                Reply::End(end) => {
                    self.over = Some(end);
                    return Err(cut());
                }
            }
            reply = self.replies.try_recv().ok();
        }
        Ok(())
    }

    /// Act on `answer`: send the file's bytes, or say it is the same.
    fn answer(&mut self, answer: &Answer) -> Result<(), Failure> {
        let (Answer::Want { id, .. } | Answer::Check { id, .. }) = *answer;
        let (file, path) = self.pending.remove(&id).ok_or_else(malformed)?;
        let hash = |len| hash_of(&file, len).map_err(|error| Failure::io(&path, &error));
        let from = match answer {
            Answer::Want {
                have,
                prefix: Some(prefix),
                ..
            } if *have > 0 && hash(Some(*have))? == *prefix => *have,
            Answer::Check { hash: theirs, .. } if hash(None)? == *theirs => {
                return self.out.item(&Item::Same(id), &[]);
            }
            Answer::Want { .. } | Answer::Check { .. } => 0,
        };
        if self.opts.dry_run {
            return self.out.item(&Item::Differs { id, from }, &[]);
        }
        self.out.item(&Item::Data { id, from }, &[])?;
        let mut at = from;
        loop {
            let n = match file.read_at(&mut self.buf, at) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(Failure::io(&path, &error)),
            };
            let (Some(len), Some(data)) = (DataLen::new(n), self.buf.get(..n)) else {
                return Err(Failure::new(FailKind::Other, &path));
            };
            self.out.item(&Item::Chunk(len), data)?;
            at = at.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        }
        self.out.item(&Item::Sent, &[])
    }
}
