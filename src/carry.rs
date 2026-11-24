//! Carrying a fux pane's folder to another machine: a mirror there is such a folder again.
//! `Mirror` is the client's half: it takes a round's messages, holds them beside the mirror
//! until the round is whole, and applies it or throws it away. Plain functions over a folder
//! and messages: no network, and no clock but the one it is given.
//!
//! Of fux's format this knows four names and no file's meaning: `generation` (odd while a round
//! is written, even when the files agree), `in` and `ctl` (the two FIFOs) and `command` (never
//! carried: it is what starts a program). A name with a dot first is not carried.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, DirBuilder, File};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::mem::discriminant;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::proto::{Edit, Had, Kind, ToMirror};

/// A file of more lines than this is never told as lines of the one before it.
const LINES: usize = 4096;
/// What a mirror holds at most: a file, all its files together (and all a round stages), its
/// names; and how many messages a round is.
const FILE: u64 = 32 << 20;
const MIRROR: u64 = 128 << 20;
const NAMES: usize = 256;
const MESSAGES: usize = 4096;
/// The longest an open round may bring no whole message, and the longest it may stay open.
const STILL: Duration = Duration::from_secs(30);
const LONG: Duration = Duration::from_secs(600);

/// Why a message was not taken.
#[derive(Debug)]
pub enum Fault {
    /// It is one a peer must not send: whoever was sent it ends, saying this. Nothing was changed.
    Refused(String),
    /// The mirror could not be written, or its round stood still: the stream is ended and the
    /// client attaches anew.
    Failed(String),
}

impl From<io::Error> for Fault {
    fn from(error: io::Error) -> Self {
        Self::Failed(error.to_string())
    }
}

/// A refusal, with the name it is about if it is about one: as a peer chose that, without
/// control characters and not without end.
fn refused<T>(what: &str, name: &str) -> Result<T, Fault> {
    let name: String = name.chars().take(80).collect();
    let about = if name.is_empty() {
        String::new()
    } else {
        format!(": {name:?}")
    };
    Err(Fault::Refused(format!("{what}{about}")))
}

/// A name a mirror has: one or two of fux's names with `/` between (letters, digits, `.`, `_`
/// and `-`, 64 at most, no dot first), and neither of the two that are never carried, however
/// they are spelled: where a file system takes `COMMAND` for `command`, it is that file.
fn plain(name: &str) -> bool {
    let part = |part: &str| {
        let letters = |b: u8| b.is_ascii_alphanumeric() || b"._-".contains(&b);
        !part.is_empty() && part.len() <= 64 && !part.starts_with('.') && part.bytes().all(letters)
    };
    let never = |never: &str| name.eq_ignore_ascii_case(never);
    name.split('/').count() <= 2
        && name.split('/').all(part)
        && !never("generation")
        && !never("command")
}

/// The lines of a file, each with the line end it has.
fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split_inclusive(|b| *b == b'\n')
}

/// What a name is the name of; and of a link where it leads.
struct Stamp {
    kind: Kind,
    to: String,
}

/// The stamp of what a name is the name of (a link is not followed), if that is carried.
fn stamp_of(path: &Path) -> Option<Stamp> {
    let kind = match fs::symlink_metadata(path).ok()?.file_type() {
        kind if kind.is_file() => Kind::File,
        kind if kind.is_dir() => Kind::Folder,
        kind if kind.is_symlink() => Kind::Link,
        kind if kind.is_fifo() => Kind::Fifo,
        _ => return None,
    };
    let to = match kind {
        Kind::Link => fs::read_link(path).ok()?.to_str()?.to_string(),
        _ => String::new(),
    };
    Some(Stamp { kind, to })
}

/// Everything a folder has that is carried, by name and in the names' order: what is at its
/// root, and what is in a folder there but for a folder.
fn walk(root: &Path) -> Vec<(String, Stamp)> {
    let names = |dir: &Path| {
        let entries = fs::read_dir(dir).into_iter().flatten().flatten();
        let mut names: Vec<String> = entries
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        names
    };
    let mut found = Vec::new();
    for name in names(root) {
        let Some(stamp) = stamp_of(&root.join(&name)).filter(|_| plain(&name)) else {
            continue;
        };
        let inside = if stamp.kind == Kind::Folder {
            names(&root.join(&name))
        } else {
            Vec::new()
        };
        found.push((name.clone(), stamp));
        for name in inside
            .iter()
            .map(|inside| format!("{name}/{inside}"))
            .filter(|name| plain(name))
        {
            if let Some(stamp) =
                stamp_of(&root.join(&name)).filter(|stamp| stamp.kind != Kind::Folder)
            {
                found.push((name, stamp));
            }
        }
    }
    found
}

/// At most `most` bytes of a file, from the place `from`.
fn read_at(mut file: &File, from: u64, most: u64) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(from))?;
    let mut bytes = Vec::new();
    file.take(most).read_to_end(&mut bytes)?;
    Ok(bytes)
}

// ---- the client's half -------------------------------------------------------------------------

/// What a mirror has under a name: a file and its length, a link and where it leads.
#[derive(Clone, PartialEq)]
enum Thing {
    File(u64),
    Folder,
    Link(String),
    Fifo,
}

impl Thing {
    fn len(&self) -> u64 {
        if let Thing::File(len) = self { *len } else { 0 }
    }
}

/// One thing a round does, held until the round is whole: a file's bytes are beside the mirror.
enum Staged {
    Make(String, Thing),
    File(String, PathBuf),
    /// The file is cut to so many bytes, and the staged ones follow.
    Add(String, u64, PathBuf),
    Moved(String, String),
    /// (And whether it is a folder that goes.)
    Remove(String, bool),
}

/// The file whose bytes are coming: where it is cut if it is added to, and where its next byte is.
struct Coming {
    name: String,
    cut: Option<u64>,
    end: u64,
    file: File,
    path: PathBuf,
}

struct Round {
    number: u64,
    ops: Vec<Staged>,
    /// The mirror as the round will leave it: every message is checked against this.
    will: BTreeMap<String, Thing>,
    /// The files this round has written (none twice), and those it gave their names by a move.
    written: HashSet<String>,
    moved: HashSet<String>,
    coming: Option<Coming>,
    staged: u64,
    messages: usize,
    began: Instant,
    last: Instant,
}

impl Round {
    /// A name this round may write a file under: free or a file's, in a folder of the mirror if
    /// it has two parts, and not written in this round.
    fn writable(&self, name: &str) -> Result<(), Fault> {
        let free = matches!(self.will.get(name), None | Some(Thing::File(_)));
        let above = name.split_once('/').map(|(above, _)| above);
        let under = above.is_none_or(|above| self.will.get(above) == Some(&Thing::Folder));
        match plain(name) && free && under && !self.written.contains(name) {
            true => Ok(()),
            false => refused("no name for a file", name),
        }
    }

    /// More bytes of the file that is coming, counted before they are kept.
    fn write(&mut self, bytes: &[u8]) -> Result<(), Fault> {
        let Some(coming) = self.coming.as_mut() else {
            return refused("no file for bytes", "");
        };
        let more = bytes.len() as u64;
        (coming.end, self.staged) = (
            coming.end.saturating_add(more),
            self.staged.saturating_add(more),
        );
        if coming.end > FILE || self.staged > MIRROR {
            return refused("more than a mirror holds", &coming.name);
        }
        Ok(coming.file.write_all(bytes)?)
    }

    /// Ends the file whose bytes were coming: it is part of the round.
    fn close(&mut self) {
        let Some(Coming {
            name,
            cut,
            end,
            path,
            ..
        }) = self.coming.take()
        else {
            return;
        };
        self.written.insert(name.clone());
        self.will.insert(name.clone(), Thing::File(end));
        self.ops.push(match cut {
            Some(cut) => Staged::Add(name, cut, path),
            None => Staged::File(name, path),
        });
    }

    /// A folder, a FIFO or a link: at the mirror's root (a FIFO is `in` or `ctl`), and never
    /// where a thing of another kind is. (A link may be turned.)
    fn make(&mut self, name: String, thing: Thing) -> Result<(), Fault> {
        let fits = match thing {
            Thing::Fifo => name == "in" || name == "ctl",
            _ => plain(&name) && !name.contains('/'),
        };
        let kind = discriminant(&thing);
        if !fits
            || self
                .will
                .get(&name)
                .is_some_and(|had| discriminant(had) != kind)
        {
            return refused("no name for it", &name);
        }
        self.will.insert(name.clone(), thing.clone());
        self.ops.push(Staged::Make(name, thing));
        Ok(())
    }
}

/// The file the edits make of the one before it, of at most `most` bytes, counted as it grows.
fn edited(old: &[u8], edits: &[Edit], most: u64) -> Result<Vec<u8>, Fault> {
    let old: Vec<&[u8]> = lines(old).take(LINES + 1).collect();
    if old.len() > LINES {
        return refused("lines of a file of too many", "");
    }
    let mut new = Vec::new();
    let mut grows = |bytes: &[u8]| {
        new.extend_from_slice(bytes);
        new.len() as u64 <= most
    };
    for edit in edits {
        let fits = match edit {
            Edit::Run { from, count } => {
                let (from, count) = (*from as usize, *count as usize);
                let run = from.checked_add(count).and_then(|end| old.get(from..end));
                let Some(run) = run else {
                    return refused("lines the file before has not", "");
                };
                run.iter().all(|line| grows(line))
            }
            Edit::New(bytes) => grows(bytes),
        };
        if !fits {
            return refused("lines that make more than a mirror holds", "");
        }
    }
    Ok(new)
}

/// A client's copy of a pane's folder: koh makes it and alone writes it. After every `Done` it
/// is what the server read; nothing of a round touches it before.
pub struct Mirror {
    dir: PathBuf,
    /// What the mirror has, as the last whole round (or the last look at it) left it.
    table: BTreeMap<String, Thing>,
    fifos: Vec<(String, File)>,
    round: Option<Round>,
    /// How many files were staged: each has a name of its own in `.koh`.
    files: u64,
}

impl Mirror {
    /// Makes the mirror's folder, the owner's alone. One that is there is not taken.
    pub fn make(dir: &Path) -> io::Result<Mirror> {
        // (Staged files are in a folder whose name has a dot first: fux passes it over, and no
        // message can name it.)
        DirBuilder::new().mode(0o700).create(dir)?;
        DirBuilder::new().mode(0o700).create(dir.join(".koh"))?;
        let (table, fifos) = (BTreeMap::new(), Vec::new());
        Ok(Mirror {
            dir: dir.into(),
            table,
            fifos,
            round: None,
            files: 0,
        })
    }

    /// One of the mirror's two FIFOs, open to read what is written to it, once a round made it.
    pub fn fifo(&self, name: &str) -> Option<&File> {
        self.fifos
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, fifo)| fifo)
    }

    /// What the mirror has, as it is on disk, for the server to check: asked at every attach.
    /// (A round that was open is of a stream that ended: it is thrown away.)
    pub fn has(&mut self) -> io::Result<Vec<Had>> {
        self.discard();
        self.table.clear();
        let mut list = Vec::new();
        for (name, stamp) in walk(&self.dir) {
            let mut hasher = blake3::Hasher::new();
            let thing = match stamp.kind {
                Kind::File => {
                    let file = fuxix::open_regular(self.dir.join(&name))?;
                    Thing::File(hasher.update_reader(file.take(FILE))?.count())
                }
                Kind::Folder => Thing::Folder,
                Kind::Link => Thing::Link(stamp.to),
                Kind::Fifo => Thing::Fifo,
            };
            let (kind, len, hash) = (stamp.kind, thing.len(), hasher.finalize().into());
            list.push(Had {
                name: name.clone(),
                kind,
                len,
                hash,
            });
            self.table.insert(name, thing);
        }
        Ok(list)
    }

    /// When the open round is thrown away if it is not whole by then (the transport's end, to
    /// the caller): `STILL` after its last whole message, and `LONG` after it began.
    pub fn due(&self) -> Option<Instant> {
        let round = self.round.as_ref()?;
        Some(
            round
                .last
                .checked_add(STILL)?
                .min(round.began.checked_add(LONG)?),
        )
    }

    /// Throws away a round that is not whole: nothing of it was ever under a name of the mirror.
    pub fn discard(&mut self) {
        self.round = None;
        for staged in fs::read_dir(self.dir.join(".koh"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let _ = fs::remove_file(staged.path());
        }
    }

    /// One message from the server, at the moment `now`: a round's are held, and done to the
    /// mirror only at its `Done`. Says whether the server said that nothing follows (`Ended`).
    /// A message that is not taken leaves the mirror as the last `Done` left it, and nothing staged.
    pub fn take(&mut self, message: ToMirror, now: Instant) -> Result<bool, Fault> {
        let taken = self.step(message, now);
        if taken.is_err() {
            self.discard();
        }
        taken
    }

    fn step(&mut self, message: ToMirror, now: Instant) -> Result<bool, Fault> {
        if self.due().is_some_and(|due| now > due) {
            return Err(Fault::Failed("a round stood still".into()));
        }
        let Some(mut round) = self.round.take() else {
            return match message {
                ToMirror::Round(number) if number >= 2 && number % 2 == 0 => {
                    self.round = Some(Round {
                        number,
                        ops: Vec::new(),
                        will: self.table.clone(),
                        written: HashSet::new(),
                        moved: HashSet::new(),
                        coming: None,
                        staged: 0,
                        messages: 0,
                        began: now,
                        last: now,
                    });
                    Ok(false)
                }
                ToMirror::Round(_) => refused("a round whose number is none", ""),
                ToMirror::Ended => Ok(true),
                _ => refused("a message outside a round", ""),
            };
        };
        (round.messages, round.last) = (round.messages + 1, now);
        if round.messages > MESSAGES {
            return refused("a round of too many messages", "");
        }
        // The pieces of one file follow each other. Anything else ends a file that was added to,
        // and is refused while a whole file's pieces are still to come.
        let goes_on = match (&round.coming, &message) {
            (Some(coming), ToMirror::Put { name, .. }) => {
                coming.cut.is_none() && coming.name == *name
            }
            (Some(coming), ToMirror::Add { name, .. }) => {
                coming.cut.is_some() && coming.name == *name
            }
            _ => false,
        };
        if !goes_on {
            if let Some(coming) = round.coming.as_ref().filter(|coming| coming.cut.is_none()) {
                return refused("a file in pieces that was not ended", &coming.name);
            }
            round.close();
        }
        match message {
            ToMirror::Round(_) | ToMirror::Ended => return refused("a round inside a round", ""),
            ToMirror::Folder(name) => round.make(name, Thing::Folder)?,
            ToMirror::Fifo(name) => round.make(name, Thing::Fifo)?,
            ToMirror::Link { name, to } => round.make(name, Thing::Link(to))?,
            ToMirror::Put { name, more, bytes } => {
                if !goes_on {
                    round.writable(&name)?;
                    round.coming = Some(self.stage(name, None)?);
                }
                round.write(&bytes)?;
                if !more {
                    round.close();
                }
            }
            // Added to: a file the mirror has, from a place inside it or at its end.
            ToMirror::Add { name, at, bytes } => {
                if !goes_on {
                    round.writable(&name)?;
                    if !matches!(round.will.get(&name), Some(Thing::File(len)) if at <= *len) {
                        return refused("nothing to add to", &name);
                    }
                    round.coming = Some(self.stage(name, Some(at))?);
                }
                if round.coming.as_ref().is_none_or(|coming| coming.end != at) {
                    return refused("bytes added out of their place", "");
                }
                round.write(&bytes)?;
            }
            // Told against the file the mirror has under that name: one this round has not touched.
            ToMirror::Lines { name, edits } => {
                round.writable(&name)?;
                let file = matches!(round.will.get(&name), Some(Thing::File(_)));
                if !file || round.moved.contains(&name) {
                    return refused("no file before it", &name);
                }
                let old = read_at(&fuxix::open_regular(self.dir.join(&name))?, 0, FILE)?;
                let new = edited(&old, &edits, FILE.min(MIRROR.saturating_sub(round.staged)))?;
                round.coming = Some(self.stage(name, None)?);
                round.write(&new)?;
                round.close();
            }
            ToMirror::Moved { from, to } => {
                round.writable(&to)?;
                let touched = round.written.contains(&from) || round.moved.contains(&from);
                let file = round
                    .will
                    .get(&from)
                    .filter(|_| !touched && from != to)
                    .cloned();
                let Some(file @ Thing::File(_)) = file else {
                    return refused("no file to move", &from);
                };
                round.will.remove(&from);
                round.will.insert(to.clone(), file);
                round.moved.insert(to.clone());
                round.ops.push(Staged::Moved(from, to));
            }
            // (Of what the round has so far: a folder made and removed in one round is a folder.)
            ToMirror::Remove(name) => {
                let Some(was) = round.will.remove(&name) else {
                    return refused("nothing to remove", &name);
                };
                if was == Thing::Folder {
                    let inside = format!("{name}/");
                    round.will.retain(|other, _| !other.starts_with(&inside));
                }
                round.ops.push(Staged::Remove(name, was == Thing::Folder));
            }
            // What the round leaves is a mirror: no more than one holds, and every link it has,
            // this round's and those before it, leads to a folder at its root.
            ToMirror::Done => {
                let sizes: u64 = round.will.values().map(Thing::len).sum();
                let led = |thing: &Thing| match thing {
                    Thing::Link(to) => round.will.get(to) == Some(&Thing::Folder),
                    _ => true,
                };
                if round.will.len() > NAMES || sizes > MIRROR || !round.will.values().all(led) {
                    return refused("a round that leaves no mirror", "");
                }
                return self.apply(round).map(|()| false);
            }
        }
        self.round = Some(round);
        Ok(false)
    }

    /// A new file beside the mirror for bytes that are coming.
    fn stage(&mut self, name: String, cut: Option<u64>) -> io::Result<Coming> {
        self.files += 1;
        let path = self.dir.join(".koh").join(self.files.to_string());
        let (file, end) = (File::create_new(&path)?, cut.unwrap_or(0));
        Ok(Coming {
            name,
            cut,
            end,
            file,
            path,
        })
    }

    /// A round that is whole, done to the mirror as fux's holder does one: `generation` odd,
    /// each thing in the round's order, `generation` even. Both are new files, so a viewer
    /// reads the pane again. A write that fails leaves the number odd, which is true.
    fn apply(&mut self, round: Round) -> Result<(), Fault> {
        let dir = self.dir.clone();
        let number =
            |number: u64| fux::replace(dir.join("generation"), format!("{number}\n").as_bytes());
        let absent = |made: io::Result<()>, kind| {
            made.or_else(|e| if e.kind() == kind { Ok(()) } else { Err(e) })
        };
        number(round.number - 1)?;
        for op in round.ops {
            match op {
                Staged::Make(name, Thing::Folder) => {
                    absent(fs::create_dir(dir.join(name)), ErrorKind::AlreadyExists)?
                }
                // (Made once: one that is there is the one a viewer writes to.)
                Staged::Make(name, Thing::Fifo) if self.fifo(&name).is_none() => {
                    let fifo = fuxix::fifo(dir.join(&name))?;
                    self.fifos.push((name, fifo));
                }
                Staged::Make(name, Thing::Link(to)) => {
                    let new = fux::staging(&dir.join(&name));
                    absent(fs::remove_file(&new), ErrorKind::NotFound)?;
                    symlink(to, &new)?;
                    fs::rename(new, dir.join(name))?;
                }
                Staged::Make(..) => {}
                Staged::File(name, staged) => fs::rename(staged, dir.join(name))?,
                Staged::Add(name, cut, staged) => {
                    let mut file = fuxix::open(dir.join(&name), true)?;
                    if !file.metadata()?.is_file() {
                        return Err(Fault::Failed(format!("no file to add to: {name}")));
                    }
                    file.set_len(cut)?;
                    file.seek(SeekFrom::End(0))?;
                    io::copy(&mut File::open(&staged)?, &mut file)?;
                    fs::remove_file(staged)?;
                }
                Staged::Moved(from, to) => fs::rename(dir.join(from), dir.join(to))?,
                Staged::Remove(name, folder) => {
                    self.fifos.retain(|(known, _)| *known != name);
                    let path = dir.join(name);
                    let removed = if folder {
                        fs::remove_dir_all(path)
                    } else {
                        fs::remove_file(path)
                    };
                    absent(removed, ErrorKind::NotFound)?;
                }
            }
        }
        self.table = round.will;
        Ok(number(round.number)?)
    }
}

#[cfg(test)]
mod tests;
