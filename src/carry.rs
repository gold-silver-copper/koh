//! Carrying a fux pane's folder to another machine: a mirror there is such a folder again.
//! `Reader` is the server's half: it reads the folder into rounds of messages, each what differs
//! from what the client has. `Mirror` is the client's: it takes a round's messages, holds them
//! beside the mirror until the round is whole, and applies it or throws it away. Plain functions
//! over a folder and messages: no network, and no clock but the one they are given.
//!
//! Of fux's format this knows five names and no file's meaning: `generation` (odd while a round
//! is written, even when the files agree), `in` and `ctl` (the two FIFOs), and the two never
//! carried: `command` (it is what starts a program) and `status` (it names the holder and the
//! program by their numbers on the server). A name with a dot first is not carried.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, DirBuilder, File};
use std::hash::{BuildHasher, RandomState};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
use std::mem::discriminant;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::proto::{Edit, Had, Kind, MAX_CHUNK, ToMirror};

/// The most of a file's bytes in one message: with its name and its numbers the message is
/// within `MAX_CHUNK` as it is sent.
const PIECE: usize = MAX_CHUNK - 512;
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

/// The names a mirror never has: the one it writes itself, and the two that are not carried.
const NEVER: [&str; 3] = ["generation", "command", "status"];

/// A name a mirror has: one or two of fux's names with `/` between (letters, digits, `.`, `_`
/// and `-`, 64 at most, no dot first), and none of those it never has, however they are
/// spelled: where a file system takes `COMMAND` for `command`, it is that file.
fn plain(name: &str) -> bool {
    let part = |part: &str| {
        let letters = |b: u8| b.is_ascii_alphanumeric() || b"._-".contains(&b);
        !part.is_empty() && part.len() <= 64 && !part.starts_with('.') && part.bytes().all(letters)
    };
    let never = |never: &&str| name.eq_ignore_ascii_case(never);
    name.split('/').count() <= 2 && name.split('/').all(part) && !NEVER.iter().any(never)
}

/// The lines of a file, each with the line end it has.
fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split_inclusive(|b| *b == b'\n')
}

/// What tells one writing of a name from the next: what it is, which file, its time and its
/// length; and of a link where it leads.
#[derive(Clone, PartialEq)]
struct Stamp {
    kind: Kind,
    file: (u64, u64),
    time: (i64, i64),
    len: u64,
    to: String,
}

impl Stamp {
    fn of(kind: Kind, meta: &fs::Metadata, to: String) -> Stamp {
        let (file, time) = ((meta.dev(), meta.ino()), (meta.mtime(), meta.mtime_nsec()));
        Stamp {
            kind,
            file,
            time,
            len: meta.len(),
            to,
        }
    }
}

/// The stamp of what a name is the name of (a link is not followed), if that is carried.
fn stamp_of(path: &Path) -> Option<Stamp> {
    let meta = fs::symlink_metadata(path).ok()?;
    let kind = match meta.file_type() {
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
    Some(Stamp::of(kind, &meta, to))
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

// ---- the server's half -------------------------------------------------------------------------

/// A file up to this long is sent whole without a look at its lines.
const SMALL: usize = 128;
/// What is kept of the end of a file as it was sent (its kept end): where a file written in
/// place was cut is looked for in these bytes. A cut takes from them what it takes from the
/// file, and what is added after fills them again.
const END: usize = 64 << 10;
/// How many places of the file before are tried for a line of the new one, and how many bytes
/// a run of its lines must be to be told as one.
const PLACES: usize = 16;
const WORTH: usize = 6;
/// A file a mirror has is looked for under another name here only if it is this long.
const MOVED: u64 = 4096;
/// How many times as long as a look at the folder took it is then left alone.
const REST: u32 = 9;

/// The number in a folder's `generation`.
fn number_in(root: &Path) -> Option<u64> {
    let file = fuxix::open_regular(root.join("generation")).ok()?;
    String::from_utf8(read_at(&file, 0, 32).ok()?)
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// A file as it is opened to be read, and its stamp then: what is read of it is no older.
fn opened(path: &Path) -> Option<(File, Stamp)> {
    let file = fuxix::open_regular(path).ok()?;
    let stamp = Stamp::of(Kind::File, &file.metadata().ok()?, String::new());
    Some((file, stamp))
}

/// How long no file is proved after a look that proved one: nine times as long as the look
/// took, and nine times what the reads took that were thrown away before it with a file to
/// prove, as far as that is no more than one rest of the look's own (nine times its length).
/// So proving has a tenth of a core where up to nine reads are thrown away for each that
/// stands, and reads thrown away for a long time are never one long rest after it: a rest
/// is ninety-one times its look at the most.
fn rest(took: Duration, owed: Duration) -> Duration {
    let owed = owed.min(took.saturating_mul(REST));
    took.saturating_add(took.saturating_add(owed).saturating_mul(REST))
}

/// A file's bytes as as many pieces as it takes, one at least.
fn pieces(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        vec![bytes]
    } else {
        bytes.chunks(PIECE).collect()
    }
}

fn put(out: &mut Vec<ToMirror>, name: &str, bytes: &[u8]) {
    let pieces = pieces(bytes);
    for (n, piece) in pieces.iter().enumerate() {
        let (name, more) = (name.to_string(), n + 1 < pieces.len());
        out.push(ToMirror::Put {
            name,
            more,
            bytes: piece.to_vec(),
        });
    }
}

/// A file as lines of the one before it: runs of that one's lines, from anywhere in it, and new
/// bytes. None where that is no smaller than the file, fits no message, or the file has too
/// many lines.
fn edits(old: &[u8], new: &[u8]) -> Option<Vec<Edit>> {
    let (old, lined): (Vec<&[u8]>, Vec<&[u8]>) =
        (lines(old).collect(), lines(new).take(LINES + 1).collect());
    if lined.len() > LINES {
        return None;
    }
    let mut places: HashMap<&[u8], Vec<usize>> = HashMap::new();
    for (at, line) in old.iter().enumerate() {
        let known = places.entry(line).or_default();
        if known.len() < PLACES {
            known.push(at);
        }
    }
    let run = |from: usize, at: usize| {
        old.iter()
            .skip(from)
            .zip(lined.iter().skip(at))
            .take_while(|(a, b)| a == b)
            .count()
    };
    let (mut out, mut cost, mut at) = (Vec::new(), 0, 0);
    while let Some(line) = lined.get(at) {
        // (The same place in the file before is tried first, then the places that have the line.)
        let tried = [at]
            .into_iter()
            .chain(places.get(line).into_iter().flatten().copied());
        let (count, from) = tried.map(|from| (run(from, at), from)).max()?;
        let worth: usize = lined
            .iter()
            .skip(at)
            .take(count)
            .map(|line| line.len())
            .sum();
        match out.last_mut() {
            _ if worth >= WORTH => {
                out.push(Edit::Run {
                    from: u32::try_from(from).ok()?,
                    count: u32::try_from(count).ok()?,
                });
                (cost, at) = (cost + 8, at + count);
                continue;
            }
            Some(Edit::New(bytes)) => bytes.extend_from_slice(line),
            _ => out.push(Edit::New(line.to_vec())),
        }
        (cost, at) = (cost + 8 + line.len(), at + 1);
    }
    (cost < new.len() && cost <= PIECE).then_some(out)
}

/// A sum of bytes this reader sent, by which it finds later that its own open file still begins
/// with them. It never leaves the reader, so it need not be blake3: what must collide is other
/// bytes of the same length under a key made with the reader that nothing shows, and whoever
/// writes that file is the server's own side, which chooses what a mirror holds anyway.
#[derive(Clone, Default, PartialEq)]
struct Sum {
    key: [u64; 8],
    lanes: [u64; 4],
    /// The bytes after the last whole block of 64.
    rest: Vec<u8>,
}

impl Sum {
    fn update(&mut self, bytes: &[u8]) {
        let fill = (64 - self.rest.len()) % 64;
        let (head, bytes) = bytes.split_at(fill.min(bytes.len()));
        self.rest.extend_from_slice(head);
        let held = std::mem::take(&mut self.rest);
        match held.as_chunks() {
            ([block], []) => self.mix(block),
            _ => self.rest = held,
        }
        let (blocks, rest) = bytes.as_chunks();
        blocks.iter().for_each(|block| self.mix(block));
        self.rest.extend_from_slice(rest);
    }

    /// Four lanes, each the product of two keyed words folded to one word (as wyhash's are).
    fn mix(&mut self, block: &[u8; 64]) {
        let (words, keys) = (block.as_chunks::<16>().0, self.key.as_chunks::<2>().0);
        for ((lane, pair), [k0, k1]) in self.lanes.iter_mut().zip(words).zip(keys) {
            let (a, b) = pair.split_at(8);
            let word = |bytes: &[u8]| u64::from_le_bytes(bytes.try_into().unwrap_or_default());
            let wide = u128::from(word(a) ^ k0) * u128::from(word(b) ^ k1 ^ *lane);
            *lane = wide as u64 ^ (wide >> 64) as u64;
        }
    }

    /// The sum of the first `len` bytes of a file as they are now, if it has that many.
    fn of(key: [u64; 8], mut file: &File, len: u64) -> Option<Sum> {
        let (mut sum, mut read) = (
            Sum {
                key,
                ..Sum::default()
            },
            0,
        );
        file.seek(SeekFrom::Start(0)).ok()?;
        let mut file = BufReader::with_capacity(1 << 18, file.take(len));
        loop {
            let bytes = file.fill_buf().ok()?;
            let more = bytes.len();
            if more == 0 {
                return (read == len).then_some(sum);
            }
            sum.update(bytes);
            file.consume(more);
            read += more as u64;
        }
    }
}

/// What a client has of a name, as the server knows it.
struct Kept {
    /// What was read: of a file, with the length that was sent.
    stamp: Stamp,
    /// The file as it was read, held open: while it is, its number is no other file's.
    held: Option<File>,
    /// What was sent of a replaced file of few lines: the next one is told against it.
    content: Option<Vec<u8>>,
    /// The last bytes sent of the file, and the sum of all that was sent before those.
    end: Vec<u8>,
    before: Sum,
}

impl Kept {
    /// A name the client has that is no file, or a file of which nothing is proved.
    fn marker(stamp: Stamp) -> Kept {
        Kept {
            stamp,
            held: None,
            content: None,
            end: Vec::new(),
            before: Sum::default(),
        }
    }

    /// A file of which the client has these bytes: `whole` if they are all it has here now.
    fn of(key: [u64; 8], stamp: Stamp, held: File, bytes: &[u8], whole: bool) -> Kept {
        let (head, end) = bytes.split_at(bytes.len().saturating_sub(END));
        let mut before = Sum {
            key,
            ..Sum::default()
        };
        before.update(head);
        // (Kept for `Lines` only where that could ever be sent: few lines, and none that no
        // message holds, as a picture's megabytes in one line are.)
        let told = |(n, line): (usize, &[u8])| n < LINES && line.len() <= PIECE;
        let content = (whole && lines(bytes).enumerate().all(told)).then(|| bytes.to_vec());
        let stamp = Stamp {
            len: bytes.len() as u64,
            ..stamp
        };
        Kept {
            stamp,
            held: Some(held),
            content,
            end: end.to_vec(),
            before,
        }
    }

    /// Whether the file a name has now is the one that was read.
    fn is(&self, now: &Stamp) -> bool {
        self.held.is_some() && now.kind == Kind::File && self.stamp.file == now.file
    }

    /// Where the kept end begins in the file.
    fn from(&self) -> u64 {
        self.stamp.len.saturating_sub(self.end.len() as u64)
    }

    /// Where the file as it is now parts from what was sent of it, if all before that place is
    /// proved to be what was sent: the bytes before the kept end by their sum, the kept end by
    /// itself. Not proved: nothing is said, and the file goes whole.
    fn parts_at(&self) -> Option<u64> {
        let held = self.held.as_ref()?;
        if Sum::of(self.before.key, held, self.from())? != self.before {
            return None;
        }
        let there = read_at(held, self.from(), self.end.len() as u64).ok()?;
        let same = there
            .iter()
            .zip(&self.end)
            .take_while(|(a, b)| a == b)
            .count();
        Some(self.from() + same as u64)
    }
}

/// What a look at a pane's folder gave.
#[derive(Debug, PartialEq)]
pub enum Look {
    /// What differs from what the client has, from `Round` to `Done`: to be sent. No message,
    /// where nothing differs and a round was sent before.
    Round(Vec<ToMirror>),
    /// Nothing was read: the folder is being written (its number is odd), or has no number.
    Odd,
    /// What was read is thrown away: the folder's number moved meanwhile.
    Moved,
    /// Nothing was read: a file must be proved, and the reader rests until then.
    Rests(Instant),
}

/// What a server reads of a pane's folder for one client: the folder, and name by name what
/// that client has. After every `Done` this record and the client's mirror are the same; it
/// moves only with a round that was read whole.
pub struct Reader {
    root: PathBuf,
    /// The key of this reader's sums: made with it, and never shown.
    key: [u64; 8],
    kept: BTreeMap<String, Kept>,
    /// Files the client has under another name than they have here (`has` found them): moved first.
    moved: Vec<(String, String)>,
    /// A round was sent since the client said what it has: the first is sent whatever it holds.
    sent: bool,
    /// Until when no file is proved; and how long the reads took that had a file to prove and
    /// were thrown away since one was, which the next rest is for too (`rest`).
    rests: Option<Instant>,
    owed: Duration,
    /// What a test does between a reading and the second look at the folder's number.
    #[cfg(test)]
    midway: Option<Box<dyn FnOnce()>>,
}

impl Reader {
    /// A reader of the pane's folder `root`, for a client that has not yet said what it has.
    pub fn new(root: &Path) -> Reader {
        let random = RandomState::new();
        Reader {
            root: root.into(),
            key: [0u8, 1, 2, 3, 4, 5, 6, 7].map(|n| random.hash_one(n)),
            kept: BTreeMap::new(),
            moved: Vec::new(),
            sent: false,
            rests: None,
            owed: Duration::ZERO,
            #[cfg(test)]
            midway: None,
        }
    }

    /// The number the folder has, and the number a round of the folder as it is has: the same
    /// even one; or, with no holder left (`dead`), the next after an odd one, which a holder
    /// that died as it wrote left for good.
    fn number(&self, dead: bool) -> Option<(u64, u64)> {
        let there = number_in(&self.root)?;
        match (there % 2, dead) {
            // (A round's number is 2 at least: at 0 none was written yet.)
            (0, _) => (there >= 2).then_some((there, there)),
            (_, true) => Some((there, there.checked_add(1)?)),
            _ => None,
        }
    }

    /// The second look: whether the folder's number is still the one a reading began under.
    fn stood_still(&mut self, there: u64) -> bool {
        #[cfg(test)]
        self.midway.take().into_iter().for_each(|midway| midway());
        number_in(&self.root) == Some(there)
    }

    /// A file here of which the client has the first `had.len` bytes, if these hash as it says.
    /// (Its lines are kept only where it has the client's name for it and no more than those.)
    fn proved(&self, name: &str, had: &Had) -> Option<Kept> {
        let (held, stamp) = opened(&self.root.join(name))?;
        let bytes = read_at(&held, 0, had.len.min(FILE)).ok()?;
        let same = bytes.len() as u64 == had.len && *blake3::hash(&bytes).as_bytes() == had.hash;
        let whole = stamp.len == had.len && name == had.name;
        same.then(|| Kept::of(self.key, stamp, held, &bytes, whole))
    }

    /// What a client says its mirror has. Nothing of it is believed: a file counts as had only
    /// if the bytes here hash as the client says, whole or as what a longer file here begins
    /// with, under its name or under another that no entry accounts for. Everything else it
    /// lists is taken as not had. False when the folder was written meanwhile: to be read again.
    pub fn has(&mut self, list: &[Had], dead: bool) -> Result<bool, Fault> {
        let mut seen = HashSet::new();
        if list.len() > NAMES
            || !list
                .iter()
                .all(|had| plain(&had.name) && seen.insert(&had.name))
        {
            return refused("a list of what a mirror has that is none", "");
        }
        let Some((there, _)) = self.number(dead) else {
            return Ok(false);
        };
        let here = walk(&self.root);
        let (mut kept, mut open) = (BTreeMap::new(), Vec::new());
        for had in list {
            let now = here
                .iter()
                .find(|(name, _)| *name == had.name)
                .map(|(_, stamp)| stamp);
            // (A file that could be it: as long at least, and no longer than a mirror's may be.
            // No other is opened.)
            let fits = |now: &Stamp| now.kind == Kind::File && had.len <= now.len.min(FILE);
            let file = now.filter(|now| had.kind == Kind::File && fits(now));
            let was = match (file.and_then(|_| self.proved(&had.name, had)), now) {
                (Some(proved), _) => proved,
                (None, Some(now))
                    if now.kind == had.kind && matches!(had.kind, Kind::Folder | Kind::Fifo) =>
                {
                    Kept::marker(now.clone())
                }
                _ => {
                    if had.kind == Kind::File && (MOVED..=FILE).contains(&had.len) {
                        open.push(had);
                    }
                    // (No stamp that is read is this one: whatever is here is sent over it.)
                    let (file, time, to) = ((0, 0), (0, 0), String::new());
                    Kept::marker(Stamp {
                        kind: had.kind,
                        file,
                        time,
                        len: 0,
                        to,
                    })
                }
            };
            kept.insert(had.name.clone(), was);
        }
        let mut moved: Vec<(&String, &String, Kept)> = Vec::new();
        for had in open {
            // (At the root: a move is told before the folders are, and fux renames nothing else.)
            let free = |name: &String, now: &Stamp| {
                let unproved = kept.get(name).is_none_or(|kept| kept.held.is_none());
                let taken = moved.iter().any(|(_, to, _)| *to == name);
                let fits = now.kind == Kind::File && had.len <= now.len;
                fits && *name != had.name && !name.contains('/') && unproved && !taken
            };
            let mut others = here.iter().filter(|(name, now)| free(name, now));
            if let Some((to, was)) =
                others.find_map(|(name, _)| Some((name, self.proved(name, had)?)))
            {
                moved.push((&had.name, to, was));
            }
        }
        // (Never a move onto what another move takes from: those files go whole.)
        if moved
            .iter()
            .any(|(_, to, _)| moved.iter().any(|(from, ..)| from == to))
        {
            moved.clear();
        }
        if !self.stood_still(there) {
            return Ok(false);
        }
        self.moved.clear();
        for (from, to, was) in moved {
            kept.remove(from);
            kept.insert(to.clone(), was);
            self.moved.push((from.clone(), to.clone()));
        }
        (self.kept, self.sent) = (kept, false);
        Ok(true)
    }

    /// One look at the folder, at the moment `now`. A look that proves a file (one written in
    /// place, or one that has another name now) owes a rest: no file is proved again until
    /// nine times as long as that look took has passed, so whatever proving costs, it has a
    /// tenth of a core at most. A look that proves nothing owes none, and is not held back.
    /// A read that is thrown away is not rested for then, or a holder that keeps writing
    /// would starve the mirror: the next look is at once, and the rest after it is for both
    /// (`rest`).
    pub fn look(&mut self, dead: bool, now: Instant) -> Look {
        let began = Instant::now();
        let Some(numbers) = self.number(dead) else {
            return Look::Odd;
        };
        let here = walk(&self.root);
        let known = |name: &String, stamp: &Stamp, (old, kept): (&String, &Kept)| {
            kept.is(stamp) && (old != name || kept.stamp != *stamp)
        };
        let proves =
            |(name, stamp): &(String, Stamp)| self.kept.iter().any(|kept| known(name, stamp, kept));
        let proves = here.iter().any(proves);
        if let Some(rests) = self.rests.filter(|rests| proves && now < *rests) {
            return Look::Rests(rests);
        }
        let round = self.read(numbers, here);
        let took = began.elapsed();
        match round {
            Some(round) => {
                if proves {
                    self.rests = now.checked_add(rest(took, std::mem::take(&mut self.owed)));
                }
                Look::Round(round)
            }
            None => {
                if proves {
                    self.owed = self.owed.saturating_add(took);
                }
                Look::Moved
            }
        }
    }

    fn read(
        &mut self,
        (there, number): (u64, u64),
        now: Vec<(String, Stamp)>,
    ) -> Option<Vec<ToMirror>> {
        let current: HashMap<&str, &Stamp> = now
            .iter()
            .map(|(name, stamp)| (name.as_str(), stamp))
            .collect();
        // A file that has another name now, that name having it no more: the same file, and what
        // was sent of it is where it was. Not where one move's target is another's source.
        let mut moved: Vec<(&str, &str)> = Vec::new();
        for (name, stamp) in now
            .iter()
            .filter(|(name, stamp)| !self.kept.get(name).is_some_and(|kept| kept.is(stamp)))
        {
            let left =
                |old: &str, kept: &Kept| !current.get(old).is_some_and(|there| kept.is(there));
            let mut was = self
                .kept
                .iter()
                .filter(|(old, kept)| kept.is(stamp) && left(old, kept));
            if let Some((old, _)) = was.find(|(_, kept)| kept.parts_at().is_some()) {
                moved.push((old, name));
            }
        }
        if moved
            .iter()
            .any(|(_, to)| moved.iter().any(|(from, _)| from == to))
        {
            moved.clear();
        }
        // The round's order: moves, folders and files, links, then what is gone. So a screen's
        // folder is filled before `shown` is turned to it, and removed after it is turned back.
        let said = self
            .moved
            .iter()
            .map(|(from, to)| (from.as_str(), to.as_str()));
        let moves = said.chain(moved.iter().copied());
        let mut first: Vec<ToMirror> = moves
            .map(|(from, to)| ToMirror::Moved {
                from: from.into(),
                to: to.into(),
            })
            .collect();
        let (mut links, mut next) = (Vec::new(), Vec::new());
        for (name, stamp) in &now {
            let from = moved
                .iter()
                .find(|(_, to)| to == name)
                .map(|(from, _)| *from);
            let away = moved.iter().any(|(from, _)| from == name);
            let kept = self
                .kept
                .get(from.unwrap_or(name))
                .filter(|_| from.is_some() || !away);
            let kind = kept.is_some_and(|kept| kept.stamp.kind == stamp.kind);
            match stamp.kind {
                // Its stamp is the one that was read: nothing.
                _ if from.is_none() && kept.is_some_and(|kept| kept.stamp == *stamp) => continue,
                Kind::Folder | Kind::Fifo if kind => continue,
                Kind::Folder => first.push(ToMirror::Folder(name.clone())),
                Kind::Fifo => first.push(ToMirror::Fifo(name.clone())),
                Kind::Link => links.push(ToMirror::Link {
                    name: name.clone(),
                    to: stamp.to.clone(),
                }),
                Kind::File => {
                    next.push((name.clone(), self.file(name, stamp, kept, &mut first)?));
                    continue;
                }
            }
            next.push((name.clone(), Kept::marker(stamp.clone())));
        }
        // (A folder goes after what was in it.)
        let left = |name: &&String| {
            !current.contains_key(name.as_str()) && !moved.iter().any(|(from, _)| from == *name)
        };
        let gone: Vec<String> = self.kept.keys().rev().filter(left).cloned().collect();
        let leaves: Vec<String> = moved
            .iter()
            .map(|(from, _)| from.to_string())
            .chain(gone.clone())
            .collect();
        let last = gone
            .into_iter()
            .map(ToMirror::Remove)
            .chain([ToMirror::Done]);
        let round: Vec<ToMirror> = [ToMirror::Round(number)]
            .into_iter()
            .chain(first)
            .chain(links)
            .chain(last)
            .collect();
        // Nothing of what is kept is changed unless the round is one.
        if !self.stood_still(there) {
            return None;
        }
        leaves.iter().for_each(|name| _ = self.kept.remove(name));
        self.kept.extend(next);
        self.moved.clear();
        // The first round is sent whatever it holds: it makes a mirror that a failed write left
        // odd even, and its number the pane's. After it, a round that changes nothing is not sent.
        let sent = std::mem::replace(&mut self.sent, true);
        Some(if sent && round.len() == 2 {
            Vec::new()
        } else {
            round
        })
    }

    /// A file that is not as it was read: what is sent of it, and what the client then has.
    fn file(
        &self,
        name: &str,
        stamp: &Stamp,
        kept: Option<&Kept>,
        out: &mut Vec<ToMirror>,
    ) -> Option<Kept> {
        // Written in place: it is the file that was read. If all of it up to some place is proved
        // to be what was sent, what follows that place is sent with the place (a cut, then what
        // was added). Not proved: whole.
        if let Some(kept) = kept.filter(|kept| kept.is(stamp)) {
            let held = kept.held.as_ref()?.try_clone().ok()?;
            let Some(at) = kept.parts_at() else {
                let bytes = read_at(&held, 0, FILE).ok()?;
                put(out, name, &bytes);
                return Some(Kept::of(self.key, stamp.clone(), held, &bytes, false));
            };
            let bytes = read_at(&held, at, FILE.saturating_sub(at)).ok()?;
            if at < kept.stamp.len || !bytes.is_empty() {
                for (n, piece) in pieces(&bytes).iter().enumerate() {
                    let (name, at) = (name.to_string(), at + (n * PIECE) as u64);
                    out.push(ToMirror::Add {
                        name,
                        at,
                        bytes: piece.to_vec(),
                    });
                }
            }
            // What the client has from the kept end's start on, once this is done to its file.
            let same = usize::try_from(at.checked_sub(kept.from())?).ok()?;
            let mut end = [kept.end.get(..same)?, &bytes].concat();
            let (over, mut before) = (end.len().saturating_sub(END), kept.before.clone());
            before.update(end.get(..over)?);
            end.drain(..over);
            let stamp = Stamp {
                len: at + bytes.len() as u64,
                ..stamp.clone()
            };
            return Some(Kept {
                stamp,
                held: Some(held),
                content: None,
                end,
                before,
            });
        }
        // Replaced, or new: whole, or as lines of the one before it where that is less.
        let (held, stamp) = opened(&self.root.join(name))?;
        let bytes = read_at(&held, 0, FILE).ok()?;
        let old = kept.and_then(|kept| kept.content.as_deref());
        let told = old
            .filter(|old| old.len() > SMALL && bytes.len() > SMALL)
            .and_then(|old| edits(old, &bytes));
        match told {
            Some(edits) => out.push(ToMirror::Lines {
                name: name.into(),
                edits,
            }),
            None => put(out, name, &bytes),
        }
        Some(Kept::of(self.key, stamp, held, &bytes, true))
    }
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
    /// One name has one spelling. Two that differ only in the case of their letters are one name
    /// to a mirror, whatever its file system would make of them: no message may name, in
    /// another spelling, a thing the round has so far.
    fn alone(&self, name: &str) -> bool {
        let other = |had: &String| had != name && had.eq_ignore_ascii_case(name);
        !self.will.keys().any(other)
    }

    /// A name this round may write a file under: free or a file's, in a folder of the mirror if
    /// it has two parts, and not written in this round.
    fn writable(&self, name: &str) -> Result<(), Fault> {
        let free = matches!(self.will.get(name), None | Some(Thing::File(_)));
        let above = name.split_once('/').map(|(above, _)| above);
        let under = above.is_none_or(|above| self.will.get(above) == Some(&Thing::Folder));
        match plain(name) && self.alone(name) && free && under && !self.written.contains(name) {
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
    /// where a thing of another kind is. A link may be turned; it leads to a folder the round
    /// has so far, so none is ever made, even for a moment, that leads anywhere else.
    fn make(&mut self, name: String, thing: Thing) -> Result<(), Fault> {
        let fits = match &thing {
            Thing::Fifo => (name == "in" || name == "ctl") && self.alone(&name),
            Thing::Link(to) if self.will.get(to) != Some(&Thing::Folder) => false,
            _ => plain(&name) && !name.contains('/') && self.alone(&name),
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
        let fits = (new.len() as u64).saturating_add(bytes.len() as u64) <= most;
        fits.then(|| new.extend_from_slice(bytes)).is_some()
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
    /// The server said that nothing follows: nothing more is taken.
    ended: bool,
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
            ended: false,
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
        if self.ended {
            return refused("a message after the end", "");
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
                ToMirror::Ended => {
                    self.ended = true;
                    Ok(true)
                }
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
                // (A FIFO's handle is let go once the FIFO is gone, and not if it stays.)
                Staged::Remove(name, folder) => {
                    let path = dir.join(&name);
                    let removed = if folder {
                        fs::remove_dir_all(path)
                    } else {
                        fs::remove_file(path)
                    };
                    absent(removed, ErrorKind::NotFound)?;
                    self.fifos.retain(|(known, _)| *known != name);
                }
            }
        }
        self.table = round.will;
        Ok(number(round.number)?)
    }
}

#[cfg(test)]
mod tests;
