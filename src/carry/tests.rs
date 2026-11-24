//! A pane's folder written by hand as fux's holder writes one, its rounds through the wire, and
//! a mirror: what must be carried right, and what a mirror must not take.

use super::*;
use crate::proto::{FromMirror, decode, encode};

/// A folder of the test's own, gone when the test is.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("koh-carry-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn mirror(&self) -> Mirror {
        Mirror::make(&self.0.join("mirror")).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Everything in a folder by name, a folder's own too: a file's bytes, where a link leads, what
/// else a name is. With `staged`, the names with a dot first as well (what a round stages).
fn snapshot(dir: &Path, staged: bool) -> BTreeMap<String, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut folders = vec![(dir.to_path_buf(), String::new())];
    while let Some((folder, prefix)) = folders.pop() {
        for entry in fs::read_dir(&folder).unwrap() {
            let (path, name) = (entry.as_ref().unwrap().path(), entry.unwrap().file_name());
            let name = format!("{prefix}{}", name.to_str().unwrap());
            if name.starts_with('.') && !staged {
                continue;
            }
            let kind = fs::symlink_metadata(&path).unwrap().file_type();
            let what = match () {
                () if kind.is_file() => fs::read(&path).unwrap(),
                () if kind.is_symlink() => {
                    format!("-> {}", fs::read_link(&path).unwrap().display()).into()
                }
                () if kind.is_fifo() => b"a FIFO".to_vec(),
                () => {
                    folders.push((path, format!("{name}/")));
                    b"a folder".to_vec()
                }
            };
            found.insert(name, what);
        }
    }
    found
}

/// A message as the other end has it: within its bound as it is sent, its length counted.
fn sent(message: &ToMirror) -> ToMirror {
    let bytes = encode(message, MAX_CHUNK).unwrap();
    assert!(
        4 + bytes.len() <= MAX_CHUNK,
        "a message of {} bytes",
        bytes.len()
    );
    decode(&bytes, MAX_CHUNK).unwrap()
}

/// Gives a mirror a whole round, which it must take.
fn give(mirror: &mut Mirror, round: &[ToMirror]) {
    let now = Instant::now();
    for message in round {
        let taken = mirror.take(sent(message), now);
        assert!(matches!(taken, Ok(false)), "{message:?}: {taken:?}");
    }
}

fn put(name: &str, bytes: &[u8]) -> ToMirror {
    ToMirror::Put {
        name: name.into(),
        more: false,
        bytes: bytes.to_vec(),
    }
}

/// A piece of a file that more follow.
fn piece(name: &str, bytes: &[u8]) -> ToMirror {
    ToMirror::Put {
        name: name.into(),
        more: true,
        bytes: bytes.to_vec(),
    }
}

fn add(name: &str, at: u64, bytes: &[u8]) -> ToMirror {
    ToMirror::Add {
        name: name.into(),
        at,
        bytes: bytes.to_vec(),
    }
}

fn moved(from: &str, to: &str) -> ToMirror {
    ToMirror::Moved {
        from: from.into(),
        to: to.into(),
    }
}

fn link(name: &str, to: &str) -> ToMirror {
    ToMirror::Link {
        name: name.into(),
        to: to.into(),
    }
}

fn lines_of(name: &str, edits: Vec<Edit>) -> ToMirror {
    ToMirror::Lines {
        name: name.into(),
        edits,
    }
}

fn folder(name: &str) -> ToMirror {
    ToMirror::Folder(name.into())
}

fn fifo(name: &str) -> ToMirror {
    ToMirror::Fifo(name.into())
}

fn remove(name: &str) -> ToMirror {
    ToMirror::Remove(name.into())
}

fn run(from: u32, count: u32) -> Edit {
    Edit::Run { from, count }
}

/// A round of that number with those messages.
fn round_of(number: u64, messages: Vec<ToMirror>) -> Vec<ToMirror> {
    [ToMirror::Round(number)]
        .into_iter()
        .chain(messages)
        .chain([ToMirror::Done])
        .collect()
}

/// The round every mirror of these tests has first.
fn first_round() -> Vec<ToMirror> {
    let screen = put("main/screen", &b"row\n".repeat(60));
    round_of(
        2,
        vec![
            folder("main"),
            put("title", b"a title\n"),
            screen,
            link("shown", "main"),
            fifo("in"),
        ],
    )
}

#[test]
fn a_round_a_server_must_not_send_changes_nothing() {
    let scratch = Scratch::new("hostile");
    let outside = scratch.0.join("escaped").to_str().unwrap().to_string();
    let big = |n: usize| put(&format!("big{n}"), &vec![b'x'; 200 << 10]);
    let grown = |n: usize| lines_of(&format!("big{n}"), vec![run(0, 1); 150]);
    let names = (0..300).map(|n| put(&format!("n{n}"), b"")).collect();
    // What a server sends before the round it must not send, and that round (its number is 8).
    let cases: Vec<(&str, Vec<ToMirror>, Vec<ToMirror>)> = vec![
        (
            "a name that climbs out",
            vec![],
            vec![put("../escaped", b"out\n")],
        ),
        (
            "a name that is a path",
            vec![],
            vec![put(&outside, b"out\n")],
        ),
        (
            "a name of three parts",
            vec![],
            vec![put("main/a/b", b"deep\n")],
        ),
        (
            "a name with a dot first",
            vec![],
            vec![put(".koh/1", b"staged\n")],
        ),
        (
            "a link that leads out",
            vec![],
            vec![link("shown", "../..")],
        ),
        ("a link to a file", vec![], vec![link("shown", "title")]),
        (
            "a link that is then written through",
            vec![],
            vec![link("way", "main"), put("way/screen", b"through\n")],
        ),
        (
            "a link where a folder is",
            vec![],
            vec![link("main", "main")],
        ),
        (
            "a folder where a file is",
            vec![],
            vec![folder("title"), put("title/x", b"x\n")],
        ),
        (
            "the file `generation`",
            vec![],
            vec![put("generation", b"7\n")],
        ),
        (
            "the file `command`",
            vec![],
            vec![put("command", b"sh\0-c\0true\0")],
        ),
        (
            "the file `command` in capitals",
            vec![],
            vec![put("COMMAND", b"sh\0-c\0true\0")],
        ),
        (
            "a move onto `command`",
            vec![],
            vec![moved("title", "command")],
        ),
        ("a FIFO of another name", vec![], vec![fifo("evil")]),
        (
            "bytes added past a file's end",
            vec![],
            vec![add("title", 999, b"far\n")],
        ),
        (
            "bytes added to no file",
            vec![],
            vec![add("nothing", 0, b"new\n")],
        ),
        (
            "lines that would grow to 16 GB",
            vec![big(0)],
            vec![lines_of("big0", vec![run(0, 1); 80_000])],
        ),
        (
            "a run of lines the file has not",
            vec![],
            vec![lines_of("title", vec![run(5, 3)])],
        ),
        (
            "a file in pieces that is never ended",
            vec![],
            vec![piece("title", b"half"), put("main/screen", b"other\n")],
        ),
        (
            "a round inside a round",
            vec![],
            vec![put("title", b"t\n"), ToMirror::Round(10)],
        ),
        (
            "a message over its bound",
            vec![],
            vec![put("title", &vec![b'x'; MAX_CHUNK])],
        ),
        ("more names than a mirror has", vec![], names),
        (
            "lines staged past what a mirror holds",
            (0..5).map(big).collect(),
            (0..5)
                .map(grown)
                .chain((0..5).map(|n| remove(&format!("big{n}"))))
                .collect(),
        ),
        (
            "a link left leading to a file by a later round",
            vec![folder("alt"), link("shown", "alt")],
            vec![remove("alt"), put("alt", b"no folder\n")],
        ),
        // One name has one spelling: another is refused, whatever the file system would do.
        (
            "a file's name spelled another way",
            vec![],
            vec![put("TITLE", b"t\n")],
        ),
        ("`IN` where `in` is", vec![], vec![put("IN", b"typed\n")]),
        (
            "a folder's name spelled another way",
            vec![],
            vec![folder("MAIN")],
        ),
        (
            "a link's name spelled another way",
            vec![],
            vec![link("Shown", "main")],
        ),
        (
            "a move to another spelling",
            vec![],
            vec![moved("title", "Title")],
        ),
        (
            "one name made in two spellings",
            vec![],
            vec![put("x", b"x\n"), put("X", b"X\n")],
        ),
        // A FIFO's name has one spelling too, whatever was made in another, and whenever.
        (
            "`IN` put, then the FIFO `in`",
            vec![remove("in")],
            vec![put("IN", b"typed\n"), fifo("in")],
        ),
        (
            "`CTL` put, then the FIFO `ctl`",
            vec![],
            vec![put("CTL", b"x\n"), fifo("ctl")],
        ),
        (
            "a folder `IN`, then the FIFO `in`",
            vec![remove("in")],
            vec![folder("IN"), fifo("in")],
        ),
        (
            "a link `In`, then the FIFO `in`",
            vec![remove("in")],
            vec![link("In", "main"), fifo("in")],
        ),
        (
            "the FIFO `in` a round after `IN`",
            vec![remove("in"), put("IN", b"typed\n")],
            vec![fifo("in")],
        ),
        (
            "the FIFO `ctl` a round after `CTL`",
            vec![put("CTL", b"x\n")],
            vec![fifo("ctl")],
        ),
        // A link is checked when it comes: one that is gone again by `Done` is never made.
        (
            "a link to no folder, removed again",
            vec![],
            vec![link("way", "missing"), remove("way")],
        ),
        (
            "a link that leads out, removed again",
            vec![],
            vec![link("way", "../.."), remove("way")],
        ),
        (
            "a link before its folder",
            vec![],
            vec![link("way", "alt"), folder("alt")],
        ),
        (
            "the file `status`",
            vec![],
            vec![put("status", b"holder 1\n")],
        ),
        (
            "a file written twice in a round",
            vec![],
            vec![put("title", b"one\n"), put("title", b"two\n")],
        ),
        (
            "more messages than a round has",
            vec![],
            vec![folder("main"); 4096],
        ),
        (
            "a later piece of added bytes out of its place",
            vec![],
            vec![add("title", 2, b"ab"), add("title", 5, b"cd")],
        ),
        (
            "a name of 65 characters",
            vec![],
            vec![put(&"n".repeat(65), b"")],
        ),
        // (The first has no `Round` before it; the last one's link ends before its `Done`.)
        ("a message outside a round", vec![], vec![]),
        ("an odd round", vec![], vec![]),
        (
            "a round that never ends",
            vec![],
            vec![put("title", b"changed\n")],
        ),
    ];
    let mut failed = Vec::new();
    for (case, (what, before, hostile)) in cases.into_iter().enumerate() {
        let scratch = Scratch::new(&format!("hostile-{case}"));
        let mut mirror = scratch.mirror();
        give(&mut mirror, &first_round());
        give(&mut mirror, &round_of(4, before));
        let was = snapshot(&scratch.0, true);
        let mut hostile = round_of(8, hostile);
        match what {
            "a message outside a round" => hostile = vec![put("title", b"t\n")],
            "an odd round" => hostile = round_of(9, vec![]),
            "a round that never ends" => _ = hostile.pop(),
            _ => {}
        }
        // (As they are sent, so that one of them can be no message.)
        let refusal = hostile.iter().find_map(|message| {
            let message = decode(&encode(message, usize::MAX).unwrap(), MAX_CHUNK);
            let message = message.map_err(|e| Fault::Refused(e.to_string()));
            message
                .and_then(|message| mirror.take(message, Instant::now()))
                .err()
        });
        // (A refusal leaves nothing staged by itself; a link that ends is the caller's to say.)
        let refused = match what {
            "a round that never ends" => {
                mirror.discard();
                refusal.is_none()
            }
            _ => matches!(refusal, Some(Fault::Refused(_))),
        };
        let staged = was.keys().any(|name| name.starts_with("mirror/.koh/"));
        if !refused || snapshot(&scratch.0, true) != was || staged {
            failed.push(format!("{what}: {refusal:?}"));
        }
    }
    assert!(
        failed.is_empty(),
        "the mirror took, or is not as it was after: {failed:#?}"
    );
    // And one a server may send, though it looks like none: a folder made and removed in one
    // round is a folder when it is removed.
    let mut mirror = scratch.mirror();
    give(&mut mirror, &first_round());
    let mut was = snapshot(&scratch.0, true);
    give(
        &mut mirror,
        &round_of(4, vec![folder("tmp"), put("tmp/x", b"x\n"), remove("tmp")]),
    );
    was.insert("mirror/generation".into(), b"4\n".to_vec());
    assert!(snapshot(&scratch.0, true) == was);
    // A capital letter is carried all the same, and so is a name in another spelling once the
    // first is gone.
    let capitals = vec![put("README", b""), remove("title"), put("Title", b"T\n")];
    give(&mut mirror, &round_of(6, capitals));
    // What is at a bound is taken: a name of 64 characters, a round of 4,096 messages with its
    // `Done`.
    let at_bounds = [vec![put(&"n".repeat(64), b"")], vec![folder("main"); 4094]].concat();
    give(&mut mirror, &round_of(8, at_bounds));
    let now = snapshot(&scratch.0.join("mirror"), true);
    assert!(now.contains_key("README") && now.contains_key("Title") && !now.contains_key("title"));
    // After `Ended` a mirror takes nothing more.
    assert!(matches!(
        mirror.take(ToMirror::Ended, Instant::now()),
        Ok(true)
    ));
    let after = mirror.take(ToMirror::Round(10), Instant::now());
    assert!(matches!(after, Err(Fault::Refused(_))), "{after:?}");
}

/// A second round that has every kind of message, for a mirror that had `first_round`.
fn second_round() -> Vec<ToMirror> {
    let messages = vec![
        moved("title", "title.1"),
        folder("alt"),
        piece("alt/screen", b"an editor's "),
        put("alt/screen", b"screen\n"),
        lines_of(
            "main/screen",
            vec![run(1, 59), Edit::New(b"last\n".to_vec())],
        ),
        add("title.1", 2, b"new "),
        add("title.1", 6, b"title\n"),
        put("title", b"another\n"),
        fifo("ctl"),
        link("shown", "alt"),
        remove("in"),
    ];
    round_of(4, messages)
}

#[test]
fn a_round_cut_at_any_message_leaves_the_round_before() {
    let round = second_round();
    for cut in 0..round.len() {
        let scratch = Scratch::new(&format!("cut-{cut}"));
        let mut mirror = scratch.mirror();
        give(&mut mirror, &first_round());
        let was = snapshot(&scratch.0, true);
        give(&mut mirror, &round[..cut]);
        // (The link is gone.)
        mirror.discard();
        assert!(
            snapshot(&scratch.0, true) == was,
            "cut before message {cut}"
        );
        // The link is back: the round comes whole.
        give(&mut mirror, &round);
        let now = snapshot(&scratch.0.join("mirror"), true);
        let text = |name: &str| String::from_utf8(now[name].clone()).unwrap();
        assert_eq!(
            now.keys().filter(|name| name.starts_with(".koh/")).count(),
            0
        );
        assert_eq!(text("generation"), "4\n");
        assert_eq!(text("title.1"), "a new title\n");
        assert_eq!(text("title"), "another\n");
        assert_eq!(text("alt/screen"), "an editor's screen\n");
        assert_eq!(text("main/screen"), "row\n".repeat(59) + "last\n");
        assert_eq!(text("shown"), "-> alt");
        assert_eq!((text("ctl"), now.get("in")), ("a FIFO".to_string(), None));
        assert!(mirror.fifo("ctl").is_some() && mirror.fifo("in").is_none());
    }
}

#[test]
fn a_round_that_stands_still_or_takes_too_long_is_thrown_away() {
    let scratch = Scratch::new("deadlines");
    let mut mirror = scratch.mirror();
    give(&mut mirror, &first_round());
    let was = snapshot(&scratch.0, true);
    let (began, second) = (Instant::now(), Duration::from_secs(1));
    assert_eq!((STILL, LONG), (30 * second, 600 * second));
    assert!(mirror.due().is_none(), "no round is open");
    // Thirty seconds between two whole messages of an open round, and no more.
    assert!(matches!(mirror.take(ToMirror::Round(4), began), Ok(false)));
    assert_eq!(mirror.due(), Some(began + STILL));
    assert!(matches!(
        mirror.take(put("title", b"one\n"), began + STILL),
        Ok(false)
    ));
    assert_eq!(mirror.due(), Some(began + 2 * STILL));
    let late = mirror.take(put("main/screen", b"late\n"), began + 2 * STILL + second);
    assert!(matches!(late, Err(Fault::Failed(_))), "{late:?}");
    assert!(mirror.due().is_none() && snapshot(&scratch.0, true) == was);
    // Ten minutes from `Round` to `Done`, though its messages never stop coming.
    assert!(matches!(mirror.take(ToMirror::Round(4), began), Ok(false)));
    for n in 0..30 {
        let more = piece("title", b"more\n");
        assert!(matches!(
            mirror.take(more, began + 20 * n * second),
            Ok(false)
        ));
    }
    assert_eq!(mirror.due(), Some(began + LONG));
    let late = mirror.take(ToMirror::Done, began + LONG + second);
    assert!(matches!(late, Err(Fault::Failed(_))), "{late:?}");
    assert!(mirror.due().is_none() && snapshot(&scratch.0, true) == was);
    // What comes in time is taken.
    give(
        &mut mirror,
        &[
            ToMirror::Round(4),
            put("title", b"in time\n"),
            ToMirror::Done,
        ],
    );
    assert_eq!(
        fs::read(scratch.0.join("mirror/title")).unwrap(),
        b"in time\n"
    );
}

/// A pane's folder written by hand as fux's holder writes one: files replaced in one rename,
/// history added to in place, `generation` odd around every change.
struct Hand {
    dir: PathBuf,
    number: u64,
}

impl Hand {
    /// A pane as a shell's is after its first round, with what is never carried beside it.
    fn new(scratch: &Scratch) -> Hand {
        let mut hand = Hand {
            dir: scratch.0.join("pane"),
            number: 0,
        };
        fs::create_dir(&hand.dir).unwrap();
        hand.round(|hand| {
            fs::create_dir(hand.dir.join("main")).unwrap();
            for fifo in ["in", "ctl"] {
                fuxix::fifo(hand.dir.join(fifo)).unwrap();
            }
            hand.replace("status", b"holder 1\npid 2\ncommand sh\n");
            hand.replace("command", b"sh\0");
            hand.replace(".view.7", b"a viewer's\n");
            hand.replace("main/screen", &b"$ \n".repeat(24));
            hand.replace("main/screen.styled", &b"\x1b[32m$\x1b[m \n".repeat(24));
            hand.replace("main/lines", b"0\n\n");
            hand.replace("size", b"80 24\n");
            hand.replace("state", b"running\n");
            hand.replace("history", b"");
            hand.turn_to("main");
        });
        hand
    }

    fn replace(&self, name: &str, bytes: &[u8]) {
        fux::replace(self.dir.join(name), bytes).unwrap();
    }

    fn append(&self, name: &str, bytes: &[u8]) {
        let file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.dir.join(name));
        file.unwrap().write_all(bytes).unwrap();
    }

    /// Cuts a file to `len` bytes in place and writes others after them: what a resize does to
    /// history when it takes rows back and gives others.
    fn cut(&self, name: &str, len: usize, then: &[u8]) {
        let file = fs::OpenOptions::new()
            .write(true)
            .open(self.dir.join(name))
            .unwrap();
        file.set_len(len as u64).unwrap();
        self.append(name, then);
    }

    fn rename(&self, from: &str, to: &str) {
        fs::rename(self.dir.join(from), self.dir.join(to)).unwrap();
    }

    /// `shown` turned to a screen's folder, in one step.
    fn turn_to(&self, screen: &str) {
        let new = fux::staging(&self.dir.join("shown"));
        symlink(screen, &new).unwrap();
        fs::rename(new, self.dir.join("shown")).unwrap();
    }

    fn turn(&mut self) {
        self.number += 1;
        self.replace("generation", format!("{}\n", self.number).as_bytes());
    }

    fn round(&mut self, change: impl FnOnce(&Hand)) {
        self.turn();
        change(self);
        self.turn();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.dir.join(name)).unwrap()
    }
}

/// A look as the tests mostly ask for one: the round it read, if it read one.
trait Rounds {
    fn round(&mut self, dead: bool, now: Instant) -> Option<Vec<ToMirror>>;
}

impl Rounds for Reader {
    fn round(&mut self, dead: bool, now: Instant) -> Option<Vec<ToMirror>> {
        match self.look(dead, now) {
            Look::Round(round) => Some(round),
            _ => None,
        }
    }
}

/// How many bytes a round is as it is sent.
fn wire(round: &[ToMirror]) -> usize {
    round
        .iter()
        .map(|message| 4 + encode(message, MAX_CHUNK).unwrap().len())
        .sum()
}

/// A server's reader of a pane and a client's mirror of it, with the wire between them.
struct Line {
    pane: PathBuf,
    reader: Reader,
    mirror: Mirror,
    clock: Instant,
}

impl Line {
    /// A client that attached and has its first round.
    fn new(scratch: &Scratch, hand: &Hand) -> Line {
        let (reader, mirror) = (Reader::new(&hand.dir), scratch.mirror());
        let mut line = Line {
            pane: hand.dir.clone(),
            reader,
            mirror,
            clock: Instant::now(),
        };
        line.attach();
        line.round();
        line
    }

    /// The link is back, on a stream of its own: the server has no record, and the client says
    /// what its mirror has.
    fn attach(&mut self) {
        self.reader = Reader::new(&self.pane);
        let list = encode(&FromMirror::Has(self.mirror.has().unwrap()), MAX_CHUNK).unwrap();
        let Ok(FromMirror::Has(list)) = decode(&list, MAX_CHUNK) else {
            panic!("no list")
        };
        assert!(matches!(self.reader.has(&list, false), Ok(true)));
    }

    /// One look at the pane when its reader has rested, and what it read through the wire into
    /// the mirror: the round, which is none where nothing differs.
    fn round(&mut self) -> Vec<ToMirror> {
        self.clock += Duration::from_secs(3600);
        let round = self
            .reader
            .round(false, self.clock)
            .expect("the folder stood still");
        give(&mut self.mirror, &round);
        round
    }

    /// What differs between the pane and its mirror, of what is carried: nothing, after a round.
    fn differs(&self) -> Vec<String> {
        let mut pane = snapshot(&self.pane, false);
        pane.retain(|name, _| name != "command" && name != "status");
        let mirror = snapshot(&self.pane.with_file_name("mirror"), false);
        let names = pane
            .keys()
            .chain(mirror.keys())
            .filter(|name| pane.get(*name) != mirror.get(*name));
        names.cloned().collect::<HashSet<_>>().into_iter().collect()
    }
}

const NONE: Vec<String> = Vec::new();

/// Lines of text that are all different, `count` of them from the line `from`.
fn text(from: usize, count: usize) -> Vec<u8> {
    (from..from + count)
        .flat_map(|n| {
            format!("line {n:06} of a history as long as fux lets one grow, more or less\n")
                .into_bytes()
        })
        .collect()
}

#[test]
fn a_folder_through_a_pipe_is_the_same_folder() {
    let scratch = Scratch::new("pipe");
    let mut hand = Hand::new(&scratch);
    hand.round(|hand| hand.append("history", &text(0, 20_000)));
    let (mut reader, mut mirror) = (Reader::new(&hand.dir), scratch.mirror());
    assert!(matches!(
        reader.has(&mirror.has().unwrap(), false),
        Ok(true)
    ));
    let round = reader.round(false, Instant::now()).unwrap();
    // The round as it is sent: each message's length, then the message.
    let (mut from, mut to) = io::pipe().unwrap();
    let client = std::thread::spawn(move || {
        let mut length = [0; 4];
        while from.read_exact(&mut length).is_ok() {
            let mut body = vec![0; u32::from_be_bytes(length) as usize];
            from.read_exact(&mut body).unwrap();
            let message = decode(&body, MAX_CHUNK).unwrap();
            assert!(matches!(mirror.take(message, Instant::now()), Ok(false)));
        }
        mirror
    });
    for message in &round {
        let body = encode(message, MAX_CHUNK).unwrap();
        to.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        to.write_all(&body).unwrap();
    }
    drop(to);
    let mirror = client.join().unwrap();
    let line = Line {
        pane: hand.dir.clone(),
        reader,
        mirror,
        clock: Instant::now(),
    };
    assert_eq!(line.differs(), NONE);
    let mirror = snapshot(&scratch.0.join("mirror"), true);
    let pieces = |message: &&ToMirror| matches!(message, ToMirror::Put { more: true, .. });
    assert!(mirror["history"].len() > 1 << 20 && round.iter().filter(pieces).count() == 5);
    assert_eq!(
        (mirror["generation"].as_slice(), mirror["shown"].as_slice()),
        (&b"4\n"[..], &b"-> main"[..])
    );
    assert_eq!(mirror["in"], b"a FIFO");
    let never = ["command", "status", ".view.7"];
    assert!(
        !never.iter().any(|name| mirror.contains_key(*name)),
        "{:?}",
        mirror.keys()
    );
    assert_eq!(
        fs::metadata(scratch.0.join("mirror")).unwrap().mode() & 0o777,
        0o700
    );
}

#[test]
fn every_change_a_holder_makes_is_carried() {
    let scratch = Scratch::new("changes");
    let mut hand = Hand::new(&scratch);
    let mut line = Line::new(&scratch, &hand);
    assert_eq!(line.differs(), NONE);
    const ALT: [&str; 3] = ["alt/screen", "alt/screen.styled", "alt/lines"];
    type Change = Box<dyn Fn(&Hand)>;
    let changes: Vec<(&str, Change)> = vec![
        (
            "files replaced",
            Box::new(|hand| {
                hand.replace("main/screen", &b"$ make\n".repeat(24));
                hand.replace("title", b"make\n");
            }),
        ),
        (
            "a file added to",
            Box::new(|hand| hand.append("history", &text(0, 300))),
        ),
        (
            "the alternate screen taken",
            Box::new(|hand| {
                fs::create_dir(hand.dir.join("alt")).unwrap();
                ALT.iter()
                    .for_each(|name| hand.replace(name, b"an editor\n"));
                hand.turn_to("alt");
            }),
        ),
        (
            "and left",
            Box::new(|hand| {
                hand.turn_to("main");
                fs::remove_dir_all(hand.dir.join("alt")).unwrap();
            }),
        ),
        (
            "a file removed",
            Box::new(|hand| fs::remove_file(hand.dir.join("title")).unwrap()),
        ),
        (
            "the program's end",
            Box::new(|hand| {
                hand.replace("state", b"exited 7\n");
                ["in", "ctl"]
                    .iter()
                    .for_each(|name| fs::remove_file(hand.dir.join(name)).unwrap());
            }),
        ),
    ];
    let mut rounds = Vec::new();
    for (what, change) in changes {
        hand.round(change);
        rounds.push(line.round());
        assert_eq!(line.differs(), NONE, "{what}");
        // Nothing changed since: the next look reads no round.
        assert_eq!(line.round(), vec![], "{what}");
    }
    // A screen's folder is filled before `shown` is turned to it, and goes after it is turned back.
    let at =
        |round: &[ToMirror], message: ToMirror| round.iter().position(|m| *m == message).unwrap();
    let (taken, left) = (&rounds[2], &rounds[3]);
    assert!(at(taken, put("alt/screen", b"an editor\n")) < at(taken, link("shown", "alt")));
    assert!(
        at(left, link("shown", "main")) < at(left, remove("alt")),
        "{left:?}"
    );
    assert_eq!(
        left.len(),
        7,
        "the link, a folder and its three files: {left:?}"
    );
    // What came and went between two looks is not told of. (The link may be: it is another
    // than the one that was read, though it leads where that did.)
    hand.round(|hand| fs::create_dir(hand.dir.join("alt")).unwrap());
    hand.round(|hand| hand.turn_to("alt"));
    hand.round(|hand| {
        hand.turn_to("main");
        fs::remove_dir_all(hand.dir.join("alt")).unwrap();
    });
    let round = line.round();
    let told = |message: &ToMirror| matches!(message, ToMirror::Folder(_) | ToMirror::Remove(_));
    assert!(!round.iter().any(told) && round.len() <= 3, "{round:?}");
    assert_eq!(line.differs(), NONE);
    // A folder inside a folder is not carried, nor what is in it.
    hand.round(|hand| {
        fs::create_dir(hand.dir.join("main/deep")).unwrap();
        hand.replace("main/deep/x", b"not a pane's\n");
    });
    assert_eq!(line.round(), vec![]);
}

#[test]
fn a_cut_inside_the_kept_end_sends_only_what_follows_it() {
    let scratch = Scratch::new("cut-in-end");
    let mut hand = Hand::new(&scratch);
    hand.round(|hand| hand.append("history", &text(0, 64_000)));
    let mut line = Line::new(&scratch, &hand);
    let whole = hand.read("history").len();
    assert!(whole > 4 << 20);
    // A resize takes rows back from history's end and gives others, again and again.
    // (What is cut is cut from the kept end too, and what is added fills it again.)
    for (taken, given) in [(1024, 3000), (40_000, 100), (0, 5000), (30_000, 0)] {
        let kept = hand.read("history").len() - taken;
        hand.round(|hand| hand.cut("history", kept, &b"x".repeat(given)));
        let round = line.round();
        assert_eq!(line.differs(), NONE);
        assert!(
            wire(&round) < given + 256,
            "{} bytes for {given} after a cut of {taken}",
            wire(&round)
        );
    }
}

/// A file written in place is cut to so many bytes and given others, as `changed` says of what
/// it was, in one round: the mirror's is the pane's after it, and it went whole.
fn cut_and_grown(name: &str, old: &[u8], changed: impl Fn(&[u8]) -> (usize, Vec<u8>)) {
    let scratch = Scratch::new(name);
    let mut hand = Hand::new(&scratch);
    hand.round(|hand| hand.append("history", old));
    let mut line = Line::new(&scratch, &hand);
    // (Added to in place once, so that it is known as a file that is.)
    hand.round(|hand| hand.append("history", &b"z".repeat(80)));
    line.round();
    let old = hand.read("history");
    let (kept, then) = changed(&old);
    hand.round(|hand| hand.cut("history", kept, &then));
    let round = line.round();
    assert_eq!(line.differs(), NONE);
    assert!(
        round
            .iter()
            .all(|message| !matches!(message, ToMirror::Add { .. })),
        "{name}"
    );
    assert!(wire(&round) > kept + then.len(), "{name}");
}

#[test]
fn a_file_cut_past_its_kept_end_goes_whole() {
    // Cut to 10 KiB and grown to 88: other bytes where the kept end began, but for its first.
    cut_and_grown("cut-past-end", &b"a".repeat(80 << 10), |old| {
        let mut then = b"b".repeat(78 << 10);
        then[old.len() - END - (10 << 10)] = b'a';
        (10 << 10, then)
    });
    // Cut to less than what was before the kept end, and no more.
    cut_and_grown("cut-short", &text(0, 2000), |_| (10 << 10, Vec::new()));
}

#[test]
fn the_same_end_over_other_bytes_goes_whole() {
    // Cut far back and grown past its old length, and the 64 KiB before that length the same
    // bytes as before, though earlier ones are not: only the hash says so.
    let same = b"y\n".repeat(END / 2);
    let old = [text(0, 2000), same.clone()[..END - 80].to_vec()].concat();
    cut_and_grown("same-end", &old, |old| {
        let other = text(5000, 2000)[..old.len() - END - (50 << 10)].to_vec();
        (
            50 << 10,
            [other, same.clone(), b"z".repeat(10 << 10)].concat(),
        )
    });
}

#[test]
fn a_file_replaced_after_bytes_were_added_is_told_from_the_disk() {
    let marks = |from: usize, count: usize| -> Vec<u8> {
        let mark = |n| format!("{n} 0 prompt\n{n} 2 command\n").into_bytes();
        (from..from + count).flat_map(mark).collect()
    };
    for back in [false, true] {
        let scratch = Scratch::new(&format!("replaced-{back}"));
        let mut hand = Hand::new(&scratch);
        hand.round(|hand| hand.replace("marks", &marks(100, 40)));
        let mut line = Line::new(&scratch, &hand);
        // Cut and added to in place: the lines the server kept of the file are the client's no more.
        hand.round(|hand| hand.cut("marks", marks(100, 10).len(), &marks(500, 30)));
        line.round();
        if back {
            // (The link gone and back: the server knows the file again, by the mirror's list.)
            line.attach();
            line.round();
        }
        // Replaced by a file that has the lines that were cut, and those that came instead.
        hand.round(|hand| hand.replace("marks", &[marks(100, 40), marks(505, 20)].concat()));
        let round = line.round();
        assert_eq!(line.differs(), NONE, "back: {back}");
        // What is proved of the file before is the base of the new one's lines; else it goes whole.
        let lines = |message: &ToMirror| matches!(message, ToMirror::Lines { .. });
        assert_eq!(round.iter().any(lines), back);
    }
}

#[test]
fn a_history_renamed_while_away_is_moved_and_added_to() {
    let scratch = Scratch::new("renamed");
    let mut hand = Hand::new(&scratch);
    hand.round(|hand| hand.append("history", &text(0, 20_000)));
    let mut line = Line::new(&scratch, &hand);
    // The holder puts `history` and `history.styled` aside in one round, where a line ends, and
    // begins new ones: three times, the second and third over older ones; the client away,
    // there, and away again.
    hand.round(|hand| hand.append("history.styled", &text(0, 20_000)));
    line.round();
    for (turn, away) in [true, false, true].into_iter().enumerate() {
        hand.round(|hand| {
            for name in ["history", "history.styled"] {
                hand.append(name, &text(30_000, 100));
                hand.rename(name, &format!("{name}.1"));
                hand.append(name, &text(40_000 + turn, 200));
            }
        });
        if away {
            line.attach();
        }
        let round = line.round();
        assert_eq!(line.differs(), NONE, "turn {turn}");
        let moves = [
            moved("history", "history.1"),
            moved("history.styled", "history.styled.1"),
        ];
        assert_eq!(round.get(1..3), Some(&moves[..]), "turn {turn}");
        assert!(
            !matches!(round.get(3), Some(ToMirror::Moved { .. })),
            "turn {turn}"
        );
        let added = 2 * text(0, 300).len();
        assert!(
            wire(&round) < added + 1024,
            "turn {turn}: {} bytes for {added} added",
            wire(&round)
        );
    }
    // Two moves a list could find and the first round must not tell, as a mirror takes neither:
    // into a folder it has not yet, and of a file that is told as lines of itself right after.
    hand.round(|hand| {
        hand.replace("notes", &text(0, 100));
        hand.replace("other", &text(200, 100));
    });
    line.round();
    hand.round(|hand| {
        fs::create_dir(hand.dir.join("alt")).unwrap();
        hand.rename("notes", "alt/notes");
        hand.rename("other", "other.1");
    });
    line.attach();
    hand.round(|hand| hand.replace("other.1", &text(201, 99)));
    let round = line.round();
    assert_eq!(line.differs(), NONE);
    assert!(
        round.contains(&moved("other", "other.1"))
            && round.contains(&put("other.1", &text(201, 99)))
    );
    assert!(round.contains(&put("alt/notes", &text(0, 100))));
}

#[test]
fn moves_that_chain_move_nothing() {
    for away in [false, true] {
        let scratch = Scratch::new(&format!("chain-{away}"));
        let mut hand = Hand::new(&scratch);
        hand.round(|hand| {
            hand.append("a", &text(0, 100));
            hand.append("b", &text(500, 100));
        });
        let mut line = Line::new(&scratch, &hand);
        hand.round(|hand| {
            hand.rename("b", "c");
            hand.rename("a", "b");
        });
        if away {
            line.attach();
        }
        let round = line.round();
        assert_eq!(line.differs(), NONE, "away: {away}");
        assert!(
            !round
                .iter()
                .any(|message| matches!(message, ToMirror::Moved { .. })),
            "away: {away}"
        );
        assert!(wire(&round) > text(0, 200).len(), "both files go whole");
    }
}

#[test]
fn a_list_read_while_the_folder_changes_is_read_again() {
    let scratch = Scratch::new("list");
    let mut hand = Hand::new(&scratch);
    let mut line = Line::new(&scratch, &hand);
    // The holder writes a round while the server reads what the client says it has.
    let list = line.mirror.has().unwrap();
    line.reader = Reader::new(&hand.dir);
    let pane = hand.dir.clone();
    line.reader.midway = Some(Box::new(move || {
        fux::replace(pane.join("generation"), b"5\n").unwrap();
        fux::replace(pane.join("title"), b"written meanwhile\n").unwrap();
        fux::replace(pane.join("generation"), b"6\n").unwrap();
    }));
    assert!(matches!(line.reader.has(&list, false), Ok(false)));
    assert!(line.reader.kept.is_empty() && line.reader.round(false, line.clock).unwrap().len() > 9);
    // Read again, it is one list of one round; and while the number is odd it is not read.
    fux::replace(hand.dir.join("generation"), b"7\n").unwrap();
    assert!(matches!(line.reader.has(&list, false), Ok(false)));
    fux::replace(hand.dir.join("generation"), b"8\n").unwrap();
    assert!(matches!(line.reader.has(&list, false), Ok(true)));
    hand.number = 8;
    let round = line.round();
    assert_eq!(
        round,
        round_of(
            8,
            vec![put("title", b"written meanwhile\n"), link("shown", "main")]
        )
    );
    assert_eq!(line.differs(), NONE);
    // A list that is none is refused: a name twice, a name that is none, more than a mirror has.
    let had = |name: &str| Had {
        name: name.into(),
        kind: Kind::File,
        len: 0,
        hash: [0; 32],
    };
    let many: Vec<Had> = (0..=NAMES).map(|n| had(&format!("n{n}"))).collect();
    for list in [
        vec![had("title"), had("title")],
        vec![had("../title")],
        vec![had("command")],
        many,
    ] {
        assert!(matches!(
            line.reader.has(&list, false),
            Err(Fault::Refused(_))
        ));
    }
}

#[test]
fn nothing_kept_changes_unless_the_round_is_one() {
    let scratch = Scratch::new("kept");
    let mut hand = Hand::new(&scratch);
    let mut line = Line::new(&scratch, &hand);
    hand.round(|hand| {
        hand.append("history", &text(0, 10));
        hand.replace("title", b"one\n");
    });
    // The holder writes its next round while this one is read: what was read is of two rounds.
    let pane = hand.dir.clone();
    line.reader.midway = Some(Box::new(move || {
        fux::replace(pane.join("generation"), b"7\n").unwrap();
        fux::replace(pane.join("title"), b"two\n").unwrap();
        fux::replace(pane.join("generation"), b"8\n").unwrap();
    }));
    line.clock += Duration::from_secs(3600);
    assert_eq!(line.reader.look(false, line.clock), Look::Moved);
    // So nothing was sent, and nothing is taken as sent: the next round has all of it. And
    // the reader does not rest then, with nothing sent: the next look is read at once.
    hand.number = 8;
    let thrown = line.reader.owed;
    assert!(line.reader.rests.is_none() && !thrown.is_zero());
    let Look::Round(round) = line.reader.look(false, line.clock) else {
        panic!("a read that was thrown away earned a rest")
    };
    give(&mut line.mirror, &round);
    // (What the read took, having a file to prove, is rested for after the look that proves.)
    assert!(line.reader.rests.is_some() && line.reader.owed.is_zero());
    assert_eq!(
        round,
        round_of(
            8,
            vec![add("history", 0, &text(0, 10)), put("title", b"two\n")]
        )
    );
    assert_eq!(line.differs(), NONE);
    // While the holder writes (an odd number) nothing is read at all.
    hand.turn();
    line.clock += Duration::from_secs(3600);
    assert_eq!(line.reader.look(false, line.clock), Look::Odd);
    // Nor at the number 0, which no round has: a round's is 2 at least.
    hand.replace("generation", b"0\n");
    assert_eq!(line.reader.look(false, line.clock), Look::Odd);
    assert!(matches!(line.reader.has(&[], false), Ok(false)));
}

#[test]
fn a_holder_dead_at_an_odd_number_is_read_as_it_is() {
    let scratch = Scratch::new("dead");
    let mut hand = Hand::new(&scratch);
    let mut line = Line::new(&scratch, &hand);
    // Killed in the middle of a round: the number stays odd for good.
    hand.number = 40;
    hand.turn();
    hand.replace("main/screen", b"half a round\n");
    let later = line.clock + Duration::from_secs(3600);
    assert!(
        line.reader.round(false, later).is_none(),
        "a holder that lives is writing"
    );
    let round = line
        .reader
        .round(true, later + Duration::from_secs(3600))
        .unwrap();
    assert_eq!(
        round,
        round_of(42, vec![put("main/screen", b"half a round\n")])
    );
    give(&mut line.mirror, &round);
    assert_eq!(line.differs(), vec!["generation".to_string()]);
    assert_eq!(
        fs::read(scratch.0.join("mirror/generation")).unwrap(),
        b"42\n"
    );
    // And the list of a client that comes then is read, as the folder is.
    line.reader = Reader::new(&hand.dir);
    let list = line.mirror.has().unwrap();
    assert!(matches!(line.reader.has(&list, false), Ok(false)));
    assert!(matches!(line.reader.has(&list, true), Ok(true)));
    let round = line.reader.round(true, later).unwrap();
    assert_eq!(round, round_of(42, vec![link("shown", "main")]));
}

#[test]
fn the_first_round_is_sent_though_nothing_differs_and_makes_an_odd_mirror_even() {
    let scratch = Scratch::new("first");
    let mut hand = Hand::new(&scratch);
    // (A link is sent at every attach, as a list does not say where one leads: a pane without.)
    hand.round(|hand| fs::remove_file(hand.dir.join("shown")).unwrap());
    let mut line = Line::new(&scratch, &hand);
    // A write that failed while a round was applied left the mirror's number odd.
    fux::replace(scratch.0.join("mirror/generation"), b"1\n").unwrap();
    line.attach();
    assert_eq!(line.round(), round_of(4, vec![]));
    assert_eq!(line.differs(), NONE);
    // After the first, a round in which nothing changed is not sent.
    assert_eq!(line.round(), vec![]);
}

#[test]
fn no_message_is_over_its_bound() {
    let scratch = Scratch::new("bound");
    let mut hand = Hand::new(&scratch);
    hand.round(|hand| {
        hand.append("history", &text(0, 70_000));
        hand.append("history.styled", &text(0, 40_000));
        hand.replace(
            "main/screen.styled",
            &b"\x1b[38;2;1;2;3mx\x1b[m".repeat(250_000 / 17),
        );
    });
    // A whole folder, in pieces: each is checked as it is sent (`give`), and none is small.
    let mut line = Line::new(&scratch, &hand);
    assert_eq!((line.round(), line.differs()), (vec![], NONE));
    // A flood's round: what was added, in pieces that say their places.
    hand.round(|hand| hand.append("history", &text(70_000, 9000)));
    let round = line.round();
    let was = text(0, 70_000).len() as u64;
    let places: Vec<u64> = round
        .iter()
        .filter_map(|message| {
            if let ToMirror::Add { at, .. } = message {
                Some(*at - was)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(places, [0, PIECE as u64, 2 * PIECE as u64]);
    assert_eq!(line.differs(), NONE);
    // And what fits no message is refused by whoever is to send it, and by whoever is sent it.
    let over = put("title", &vec![0; MAX_CHUNK]);
    assert!(encode(&over, MAX_CHUNK).is_err());
    assert!(decode::<ToMirror>(&encode(&over, usize::MAX).unwrap(), MAX_CHUNK).is_err());
    assert!(
        decode::<ToMirror>(&[encode(&ToMirror::Done, 9).unwrap(), vec![0]].concat(), 9).is_err()
    );
}

/// A screen replaced by another: the round that tells of it, with the mirror the pane's after it.
fn replaced(name: &str, old: &[u8], new: &[u8]) -> Vec<ToMirror> {
    let scratch = Scratch::new(name);
    let mut hand = Hand::new(&scratch);
    hand.round(|hand| hand.replace("main/screen", old));
    let mut line = Line::new(&scratch, &hand);
    hand.round(|hand| hand.replace("main/screen", new));
    let round = line.round();
    assert_eq!(line.differs(), NONE, "{name}");
    round
}

#[test]
fn lines_as_runs_make_the_same_file() {
    // A screen scrolled by three lines, with a line changed in it: runs of the one before.
    let (old, mut new) = (text(0, 60), [text(3, 57), text(100, 3)].concat());
    new[70] = b'X';
    let round = replaced("lines-scrolled", &old, &new);
    assert!(
        matches!(round.get(1), Some(ToMirror::Lines { edits, .. }) if edits.len() == 4),
        "{round:?}"
    );
    assert!(wire(&round) < new.len() / 8, "{} bytes", wire(&round));
    // Lines from anywhere in the file before, in another order and more than once; a file with
    // no line end at its end; and one whose every line is the same.
    let shuffled = [text(40, 20), text(0, 10), text(40, 20), b"the end".to_vec()].concat();
    let round = replaced("lines-shuffled", &old, &shuffled);
    assert!(
        matches!(round.get(1), Some(ToMirror::Lines { edits, .. }) if edits.len() == 4),
        "{round:?}"
    );
    let round = replaced(
        "lines-same",
        &b"the same line\n".repeat(50),
        &b"the same line\n".repeat(70),
    );
    assert!(
        matches!(round.get(1), Some(ToMirror::Lines { .. })),
        "{round:?}"
    );
}

#[test]
fn lines_no_smaller_than_the_file_go_whole() {
    let other: Vec<u8> = text(0, 60)
        .iter()
        .map(|byte| byte.to_ascii_uppercase())
        .collect();
    assert_eq!(
        replaced("lines-other", &text(0, 60), &other),
        round_of(6, vec![put("main/screen", &other)])
    );
    // And a file of 128 bytes or fewer, before or after, is not looked at for its lines.
    let small = &text(0, 2)[..SMALL];
    assert_eq!(
        replaced("lines-small", &text(0, 60), small),
        round_of(6, vec![put("main/screen", small)])
    );
    assert_eq!(
        replaced("lines-grown", small, &text(0, 2)),
        round_of(6, vec![put("main/screen", &text(0, 2))])
    );
}

#[test]
fn more_lines_than_the_gate_go_whole() {
    let numbers = |count: usize| -> Vec<u8> {
        (0..count)
            .flat_map(|n| format!("{n:07}\n").into_bytes())
            .collect()
    };
    let lines = |round: &[ToMirror]| {
        round
            .iter()
            .any(|message| matches!(message, ToMirror::Lines { .. }))
    };
    // A file with a line no message holds is not told as lines, and its bytes are not kept for
    // it: a picture of megabytes in one line would be, for every client, and for nothing.
    let picture = [vec![b'~'; PIECE + 1], b"\nand a line\n".repeat(20)].concat();
    let changed = [&picture[..], b"one more\n"].concat();
    assert!(!lines(&replaced("gate-long", &picture, &changed)));
    // 4,096 lines are told as lines; one more, of the file or of the one before it, and it goes whole.
    assert!(lines(&replaced(
        "gate-at",
        &numbers(LINES),
        &numbers(LINES - 1)
    )));
    assert!(!lines(&replaced(
        "gate-new",
        &numbers(LINES),
        &numbers(LINES + 1)
    )));
    assert!(!lines(&replaced(
        "gate-old",
        &numbers(LINES + 1),
        &numbers(LINES)
    )));
}

#[test]
fn the_reader_rests_nine_times_as_long_as_its_round_took() {
    let scratch = Scratch::new("rest");
    let mut hand = Hand::new(&scratch);
    hand.round(|hand| hand.append("history", &text(0, 64_000)));
    let mut line = Line::new(&scratch, &hand);
    // A look that has 4 MiB to prove.
    hand.round(|hand| hand.append("history", b"more\n"));
    let at = line.clock + Duration::from_secs(3600);
    let outside = Instant::now();
    assert_eq!(line.reader.round(false, at).unwrap().len(), 3);
    let rests = line.reader.rests.unwrap();
    let took = (rests - at) / 10;
    assert!(!took.is_zero() && took <= outside.elapsed());
    // No file is proved again until nine times that long after the look: not though one changed.
    hand.round(|hand| hand.append("history", b"and more\n"));
    let before = rests - Duration::from_nanos(1);
    assert_eq!(line.reader.look(false, before), Look::Rests(rests));
    assert_eq!(line.reader.round(false, rests).unwrap().len(), 3);
    // The rest is owed by proving alone. A look that proves nothing is not held back by it (a
    // key's echo changes a screen), and earns none.
    let rests = line.reader.rests.unwrap();
    hand.round(|hand| hand.replace("main/screen", b"$ l\n"));
    let round = line.reader.round(false, rests - Duration::from_nanos(1));
    assert_eq!(
        round,
        Some(round_of(hand.number, vec![put("main/screen", b"$ l\n")]))
    );
    assert_eq!(line.reader.rests, Some(rests));
    // Nine times the look, and nine times what the reads took that were thrown away before
    // it: as far as that is no more than one rest of the look's own, so that reads thrown
    // away for a minute are not nine minutes of rest. And no length of time overflows it.
    let second = Duration::from_secs(1);
    assert_eq!(rest(second, Duration::ZERO), 10 * second);
    assert_eq!(rest(2 * second, second), 29 * second);
    assert_eq!(rest(second, 9 * second), 91 * second);
    assert_eq!(rest(second, 100 * second), 91 * second);
    assert_eq!(rest(Duration::MAX, Duration::MAX), Duration::MAX);
    line.reader.owed = 1000 * second;
    hand.round(|hand| hand.append("history", b"and yet more\n"));
    assert_eq!(line.reader.round(false, rests).unwrap().len(), 3);
    assert!(line.reader.rests.unwrap() - rests < 100 * second && line.reader.owed.is_zero());
    // Only a read that had a file to prove is owed for. Twenty reads of a screen thrown away,
    // each with a round of a screen after it, a day apart: nothing is owed, then or ever.
    let later = line.reader.rests.unwrap();
    for day in 1..=20 {
        hand.round(|hand| hand.replace("main/screen", format!("day {day}\n").as_bytes()));
        let (pane, number) = (hand.dir.clone(), hand.number);
        line.reader.midway = Some(Box::new(move || {
            fux::replace(
                pane.join("generation"),
                format!("{}\n", number + 2).as_bytes(),
            )
            .unwrap();
        }));
        hand.number += 2;
        let at = later + 86_400 * day * second;
        assert_eq!(line.reader.look(false, at), Look::Moved);
        assert!(matches!(line.reader.look(false, at), Look::Round(round) if round.len() == 3));
        assert!(
            line.reader.owed.is_zero(),
            "day {day}: {:?}",
            line.reader.owed
        );
    }
}

#[test]
fn a_sum_is_of_its_bytes_however_they_come_and_of_its_readers_key() {
    const KEY: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let bytes = text(0, 40);
    let sum = |key: [u64; 8], bytes: &[u8], pieces: usize| {
        let mut sum = Sum {
            key,
            ..Sum::default()
        };
        bytes.chunks(pieces).for_each(|piece| sum.update(piece));
        sum
    };
    let whole = sum(KEY, &bytes, bytes.len());
    for pieces in [1, 7, 63, 64, 65, 128, 1000] {
        assert!(sum(KEY, &bytes, pieces) == whole, "in pieces of {pieces}");
    }
    // Another key is another sum, and so is another byte anywhere: in each word of a block,
    // in another block, and after the last whole one.
    for word in 0..8 {
        let mut key = KEY;
        key[word] ^= 1;
        assert!(
            sum(key, &bytes, 64).lanes != whole.lanes,
            "word {word} of the key"
        );
    }
    for at in (0..64)
        .step_by(8)
        .chain([63, 64, 127, bytes.len() - 70, bytes.len() - 1])
    {
        let mut other = bytes.clone();
        other[at] ^= 1;
        assert!(sum(KEY, &other, 64) != whole, "byte {at}");
    }
    // A file's is read from the file, and is none where the file is shorter than was asked.
    let scratch = Scratch::new("sum");
    fs::write(scratch.0.join("file"), &bytes).unwrap();
    let file = File::open(scratch.0.join("file")).unwrap();
    assert!(Sum::of(KEY, &file, bytes.len() as u64) == Some(whole));
    assert!(Sum::of(KEY, &file, bytes.len() as u64 + 1).is_none());
    // Two readers have two keys.
    assert_ne!(Reader::new(&scratch.0).key, Reader::new(&scratch.0).key);
}
