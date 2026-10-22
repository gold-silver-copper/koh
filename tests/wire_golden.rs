//! The koh/16 encoding.
//!
//! Messages built here by hand from the wire types, both ways, are pinned: the expected bytes were
//! captured by running the encoder, and a change to the wire must change them in the same commit,
//! deliberately, and bump the protocol's name (the ALPN), which is pinned beside them. Each also
//! decodes back to itself, and seeds the fuzzers.
#![forbid(clippy::disallowed_methods)]

use koh::events::{InputEvent, WireColours, WireKey, WireKeyCode, WireScheme};
use koh::proto::{encode_client, encode_shown, ClientMsg, InputSeq, MarkText, Shown};
use koh::request::{
    Answer, Argv, Attached, Command, CommandLine, ExitStatus, JobName, KeyProof, LogMsg, On, Pick,
    Problem, ProblemKind, RemotePath, Request, Resume, Run, RunId, SessionNum, Until, Wait,
    WaitText,
};
use koh::sync::{Answer as SyncAnswer, FileId, Item, Mode, Name, Opts, Reply, SourceCount};
use koh::terminal::{Activity, Size, TtyModes};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn path(p: &str) -> Option<RemotePath> {
    RemotePath::new(p.as_bytes().to_vec()).ok()
}

fn requests() -> Option<Vec<Request>> {
    let argv = |words: &[&str]| {
        Argv::new(words.iter().map(|w| w.as_bytes().to_vec()).collect())
            .ok()
            .map(Command::Argv)
    };
    Some(vec![
        Request::Shell {
            pick: Pick::Resume(Resume {
                run: RunId(9),
                session: SessionNum(2),
            }),
            size: Size::new(24, 80),
            program: None,
            cwd: None,
        },
        Request::Shell {
            pick: Pick::New,
            size: Size::new(24, 80),
            program: Argv::new(vec![b"gdb".to_vec()]).ok(),
            cwd: Some(path("proj")?),
        },
        Request::Exec {
            run: Run {
                command: argv(&["make", "-j4"])?,
                cwd: Some(path("src")?),
            },
            together: false,
        },
        Request::Start {
            name: Some(JobName::new("build").ok()?),
            run: Run {
                command: Command::Shell(CommandLine::new(b"cd x && make".to_vec()).ok()?),
                cwd: None,
            },
        },
        Request::Logs {
            job: JobName::new("build").ok()?,
            follow: true,
            tail: Some(200),
        },
        Request::Wait(
            Wait::new(
                Some(On::Job(JobName::new("build").ok()?)),
                Until::Text(WaitText::new("listening".into()).ok()?),
            )
            .ok()?,
        ),
        Request::Copy(koh::sync::Copy::Put {
            dest: path("proj/")?,
            sources: SourceCount::new(2)?,
            opts: Opts {
                delete: true,
                dry_run: true,
                diff: true,
                ..Opts::default()
            },
        }),
    ])
}

fn client_msgs() -> Vec<ClientMsg> {
    vec![
        ClientMsg::Keys {
            seq: InputSeq(3),
            events: vec![
                InputEvent::Key(WireKey {
                    key: WireKeyCode::Char('a'),
                    mods: 4,
                    kitty: None,
                }),
                InputEvent::Paste("pasted".into()),
            ],
        },
        ClientMsg::Resize {
            n: 1,
            size: Size::new(30, 100),
        },
        ClientMsg::Colours(WireColours {
            foreground: Some([1, 2, 3]),
            scheme: Some(WireScheme::Dark),
            ..WireColours::default()
        }),
        ClientMsg::Read {
            epoch: 2,
            bytes: 70_000,
        },
        ClientMsg::Redraw,
    ]
}

fn shown() -> Option<Vec<Shown>> {
    Some(vec![
        Shown::Out(b"\x1b[1mhi\x1b[m\r\n".to_vec()),
        Shown::Mark(MarkText::new(b"D;1".to_vec())?),
        Shown::Report {
            activity: Activity::Reading,
            input: InputSeq(4),
        },
        Shown::Tty(TtyModes {
            echo: false,
            line: true,
        }),
        Shown::Echo(InputSeq(7)),
        Shown::Bell(2),
        Shown::Title("t".into()),
        Shown::Exit {
            code: 3,
            read: Some(InputSeq(7)),
        },
        Shown::Beat,
    ])
}

fn items() -> Option<Vec<Item>> {
    let name = |n: &str| Name::new(n.as_bytes().to_vec()).ok();
    Some(vec![
        Item::File {
            id: FileId(1),
            name: name("a.rs")?,
            mode: Mode::new(0o644)?,
            mtime: None,
            size: 12,
        },
        Item::Data {
            id: FileId(1),
            from: 0,
        },
        Item::Sent,
        Item::Same(FileId(2)),
        Item::Differs {
            id: FileId(3),
            from: 0,
        },
        Item::Done,
    ])
}

fn replies() -> Vec<Reply> {
    vec![
        Reply::Answer(SyncAnswer::Want {
            id: FileId(1),
            have: 0,
            prefix: None,
        }),
        Reply::End(Ok(koh::sync::Summary::default())),
        Reply::End(Ok(koh::sync::Summary {
            new: 1,
            changes: vec![koh::sync::Change {
                kind: koh::sync::ChangeKind::New,
                path: "src/a.rs".into(),
                size: Some(12),
                was: None,
                diff: None,
            }],
            ..koh::sync::Summary::default()
        })),
    ]
}

/// Every pinned message, framed, as it goes on the wire.
/// What opens a connection: a key's proof, signed over a fixed message (Ed25519 signs the same way
/// each time).
fn key_proof() -> KeyProof {
    let key = iroh::SecretKey::from_bytes(&[7; 32]);
    KeyProof {
        key: key.public(),
        signature: key.sign(b"koh client key proof"),
    }
}

fn framed() -> Option<Vec<(String, Vec<u8>)>> {
    let mut all = Vec::new();
    for r in requests()? {
        all.push((format!("{r:?}"), koh::request::encode(&r, usize::MAX).ok()?));
    }
    for m in client_msgs() {
        all.push((format!("{m:?}"), encode_client(&m).ok()?));
    }
    for s in shown()? {
        all.push((format!("{s:?}"), encode_shown(&s).ok()?));
    }
    for i in items()? {
        all.push((format!("{i:?}"), koh::request::encode(&i, usize::MAX).ok()?));
    }
    for r in replies() {
        all.push((format!("{r:?}"), koh::request::encode(&r, usize::MAX).ok()?));
    }
    let answers: Vec<Vec<u8>> = vec![
        koh::request::encode(
            &Attached {
                at: Resume {
                    run: RunId(9),
                    session: SessionNum(2),
                },
            },
            usize::MAX,
        )
        .ok()?,
        koh::request::encode(&ExitStatus::Exited(137), usize::MAX).ok()?,
        koh::request::encode(
            &Answer::<()>::Err(Problem::new(ProblemKind::NoSuchJob, "build")),
            usize::MAX,
        )
        .ok()?,
        koh::request::encode(&LogMsg::Data(b"out\n".to_vec()), usize::MAX).ok()?,
        koh::request::encode(&LogMsg::Cut(3), usize::MAX).ok()?,
        koh::request::encode(
            &LogMsg::End {
                exit: Some(101),
                secs: 34,
            },
            usize::MAX,
        )
        .ok()?,
    ];
    for (n, a) in answers.into_iter().enumerate() {
        all.push((format!("answer {n}"), a));
    }
    all.push((
        "a key proof".to_owned(),
        koh::request::encode(&key_proof(), usize::MAX).ok()?,
    ));
    Some(all)
}

#[test]
fn the_wire_is_pinned() {
    assert_eq!(koh::transport_iroh::PROTOCOL, "koh/16");
    let got: Vec<String> = framed()
        .unwrap()
        .iter()
        .map(|(_, bytes)| hex(bytes))
        .collect();
    let want = PINNED;
    let said: Vec<String> = framed()
        .unwrap()
        .iter()
        .map(|(what, bytes)| format!("{what}\n  {}", hex(bytes)))
        .collect();
    assert_eq!(got, want, "the wire changed:\n{}", said.join("\n"));
    // And each decodes back to itself.
    for r in requests().unwrap() {
        let bytes = koh::request::encode(&r, usize::MAX).expect("encodes");
        assert_eq!(
            koh::request::decode_framed::<Request>(&bytes, usize::MAX).expect("decodes"),
            r
        );
    }
    let bytes = koh::request::encode(&key_proof(), usize::MAX).expect("encodes");
    assert_eq!(
        koh::request::decode_framed::<KeyProof>(&bytes, koh::request::MAX_PROOF).expect("decodes"),
        key_proof()
    );
    let mut decoder = koh::proto::ShownDecoder::default();
    for s in shown().unwrap() {
        decoder.push(&encode_shown(&s).expect("encodes"));
        assert_eq!(decoder.next_shown().expect("decodes"), Some(s));
    }
    let mut decoder = koh::proto::ClientDecoder::default();
    for m in client_msgs() {
        decoder.push(&encode_client(&m).expect("encodes"));
        assert_eq!(decoder.next_msg().expect("decodes"), Some(m));
    }
}

/// The pinned messages, as fuzz seeds, into `KOH_FUZZ_SEEDS` if it names a directory.
#[test]
fn the_wire_messages_seed_the_fuzzers() {
    let client: Vec<u8> = client_msgs()
        .iter()
        .flat_map(|m| encode_client(m).expect("encodes"))
        .collect();
    let streamed: Vec<u8> = shown()
        .unwrap()
        .iter()
        .flat_map(|s| encode_shown(s).expect("encodes"))
        .collect();
    let bodies = framed()
        .unwrap()
        .into_iter()
        .map(|(_, framed)| framed[4..].to_vec());
    let seeds = [
        // The first byte splits the rest into reads of that many bytes.
        ("proto_decode", [&[255][..], &client].concat()),
        ("proto_decode", [&[7][..], &streamed].concat()),
        ("server_input", [&[0][..], &client].concat()),
    ]
    .into_iter()
    .chain(bodies.map(|body| ("request_decode", body)));
    let Some(root) = std::env::var_os("KOH_FUZZ_SEEDS") else {
        return;
    };
    for (n, (target, seed)) in seeds.enumerate() {
        let dir = std::path::Path::new(&root).join(target);
        std::fs::create_dir_all(&dir).expect("the target's corpus");
        std::fs::write(dir.join(format!("wire-{n}")), seed).expect("a seed");
    }
}

/// Captured by running the encoder; see the module's doc.
const PINNED: &[&str] = &[
    "000000080003090218500000",
    "0000001000011850010103676462010470726f6a",
    "00000012030002046d616b65032d6a34010373726300",
    "000000170401056275696c64010c63642078202626206d616b6500",
    "0000000b06056275696c640101c801",
    "00000014080100056275696c6401096c697374656e696e67",
    "0000000f09010570726f6a2f02000100010100",
    "000000110103020000016104000306706173746564",
    "0000000400011e64",
    "00000009020101020300000100",
    "000000050302f0a204",
    "0000000104",
    "0000000d000b1b5b316d68691b5b6d0d0a",
    "000000050103443b31",
    "00000003020004",
    "00000003030001",
    "000000020407",
    "000000020502",
    "00000003060174",
    "0000000407030107",
    "0000000108",
    "0000000b020104612e7273a403000c",
    "00000003060100",
    "0000000108",
    "000000020902",
    "000000030c0300",
    "000000010b",
    "000000050000010000",
    "0000001001000000000000000000000000000000",
    "0000001e01000100000000000000000000000100087372632f612e7273010c000000",
    "000000020902",
    "00000003008901",
    "000000080100056275696c64",
    "0000000602046f75740a",
    "000000020103",
    "0000000403016522",
    "00000060ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c51dcaa56c9b849e997169dfeff70a2c1a9320a8c9c741e00c546d2d2c7de27efb8643babafd50525888e47d9dc80cb37f2ee24d53fc1d1af9bde980d4a0d7e02",
];
