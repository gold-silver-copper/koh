//! The koh/7 encoding.
//!
//! Messages built here by hand from the wire types, both ways, are pinned: the expected bytes were
//! captured by running the encoder, and a change to the wire must change them in the same commit,
//! deliberately, and bump the protocol's name (the ALPN), which is pinned beside them. What the
//! emulator draws may improve, so frames and history rows drawn from its output are checked only
//! to round-trip through their streams.
#![forbid(clippy::disallowed_methods)]

use koh::copy::{FailKind, Failure, Item, LinkTarget, Mode, Name, Time};
use koh::events::{
    InputEvent, WireButton, WireColours, WireKey, WireKeyCode, WireKitty, WireMouse,
    WireMouseAction, WireScheme,
};
use koh::proto::{
    decode_frame_body, decode_history, decode_server, dictionary_for, encode_client, ClientDecoder,
    ClientMsg, Frame, FrameEncoder, FrameNum, InputSeq, ServerMsg,
};
use koh::request::{
    Arity, Attached, CommandLine, Copy, ExecStream, ExitStatus, Pick, Presence, RemotePath,
    Request, Resume, RunId, SessionInfo, SessionList, SessionNum, Sources,
};
use koh::terminal::{
    CellKind, CellText, Commands, HistoryMark, HistoryReply, HistoryRequest, HistoryRow, RowDiff,
    RowEncodings, RowFlags, Run, ScreenDiff, ServerTerminal, Shift, Shifts, Size, TerminalScreen,
    TtyModes, WireCell, WireColor, WireLink, WireModes, WireMouseEncoding, WireMouseMode,
    WireStyle,
};
use std::num::{NonZeroI16, NonZeroU16};

/// A stream that must hold a frame on `screen`, the screen of its base, read as the client reads
/// it.
fn decode_frame(stream: &[u8], screen: &TerminalScreen) -> Option<Frame> {
    let ServerMsg::Frame { base, rows, body } = decode_server(stream).ok()? else {
        return None;
    };
    let dictionary = dictionary_for(base, screen, &rows, &mut RowEncodings::default());
    decode_frame_body(base, &body, &dictionary).ok()
}

/// Terminal output exercising every part of a cell and of the side channels: runs, wide glyphs
/// and their continuations, a combining mark, a cluster too long to keep inline, every colour kind
/// on both layers and as an underline's colour, every style bit and both blinks, curly, double and
/// dashed underlines, a hyperlink, a soft wrap, a prompt's mark and a command's, the
/// title, icon, clipboard, bell and the input modes.
const OUTPUT: &[u8] = "\x1b]2;the title\x07\x1b]1;the icon\x07\x1b]52;c;aGVsbG8=\x07\x07\x07\
    \x1b]133;A\x07\x1b]133;C\x07aaaa日本e\u{301}  \r\n\x1b]133;D;2\x07\
    \x1b[31mr\x1b[92mg\x1b[38;5;200mp\x1b[38;2;1;2;3mt\x1b[39m\
    \x1b[44mR\x1b[103mG\x1b[48;5;100mP\x1b[48;2;4;5;6mT\x1b[m\r\n\
    \x1b[1mB\x1b[m\x1b[2mD\x1b[m\x1b[3mI\x1b[m\x1b[4mU\x1b[m\x1b[7mV\x1b[m\
    \x1b[1;2;3;4;7mA\x1b[m\r\n\
    \x1b[5mK\x1b[6mk\x1b[8mH\x1b[9mS\x1b[m\x1b[4;58;5;9mu\x1b[58;2;7;8;9mv\x1b[m\
    \x1b[4:3mc\x1b[4:2md\x1b[4:5mw\x1b[m\x1b]8;id=k;https://koh.example/\x1b\\L\x1b]8;;\x1b\\\
    \u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}\r\n\
    a line long enough to wrap\
    \x1b[?1h\x1b=\x1b[?2004h\x1b[?25l\x1b[?1002h\x1b[?1006h\x1b[3;5H"
    .as_bytes();

/// The screen [`OUTPUT`] draws on a 6×20 terminal whose program exited with status 3.
fn exited_screen() -> Result<TerminalScreen, fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 0)?;
    emu.process(OUTPUT);
    emu.set_exit_code(3);
    Ok(emu.snapshot())
}

/// A resize, every row kind, the side channels and the exit code, from the blank screen.
fn full_frame() -> Result<(Frame, TerminalScreen), fux_vt::Error> {
    let base = TerminalScreen::default();
    let frame = Frame {
        num: FrameNum(300),
        base: FrameNum::BLANK,
        echo_ack: InputSeq(129),
        diff: exited_screen()?.diff_from(&base),
    };
    Ok((frame, base))
}

/// An incremental frame: one row changed, no resize, the side channels unchanged.
fn incremental_frame() -> Result<(Frame, TerminalScreen), fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 0)?;
    emu.process(OUTPUT);
    let base = emu.snapshot();
    emu.process(b"\x1b[6;1Hlast row");
    let frame = Frame {
        num: FrameNum(301),
        base: FrameNum(300),
        echo_ack: InputSeq(130),
        diff: emu.snapshot().diff_from(&base),
    };
    Ok((frame, base))
}

/// A frame that scrolls: the screen scrolled up a line and a line written at the bottom, the rest
/// moved rather than sent, and the line scrolled off kept in history.
fn scrolled_frame() -> Result<(Frame, TerminalScreen), fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 1 << 20)?;
    emu.process(OUTPUT);
    let base = emu.snapshot();
    emu.process(b"\x1b[6;1H\r\nscrolled in");
    let frame = Frame {
        num: FrameNum(302),
        base: FrameNum(301),
        echo_ack: InputSeq(130),
        diff: emu.snapshot().diff_from(&base),
    };
    Ok((frame, base))
}

/// The history the scrolled frame's server holds: the two rows its output scrolled off.
fn history_reply() -> Result<HistoryReply, fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 1 << 20)?;
    emu.process(OUTPUT);
    emu.process(b"\x1b[6;1H\r\nscrolled in\r\n");
    let mark = emu.snapshot().history();
    Ok(emu.history(HistoryRequest {
        id: 0,
        newest: mark.newest,
        count: 5,
    }))
}

/// The modes for every mouse mode (with the default encoding) and every mouse encoding (with
/// press/release reporting).
fn modes() -> Vec<WireModes> {
    let sequences: [&[u8]; 9] = [
        b"",
        b"\x1b[?9h",
        b"\x1b[?1000h",
        b"\x1b[?1002h",
        b"\x1b[?1003h",
        b"\x1b[?1000h\x1b[?1005h",
        b"\x1b[?1000h\x1b[?1006h",
        b"\x1b[?1h\x1b=\x1b[?2004h\x1b[?25l",
        b"\x1b[?1049h",
    ];
    sequences
        .iter()
        .map(|seq| {
            TerminalScreen::from_bytes(4, 4, seq)
                .diff_from(&TerminalScreen::default())
                .modes
        })
        .collect()
}

/// One message of each kind, with varints of one and several bytes.
fn client_msgs() -> Option<Vec<ClientMsg>> {
    Some(vec![
        ClientMsg::Resize {
            n: 1,
            size: Size::new(50, 132),
        },
        ClientMsg::Resize {
            n: 70_000,
            size: Size::new(1000, 1000),
        },
        ClientMsg::Ack {
            frame: FrameNum(70_000),
        },
        ClientMsg::Resync,
        ClientMsg::History(HistoryRequest {
            id: 300,
            newest: 70_000,
            count: 256,
        }),
        ClientMsg::Keys {
            seq: InputSeq(2),
            events: vec![
                InputEvent::Key(WireKey {
                    key: WireKeyCode::Char('é'),
                    mods: 5,
                    kitty: None,
                }),
                InputEvent::Key(WireKey {
                    key: WireKeyCode::F(12.try_into().ok()?),
                    mods: 0,
                    kitty: Some(WireKitty {
                        code: Some(57_399),
                        shifted: Some(65),
                        base: None,
                        mods: 0x84,
                    }),
                }),
                InputEvent::Mouse(WireMouse {
                    action: WireMouseAction::Release(Some(WireButton::WheelDown)),
                    mods: 2,
                    row: 300,
                    col: 7,
                }),
                InputEvent::Mouse(WireMouse {
                    action: WireMouseAction::Press(WireButton::Left),
                    mods: 0,
                    row: 1,
                    col: 2,
                }),
                InputEvent::Focus(true),
                InputEvent::Paste("hi".to_owned()),
            ],
        },
        ClientMsg::Keys {
            seq: InputSeq(300),
            events: vec![InputEvent::Paste("x".repeat(200))],
        },
        ClientMsg::Colours(WireColours {
            foreground: Some([0xdd, 0xdd, 0xdd]),
            background: None,
            palette: vec![None, Some([0xcd, 0, 0])],
            scheme: Some(WireScheme::Light),
        }),
    ])
}

/// One cell with `text`, of `kind`, `fg` and `style`, the rest default.
fn cell(text: &str, kind: CellKind, fg: WireColor, style: u16) -> Option<WireCell> {
    Some(WireCell {
        text: CellText::new(text)?,
        kind,
        fg,
        bg: WireColor::Default,
        underline_color: WireColor::Default,
        style: WireStyle::new(style)?,
        link: 0,
    })
}

/// `count` of `cell`.
fn run(count: u16, cell: Option<WireCell>) -> Option<Run> {
    Some(Run {
        count: NonZeroU16::new(count)?,
        cell: cell?,
    })
}

/// An 8-cell row of every cell kind, every colour kind, a styled underline with its colour, a
/// cluster too long to keep inline, and a hyperlink.
fn wire_row(row: u16) -> Option<RowDiff> {
    let linked = WireCell {
        bg: WireColor::Idx(200),
        underline_color: WireColor::Rgb(7, 8, 9),
        link: 1,
        ..cell(
            "e\u{301}",
            CellKind::Narrow,
            WireColor::Rgb(1, 2, 3),
            WireStyle::UNDERLINE | WireStyle::UNDERLINE_CURLY,
        )?
    };
    let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}";
    Some(RowDiff {
        row,
        flags: RowFlags {
            wrapped: true,
            prompt: true,
        },
        runs: vec![
            run(
                3,
                cell("abc", CellKind::Chars, WireColor::Idx(1), WireStyle::BOLD),
            )?,
            run(1, cell("日", CellKind::WideChars, WireColor::Default, 0))?,
            run(1, Some(linked))?,
            run(1, cell(family, CellKind::Wide, WireColor::Default, 0))?,
            run(1, cell("", CellKind::Continuation, WireColor::Default, 0))?,
        ],
        links: vec![WireLink {
            uri: "https://koh.example/".to_owned(),
            id: "k".to_owned(),
        }],
    })
}

/// A frame from the blank screen with a resize and every side channel, and one on it that moves
/// rows and replaces one.
fn wire_frames() -> Option<Vec<Frame>> {
    let full = Frame {
        num: FrameNum(300),
        base: FrameNum::BLANK,
        echo_ack: InputSeq(129),
        diff: ScreenDiff {
            resize: Some(Size::new(3, 8)),
            title: Some("the title".to_owned()),
            icon: Some("the icon".to_owned()),
            clipboard: Some("aGk=".to_owned()),
            bell_count: 2,
            exit_code: Some(3),
            history: Some(HistoryMark {
                newest: 70_000,
                len: 2,
            }),
            tty: Some(TtyModes {
                echo: true,
                line: false,
            }),
            commands: Some(Commands {
                finished: 300,
                status: Some(-1),
                output: Some(((0, 0), (2, 7))),
                running: Some((2, 3)),
            }),
            cursor: (1, 2),
            modes: WireModes {
                hide_cursor: true,
                application_cursor: false,
                application_keypad: true,
                bracketed_paste: true,
                mouse_mode: WireMouseMode::ButtonMotion,
                mouse_encoding: WireMouseEncoding::Sgr,
                alternate: false,
            },
            shifts: Shifts::default(),
            rows: vec![wire_row(0)?, wire_row(2)?],
        },
    };
    let moved = Frame {
        num: FrameNum(301),
        base: FrameNum(300),
        echo_ack: InputSeq(130),
        diff: ScreenDiff {
            resize: None,
            title: None,
            icon: None,
            clipboard: None,
            exit_code: None,
            history: None,
            tty: None,
            commands: None,
            shifts: Shifts::new(vec![Shift {
                top: 1,
                len: NonZeroU16::new(2)?,
                by: NonZeroI16::new(-1)?,
            }])?,
            rows: vec![RowDiff {
                row: 2,
                flags: RowFlags::default(),
                runs: vec![run(8, cell(" ", CellKind::Narrow, WireColor::Default, 0))?],
                links: Vec::new(),
            }],
            ..full.diff
        },
    };
    Some(vec![full, moved])
}

/// History rows, the first a whole [`wire_row`].
fn wire_history() -> Option<HistoryReply> {
    let RowDiff { runs, links, .. } = wire_row(0)?;
    Some(HistoryReply {
        id: 300,
        rows: vec![
            HistoryRow {
                name: 69_999,
                flags: RowFlags {
                    wrapped: true,
                    prompt: true,
                },
                runs,
                links,
            },
            HistoryRow {
                name: 70_000,
                flags: RowFlags::default(),
                runs: vec![run(2, cell("z", CellKind::Narrow, WireColor::Idx(9), 0))?],
                links: Vec::new(),
            },
        ],
    })
}

/// `hex` as bytes, or `None` if it is not an even run of hex digits.
fn unhex(hex: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = hex.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            (pair.len() == 2).then_some(())?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

/// `bytes` as lowercase hex, for readable failures.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The postcard encoding of each of [`modes`].
const MODES: [&str; 9] = [
    "00000000000000",
    "00000000010000",
    "00000000020000",
    "00000000030000",
    "00000000040000",
    "00000000020100",
    "00000000020200",
    "01010101000000",
    "00000000000001",
];

/// Each of [`client_msgs`] as the client's stream carries it, length prefix included.
const CLIENT_MSGS: [&str; 8] = [
    "000000050001328401",
    "0000000800f0a204e807e807",
    "0000000401f0a204",
    "0000000102",
    "0000000803ac02f0a2048002",
    "0000002b040206000002c3a90500000f0c000101b7c003014100840101010402ac0207010000000102020103026869",
    "000000cf04ac020103c8017878787878787878787878787878787878787878787878787878787878787878787878\
        78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878\
        78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878\
        78787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878\
        787878787878787878787878787878787878787878787878787878",
    "0000000e0501dddddd00020001cd00000101",
];

/// Each of [`wire_frames`], and the header of its stream: tag, base, the rows it changes.
const FRAMES: [(&str, &str); 2] = [
    (
        "ac020081010103080109746865207469746c6501087468652069636f6e010461476b3d02010301f0a2040201\
        010001ac020101010000020701020301020100010103020000020003050303616263030101000001000103e6\
        97a5040000000000010365cc81000201020301c8020708098808010119f09f91a8e2808df09f91a9e2808df0\
        9f91a7e2808df09f91a60100000000000100020000000000011468747470733a2f2f6b6f682e6578616d706c\
        652f016b0203050303616263030101000001000103e697a5040000000000010365cc81000201020301c80207\
        08098808010119f09f91a8e2808df09f91a9e2808df09f91a7e2808df09f91a6010000000000010002000000\
        0000011468747470733a2f2f6b6f682e6578616d706c652f016b",
        "0000020002",
    ),
    (
        "ad02ac028201000000000200000000010201000101030200010102010102000108012000000000000000",
        "00ac020102",
    ),
];

/// [`wire_history`].
const HISTORY: &str =
    "ac0202efa20403050303616263030101000001000103e697a5040000000000010365cc81000201020301c802\
        0708098808010119f09f91a8e2808df09f91a9e2808df09f91a7e2808df09f91a60100000000000100020000\
        000000011468747470733a2f2f6b6f682e6578616d706c652f016bf0a204000102017a0001090000000000";

#[test]
fn frames_and_history_round_trip_through_their_streams() {
    for (frame, base) in [
        full_frame().expect("frame"),
        incremental_frame().expect("frame"),
        scrolled_frame().expect("frame"),
    ] {
        let raw = postcard::to_allocvec(&frame).expect("encodes");
        assert_eq!(postcard::from_bytes::<Frame>(&raw).expect("decodes"), frame);
        // A stream inflates only against its base's dictionary.
        let stream = FrameEncoder::default()
            .encode(&frame, &base)
            .expect("encodes");
        assert_eq!(decode_frame(&stream, &base).expect("decodes"), frame);
    }
    let reply = history_reply().expect("reply");
    assert_eq!(reply.rows.len(), 2, "two rows scrolled off");
    let encoded = FrameEncoder::default()
        .encode_history(&reply)
        .expect("encodes");
    assert!(matches!(decode_server(&encoded), Ok(ServerMsg::History(_))));
    assert_eq!(decode_history(&encoded[1..]).ok(), Some(reply));
    assert!(
        decode_frame(&encoded, &TerminalScreen::default()).is_none(),
        "history rows are not a frame"
    );
}

/// The protocol these bytes are pinned for. A change to them is a new protocol: bump the ALPN
/// (`koh::transport_iroh::ALPN`) and this with it.
const PINNED_FOR: &[u8] = b"koh/7";

/// One opening request of each kind, with varints of one and several bytes.
fn requests() -> Option<Vec<Request>> {
    let path = |p: &[u8]| RemotePath::new(p.to_vec()).ok();
    Some(vec![
        Request::Shell(Pick::Latest),
        Request::Shell(Pick::New),
        Request::Shell(Pick::Id(SessionNum(300))),
        Request::Shell(Pick::Resume(Resume {
            run: RunId(0x0102_0304_0506_0708),
            session: SessionNum(3),
        })),
        Request::Sessions,
        Request::Exec(CommandLine::join(&["echo", "a b"]).ok()?),
        Request::Copy(Copy::Get(
            Sources::new(vec![path(b"~/x")?, path(b"")?]).ok()?,
        )),
        Request::Copy(Copy::Put {
            dest: path(b"/srv")?,
            arity: Arity::Several,
        }),
    ])
}

/// [`requests`], as the client's first stream carries them, length prefix included.
const REQUESTS: [&str; 8] = [
    "000000020000",
    "000000020001",
    "000000040002ac02",
    "0000000c0003888e98a8c0e080810103",
    "0000000101",
    "0000000a02086563686f20612062",
    "00000008030002037e2f7800",
    "000000080301042f73727601",
];

/// The server's replies sent whole: a shell's admission, a listing and a command's status.
fn replies() -> Vec<Vec<u8>> {
    let attached = Attached {
        at: Resume {
            run: RunId(9),
            session: SessionNum(300),
        },
    };
    let list = SessionList(vec![
        SessionInfo {
            session: SessionNum(1),
            age_secs: 70_000,
            presence: Presence::Attached,
            size: Size::new(24, 80),
            title: "vim".to_owned(),
            exited: None,
        },
        SessionInfo {
            session: SessionNum(2),
            age_secs: 5,
            presence: Presence::Detached { secs: 4 },
            size: Size::new(50, 132),
            title: String::new(),
            exited: Some(137),
        },
    ]);
    let max = koh::request::MAX_REPLY;
    [
        koh::request::encode(&attached, max),
        koh::request::encode(&list, max),
        koh::request::encode(&ExitStatus(137), max),
    ]
    .into_iter()
    .filter_map(Result::ok)
    .collect()
}

/// [`replies`].
const REPLIES: [&str; 3] = [
    "0000000309ac02",
    "000000180201f0a2040018500376696d000205010432840100018901",
    "000000028901",
];

/// One copy item of each kind.
fn copy_items() -> Option<Vec<Item>> {
    let name = |n: &[u8]| Name::new(n.to_vec()).ok();
    Some(vec![
        Item::Dir {
            name: name(b"a dir")?,
            mode: Mode::new(0o755)?,
            mtime: Time::new(1_700_000_000, 5),
        },
        Item::File {
            name: name(b"odd\n\xff")?,
            mode: Mode::new(0o4751)?,
            mtime: None,
        },
        Item::Data(koh::copy::DataLen::new(65_536)?),
        Item::Symlink {
            name: name(b"link")?,
            target: LinkTarget::new(b"../x".to_vec()).ok()?,
        },
        Item::End,
        Item::Skipped(name(b"fifo")?),
        Item::Failed(Failure::new(
            FailKind::PermissionDenied,
            std::path::Path::new("/root"),
        )),
        Item::Done,
    ])
}

/// [`copy_items`], as a copy stream carries them, length prefix included.
const COPY_ITEMS: [&str; 8] = [
    "0000001000056120646972ed030180e2cfaa0605",
    "0000000a01056f64640affe91300",
    "0000000402808004",
    "0000000b03046c696e6b042e2e2f78",
    "0000000104",
    "0000000605046669666f",
    "000000080601052f726f6f74",
    "0000000107",
];

#[test]
fn opening_requests_replies_and_copy_items_encode_as_pinned() {
    assert_eq!(koh::transport_iroh::ALPN, PINNED_FOR);
    let requests = requests().expect("requests");
    let items = copy_items().expect("items");
    let encoded = |msg: &dyn erased::Encode| hex(&msg.encode());
    let actual: Vec<String> = (requests.iter().map(|r| encoded(r)))
        .chain(replies().iter().map(|reply| hex(reply)))
        .chain(items.iter().map(|item| encoded(item)))
        .collect();
    let pinned: Vec<&str> = REQUESTS
        .iter()
        .chain(&REPLIES)
        .chain(&COPY_ITEMS)
        .copied()
        .collect();
    assert_eq!(actual, pinned, "a change here is a new protocol");
    for (request, pinned) in requests.iter().zip(REQUESTS) {
        let pinned = unhex(pinned).expect("hex");
        let decoded: Request =
            koh::request::decode_framed(&pinned, koh::request::MAX_REQUEST).expect("decodes");
        assert_eq!(&decoded, request);
    }
    for (item, pinned) in items.iter().zip(COPY_ITEMS) {
        let pinned = unhex(pinned).expect("hex");
        let decoded: Item =
            koh::request::decode_framed(&pinned, koh::copy::MAX_ITEM).expect("decodes");
        assert_eq!(&decoded, item);
    }
    assert_eq!(
        [ExecStream::Stdout, ExecStream::Stderr, ExecStream::Status].map(ExecStream::tag),
        [0, 1, 2]
    );
}

/// Framed encodings of the opening's types, as one list.
mod erased {
    pub trait Encode {
        fn encode(&self) -> Vec<u8>;
    }

    impl<T: serde::Serialize> Encode for T {
        fn encode(&self) -> Vec<u8> {
            koh::request::encode(self, usize::MAX).unwrap_or_default()
        }
    }
}

#[test]
fn client_messages_encode_as_pinned() {
    assert_eq!(koh::transport_iroh::ALPN, PINNED_FOR);
    let msgs = client_msgs().expect("messages");
    assert_eq!(msgs.len(), CLIENT_MSGS.len());
    for (msg, pinned) in msgs.iter().zip(CLIENT_MSGS) {
        let pinned = unhex(pinned).expect("hex");
        assert_eq!(
            hex(&encode_client(msg).expect("encodes")),
            hex(&pinned),
            "{msg:?}"
        );
        let mut decoder = ClientDecoder::default();
        decoder.push(&pinned);
        assert_eq!(decoder.next_msg().expect("decodes").as_ref(), Some(msg));
        decoder.finish().expect("nothing left over");
    }
}

#[test]
fn server_messages_encode_as_pinned() {
    assert_eq!(koh::transport_iroh::ALPN, PINNED_FOR);
    let frames = wire_frames().expect("frames");
    assert_eq!(frames.len(), FRAMES.len());
    let mut client = TerminalScreen::default();
    for (frame, (pinned, header)) in frames.iter().zip(FRAMES) {
        let pinned = unhex(pinned).expect("hex");
        assert_eq!(
            hex(&postcard::to_allocvec(frame).expect("encodes")),
            hex(&pinned),
            "frame {:?}: a change here is a new protocol",
            frame.num
        );
        assert_eq!(
            &postcard::from_bytes::<Frame>(&pinned).expect("decodes"),
            frame
        );
        // The stream's header is pinned; the DEFLATE body after it only through decoding, as the
        // compressor may pick other bytes for the same frame.
        let stream = FrameEncoder::default()
            .encode(frame, &client)
            .expect("encodes");
        assert!(hex(&stream).starts_with(header), "{:?}", frame.num);
        assert_eq!(&decode_frame(&stream, &client).expect("decodes"), frame);
        client.apply(&frame.diff).expect("a frame the client takes");
    }
    let reply = wire_history().expect("history");
    let pinned = unhex(HISTORY).expect("hex");
    assert_eq!(
        hex(&postcard::to_allocvec(&reply).expect("encodes")),
        hex(&pinned),
        "history: a change here is a new protocol"
    );
    let stream = FrameEncoder::default()
        .encode_history(&reply)
        .expect("encodes");
    assert_eq!(stream.first(), Some(&1), "the history stream's tag");
    assert_eq!(decode_history(&stream[1..]).ok(), Some(reply));
}

#[test]
fn modes_encode_as_pinned() {
    assert_eq!(koh::transport_iroh::ALPN, PINNED_FOR);
    let modes = modes();
    assert_eq!(modes.len(), MODES.len());
    for (modes, pinned) in modes.iter().zip(MODES) {
        let pinned = unhex(pinned).expect("hex");
        assert_eq!(
            hex(&postcard::to_allocvec(modes).expect("encodes")),
            hex(&pinned),
            "{modes:?}"
        );
        assert_eq!(
            &postcard::from_bytes::<WireModes>(&pinned).expect("decodes"),
            modes
        );
    }
}

/// The hand-built messages, as the fuzz targets read their input: CI's fuzz job starts each target
/// from them (in `$KOH_FUZZ_SEEDS/<target>/`, when that is set) instead of from nothing. Each seed
/// must reach the code it seeds: the client stream decodes whole, every diff applies.
#[test]
fn the_wire_messages_seed_the_fuzzers() {
    let client: Vec<u8> = client_msgs()
        .expect("messages")
        .iter()
        .flat_map(|msg| encode_client(msg).expect("encodes"))
        .collect();
    let mut decoder = ClientDecoder::default();
    decoder.push(&client);
    while decoder.next_msg().expect("decodes").is_some() {}
    decoder.finish().expect("whole");

    let frames = wire_frames().expect("frames");
    let reply = wire_history().expect("history");
    let mut screen = TerminalScreen::default();
    let mut streams = Vec::new();
    for frame in &frames {
        streams.push(
            FrameEncoder::default()
                .encode(frame, &screen)
                .expect("encodes"),
        );
        screen.apply(&frame.diff).expect("applies");
    }
    streams.push(
        FrameEncoder::default()
            .encode_history(&reply)
            .expect("encodes"),
    );
    // What request_decode reads: a message's body, as `decode` takes it.
    let (requests, items) = (requests().expect("requests"), copy_items().expect("items"));
    let bodies = (requests.iter())
        .map(|request| koh::request::encode(request, usize::MAX).expect("encodes"))
        .chain(replies())
        .chain((items.iter()).map(|item| koh::request::encode(item, usize::MAX).expect("encodes")))
        .map(|framed| framed[4..].to_vec());
    // What history_apply reads first: the mark, the request and the view's offset.
    let header =
        postcard::to_allocvec(&(70_000_u64, 2_u32, 70_000_u64, 2_u16, 1_u16)).expect("encodes");
    let seeds = [
        // The first byte splits the rest into reads of that many bytes.
        ("proto_decode", [&[255][..], &client].concat()),
        ("server_input", [&[0][..], &client].concat()),
        (
            "history_apply",
            [header, postcard::to_allocvec(&reply).expect("encodes")].concat(),
        ),
    ]
    .into_iter()
    .chain(streams.into_iter().map(|stream| ("proto_decode", stream)))
    .chain(bodies.map(|body| ("request_decode", body)))
    .chain(frames.iter().map(|frame| {
        (
            "screen_apply",
            postcard::to_allocvec(&frame.diff).expect("encodes"),
        )
    }));
    let Some(root) = std::env::var_os("KOH_FUZZ_SEEDS") else {
        return;
    };
    for (n, (target, seed)) in seeds.enumerate() {
        let dir = std::path::Path::new(&root).join(target);
        std::fs::create_dir_all(&dir).expect("the target's corpus");
        std::fs::write(dir.join(format!("wire-{n}")), seed).expect("a seed");
    }
}
